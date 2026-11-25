/// Phase 2 Sui Move Package: `cowrie_cashu::mint_vault`
/// Implements Calle's Federated Cashu "Consensus Box" as a Sui Shared Object (`MintVault<Asset>`)
/// with real-time Proof of Reserves, fixed-size 48-byte `Y = H_G1(secret)` nullifiers (`NUT-07`),
/// slot-grouped multi-pairing BLS12-381 verification (<= max_slots pairings even for 500+ notes),
/// NUT-11 P2PK locks, and hourly melt circuit breakers.
module cowrie_cashu::mint_vault;

use blind_seal::blind_seal::{Self, IssuerCap, KeysetInfo};
use std::hash::sha2_256;
use sui::balance::{Self, Balance};
use sui::bls12381::{
    G1, GT, Scalar, g1_add, g1_from_bytes, g1_identity, g1_mul, g2_generator, gt_add, hash_to_g1,
    pairing, scalar_from_bytes,
};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::ecdsa_k1::secp256k1_verify;
use sui::event;
use sui::group_ops::{Self, Element};
use sui::table::{Self, Table};

const EAmountConservationMismatch: u64 = 100;
const ENullifierAlreadySpent: u64 = 101;
const EInvalidBlsBatchSignature: u64 = 102;
const EInvalidP2pkSchnorrSig: u64 = 103;
const EMeltCircuitBreakerTripped: u64 = 104;
const EKeysetInfoMismatch: u64 = 105;
const EEmptyProofBatch: u64 = 106;

const ONE_HOUR_MS: u64 = 3_600_000;

/// Generic Multi-Asset Federated Cashu Vault (`USDC`, `LBTC`, `SUI`, etc.).
/// `spent_ys` indexes fixed 48-byte compressed `G1` points `Y = H_G1(secret)` (`NUT-07`),
/// preventing unbounded secret-size storage bloat and keeping `/v1/checkstate` private.
public struct MintVault<phantom Asset> has key {
    id: UID,
    issuer_cap: IssuerCap,
    keyset_id: vector<u8>,
    reserve: Balance<Asset>,
    spent_ys: Table<vector<u8>, bool>,
    notes_per_coin_unit: u64,
    hourly_melt_cap_notes: u64,
    window_start_ms: u64,
    melted_in_window_notes: u64,
}

public struct TicketIssuedEvent has copy, drop {
    ticket_id: ID,
    keyset_id: vector<u8>,
    note_amount: u64,
}

public fun create_vault<Asset>(
    issuer_cap: IssuerCap,
    keyset_id: vector<u8>,
    notes_per_coin_unit: u64,
    hourly_melt_cap_notes: u64,
    ctx: &mut TxContext,
) {
    let vault = MintVault<Asset> {
        id: object::new(ctx),
        issuer_cap,
        keyset_id,
        reserve: balance::zero(),
        spent_ys: table::new(ctx),
        notes_per_coin_unit,
        hourly_melt_cap_notes,
        window_start_ms: 0,
        melted_in_window_notes: 0,
    };
    transfer::share_object(vault);
}

fun sum_slots(slots: &vector<u8>, max_slots: u8): u64 {
    let mut total: u64 = 0;
    let mut i = 0;
    let len = slots.length();
    while (i < len) {
        let s = slots[i];
        assert!(s < max_slots && s < 63, EAmountConservationMismatch);
        total = total + (1u64 << s);
        i = i + 1;
    };
    total
}

/// Derives a guaranteed non-zero 120-bit Fiat-Shamir scalar `< q` from `(transcript_digest, index)`.
fun derive_fiat_shamir_scalar(transcript_digest: &vector<u8>, idx: u64): Element<Scalar> {
    let mut input = *transcript_digest;
    input.push_back(((idx >> 24) & 0xFF) as u8);
    input.push_back(((idx >> 16) & 0xFF) as u8);
    input.push_back(((idx >> 8) & 0xFF) as u8);
    input.push_back((idx & 0xFF) as u8);
    let digest = sha2_256(input);

    // Zero bytes `[0..16]` and `[31]` while populating `[16..31]` with 120 bits of SHA-256 output
    // (`byte[16] |= 1`), ensuring `1 <= z < q` under canonical scalar encoding.
    let mut raw = vector[];
    let mut k = 0u64;
    while (k < 16) {
        raw.push_back(0u8);
        k = k + 1;
    };
    let mut j = 0u64;
    while (j < 15) {
        let mut b = digest[j];
        if (j == 0) {
            b = b | 1u8;
        };
        raw.push_back(b);
        j = j + 1;
    };
    raw.push_back(0u8);
    scalar_from_bytes(&raw)
}

/// NUT-04 (Sui Collateral Deposit -> Immutable `BlindSigningTicket`).
public fun mint_from_sui<Asset>(
    vault: &mut MintVault<Asset>,
    payment: Coin<Asset>,
    out_slots: vector<u8>,
    out_blinded_g1: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let requested_notes = sum_slots(&out_slots, max_slots);
    let backed_notes = payment.value() * vault.notes_per_coin_unit;
    assert!(requested_notes == backed_notes, EAmountConservationMismatch);

    vault.reserve.join(coin::into_balance(payment));
    let ticket_id = blind_seal::issue_blind_ticket(
        &vault.issuer_cap,
        out_slots,
        out_blinded_g1,
        ctx,
    );
    event::emit(TicketIssuedEvent {
        ticket_id,
        keyset_id: vault.keyset_id,
        note_amount: requested_notes,
    });
}

fun verify_and_nullify_native_bls<Asset>(
    vault: &mut MintVault<Asset>,
    keyset_info: &KeysetInfo,
    in_slots: &vector<u8>,
    secrets: &vector<vector<u8>>,
    raw_sigs_g1: &vector<vector<u8>>,
    p2pk_pubkeys: &vector<vector<u8>>,
    p2pk_sigs: &vector<vector<u8>>,
    sighash_context: &vector<u8>,
): u64 {
    assert!(blind_seal::keyset_id(keyset_info) == &vault.keyset_id, EKeysetInfoMismatch);
    let n = secrets.length();
    assert!(n > 0 && n == in_slots.length() && n == raw_sigs_g1.length(), EEmptyProofBatch);

    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let total_in = sum_slots(in_slots, max_slots);

    // Pre-allocate per-slot `G1` hash accumulators (`length == max_slots`) so even a 500-note
    // HTTP-402 batch performs cheap `g1_add`s in the loop and at most `max_slots` pairings total!
    let id_g1 = g1_identity();
    let mut slot_h_sums: vector<Element<G1>> = vector[];
    let mut slot_used: vector<bool> = vector[];
    let mut s_idx: u8 = 0;
    while (s_idx < max_slots) {
        slot_h_sums.push_back(id_g1);
        slot_used.push_back(false);
        s_idx = s_idx + 1;
    };

    let mut sig_sum = id_g1;

    // Derive a Fiat-Shamir batch transcript digest whenever `n >= 2` so rogue cancellation
    // pairs `(C_0 + Delta, C_1 - Delta)` abort with 1 - 2^-120 soundness!
    let mut fs_seed = vector[];
    if (n > 1) {
        fs_seed.append(b"COWRIE_MOVE_FS_BATCH_V1");
        fs_seed.append(vault.keyset_id);
        let mut t_idx = 0;
        while (t_idx < n) {
            fs_seed.push_back(in_slots[t_idx]);
            fs_seed.append(secrets[t_idx]);
            fs_seed.append(raw_sigs_g1[t_idx]);
            t_idx = t_idx + 1;
        };
        fs_seed = sha2_256(fs_seed);
    };

    let mut i = 0;
    while (i < n) {
        let h_pt = hash_to_g1(&secrets[i]);
        let y_bytes = *group_ops::bytes(&h_pt);
        assert!(!vault.spent_ys.contains(y_bytes), ENullifierAlreadySpent);
        vault.spent_ys.add(y_bytes, true);

        let sig_pt = g1_from_bytes(&raw_sigs_g1[i]);
        let (weighted_sig, weighted_h) = if (n > 1) {
            let z_i = derive_fiat_shamir_scalar(&fs_seed, i);
            (g1_mul(&z_i, &sig_pt), g1_mul(&z_i, &h_pt))
        } else {
            (sig_pt, h_pt)
        };
        sig_sum = g1_add(&sig_sum, &weighted_sig);

        let slot_u64 = (in_slots[i] as u64);
        let acc_ref = &mut slot_h_sums[slot_u64];
        *acc_ref = g1_add(acc_ref, &weighted_h);
        let used_ref = &mut slot_used[slot_u64];
        *used_ref = true;

        i = i + 1;
    };

    // Optional P2PK lock checks
    let mut p = 0;
    let p_len = p2pk_pubkeys.length();
    while (p < p_len) {
        assert!(
            secp256k1_verify(&p2pk_sigs[p], &p2pk_pubkeys[p], sighash_context, 1),
            EInvalidP2pkSchnorrSig,
        );
        p = p + 1;
    };

    // Compute RHS product of pairings across ONLY active slots (`<= max_slots` pairings!)
    let mut rhs_opt: Option<Element<GT>> = option::none();
    let mut k: u8 = 0;
    while (k < max_slots) {
        let k_u64 = (k as u64);
        if (slot_used[k_u64]) {
            let pk_pt = blind_seal::keyset_slot_pk(keyset_info, k);
            let term = pairing(&slot_h_sums[k_u64], pk_pt);
            if (rhs_opt.is_none()) {
                rhs_opt.fill(term);
            } else {
                let prev = rhs_opt.extract();
                rhs_opt.fill(gt_add(&prev, &term));
            };
        };
        k = k + 1;
    };

    let rhs_gt = rhs_opt.destroy_some();
    let lhs_gt = pairing(&sig_sum, &g2_generator());
    assert!(&lhs_gt == &rhs_gt, EInvalidBlsBatchSignature);

    total_in
}

/// NUT-03 Atomic Swap inside the Sui Move "Consensus Box".
public fun swap_native_dst<Asset>(
    vault: &mut MintVault<Asset>,
    keyset_info: &KeysetInfo,
    in_slots: vector<u8>,
    secrets: vector<vector<u8>>,
    raw_sigs_g1: vector<vector<u8>>,
    p2pk_pubkeys: vector<vector<u8>>,
    p2pk_sigs: vector<vector<u8>>,
    out_slots: vector<u8>,
    out_blinded_g1: vector<vector<u8>>,
    fee_notes: u64,
    sighash_context: vector<u8>,
    ctx: &mut TxContext,
) {
    let total_in = verify_and_nullify_native_bls(
        vault,
        keyset_info,
        &in_slots,
        &secrets,
        &raw_sigs_g1,
        &p2pk_pubkeys,
        &p2pk_sigs,
        &sighash_context,
    );
    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let total_out = sum_slots(&out_slots, max_slots);
    assert!(total_in == total_out + fee_notes, EAmountConservationMismatch);

    let ticket_id = blind_seal::issue_blind_ticket(
        &vault.issuer_cap,
        out_slots,
        out_blinded_g1,
        ctx,
    );
    event::emit(TicketIssuedEvent {
        ticket_id,
        keyset_id: vault.keyset_id,
        note_amount: total_out,
    });
}

/// NUT-05 Melt / Batch HTTP-402 Settlement back into native Sui `Coin<Asset>`.
public fun melt_native_dst<Asset>(
    vault: &mut MintVault<Asset>,
    keyset_info: &KeysetInfo,
    clock: &Clock,
    in_slots: vector<u8>,
    secrets: vector<vector<u8>>,
    raw_sigs_g1: vector<vector<u8>>,
    p2pk_pubkeys: vector<vector<u8>>,
    p2pk_sigs: vector<vector<u8>>,
    recipient: address,
    sighash_context: vector<u8>,
    ctx: &mut TxContext,
) {
    let total_in = verify_and_nullify_native_bls(
        vault,
        keyset_info,
        &in_slots,
        &secrets,
        &raw_sigs_g1,
        &p2pk_pubkeys,
        &p2pk_sigs,
        &sighash_context,
    );
    assert!(total_in % vault.notes_per_coin_unit == 0, EAmountConservationMismatch);

    let now_ms = clock.timestamp_ms();
    if (now_ms >= vault.window_start_ms + ONE_HOUR_MS) {
        vault.window_start_ms = now_ms;
        vault.melted_in_window_notes = 0;
    };
    assert!(
        vault.melted_in_window_notes + total_in <= vault.hourly_melt_cap_notes,
        EMeltCircuitBreakerTripped,
    );
    vault.melted_in_window_notes = vault.melted_in_window_notes + total_in;

    let payout_coins = total_in / vault.notes_per_coin_unit;
    let coin_out = coin::take(&mut vault.reserve, payout_coins, ctx);
    transfer::public_transfer(coin_out, recipient);
}

public fun vault_reserve_value<Asset>(vault: &MintVault<Asset>): u64 {
    vault.reserve.value()
}

public fun is_y_spent<Asset>(vault: &MintVault<Asset>, y_bytes: vector<u8>): bool {
    vault.spent_ys.contains(y_bytes)
}

public fun melted_in_window_notes<Asset>(vault: &MintVault<Asset>): u64 {
    vault.melted_in_window_notes
}
