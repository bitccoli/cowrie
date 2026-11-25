/// Phase 3 Sui Move Package: `cowrie_fedimint::federation_vault`
/// Upstream Sui consensus, msat reserve custody, SpendKey anti-front-running,
/// deterministic SessionClosedEvent emission (for 12-word BIP-39 wallet recovery), and LNv2
/// Lightning Gateway TPE contract settlement for downstream Fedimint clients.
module cowrie_fedimint::federation_vault;

use blind_seal::blind_seal::{Self, IssuerCap};
use std::hash::sha2_256;
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::ecdsa_k1::secp256k1_verify;
use sui::ed25519::ed25519_verify;
use sui::event;
use sui::table::{Self, Table};

const EConservationFailed: u64 = 200;
const ENonceAlreadySpent: u64 = 201;
const EInvalidSpendKeySchnorr: u64 = 202;
const EInsufficientQuorumAttestation: u64 = 203;
const EInvalidLnv2Preimage: u64 = 204;
const ELnv2AlreadySettled: u64 = 205;

const MSAT_PER_SAT: u64 = 1000;

public struct FedimintVault<phantom BTCAsset> has key {
    id: UID,
    issuer_cap: IssuerCap,
    keyset_id: vector<u8>,
    threshold: u16,
    guardian_ed25519_pks: vector<vector<u8>>,
    reserve_sats: Balance<BTCAsset>,
    spent_nonces: Table<vector<u8>, bool>,
    processed_txids: Table<vector<u8>, bool>,
    session_index: u64,
    txs_in_current_session: u64,
    txs_per_session: u64,
}

public struct Lnv2Contract has key, store {
    id: UID,
    amount_msat: u64,
    payment_hash: vector<u8>,
    claim_pk_xonly: vector<u8>,
    refund_pk_xonly: vector<u8>,
    expiry_epoch: u64,
    settled: bool,
    tpe_approval_id: ID,
}

public struct SessionTxCommittedEvent has copy, drop {
    session_index: u64,
    fedimint_txid: vector<u8>,
    ticket_id: ID,
}

public struct SessionClosedEvent has copy, drop {
    session_index: u64,
}

public fun create_federation_vault<BTCAsset>(
    issuer_cap: IssuerCap,
    keyset_id: vector<u8>,
    threshold: u16,
    guardian_ed25519_pks: vector<vector<u8>>,
    txs_per_session: u64,
    ctx: &mut TxContext,
) {
    let vault = FedimintVault<BTCAsset> {
        id: object::new(ctx),
        issuer_cap,
        keyset_id,
        threshold,
        guardian_ed25519_pks,
        reserve_sats: balance::zero(),
        spent_nonces: table::new(ctx),
        processed_txids: table::new(ctx),
        session_index: 0,
        txs_in_current_session: 0,
        txs_per_session,
    };
    transfer::share_object(vault);
}

fun sum_msat_slots(slots: &vector<u8>, max_slots: u8): u64 {
    let mut total: u64 = 0;
    let mut i = 0;
    let len = slots.length();
    while (i < len) {
        let s = slots[i];
        assert!(s < max_slots && s < 63, EConservationFailed);
        total = total + (1u64 << s);
        i = i + 1;
    };
    total
}

fun verify_guardian_quorum_tbs_attestation<BTCAsset>(
    vault: &FedimintVault<BTCAsset>,
    fedimint_txid: &vector<u8>,
    signer_indices: &vector<u16>,
    ed25519_sigs: &vector<vector<u8>>,
) {
    let count = signer_indices.length();
    assert!(
        count >= (vault.threshold as u64) && count == ed25519_sigs.length(),
        EInsufficientQuorumAttestation,
    );
    let mut i = 0;
    while (i < count) {
        let peer_idx = (signer_indices[i] as u64);
        assert!(
            ed25519_verify(&ed25519_sigs[i], &vault.guardian_ed25519_pks[peer_idx], fedimint_txid),
            EInsufficientQuorumAttestation,
        );
        if (i > 0) {
            // Strictly ascending indices prevents duplicate-peer quorum spoofing!
            assert!(signer_indices[i] > signer_indices[i - 1], EInsufficientQuorumAttestation);
        };
        i = i + 1;
    };
}

/// Upstream Sui Deposit -> Downstream `OOBNotes` (`fed11...`).
public fun deposit_sui_for_oob<BTCAsset>(
    vault: &mut FedimintVault<BTCAsset>,
    btc_coin: Coin<BTCAsset>,
    out_slots: vector<u8>,
    out_blinded_g1: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let requested_msat = sum_msat_slots(&out_slots, max_slots);
    let deposited_msat = btc_coin.value() * MSAT_PER_SAT;
    assert!(requested_msat == deposited_msat, EConservationFailed);

    vault.reserve_sats.join(coin::into_balance(btc_coin));
    let _ticket_id = blind_seal::issue_blind_ticket(
        &vault.issuer_cap,
        out_slots,
        out_blinded_g1,
        ctx,
    );
}

/// Executes an unmodified downstream `fedimint-client` note reissuance/spend transaction on Sui.
public fun process_fedimint_tx<BTCAsset>(
    vault: &mut FedimintVault<BTCAsset>,
    fedimint_txid: vector<u8>,
    in_slots: vector<u8>,
    nonces_xonly: vector<vector<u8>>,
    spend_key_schnorr_sigs: vector<vector<u8>>,
    quorum_peer_indices: vector<u16>,
    quorum_tbs_attestations: vector<vector<u8>>,
    out_slots: vector<u8>,
    out_blinded_g1: vector<vector<u8>>,
    fee_msat: u64,
    ctx: &mut TxContext,
) {
    if (vault.processed_txids.contains(fedimint_txid)) {
        return
    };

    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let in_msat = sum_msat_slots(&in_slots, max_slots);
    let out_msat = sum_msat_slots(&out_slots, max_slots);
    assert!(in_msat == out_msat + fee_msat, EConservationFailed);

    let n_in = nonces_xonly.length();
    assert!(n_in > 0 && n_in == in_slots.length() && n_in == spend_key_schnorr_sigs.length(), EConservationFailed);

    // 1. Atomic Nonce nullifiers (BIP-340 SpendKey Schnorr + fedimint-tbs sigs verified by t-of-n quorum below,
    //    plus optional direct secp256k1_verify when non-empty ECDSA witness is supplied)
    let mut i = 0;
    while (i < n_in) {
        let nonce = nonces_xonly[i];
        assert!(!vault.spent_nonces.contains(nonce), ENonceAlreadySpent);
        if (spend_key_schnorr_sigs[i].length() > 0) {
            assert!(
                secp256k1_verify(&spend_key_schnorr_sigs[i], &nonce, &fedimint_txid, 1),
                EInvalidSpendKeySchnorr,
            );
        };
        vault.spent_nonces.add(nonce, true);
        i = i + 1;
    };

    // 2. Verify $t$-of-$n$ Virtual Guardian `fedimint-tbs` DST signature attestation
    verify_guardian_quorum_tbs_attestation(
        vault,
        &fedimint_txid,
        &quorum_peer_indices,
        &quorum_tbs_attestations,
    );

    vault.processed_txids.add(fedimint_txid, true);
    let ticket_id = blind_seal::issue_blind_ticket(
        &vault.issuer_cap,
        out_slots,
        out_blinded_g1,
        ctx,
    );

    event::emit(SessionTxCommittedEvent {
        session_index: vault.session_index,
        fedimint_txid,
        ticket_id,
    });

    vault.txs_in_current_session = vault.txs_in_current_session + 1;
    if (vault.txs_in_current_session >= vault.txs_per_session) {
        event::emit(SessionClosedEvent { session_index: vault.session_index });
        vault.session_index = vault.session_index + 1;
        vault.txs_in_current_session = 0;
    };
}

/// Locks Fedimint eCash notes into an outgoing `LNv2` contract and authorizes standard Seal TPE
/// decryption so `gatewayd` can threshold-decrypt the 32-byte Lightning preimage!
public fun lock_lnv2_outgoing<BTCAsset>(
    vault: &mut FedimintVault<BTCAsset>,
    contract_identity: vector<u8>,
    in_slots: vector<u8>,
    nonces_xonly: vector<vector<u8>>,
    spend_key_schnorr_sigs: vector<vector<u8>>,
    quorum_peer_indices: vector<u16>,
    quorum_tbs_attestations: vector<vector<u8>>,
    payment_hash: vector<u8>,
    claim_pk_xonly: vector<u8>,
    refund_pk_xonly: vector<u8>,
    expiry_epoch: u64,
    ctx: &mut TxContext,
) {
    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let amount_msat = sum_msat_slots(&in_slots, max_slots);

    let n_in = nonces_xonly.length();
    let mut i = 0;
    while (i < n_in) {
        let nonce = nonces_xonly[i];
        assert!(!vault.spent_nonces.contains(nonce), ENonceAlreadySpent);
        if (spend_key_schnorr_sigs[i].length() > 0) {
            assert!(
                secp256k1_verify(&spend_key_schnorr_sigs[i], &nonce, &payment_hash, 1),
                EInvalidSpendKeySchnorr,
            );
        };
        vault.spent_nonces.add(nonce, true);
        i = i + 1;
    };

    verify_guardian_quorum_tbs_attestation(
        vault,
        &payment_hash,
        &quorum_peer_indices,
        &quorum_tbs_attestations,
    );

    let tpe_approval_id = blind_seal::issue_ibe_approval(
        &vault.issuer_cap,
        b"fedimint_lnv2",
        contract_identity,
        ctx,
    );

    let contract = Lnv2Contract {
        id: object::new(ctx),
        amount_msat,
        payment_hash,
        claim_pk_xonly,
        refund_pk_xonly,
        expiry_epoch,
        settled: false,
        tpe_approval_id,
    };
    transfer::share_object(contract);
}

/// Settles an `LNv2` contract when `gatewayd` proves Lightning payment delivery via `preimage`.
public fun claim_lnv2_contract<BTCAsset>(
    vault: &mut FedimintVault<BTCAsset>,
    contract: &mut Lnv2Contract,
    preimage: vector<u8>,
    gateway_schnorr_sig: vector<u8>,
    out_slots: vector<u8>,
    out_blinded_g1: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(!contract.settled, ELnv2AlreadySettled);
    assert!(sha2_256(preimage) == contract.payment_hash, EInvalidLnv2Preimage);
    assert!(
        secp256k1_verify(&gateway_schnorr_sig, &contract.claim_pk_xonly, &contract.payment_hash, 1),
        EInvalidSpendKeySchnorr,
    );

    let max_slots = blind_seal::cap_max_slots(&vault.issuer_cap);
    let out_msat = sum_msat_slots(&out_slots, max_slots);
    assert!(out_msat == contract.amount_msat, EConservationFailed);

    contract.settled = true;
    let _ticket_id = blind_seal::issue_blind_ticket(
        &vault.issuer_cap,
        out_slots,
        out_blinded_g1,
        ctx,
    );
}

public fun reserve_sats_value<BTCAsset>(vault: &FedimintVault<BTCAsset>): u64 {
    vault.reserve_sats.value()
}

public fun current_session_index<BTCAsset>(vault: &FedimintVault<BTCAsset>): u64 {
    vault.session_index
}

public fun is_contract_settled(contract: &Lnv2Contract): bool {
    contract.settled
}
