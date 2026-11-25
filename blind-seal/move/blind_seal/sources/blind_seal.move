/// Phase 1 Core Sui Move Package: `blind_seal`
/// Extends Mysten Labs' Seal `seal_approve*` dry-run pattern to threshold blind BLS12-381 signing
/// while preserving standard Boneh-Franklin IBE approvals for Walrus & Fedimint LNv2 TPE.
module blind_seal::blind_seal;

use sui::bls12381::{Self, G1, G2, g1_from_bytes, g1_identity, g2_from_bytes};
use sui::group_ops::Element;

const EInvalidSlotCount: u64 = 1;
const EIdentityPointRejected: u64 = 2;
const EKeysetMismatch: u64 = 3;
const ELengthMismatch: u64 = 4;
const EInvalidSlotIndex: u64 = 5;
const EIdentityMismatch: u64 = 6;

/// On-chain public keyset metadata for a dedicated $t$-of-$n$ Blind-Seal committee.
/// Each slot `s` holds an algebraically independent `G2` public key (`amount = 2^s`).
public struct KeysetInfo has key, store {
    id: UID,
    keyset_id: vector<u8>,
    unit: vector<u8>,
    threshold: u16,
    num_peers: u16,
    agg_pks_g2: vector<Element<G2>>,
    ibe_mpk_g1: Element<G1>,
}

/// Capability binding a specific Move vault/credential module to issue tickets under `keyset_id`.
public struct IssuerCap has key, store {
    id: UID,
    keyset_id: vector<u8>,
    max_slots: u8,
}

/// Finalized, immutable blind-signing authorization committed on-chain.
/// Storing `slots` and `blinded_messages` inside a finalized Sui object completely prevents
/// Trap 3 (`sui_dryRunTransactionBlock` replay / infinite-mint inflation).
public struct BlindSigningTicket has key, store {
    id: UID,
    keyset_id: vector<u8>,
    slots: vector<u8>,
    blinded_messages: vector<Element<G1>>,
}

/// Finalized on-chain approval for standard Seal IBE / Walrus read passes / Fedimint LNv2 TPE.
public struct IbeDecryptionApproval has key, store {
    id: UID,
    keyset_id: vector<u8>,
    namespace: vector<u8>,
    identity: vector<u8>,
}

/// Registers a new multi-slot BLS12-381 keyset and returns the exclusive `IssuerCap`.
public fun register_keyset(
    keyset_id: vector<u8>,
    unit: vector<u8>,
    threshold: u16,
    num_peers: u16,
    raw_agg_pks_g2: vector<vector<u8>>,
    raw_ibe_mpk_g1: vector<u8>,
    ctx: &mut TxContext,
): IssuerCap {
    let n_slots = raw_agg_pks_g2.length();
    assert!(n_slots > 0 && n_slots <= 63, EInvalidSlotCount);

    let mut agg_pks_g2 = vector[];
    let mut i = 0;
    while (i < n_slots) {
        let pk = g2_from_bytes(&raw_agg_pks_g2[i]);
        agg_pks_g2.push_back(pk);
        i = i + 1;
    };

    let ibe_mpk_g1 = g1_from_bytes(&raw_ibe_mpk_g1);
    assert!(&ibe_mpk_g1 != &g1_identity(), EIdentityPointRejected);

    let info = KeysetInfo {
        id: object::new(ctx),
        keyset_id,
        unit,
        threshold,
        num_peers,
        agg_pks_g2,
        ibe_mpk_g1,
    };
    transfer::freeze_object(info);

    IssuerCap {
        id: object::new(ctx),
        keyset_id,
        max_slots: (n_slots as u8),
    }
}

/// Validates canonical prime-order `G1` subgroup points and freezes an immutable `BlindSigningTicket`.
public fun issue_blind_ticket(
    cap: &IssuerCap,
    slots: vector<u8>,
    raw_blinded_g1: vector<vector<u8>>,
    ctx: &mut TxContext,
): ID {
    let len = slots.length();
    assert!(len > 0 && len == raw_blinded_g1.length(), ELengthMismatch);

    let id_pt = g1_identity();
    let mut blinded_messages = vector[];
    let mut i = 0;
    while (i < len) {
        let s = slots[i];
        assert!(s < cap.max_slots, EInvalidSlotIndex);
        let pt = g1_from_bytes(&raw_blinded_g1[i]);
        assert!(&pt != &id_pt, EIdentityPointRejected);
        blinded_messages.push_back(pt);
        i = i + 1;
    };

    let ticket = BlindSigningTicket {
        id: object::new(ctx),
        keyset_id: cap.keyset_id,
        slots,
        blinded_messages,
    };
    let ticket_id = object::id(&ticket);
    transfer::freeze_object(ticket);
    ticket_id
}

public fun issue_ibe_approval(
    cap: &IssuerCap,
    namespace: vector<u8>,
    identity: vector<u8>,
    ctx: &mut TxContext,
): ID {
    let approval = IbeDecryptionApproval {
        id: object::new(ctx),
        keyset_id: cap.keyset_id,
        namespace,
        identity,
    };
    let app_id = object::id(&approval);
    transfer::freeze_object(approval);
    app_id
}

/// Evaluated off-chain by Blind-Seal Key Servers via `sui_dryRunTransactionBlock`.
entry fun seal_approve_blind_sign(
    ticket: &BlindSigningTicket,
    expected_keyset_id: vector<u8>,
) {
    assert!(ticket.keyset_id == expected_keyset_id, EKeysetMismatch);
}

/// Evaluated off-chain by Seal Key Servers via `sui_dryRunTransactionBlock` for Walrus / LNv2 TPE.
entry fun seal_approve_ibe(
    id: vector<u8>,
    approval: &IbeDecryptionApproval,
    expected_keyset_id: vector<u8>,
) {
    assert!(approval.keyset_id == expected_keyset_id, EKeysetMismatch);
    assert!(approval.identity == id, EIdentityMismatch);
}

public fun keyset_slot_pk(info: &KeysetInfo, slot: u8): &Element<G2> {
    &info.agg_pks_g2[(slot as u64)]
}

public fun keyset_id(info: &KeysetInfo): &vector<u8> {
    &info.keyset_id
}

public fun cap_max_slots(cap: &IssuerCap): u8 {
    cap.max_slots
}

#[test_only]
use sui::bls12381::g1_generator;
#[test_only]
use sui::group_ops;
#[test_only]
use sui::test_scenario;

#[test]
fun test_register_keyset_issue_ticket_and_seal_approve() {
    let admin = @0xA11CE;
    let mut scenario = test_scenario::begin(admin);

    let pks = vector[
        x"b30a64d106f9fe307ee8638dce9af88b921a6afd24b417e4cc7f9bcf2536c841e1e781b006290043724611f8843564b704d67049b74c9bc8c6d5b68c632d517d34bcd6b547eb13eaaa4b459ee1499898049ed1f85d970340d0388735a629c639",
        x"8b65d18341ee4a4a65447eb75058146adfeac2873614f58b0f9568bd2d047178a3fe9658c59290838247b141198410390c7f6c87d203830ecb5967f5f4320d9aed262c4bd9405fadf7da3111ae89972d02ab7d44eadf8b69e673f58f15c5c8f5",
        x"8be3ed648ea0b4bcdae127e7d84c5bcfbad430f6cb329dcc1f7488721b7ea1342a30c68f710be989977b8c25ff29a5dd05a7e377ef80adda0f9a04b54e4a993da5bc963c35e4da02005f56b4544a9a5ba0d8ba41ff95cca39b88ae1f9929623f",
        x"951c246720d66a6a8939937503f899219ef90add7ad6ec0204c0e6a22bb1a8decf208994843df7dc45a6a47b55ea13d2091d4d43ebef1f06705f57b3e45d714b2aa7efb684368b6aeb11304a4acc0162b0e10426a43d6d8c6776b94759231717",
    ];
    let ibe_mpk = x"ab72a9dfddcb49c812a42b720b10d2728a4ce396f0c52545501340101df5eec4ba856575a3dfcbf3b13b3143a34aa40f";

    let cap = register_keyset(
        b"02cowriesui00001",
        b"usd",
        4,
        5,
        pks,
        ibe_mpk,
        scenario.ctx(),
    );
    assert!(cap_max_slots(&cap) == 4, 0);

    let ticket_id = issue_blind_ticket(
        &cap,
        vector[0, 2, 3],
        vector[
            x"90b06afb7208adca7ee43e3fd6cb9d92821a7fa194a4e91407ffad49d6bd337a23b913412f5ae1332cf2a8e26fa6f6a0",
            x"ac6efa01e1e9e601c4af480b3e48853ec2c2e31df1ea918ca2fac0e8a1ed90e03536af76bda7a187cf21a3cf4ccfb36a",
            x"89276f1c25b1498a956ee03bf8712d07466775e8430ed4a22df9cc6324a039398e0d43faf1f54a304addea0e988ebf8f",
        ],
        scenario.ctx(),
    );
    let app_id = issue_ibe_approval(
        &cap,
        b"fedimint_lnv2",
        b"contract_001",
        scenario.ctx(),
    );
    transfer::public_transfer(cap, admin);

    scenario.next_tx(admin);
    let ticket = scenario.take_immutable_by_id<BlindSigningTicket>(ticket_id);
    seal_approve_blind_sign(&ticket, b"02cowriesui00001");
    test_scenario::return_immutable(ticket);

    let approval = scenario.take_immutable_by_id<IbeDecryptionApproval>(app_id);
    seal_approve_ibe(b"contract_001", &approval, b"02cowriesui00001");
    test_scenario::return_immutable(approval);

    let info = scenario.take_immutable<KeysetInfo>();
    assert!(keyset_id(&info) == &b"02cowriesui00001", 0);
    test_scenario::return_immutable(info);

    scenario.end();
}

#[test]
#[expected_failure(abort_code = EIdentityPointRejected)]
fun test_reject_identity_blinded_g1_point() {
    let admin = @0xA11CE;
    let mut scenario = test_scenario::begin(admin);
    let g1_bytes = *group_ops::bytes(&g1_generator());
    let id_g1_bytes = *group_ops::bytes(&g1_identity());

    let cap = register_keyset(
        b"02cowriesui00001",
        b"usd",
        2,
        3,
        vector[
            x"b30a64d106f9fe307ee8638dce9af88b921a6afd24b417e4cc7f9bcf2536c841e1e781b006290043724611f8843564b704d67049b74c9bc8c6d5b68c632d517d34bcd6b547eb13eaaa4b459ee1499898049ed1f85d970340d0388735a629c639",
        ],
        g1_bytes,
        scenario.ctx(),
    );
    // Attempting to issue a BlindSigningTicket with G1 identity must abort!
    let _tid = issue_blind_ticket(&cap, vector[0], vector[id_g1_bytes], scenario.ctx());
    transfer::public_transfer(cap, admin);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EIdentityMismatch)]
fun test_seal_approve_ibe_identity_mismatch_aborts() {
    let admin = @0xA11CE;
    let mut scenario = test_scenario::begin(admin);
    let g1_bytes = *group_ops::bytes(&g1_generator());

    let cap = register_keyset(
        b"02cowriesui00001",
        b"usd",
        2,
        3,
        vector[
            x"b30a64d106f9fe307ee8638dce9af88b921a6afd24b417e4cc7f9bcf2536c841e1e781b006290043724611f8843564b704d67049b74c9bc8c6d5b68c632d517d34bcd6b547eb13eaaa4b459ee1499898049ed1f85d970340d0388735a629c639",
        ],
        g1_bytes,
        scenario.ctx(),
    );
    let app_id = issue_ibe_approval(&cap, b"walrus", b"doc_alpha", scenario.ctx());
    transfer::public_transfer(cap, admin);

    scenario.next_tx(admin);
    let approval = scenario.take_immutable_by_id<IbeDecryptionApproval>(app_id);
    // Requesting decryption share for `doc_beta` with an approval for `doc_alpha` must abort!
    seal_approve_ibe(b"doc_beta", &approval, b"02cowriesui00001");
    test_scenario::return_immutable(approval);
    scenario.end();
}
