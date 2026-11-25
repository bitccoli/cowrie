#[test_only]
module cowrie_fedimint::federation_vault_tests;

use blind_seal::blind_seal;
use cowrie_fedimint::federation_vault::{Self, FedimintVault, Lnv2Contract};
use sui::coin;
use sui::test_scenario::{Self, Scenario};

public struct TestLBTC has drop {}

fun setup_fedimint_vault(scenario: &mut Scenario) {
    // 16 msat slots (2^0 .. 2^15 msat) so 1 sat = 1,000 msat = 512 + 256 + 128 + 64 + 32 + 8 (`[3,5,6,7,8,9]`)
    let mut pks = vector[];
    let mut i = 0u64;
    while (i < 16) {
        pks.push_back(
            x"b30a64d106f9fe307ee8638dce9af88b921a6afd24b417e4cc7f9bcf2536c841e1e781b006290043724611f8843564b704d67049b74c9bc8c6d5b68c632d517d34bcd6b547eb13eaaa4b459ee1499898049ed1f85d970340d0388735a629c639",
        );
        i = i + 1;
    };
    let ibe_mpk = x"ab72a9dfddcb49c812a42b720b10d2728a4ce396f0c52545501340101df5eec4ba856575a3dfcbf3b13b3143a34aa40f";
    let cap = blind_seal::register_keyset(
        b"fedimint_msat_01",
        b"msat",
        3,
        4,
        pks,
        ibe_mpk,
        scenario.ctx(),
    );

    let guardian_ed_pks = vector[
        x"3ef08959033028c8fc6fc6d491a12548e78df6aefb2d7c2c190c3f78cef3f50b",
        x"c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
        x"2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7",
        x"f80cccdce4ae1c07ae208a2adf99a310ae4207e0306fa0236110b06827bbb8d0",
    ];
    // Close session after every 1 transaction so `session_index` increments deterministically!
    federation_vault::create_federation_vault<TestLBTC>(
        cap,
        b"fedimint_msat_01",
        3,
        guardian_ed_pks,
        1,
        scenario.ctx(),
    );
}

#[test]
fun test_deposit_process_fedimint_tx_session_close_and_lnv2_claim() {
    let operator = @0xFED1;
    let mut scenario = test_scenario::begin(operator);
    setup_fedimint_vault(&mut scenario);

    let bm = x"90b06afb7208adca7ee43e3fd6cb9d92821a7fa194a4e91407ffad49d6bd337a23b913412f5ae1332cf2a8e26fa6f6a0";

    // 1. Deposit 1 sat (`1,000 msat` = 8 + 32 + 64 + 128 + 256 + 512)
    scenario.next_tx(operator);
    let mut vault = scenario.take_shared<FedimintVault<TestLBTC>>();
    let btc_1sat = coin::mint_for_testing<TestLBTC>(1, scenario.ctx());
    federation_vault::deposit_sui_for_oob(
        &mut vault,
        btc_1sat,
        vector[3, 5, 6, 7, 8, 9],
        vector[bm, bm, bm, bm, bm, bm],
        scenario.ctx(),
    );
    assert!(federation_vault::reserve_sats_value(&vault) == 1, 0);

    // 2. Process downstream Fedimint tx signed by `SpendKey` + 3-of-4 Guardians `{0, 2, 3}` (peer 1 offline!)
    let k256_pk = x"023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";
    federation_vault::process_fedimint_tx(
        &mut vault,
        b"fedimint_tx_digest_32bytes_00001",
        vector[9],
        vector[k256_pk],
        vector[
            x"0456d7e3fe9b62a1bf8ebf2b23781d5c95cc7f63602586968d55beeeaa9bae2a13cd395972968f3f26f5e03e747ec8ee3c33ee42b4e342321adfb090e6d5439f",
        ],
        vector[0, 2, 3],
        vector[
            x"1f84fdfb923fdae82b141b2f0861a330424deef55730a1df36db1a98a0d93e8727644f0289dc1287be27f20f7fc8305bf67c7a35e7ad1e8ee91b5e62bf731f09",
            x"0e953f13a303e32625876e63f5f31d38b0e06f59a5cbd3cda71ff40220380c9b3c173f47cd1b7cf5233c8db70975230d0ec9eb2c9ea0587bace40511e687930f",
            x"6dbf36598b70cdd6a78118c8bf3a4499044bb4dbe0ee3789df763dfa1b35589e0a9e3b7b5f5d61c824b5db829f01cec17a42a23a78aaa30cc85b7e2112a3b109",
        ],
        vector[8, 8],
        vector[bm, bm],
        0,
        scenario.ctx(),
    );
    assert!(federation_vault::current_session_index(&vault) == 1, 1);

    // Idempotent submission of the same `fedimint_txid` must be a safe no-op!
    federation_vault::process_fedimint_tx(
        &mut vault,
        b"fedimint_tx_digest_32bytes_00001",
        vector[9],
        vector[k256_pk],
        vector[],
        vector[0, 2, 3],
        vector[],
        vector[8, 8],
        vector[bm, bm],
        0,
        scenario.ctx(),
    );
    assert!(federation_vault::current_session_index(&vault) == 1, 2);

    // 3. Lock outgoing `LNv2` TPE contract & settle with 32-byte Lightning preimage!
    let pay_hash = x"c1eb3bed017e591a4e229b3d6a3a4483d908bf3d09b0b7ff717831ff27d3ccc2";
    federation_vault::lock_lnv2_outgoing(
        &mut vault,
        b"lnv2_contract_id_01",
        vector[8],
        vector[b"fresh_ln_nonce_01"],
        vector[vector[]],
        vector[0, 1, 3],
        vector[
            x"dce877971ac7f73587300c09bf266be7e439101d83a5e4f2bb9f10e7267ef7c71ef022bfb7979e53936983c712d776662ca88e5006c8e9c0c00cc8bc88e7af05",
            x"6ea69ae3251c794b27dc919d06dffa3b80bc43112e12c3fe20670c4534f8de1417d790df7be2279584804b304605200b58a551055b83942e9b6169c110bd1a04",
            x"150ee25162e2b7b97d6b0c012be07b4bf6fe8fbee1aa6a9524171c328bff1a7d0bbbc20fcc23ffb3ded19361b4bfa66ef5e9e4e6665a436f87237dcb1d20280e",
        ],
        pay_hash,
        k256_pk,
        k256_pk,
        500,
        scenario.ctx(),
    );
    test_scenario::return_shared(vault);

    // Gateway settles `Lnv2Contract` by revealing `b"lightning_preimage_32bytes_00001"`
    scenario.next_tx(operator);
    let mut vault = scenario.take_shared<FedimintVault<TestLBTC>>();
    let mut contract = scenario.take_shared<Lnv2Contract>();
    federation_vault::claim_lnv2_contract(
        &mut vault,
        &mut contract,
        b"lightning_preimage_32bytes_00001",
        x"b48acf015206a19a2b4987101527f7fa61e012cdf6e09b72cdd4c7426a5824ff4afaa9b298d2e1020abefd497a640f030ed40292caa89f804f4bb5e16905df04",
        vector[7, 7],
        vector[bm, bm],
        scenario.ctx(),
    );
    assert!(federation_vault::is_contract_settled(&contract), 3);
    test_scenario::return_shared(contract);
    test_scenario::return_shared(vault);

    scenario.end();
}

#[test]
#[expected_failure(abort_code = 203, location = cowrie_fedimint::federation_vault)]
fun test_duplicate_peer_quorum_spoofing_aborts() {
    let operator = @0xFED1;
    let mut scenario = test_scenario::begin(operator);
    setup_fedimint_vault(&mut scenario);

    let bm = x"90b06afb7208adca7ee43e3fd6cb9d92821a7fa194a4e91407ffad49d6bd337a23b913412f5ae1332cf2a8e26fa6f6a0";
    scenario.next_tx(operator);
    let mut vault = scenario.take_shared<FedimintVault<TestLBTC>>();
    let sig0 = x"1f84fdfb923fdae82b141b2f0861a330424deef55730a1df36db1a98a0d93e8727644f0289dc1287be27f20f7fc8305bf67c7a35e7ad1e8ee91b5e62bf731f09";
    // Passing peer 0 three times `[0, 0, 0]` to spoof a 3-of-4 quorum MUST abort!
    federation_vault::process_fedimint_tx(
        &mut vault,
        b"fedimint_tx_digest_32bytes_00001",
        vector[3],
        vector[b"nonce_a"],
        vector[vector[]],
        vector[0, 0, 0],
        vector[sig0, sig0, sig0],
        vector[3],
        vector[bm],
        0,
        scenario.ctx(),
    );
    test_scenario::return_shared(vault);
    scenario.end();
}
