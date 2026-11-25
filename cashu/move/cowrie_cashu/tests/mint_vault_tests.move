#[test_only]
module cowrie_cashu::mint_vault_tests;

use blind_seal::blind_seal::{Self, KeysetInfo};
use cowrie_cashu::mint_vault::{Self, MintVault};
use sui::bls12381::{g1_add, g1_from_bytes, g1_generator, g1_sub, hash_to_g1};
use sui::clock;
use sui::coin::{Self, Coin};
use sui::group_ops;
use sui::test_scenario::{Self, Scenario};

public struct TestUSDC has drop {}

fun setup_vault(scenario: &mut Scenario, hourly_cap_notes: u64) {
    let pks = vector[
        x"b30a64d106f9fe307ee8638dce9af88b921a6afd24b417e4cc7f9bcf2536c841e1e781b006290043724611f8843564b704d67049b74c9bc8c6d5b68c632d517d34bcd6b547eb13eaaa4b459ee1499898049ed1f85d970340d0388735a629c639",
        x"8b65d18341ee4a4a65447eb75058146adfeac2873614f58b0f9568bd2d047178a3fe9658c59290838247b141198410390c7f6c87d203830ecb5967f5f4320d9aed262c4bd9405fadf7da3111ae89972d02ab7d44eadf8b69e673f58f15c5c8f5",
        x"8be3ed648ea0b4bcdae127e7d84c5bcfbad430f6cb329dcc1f7488721b7ea1342a30c68f710be989977b8c25ff29a5dd05a7e377ef80adda0f9a04b54e4a993da5bc963c35e4da02005f56b4544a9a5ba0d8ba41ff95cca39b88ae1f9929623f",
        x"951c246720d66a6a8939937503f899219ef90add7ad6ec0204c0e6a22bb1a8decf208994843df7dc45a6a47b55ea13d2091d4d43ebef1f06705f57b3e45d714b2aa7efb684368b6aeb11304a4acc0162b0e10426a43d6d8c6776b94759231717",
    ];
    let ibe_mpk = x"ab72a9dfddcb49c812a42b720b10d2728a4ce396f0c52545501340101df5eec4ba856575a3dfcbf3b13b3143a34aa40f";
    let cap = blind_seal::register_keyset(
        b"02cowriesui00001",
        b"usd",
        4,
        5,
        pks,
        ibe_mpk,
        scenario.ctx(),
    );
    mint_vault::create_vault<TestUSDC>(
        cap,
        b"02cowriesui00001",
        1,
        hourly_cap_notes,
        scenario.ctx(),
    );
}

#[test]
fun test_e2e_mint_multi_slot_batch_swap_p2pk_and_melt() {
    let alice = @0xA11CE;
    let bob = @0xB0B;
    let mut scenario = test_scenario::begin(alice);
    setup_vault(&mut scenario, 100);

    // 1. Deposit 21 TestUSDC (`13 + 8` across two deposits) to back notes
    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let coin_13 = coin::mint_for_testing<TestUSDC>(13, scenario.ctx());
    mint_vault::mint_from_sui(
        &mut vault,
        coin_13,
        vector[0, 2, 3],
        vector[
            x"90b06afb7208adca7ee43e3fd6cb9d92821a7fa194a4e91407ffad49d6bd337a23b913412f5ae1332cf2a8e26fa6f6a0",
            x"ac6efa01e1e9e601c4af480b3e48853ec2c2e31df1ea918ca2fac0e8a1ed90e03536af76bda7a187cf21a3cf4ccfb36a",
            x"89276f1c25b1498a956ee03bf8712d07466775e8430ed4a22df9cc6324a039398e0d43faf1f54a304addea0e988ebf8f",
        ],
        scenario.ctx(),
    );
    let coin_8 = coin::mint_for_testing<TestUSDC>(8, scenario.ctx());
    mint_vault::mint_from_sui(
        &mut vault,
        coin_8,
        vector[3],
        vector[
            x"819385c2b3c79adcd196853df97d8ad122674730f57b54b984530fd853b08b28c1a8cc6ee68d69bbc5c6e759cf9aead1",
        ],
        scenario.ctx(),
    );
    assert!(mint_vault::vault_reserve_value(&vault) == 21, 0);
    test_scenario::return_shared(vault);

    // 2. Multi-slot BLS12-381 batch swap (`1 + 4 + 8 = 13` -> `4 + 8 = 12` + `1` fee) + secp256k1 P2PK lock!
    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let ks_info = scenario.take_immutable<KeysetInfo>();
    mint_vault::swap_native_dst(
        &mut vault,
        &ks_info,
        vector[0, 2, 3],
        vector[b"move_note_s0_a", b"move_note_s2_b", b"move_note_s3_c"],
        vector[
            x"85115df8b67679b8f474911178e4d981b0d539d76eeb25396ede95b7f864232c1115d63e92e6823a8a640660c164756f",
            x"95745df708dd9f907877d435de2fb9d30e20a359477dda1133406b2f2b447e4de2e9e16fde40e79f1b6b20e4f55e8a02",
            x"93d7d9e261a7e4228740fd2ba8f7fea8b40d794af5212f73709b81bce35e336a7962a81d8853bde04ac2f1af9dbaef83",
        ],
        vector[x"023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1"],
        vector[
            x"fcfe35118636d8d6f6da16c635ebb9c266507214f8a870696e23f13e93f2a4d532f8aa6900f4ff77c251581bee89cfc961ce4706d32616517cf358f3026e4b32",
        ],
        vector[2, 3],
        vector[
            x"ad7d0fb6ec63fbff4f9a458fbbc10738968e7d7d332cfa67d910db2bd549e9b855d80ac5f324a5023f5f7eebc1e49968",
            x"819385c2b3c79adcd196853df97d8ad122674730f57b54b984530fd853b08b28c1a8cc6ee68d69bbc5c6e759cf9aead1",
        ],
        1,
        b"swap_ctx_01",
        scenario.ctx(),
    );

    // Verify 48-byte Y = H_G1(secret) nullifier was recorded in `spent_ys`
    let y0 = *group_ops::bytes(&hash_to_g1(&b"move_note_s0_a"));
    assert!(mint_vault::is_y_spent(&vault, y0), 1);

    // 3. Melt 8 notes (`slot 3`) back into native `Coin<TestUSDC>` for Bob!
    let mut clk = clock::create_for_testing(scenario.ctx());
    clk.set_for_testing(10_000);
    mint_vault::melt_native_dst(
        &mut vault,
        &ks_info,
        &clk,
        vector[3],
        vector[b"move_melt_s3"],
        vector[
            x"ab38b7daa23d63c3f56215fb303981404d3f349bb07763fd06f48e345e6b86a31514f34b5ec31d808a129d122c21121a",
        ],
        vector[],
        vector[],
        bob,
        b"melt_ctx_01",
        scenario.ctx(),
    );
    assert!(mint_vault::vault_reserve_value(&vault) == 13, 2);
    assert!(mint_vault::melted_in_window_notes(&vault) == 8, 3);
    clk.destroy_for_testing();
    test_scenario::return_immutable(ks_info);
    test_scenario::return_shared(vault);

    // Confirm Bob received `8 TestUSDC`!
    scenario.next_tx(bob);
    let payout = scenario.take_from_sender<Coin<TestUSDC>>();
    assert!(payout.value() == 8, 4);
    scenario.return_to_sender(payout);

    scenario.end();
}

#[test]
#[expected_failure(abort_code = 101, location = cowrie_cashu::mint_vault)]
fun test_double_spend_48_byte_y_nullifier_aborts() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    setup_vault(&mut scenario, 100);

    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let ks_info = scenario.take_immutable<KeysetInfo>();
    // First spend of `move_note_s0_a` succeeds
    mint_vault::swap_native_dst(
        &mut vault,
        &ks_info,
        vector[0],
        vector[b"move_note_s0_a"],
        vector[
            x"85115df8b67679b8f474911178e4d981b0d539d76eeb25396ede95b7f864232c1115d63e92e6823a8a640660c164756f",
        ],
        vector[],
        vector[],
        vector[0],
        vector[
            x"ad7d0fb6ec63fbff4f9a458fbbc10738968e7d7d332cfa67d910db2bd549e9b855d80ac5f324a5023f5f7eebc1e49968",
        ],
        0,
        b"ctx_1",
        scenario.ctx(),
    );
    // Second spend of the exact same `move_note_s0_a` MUST abort with `ENullifierAlreadySpent`!
    mint_vault::swap_native_dst(
        &mut vault,
        &ks_info,
        vector[0],
        vector[b"move_note_s0_a"],
        vector[
            x"85115df8b67679b8f474911178e4d981b0d539d76eeb25396ede95b7f864232c1115d63e92e6823a8a640660c164756f",
        ],
        vector[],
        vector[],
        vector[0],
        vector[
            x"819385c2b3c79adcd196853df97d8ad122674730f57b54b984530fd853b08b28c1a8cc6ee68d69bbc5c6e759cf9aead1",
        ],
        0,
        b"ctx_2",
        scenario.ctx(),
    );
    test_scenario::return_immutable(ks_info);
    test_scenario::return_shared(vault);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = 102, location = cowrie_cashu::mint_vault)]
fun test_slot_inflation_attack_aborts_multi_pairing() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    setup_vault(&mut scenario, 100);

    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let ks_info = scenario.take_immutable<KeysetInfo>();
    // Trap 2 exploit attempt: presenting a valid slot-0 ($1) signature while claiming slot-3 ($8)!
    mint_vault::swap_native_dst(
        &mut vault,
        &ks_info,
        vector[3],
        vector[b"move_note_s0_a"],
        vector[
            x"85115df8b67679b8f474911178e4d981b0d539d76eeb25396ede95b7f864232c1115d63e92e6823a8a640660c164756f",
        ],
        vector[],
        vector[],
        vector[3],
        vector[
            x"ad7d0fb6ec63fbff4f9a458fbbc10738968e7d7d332cfa67d910db2bd549e9b855d80ac5f324a5023f5f7eebc1e49968",
        ],
        0,
        b"ctx_forged",
        scenario.ctx(),
    );
    test_scenario::return_immutable(ks_info);
    test_scenario::return_shared(vault);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = 104, location = cowrie_cashu::mint_vault)]
fun test_hourly_melt_circuit_breaker_trips() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    // Hourly melt cap = 5 notes, while user attempts to melt an 8-note (`slot 3`) proof!
    setup_vault(&mut scenario, 5);

    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let ks_info = scenario.take_immutable<KeysetInfo>();
    let c8 = coin::mint_for_testing<TestUSDC>(8, scenario.ctx());
    mint_vault::mint_from_sui(
        &mut vault,
        c8,
        vector[3],
        vector[
            x"819385c2b3c79adcd196853df97d8ad122674730f57b54b984530fd853b08b28c1a8cc6ee68d69bbc5c6e759cf9aead1",
        ],
        scenario.ctx(),
    );

    let clk = clock::create_for_testing(scenario.ctx());
    mint_vault::melt_native_dst(
        &mut vault,
        &ks_info,
        &clk,
        vector[3],
        vector[b"move_melt_s3"],
        vector[
            x"ab38b7daa23d63c3f56215fb303981404d3f349bb07763fd06f48e345e6b86a31514f34b5ec31d808a129d122c21121a",
        ],
        vector[],
        vector[],
        alice,
        b"melt_breaker",
        scenario.ctx(),
    );
    clk.destroy_for_testing();
    test_scenario::return_immutable(ks_info);
    test_scenario::return_shared(vault);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = 102, location = cowrie_cashu::mint_vault)]
fun test_rogue_cancellation_batch_forgery_aborts() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    setup_vault(&mut scenario, 100);

    scenario.next_tx(alice);
    let mut vault = scenario.take_shared<MintVault<TestUSDC>>();
    let ks_info = scenario.take_immutable<KeysetInfo>();

    // Perturb two valid signatures by `+G1` and `-G1` so their unweighted sum `C0' + C2' == C0 + C2`
    // is unchanged, while BOTH individual signatures are invalid!
    // Fiat-Shamir 120-bit batch weights in `mint_vault::verify_and_nullify_native_bls` MUST catch this!
    let c0 = g1_from_bytes(
        &x"85115df8b67679b8f474911178e4d981b0d539d76eeb25396ede95b7f864232c1115d63e92e6823a8a640660c164756f",
    );
    let c2 = g1_from_bytes(
        &x"95745df708dd9f907877d435de2fb9d30e20a359477dda1133406b2f2b447e4de2e9e16fde40e79f1b6b20e4f55e8a02",
    );
    let delta = g1_generator();
    let c0_rogue = *group_ops::bytes(&g1_add(&c0, &delta));
    let c2_rogue = *group_ops::bytes(&g1_sub(&c2, &delta));

    mint_vault::swap_native_dst(
        &mut vault,
        &ks_info,
        vector[0, 2],
        vector[b"move_note_s0_a", b"move_note_s2_b"],
        vector[c0_rogue, c2_rogue],
        vector[],
        vector[],
        vector[0, 2],
        vector[
            x"90b06afb7208adca7ee43e3fd6cb9d92821a7fa194a4e91407ffad49d6bd337a23b913412f5ae1332cf2a8e26fa6f6a0",
            x"ad7d0fb6ec63fbff4f9a458fbbc10738968e7d7d332cfa67d910db2bd549e9b855d80ac5f324a5023f5f7eebc1e49968",
        ],
        0,
        b"rogue_batch_ctx",
        scenario.ctx(),
    );

    test_scenario::return_immutable(ks_info);
    test_scenario::return_shared(vault);
    scenario.end();
}
