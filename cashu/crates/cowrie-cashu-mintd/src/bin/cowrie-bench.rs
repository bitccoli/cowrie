use std::{collections::BTreeMap, time::Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blind_seal_crypto::{
    dkg::DkgParticipant,
    dst::DstProfile,
    tbs::{
        blind_message, combine_blind_shares, sign_blinded_message, unblind_signature,
        verify_batch_notes, verify_blind_share, verify_unblinded,
    },
};
use cowrie_cashu_mintd::nuts::{derive_nut02_keyset_id, CashuProof, CashuTokenV4};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

#[derive(Serialize)]
struct LegacyV4Dleq {
    #[serde(with = "serde_bytes")]
    e: Vec<u8>,
    #[serde(with = "serde_bytes")]
    s: Vec<u8>,
}

#[derive(Serialize)]
struct LegacyV4Proof {
    a: u64,
    s: String,
    #[serde(with = "serde_bytes")]
    c: Vec<u8>,
    d: LegacyV4Dleq,
}

#[derive(Serialize)]
struct LegacyV4Group {
    #[serde(with = "serde_bytes")]
    i: Vec<u8>,
    p: Vec<LegacyV4Proof>,
}

#[derive(Serialize)]
struct LegacyV4Token {
    m: String,
    u: String,
    t: Vec<LegacyV4Group>,
}

fn encode_legacy_bdhke_dleq_v4(mint_url: &str, ks_id_hex: &str, count: usize) -> String {
    let ks_bytes = hex::decode(ks_id_hex).unwrap();
    let proofs: Vec<LegacyV4Proof> = (0..count)
        .map(|idx| LegacyV4Proof {
            a: 1,
            s: format!("{idx:064x}"),
            c: vec![0x02; 33],
            d: LegacyV4Dleq {
                e: vec![0xAA; 32],
                s: vec![0xBB; 32],
            },
        })
        .collect();
    let tok = LegacyV4Token {
        m: mint_url.into(),
        u: "sat".into(),
        t: vec![LegacyV4Group {
            i: ks_bytes,
            p: proofs,
        }],
    };
    let cbor = serde_cbor::to_vec(&tok).unwrap();
    format!("cashuB{}", URL_SAFE_NO_PAD.encode(cbor))
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0x26u8; 32]);
    let dst = DstProfile::CashuBls;

    // 1. Measure 2-round 4-of-5 Batched Pedersen DKG (32 power-of-2 denomination slots)
    let t_dkg = Instant::now();
    let mut parts = Vec::new();
    let mut r1 = Vec::new();
    for p in 0..5u16 {
        let (part, bcast) = DkgParticipant::new(p, 4, 5, 32, &mut rng).unwrap();
        parts.push(part);
        r1.push(bcast);
    }
    let all_r2: Vec<Vec<_>> = parts.iter().map(|p| p.round2_packages()).collect();
    let mut ks_opt = None;
    let mut shares = Vec::new();
    for p in 0..5u16 {
        let inbox: Vec<_> = all_r2.iter().map(|s| s[usize::from(p)].clone()).collect();
        let (ks, sk) = parts[usize::from(p)]
            .finalize("tmp", "sat", &r1, &inbox)
            .unwrap();
        ks_opt = Some(ks);
        shares.push(sk);
    }
    let dkg_ms = t_dkg.elapsed().as_secs_f64() * 1000.0;
    let mut ks = ks_opt.unwrap();
    ks.keyset_id = derive_nut02_keyset_id(0x02, &ks.slot_agg_pks);

    // 2. Measure client blinding, 4-of-5 signing + share pairing check + Lagrange + unblind
    let iters = 50usize;
    let t_blind = Instant::now();
    let mut blinded_vec = Vec::with_capacity(iters);
    for idx in 0..iters {
        let sec = format!("{idx:064x}");
        let (bm, r) = blind_message(sec.as_bytes(), &dst, &mut rng).unwrap();
        blinded_vec.push((sec, bm, r));
    }
    let blind_us = t_blind.elapsed().as_secs_f64() * 1e6 / (iters as f64);

    let t_sign = Instant::now();
    let mut unblinded_vec = Vec::with_capacity(iters);
    for (sec, bm, r) in &blinded_vec {
        let mut sh = Vec::with_capacity(4);
        for peer in 0..4usize {
            let s = sign_blinded_message(
                peer as u16,
                &shares[peer].slot_scalar(0).unwrap(),
                bm,
            )
            .unwrap();
            verify_blind_share(bm, &s, ks.peer_slot_pk(peer as u16, 0).unwrap()).unwrap();
            sh.push(s);
        }
        let bsig = combine_blind_shares(&sh, 4).unwrap();
        let sig = unblind_signature(&bsig, r).unwrap();
        unblinded_vec.push((sec.clone(), sig));
    }
    let sign_4of5_ms = t_sign.elapsed().as_secs_f64() * 1000.0 / (iters as f64);

    // 3. Single-note offline NUT-24 X-Cashu pairing verification
    let t_single = Instant::now();
    for (sec, sig) in &unblinded_vec {
        verify_unblinded(sec.as_bytes(), sig, ks.slot_pk(0).unwrap(), &dst).unwrap();
    }
    let single_verify_us = t_single.elapsed().as_secs_f64() * 1e6 / (iters as f64);

    // Mint 256 notes for batch & size benchmarks
    let mut pool = Vec::with_capacity(256);
    for idx in 0..256usize {
        let sec = format!("{idx:064x}");
        let (bm, r) = blind_message(sec.as_bytes(), &dst, &mut rng).unwrap();
        let sh: Vec<_> = (0..4usize)
            .map(|p| sign_blinded_message(p as u16, &shares[p].slot_scalar(0).unwrap(), &bm).unwrap())
            .collect();
        let sig = unblind_signature(&combine_blind_shares(&sh, 4).unwrap(), &r).unwrap();
        pool.push((sec, sig));
    }

    let mut slot_pks = BTreeMap::new();
    for (idx, pk) in ks.slot_agg_pks.iter().enumerate() {
        slot_pks.insert(idx as u8, pk.clone());
    }

    println!("=== Cowrie BLS12-381 Microbenchmarks (Release Profile) ===\n");
    println!(
        "- 2-Round 4-of-5 Pedersen DKG (32 slots): {:.2} ms",
        dkg_ms
    );
    println!("- Client Hash-to-G1 + Blinding (B_):      {:.1} µs", blind_us);
    println!(
        "- 4-of-5 Sign + Share Pairing + Unblind:  {:.2} ms",
        sign_4of5_ms
    );
    println!(
        "- Offline Single-Note Pairing Verify:     {:.1} µs\n",
        single_verify_us
    );

    println!("| Batch Size (Notes) | Cowrie `cashuB` V4 Bytes (0B DLEQ) | `secp256k1` + `NUT-12` DLEQ `cashuB` Bytes | Size Savings | Naive Verify (`2N` Pairings) | Fiat-Shamir Batch Verify (`2` Pairings) | Speedup |");
    println!("|---:|---:|---:|---:|---:|---:|---:|");

    for &n in &[1usize, 16, 64, 256] {
        let proofs: Vec<CashuProof> = pool[..n]
            .iter()
            .map(|(sec, sig)| CashuProof {
                amount: 1,
                id: ks.keyset_id.clone(),
                secret: sec.clone(),
                c_hex: hex::encode(sig.as_bytes()),
                witness: None,
            })
            .collect();
        let cowrie_v4 = CashuTokenV4::from_proofs("https://cowrie.cash", "sat", &proofs, None)
            .unwrap()
            .encode()
            .unwrap();
        let legacy_v4 = encode_legacy_bdhke_dleq_v4("https://cowrie.cash", &ks.keyset_id, n);
        let savings_pct = (1.0 - (cowrie_v4.len() as f64 / legacy_v4.len() as f64)) * 100.0;

        let t_naive = Instant::now();
        for (sec, sig) in &pool[..n] {
            verify_unblinded(sec.as_bytes(), sig, ks.slot_pk(0).unwrap(), &dst).unwrap();
        }
        let naive_ms = t_naive.elapsed().as_secs_f64() * 1000.0;

        let refs: Vec<_> = pool[..n]
            .iter()
            .map(|(sec, sig)| (0u8, sec.as_bytes(), sig))
            .collect();
        let t_batch = Instant::now();
        verify_batch_notes(&refs, &slot_pks, &dst).unwrap();
        let batch_ms = t_batch.elapsed().as_secs_f64() * 1000.0;
        let speedup = naive_ms / batch_ms.max(0.001);

        println!(
            "| {n} | {} B | {} B | **{:.1}%** | {:.2} ms | **{:.2} ms** | **{:.1}x** |",
            cowrie_v4.len(),
            legacy_v4.len(),
            savings_pct,
            naive_ms,
            batch_ms,
            speedup
        );
    }
}
