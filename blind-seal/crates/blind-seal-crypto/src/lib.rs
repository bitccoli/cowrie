pub mod dkg;
pub mod dst;
pub mod elgamal;
pub mod ibe_tpe;
pub mod schnorr;
pub mod tbs;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid cryptographic encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error("degenerate curve point or scalar rejected: {0}")]
    DegeneratePoint(&'static str),
    #[error("invalid blind signature share from peer {peer_id}")]
    InvalidSignatureShare { peer_id: u16 },
    #[error("duplicate or invalid peer index {0} in share subset")]
    DuplicatePeerShare(u16),
    #[error("insufficient threshold shares: got {got}, need {need}")]
    InsufficientShares { got: usize, need: usize },
    #[error("unknown denomination slot {0}")]
    UnknownSlot(u8),
    #[error("invalid DKG configuration")]
    InvalidDkgConfig,
    #[error("invalid Feldman DKG share from peer {culprit_peer}")]
    InvalidDkgShare { culprit_peer: u16 },
    #[error("BLS12-381 signature verification failed")]
    VerificationFailed,
    #[error("BIP-340 secp256k1 Schnorr verification failed")]
    SchnorrVerificationFailed,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::dkg::{deal_multi_slot_keyset, DkgParticipant};
    use crate::dst::DstProfile;
    use crate::elgamal::{encrypt_g1_share, EphemeralElGamalSecretKey};
    use crate::ibe_tpe::{
        derive_ibe_decryption_share, ibe_combine_and_decrypt, ibe_encrypt,
        verify_ibe_decryption_share,
    };
    use crate::schnorr::{verify_bip340_schnorr, SpendKeypair};
    use crate::tbs::{
        blind_message, combine_blind_shares, sign_blinded_message, unblind_signature,
        verify_batch_notes, verify_blind_share, verify_unblinded, BlindSignatureShare,
    };

    #[test]
    fn test_threshold_blind_signing_and_trap2_denomination_isolation() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        // 4-of-5 federation with 8 denomination slots (1, 2, 4, ..., 128)
        let (pub_keyset, guardian_shares) =
            deal_multi_slot_keyset("ks_usd_01", "usd", 4, 5, 8, &mut rng).unwrap();

        let msg = b"secret_note_serial_0001";
        let dst = DstProfile::SuiNative;
        let (blinded, r) = blind_message(msg, &dst, &mut rng).unwrap();

        // Collect shares from peers {0, 2, 3, 4} for slot 0 (denomination = 1)
        let active_peers = [0usize, 2, 3, 4];
        let mut shares = Vec::new();
        for &p in &active_peers {
            let sk = guardian_shares[p].slot_scalar(0).unwrap();
            let share = sign_blinded_message(p as u16, &sk, &blinded).unwrap();
            verify_blind_share(&blinded, &share, pub_keyset.peer_slot_pk(p as u16, 0).unwrap())
                .unwrap();
            shares.push(share);
        }

        let blind_sig = combine_blind_shares(&shares, 4).unwrap();
        let unblinded = unblind_signature(&blind_sig, &r).unwrap();

        // Valid against slot 0 ($1)
        verify_unblinded(msg, &unblinded, pub_keyset.slot_pk(0).unwrap(), &dst).unwrap();

        // TRAP 2 EXPLOIT CHECK: Must strictly fail against slot 7 ($128) and wrong DST!
        assert!(verify_unblinded(msg, &unblinded, pub_keyset.slot_pk(7).unwrap(), &dst).is_err());
        assert!(verify_unblinded(
            msg,
            &unblinded,
            pub_keyset.slot_pk(0).unwrap(),
            &DstProfile::FedimintTbs
        )
        .is_err());
    }

    #[test]
    fn test_dealer_free_pedersen_dkg_and_batch_verification() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let threshold = 3u16;
        let num_peers = 4u16;
        let num_slots = 4usize;

        let mut participants = Vec::new();
        let mut round1_bcasts = Vec::new();
        for peer in 0..num_peers {
            let (p, bcast) =
                DkgParticipant::new(peer, threshold, num_peers, num_slots, &mut rng).unwrap();
            participants.push(p);
            round1_bcasts.push(bcast);
        }

        let all_round2: Vec<Vec<_>> = participants.iter().map(|p| p.round2_packages()).collect();

        let mut pub_keysets = Vec::new();
        let mut guardian_shares = Vec::new();
        for peer in 0..num_peers {
            let pkgs_for_peer: Vec<_> = all_round2
                .iter()
                .map(|sender_pkgs| sender_pkgs[usize::from(peer)].clone())
                .collect();
            let (pk_set, sk_share) = participants[usize::from(peer)]
                .finalize("ks_btc_fed", "msat", &round1_bcasts, &pkgs_for_peer)
                .unwrap();
            pub_keysets.push(pk_set);
            guardian_shares.push(sk_share);
        }

        // All 4 peers must derive the exact same PublicKeyset without a dealer
        for w in pub_keysets.windows(2) {
            assert_eq!(w[0], w[1]);
        }
        let ks = &pub_keysets[0];
        let dst = DstProfile::FedimintTbs;

        // Mint 3 notes across slots 0, 2, and 3 and verify via a single aggregated batch pairing!
        let mut minted = Vec::new();
        for (idx, slot) in [0u8, 2u8, 2u8, 3u8].into_iter().enumerate() {
            let msg = format!("fedimint_nonce_{idx}").into_bytes();
            let (blinded, r) = blind_message(&msg, &dst, &mut rng).unwrap();
            let shares: Vec<_> = (1..4usize)
                .map(|p| {
                    sign_blinded_message(
                        p as u16,
                        &guardian_shares[p].slot_scalar(slot).unwrap(),
                        &blinded,
                    )
                    .unwrap()
                })
                .collect();
            let bsig = combine_blind_shares(&shares, 3).unwrap();
            let sig = unblind_signature(&bsig, &r).unwrap();
            minted.push((slot, msg, sig));
        }

        let mut slot_pks = BTreeMap::new();
        for s in 0..num_slots as u8 {
            slot_pks.insert(s, ks.slot_pk(s).unwrap().clone());
        }
        let refs: Vec<_> = minted
            .iter()
            .map(|(s, m, sig)| (*s, m.as_slice(), sig))
            .collect();
        verify_batch_notes(&refs, &slot_pks, &dst).unwrap();

        // EXPLOIT CHECK: Rogue cancellation `(S_0 + Delta, S_1 - Delta)` MUST fail under Fiat-Shamir weights!
        let delta = DstProfile::SuiNative.hash_to_g1(b"rogue_delta_perturbation");
        let s0_bad = crate::tbs::UnblindedSignature(
            crate::tbs::BlindedMessage::from_g1(&(blstrs::G1Projective::from(minted[0].2.to_g1_affine().unwrap()) + delta))
                .unwrap()
                .0,
        );
        let s1_bad = crate::tbs::UnblindedSignature(
            crate::tbs::BlindedMessage::from_g1(&(blstrs::G1Projective::from(minted[1].2.to_g1_affine().unwrap()) - delta))
                .unwrap()
                .0,
        );
        let rogue_refs = vec![
            (minted[0].0, minted[0].1.as_slice(), &s0_bad),
            (minted[1].0, minted[1].1.as_slice(), &s1_bad),
        ];
        assert!(verify_batch_notes(&rogue_refs, &slot_pks, &dst).is_err());
    }

    #[test]
    fn test_elgamal_share_transport_and_ibe_tpe_lightning_preimage() {
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        let (ks, shares) = deal_multi_slot_keyset("ks_lnv2", "msat", 3, 4, 2, &mut rng).unwrap();

        // 1. Test ElGamal encrypted share transport
        let (esk, epk) = EphemeralElGamalSecretKey::generate(&mut rng);
        let (blinded, r) = blind_message(b"elgamal_note", &DstProfile::CashuBls, &mut rng).unwrap();
        let mut decrypted_shares = Vec::new();
        for p in 0..3usize {
            let raw =
                sign_blinded_message(p as u16, &shares[p].slot_scalar(1).unwrap(), &blinded)
                    .unwrap();
            let enc = encrypt_g1_share(p as u16, &raw.share_g1, &epk, &mut rng).unwrap();
            let dec_bytes = esk.decrypt_g1(&enc).unwrap();
            decrypted_shares.push(BlindSignatureShare {
                peer_id: p as u16,
                share_g1: dec_bytes,
            });
        }
        let bsig = combine_blind_shares(&decrypted_shares, 3).unwrap();
        let sig = unblind_signature(&bsig, &r).unwrap();
        verify_unblinded(
            b"elgamal_note",
            &sig,
            ks.slot_pk(1).unwrap(),
            &DstProfile::CashuBls,
        )
        .unwrap();

        // 2. Test Boneh-Franklin IBE / Fedimint LNv2 TPE 32-byte Lightning preimage encryption
        let preimage = [0xABu8; 32];
        let contract_id = b"lnv2_htlc_contract_hash_001";
        let ct = ibe_encrypt(&ks.ibe_agg_pk_g1, b"fedimint_lnv2", contract_id, &preimage, &mut rng)
            .unwrap();

        let mut dec_shares = Vec::new();
        for p in [0usize, 1, 3] {
            let ds = derive_ibe_decryption_share(
                p as u16,
                &shares[p].ibe_scalar().unwrap(),
                b"fedimint_lnv2",
                contract_id,
            )
            .unwrap();
            verify_ibe_decryption_share(&ks.ibe_peer_pks_g1[p], b"fedimint_lnv2", contract_id, &ds)
                .unwrap();
            dec_shares.push(ds);
        }
        let recovered = ibe_combine_and_decrypt(&ct, &dec_shares, 3).unwrap();
        assert_eq!(recovered, preimage);

        // 3. Test BIP-340 secp256k1 SpendKey / NUT-11 Schnorr verification
        let spend_kp = SpendKeypair::random(&mut rng);
        let sig = spend_kp.sign(b"fedimint_txid_12345");
        verify_bip340_schnorr(&spend_kp.public_key(), b"fedimint_txid_12345", &sig).unwrap();
    }

    #[test]
    fn test_sui_move_cross_language_crypto_vectors() {
        use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
        use k256::ecdsa::{Signature as K256Sig, SigningKey as K256Sk};
        use sha2::{Digest, Sha256};

        let mut rng = ChaCha20Rng::from_seed([0x24u8; 32]);
        // 4-of-5 BLS12-381 keyset with 4 slots (1, 2, 4, 8) under DstProfile::SuiNative
        let (ks, shares) =
            deal_multi_slot_keyset("02cowriesui00001", "usd", 4, 5, 4, &mut rng).unwrap();
        let dst = DstProfile::SuiNative;

        // Mint 3 input notes across slots [0, 2, 3] (1 + 4 + 8 = 13) + 2 output blinded notes [2, 3] (4 + 8 = 12, fee = 1)
        let secrets: [&[u8]; 3] = [b"move_note_s0_a", b"move_note_s2_b", b"move_note_s3_c"];
        let slots: [u8; 3] = [0, 2, 3];
        let mut blinded_ins = Vec::new();
        let mut unblinded_sigs = Vec::new();
        for (&slot, &sec) in slots.iter().zip(secrets.iter()) {
            let (bm, r) = blind_message(sec, &dst, &mut rng).unwrap();
            blinded_ins.push(bm.clone());
            let sh: Vec<_> = [0usize, 1, 3, 4]
                .into_iter()
                .map(|p| {
                    sign_blinded_message(p as u16, &shares[p].slot_scalar(slot).unwrap(), &bm)
                        .unwrap()
                })
                .collect();
            let bsig = combine_blind_shares(&sh, 4).unwrap();
            let sig = unblind_signature(&bsig, &r).unwrap();
            verify_unblinded(sec, &sig, ks.slot_pk(slot).unwrap(), &dst).unwrap();
            unblinded_sigs.push(sig);
        }

        let (out_bm_2, _) = blind_message(b"move_swap_out_s2", &dst, &mut rng).unwrap();
        let (out_bm_3, _) = blind_message(b"move_swap_out_s3", &dst, &mut rng).unwrap();

        // Also mint a second slot-3 (8 notes) note for melt & circuit-breaker testing
        let (bm_melt, r_melt) = blind_message(b"move_melt_s3", &dst, &mut rng).unwrap();
        let sh_melt: Vec<_> = (0..4usize)
            .map(|p| {
                sign_blinded_message(p as u16, &shares[p].slot_scalar(3).unwrap(), &bm_melt)
                    .unwrap()
            })
            .collect();
        let sig_melt = unblind_signature(&combine_blind_shares(&sh_melt, 4).unwrap(), &r_melt)
            .unwrap();

        // secp256k1 ECDSA compact signature over sighash_context = b"swap_ctx_01"
        let k256_sk = K256Sk::from_bytes(&[0x33u8; 32].into()).unwrap();
        let k256_pk_sec1 = k256_sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let swap_ecdsa_sig: K256Sig = k256_sk.sign(b"swap_ctx_01");

        // Fedimint 3-of-4 Ed25519 guardian signatures + secp256k1 signatures
        let fed_txid = b"fedimint_tx_digest_32bytes_00001";
        let preimage = b"lightning_preimage_32bytes_00001";
        let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
        let fed_ecdsa_tx_sig: K256Sig = k256_sk.sign(fed_txid);
        let fed_ecdsa_ln_sig: K256Sig = k256_sk.sign(&payment_hash);

        let mut ed_pks = Vec::new();
        let mut ed_tx_sigs = Vec::new();
        let mut ed_ln_sigs = Vec::new();
        for g in 0..4u8 {
            let esk = EdSigningKey::from_bytes(&[0x50 + g; 32]);
            ed_pks.push(esk.verifying_key().to_bytes());
            ed_tx_sigs.push(esk.sign(fed_txid).to_bytes());
            ed_ln_sigs.push(esk.sign(&payment_hash).to_bytes());
        }

        println!("AGG_PK_0={}", hex::encode(ks.slot_pk(0).unwrap().as_bytes()));
        println!("AGG_PK_1={}", hex::encode(ks.slot_pk(1).unwrap().as_bytes()));
        println!("AGG_PK_2={}", hex::encode(ks.slot_pk(2).unwrap().as_bytes()));
        println!("AGG_PK_3={}", hex::encode(ks.slot_pk(3).unwrap().as_bytes()));
        println!("IBE_MPK={}", hex::encode(&ks.ibe_agg_pk_g1));
        println!("BM_IN_0={}", hex::encode(blinded_ins[0].as_bytes()));
        println!("BM_IN_1={}", hex::encode(blinded_ins[1].as_bytes()));
        println!("BM_IN_2={}", hex::encode(blinded_ins[2].as_bytes()));
        println!("SIG_0={}", hex::encode(unblinded_sigs[0].as_bytes()));
        println!("SIG_2={}", hex::encode(unblinded_sigs[1].as_bytes()));
        println!("SIG_3={}", hex::encode(unblinded_sigs[2].as_bytes()));
        println!("OUT_BM_2={}", hex::encode(out_bm_2.as_bytes()));
        println!("OUT_BM_3={}", hex::encode(out_bm_3.as_bytes()));
        println!("SIG_MELT_3={}", hex::encode(sig_melt.as_bytes()));
        println!("K256_PK={}", hex::encode(&k256_pk_sec1));
        println!("SWAP_ECDSA={}", hex::encode(swap_ecdsa_sig.to_bytes()));
        println!("FED_ECDSA_TX={}", hex::encode(fed_ecdsa_tx_sig.to_bytes()));
        println!("FED_ECDSA_LN={}", hex::encode(fed_ecdsa_ln_sig.to_bytes()));
        println!("PAY_HASH={}", hex::encode(payment_hash));
        for g in 0..4 {
            println!("ED_PK_{g}={}", hex::encode(ed_pks[g]));
            println!("ED_TX_SIG_{g}={}", hex::encode(ed_tx_sigs[g]));
            println!("ED_LN_SIG_{g}={}", hex::encode(ed_ln_sigs[g]));
        }
    }
}
