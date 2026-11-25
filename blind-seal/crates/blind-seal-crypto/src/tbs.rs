use std::collections::BTreeMap;

use blstrs::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::{Digest, Sha256};

use crate::dst::DstProfile;
use crate::CryptoError;

/// Computes the canonical 48-byte compressed `G1` point `Y = H_dst(secret)` used as the
/// privacy-preserving `NUT-07` state-check identifier and fixed-size nullifier key.
pub fn hash_secret_to_y_bytes(message: &[u8], dst: &DstProfile) -> [u8; 48] {
    dst.hash_to_g1(message).to_affine().to_compressed()
}

/// Secret client-side scalar `r != 0` used to blind a `G1` point (`M' = r * H(m)`).
#[derive(Clone, Debug)]
pub struct BlindingFactor(pub Scalar);

impl BlindingFactor {
    pub fn random(mut rng: impl RngCore) -> Self {
        loop {
            let r = Scalar::random(&mut rng);
            if !bool::from(r.is_zero()) {
                return Self(r);
            }
        }
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let opt = Scalar::from_bytes_be(bytes);
        if bool::from(opt.is_some()) {
            let s = opt.unwrap();
            if bool::from(s.is_zero()) {
                return Err(CryptoError::DegeneratePoint("zero blinding scalar"));
            }
            Ok(Self(s))
        } else {
            Err(CryptoError::InvalidEncoding("invalid scalar bytes"))
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_bytes_be()
    }
}

/// Compressed 48-byte canonical `BLS12-381 G1` point representing `M' = r * H_dst(m)`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlindedMessage(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for BlindedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlindedMessage({})", hex::encode(&self.0))
    }
}

impl BlindedMessage {
    pub fn from_g1(point: &G1Projective) -> Result<Self, CryptoError> {
        if bool::from(point.is_identity()) {
            return Err(CryptoError::DegeneratePoint("identity G1 point rejected"));
        }
        Ok(Self(point.to_affine().to_compressed().to_vec()))
    }

    /// Strictly validates canonical compressed encoding, prime-order `G1` subgroup membership,
    /// and non-identity status (preventing trivial `0` point signing attacks).
    pub fn to_g1(&self) -> Result<G1Projective, CryptoError> {
        let arr: &[u8; 48] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding("G1 point must be 48 bytes"))?;
        let opt = G1Affine::from_compressed(arr);
        if !bool::from(opt.is_some()) {
            return Err(CryptoError::InvalidEncoding(
                "invalid or non-subgroup G1 point",
            ));
        }
        let affine = opt.unwrap();
        if bool::from(affine.is_identity()) {
            return Err(CryptoError::DegeneratePoint("identity G1 point rejected"));
        }
        Ok(G1Projective::from(affine))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Partial blind signature `S'_i = msk_i * M'` returned by guardian `peer_id` (0-indexed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindSignatureShare {
    pub peer_id: u16,
    #[serde(with = "serde_bytes")]
    pub share_g1: Vec<u8>,
}

impl BlindSignatureShare {
    pub fn to_g1(&self) -> Result<G1Projective, CryptoError> {
        BlindedMessage(self.share_g1.clone()).to_g1()
    }
}

/// Combined (still-blinded) threshold signature `S' = msk * M'` in `G1` (48 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindSignature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl BlindSignature {
    pub fn to_g1(&self) -> Result<G1Projective, CryptoError> {
        BlindedMessage(self.0.clone()).to_g1()
    }
}

/// Final unblinded Chaumian signature `S = msk * H_dst(m)` in `G1` (48 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnblindedSignature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for UnblindedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnblindedSig({})", hex::encode(&self.0))
    }
}

impl UnblindedSignature {
    pub fn to_g1_affine(&self) -> Result<G1Affine, CryptoError> {
        Ok(BlindedMessage(self.0.clone()).to_g1()?.to_affine())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Compressed 96-byte canonical `BLS12-381 G2` public key (aggregate or peer share).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKeyG2(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for PublicKeyG2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PubKeyG2({}..)", hex::encode(&self.0[..8.min(self.0.len())]))
    }
}

impl PublicKeyG2 {
    pub fn from_g2(point: &G2Projective) -> Result<Self, CryptoError> {
        if bool::from(point.is_identity()) {
            return Err(CryptoError::DegeneratePoint("identity G2 pubkey rejected"));
        }
        Ok(Self(point.to_affine().to_compressed().to_vec()))
    }

    pub fn to_g2_affine(&self) -> Result<G2Affine, CryptoError> {
        let arr: &[u8; 96] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding("G2 pubkey must be 96 bytes"))?;
        let opt = G2Affine::from_compressed(arr);
        if !bool::from(opt.is_some()) {
            return Err(CryptoError::InvalidEncoding(
                "invalid or non-subgroup G2 pubkey",
            ));
        }
        let affine = opt.unwrap();
        if bool::from(affine.is_identity()) {
            return Err(CryptoError::DegeneratePoint("identity G2 pubkey rejected"));
        }
        Ok(affine)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Blinds an arbitrary message `m` under `dst` with a fresh random scalar `r`.
pub fn blind_message(
    message: &[u8],
    dst: &DstProfile,
    rng: impl RngCore,
) -> Result<(BlindedMessage, BlindingFactor), CryptoError> {
    let r = BlindingFactor::random(rng);
    blind_message_with_factor(message, dst, &r)
}

/// Deterministic blinding given an explicit `BlindingFactor` (essential for BIP-39 seed recovery!).
pub fn blind_message_with_factor(
    message: &[u8],
    dst: &DstProfile,
    r: &BlindingFactor,
) -> Result<(BlindedMessage, BlindingFactor), CryptoError> {
    let h = dst.hash_to_g1(message);
    let blinded = h * r.0;
    Ok((BlindedMessage::from_g1(&blinded)?, r.clone()))
}

/// Guardian signing operation: multiplies validated `BlindedMessage` by `secret_share`.
pub fn sign_blinded_message(
    peer_id: u16,
    secret_share: &Scalar,
    blinded: &BlindedMessage,
) -> Result<BlindSignatureShare, CryptoError> {
    let m_prime = blinded.to_g1()?;
    let s_prime = m_prime * secret_share;
    if bool::from(s_prime.is_identity()) {
        return Err(CryptoError::DegeneratePoint("zero signature share"));
    }
    Ok(BlindSignatureShare {
        peer_id,
        share_g1: s_prime.to_affine().to_compressed().to_vec(),
    })
}

/// Verifies an individual guardian's `BlindSignatureShare` against `peer_pk_g2`
/// via bilinear pairing: `e(S'_i, G2) == e(M', PK_i)`.
pub fn verify_blind_share(
    blinded: &BlindedMessage,
    share: &BlindSignatureShare,
    peer_pk_g2: &PublicKeyG2,
) -> Result<(), CryptoError> {
    let m_prime = blinded.to_g1()?.to_affine();
    let s_prime = share.to_g1()?.to_affine();
    let pk_i = peer_pk_g2.to_g2_affine()?;
    let g2_gen = G2Affine::generator();

    if pairing(&s_prime, &g2_gen) == pairing(&m_prime, &pk_i) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignatureShare {
            peer_id: share.peer_id,
        })
    }
}

/// Computes Lagrange basis coefficient `lambda_i(0)` for Shamir evaluation point `x_i = peer_i + 1`.
pub fn lagrange_coeff_at_zero(peer_id: u16, all_peers: &[u16]) -> Result<Scalar, CryptoError> {
    let x_i = Scalar::from(u64::from(peer_id) + 1);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for &peer_j in all_peers {
        if peer_j == peer_id {
            continue;
        }
        let x_j = Scalar::from(u64::from(peer_j) + 1);
        let diff = x_j - x_i;
        if bool::from(diff.is_zero()) {
            return Err(CryptoError::DuplicatePeerShare(peer_id));
        }
        num *= x_j;
        den *= diff;
    }

    let den_inv = den
        .invert()
        .into_option()
        .ok_or(CryptoError::DuplicatePeerShare(peer_id))?;
    Ok(num * den_inv)
}

/// Combines at least `threshold` distinct `BlindSignatureShare`s using Lagrange interpolation in `G1`.
pub fn combine_blind_shares(
    shares: &[BlindSignatureShare],
    threshold: usize,
) -> Result<BlindSignature, CryptoError> {
    if shares.len() < threshold {
        return Err(CryptoError::InsufficientShares {
            got: shares.len(),
            need: threshold,
        });
    }
    let subset = &shares[..threshold];
    let peer_ids: Vec<u16> = subset.iter().map(|s| s.peer_id).collect();

    let mut combined = G1Projective::identity();
    for share in subset {
        let lambda = lagrange_coeff_at_zero(share.peer_id, &peer_ids)?;
        let pt = share.to_g1()?;
        combined += pt * lambda;
    }

    Ok(BlindSignature(
        BlindedMessage::from_g1(&combined)?.0,
    ))
}

/// Removes the client blinding factor `r`: `S = r^-1 * S'`.
pub fn unblind_signature(
    blind_sig: &BlindSignature,
    r: &BlindingFactor,
) -> Result<UnblindedSignature, CryptoError> {
    let s_prime = blind_sig.to_g1()?;
    let r_inv = r
        .0
        .invert()
        .into_option()
        .ok_or(CryptoError::DegeneratePoint("non-invertible scalar"))?;
    let s = s_prime * r_inv;
    Ok(UnblindedSignature(BlindedMessage::from_g1(&s)?.0))
}

/// Verifies an unblinded token `(message, sig)` against the slot's `AggregatePublicKey` in `G2`:
/// `e(S, G2) == e(H_dst(message), PK_slot)`.
pub fn verify_unblinded(
    message: &[u8],
    sig: &UnblindedSignature,
    slot_agg_pk: &PublicKeyG2,
    dst: &DstProfile,
) -> Result<(), CryptoError> {
    let h = dst.hash_to_g1(message).to_affine();
    let s = sig.to_g1_affine()?;
    let pk = slot_agg_pk.to_g2_affine()?;

    if pairing(&s, &G2Affine::generator()) == pairing(&h, &pk) {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

/// Batch-verifies multiple unblinded notes across potentially distinct denomination slots
/// using deterministic 128-bit Fiat-Shamir random linear combination weights `z_j` to prevent
/// rogue cancellation (`(S_1 + Delta, S_2 - Delta)`), while grouping `G1` sums per slot so
/// a 500-note batch requires at most `1 + |distinct_slots|` pairings:
/// `e(sum_j z_j S_j, G2) == sum_slot e(sum_{j in slot} z_j H(m_j), PK_slot)`.
pub fn verify_batch_notes(
    notes: &[(u8, &[u8], &UnblindedSignature)],
    slot_pks: &BTreeMap<u8, PublicKeyG2>,
    dst: &DstProfile,
) -> Result<(), CryptoError> {
    if notes.is_empty() {
        return Ok(());
    }
    if notes.len() == 1 {
        let (slot, msg, sig) = &notes[0];
        let pk = slot_pks
            .get(slot)
            .ok_or(CryptoError::UnknownSlot(*slot))?;
        return verify_unblinded(msg, sig, pk, dst);
    }

    // Bind Fiat-Shamir transcript across every `(slot, msg, sig)` in the batch
    let mut transcript = Sha256::new();
    transcript.update(b"COWRIE_BLS_BATCH_FS_TRANSCRIPT_V1");
    transcript.update(dst.as_bytes());
    for (slot, msg, sig) in notes {
        transcript.update([*slot]);
        transcript.update((msg.len() as u32).to_be_bytes());
        transcript.update(msg);
        transcript.update(sig.as_bytes());
    }
    let transcript_root: [u8; 32] = transcript.finalize().into();

    let mut sig_sum = G1Projective::identity();
    let mut per_slot_hash_sum: BTreeMap<u8, G1Projective> = BTreeMap::new();

    for (idx, (slot, msg, sig)) in notes.iter().enumerate() {
        let mut weight_hasher = Sha256::new();
        weight_hasher.update(b"COWRIE_BLS_BATCH_WEIGHT_V1");
        weight_hasher.update(transcript_root);
        weight_hasher.update((idx as u32).to_be_bytes());
        let digest = weight_hasher.finalize();

        // Non-zero 128-bit scalar weight `z_j` (top 16 bytes zero, lowest bit forced to 1)
        let mut z_be = [0u8; 32];
        z_be[16..32].copy_from_slice(&digest[..16]);
        z_be[31] |= 1;
        let z = Scalar::from_bytes_be(&z_be).unwrap();

        let s = G1Projective::from(sig.to_g1_affine()?) * z;
        sig_sum += s;
        let h = dst.hash_to_g1(msg) * z;
        per_slot_hash_sum
            .entry(*slot)
            .and_modify(|acc| *acc += h)
            .or_insert(h);
    }

    let lhs = pairing(&sig_sum.to_affine(), &G2Affine::generator());
    let mut rhs_opt = None;

    for (slot, h_sum) in per_slot_hash_sum {
        let pk = slot_pks
            .get(&slot)
            .ok_or(CryptoError::UnknownSlot(slot))?
            .to_g2_affine()?;
        let term = pairing(&h_sum.to_affine(), &pk);
        rhs_opt = Some(match rhs_opt {
            None => term,
            Some(acc) => acc + term,
        });
    }

    if Some(lhs) == rhs_opt {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}
