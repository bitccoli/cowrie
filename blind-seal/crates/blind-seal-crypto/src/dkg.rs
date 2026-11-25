use blstrs::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes;

use crate::tbs::PublicKeyG2;
use crate::CryptoError;

/// Public configuration of a multi-slot Blind-Seal keyset (e.g. 32 power-of-2 denominations).
/// Each slot `s` has an **algebraically independent** threshold secret key `msk[s]`,
/// preventing Trap 2 (cross-denomination / cross-tenant scalar forgery).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyset {
    pub keyset_id: String,
    pub unit: String,
    pub threshold: u16,
    pub num_peers: u16,
    /// `slot_agg_pks[s]` is the aggregate `G2` public key for slot `s` (`amount = 2^s`).
    pub slot_agg_pks: Vec<PublicKeyG2>,
    /// `peer_slot_pks[peer_id][s]` is peer `i`'s `G2` public key share for slot `s`.
    pub peer_slot_pks: Vec<Vec<PublicKeyG2>>,
    /// Standard Seal IBE / Fedimint TPE aggregate `G1` public key (`mpk = ibe_sk * G1`).
    #[serde(with = "serde_bytes")]
    pub ibe_agg_pk_g1: Vec<u8>,
    /// Per-peer `G1` public key shares for IBE / TPE decryption share verification.
    pub ibe_peer_pks_g1: Vec<Vec<u8>>,
}

impl PublicKeyset {
    pub fn num_slots(&self) -> usize {
        self.slot_agg_pks.len()
    }

    pub fn slot_pk(&self, slot: u8) -> Result<&PublicKeyG2, CryptoError> {
        self.slot_agg_pks
            .get(usize::from(slot))
            .ok_or(CryptoError::UnknownSlot(slot))
    }

    pub fn peer_slot_pk(&self, peer_id: u16, slot: u8) -> Result<&PublicKeyG2, CryptoError> {
        self.peer_slot_pks
            .get(usize::from(peer_id))
            .and_then(|slots| slots.get(usize::from(slot)))
            .ok_or(CryptoError::UnknownSlot(slot))
    }
}

/// Secret key material held by a single Blind-Seal guardian node (`peer_id`).
#[derive(Clone, Serialize, Deserialize)]
pub struct GuardianSecretKeyShare {
    pub keyset_id: String,
    pub peer_id: u16,
    /// `slot_shares_be[s]` = 32-byte big-endian `Scalar` share for denomination slot `s`.
    pub slot_shares_be: Vec<[u8; 32]>,
    /// 32-byte big-endian `Scalar` share for standard Seal IBE / Fedimint `LNv2` TPE.
    pub ibe_share_be: [u8; 32],
}

impl GuardianSecretKeyShare {
    pub fn slot_scalar(&self, slot: u8) -> Result<Scalar, CryptoError> {
        let bytes = self
            .slot_shares_be
            .get(usize::from(slot))
            .ok_or(CryptoError::UnknownSlot(slot))?;
        Scalar::from_bytes_be(bytes)
            .into_option()
            .ok_or(CryptoError::InvalidEncoding("corrupt secret scalar"))
    }

    pub fn ibe_scalar(&self) -> Result<Scalar, CryptoError> {
        Scalar::from_bytes_be(&self.ibe_share_be)
            .into_option()
            .ok_or(CryptoError::InvalidEncoding("corrupt ibe scalar"))
    }
}

fn eval_poly(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        acc = acc * x + coeff;
    }
    acc
}

fn sample_nonzero_poly(degree: usize, mut rng: impl RngCore) -> Vec<Scalar> {
    (0..=degree)
        .map(|_| loop {
            let s = Scalar::random(&mut rng);
            if !bool::from(s.is_zero()) {
                break s;
            }
        })
        .collect()
}

/// Fast local Shamir secret-sharing dealer for devnets, tests, and single-ceremony bootstrapping.
pub fn deal_multi_slot_keyset(
    keyset_id: impl Into<String>,
    unit: impl Into<String>,
    threshold: u16,
    num_peers: u16,
    num_slots: usize,
    mut rng: impl RngCore,
) -> Result<(PublicKeyset, Vec<GuardianSecretKeyShare>), CryptoError> {
    if threshold == 0 || threshold > num_peers || num_slots == 0 {
        return Err(CryptoError::InvalidDkgConfig);
    }

    let keyset_id = keyset_id.into();
    let unit = unit.into();
    let degree = usize::from(threshold - 1);

    let mut slot_agg_pks = Vec::with_capacity(num_slots);
    let mut peer_slot_pks = vec![Vec::with_capacity(num_slots); usize::from(num_peers)];
    let mut peer_slot_scalars = vec![Vec::with_capacity(num_slots); usize::from(num_peers)];

    for _slot in 0..num_slots {
        let poly = sample_nonzero_poly(degree, &mut rng);
        let agg_pk = G2Projective::generator() * poly[0];
        slot_agg_pks.push(PublicKeyG2::from_g2(&agg_pk)?);

        for peer in 0..num_peers {
            let x = Scalar::from(u64::from(peer) + 1);
            let share = eval_poly(&poly, x);
            let pk_share = G2Projective::generator() * share;
            peer_slot_pks[usize::from(peer)].push(PublicKeyG2::from_g2(&pk_share)?);
            peer_slot_scalars[usize::from(peer)].push(share.to_bytes_be());
        }
    }

    // Also deal an independent master key for standard Seal IBE / Fedimint TPE (public keys in G1).
    let ibe_poly = sample_nonzero_poly(degree, &mut rng);
    let ibe_agg_pk_g1 = (G1Projective::generator() * ibe_poly[0])
        .to_affine()
        .to_compressed()
        .to_vec();
    let mut ibe_peer_pks_g1 = Vec::with_capacity(usize::from(num_peers));
    let mut shares = Vec::with_capacity(usize::from(num_peers));

    for peer in 0..num_peers {
        let x = Scalar::from(u64::from(peer) + 1);
        let ibe_share = eval_poly(&ibe_poly, x);
        ibe_peer_pks_g1.push(
            (G1Projective::generator() * ibe_share)
                .to_affine()
                .to_compressed()
                .to_vec(),
        );
        shares.push(GuardianSecretKeyShare {
            keyset_id: keyset_id.clone(),
            peer_id: peer,
            slot_shares_be: peer_slot_scalars[usize::from(peer)].clone(),
            ibe_share_be: ibe_share.to_bytes_be(),
        });
    }

    let pub_keyset = PublicKeyset {
        keyset_id,
        unit,
        threshold,
        num_peers,
        slot_agg_pks,
        peer_slot_pks,
        ibe_agg_pk_g1,
        ibe_peer_pks_g1,
    };

    Ok((pub_keyset, shares))
}

/// Round-1 broadcast message for dealer-free Batched Feldman/Pedersen Verifiable DKG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgRound1Broadcast {
    pub sender_peer: u16,
    /// `slot_commitments[slot][k]` = `a_{sender, slot, k} * G2` (96-byte compressed G2).
    pub slot_commitments_g2: Vec<Vec<PublicKeyG2>>,
    /// `ibe_commitments_g1[k]` = `b_{sender, k} * G1` (48-byte compressed G1).
    pub ibe_commitments_g1: Vec<Vec<u8>>,
}

/// Round-2 private point-to-point share package sent from `sender_peer` to `recipient_peer`.
#[derive(Clone, Serialize, Deserialize)]
pub struct DkgRound2Package {
    pub sender_peer: u16,
    pub recipient_peer: u16,
    pub slot_evals_be: Vec<[u8; 32]>,
    pub ibe_eval_be: [u8; 32],
}

/// Dealer-free Batched Verifiable DKG participant generating `num_slots` independent `G2` keys
/// plus 1 `G1` IBE/TPE key in two communication rounds with zero trusted party.
pub struct DkgParticipant {
    pub peer_id: u16,
    pub threshold: u16,
    pub num_peers: u16,
    slot_polys: Vec<Vec<Scalar>>,
    ibe_poly: Vec<Scalar>,
}

impl DkgParticipant {
    pub fn new(
        peer_id: u16,
        threshold: u16,
        num_peers: u16,
        num_slots: usize,
        mut rng: impl RngCore,
    ) -> Result<(Self, DkgRound1Broadcast), CryptoError> {
        if threshold == 0 || threshold > num_peers || peer_id >= num_peers || num_slots == 0 {
            return Err(CryptoError::InvalidDkgConfig);
        }
        let degree = usize::from(threshold - 1);
        let mut slot_polys = Vec::with_capacity(num_slots);
        let mut slot_commitments_g2 = Vec::with_capacity(num_slots);

        for _ in 0..num_slots {
            let poly = sample_nonzero_poly(degree, &mut rng);
            let commits = poly
                .iter()
                .map(|c| PublicKeyG2::from_g2(&(G2Projective::generator() * c)))
                .collect::<Result<Vec<_>, _>>()?;
            slot_polys.push(poly);
            slot_commitments_g2.push(commits);
        }

        let ibe_poly = sample_nonzero_poly(degree, &mut rng);
        let ibe_commitments_g1 = ibe_poly
            .iter()
            .map(|c| {
                (G1Projective::generator() * c)
                    .to_affine()
                    .to_compressed()
                    .to_vec()
            })
            .collect();

        let broadcast = DkgRound1Broadcast {
            sender_peer: peer_id,
            slot_commitments_g2,
            ibe_commitments_g1,
        };

        Ok((
            Self {
                peer_id,
                threshold,
                num_peers,
                slot_polys,
                ibe_poly,
            },
            broadcast,
        ))
    }

    pub fn round2_packages(&self) -> Vec<DkgRound2Package> {
        (0..self.num_peers)
            .map(|target| {
                let x = Scalar::from(u64::from(target) + 1);
                let slot_evals_be = self
                    .slot_polys
                    .iter()
                    .map(|poly| eval_poly(poly, x).to_bytes_be())
                    .collect();
                let ibe_eval_be = eval_poly(&self.ibe_poly, x).to_bytes_be();
                DkgRound2Package {
                    sender_peer: self.peer_id,
                    recipient_peer: target,
                    slot_evals_be,
                    ibe_eval_be,
                }
            })
            .collect()
    }

    /// Verifies all Round-1 Feldman commitments against Round-2 private evaluations and
    /// outputs this guardian's `GuardianSecretKeyShare` and the common `PublicKeyset`.
    pub fn finalize(
        &self,
        keyset_id: impl Into<String>,
        unit: impl Into<String>,
        broadcasts: &[DkgRound1Broadcast],
        packages_for_me: &[DkgRound2Package],
    ) -> Result<(PublicKeyset, GuardianSecretKeyShare), CryptoError> {
        let num_slots = self.slot_polys.len();
        let n = usize::from(self.num_peers);
        if broadcasts.len() != n || packages_for_me.len() != n {
            return Err(CryptoError::InvalidDkgConfig);
        }

        let my_x = Scalar::from(u64::from(self.peer_id) + 1);
        let mut my_slot_totals = vec![Scalar::ZERO; num_slots];
        let mut my_ibe_total = Scalar::ZERO;

        for pkg in packages_for_me {
            if pkg.recipient_peer != self.peer_id || pkg.slot_evals_be.len() != num_slots {
                return Err(CryptoError::InvalidDkgShare {
                    culprit_peer: pkg.sender_peer,
                });
            }
            let bcast = broadcasts
                .iter()
                .find(|b| b.sender_peer == pkg.sender_peer)
                .ok_or(CryptoError::InvalidDkgShare {
                    culprit_peer: pkg.sender_peer,
                })?;

            // Verify each slot's Feldman commitment: `eval * G2 == sum_k C_{sender, slot, k} * my_x^k`
            for slot in 0..num_slots {
                let eval = Scalar::from_bytes_be(&pkg.slot_evals_be[slot])
                    .into_option()
                    .ok_or(CryptoError::InvalidDkgShare {
                        culprit_peer: pkg.sender_peer,
                    })?;
                let commits = bcast.slot_commitments_g2.get(slot).ok_or(
                    CryptoError::InvalidDkgShare {
                        culprit_peer: pkg.sender_peer,
                    },
                )?;
                if commits.len() != usize::from(self.threshold) {
                    return Err(CryptoError::InvalidDkgShare {
                        culprit_peer: pkg.sender_peer,
                    });
                }

                let mut rhs = G2Projective::identity();
                let mut x_pow = Scalar::ONE;
                for c in commits {
                    rhs += G2Projective::from(c.to_g2_affine()?) * x_pow;
                    x_pow *= my_x;
                }
                if G2Projective::generator() * eval != rhs {
                    return Err(CryptoError::InvalidDkgShare {
                        culprit_peer: pkg.sender_peer,
                    });
                }
                my_slot_totals[slot] += eval;
            }

            // Verify IBE G1 Feldman commitment
            let ibe_eval = Scalar::from_bytes_be(&pkg.ibe_eval_be)
                .into_option()
                .ok_or(CryptoError::InvalidDkgShare {
                    culprit_peer: pkg.sender_peer,
                })?;
            let mut ibe_rhs = G1Projective::identity();
            let mut x_pow = Scalar::ONE;
            for c_bytes in &bcast.ibe_commitments_g1 {
                let pt = crate::tbs::BlindedMessage(c_bytes.clone()).to_g1()?;
                ibe_rhs += pt * x_pow;
                x_pow *= my_x;
            }
            if G1Projective::generator() * ibe_eval != ibe_rhs {
                return Err(CryptoError::InvalidDkgShare {
                    culprit_peer: pkg.sender_peer,
                });
            }
            my_ibe_total += ibe_eval;
        }

        // Compute aggregate & per-peer public keys directly from verified Round-1 commitments!
        let mut slot_agg_pks = Vec::with_capacity(num_slots);
        let mut peer_slot_pks = vec![Vec::with_capacity(num_slots); n];

        for slot in 0..num_slots {
            let mut agg = G2Projective::identity();
            for bcast in broadcasts {
                agg += G2Projective::from(bcast.slot_commitments_g2[slot][0].to_g2_affine()?);
            }
            slot_agg_pks.push(PublicKeyG2::from_g2(&agg)?);

            for peer in 0..self.num_peers {
                let px = Scalar::from(u64::from(peer) + 1);
                let mut peer_pk = G2Projective::identity();
                for bcast in broadcasts {
                    let mut x_pow = Scalar::ONE;
                    for c in &bcast.slot_commitments_g2[slot] {
                        peer_pk += G2Projective::from(c.to_g2_affine()?) * x_pow;
                        x_pow *= px;
                    }
                }
                peer_slot_pks[usize::from(peer)].push(PublicKeyG2::from_g2(&peer_pk)?);
            }
        }

        let mut ibe_agg = G1Projective::identity();
        for bcast in broadcasts {
            ibe_agg += crate::tbs::BlindedMessage(bcast.ibe_commitments_g1[0].clone()).to_g1()?;
        }
        let mut ibe_peer_pks_g1 = Vec::with_capacity(n);
        for peer in 0..self.num_peers {
            let px = Scalar::from(u64::from(peer) + 1);
            let mut peer_pk = G1Projective::identity();
            for bcast in broadcasts {
                let mut x_pow = Scalar::ONE;
                for c_bytes in &bcast.ibe_commitments_g1 {
                    peer_pk += crate::tbs::BlindedMessage(c_bytes.clone()).to_g1()? * x_pow;
                    x_pow *= px;
                }
            }
            ibe_peer_pks_g1.push(peer_pk.to_affine().to_compressed().to_vec());
        }

        let keyset_id = keyset_id.into();
        let pub_keyset = PublicKeyset {
            keyset_id: keyset_id.clone(),
            unit: unit.into(),
            threshold: self.threshold,
            num_peers: self.num_peers,
            slot_agg_pks,
            peer_slot_pks,
            ibe_agg_pk_g1: ibe_agg.to_affine().to_compressed().to_vec(),
            ibe_peer_pks_g1,
        };

        let secret_share = GuardianSecretKeyShare {
            keyset_id,
            peer_id: self.peer_id,
            slot_shares_be: my_slot_totals.into_iter().map(|s| s.to_bytes_be()).collect(),
            ibe_share_be: my_ibe_total.to_bytes_be(),
        };

        Ok((pub_keyset, secret_share))
    }
}
