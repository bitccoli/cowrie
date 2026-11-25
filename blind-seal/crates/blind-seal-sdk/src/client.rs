use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};

use blind_seal_crypto::{
    dkg::PublicKeyset,
    dst::DstProfile,
    elgamal::EphemeralElGamalSecretKey,
    ibe_tpe::{
        ibe_combine_and_decrypt, verify_ibe_decryption_share, IbeDecryptionShare, IbeTpeCiphertext,
    },
    tbs::{
        combine_blind_shares, unblind_signature, verify_blind_share, BlindSignature,
        BlindSignatureShare, BlindedMessage, BlindingFactor, UnblindedSignature,
    },
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        BlindTicketOnChain, FetchBlindSigRequest, FetchBlindSigResponse, FetchIbeKeyRequest,
        FetchIbeKeyResponse, SharePayload,
    },
    sui_backend::BoxFuture,
    SdkError,
};

/// Pluggable transport trait allowing `BlindSealClient` to query either live remote HTTP
/// Key Servers or in-process `BlindSealKeyServerState` instances (for sandbox-friendly tests).
pub trait BlindSealPeerHandler: Send + Sync {
    fn fetch_blind_sig<'a>(
        &'a self,
        req: FetchBlindSigRequest,
    ) -> BoxFuture<'a, Result<FetchBlindSigResponse, SdkError>>;

    fn fetch_ibe_key<'a>(
        &'a self,
        req: FetchIbeKeyRequest,
    ) -> BoxFuture<'a, Result<FetchIbeKeyResponse, SdkError>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianFaultMode {
    Healthy = 0,
    Offline = 1,
    ByzantineForge = 2,
}

impl GuardianFaultMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Offline,
            2 => Self::ByzantineForge,
            _ => Self::Healthy,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianPeerSnapshot {
    pub peer_id: u16,
    pub mode: GuardianFaultMode,
    pub shares_accepted: u64,
    pub byzantine_shares_rejected: u64,
}

/// Interactive fault-injection & telemetry wrapper around a single Guardian node (`peer_id`).
/// Allows live toggling between `Healthy`, `Offline`, and `ByzantineForge` (injecting forged `G1`
/// shares that `BlindSealClient`'s bilinear pairing check catches and rejects in real time!).
pub struct ControllableGuardianPeer {
    pub peer_id: u16,
    inner: Arc<dyn BlindSealPeerHandler>,
    mode: AtomicU8,
    pub shares_accepted: AtomicU64,
    pub byzantine_shares_rejected: AtomicU64,
}

impl ControllableGuardianPeer {
    pub fn new(peer_id: u16, inner: Arc<dyn BlindSealPeerHandler>) -> Self {
        Self {
            peer_id,
            inner,
            mode: AtomicU8::new(GuardianFaultMode::Healthy as u8),
            shares_accepted: AtomicU64::new(0),
            byzantine_shares_rejected: AtomicU64::new(0),
        }
    }

    pub fn set_mode(&self, mode: GuardianFaultMode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }

    pub fn mode(&self) -> GuardianFaultMode {
        GuardianFaultMode::from_u8(self.mode.load(Ordering::SeqCst))
    }

    pub fn snapshot(&self) -> GuardianPeerSnapshot {
        GuardianPeerSnapshot {
            peer_id: self.peer_id,
            mode: self.mode(),
            shares_accepted: self.shares_accepted.load(Ordering::Relaxed),
            byzantine_shares_rejected: self.byzantine_shares_rejected.load(Ordering::Relaxed),
        }
    }
}

impl BlindSealPeerHandler for ControllableGuardianPeer {
    fn fetch_blind_sig<'a>(
        &'a self,
        req: FetchBlindSigRequest,
    ) -> BoxFuture<'a, Result<FetchBlindSigResponse, SdkError>> {
        Box::pin(async move {
            match self.mode() {
                GuardianFaultMode::Offline => Err(SdkError::Rpc(format!(
                    "guardian {} simulated offline",
                    self.peer_id
                ))),
                GuardianFaultMode::Healthy => {
                    let resp = self.inner.fetch_blind_sig(req).await?;
                    self.shares_accepted.fetch_add(1, Ordering::Relaxed);
                    Ok(resp)
                }
                GuardianFaultMode::ByzantineForge => {
                    let mut resp = self.inner.fetch_blind_sig(req).await?;
                    // Corrupt every returned share into a valid-subgroup but WRONG G1 point!
                    let forged_g1 = BlindedMessage::from_g1(
                        &DstProfile::SuiNative.hash_to_g1(b"BYZANTINE_FORGED_G1_SHARE"),
                    )?
                    .0;
                    if let SharePayload::Plain(ref mut list) = resp.shares {
                        for s in list.iter_mut() {
                            s.share_g1 = forged_g1.clone();
                        }
                    }
                    self.byzantine_shares_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    Ok(resp)
                }
            }
        })
    }

    fn fetch_ibe_key<'a>(
        &'a self,
        req: FetchIbeKeyRequest,
    ) -> BoxFuture<'a, Result<FetchIbeKeyResponse, SdkError>> {
        Box::pin(async move {
            if self.mode() == GuardianFaultMode::Offline {
                return Err(SdkError::Rpc("guardian simulated offline".into()));
            }
            self.inner.fetch_ibe_key(req).await
        })
    }
}

struct HttpPeerHandler {
    base_url: String,
    http: reqwest::Client,
}

impl BlindSealPeerHandler for HttpPeerHandler {
    fn fetch_blind_sig<'a>(
        &'a self,
        req: FetchBlindSigRequest,
    ) -> BoxFuture<'a, Result<FetchBlindSigResponse, SdkError>> {
        Box::pin(async move {
            let endpoint = format!("{}/v1/fetch_blind_sig", self.base_url.trim_end_matches('/'));
            let resp = self
                .http
                .post(&endpoint)
                .json(&req)
                .send()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(SdkError::Rpc(format!("HTTP {}", resp.status())));
            }
            resp.json()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))
        })
    }

    fn fetch_ibe_key<'a>(
        &'a self,
        req: FetchIbeKeyRequest,
    ) -> BoxFuture<'a, Result<FetchIbeKeyResponse, SdkError>> {
        Box::pin(async move {
            let endpoint = format!("{}/v1/fetch_key", self.base_url.trim_end_matches('/'));
            let resp = self
                .http
                .post(&endpoint)
                .json(&req)
                .send()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(SdkError::Rpc(format!("HTTP {}", resp.status())));
            }
            resp.json()
                .await
                .map_err(|e| SdkError::Rpc(e.to_string()))
        })
    }
}

/// High-level client SDK for querying a $t$-of-$n$ committee of `Blind-Seal` Key Servers.
/// Automatically handles Byzantine share filtering (pairing verification per share), optional
/// ElGamal share transport encryption, and offline/faulty server tolerance!
#[derive(Clone)]
pub struct BlindSealClient {
    peers: Vec<Arc<dyn BlindSealPeerHandler>>,
}

impl BlindSealClient {
    pub fn new_http(server_urls: Vec<String>) -> Self {
        let http = reqwest::Client::builder().no_proxy().build().unwrap_or_default();
        let peers = server_urls
            .into_iter()
            .map(|base_url| {
                Arc::new(HttpPeerHandler {
                    base_url,
                    http: http.clone(),
                }) as Arc<dyn BlindSealPeerHandler>
            })
            .collect();
        Self { peers }
    }

    pub fn new_with_handlers(peers: Vec<Arc<dyn BlindSealPeerHandler>>) -> Self {
        Self { peers }
    }

    /// Queries the Blind-Seal committee for `ticket`, verifies each guardian's share via pairing,
    /// and returns combined `BlindSignature`s (one per output in `ticket`).
    /// Used both by Cashu coordinators (server-side aggregation) and direct Blind-Seal clients.
    pub async fn fetch_combined_blind_signatures(
        &self,
        keyset: &PublicKeyset,
        ticket: &BlindTicketOnChain,
        use_elgamal_transport: bool,
    ) -> Result<Vec<BlindSignature>, SdkError> {
        let elgamal_pair = if use_elgamal_transport {
            Some(EphemeralElGamalSecretKey::generate(&mut OsRng))
        } else {
            None
        };

        let req_body = FetchBlindSigRequest {
            keyset_id: keyset.keyset_id.clone(),
            ticket_id_hex: hex::encode(ticket.ticket_id),
            seal_approve_ptb_b64: None,
            ephemeral_elgamal_pk: elgamal_pair.as_ref().map(|(_, pk)| pk.clone()),
        };

        let num_outputs = ticket.blinded_messages.len();
        let threshold = usize::from(keyset.threshold);
        let mut valid_shares_per_output: Vec<Vec<BlindSignatureShare>> =
            vec![Vec::with_capacity(threshold); num_outputs];

        for peer in &self.peers {
            if valid_shares_per_output
                .iter()
                .all(|s| s.len() >= threshold)
            {
                break;
            }
            let Ok(parsed) = peer.fetch_blind_sig(req_body.clone()).await else {
                continue;
            };

            let decoded_shares: Vec<BlindSignatureShare> = match (parsed.shares, &elgamal_pair) {
                (SharePayload::Plain(plain), None) => plain,
                (SharePayload::Encrypted(enc_list), Some((esk, _))) => {
                    let mut out = Vec::with_capacity(enc_list.len());
                    let mut ok = true;
                    for enc in enc_list {
                        match esk.decrypt_g1(&enc) {
                            Ok(bytes) => out.push(BlindSignatureShare {
                                peer_id: enc.peer_id,
                                share_g1: bytes,
                            }),
                            Err(_) => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if !ok {
                        continue;
                    }
                    out
                }
                _ => continue,
            };

            if decoded_shares.len() != num_outputs {
                continue;
            }

            // Cryptographically verify every individual share against `peer_slot_pks` before accepting!
            let mut all_valid = true;
            for (idx, share) in decoded_shares.iter().enumerate() {
                let slot = ticket.slots[idx];
                let Ok(peer_pk) = keyset.peer_slot_pk(share.peer_id, slot) else {
                    all_valid = false;
                    break;
                };
                if verify_blind_share(&ticket.blinded_messages[idx], share, peer_pk).is_err() {
                    all_valid = false;
                    break;
                }
            }
            if !all_valid {
                continue;
            }

            for (idx, share) in decoded_shares.into_iter().enumerate() {
                if !valid_shares_per_output[idx]
                    .iter()
                    .any(|s| s.peer_id == share.peer_id)
                {
                    valid_shares_per_output[idx].push(share);
                }
            }
        }

        valid_shares_per_output
            .iter()
            .map(|shares| combine_blind_shares(shares, threshold).map_err(SdkError::from))
            .collect()
    }

    /// Convenience helper that fetches combined `BlindSignature`s AND unblinds them locally.
    pub async fn fetch_and_unblind(
        &self,
        keyset: &PublicKeyset,
        ticket: &BlindTicketOnChain,
        blinding_factors: &[BlindingFactor],
        use_elgamal_transport: bool,
    ) -> Result<Vec<UnblindedSignature>, SdkError> {
        let combined = self
            .fetch_combined_blind_signatures(keyset, ticket, use_elgamal_transport)
            .await?;
        combined
            .iter()
            .zip(blinding_factors.iter())
            .map(|(bsig, r)| unblind_signature(bsig, r).map_err(SdkError::from))
            .collect()
    }

    /// Fetches $t$-of-$n$ Boneh-Franklin IBE / Fedimint `LNv2` TPE decryption shares and
    /// reconstructs the plaintext secret locally.
    pub async fn fetch_and_decrypt_ibe(
        &self,
        keyset: &PublicKeyset,
        approval_id: [u8; 32],
        ciphertext: &IbeTpeCiphertext,
    ) -> Result<Vec<u8>, SdkError> {
        let req_body = FetchIbeKeyRequest {
            keyset_id: keyset.keyset_id.clone(),
            approval_id_hex: hex::encode(approval_id),
            seal_approve_ptb_b64: None,
        };
        let threshold = usize::from(keyset.threshold);
        let mut valid_shares: Vec<IbeDecryptionShare> = Vec::with_capacity(threshold);

        for peer in &self.peers {
            if valid_shares.len() >= threshold {
                break;
            }
            let Ok(parsed) = peer.fetch_ibe_key(req_body.clone()).await else {
                continue;
            };
            let peer_idx = usize::from(parsed.share.peer_id);
            let Some(peer_pk_g1) = keyset.ibe_peer_pks_g1.get(peer_idx) else {
                continue;
            };
            if verify_ibe_decryption_share(
                peer_pk_g1,
                &ciphertext.namespace,
                &ciphertext.identity,
                &parsed.share,
            )
            .is_ok()
                && !valid_shares
                    .iter()
                    .any(|s| s.peer_id == parsed.share.peer_id)
            {
                valid_shares.push(parsed.share);
            }
        }

        ibe_combine_and_decrypt(ciphertext, &valid_shares, threshold).map_err(SdkError::from)
    }
}
