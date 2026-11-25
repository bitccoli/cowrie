pub mod encoding;
pub mod wire;
pub mod ws_rpc;

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use blind_seal_crypto::{
    dst::DstProfile,
    ibe_tpe::{ibe_combine_and_decrypt, verify_ibe_decryption_share},
    tbs::{
        blind_message_with_factor, combine_blind_shares, unblind_signature, verify_blind_share,
        BlindedMessage,
    },
};
use blind_seal_sdk::{
    api::{FetchBlindSigRequest, FetchIbeKeyRequest, SharePayload},
    client::{BlindSealClient, BlindSealPeerHandler},
    sui_backend::{EmbeddedMoveEngine, Lnv2ContractOnChain, SpendProofInput},
    SdkError,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wire::{
    derive_deterministic_note_material, FederationId, FedimintClientConfig, FedimintMintInput,
    FedimintMintOutput, FedimintTransaction, Lnv2OutgoingRequest, Lnv2TpeShareOutcome,
    MintOutputOutcome, OOBNotes, OutPoint, SignedSessionOutcome, SpendableNote,
};

/// Stateless "Virtual Guardian" Shim implementing Fedimint's `IGlobalFederationApi` downstream
/// while delegating consensus & msat reserves upstream to Sui Move + `Blind-Seal`.
#[derive(Clone)]
pub struct VirtualGuardianShim {
    pub peer_id: u16,
    pub client_config: Arc<FedimintClientConfig>,
    pub guardian_signing_key: Arc<SigningKey>,
    pub local_seal_peer: Arc<dyn BlindSealPeerHandler>,
    pub move_vault: Arc<EmbeddedMoveEngine>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GuardianRpcRequest {
    DownloadClientConfig,
    SubmitTransaction(FedimintTransaction),
    AwaitOutputOutcome(OutPoint),
    SessionCount,
    AwaitSessionOutcome { session_index: u64 },
}

impl VirtualGuardianShim {
    pub fn new(
        peer_id: u16,
        client_config: Arc<FedimintClientConfig>,
        guardian_signing_key: SigningKey,
        local_seal_peer: Arc<dyn BlindSealPeerHandler>,
        move_vault: Arc<EmbeddedMoveEngine>,
    ) -> Self {
        Self {
            peer_id,
            client_config,
            guardian_signing_key: Arc::new(guardian_signing_key),
            local_seal_peer,
            move_vault,
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(ws_rpc::handle_ws_upgrade).post(ws_rpc::handle_http_jsonrpc))
            .route("/ws", get(ws_rpc::handle_ws_upgrade))
            .route("/jsonrpc", post(ws_rpc::handle_http_jsonrpc))
            .route("/config", get(handle_config))
            .route("/rpc", post(handle_rpc))
            .with_state(self)
    }

    /// `IGlobalFederationApi::download_client_config`
    pub fn download_client_config(&self) -> FedimintClientConfig {
        (*self.client_config).clone()
    }

    /// `IGlobalFederationApi::submit_transaction`:
    /// Translates a downstream Fedimint `Transaction` into a Sui Move `process_fedimint_tx` call.
    pub fn submit_transaction(&self, tx: &FedimintTransaction) -> Result<[u8; 32], SdkError> {
        if tx.inputs.len() != tx.spend_signatures.len() {
            return Err(SdkError::MoveAbort(
                "inputs and spend_signatures length mismatch".into(),
            ));
        }
        let txid = tx.txid();
        let spend_inputs: Vec<SpendProofInput> = tx
            .inputs
            .iter()
            .zip(tx.spend_signatures.iter())
            .map(|(inp, schnorr_sig)| SpendProofInput {
                slot: inp.slot,
                secret_or_nonce: inp.nonce.0.to_vec(),
                signature: inp.tbs_signature.clone(),
                schnorr_lock: Some((inp.nonce.clone(), schnorr_sig.clone())),
                schnorr_msg_override: None,
                htlc_preimage: None,
                htlc_expected_hash: None,
            })
            .collect();
        let outputs: Vec<(u8, BlindedMessage)> = tx
            .outputs
            .iter()
            .map(|o| (o.slot, o.blind_nonce.clone()))
            .collect();

        self.move_vault.process_fedimint_tx(
            &self.client_config.mint_tbs_keyset.keyset_id,
            txid,
            spend_inputs,
            outputs,
            0,
        )?;
        Ok(txid)
    }

    /// `IGlobalFederationApi::await_output_outcome`:
    /// Queries ONLY this guardian's co-located `Blind-Seal` server and returns its individual
    /// `BlindSignatureShare`—preserving 100% compatibility with Fedimint's client-side aggregation!
    pub async fn await_output_outcome(
        &self,
        outpoint: OutPoint,
    ) -> Result<MintOutputOutcome, SdkError> {
        let ticket_id = self
            .move_vault
            .lookup_fedimint_outpoint_ticket(outpoint.txid, outpoint.out_idx)
            .ok_or_else(|| SdkError::MoveAbort("OutPoint not finalized on Sui".into()))?;

        let resp = self
            .local_seal_peer
            .fetch_blind_sig(FetchBlindSigRequest {
                keyset_id: self.client_config.mint_tbs_keyset.keyset_id.clone(),
                ticket_id_hex: hex::encode(ticket_id),
                seal_approve_ptb_b64: None,
                ephemeral_elgamal_pk: None,
            })
            .await?;

        let SharePayload::Plain(mut shares) = resp.shares else {
            return Err(SdkError::Rpc("unexpected encrypted share".into()));
        };
        let share = shares
            .pop()
            .ok_or_else(|| SdkError::Rpc("empty share response".into()))?;
        Ok(MintOutputOutcome {
            peer_id: self.peer_id,
            share,
        })
    }

    /// `IGlobalFederationApi::session_count`
    pub fn session_count(&self) -> u64 {
        self.move_vault.fedimint_sessions().len() as u64
    }

    /// `IGlobalFederationApi::await_block`:
    /// Synthesizes & signs a deterministic Fedimint `SessionOutcome` from Sui `SessionClosedEvent`s
    /// so downstream 12-word BIP-39 wallet seed recovery works unmodified!
    pub fn await_session_outcome(&self, session_index: u64) -> Result<SignedSessionOutcome, SdkError> {
        let sessions = self.move_vault.fedimint_sessions();
        let event = sessions
            .get(session_index as usize)
            .cloned()
            .ok_or_else(|| SdkError::MoveAbort(format!("session {session_index} not closed yet")))?;
        let msg = bcs::to_bytes(&event).map_err(|e| SdkError::Rpc(e.to_string()))?;
        let sig = self.guardian_signing_key.sign(&msg);
        Ok(SignedSessionOutcome {
            peer_id: self.peer_id,
            event,
            guardian_ed25519_sig: sig.to_bytes().to_vec(),
        })
    }

    /// Locks eCash notes into an outgoing `LNv2` Lightning Gateway contract on Sui Move.
    pub fn submit_lnv2_outgoing(
        &self,
        req: &Lnv2OutgoingRequest,
    ) -> Result<Lnv2ContractOnChain, SdkError> {
        let inputs: Vec<SpendProofInput> = req
            .inputs
            .iter()
            .zip(req.spend_signatures.iter())
            .map(|(inp, sig)| SpendProofInput {
                slot: inp.slot,
                secret_or_nonce: inp.nonce.0.to_vec(),
                signature: inp.tbs_signature.clone(),
                schnorr_lock: Some((inp.nonce.clone(), sig.clone())),
                schnorr_msg_override: None,
                htlc_preimage: None,
                htlc_expected_hash: None,
            })
            .collect();

        self.move_vault.lock_lnv2_outgoing_contract(
            &self.client_config.mint_tbs_keyset.keyset_id,
            inputs,
            req.payment_hash,
            req.gateway_claim_pk.clone(),
            req.user_refund_pk.clone(),
            req.expiry_epoch,
        )
    }

    /// Issues this guardian's `BLS12-381` TPE preimage decryption share (`Seal` `/v1/fetch_key`)
    /// once the `LNv2` outgoing contract is finalized on Sui!
    pub async fn await_lnv2_tpe_share(
        &self,
        contract: &Lnv2ContractOnChain,
    ) -> Result<Lnv2TpeShareOutcome, SdkError> {
        let resp = self
            .local_seal_peer
            .fetch_ibe_key(FetchIbeKeyRequest {
                keyset_id: contract.keyset_id.clone(),
                approval_id_hex: hex::encode(contract.preimage_approval_id),
                seal_approve_ptb_b64: None,
            })
            .await?;
        Ok(Lnv2TpeShareOutcome {
            peer_id: self.peer_id,
            decryption_share: resp.share,
        })
    }
}

/// Upstream Sui Liquidity Bridge: Mints genuine downstream `fed11...` `OOBNotes` directly from
/// Sui `LBTC`/`sBTC` deposits (`1 sat = 1,000 msat`) and melts `fed11...` notes back to Sui BTC!
pub struct UpstreamSuiFedimintBridge {
    pub federation_id: FederationId,
    pub keyset_id: String,
    pub move_vault: Arc<EmbeddedMoveEngine>,
    pub seal_client: BlindSealClient,
    pub config: Arc<FedimintClientConfig>,
}

impl UpstreamSuiFedimintBridge {
    /// Locks `deposit_sats` on Sui (`deposit_sats * 1,000 msat`) and packages unblinded `OOBNotes` (`fed11...`).
    pub async fn mint_sui_btc_to_oob(
        &self,
        deposit_sats: u64,
        master_seed: &[u8; 32],
        start_derivation_idx: u64,
    ) -> Result<(String, OOBNotes), SdkError> {
        let mut remaining_msat = deposit_sats
            .checked_mul(1_000)
            .ok_or_else(|| SdkError::MoveAbort("sats overflow".into()))?;

        let mut slots = Vec::new();
        for bit in (0..self.config.mint_tbs_keyset.num_slots().min(63)).rev() {
            let val = 1u64 << bit;
            if remaining_msat >= val {
                slots.push(bit as u8);
                remaining_msat -= val;
            }
        }
        if remaining_msat != 0 {
            return Err(SdkError::MoveAbort(
                "msat amount could not be decomposed into configured slots".into(),
            ));
        }

        let mut keypairs = Vec::with_capacity(slots.len());
        let mut factors = Vec::with_capacity(slots.len());
        let mut blinded = Vec::with_capacity(slots.len());

        for (offset, _) in slots.iter().enumerate() {
            let (kp, r) =
                derive_deterministic_note_material(master_seed, start_derivation_idx + offset as u64);
            let nonce = kp.public_key();
            let (bm, _) =
                blind_message_with_factor(&nonce.0, &DstProfile::FedimintTbs, &r)?;
            keypairs.push(kp);
            factors.push(r);
            blinded.push(bm);
        }

        let ticket = self.move_vault.deposit_and_create_ticket(
            &self.keyset_id,
            deposit_sats,
            slots.clone(),
            blinded,
        )?;
        let unblinded_sigs = self
            .seal_client
            .fetch_and_unblind(&self.config.mint_tbs_keyset, &ticket, &factors, false)
            .await?;

        let notes = slots
            .into_iter()
            .zip(keypairs.into_iter())
            .zip(unblinded_sigs.into_iter())
            .map(|((slot, kp), sig)| SpendableNote {
                slot,
                spend_key_secret: kp.to_secret_bytes(),
                nonce: kp.public_key(),
                signature: sig,
            })
            .collect();

        let oob = OOBNotes {
            federation_id: self.federation_id,
            notes,
        };
        let encoded = oob.encode().map_err(SdkError::MoveAbort)?;
        Ok((encoded, oob))
    }

    /// Burns downstream `fed11...` `OOBNotes` directly on Sui Move and releases `LBTC` sats!
    pub fn melt_oob_to_sui_btc(
        &self,
        oob_str: &str,
        recipient_sui_addr: &str,
    ) -> Result<u64, SdkError> {
        let oob = OOBNotes::decode(oob_str).map_err(SdkError::MoveAbort)?;
        if !self.federation_id.matches_or_prefix(&oob.federation_id) {
            return Err(SdkError::MoveAbort("OOBNotes FederationId mismatch".into()));
        }
        let ctx_bytes = recipient_sui_addr.as_bytes();
        let mut inputs = Vec::with_capacity(oob.notes.len());
        for note in &oob.notes {
            let kp = note.keypair().map_err(SdkError::MoveAbort)?;
            let sig = kp.sign(ctx_bytes);
            inputs.push(SpendProofInput {
                slot: note.slot,
                secret_or_nonce: note.nonce.0.to_vec(),
                signature: note.signature.clone(),
                schnorr_lock: Some((note.nonce.clone(), sig)),
                schnorr_msg_override: None,
                htlc_preimage: None,
                htlc_expected_hash: None,
            });
        }
        self.move_vault
            .atomic_melt(&self.keyset_id, inputs, ctx_bytes)
    }
}

/// Reference Unmodified Downstream Fedimint Client speaking ONLY Guardian RPCs (`VirtualGuardianShim`s).
/// Performs client-side share verification, Lagrange combination, unblinding, and BIP-39 seed recovery!
pub struct DownstreamFedimintClient {
    pub config: FedimintClientConfig,
    pub master_seed: [u8; 32],
    pub next_derivation_idx: u64,
    /// `(guardian, online_flag)` to simulate arbitrary guardian outages!
    pub guardians: Vec<(VirtualGuardianShim, bool)>,
}

impl DownstreamFedimintClient {
    pub fn join_from_guardians(
        guardians: Vec<(VirtualGuardianShim, bool)>,
        master_seed: [u8; 32],
    ) -> Result<Self, SdkError> {
        let first_online = guardians
            .iter()
            .find(|(_, online)| *online)
            .ok_or_else(|| SdkError::Rpc("no online guardians".into()))?;
        let config = first_online.0.download_client_config();
        Ok(Self {
            config,
            master_seed,
            next_derivation_idx: 0,
            guardians,
        })
    }

    /// Reissues external `fed11...` `OOBNotes` into fresh wallet-controlled deterministic `SpendableNote`s
    /// by broadcasting `submit_transaction` and polling $t$-of-$n$ Guardians for `await_output_outcome`.
    pub async fn reissue_external_oob(&mut self, oob_str: &str) -> Result<Vec<SpendableNote>, SdkError> {
        let oob = OOBNotes::decode(oob_str).map_err(SdkError::MoveAbort)?;
        if !self.config.federation_id.matches_or_prefix(&oob.federation_id) {
            return Err(SdkError::MoveAbort("wrong FederationId on OOBNotes".into()));
        }

        let mut tx_inputs = Vec::with_capacity(oob.notes.len());
        let mut tx_outputs = Vec::with_capacity(oob.notes.len());
        let mut out_meta = Vec::with_capacity(oob.notes.len());

        for note in &oob.notes {
            tx_inputs.push(FedimintMintInput {
                slot: note.slot,
                nonce: note.nonce.clone(),
                tbs_signature: note.signature.clone(),
            });

            let deriv_idx = self.next_derivation_idx;
            self.next_derivation_idx += 1;
            let (new_kp, r) = derive_deterministic_note_material(&self.master_seed, deriv_idx);
            let new_nonce = new_kp.public_key();
            let (blind_nonce, _) =
                blind_message_with_factor(&new_nonce.0, &DstProfile::FedimintTbs, &r)?;

            tx_outputs.push(FedimintMintOutput {
                slot: note.slot,
                blind_nonce: blind_nonce.clone(),
            });
            out_meta.push((note.slot, new_kp, r, blind_nonce));
        }

        let mut tx = FedimintTransaction {
            inputs: tx_inputs,
            outputs: tx_outputs,
            spend_signatures: Vec::new(),
        };
        let txid = tx.txid();
        for note in &oob.notes {
            let kp = note.keypair().map_err(SdkError::MoveAbort)?;
            tx.spend_signatures.push(kp.sign(&txid));
        }

        // Broadcast `submit_transaction` to online Virtual Guardians (idempotently deduplicated on Sui!)
        let mut submitted = false;
        for (g, online) in &self.guardians {
            if *online && g.submit_transaction(&tx).is_ok() {
                submitted = true;
            }
        }
        if !submitted {
            return Err(SdkError::Rpc("failed to submit transaction to quorum".into()));
        }

        // Poll $t$-of-$n$ Guardians for `await_output_outcome` and combine/unblind ON THE CLIENT!
        let threshold = usize::from(self.config.mint_tbs_keyset.threshold);
        let mut reissued = Vec::with_capacity(out_meta.len());

        for (out_idx, (slot, new_kp, r, blind_nonce)) in out_meta.into_iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                out_idx: out_idx as u32,
            };
            let mut shares = Vec::with_capacity(threshold);
            for (g, online) in &self.guardians {
                if !*online || shares.len() >= threshold {
                    continue;
                }
                if let Ok(outcome) = g.await_output_outcome(outpoint).await {
                    let peer_pk = self
                        .config
                        .mint_tbs_keyset
                        .peer_slot_pk(outcome.peer_id, slot)?;
                    if verify_blind_share(&blind_nonce, &outcome.share, peer_pk).is_ok() {
                        shares.push(outcome.share);
                    }
                }
            }
            let blind_sig = combine_blind_shares(&shares, threshold)?;
            let unblinded = unblind_signature(&blind_sig, &r)?;
            reissued.push(SpendableNote {
                slot,
                spend_key_secret: new_kp.to_secret_bytes(),
                nonce: new_kp.public_key(),
                signature: unblinded,
            });
        }

        Ok(reissued)
    }

    /// Restores a wiped wallet strictly from its `master_seed` by downloading `SignedSessionOutcome`
    /// history from $t$-of-$n$ Guardians, verifying Guardian Ed25519 quorum signatures, matching
    /// deterministic `BlindNonce`s, and re-fetching `await_output_outcome` shares!
    pub async fn recover_from_seed_phrase(
        &self,
        max_scan_gap: u64,
    ) -> Result<Vec<SpendableNote>, SdkError> {
        let threshold = usize::from(self.config.mint_tbs_keyset.threshold);
        let session_count = self
            .guardians
            .iter()
            .find(|(_, online)| *online)
            .map(|(g, _)| g.session_count())
            .unwrap_or(0);

        // Precompute candidate deterministic `BlindNonce`s from `master_seed`
        let mut candidates = Vec::new();
        for idx in 0..max_scan_gap {
            let (kp, r) = derive_deterministic_note_material(&self.master_seed, idx);
            let (bm, _) =
                blind_message_with_factor(&kp.public_key().0, &DstProfile::FedimintTbs, &r)?;
            candidates.push((kp, r, bm));
        }

        let mut recovered = Vec::new();
        for s_idx in 0..session_count {
            let mut valid_outcomes = Vec::new();
            for (g, online) in &self.guardians {
                if !*online {
                    continue;
                }
                if let Ok(signed) = g.await_session_outcome(s_idx) {
                    let gpk_bytes = self.config.guardian_ed25519_pks[usize::from(signed.peer_id)];
                    let vk = VerifyingKey::from_bytes(&gpk_bytes)
                        .map_err(|e| SdkError::Rpc(e.to_string()))?;
                    let msg = bcs::to_bytes(&signed.event)
                        .map_err(|e| SdkError::Rpc(e.to_string()))?;
                    let sig = ed25519_dalek::Signature::from_slice(&signed.guardian_ed25519_sig)
                        .map_err(|e| SdkError::Rpc(e.to_string()))?;
                    if vk.verify(&msg, &sig).is_ok() {
                        valid_outcomes.push(signed.event);
                    }
                }
            }
            if valid_outcomes.len() < threshold {
                return Err(SdkError::Rpc("insufficient signed SessionOutcomes".into()));
            }
            let session = &valid_outcomes[0];

            for (txid, outputs) in &session.outputs_by_tx {
                for (out_idx, (slot, bm)) in outputs.iter().enumerate() {
                    if let Some((kp, r, _)) = candidates.iter().find(|(_, _, c_bm)| c_bm == bm) {
                        let outpoint = OutPoint {
                            txid: *txid,
                            out_idx: out_idx as u32,
                        };
                        let mut shares = Vec::new();
                        for (g, online) in &self.guardians {
                            if !*online || shares.len() >= threshold {
                                continue;
                            }
                            if let Ok(out) = g.await_output_outcome(outpoint).await {
                                shares.push(out.share);
                            }
                        }
                        let bsig = combine_blind_shares(&shares, threshold)?;
                        let sig = unblind_signature(&bsig, r)?;
                        recovered.push(SpendableNote {
                            slot: *slot,
                            spend_key_secret: kp.to_secret_bytes(),
                            nonce: kp.public_key(),
                            signature: sig,
                        });
                    }
                }
            }
        }
        Ok(recovered)
    }
}

/// Helper for `gatewayd` (`fedimint-lnv2`) to threshold-decrypt the 32-byte Lightning preimage
/// from $t$-of-$n$ Virtual Guardians once the `LNv2` contract locks on Sui!
pub async fn gateway_decrypt_lnv2_preimage(
    guardians: &[(VirtualGuardianShim, bool)],
    config: &FedimintClientConfig,
    contract: &Lnv2ContractOnChain,
    tpe_ciphertext: & blind_seal_crypto::ibe_tpe::IbeTpeCiphertext,
) -> Result<[u8; 32], SdkError> {
    let threshold = usize::from(config.mint_tbs_keyset.threshold);
    let mut shares = Vec::with_capacity(threshold);
    let mut patched_ct = tpe_ciphertext.clone();
    patched_ct.identity = contract.contract_id.to_vec();

    for (g, online) in guardians {
        if !*online || shares.len() >= threshold {
            continue;
        }
        if let Ok(res) = g.await_lnv2_tpe_share(contract).await {
            let peer_pk_g1 = &config.mint_tbs_keyset.ibe_peer_pks_g1[usize::from(res.peer_id)];
            if verify_ibe_decryption_share(
                peer_pk_g1,
                b"fedimint_lnv2",
                &contract.contract_id,
                &res.decryption_share,
            )
            .is_ok()
            {
                shares.push(res.decryption_share);
            }
        }
    }

    let raw = ibe_combine_and_decrypt(&patched_ct, &shares, threshold)?;
    raw.try_into()
        .map_err(|_| SdkError::MoveAbort("decrypted preimage must be 32 bytes".into()))
}

type ApiErr = (StatusCode, Json<Value>);

async fn handle_config(State(s): State<VirtualGuardianShim>) -> Json<FedimintClientConfig> {
    Json(s.download_client_config())
}

async fn handle_rpc(
    State(s): State<VirtualGuardianShim>,
    Json(req): Json<GuardianRpcRequest>,
) -> Result<Json<Value>, ApiErr> {
    let map_e = |e: SdkError| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
    };
    match req {
        GuardianRpcRequest::DownloadClientConfig => {
            Ok(Json(serde_json::to_value(s.download_client_config()).unwrap()))
        }
        GuardianRpcRequest::SubmitTransaction(tx) => {
            let txid = s.submit_transaction(&tx).map_err(map_e)?;
            Ok(Json(json!({ "txid": hex::encode(txid) })))
        }
        GuardianRpcRequest::AwaitOutputOutcome(op) => {
            let out = s.await_output_outcome(op).await.map_err(map_e)?;
            Ok(Json(serde_json::to_value(out).unwrap()))
        }
        GuardianRpcRequest::SessionCount => Ok(Json(json!({ "session_count": s.session_count() }))),
        GuardianRpcRequest::AwaitSessionOutcome { session_index } => {
            let out = s.await_session_outcome(session_index).map_err(map_e)?;
            Ok(Json(serde_json::to_value(out).unwrap()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use blind_seal_crypto::{
        dkg::deal_multi_slot_keyset,
        ibe_tpe::ibe_encrypt,
        schnorr::SpendKeypair,
        tbs::{blind_message, verify_unblinded},
    };
    use blind_seal_sdk::sui_backend::VaultConfig;
    use blind_seal_server::BlindSealKeyServerState;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use wire::InviteCode;

    use super::*;

    struct TestFederationSetup {
        config: Arc<FedimintClientConfig>,
        move_vault: Arc<EmbeddedMoveEngine>,
        shims: Vec<VirtualGuardianShim>,
        bridge: UpstreamSuiFedimintBridge,
    }

    fn setup_3_of_4_sui_backed_fedimint() -> TestFederationSetup {
        // 24 msat power-of-2 tiers: 2^0 (1 msat) up to 2^23 (~8.3M msat = 8,388 sats)
        let (pub_ks, shares) =
            deal_multi_slot_keyset("fedimint_btc_msat_01", "msat", 3, 4, 24, &mut OsRng).unwrap();

        let move_vault = Arc::new(EmbeddedMoveEngine::new(1)); // Close a session on every tx!
        move_vault.register_vault(VaultConfig {
            keyset: pub_ks.clone(),
            dst: DstProfile::FedimintTbs,
            notes_per_coin_unit: 1_000, // 1 Sui BTC sat = 1,000 Fedimint msat!
            hourly_melt_cap_notes: 100_000_000,
            input_fee_ppk: 0,
        });

        let mut guardian_keys = Vec::new();
        let mut guardian_pks = Vec::new();
        for _ in 0..4 {
            let sk = SigningKey::generate(&mut OsRng);
            guardian_pks.push(sk.verifying_key().to_bytes());
            guardian_keys.push(sk);
        }

        let fed_id = FedimintClientConfig::compute_federation_id(&pub_ks, &guardian_pks);
        let config = Arc::new(FedimintClientConfig {
            federation_id: fed_id,
            federation_name: "Sui-Seal Upstream Fedimint".into(),
            active_modules: vec!["fedimint-mint".into(), "fedimint-lnv2".into()],
            mint_tbs_keyset: pub_ks.clone(),
            guardian_ed25519_pks: guardian_pks,
        });

        let mut seal_peers: Vec<Arc<dyn BlindSealPeerHandler>> = Vec::new();
        let mut shims = Vec::new();
        for peer in 0..4u16 {
            let seal_node = Arc::new(BlindSealKeyServerState::new(
                peer,
                vec![(pub_ks.clone(), shares[usize::from(peer)].clone())],
                move_vault.clone(),
            ));
            shims.push(VirtualGuardianShim::new(
                peer,
                config.clone(),
                guardian_keys[usize::from(peer)].clone(),
                seal_node.clone(),
                move_vault.clone(),
            ));
            seal_peers.push(seal_node);
        }

        let bridge = UpstreamSuiFedimintBridge {
            federation_id: fed_id,
            keyset_id: pub_ks.keyset_id.clone(),
            move_vault: move_vault.clone(),
            seal_client: BlindSealClient::new_with_handlers(seal_peers),
            config: config.clone(),
        };

        TestFederationSetup {
            config,
            move_vault,
            shims,
            bridge,
        }
    }

    #[tokio::test]
    async fn test_upstream_sui_mint_downstream_reissue_and_bip39_seed_recovery() {
        let env = setup_3_of_4_sui_backed_fedimint();

        // Verify standard Bech32 `fed11...` InviteCode round-trip (with Iroh endpoints!)
        let invite = InviteCode {
            federation_id: env.config.federation_id,
            peers: (0..4u16)
                .map(|p| (p, format!("ws://127.0.0.1:{}", 8173 + p)))
                .collect(),
            api_secret: None,
            iroh_endpoints: (0..4u16)
                .map(|p| wire::IrohPeerEndpoint {
                    peer_id: p,
                    node_id_hex: hex::encode(env.config.guardian_ed25519_pks[usize::from(p)]),
                    relay_url: "https://relay.iroh.network".into(),
                    alpn: "fedimint/rpc/0".into(),
                })
                .collect(),
        };
        let encoded_invite = invite.encode().unwrap();
        assert!(encoded_invite.starts_with("fed11"));
        let decoded_invite = InviteCode::decode(&encoded_invite).unwrap();
        assert_eq!(decoded_invite.federation_id, env.config.federation_id);
        assert_eq!(decoded_invite.iroh_endpoints.len(), 4);

        // 1. UPSTREAM MINT: Lock 5 sats (`5,000 msat` = 4096 + 512 + 256 + 128 + 8 msat) on Sui!
        let lp_seed = [0x11u8; 32];
        let (oob_str, oob_parsed) = env
            .bridge
            .mint_sui_btc_to_oob(5, &lp_seed, 0)
            .await
            .unwrap();
        assert!(oob_str.starts_with("fed11"));
        assert_eq!(oob_parsed.total_msat(), 5_000);
        assert_eq!(
            env.move_vault
                .vault_reserve_coin_units("fedimint_btc_msat_01")
                .unwrap(),
            5
        );

        // 2. DOWNSTREAM WALLET REISSUE (with Guardian #2 OFFLINE to prove 3-of-4 BFT tolerance!):
        let bob_seed = [0x77u8; 32];
        let guardians_with_outage: Vec<_> = env
            .shims
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, g)| (g, idx != 2))
            .collect();

        let mut bob_wallet =
            DownstreamFedimintClient::join_from_guardians(guardians_with_outage.clone(), bob_seed)
                .unwrap();
        let bob_notes = bob_wallet.reissue_external_oob(&oob_str).await.unwrap();
        let bob_total: u64 = bob_notes.iter().map(SpendableNote::amount_msat).sum();
        assert_eq!(bob_total, 5_000);

        // Reissuing the same `fed11...` string a second time MUST fail (double-spend prevented on Sui!)
        assert!(bob_wallet.reissue_external_oob(&oob_str).await.is_err());

        // 3. ANTI-FRONT-RUNNING EXPLOIT CHECK:
        //    Attacker intercepts Bob's unblinded note in mempool and tries to substitute attacker's BlindNonce
        //    without Bob's `SpendKey` Schnorr signature over the mutated `txid` -> MUST ABORT!
        let stolen_note = &bob_notes[0];
        let (attacker_bm, _) =
            blind_message(b"attacker_nonce", &DstProfile::FedimintTbs, &mut OsRng).unwrap();
        let forged_kp = SpendKeypair::random(&mut OsRng);
        let mut hijack_tx = FedimintTransaction {
            inputs: vec![FedimintMintInput {
                slot: stolen_note.slot,
                nonce: stolen_note.nonce.clone(),
                tbs_signature: stolen_note.signature.clone(),
            }],
            outputs: vec![FedimintMintOutput {
                slot: stolen_note.slot,
                blind_nonce: attacker_bm,
            }],
            spend_signatures: Vec::new(),
        };
        let hijack_txid = hijack_tx.txid();
        hijack_tx.spend_signatures.push(forged_kp.sign(&hijack_txid));
        assert!(env.shims[0].submit_transaction(&hijack_tx).is_err());

        // 4. WIPE BOB'S PHONE & RECOVER 100% OF FUNDS FROM `bob_seed` VIA SIGNED `SessionOutcome`s!
        let fresh_restored_client =
            DownstreamFedimintClient::join_from_guardians(guardians_with_outage, bob_seed).unwrap();
        let recovered_notes = fresh_restored_client
            .recover_from_seed_phrase(16)
            .await
            .unwrap();
        assert_eq!(recovered_notes.len(), bob_notes.len());
        let recovered_msat: u64 = recovered_notes.iter().map(SpendableNote::amount_msat).sum();
        assert_eq!(recovered_msat, 5_000);

        // 5. UPSTREAM MELT: Bob exports his `fed11...` notes and melts all `5,000 msat` back into `5 sats` on Sui!
        let bob_oob_out = OOBNotes {
            federation_id: env.config.federation_id,
            notes: recovered_notes,
        }
        .encode()
        .unwrap();
        let released_sats = env
            .bridge
            .melt_oob_to_sui_btc(&bob_oob_out, "0xcccc000000000000000000000000000000000055")
            .unwrap();
        assert_eq!(released_sats, 5);
        assert_eq!(
            env.move_vault
                .vault_reserve_coin_units("fedimint_btc_msat_01")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_fedimint_lnv2_lightning_gateway_tpe_end_to_end_settlement() {
        let env = setup_3_of_4_sui_backed_fedimint();

        // 1. Mint 2 sats (`2,000 msat`) upstream to Alice
        let alice_seed = [0x33u8; 32];
        let (_, alice_oob) = env
            .bridge
            .mint_sui_btc_to_oob(2, &alice_seed, 0)
            .await
            .unwrap();
        assert_eq!(alice_oob.total_msat(), 2_000);

        // 2. Lightning recipient generates a 32-byte Bolt11 preimage & payment_hash
        let ln_preimage = [0x5Au8; 32];
        let payment_hash: [u8; 32] = Sha256::digest(ln_preimage).into();
        let gateway_claim_kp = SpendKeypair::random(&mut OsRng);
        let alice_refund_kp = SpendKeypair::random(&mut OsRng);

        // 3. Alice locks her `2,000 msat` notes into an outgoing `LNv2` contract on Sui
        let mut lnv2_inputs = Vec::new();
        let mut lnv2_sigs = Vec::new();
        for note in &alice_oob.notes {
            let kp = note.keypair().unwrap();
            lnv2_sigs.push(kp.sign(&payment_hash));
            lnv2_inputs.push(FedimintMintInput {
                slot: note.slot,
                nonce: note.nonce.clone(),
                tbs_signature: note.signature.clone(),
            });
        }

        // Placeholder ciphertext passed on submission; TPE encrypts preimage to `contract.contract_id`
        let dummy_ct = ibe_encrypt(
            &env.config.mint_tbs_keyset.ibe_agg_pk_g1,
            b"fedimint_lnv2",
            &payment_hash,
            &ln_preimage,
            &mut OsRng,
        )
        .unwrap();

        let contract = env.shims[0]
            .submit_lnv2_outgoing(&Lnv2OutgoingRequest {
                inputs: lnv2_inputs,
                spend_signatures: lnv2_sigs,
                payment_hash,
                tpe_encrypted_preimage: dummy_ct,
                gateway_claim_pk: gateway_claim_kp.public_key(),
                user_refund_pk: alice_refund_kp.public_key(),
                expiry_epoch: 500,
            })
            .unwrap();
        assert_eq!(contract.amount_msat, 2_000);

        // Encrypt the 32-byte preimage via `BLS12-381` TPE bound to `contract.contract_id`
        let tpe_ct = ibe_encrypt(
            &env.config.mint_tbs_keyset.ibe_agg_pk_g1,
            b"fedimint_lnv2",
            &contract.contract_id,
            &ln_preimage,
            &mut OsRng,
        )
        .unwrap();

        // 4. `gatewayd` collects 3-of-4 TPE decryption shares from Virtual Guardians & recovers `ln_preimage`!
        let online_guardians: Vec<_> = env.shims.iter().cloned().map(|g| (g, true)).collect();
        let decrypted_preimage = gateway_decrypt_lnv2_preimage(
            &online_guardians,
            &env.config,
            &contract,
            &tpe_ct,
        )
        .await
        .unwrap();
        assert_eq!(decrypted_preimage, ln_preimage);

        // 5. `gatewayd` settles the `LNv2` contract on Sui using `decrypted_preimage` and claims `2,000 msat` (`1024 + 512 + 256 + 128 + 64 + 16`)!
        let gw_slots = vec![10u8, 9, 8, 7, 6, 4]; // sum = 2,000 msat
        let mut gw_blinded = Vec::new();
        let mut gw_factors = Vec::new();
        let mut gw_nonces = Vec::new();
        for idx in 0..gw_slots.len() {
            let n = format!("gateway_claimed_note_{idx}").into_bytes();
            let (bm, r) = blind_message(&n, &DstProfile::FedimintTbs, &mut OsRng).unwrap();
            gw_nonces.push(n);
            gw_blinded.push(bm);
            gw_factors.push(r);
        }

        let gw_sig = gateway_claim_kp.sign(&contract.contract_id);
        let claim_ticket = env
            .move_vault
            .claim_lnv2_contract_with_preimage(
                contract.contract_id,
                &decrypted_preimage,
                &gw_sig,
                gw_slots.clone(),
                gw_blinded,
            )
            .unwrap();

        let gw_sigs = env
            .bridge
            .seal_client
            .fetch_and_unblind(&env.config.mint_tbs_keyset, &claim_ticket, &gw_factors, false)
            .await
            .unwrap();
        for ((slot, nonce), sig) in gw_slots.iter().zip(gw_nonces.iter()).zip(gw_sigs.iter()) {
            verify_unblinded(
                nonce,
                sig,
                env.config.mint_tbs_keyset.slot_pk(*slot).unwrap(),
                &DstProfile::FedimintTbs,
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn test_bech32_tlv_binary_wire_and_jsonrpsee_websocket_guardian_rpc() {
        use crate::{
            encoding::{encode_tlv_stream, FedimintEncodable, TlvRecord},
            ws_rpc::{compute_ws_accept_key, serve_ws_jsonrpc_stream, WsFederationRpcClient},
        };

        // 1. Verify RFC 6455 Section 4.2.2 test vector for Sec-WebSocket-Accept
        assert_eq!(
            compute_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );

        let env = setup_3_of_4_sui_backed_fedimint();
        let (oob_str, oob) = env
            .bridge
            .mint_sui_btc_to_oob(1, &[0x44u8; 32], 0)
            .await
            .unwrap();
        assert!(oob_str.starts_with("fed11"));

        // Corrupting a character in Bech32 `fed11...` MUST fail BCH checksum verification!
        let mut corrupted = oob_str.clone();
        let last_ch = if corrupted.ends_with('q') { 'p' } else { 'q' };
        corrupted.pop();
        corrupted.push(last_ch);
        assert!(OOBNotes::decode(&corrupted).is_err());

        // Forward-compatibility check: appending an unknown TLV variant `99` must decode cleanly!
        let mut raw_with_unknown = Vec::new();
        let mut base_records = crate::encoding::decode_tlv_stream(
            &mut oob.consensus_encode_to_vec().as_slice(),
        )
        .unwrap();
        base_records.push(TlvRecord {
            variant: 99,
            bytes: b"future_fip_metadata".to_vec(),
        });
        encode_tlv_stream(&base_records, &mut raw_with_unknown);
        let decoded_fwd =
            <OOBNotes as crate::encoding::FedimintDecodable>::consensus_decode_whole(
                &raw_with_unknown,
            )
            .unwrap();
        assert_eq!(decoded_fwd.total_msat(), 1_000);

        // 2. Spin up 3-of-4 Virtual Guardians over RFC 6455 WebSocket streams (`tokio::io::duplex`)
        //    and execute binary `SerdeModuleEncoding` reissuance via `WsFederationRpcClient`!
        let mut ws_clients = Vec::new();
        for peer in 0..3usize {
            let (client_io, server_io) = tokio::io::duplex(65_536);
            let shim = env.shims[peer].clone();
            tokio::spawn(async move {
                let _ = serve_ws_jsonrpc_stream(shim, server_io).await;
            });
            ws_clients.push((peer as u16, WsFederationRpcClient::new(client_io)));
        }

        let ver = ws_clients[0]
            .1
            .call_erased("version", Value::Null)
            .await
            .unwrap();
        assert_eq!(ver.pointer("/core/minor").and_then(|v| v.as_u64()), Some(5));

        let iroh_info = ws_clients[0]
            .1
            .call_erased("iroh_endpoint_info", Value::Null)
            .await
            .unwrap();
        assert_eq!(
            iroh_info.get("alpn").and_then(|v| v.as_str()),
            Some("fedimint/rpc/0")
        );

        // Construct binary `FedimintTransaction` spending the first note (`slot` -> `slot`)
        let in_note = &oob.notes[0];
        let (out_kp, out_r) = derive_deterministic_note_material(&[0x99u8; 32], 0);
        let (out_bm, _) =
            blind_message_with_factor(&out_kp.public_key().0, &DstProfile::FedimintTbs, &out_r)
                .unwrap();
        let mut tx = FedimintTransaction {
            inputs: vec![FedimintMintInput {
                slot: in_note.slot,
                nonce: in_note.nonce.clone(),
                tbs_signature: in_note.signature.clone(),
            }],
            outputs: vec![FedimintMintOutput {
                slot: in_note.slot,
                blind_nonce: out_bm.clone(),
            }],
            spend_signatures: Vec::new(),
        };
        let txid = tx.txid();
        tx.spend_signatures
            .push(in_note.keypair().unwrap().sign(&txid));

        let tx_hex = tx.consensus_encode_to_hex();
        let submit_res = ws_clients[0]
            .1
            .call_erased("submit_transaction", json!(tx_hex))
            .await
            .unwrap();
        assert_eq!(
            submit_res.get("txid").and_then(|v| v.as_str()),
            Some(hex::encode(txid).as_str())
        );

        // Fetch binary `SerdeModuleEncoding` output shares over WebSocket from all 3 online guardians!
        let op_hex = OutPoint { txid, out_idx: 0 }.consensus_encode_to_hex();
        let mut shares = Vec::new();
        for (peer_id, ws) in &mut ws_clients {
            let res = ws
                .call_erased("await_output_outcome", json!(op_hex))
                .await
                .unwrap();
            let mod_hex = res.get("serde_module_hex").and_then(|v| v.as_str()).unwrap();
            let parsed = MintOutputOutcome::from_serde_module_hex(*peer_id, mod_hex).unwrap();
            let peer_pk = env
                .config
                .mint_tbs_keyset
                .peer_slot_pk(*peer_id, in_note.slot)
                .unwrap();
            verify_blind_share(&out_bm, &parsed.share, peer_pk).unwrap();
            shares.push(parsed.share);
        }

        let bsig = combine_blind_shares(&shares, 3).unwrap();
        let unblinded = unblind_signature(&bsig, &out_r).unwrap();
        verify_unblinded(
            &out_kp.public_key().0,
            &unblinded,
            env.config.mint_tbs_keyset.slot_pk(in_note.slot).unwrap(),
            &DstProfile::FedimintTbs,
        )
        .unwrap();

        let block_res = ws_clients[0]
            .1
            .call_erased("await_block", json!({ "index": 0 }))
            .await
            .unwrap();
        assert_eq!(block_res.get("peer_id").and_then(|v| v.as_u64()), Some(0));

        for (_, ws) in ws_clients {
            ws.close().await.unwrap();
        }
    }
}
