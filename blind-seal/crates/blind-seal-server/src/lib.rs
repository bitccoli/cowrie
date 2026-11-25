use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use blind_seal_crypto::{
    dkg::{
        DkgParticipant, DkgRound1Broadcast, DkgRound2Package, GuardianSecretKeyShare, PublicKeyset,
    },
    elgamal::encrypt_g1_share,
    ibe_tpe::derive_ibe_decryption_share,
    tbs::sign_blinded_message,
};
use blind_seal_sdk::{
    api::{
        FetchBlindSigRequest, FetchBlindSigResponse, FetchIbeKeyRequest, FetchIbeKeyResponse,
        KeysetsResponse, SharePayload,
    },
    client::BlindSealPeerHandler,
    sui_backend::{BoxFuture, SuiConsensusBackend},
    SdkError,
};
use rand::{rngs::OsRng, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgRound1HttpReq {
    pub ceremony_id: String,
    pub threshold: u16,
    pub num_peers: u16,
    pub num_slots: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DkgInboxDeliverReq {
    pub ceremony_id: String,
    pub package: DkgRound2Package,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgPushSharesHttpReq {
    pub ceremony_id: String,
    /// Ordered base URLs `peer_urls[0..num_peers]` so this guardian pushes each private
    /// `DkgRound2Package` directly peer-to-peer to `POST {peer_urls[j]}/v1/dkg/inbox`!
    pub peer_urls: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgFinalizeHttpReq {
    pub ceremony_id: String,
    pub keyset_id: String,
    pub unit: String,
    pub broadcasts: Vec<DkgRound1Broadcast>,
}

struct ActiveCeremony {
    participant: DkgParticipant,
    inbox: Vec<DkgRound2Package>,
}

#[derive(Clone)]
pub struct BlindSealKeyServerState {
    pub peer_id: u16,
    pub keysets: Arc<RwLock<HashMap<String, (PublicKeyset, GuardianSecretKeyShare)>>>,
    pub sui_backend: Arc<dyn SuiConsensusBackend>,
    pub keys_persist_dir: Option<Arc<PathBuf>>,
    dkg_ceremonies: Arc<Mutex<HashMap<String, ActiveCeremony>>>,
}

impl BlindSealKeyServerState {
    pub fn new(
        peer_id: u16,
        loaded_keysets: Vec<(PublicKeyset, GuardianSecretKeyShare)>,
        sui_backend: Arc<dyn SuiConsensusBackend>,
    ) -> Self {
        Self::new_with_storage(peer_id, loaded_keysets, sui_backend, None)
    }

    pub fn new_with_storage(
        peer_id: u16,
        loaded_keysets: Vec<(PublicKeyset, GuardianSecretKeyShare)>,
        sui_backend: Arc<dyn SuiConsensusBackend>,
        keys_persist_dir: Option<PathBuf>,
    ) -> Self {
        let mut map = HashMap::with_capacity(loaded_keysets.len());
        for (pk, sk) in loaded_keysets {
            assert_eq!(
                sk.peer_id, peer_id,
                "secret share peer_id mismatch on Blind-Seal server"
            );
            map.insert(pk.keyset_id.clone(), (pk, sk));
        }
        Self {
            peer_id,
            keysets: Arc::new(RwLock::new(map)),
            sui_backend,
            keys_persist_dir: keys_persist_dir.map(Arc::new),
            dkg_ceremonies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/keysets", get(handle_get_keysets))
            .route("/v1/fetch_blind_sig", post(handle_fetch_blind_sig))
            .route("/v1/fetch_key", post(handle_fetch_ibe_key))
            // Networked Multi-Host Dealer-Free Pedersen DKG Ceremony Routes
            .route("/v1/dkg/round1", post(handle_dkg_round1))
            .route("/v1/dkg/inbox", post(handle_dkg_inbox))
            .route("/v1/dkg/push_shares", post(handle_dkg_push_shares))
            .route("/v1/dkg/finalize", post(handle_dkg_finalize))
            .with_state(self)
    }

    /// Step 1 of Networked Pedersen DKG: Generates secret polynomials in RAM and returns ONLY
    /// public `G2`/`G1` Feldman commitments (`DkgRound1Broadcast`).
    pub fn dkg_start_round1(&self, req: DkgRound1HttpReq) -> Result<DkgRound1Broadcast, SdkError> {
        let (participant, bcast) = DkgParticipant::new(
            self.peer_id,
            req.threshold,
            req.num_peers,
            req.num_slots,
            &mut OsRng,
        )?;
        let self_pkg = participant
            .round2_packages()
            .into_iter()
            .find(|p| p.recipient_peer == self.peer_id)
            .unwrap();
        self.dkg_ceremonies.lock().unwrap().insert(
            req.ceremony_id,
            ActiveCeremony {
                participant,
                inbox: vec![self_pkg],
            },
        );
        Ok(bcast)
    }

    /// Exports private Round-2 packages addressed to all OTHER peers so this guardian can deliver
    /// them directly peer-to-peer (never passing private shares through a coordinator!).
    pub fn dkg_outbound_packages(&self, ceremony_id: &str) -> Result<Vec<DkgRound2Package>, SdkError> {
        let guard = self.dkg_ceremonies.lock().unwrap();
        let c = guard
            .get(ceremony_id)
            .ok_or_else(|| SdkError::MoveAbort("unknown DKG ceremony_id".into()))?;
        Ok(c.participant
            .round2_packages()
            .into_iter()
            .filter(|p| p.recipient_peer != self.peer_id)
            .collect())
    }

    /// Receives a private point-to-point `DkgRound2Package` from another guardian peer.
    pub fn dkg_receive_inbox(&self, req: DkgInboxDeliverReq) -> Result<(), SdkError> {
        if req.package.recipient_peer != self.peer_id {
            return Err(SdkError::MoveAbort("DKG package recipient_peer mismatch".into()));
        }
        let mut guard = self.dkg_ceremonies.lock().unwrap();
        let c = guard
            .get_mut(&req.ceremony_id)
            .ok_or_else(|| SdkError::MoveAbort("unknown DKG ceremony_id".into()))?;
        if !c
            .inbox
            .iter()
            .any(|p| p.sender_peer == req.package.sender_peer)
        {
            c.inbox.push(req.package);
        }
        Ok(())
    }

    /// Verifies all Feldman commitments against received Round-2 shares, persists this guardian's
    /// private share locally (if `--keys-dir` is configured), activates the keyset live in RAM,
    /// and returns ONLY the `PublicKeyset`!
    pub fn dkg_finalize(&self, req: DkgFinalizeHttpReq) -> Result<PublicKeyset, SdkError> {
        let ceremony = self
            .dkg_ceremonies
            .lock()
            .unwrap()
            .remove(&req.ceremony_id)
            .ok_or_else(|| SdkError::MoveAbort("unknown or already finalized DKG ceremony".into()))?;

        let (pub_ks, sk_share) = ceremony.participant.finalize(
            &req.keyset_id,
            &req.unit,
            &req.broadcasts,
            &ceremony.inbox,
        )?;

        if let Some(dir) = &self.keys_persist_dir {
            fs::create_dir_all(dir.as_ref()).map_err(|e| SdkError::Rpc(e.to_string()))?;
            let pub_path = dir.join(format!("{}_public.json", req.keyset_id));
            let sk_path = dir.join(format!("{}_guardian_{}.json", req.keyset_id, self.peer_id));
            fs::write(
                &pub_path,
                serde_json::to_string_pretty(&pub_ks).map_err(|e| SdkError::Rpc(e.to_string()))?,
            )
            .map_err(|e| SdkError::Rpc(e.to_string()))?;
            fs::write(
                &sk_path,
                serde_json::to_string_pretty(&sk_share)
                    .map_err(|e| SdkError::Rpc(e.to_string()))?,
            )
            .map_err(|e| SdkError::Rpc(e.to_string()))?;
        }

        self.keysets
            .write()
            .unwrap()
            .insert(pub_ks.keyset_id.clone(), (pub_ks.clone(), sk_share));
        Ok(pub_ks)
    }

    pub async fn process_blind_sig_request(
        &self,
        req: FetchBlindSigRequest,
    ) -> Result<FetchBlindSigResponse, SdkError> {
        let sk_share = {
            let guard = self.keysets.read().unwrap();
            guard
                .get(&req.keyset_id)
                .map(|(_, sk)| sk.clone())
                .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset_id {}", req.keyset_id)))?
        };

        let raw_id = hex::decode(&req.ticket_id_hex)
            .map_err(|_| SdkError::MoveAbort("ticket_id_hex must be 64-char hex".into()))?;
        let ticket_id: [u8; 32] = raw_id
            .try_into()
            .map_err(|_| SdkError::MoveAbort("ticket_id must be 32 bytes".into()))?;

        let ticket = self
            .sui_backend
            .verify_and_load_blind_ticket(
                &req.keyset_id,
                ticket_id,
                req.seal_approve_ptb_b64.as_deref(),
            )
            .await?;

        let mut plain_shares = Vec::with_capacity(ticket.blinded_messages.len());
        for (&slot, bm) in ticket.slots.iter().zip(ticket.blinded_messages.iter()) {
            let scalar = sk_share.slot_scalar(slot)?;
            let share = sign_blinded_message(self.peer_id, &scalar, bm)?;
            plain_shares.push(share);
        }

        let shares = if let Some(epk) = &req.ephemeral_elgamal_pk {
            let mut rng = thread_rng();
            let mut enc = Vec::with_capacity(plain_shares.len());
            for s in &plain_shares {
                enc.push(encrypt_g1_share(self.peer_id, &s.share_g1, epk, &mut rng)?);
            }
            SharePayload::Encrypted(enc)
        } else {
            SharePayload::Plain(plain_shares)
        };

        Ok(FetchBlindSigResponse {
            peer_id: self.peer_id,
            ticket_id_hex: req.ticket_id_hex,
            shares,
        })
    }

    pub async fn process_ibe_key_request(
        &self,
        req: FetchIbeKeyRequest,
    ) -> Result<FetchIbeKeyResponse, SdkError> {
        let sk_share = {
            let guard = self.keysets.read().unwrap();
            guard
                .get(&req.keyset_id)
                .map(|(_, sk)| sk.clone())
                .ok_or_else(|| SdkError::MoveAbort(format!("unknown keyset_id {}", req.keyset_id)))?
        };

        let raw_id = hex::decode(&req.approval_id_hex)
            .map_err(|_| SdkError::MoveAbort("approval_id_hex must be 64-char hex".into()))?;
        let approval_id: [u8; 32] = raw_id
            .try_into()
            .map_err(|_| SdkError::MoveAbort("approval_id must be 32 bytes".into()))?;

        let approval = self
            .sui_backend
            .verify_and_load_ibe_approval(
                &req.keyset_id,
                approval_id,
                req.seal_approve_ptb_b64.as_deref(),
            )
            .await?;

        let ibe_scalar = sk_share.ibe_scalar()?;
        let share = derive_ibe_decryption_share(
            self.peer_id,
            &ibe_scalar,
            &approval.namespace,
            &approval.identity,
        )?;

        Ok(FetchIbeKeyResponse { share })
    }
}

impl BlindSealPeerHandler for BlindSealKeyServerState {
    fn fetch_blind_sig<'a>(
        &'a self,
        req: FetchBlindSigRequest,
    ) -> BoxFuture<'a, Result<FetchBlindSigResponse, SdkError>> {
        Box::pin(async move { self.process_blind_sig_request(req).await })
    }

    fn fetch_ibe_key<'a>(
        &'a self,
        req: FetchIbeKeyRequest,
    ) -> BoxFuture<'a, Result<FetchIbeKeyResponse, SdkError>> {
        Box::pin(async move { self.process_ibe_key_request(req).await })
    }
}

type ApiErr = (StatusCode, Json<Value>);

fn map_sdk_err(err: SdkError) -> ApiErr {
    match err {
        SdkError::MoveAbort(m) | SdkError::NullifierAlreadySpent(m) => {
            (StatusCode::FORBIDDEN, Json(json!({ "error": m })))
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": other.to_string() })),
        ),
    }
}

async fn handle_get_keysets(State(st): State<BlindSealKeyServerState>) -> Json<KeysetsResponse> {
    let mut keysets: Vec<PublicKeyset> = st
        .keysets
        .read()
        .unwrap()
        .values()
        .map(|(pk, _)| pk.clone())
        .collect();
    keysets.sort_by(|a, b| a.keyset_id.cmp(&b.keyset_id));
    Json(KeysetsResponse {
        peer_id: st.peer_id,
        keysets,
    })
}

async fn handle_fetch_blind_sig(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<FetchBlindSigRequest>,
) -> Result<Json<FetchBlindSigResponse>, ApiErr> {
    st.process_blind_sig_request(req)
        .await
        .map(Json)
        .map_err(map_sdk_err)
}

async fn handle_fetch_ibe_key(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<FetchIbeKeyRequest>,
) -> Result<Json<FetchIbeKeyResponse>, ApiErr> {
    st.process_ibe_key_request(req)
        .await
        .map(Json)
        .map_err(map_sdk_err)
}

async fn handle_dkg_round1(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<DkgRound1HttpReq>,
) -> Result<Json<DkgRound1Broadcast>, ApiErr> {
    st.dkg_start_round1(req).map(Json).map_err(map_sdk_err)
}

async fn handle_dkg_inbox(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<DkgInboxDeliverReq>,
) -> Result<Json<Value>, ApiErr> {
    st.dkg_receive_inbox(req).map_err(map_sdk_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn handle_dkg_push_shares(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<DkgPushSharesHttpReq>,
) -> Result<Json<Value>, ApiErr> {
    let pkgs = st
        .dkg_outbound_packages(&req.ceremony_id)
        .map_err(map_sdk_err)?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|e| map_sdk_err(SdkError::Rpc(e.to_string())))?;

    for pkg in pkgs {
        let target_url = req
            .peer_urls
            .get(usize::from(pkg.recipient_peer))
            .ok_or_else(|| map_sdk_err(SdkError::MoveAbort("missing peer_url for target".into())))?;
        let endpoint = format!("{}/v1/dkg/inbox", target_url.trim_end_matches('/'));
        let r = http
            .post(&endpoint)
            .json(&DkgInboxDeliverReq {
                ceremony_id: req.ceremony_id.clone(),
                package: pkg,
            })
            .send()
            .await
            .map_err(|e| map_sdk_err(SdkError::Rpc(e.to_string())))?;
        if !r.status().is_success() {
            return Err(map_sdk_err(SdkError::Rpc(format!(
                "peer inbox returned {}",
                r.status()
            ))));
        }
    }
    Ok(Json(json!({ "pushed": true })))
}

async fn handle_dkg_finalize(
    State(st): State<BlindSealKeyServerState>,
    Json(req): Json<DkgFinalizeHttpReq>,
) -> Result<Json<PublicKeyset>, ApiErr> {
    st.dkg_finalize(req).map(Json).map_err(map_sdk_err)
}

pub async fn spawn_ephemeral_server(
    state: BlindSealKeyServerState,
) -> anyhow::Result<(String, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let addr = listener.local_addr()?;
    let app = state.router();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((format!("http://{addr}"), handle))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use blind_seal_crypto::{
        dkg::deal_multi_slot_keyset,
        dst::DstProfile,
        ibe_tpe::ibe_encrypt,
        tbs::{blind_message, verify_unblinded},
    };
    use blind_seal_sdk::{
        api::BlindTicketOnChain,
        client::{BlindSealClient, BlindSealPeerHandler},
        sui_backend::{EmbeddedMoveEngine, SpendProofInput, VaultConfig},
    };
    use rand::thread_rng;

    use super::*;

    struct OfflinePeer;
    impl BlindSealPeerHandler for OfflinePeer {
        fn fetch_blind_sig<'a>(
            &'a self,
            _req: FetchBlindSigRequest,
        ) -> BoxFuture<'a, Result<FetchBlindSigResponse, SdkError>> {
            Box::pin(async { Err(SdkError::Rpc("peer offline".into())) })
        }

        fn fetch_ibe_key<'a>(
            &'a self,
            _req: FetchIbeKeyRequest,
        ) -> BoxFuture<'a, Result<FetchIbeKeyResponse, SdkError>> {
            Box::pin(async { Err(SdkError::Rpc("peer offline".into())) })
        }
    }

    #[tokio::test]
    async fn test_phase1_blind_seal_committee_walrus_pass_and_trap3_replay() {
        let mut rng = thread_rng();
        let (pub_ks, shares) =
            deal_multi_slot_keyset("ks_walrus_pass", "pass", 3, 4, 4, &mut rng).unwrap();

        let move_engine = Arc::new(EmbeddedMoveEngine::default());
        move_engine.register_vault(VaultConfig {
            keyset: pub_ks.clone(),
            dst: DstProfile::SuiNative,
            notes_per_coin_unit: 1,
            hourly_melt_cap_notes: 1000,
            input_fee_ppk: 0,
        });

        let mut handlers: Vec<Arc<dyn BlindSealPeerHandler>> = Vec::new();
        for peer in 0..4u16 {
            if peer == 1 {
                handlers.push(Arc::new(OfflinePeer));
            } else {
                handlers.push(Arc::new(BlindSealKeyServerState::new(
                    peer,
                    vec![(pub_ks.clone(), shares[usize::from(peer)].clone())],
                    move_engine.clone(),
                )));
            }
        }

        let client = BlindSealClient::new_with_handlers(handlers);

        let pass_secret = b"walrus_anon_pass_secret_999";
        let (blinded, r) = blind_message(pass_secret, &DstProfile::SuiNative, &mut rng).unwrap();
        let ticket = move_engine
            .deposit_and_create_ticket("ks_walrus_pass", 1, vec![0], vec![blinded])
            .unwrap();

        let sigs = client
            .fetch_and_unblind(&pub_ks, &ticket, &[r], true)
            .await
            .unwrap();
        verify_unblinded(
            pass_secret,
            &sigs[0],
            pub_ks.slot_pk(0).unwrap(),
            &DstProfile::SuiNative,
        )
        .unwrap();

        let fake_ticket = BlindTicketOnChain {
            ticket_id: [0xEE; 32],
            keyset_id: "ks_walrus_pass".into(),
            slots: vec![0],
            blinded_messages: ticket.blinded_messages.clone(),
            finalized_checkpoint: 99,
        };
        assert!(client
            .fetch_combined_blind_signatures(&pub_ks, &fake_ticket, false)
            .await
            .is_err());

        let walrus_file_key = b"32_byte_secret_walrus_video_key!";
        let blob_id = b"walrus://blob/0xdeadbeef";
        let ct = ibe_encrypt(
            &pub_ks.ibe_agg_pk_g1,
            b"walrus_media",
            blob_id,
            walrus_file_key,
            &mut rng,
        )
        .unwrap();

        let approval = move_engine
            .burn_blind_pass_for_ibe_approval(
                "ks_walrus_pass",
                SpendProofInput {
                    slot: 0,
                    secret_or_nonce: pass_secret.to_vec(),
                    signature: sigs[0].clone(),
                    schnorr_lock: None,
                    schnorr_msg_override: None,
                    htlc_preimage: None,
                    htlc_expected_hash: None,
                },
                b"walrus_media".to_vec(),
                blob_id.to_vec(),
            )
            .unwrap();

        let decrypted = client
            .fetch_and_decrypt_ibe(&pub_ks, approval.approval_id, &ct)
            .await
            .unwrap();
        assert_eq!(decrypted, walrus_file_key);
    }

    #[tokio::test]
    async fn test_multi_server_peer_to_peer_pedersen_dkg_ceremony_activates_live_signing() {
        let mut rng = thread_rng();
        let move_engine = Arc::new(EmbeddedMoveEngine::default());

        // Boot 5 completely uninitialized (0-keyset) BlindSealKeyServerState guardian nodes!
        let servers: Vec<Arc<BlindSealKeyServerState>> = (0..5u16)
            .map(|p| Arc::new(BlindSealKeyServerState::new(p, vec![], move_engine.clone())))
            .collect();

        // Round 1: Each guardian generates polynomials in RAM & emits ONLY public commitments
        let mut broadcasts = Vec::new();
        for s in &servers {
            let b = s
                .dkg_start_round1(DkgRound1HttpReq {
                    ceremony_id: "ceremony_2026_01".into(),
                    threshold: 4,
                    num_peers: 5,
                    num_slots: 8,
                })
                .unwrap();
            broadcasts.push(b);
        }

        // Round 2: Guardians deliver private packages peer-to-peer (zero coordinator visibility!)
        for sender in &servers {
            for pkg in sender.dkg_outbound_packages("ceremony_2026_01").unwrap() {
                let target = &servers[usize::from(pkg.recipient_peer)];
                target
                    .dkg_receive_inbox(DkgInboxDeliverReq {
                        ceremony_id: "ceremony_2026_01".into(),
                        package: pkg,
                    })
                    .unwrap();
            }
        }

        // Finalize: Every guardian verifies Feldman commitments & activates `02_net_dkg` live in RAM!
        let mut derived_pks = Vec::new();
        for s in &servers {
            let pk = s
                .dkg_finalize(DkgFinalizeHttpReq {
                    ceremony_id: "ceremony_2026_01".into(),
                    keyset_id: "02_net_dkg".into(),
                    unit: "sat".into(),
                    broadcasts: broadcasts.clone(),
                })
                .unwrap();
            derived_pks.push(pk);
        }
        for w in derived_pks.windows(2) {
            assert_eq!(w[0], w[1]);
        }

        // Immediately mint & verify a live note using the newly DKG-generated keyset!
        let pub_ks = derived_pks.remove(0);
        move_engine.register_vault(VaultConfig {
            keyset: pub_ks.clone(),
            dst: DstProfile::CashuBls,
            notes_per_coin_unit: 1,
            hourly_melt_cap_notes: 1000,
            input_fee_ppk: 0,
        });
        let (bm, r) = blind_message(b"dkg_minted_note", &DstProfile::CashuBls, &mut rng).unwrap();
        let ticket = move_engine
            .deposit_and_create_ticket("02_net_dkg", 4, vec![2], vec![bm])
            .unwrap();

        let handlers: Vec<Arc<dyn BlindSealPeerHandler>> = servers
            .into_iter()
            .map(|s| s as Arc<dyn BlindSealPeerHandler>)
            .collect();
        let client = BlindSealClient::new_with_handlers(handlers);
        let sigs = client
            .fetch_and_unblind(&pub_ks, &ticket, &[r], false)
            .await
            .unwrap();
        verify_unblinded(
            b"dkg_minted_note",
            &sigs[0],
            pub_ks.slot_pk(2).unwrap(),
            &DstProfile::CashuBls,
        )
        .unwrap();
    }
}
