use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use blind_seal_sdk::client::{ControllableGuardianPeer, GuardianFaultMode, GuardianPeerSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    nuts::{CashuProof, Nut05MeltExecuteRequest, Nut05MeltQuoteRequest},
    SealCashuMint,
};

const COWRIE_BLS_WASM: &[u8] = include_bytes!("../assets/cowrie_bls.wasm");

/// Landing page (`/`) and the interactive playground (`/playground`), Lighthouse Coast theme.
const LANDING_HTML: &str = include_str!("../assets/landing.html");
const PLAYGROUND_HTML: &str = include_str!("../assets/playground.html");

/// Storybook illustrations shared by the landing page and the playground (`/assets/site/{name}`).
const SITE_ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "hero.jpg",
        "image/jpeg",
        include_bytes!("../assets/site/hero.jpg"),
    ),
    (
        "map.jpg",
        "image/jpeg",
        include_bytes!("../assets/site/map.jpg"),
    ),
    (
        "sky-night.jpg",
        "image/jpeg",
        include_bytes!("../assets/site/sky-night.jpg"),
    ),
    (
        "cowrie.png",
        "image/png",
        include_bytes!("../assets/site/cowrie.png"),
    ),
    (
        "vault.png",
        "image/png",
        include_bytes!("../assets/site/vault.png"),
    ),
    (
        "keeper.png",
        "image/png",
        include_bytes!("../assets/site/keeper.png"),
    ),
    (
        "chest-empty.png",
        "image/png",
        include_bytes!("../assets/site/chest-empty.png"),
    ),
    (
        "hourglass.png",
        "image/png",
        include_bytes!("../assets/site/hourglass.png"),
    ),
    (
        "manifest.png",
        "image/png",
        include_bytes!("../assets/site/manifest.png"),
    ),
    (
        "ship.png",
        "image/png",
        include_bytes!("../assets/site/ship.png"),
    ),
    (
        "lighthouse-lit.png",
        "image/png",
        include_bytes!("../assets/site/lighthouse-lit.png"),
    ),
    (
        "lighthouse-dark.png",
        "image/png",
        include_bytes!("../assets/site/lighthouse-dark.png"),
    ),
    (
        "lighthouse-false.png",
        "image/png",
        include_bytes!("../assets/site/lighthouse-false.png"),
    ),
];

/// Server-side state for Guardian Chaos fault injection and the simulated Value4Value
/// content/API creator endpoint (`POST /demo/v4v/protected_resource` gated by `HTTP-402` `X-Cashu`).
/// NOTE: The user wallet itself is now **100% non-custodial in the browser** (`WebAssembly` + `localStorage`)!
#[derive(Clone)]
pub struct DemoPlaygroundState {
    pub mint: SealCashuMint,
    pub sat_keyset_id: String,
    pub peers: Vec<Arc<ControllableGuardianPeer>>,
    pub creator_v4v_buffer: Arc<Mutex<Vec<CashuProof>>>,
    pub total_v4v_settled_sats: Arc<Mutex<u64>>,
}

#[derive(Deserialize)]
pub struct SetGuardianModeReq {
    pub peer_id: u16,
    pub mode: GuardianFaultMode,
}

#[derive(Serialize)]
pub struct DemoStatusResp {
    pub mint_name: String,
    pub sat_keyset_id: String,
    pub dst_utf8: String,
    pub threshold: u16,
    pub num_peers: u16,
    pub vault_reserve_sats: u64,
    pub v4v_buffered_notes: usize,
    pub v4v_buffered_sats: u64,
    pub v4v_settled_sats: u64,
    pub guardians: Vec<GuardianPeerSnapshot>,
}

pub fn attach_demo_routes(router: Router, demo: DemoPlaygroundState) -> Router {
    let sub = Router::new()
        .route("/", get(serve_landing_html))
        .route("/playground", get(serve_playground_html))
        .route("/assets/cowrie_bls.wasm", get(serve_wasm_binary))
        .route("/assets/site/{name}", get(serve_site_asset))
        .route("/demo/status", get(handle_demo_status))
        .route("/demo/guardian", post(handle_set_guardian_mode))
        .route(
            "/demo/v4v/protected_resource",
            post(handle_v4v_protected_resource),
        )
        .route("/demo/v4v/settle", post(handle_v4v_batch_settle))
        .with_state(demo);
    router.merge(sub)
}

async fn serve_site_asset(Path(name): Path<String>) -> impl IntoResponse {
    match SITE_ASSETS.iter().find(|(n, _, _)| *n == name) {
        Some((_, mime, bytes)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, *mime),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            *bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_wasm_binary() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/wasm")],
        COWRIE_BLS_WASM,
    )
}

async fn handle_demo_status(State(d): State<DemoPlaygroundState>) -> Json<DemoStatusResp> {
    let meta = d.mint.keysets.get(&d.sat_keyset_id).unwrap();
    let reserve = d
        .mint
        .move_box
        .box_vault_reserve_coin_units(&d.sat_keyset_id)
        .await
        .unwrap_or(0);
    let buf = d.creator_v4v_buffer.lock().unwrap();
    let buf_sats: u64 = buf.iter().map(|p| p.amount).sum();
    let settled = *d.total_v4v_settled_sats.lock().unwrap();

    Json(DemoStatusResp {
        mint_name: d.mint.mint_name.clone(),
        sat_keyset_id: d.sat_keyset_id.clone(),
        dst_utf8: String::from_utf8_lossy(meta.dst.as_bytes()).to_string(),
        threshold: meta.keyset.threshold,
        num_peers: meta.keyset.num_peers,
        vault_reserve_sats: reserve,
        v4v_buffered_notes: buf.len(),
        v4v_buffered_sats: buf_sats,
        v4v_settled_sats: settled,
        guardians: d.peers.iter().map(|p| p.snapshot()).collect(),
    })
}

async fn handle_set_guardian_mode(
    State(d): State<DemoPlaygroundState>,
    Json(req): Json<SetGuardianModeReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let peer = d
        .peers
        .iter()
        .find(|p| p.peer_id == req.peer_id)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "unknown peer_id" })),
            )
        })?;
    peer.set_mode(req.mode);
    Ok(Json(json!({ "ok": true, "guardian": peer.snapshot() })))
}

/// Real `NUT-24` (`HTTP-402`) protected endpoint!
/// Expects `X-Cashu: cashuB...` header built by the browser's non-custodial WASM wallet,
/// verifies the `BLS12-381` signature **offline via pairing** (<1ms, 0 DLEQ bytes!),
/// and buffers the proof for later creator batch settlement.
async fn handle_v4v_protected_resource(
    State(d): State<DemoPlaygroundState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let raw_hdr = headers
        .get("X-Cashu")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let t_verify = Instant::now();
    let verified = d
        .mint
        .verify_http402_xcashu_header_offchain(&headers, "sat", 1)
        .map_err(|e| {
            (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({ "error": e.detail, "code": e.code })),
            )
        })?;
    let verify_us = t_verify.elapsed().as_micros();
    let paid_sats: u64 = verified.iter().map(|p| p.amount).sum();
    d.creator_v4v_buffer.lock().unwrap().extend(verified);

    Ok(Json(json!({
        "streamed_sats": paid_sats,
        "xcashu_header_bytes": raw_hdr.len(),
        "dleq_overhead_bytes": 0,
        "offline_pairing_verify_us": verify_us,
        "chunk": "Unlocked 1s Value4Value audio/API frame"
    })))
}

/// Settles ALL buffered Value4Value streamed notes in ONE single Fiat-Shamir aggregated multi-pairing melt!
async fn handle_v4v_batch_settle(
    State(d): State<DemoPlaygroundState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let buffered: Vec<CashuProof> = {
        let mut buf = d.creator_v4v_buffer.lock().unwrap();
        if buf.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "No streamed V4V notes in creator buffer yet!" })),
            ));
        }
        std::mem::take(&mut *buf)
    };

    let total_sats: u64 = buffered.iter().map(|p| p.amount).sum();
    let note_count = buffered.len();
    let t0 = Instant::now();

    let q = d
        .mint
        .create_melt_quote(
            "bolt11",
            Nut05MeltQuoteRequest {
                request: format!("lnbc{total_sats}sat1p_creator_nodesignal_v4v"),
                unit: "sat".into(),
                amount: Some(total_sats),
            },
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.detail }))))?;

    let res = d
        .mint
        .execute_melt(
            "bolt11",
            Nut05MeltExecuteRequest {
                quote: q.quote,
                inputs: buffered,
                outputs: vec![],
            },
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.detail }))))?;

    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    *d.total_v4v_settled_sats.lock().unwrap() += total_sats;

    Ok(Json(json!({
        "settled_notes": note_count,
        "settled_sats": total_sats,
        "payment_preimage": res.payment_preimage,
        "batch_pairing_ms": elapsed_ms
    })))
}

async fn serve_landing_html() -> Html<&'static str> {
    Html(LANDING_HTML)
}

async fn serve_playground_html() -> Html<&'static str> {
    Html(PLAYGROUND_HTML)
}
