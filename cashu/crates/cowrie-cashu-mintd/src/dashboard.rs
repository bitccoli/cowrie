use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    extract::State,
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
        .route("/", get(serve_dashboard_html))
        .route("/assets/cowrie_bls.wasm", get(serve_wasm_binary))
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

async fn serve_wasm_binary() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/wasm")], COWRIE_BLS_WASM)
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

async fn serve_dashboard_html() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Cowrie — Non-Custodial Browser BLS12-381 Cashu Wallet & 4-of-5 Mint</title>
<style>
  :root {
    --bg: #0b0f17; --card: #131a27; --border: #233047; --text: #e6edf7;
    --muted: #8b9bb4; --accent: #38bdf8; --green: #22c55e; --amber: #f59e0b; --red: #ef4444;
  }
  * { box-sizing: border-box; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
  body { margin: 0; background: var(--bg); color: var(--text); padding: 24px; }
  .wrap { max-width: 1140px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 16px; gap: 12px; flex-wrap: wrap; }
  h1 { margin: 0; font-size: 22px; letter-spacing: -0.02em; }
  .badge { background: rgba(56,189,248,0.15); color: var(--accent); border: 1px solid rgba(56,189,248,0.35); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }
  .card h2 { margin: 0 0 12px 0; font-size: 14px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-row { display: flex; justify-content: space-between; margin: 8px 0; font-size: 14px; }
  .stat-val { font-weight: 700; font-family: ui-monospace, SFMono-Regular, monospace; }
  .peers { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
  .peer { background: #0e1420; border: 1px solid var(--border); border-radius: 10px; padding: 12px; text-align: center; }
  .peer.healthy { border-color: rgba(34,197,94,0.5); }
  .peer.offline { border-color: rgba(239,68,68,0.5); opacity: 0.75; }
  .peer.byzantine_forge { border-color: rgba(245,158,11,0.65); }
  .peer-title { font-weight: 700; font-size: 13px; margin-bottom: 6px; }
  .peer-meta { font-size: 11px; color: var(--muted); margin-bottom: 8px; font-family: ui-monospace, monospace; }
  .btn-group { display: flex; flex-direction: column; gap: 4px; }
  button { cursor: pointer; border: 1px solid var(--border); background: #1c2638; color: var(--text); padding: 8px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; transition: 0.15s; }
  button:hover { border-color: var(--accent); }
  button.primary { background: var(--accent); color: #06121d; border-color: var(--accent); }
  button.green { background: var(--green); color: #051b0d; border-color: var(--green); }
  button.sm { padding: 4px 6px; font-size: 11px; }
  button.active-healthy { background: rgba(34,197,94,0.2); border-color: var(--green); color: var(--green); }
  button.active-offline { background: rgba(239,68,68,0.2); border-color: var(--red); color: var(--red); }
  button.active-byz { background: rgba(245,158,11,0.2); border-color: var(--amber); color: var(--amber); }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  pre { background: #080b11; border: 1px solid var(--border); border-radius: 8px; padding: 10px; font-size: 11px; color: #9cdcfe; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 115px; margin: 10px 0 0 0; font-family: ui-monospace, monospace; }
  #log { max-height: 190px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>🐚 Cowrie — Federated <code>BLS12-381</code> Cashu Mint & Non-Custodial Browser Wallet</h1>
      <div style="color:var(--muted);font-size:13px;margin-top:4px;">Client-Side WASM Blinding &amp; Pairing Verification (<code>localStorage</code>) • Zero-DLEQ <code>HTTP-402</code> Streaming</div>
    </div>
    <span class="badge" id="ks-badge">Loading WASM &amp; keysets...</span>
  </header>

  <div class="card" style="margin-bottom:16px;">
    <h2>4-of-5 Threshold Guardian Chaos Matrix (Click to Inject Faults Live)</h2>
    <div style="color:var(--muted);font-size:13px;margin-bottom:12px;">
      Toggle any <b>1 guardian</b> to <b>Offline</b> or <b>Byzantine (Forge Bad G1 Share)</b> — pairing checks reject forged shares automatically while 4-of-5 keeps signing! Toggle <b>2 guardians</b> faulty to verify threshold safety halts issuance.
    </div>
    <div class="peers" id="peers-grid"></div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>1. Non-Custodial Browser Wallet (WASM + localStorage)</h2>
      <div class="stat-row"><span>Browser Wallet Balance:</span><span class="stat-val" id="w-bal">0 sat</span></div>
      <div class="stat-row"><span>Local Unspent Proofs:</span><span class="stat-val" id="w-cnt">0</span></div>
      <div class="stat-row"><span>Mint Reserve (Consensus Box):</span><span class="stat-val" id="m-res">0 sat</span></div>
      <div class="actions">
        <button class="primary" onclick="mintInBrowser(16)">⚡ Mint 16x1 sat (BOLT11)</button>
        <button onclick="mintInBrowser(64)">⚡ Mint 64 sat</button>
        <button onclick="swapInBrowser()">🔄 NUT-03 Swap</button>
        <button onclick="checkStateInBrowser()">🕵️ NUT-07 Y-Check</button>
        <button onclick="wipeAndRestoreInBrowser()">🌱 Wipe &amp; Restore (NUT-13)</button>
      </div>
      <pre id="v4-box">Secrets &amp; blinding factors r never leave your browser! Mint sats to inspect compact binary NUT-00 V4 CBOR (cashuB...).</pre>
    </div>

    <div class="card">
      <h2>2. Value4Value HTTP-402 Stream (NUT-24 X-Cashu)</h2>
      <div class="stat-row"><span>Creator Stream Buffer (Off-Chain):</span><span class="stat-val" id="v-buf">0 sat (0 notes)</span></div>
      <div class="stat-row"><span>Batch-Settled Creator Earnings:</span><span class="stat-val" id="v-set" style="color:var(--green)">0 sat</span></div>
      <div class="stat-row"><span>NUT-12 DLEQ Proof Bloat:</span><span class="stat-val" style="color:var(--accent)">0 bytes (Native Pairing)</span></div>
      <div class="actions">
        <button class="green" id="stream-btn" onclick="toggleStream()">▶ Start 1-sat/sec HTTP-402 Stream</button>
        <button onclick="tick402()">Single 402 Tick</button>
        <button class="primary" onclick="batchSettle()">📦 Batch-Melt All Buffered Sats</button>
      </div>
      <pre id="v4v-box">Browser encodes binary NUT-00 V4 CBOR X-Cashu header &amp; sends to POST /demo/v4v/protected_resource.</pre>
    </div>
  </div>

  <div class="card">
    <h2>Live Client-WASM &amp; Mint Protocol Log</h2>
    <pre id="log">Initializing cowrie_bls.wasm...</pre>
  </div>
</div>

<script>
const STORAGE_KEY = 'cowrie_noncustodial_proofs_v1';
const SEED_KEY = 'cowrie_nut13_master_seed_v1';
const CTR_KEY = 'cowrie_nut13_counter_v1';
let wasm = null;
let satKeyset = null; // { id, keys: { "1": hex96, ... } }
let dstBytes = null;
let streamTimer = null;
let nut17Socket = null;

function getMasterSeed() {
  let s = localStorage.getItem(SEED_KEY);
  if (!s) {
    s = 'cowrie-web-seed-' + toHex(crypto.getRandomValues(new Uint8Array(16)));
    localStorage.setItem(SEED_KEY, s);
  }
  return s;
}
function nextCounter() {
  const c = parseInt(localStorage.getItem(CTR_KEY) || '0', 10);
  localStorage.setItem(CTR_KEY, String(c + 1));
  return c;
}
async function deriveNut13Browser(counter) {
  const seed = getMasterSeed();
  const enc = new TextEncoder();
  const sBuf = await crypto.subtle.digest('SHA-256', enc.encode(`NUT13_COWRIE_SECRET_V1|${seed}|${satKeyset.id}|${counter}`));
  const rBuf = await crypto.subtle.digest('SHA-256', enc.encode(`NUT13_COWRIE_BLIND_SEED_V1|${seed}|${satKeyset.id}|${counter}`));
  const secret = toHex(new Uint8Array(sBuf));
  const seed32 = new Uint8Array(rBuf);
  return { secret, seed32, B_: wasmBlind(secret, seed32) };
}

function connectNut17WebSocket() {
  try {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    nut17Socket = new WebSocket(`${proto}//${location.host}/v1/ws`);
    nut17Socket.onopen = () => {
      nut17Socket.send(JSON.stringify({ jsonrpc:'2.0', id:1, method:'subscribe', params:{ kind:'bolt11_mint_quote', subId:'ws_mint', filters:['*'] } }));
      nut17Socket.send(JSON.stringify({ jsonrpc:'2.0', id:2, method:'subscribe', params:{ kind:'bolt11_melt_quote', subId:'ws_melt', filters:['*'] } }));
      nut17Socket.send(JSON.stringify({ jsonrpc:'2.0', id:3, method:'subscribe', params:{ kind:'proof_state', subId:'ws_proof', filters:['*'] } }));
      log('🔌 Connected to NUT-17 WebSocket (/v1/ws) for real-time quote & proof_state push events');
    };
    nut17Socket.onmessage = ev => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.method === 'subscribe' && msg.params && msg.params.payload) {
          const p = msg.params.payload;
          if (p.Y) log(`📡 NUT-17 Push [proof_state]: Y=${p.Y.slice(0,16)}... -> ${p.state}`);
          else if (p.quote) log(`📡 NUT-17 Push [${msg.params.subId}]: quote=${p.quote.slice(0,12)}... -> ${p.state}`);
        }
      } catch {}
    };
  } catch {}
}

function log(msg) {
  const el = document.getElementById('log');
  const ts = new Date().toISOString().slice(11, 23);
  el.textContent = `[${ts}] ${msg}\n` + el.textContent;
}

const toHex = u8 => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = hex => new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
const b64url = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function loadProofs() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { return []; }
}
function saveProofs(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// Minimal RFC 8949 CBOR encoder specifically for official NUT-00 V4 binary `cashuB...` tokens:
// `{ "m": str, "u": str, "t": [{ "i": bytes, "p": [{ "a": uint, "s": str, "c": bytes }] }] }`
function cborHead(major, len) {
  const mt = major << 5;
  if (len < 24) return [mt | len];
  if (len < 256) return [mt | 24, len];
  if (len < 65536) return [mt | 25, (len >> 8) & 0xff, len & 0xff];
  return [mt | 26, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
}
const cborUint = n => cborHead(0, n);
const cborBytes = u8 => [...cborHead(2, u8.length), ...u8];
const cborStr = s => { const b = new TextEncoder().encode(s); return [...cborHead(3, b.length), ...b]; };
function encodeNut00V4Token(mintUrl, unit, proofs) {
  const byId = {};
  for (const p of proofs) { (byId[p.id] = byId[p.id] || []).push(p); }
  const groups = Object.entries(byId);
  const out = [...cborHead(5, 3), ...cborStr('m'), ...cborStr(mintUrl), ...cborStr('u'), ...cborStr(unit), ...cborStr('t'), ...cborHead(4, groups.length)];
  for (const [idHex, plist] of groups) {
    out.push(...cborHead(5, 2), ...cborStr('i'), ...cborBytes(fromHex(idHex)), ...cborStr('p'), ...cborHead(4, plist.length));
    for (const p of plist) {
      out.push(...cborHead(5, 3), ...cborStr('a'), ...cborUint(p.amount), ...cborStr('s'), ...cborStr(p.secret), ...cborStr('c'), ...cborBytes(fromHex(p.C)));
    }
  }
  return 'cashuB' + b64url(new Uint8Array(out));
}

// WASM FFI Wrappers (zero secrets ever sent to server during blinding!)
function wasmWrite(u8) {
  const ptr = wasm.wasm_alloc(u8.length);
  new Uint8Array(wasm.memory.buffer, ptr, u8.length).set(u8);
  return ptr;
}
function wasmBlind(secretStr, seed32) {
  const msg = new TextEncoder().encode(secretStr);
  const mPtr = wasmWrite(msg), dPtr = wasmWrite(dstBytes), sPtr = wasmWrite(seed32), outPtr = wasm.wasm_alloc(48);
  const ok = wasm.wasm_blind_message(mPtr, msg.length, dPtr, dstBytes.length, sPtr, outPtr);
  const res = new Uint8Array(wasm.memory.buffer.slice(outPtr, outPtr + 48));
  wasm.wasm_dealloc(mPtr, msg.length); wasm.wasm_dealloc(dPtr, dstBytes.length); wasm.wasm_dealloc(sPtr, 32); wasm.wasm_dealloc(outPtr, 48);
  if (!ok) throw new Error('WASM blind failed');
  return toHex(res);
}
function wasmUnblindAndVerify(cBlindHex, seed32, secretStr, pkG2Hex) {
  const cb = fromHex(cBlindHex), msg = new TextEncoder().encode(secretStr), pk = fromHex(pkG2Hex);
  const cbPtr = wasmWrite(cb), sPtr = wasmWrite(seed32), mPtr = wasmWrite(msg), dPtr = wasmWrite(dstBytes), pkPtr = wasmWrite(pk), outPtr = wasm.wasm_alloc(48);
  const ok = wasm.wasm_unblind_and_verify(cbPtr, sPtr, mPtr, msg.length, dPtr, dstBytes.length, pkPtr, outPtr);
  const res = new Uint8Array(wasm.memory.buffer.slice(outPtr, outPtr + 48));
  wasm.wasm_dealloc(cbPtr, 48); wasm.wasm_dealloc(sPtr, 32); wasm.wasm_dealloc(mPtr, msg.length); wasm.wasm_dealloc(dPtr, dstBytes.length); wasm.wasm_dealloc(pkPtr, 96); wasm.wasm_dealloc(outPtr, 48);
  if (!ok) throw new Error('Offline BLS12-381 pairing verification FAILED in browser WASM!');
  return toHex(res);
}
function wasmHashToY(secretStr) {
  const msg = new TextEncoder().encode(secretStr);
  const mPtr = wasmWrite(msg), dPtr = wasmWrite(dstBytes), outPtr = wasm.wasm_alloc(48);
  const ok = wasm.wasm_hash_to_y(mPtr, msg.length, dPtr, dstBytes.length, outPtr);
  const res = new Uint8Array(wasm.memory.buffer.slice(outPtr, outPtr + 48));
  wasm.wasm_dealloc(mPtr, msg.length); wasm.wasm_dealloc(dPtr, dstBytes.length); wasm.wasm_dealloc(outPtr, 48);
  if (!ok) throw new Error('WASM hash_to_y failed');
  return toHex(res);
}

async function init() {
  const res = await WebAssembly.instantiateStreaming(fetch('/assets/cowrie_bls.wasm'), {});
  wasm = res.instance.exports;
  const keysResp = await (await fetch('/v1/keys')).json();
  satKeyset = keysResp.keysets.find(k => k.unit === 'sat');
  await refresh();
  connectNut17WebSocket();
  log(`Loaded cowrie_bls.wasm & NUT-01 G2 keyset ${satKeyset.id} — non-custodial NUT-13 deterministic wallet ready.`);
}

async function refresh() {
  const st = await (await fetch('/demo/status')).json();
  dstBytes = new TextEncoder().encode(st.dst_utf8);
  const proofs = loadProofs().filter(p => p.id === st.sat_keyset_id);
  saveProofs(proofs);
  const bal = proofs.reduce((s, p) => s + p.amount, 0);

  document.getElementById('ks-badge').textContent = `Keyset ${st.sat_keyset_id} (${st.threshold}-of-${st.num_peers} BLS12-381)`;
  document.getElementById('w-bal').textContent = `${bal} sat`;
  document.getElementById('w-cnt').textContent = `${proofs.length} notes`;
  document.getElementById('m-res').textContent = `${st.vault_reserve_sats} sat`;
  document.getElementById('v-buf').textContent = `${st.v4v_buffered_sats} sat (${st.v4v_buffered_notes} notes)`;
  document.getElementById('v-set').textContent = `${st.v4v_settled_sats} sat`;
  if (proofs.length > 0) {
    document.getElementById('v4-box').textContent = encodeNut00V4Token(location.origin, 'sat', proofs);
  }

  document.getElementById('peers-grid').innerHTML = st.guardians.map(g => `
    <div class="peer ${g.mode}">
      <div class="peer-title">Guardian #${g.peer_id}</div>
      <div class="peer-meta">Signed: ${g.shares_accepted} | Caught: ${g.byzantine_shares_rejected}</div>
      <div class="btn-group">
        <button class="sm ${g.mode==='healthy'?'active-healthy':''}" onclick="setMode(${g.peer_id},'healthy')">Healthy</button>
        <button class="sm ${g.mode==='offline'?'active-offline':''}" onclick="setMode(${g.peer_id},'offline')">Offline</button>
        <button class="sm ${g.mode==='byzantine_forge'?'active-byz':''}" onclick="setMode(${g.peer_id},'byzantine_forge')">Byzantine</button>
      </div>
    </div>
  `).join('');
}

async function setMode(peer_id, mode) {
  await fetch('/demo/guardian', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id, mode}) });
  log(`Guardian #${peer_id} -> ${mode.toUpperCase()}`);
  await refresh();
}

function splitDenoms(amount) {
  if (amount <= 16) return Array(amount).fill(1);
  const out = [];
  for (let b = 30; b >= 0; b--) { const v = 1 << b; while (amount >= v) { out.push(v); amount -= v; } }
  return out;
}

async function mintInBrowser(amount) {
  const t0 = performance.now();
  const qResp = await fetch('/v1/mint/quote/bolt11', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ amount, unit: 'sat', description: 'Browser WASM Mint' })
  });
  const quote = await qResp.json();
  if (!qResp.ok) { log(`❌ Quote error: ${quote.detail}`); return; }

  const denoms = splitDenoms(amount);
  const pending = [];
  for (const amt of denoms) {
    const d = await deriveNut13Browser(nextCounter());
    pending.push({ amount: amt, ...d });
  }

  const mResp = await fetch('/v1/mint/bolt11', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      quote: quote.quote,
      outputs: pending.map(p => ({ amount: p.amount, id: satKeyset.id, B_: p.B_ }))
    })
  });
  const mData = await mResp.json();
  if (!mResp.ok) { log(`❌ Mint aborted by threshold/policy: ${mData.detail} (code ${mData.code})`); await refresh(); return; }

  const newProofs = pending.map((p, i) => {
    const C = wasmUnblindAndVerify(mData.signatures[i].C_, p.seed32, p.secret, satKeyset.keys[String(p.amount)]);
    return { amount: p.amount, id: satKeyset.id, secret: p.secret, C };
  });
  saveProofs([...loadProofs(), ...newProofs]);
  log(`✅ Browser WASM blinded, minted ${amount} sat (${newProofs.length} notes), & pairing-verified offline in ${(performance.now() - t0).toFixed(1)} ms!`);
  await refresh();
}

async function swapInBrowser() {
  const all = loadProofs();
  if (!all.length) { log('⚠️ Browser wallet empty — mint sats first!'); return; }
  const take = all.slice(0, 8), keep = all.slice(8);
  const total = take.reduce((s, p) => s + p.amount, 0);
  const denoms = total <= 32 ? Array(total).fill(1) : splitDenoms(total);

  const t0 = performance.now();
  const pending = [];
  for (const amt of denoms) {
    const d = await deriveNut13Browser(nextCounter());
    pending.push({ amount: amt, ...d });
  }

  const r = await fetch('/v1/swap', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      inputs: take,
      outputs: pending.map(p => ({ amount: p.amount, id: satKeyset.id, B_: p.B_ }))
    })
  });
  const d = await r.json();
  if (!r.ok) { log(`❌ Swap rejected: ${d.detail} (code ${d.code})`); await refresh(); return; }

  const fresh = pending.map((p, i) => ({
    amount: p.amount, id: satKeyset.id, secret: p.secret,
    C: wasmUnblindAndVerify(d.signatures[i].C_, p.seed32, p.secret, satKeyset.keys[String(p.amount)])
  }));
  saveProofs([...keep, ...fresh]);
  log(`🔄 Browser WASM NUT-03 Swap: ${total} sat -> ${fresh.length} fresh pairing-verified notes in ${(performance.now() - t0).toFixed(1)} ms`);
  await refresh();
}

async function checkStateInBrowser() {
  const proofs = loadProofs();
  if (!proofs.length) { log('⚠️ No local proofs to check.'); return; }
  const Ys = proofs.map(p => wasmHashToY(p.secret));
  const r = await fetch('/v1/checkstate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ Ys })
  });
  const d = await r.json();
  const unspent = d.states.filter(s => s.state === 'UNSPENT').length;
  log(`🕵️ NUT-07 Privacy Check: Sent ${Ys.length} 48-byte Y points (0 secrets leaked) -> ${unspent}/${Ys.length} UNSPENT`);
}

async function wipeAndRestoreInBrowser() {
  const t0 = performance.now();
  saveProofs([]);
  await refresh();
  log('🧹 Wiped browser localStorage proofs (0 sat). Scanning NUT-13 deterministic seed via /v1/restore (NUT-09)...');

  const scanCount = Math.max(parseInt(localStorage.getItem(CTR_KEY) || '0', 10) + 16, 64);
  const candidates = [];
  for (let ctr = 0; ctr < scanCount; ctr++) {
    const d = await deriveNut13Browser(ctr);
    candidates.push({ ctr, ...d });
  }
  const r = await fetch('/v1/restore', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outputs: candidates.map(c => ({ amount: 1, id: satKeyset.id, B_: c.B_ })) })
  });
  const res = await r.json();
  const byB = Object.fromEntries(candidates.map(c => [c.B_, c]));
  const verified = [];
  let maxCtr = 0;
  for (let i = 0; i < res.outputs.length; i++) {
    const out = res.outputs[i], sig = res.signatures[i];
    const meta = byB[out.B_];
    if (!meta) continue;
    maxCtr = Math.max(maxCtr, meta.ctr + 1);
    const C = wasmUnblindAndVerify(sig.C_, meta.seed32, meta.secret, satKeyset.keys[String(sig.amount)]);
    verified.push({ amount: sig.amount, id: satKeyset.id, secret: meta.secret, C });
  }
  let unspent = [];
  if (verified.length > 0) {
    const Ys = verified.map(p => wasmHashToY(p.secret));
    const cs = await (await fetch('/v1/checkstate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ Ys })
    })).json();
    unspent = verified.filter((_, idx) => cs.states[idx].state === 'UNSPENT');
  }
  localStorage.setItem(CTR_KEY, String(maxCtr));
  saveProofs(unspent);
  const sats = unspent.reduce((s, p) => s + p.amount, 0);
  log(`🌱 NUT-13 + NUT-09 Restore Complete: Recovered ${sats} sat (${unspent.length} unspent notes) from seed in ${(performance.now() - t0).toFixed(1)} ms!`);
  await refresh();
}

async function tick402() {
  const proofs = loadProofs();
  const idx = proofs.findIndex(p => p.amount === 1);
  const pickIdx = idx >= 0 ? idx : (proofs.length ? 0 : -1);
  if (pickIdx < 0) {
    log('⚠️ HTTP-402 stream paused: Browser localStorage out of sats!');
    if (streamTimer) toggleStream();
    return;
  }
  const [note] = proofs.splice(pickIdx, 1);
  saveProofs(proofs);

  const token = encodeNut00V4Token(location.origin, 'sat', [note]);
  const r = await fetch('/demo/v4v/protected_resource', {
    method: 'POST',
    headers: { 'X-Cashu': token }
  });
  const d = await r.json();
  if (!r.ok) {
    saveProofs([note, ...loadProofs()]);
    log(`❌ HTTP-402 error: ${d.error}`);
  } else {
    document.getElementById('v4v-box').textContent = `X-Cashu (${d.xcashu_header_bytes}B binary V4 CBOR, 0B DLEQ) verified offline in ${d.offline_pairing_verify_us} µs:\n${token}`;
    log(`🎵 HTTP-402 Sent from Browser: +${d.streamed_sats} sat verified offline in ${d.offline_pairing_verify_us} µs`);
  }
  await refresh();
}

function toggleStream() {
  const btn = document.getElementById('stream-btn');
  if (streamTimer) { clearInterval(streamTimer); streamTimer = null; btn.textContent = '▶ Start 1-sat/sec HTTP-402 Stream'; }
  else { tick402(); streamTimer = setInterval(tick402, 1000); btn.textContent = '⏸ Stop HTTP-402 Stream'; }
}

async function batchSettle() {
  const r = await fetch('/demo/v4v/settle', { method:'POST' });
  const d = await r.json();
  if (!r.ok) log(`⚠️ ${d.error}`);
  else log(`📦 NUT-05 Batch Melt: Settled ${d.settled_notes} streamed notes (${d.settled_sats} sats) in 1 Fiat-Shamir batch pairing (${d.batch_pairing_ms.toFixed(2)} ms)!`);
  await refresh();
}

init();
</script>
</body>
</html>
"#;
