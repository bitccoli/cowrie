//! Official Cashu `NUT-17` WebSocket Subscriptions (`GET /v1/ws`):
//! Real-time JSON-RPC 2.0 `subscribe` / `unsubscribe` notifications for
//! `bolt11_mint_quote`, `bolt11_melt_quote`, and `proof_state` (`Y` curve point nullifiers).

use std::collections::{HashMap, HashSet};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Response, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64_STD, Engine};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::broadcast,
};

use crate::{
    nuts::{
        Nut04MintQuoteResponse, Nut05MeltQuoteResponse, Nut07CheckStateRequest, Nut07StateEntry,
    },
    SealCashuMint,
};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nut17Kind {
    Bolt11MintQuote,
    Bolt11MeltQuote,
    ProofState,
}

#[derive(Clone, Debug)]
pub enum Nut17Event {
    MintQuote(Nut04MintQuoteResponse),
    MeltQuote(Nut05MeltQuoteResponse),
    ProofState(Nut07StateEntry),
}

#[derive(Clone, Debug, Deserialize)]
struct Nut17RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct Nut17SubscribeParams {
    kind: Nut17Kind,
    #[serde(rename = "subId")]
    sub_id: String,
    filters: Vec<String>,
}

struct ActiveSub {
    kind: Nut17Kind,
    filters: HashSet<String>,
}

fn compute_ws_accept(sec_key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(sec_key.trim().as_bytes());
    sha1.update(WS_GUID.as_bytes());
    B64_STD.encode(sha1.finalize())
}

pub async fn handle_nut17_ws_upgrade(
    State(mint): State<SealCashuMint>,
    req: Request,
) -> Response<Body> {
    let Some(ws_key) = req
        .headers()
        .get(header::SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
    else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("missing Sec-WebSocket-Key"))
            .unwrap();
    };
    let accept = compute_ws_accept(&ws_key);
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            let io = TokioIo::new(upgraded);
            let _ = serve_nut17_ws_stream(mint, io).await;
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(Body::empty())
        .unwrap()
}

pub async fn read_ws_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 2];
    match stream.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let len_code = (hdr[1] & 0x7F) as usize;
    let payload_len = if len_code <= 125 {
        len_code
    } else if len_code == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await?;
        u16::from_be_bytes(ext) as usize
    } else {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await?;
        u64::from_be_bytes(ext) as usize
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok(Some((opcode, payload)))
}

pub async fn write_ws_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(0x80 | (opcode & 0x0F));
    let mask_bit = if mask_key.is_some() { 0x80u8 } else { 0x00u8 };
    let len = payload.len();
    if len <= 125 {
        frame.push(mask_bit | (len as u8));
    } else if len <= 65_535 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if let Some(mask) = mask_key {
        frame.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
    } else {
        frame.extend_from_slice(payload);
    }
    stream.write_all(&frame).await?;
    stream.flush().await
}

async fn send_json<S: AsyncWrite + Unpin>(stream: &mut S, v: &Value) -> std::io::Result<()> {
    let raw = serde_json::to_vec(v).unwrap_or_default();
    write_ws_frame(stream, 0x1, &raw, None).await
}

/// Serves official `NUT-17` JSON-RPC 2.0 subscriptions & real-time push events over an upgraded WebSocket!
pub async fn serve_nut17_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mint: SealCashuMint,
    mut stream: S,
) -> std::io::Result<()> {
    let mut rx = mint.subscribe_nut17();
    let mut subs: HashMap<String, ActiveSub> = HashMap::new();

    loop {
        tokio::select! {
            inbound = read_ws_frame(&mut stream) => {
                let Some((opcode, payload)) = inbound? else { break; };
                match opcode {
                    0x1 | 0x2 => {
                        let Ok(req) = serde_json::from_slice::<Nut17RpcRequest>(&payload) else {
                            send_json(&mut stream, &json!({
                                "jsonrpc": "2.0",
                                "error": { "code": -32700, "message": "Parse error" },
                                "id": null
                            })).await?;
                            continue;
                        };
                        match req.method.as_str() {
                            "subscribe" => {
                                let Ok(p) = serde_json::from_value::<Nut17SubscribeParams>(req.params) else {
                                    send_json(&mut stream, &json!({
                                        "jsonrpc": "2.0",
                                        "error": { "code": -32602, "message": "Invalid subscribe params" },
                                        "id": req.id
                                    })).await?;
                                    continue;
                                };
                                let sub_id = p.sub_id.clone();
                                let filters_vec = p.filters.clone();
                                let filter_set: HashSet<String> = p
                                    .filters
                                    .into_iter()
                                    .map(|f| f.to_lowercase())
                                    .collect();
                                let kind = p.kind.clone();
                                subs.insert(sub_id.clone(), ActiveSub { kind: kind.clone(), filters: filter_set });

                                // 1. Acknowledge subscription (`status: "OK"`)
                                send_json(&mut stream, &json!({
                                    "jsonrpc": "2.0",
                                    "result": { "status": "OK", "subId": sub_id },
                                    "id": req.id
                                })).await?;

                                // 2. Per NUT-17 spec, immediately emit current state snapshot for each filter!
                                match kind {
                                    Nut17Kind::Bolt11MintQuote => {
                                        for qid in &filters_vec {
                                            if let Ok(q) = mint.get_mint_quote("bolt11", qid) {
                                                send_json(&mut stream, &json!({
                                                    "jsonrpc": "2.0",
                                                    "method": "subscribe",
                                                    "params": { "subId": sub_id, "payload": q }
                                                })).await?;
                                            }
                                        }
                                    }
                                    Nut17Kind::Bolt11MeltQuote => {
                                        for qid in &filters_vec {
                                            if let Ok(q) = mint.get_melt_quote("bolt11", qid) {
                                                send_json(&mut stream, &json!({
                                                    "jsonrpc": "2.0",
                                                    "method": "subscribe",
                                                    "params": { "subId": sub_id, "payload": q }
                                                })).await?;
                                            }
                                        }
                                    }
                                    Nut17Kind::ProofState => {
                                        if let Ok(cs) = mint.check_state(Nut07CheckStateRequest { ys: filters_vec }).await {
                                            for st in cs.states {
                                                send_json(&mut stream, &json!({
                                                    "jsonrpc": "2.0",
                                                    "method": "subscribe",
                                                    "params": { "subId": sub_id, "payload": st }
                                                })).await?;
                                            }
                                        }
                                    }
                                }
                            }
                            "unsubscribe" => {
                                let sub_id = req.params.get("subId").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                                subs.remove(&sub_id);
                                send_json(&mut stream, &json!({
                                    "jsonrpc": "2.0",
                                    "result": { "status": "OK", "subId": sub_id },
                                    "id": req.id
                                })).await?;
                            }
                            _ => {
                                send_json(&mut stream, &json!({
                                    "jsonrpc": "2.0",
                                    "error": { "code": -32601, "message": "Method not found" },
                                    "id": req.id
                                })).await?;
                            }
                        }
                    }
                    0x8 => {
                        let _ = write_ws_frame(&mut stream, 0x8, &[], None).await;
                        break;
                    }
                    0x9 => {
                        write_ws_frame(&mut stream, 0xA, &payload, None).await?;
                    }
                    _ => {}
                }
            }
            ev_res = rx.recv() => {
                match ev_res {
                    Ok(ev) => {
                        for (sub_id, sub) in &subs {
                            match (&sub.kind, &ev) {
                                (Nut17Kind::Bolt11MintQuote, Nut17Event::MintQuote(q))
                                    if sub.filters.contains("*") || sub.filters.contains(&q.quote.to_lowercase()) =>
                                {
                                    send_json(&mut stream, &json!({
                                        "jsonrpc": "2.0",
                                        "method": "subscribe",
                                        "params": { "subId": sub_id, "payload": q }
                                    })).await?;
                                }
                                (Nut17Kind::Bolt11MeltQuote, Nut17Event::MeltQuote(q))
                                    if sub.filters.contains("*") || sub.filters.contains(&q.quote.to_lowercase()) =>
                                {
                                    send_json(&mut stream, &json!({
                                        "jsonrpc": "2.0",
                                        "method": "subscribe",
                                        "params": { "subId": sub_id, "payload": q }
                                    })).await?;
                                }
                                (Nut17Kind::ProofState, Nut17Event::ProofState(st))
                                    if sub.filters.contains("*") || sub.filters.contains(&st.y.to_lowercase()) =>
                                {
                                    send_json(&mut stream, &json!({
                                        "jsonrpc": "2.0",
                                        "method": "subscribe",
                                        "params": { "subId": sub_id, "payload": st }
                                    })).await?;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}
