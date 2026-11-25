//! `jsonrpsee`-compatible JSON-RPC 2.0 over RFC 6455 WebSockets (`ws://.../ws`) & HTTP POST,
//! plus `iroh` QUIC endpoint advertisement (`fedimint/rpc/0` ALPN) for Virtual Guardians.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Response, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64_STD, Engine};
use blind_seal_sdk::{sui_backend::Lnv2ContractOnChain, SdkError};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    encoding::FedimintDecodable,
    wire::{FedimintTransaction, IrohPeerEndpoint, Lnv2OutgoingRequest, OutPoint},
    VirtualGuardianShim,
};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Unwraps upstream `fedimint-api-client`'s `ApiRequestErased` (`[{"auth": null, "params": ...}]`)
/// as well as plain positional `[param0]` or direct JSON object `params`.
fn extract_inner_param(params: &Value) -> &Value {
    if let Some(arr) = params.as_array() {
        if let Some(first) = arr.first() {
            if let Some(obj) = first.as_object() {
                if obj.contains_key("params") && (obj.contains_key("auth") || obj.len() <= 2) {
                    return obj.get("params").unwrap_or(&Value::Null);
                }
            }
            return first;
        }
    }
    if let Some(obj) = params.as_object() {
        if obj.contains_key("params") && (obj.contains_key("auth") || obj.len() <= 2) {
            return obj.get("params").unwrap_or(&Value::Null);
        }
    }
    params
}

/// Dispatches an upstream Fedimint `IGlobalFederationApi` / module JSON-RPC 2.0 call on a `VirtualGuardianShim`.
pub async fn dispatch_jsonrpc(shim: &VirtualGuardianShim, req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone();
    match dispatch_method(shim, &req.method, &req.params).await {
        Ok(res) => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(res),
            error: None,
        },
        Err(err) => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(json!({
                "code": -32000,
                "message": err.to_string(),
            })),
        },
    }
}

async fn dispatch_method(
    shim: &VirtualGuardianShim,
    method: &str,
    raw_params: &Value,
) -> Result<Value, SdkError> {
    let p = extract_inner_param(raw_params);
    match method {
        "version" => Ok(json!({
            "core": { "major": 0, "minor": 5 },
            "modules": {
                "0": { "major": 0, "minor": 5 },
                "1": { "major": 0, "minor": 5 }
            }
        })),
        "status" => Ok(json!({
            "server": "Synced",
            "federation": {
                "session_count": shim.session_count(),
                "status_by_peer": {}
            }
        })),
        "client_config" | "download_client_config" => {
            let cfg = shim.download_client_config();
            Ok(serde_json::to_value(cfg).map_err(|e| SdkError::Rpc(e.to_string()))?)
        }
        "iroh_endpoint_info" => {
            let pk_hex = hex::encode(shim.guardian_signing_key.verifying_key().to_bytes());
            let ep = IrohPeerEndpoint {
                peer_id: shim.peer_id,
                node_id_hex: pk_hex,
                relay_url: "https://relay.iroh.network".into(),
                alpn: "fedimint/rpc/0".into(),
            };
            Ok(serde_json::to_value(ep).map_err(|e| SdkError::Rpc(e.to_string()))?)
        }
        "submit_transaction" => {
            // Accept EITHER upstream `SerdeModuleEncoding<Transaction>` hex string OR JSON `FedimintTransaction`!
            let tx: FedimintTransaction = if let Some(hex_str) = p.as_str() {
                FedimintTransaction::consensus_decode_hex(hex_str)
                    .map_err(|e| SdkError::Rpc(format!("FedimintDecodable tx error: {e}")))?
            } else {
                serde_json::from_value(p.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?
            };
            let txid = shim.submit_transaction(&tx)?;
            Ok(json!({
                "txid": hex::encode(txid),
                "accepted": true
            }))
        }
        "await_transaction" => {
            let txid_hex = p
                .as_str()
                .or_else(|| p.get("txid").and_then(|v| v.as_str()))
                .unwrap_or_default();
            Ok(json!(txid_hex))
        }
        "await_output_outcome" => {
            let outpoint: OutPoint = if let Some(hex_str) = p.as_str() {
                OutPoint::consensus_decode_hex(hex_str)
                    .map_err(|e| SdkError::Rpc(e.to_string()))?
            } else if let Some(txid_hex) = p.get("txid").and_then(|v| v.as_str()) {
                let raw_txid = hex::decode(txid_hex).map_err(|e| SdkError::Rpc(e.to_string()))?;
                let arr: [u8; 32] = raw_txid
                    .try_into()
                    .map_err(|_| SdkError::Rpc("txid must be 32 bytes".into()))?;
                let out_idx = p.get("out_idx").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                OutPoint { txid: arr, out_idx }
            } else {
                serde_json::from_value(p.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?
            };
            let out = shim.await_output_outcome(outpoint).await?;
            Ok(json!({
                "peer_id": out.peer_id,
                "share": out.share,
                "serde_module_hex": out.to_serde_module_hex()
            }))
        }
        "session_count" => Ok(json!(shim.session_count())),
        "await_block" | "await_session_outcome" => {
            let idx = p
                .as_u64()
                .or_else(|| p.get("index").and_then(|v| v.as_u64()))
                .or_else(|| p.get("session_index").and_then(|v| v.as_u64()))
                .ok_or_else(|| SdkError::Rpc("missing session index".into()))?;
            let signed = shim.await_session_outcome(idx)?;
            Ok(serde_json::to_value(signed).map_err(|e| SdkError::Rpc(e.to_string()))?)
        }
        "module_1_lnv2_submit_outgoing" => {
            let req: Lnv2OutgoingRequest =
                serde_json::from_value(p.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?;
            let contract = shim.submit_lnv2_outgoing(&req)?;
            Ok(serde_json::to_value(contract).map_err(|e| SdkError::Rpc(e.to_string()))?)
        }
        "module_1_lnv2_await_tpe_share" => {
            let contract: Lnv2ContractOnChain =
                serde_json::from_value(p.clone()).map_err(|e| SdkError::Rpc(e.to_string()))?;
            let share = shim.await_lnv2_tpe_share(&contract).await?;
            Ok(serde_json::to_value(share).map_err(|e| SdkError::Rpc(e.to_string()))?)
        }
        unknown => Err(SdkError::Rpc(format!("unknown JSON-RPC method: {unknown}"))),
    }
}

/// HTTP JSON-RPC 2.0 handler (`POST /jsonrpc`).
pub async fn handle_http_jsonrpc(
    State(shim): State<VirtualGuardianShim>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(dispatch_jsonrpc(&shim, req).await)
}

pub fn compute_ws_accept_key(sec_ws_key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(sec_ws_key.trim().as_bytes());
    sha1.update(WS_GUID.as_bytes());
    B64_STD.encode(sha1.finalize())
}

/// RFC 6455 WebSocket HTTP `101 Switching Protocols` handler (`GET /ws` & `GET /`).
pub async fn handle_ws_upgrade(
    State(shim): State<VirtualGuardianShim>,
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
            .body(Body::from("missing Sec-WebSocket-Key header"))
            .unwrap();
    };

    let accept_val = compute_ws_accept_key(&ws_key);
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            let io = TokioIo::new(upgraded);
            let _ = serve_ws_jsonrpc_stream(shim, io).await;
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept_val)
        .body(Body::empty())
        .unwrap()
}

// ============================================================================
// RFC 6455 WebSocket Framing (Server & Client over any AsyncRead + AsyncWrite)
// ============================================================================

async fn read_ws_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<(u8, Vec<u8>)>> {
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

async fn write_ws_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(0x80 | (opcode & 0x0F)); // FIN = 1
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

/// Serves `jsonrpsee` JSON-RPC 2.0 messages over an upgraded RFC 6455 WebSocket stream.
pub async fn serve_ws_jsonrpc_stream<S: AsyncRead + AsyncWrite + Unpin>(
    shim: VirtualGuardianShim,
    mut stream: S,
) -> std::io::Result<()> {
    while let Some((opcode, payload)) = read_ws_frame(&mut stream).await? {
        match opcode {
            0x1 | 0x2 => {
                // Text (0x1) or Binary (0x2) JSON-RPC 2.0 frame
                let resp = match serde_json::from_slice::<JsonRpcRequest>(&payload) {
                    Ok(req) => dispatch_jsonrpc(&shim, req).await,
                    Err(e) => JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: Value::Null,
                        result: None,
                        error: Some(json!({ "code": -32700, "message": format!("parse error: {e}") })),
                    },
                };
                let encoded = serde_json::to_vec(&resp).unwrap_or_default();
                write_ws_frame(&mut stream, 0x1, &encoded, None).await?;
            }
            0x8 => {
                // Close frame
                let _ = write_ws_frame(&mut stream, 0x8, &[], None).await;
                break;
            }
            0x9 => {
                // Ping -> Pong
                write_ws_frame(&mut stream, 0xA, &payload, None).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Lightweight `jsonrpsee`-style WebSocket JSON-RPC 2.0 client speaking masked RFC 6455 frames
/// with upstream `ApiRequestErased` (`[{"auth": null, "params": ...}]`) parameter wrapping.
pub struct WsFederationRpcClient<S> {
    stream: S,
    next_id: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsFederationRpcClient<S> {
    pub fn new(stream: S) -> Self {
        Self { stream, next_id: 1 }
    }

    pub async fn call_erased(&mut self, method: &str, params: Value) -> Result<Value, SdkError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(id),
            method: method.into(),
            params: json!([{ "auth": null, "params": params }]),
        };
        let raw = serde_json::to_vec(&req).map_err(|e| SdkError::Rpc(e.to_string()))?;
        // Per RFC 6455 Section 5.3, client-to-server WebSocket frames MUST be masked!
        write_ws_frame(&mut self.stream, 0x1, &raw, Some([0x37, 0xFA, 0x21, 0x3D]))
            .await
            .map_err(|e| SdkError::Rpc(e.to_string()))?;

        let Some((opcode, resp_bytes)) = read_ws_frame(&mut self.stream)
            .await
            .map_err(|e| SdkError::Rpc(e.to_string()))?
        else {
            return Err(SdkError::Rpc("WebSocket closed before response".into()));
        };
        if opcode != 0x1 {
            return Err(SdkError::Rpc(format!("unexpected WS opcode {opcode}")));
        }
        let resp: JsonRpcResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| SdkError::Rpc(e.to_string()))?;
        if let Some(err) = resp.error {
            return Err(SdkError::Rpc(format!("JSON-RPC error: {err}")));
        }
        Ok(resp.result.unwrap_or(Value::Null))
    }

    pub async fn close(mut self) -> std::io::Result<()> {
        write_ws_frame(&mut self.stream, 0x8, &[], Some([0x11, 0x22, 0x33, 0x44])).await
    }
}
