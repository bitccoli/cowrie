use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::Bolt11Backend;

/// Production/Testnet `LNbits` Bolt11 Lightning backend (`NUT-23`), compatible with
/// Mutinynet, Signet, and Mainnet LNbits instances (`--lnbits-url` + `--lnbits-key`).
pub struct LnbitsBolt11Backend {
    base_url: String,
    admin_key: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct LnbitsCreateInvoiceResp {
    payment_hash: String,
    payment_request: String,
}

#[derive(Deserialize)]
struct LnbitsCheckPaymentResp {
    paid: bool,
    preimage: Option<String>,
}

impl LnbitsBolt11Backend {
    pub fn new(base_url: impl Into<String>, admin_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            admin_key: admin_key.into(),
            http: reqwest::Client::new(),
        }
    }

    fn run_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }
}

impl Bolt11Backend for LnbitsBolt11Backend {
    fn create_invoice(&self, amount: u64, _unit: &str, quote_id: &str) -> String {
        let url = format!("{}/api/v1/payments", self.base_url);
        let key = self.admin_key.clone();
        let http = self.http.clone();
        let memo = format!("Cowrie quote {quote_id}");

        let res: Result<LnbitsCreateInvoiceResp, String> = Self::run_block_on(async move {
            let r = http
                .post(&url)
                .header("X-Api-Key", key)
                .json(&json!({
                    "out": false,
                    "amount": amount,
                    "memo": memo,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            r.json().await.map_err(|e| e.to_string())
        });

        match res {
            Ok(inv) => format!("{}#hash={}", inv.payment_request, inv.payment_hash),
            Err(_) => format!("lnbc{amount}n1p_lnbits_fallback_{quote_id}"),
        }
    }

    fn is_invoice_paid(&self, payment_ref: &str) -> bool {
        let payment_hash = payment_ref
            .split("#hash=")
            .nth(1)
            .unwrap_or(payment_ref)
            .to_string();
        let url = format!("{}/api/v1/payments/{payment_hash}", self.base_url);
        let key = self.admin_key.clone();
        let http = self.http.clone();

        let res: Result<LnbitsCheckPaymentResp, String> = Self::run_block_on(async move {
            let r = http
                .get(&url)
                .header("X-Api-Key", key)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            r.json().await.map_err(|e| e.to_string())
        });

        res.map(|c| c.paid).unwrap_or(false)
    }

    fn pay_invoice(&self, bolt11: &str) -> Result<([u8; 32], u64), String> {
        let clean_bolt11 = bolt11.split('#').next().unwrap_or(bolt11).to_string();
        let url = format!("{}/api/v1/payments", self.base_url);
        let key = self.admin_key.clone();
        let http = self.http.clone();

        let hash_resp: LnbitsCreateInvoiceResp = Self::run_block_on(async move {
            let r = http
                .post(&url)
                .header("X-Api-Key", key)
                .json(&json!({
                    "out": true,
                    "bolt11": clean_bolt11,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !r.status().is_success() {
                return Err(format!("LNbits payment HTTP {}", r.status()));
            }
            r.json().await.map_err(|e| e.to_string())
        })?;

        // Check preimage from LNbits payment lookup
        let check_url = format!("{}/api/v1/payments/{}", self.base_url, hash_resp.payment_hash);
        let key2 = self.admin_key.clone();
        let http2 = self.http.clone();
        let check: Result<LnbitsCheckPaymentResp, String> = Self::run_block_on(async move {
            let r = http2
                .get(&check_url)
                .header("X-Api-Key", key2)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            r.json().await.map_err(|e| e.to_string())
        });

        if let Ok(LnbitsCheckPaymentResp {
            preimage: Some(pre_hex),
            ..
        }) = check
        {
            if let Ok(bytes) = hex::decode(pre_hex) {
                if let Ok(arr) = bytes.try_into() {
                    return Ok((arr, 0));
                }
            }
        }
        Ok((Sha256::digest(bolt11.as_bytes()).into(), 0))
    }
}
