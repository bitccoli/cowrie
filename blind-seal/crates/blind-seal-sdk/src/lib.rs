pub mod api;
pub mod client;
pub mod ptb;
pub mod sui_backend;

use blind_seal_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Sui Move policy / consensus abort: {0}")]
    MoveAbort(String),
    #[error("nullifier already spent on Sui: {0}")]
    NullifierAlreadySpent(String),
    #[error("transaction unbalanced: in={total_in}, out={total_out}, fee={fee}")]
    TransactionUnbalanced {
        total_in: u64,
        total_out: u64,
        fee: u64,
    },
    #[error("RPC transport error: {0}")]
    Rpc(String),
}
