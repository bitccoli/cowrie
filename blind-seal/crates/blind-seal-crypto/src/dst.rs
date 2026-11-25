use blstrs::G1Projective;
use serde::{Deserialize, Serialize};

/// Pluggable Hash-to-Curve Domain Separation Tag (DST) profiles.
///
/// Note: Blind-Seal key servers sign pre-blinded `G1` points (`M' = r * H_dst(m)`),
/// so key servers are completely agnostic to which `DstProfile` a client/mint uses.
/// Only the client (blinding/unblinding) and redemption verifier need `DstProfile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DstProfile {
    /// Sui Move native `sui::bls12381::hash_to_g1` IETF NUL suite.
    /// Enables single-call on-chain verification in Sui Move with zero witness overhead.
    SuiNative,
    /// Federated Cashu BLS12-381 keyset profile (NUT BLS draft).
    CashuBls,
    /// Downstream Fedimint `fedimint-tbs` BLS12-381 hash-to-G1 profile.
    FedimintTbs,
    /// Arbitrary custom DST bytes for forward compatibility with evolving NUT/FIP specs.
    Custom(Vec<u8>),
}

impl DstProfile {
    pub const SUI_NATIVE_DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    pub const CASHU_BLS_DST: &'static [u8] = b"CASHU_BLS12381G1_XMD:SHA-256_SSWU_RO_V1_";
    pub const FEDIMINT_TBS_DST: &'static [u8] = b"FEDIMINT_TBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SuiNative => Self::SUI_NATIVE_DST,
            Self::CashuBls => Self::CASHU_BLS_DST,
            Self::FedimintTbs => Self::FEDIMINT_TBS_DST,
            Self::Custom(bytes) => bytes.as_slice(),
        }
    }

    /// Hashes an arbitrary message byte slice onto the prime-order subgroup `G1`
    /// using RFC 9380 `ExpandMsgXmd<SHA-256>` SSWU random-oracle mapping.
    pub fn hash_to_g1(&self, message: &[u8]) -> G1Projective {
        G1Projective::hash_to_curve(message, self.as_bytes(), &[])
    }
}
