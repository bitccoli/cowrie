//! Upstream-compatible `fedimint_core::encoding::{Encodable, Decodable}` binary wire codec,
//! Bitcoin/Fedimint `VarInt` (`CompactSize`), `DynModuleEnvelope`, and forward-compatible TLV streams.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DecodeError {}

pub trait FedimintEncodable {
    fn consensus_encode(&self, out: &mut Vec<u8>);

    fn consensus_encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.consensus_encode(&mut buf);
        buf
    }

    fn consensus_encode_to_hex(&self) -> String {
        hex::encode(self.consensus_encode_to_vec())
    }
}

pub trait FedimintDecodable: Sized {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError>;

    fn consensus_decode_whole(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cursor = bytes;
        let val = Self::consensus_decode(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(DecodeError(format!(
                "trailing {} bytes after FedimintDecodable",
                cursor.len()
            )));
        }
        Ok(val)
    }

    fn consensus_decode_hex(hex_str: &str) -> Result<Self, DecodeError> {
        let raw = hex::decode(hex_str.trim()).map_err(|e| DecodeError(e.to_string()))?;
        Self::consensus_decode_whole(&raw)
    }
}

pub fn read_exact<'a>(slice: &mut &'a [u8], len: usize) -> Result<&'a [u8], DecodeError> {
    if slice.len() < len {
        return Err(DecodeError(format!(
            "unexpected EOF: needed {len} bytes, had {}",
            slice.len()
        )));
    }
    let (head, tail) = slice.split_at(len);
    *slice = tail;
    Ok(head)
}

/// Encodes `u64` using Bitcoin/Fedimint `VarInt` (`CompactSize`).
pub fn encode_varint(val: u64, out: &mut Vec<u8>) {
    if val < 0xFD {
        out.push(val as u8);
    } else if val <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&val.to_le_bytes());
    }
}

pub fn decode_varint(slice: &mut &[u8]) -> Result<u64, DecodeError> {
    let tag = read_exact(slice, 1)?[0];
    match tag {
        0x00..=0xFC => Ok(u64::from(tag)),
        0xFD => {
            let b = read_exact(slice, 2)?;
            let v = u16::from_le_bytes([b[0], b[1]]);
            if v < 0xFD {
                return Err(DecodeError("non-canonical 2-byte VarInt".into()));
            }
            Ok(u64::from(v))
        }
        0xFE => {
            let b = read_exact(slice, 4)?;
            let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            if v <= 0xFFFF {
                return Err(DecodeError("non-canonical 4-byte VarInt".into()));
            }
            Ok(u64::from(v))
        }
        0xFF => {
            let b = read_exact(slice, 8)?;
            let v = u64::from_le_bytes(b.try_into().unwrap());
            if v <= 0xFFFF_FFFF {
                return Err(DecodeError("non-canonical 8-byte VarInt".into()));
            }
            Ok(v)
        }
    }
}

impl FedimintEncodable for u8 {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl FedimintDecodable for u8 {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(read_exact(slice, 1)?[0])
    }
}

impl FedimintEncodable for u16 {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(u64::from(*self), out);
    }
}

impl FedimintDecodable for u16 {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let v = decode_varint(slice)?;
        u16::try_from(v).map_err(|_| DecodeError("VarInt overflow for u16".into()))
    }
}

impl FedimintEncodable for u32 {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(u64::from(*self), out);
    }
}

impl FedimintDecodable for u32 {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let v = decode_varint(slice)?;
        u32::try_from(v).map_err(|_| DecodeError("VarInt overflow for u32".into()))
    }
}

impl FedimintEncodable for u64 {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(*self, out);
    }
}

impl FedimintDecodable for u64 {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        decode_varint(slice)
    }
}

impl<const N: usize> FedimintEncodable for [u8; N] {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> FedimintDecodable for [u8; N] {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let raw = read_exact(slice, N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(raw);
        Ok(arr)
    }
}

impl FedimintEncodable for Vec<u8> {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(self.len() as u64, out);
        out.extend_from_slice(self);
    }
}

impl FedimintDecodable for Vec<u8> {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let len = decode_varint(slice)? as usize;
        if len > 16 * 1024 * 1024 {
            return Err(DecodeError("byte vector exceeds 16 MiB limit".into()));
        }
        Ok(read_exact(slice, len)?.to_vec())
    }
}

impl FedimintEncodable for String {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(self.len() as u64, out);
        out.extend_from_slice(self.as_bytes());
    }
}

impl FedimintDecodable for String {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::consensus_decode(slice)?;
        String::from_utf8(bytes).map_err(|e| DecodeError(e.to_string()))
    }
}

impl<K: FedimintEncodable, V: FedimintEncodable> FedimintEncodable for BTreeMap<K, V> {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        encode_varint(self.len() as u64, out);
        for (k, v) in self {
            k.consensus_encode(out);
            v.consensus_encode(out);
        }
    }
}

impl<K: FedimintDecodable + Ord, V: FedimintDecodable> FedimintDecodable for BTreeMap<K, V> {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        let count = decode_varint(slice)? as usize;
        if count > 65_536 {
            return Err(DecodeError("BTreeMap count exceeds limit".into()));
        }
        let mut map = BTreeMap::new();
        for _ in 0..count {
            let k = K::consensus_decode(slice)?;
            let v = V::consensus_decode(slice)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

/// Matches upstream Fedimint's `DynInput` / `DynOutput` / `DynOutputOutcome`:
/// `(module_instance_id: u16, payload_bytes: Vec<u8>)`.
/// Standard Fedimint module instance IDs: `0 = fedimint-mint`, `1 = fedimint-lnv2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynModuleEnvelope {
    pub module_instance_id: u16,
    pub payload: Vec<u8>,
}

impl FedimintEncodable for DynModuleEnvelope {
    fn consensus_encode(&self, out: &mut Vec<u8>) {
        self.module_instance_id.consensus_encode(out);
        self.payload.consensus_encode(out);
    }
}

impl FedimintDecodable for DynModuleEnvelope {
    fn consensus_decode(slice: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            module_instance_id: u16::consensus_decode(slice)?,
            payload: Vec::<u8>::consensus_decode(slice)?,
        })
    }
}

/// Forward-compatible Type-Length-Value record used by `OOBNotes` (`Vec<OOBNotesPart>`)
/// and `InviteCode` (`Vec<InviteCodePart>`) in upstream Fedimint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvRecord {
    pub variant: u64,
    pub bytes: Vec<u8>,
}

pub fn encode_tlv_stream(records: &[TlvRecord], out: &mut Vec<u8>) {
    encode_varint(records.len() as u64, out);
    for rec in records {
        encode_varint(rec.variant, out);
        rec.bytes.consensus_encode(out);
    }
}

pub fn decode_tlv_stream(slice: &mut &[u8]) -> Result<Vec<TlvRecord>, DecodeError> {
    let count = decode_varint(slice)? as usize;
    if count > 4096 {
        return Err(DecodeError("TLV stream exceeds 4096 records".into()));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let variant = decode_varint(slice)?;
        let bytes = Vec::<u8>::consensus_decode(slice)?;
        out.push(TlvRecord { variant, bytes });
    }
    Ok(out)
}
