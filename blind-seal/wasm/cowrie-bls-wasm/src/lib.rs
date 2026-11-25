use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, Scalar,
};
use sha2::{Digest, Sha256, Sha512};

fn scalar_from_seed32(seed32: &[u8; 32]) -> Option<Scalar> {
    let mut h = Sha512::new();
    h.update(b"COWRIE_BROWSER_BLINDING_SCALAR_V1");
    h.update(seed32);
    let wide: [u8; 64] = h.finalize().into();
    let s = Scalar::from_bytes_wide(&wide);
    if s == Scalar::zero() {
        None
    } else {
        Some(s)
    }
}

fn hash_msg_g1(msg: &[u8], dst: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], dst)
}

#[no_mangle]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn wasm_dealloc(ptr: *mut u8, cap: usize) {
    if !ptr.is_null() && cap > 0 {
        let _ = Vec::from_raw_parts(ptr, 0, cap);
    }
}

/// Computes `Y = H_dst(msg)` (48-byte compressed `G1` point) for `NUT-07` `/v1/checkstate`.
/// Returns `1` on success, `0` on failure.
#[no_mangle]
pub unsafe extern "C" fn wasm_hash_to_y(
    msg_ptr: *const u8,
    msg_len: usize,
    dst_ptr: *const u8,
    dst_len: usize,
    out_y48_ptr: *mut u8,
) -> u32 {
    let msg = core::slice::from_raw_parts(msg_ptr, msg_len);
    let dst = core::slice::from_raw_parts(dst_ptr, dst_len);
    let y = G1Affine::from(hash_msg_g1(msg, dst));
    if bool::from(y.is_identity()) {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_y48_ptr, 48);
    out.copy_from_slice(&y.to_compressed());
    1
}

/// Client-side blinding: given `(msg, dst, seed32)`, computes `B_ = r * H_dst(msg)` (48 bytes)
///entirely inside browser WASM so the mint server NEVER sees `msg` (`secret`) or `seed32` (`r`)!
#[no_mangle]
pub unsafe extern "C" fn wasm_blind_message(
    msg_ptr: *const u8,
    msg_len: usize,
    dst_ptr: *const u8,
    dst_len: usize,
    seed32_ptr: *const u8,
    out_b48_ptr: *mut u8,
) -> u32 {
    let msg = core::slice::from_raw_parts(msg_ptr, msg_len);
    let dst = core::slice::from_raw_parts(dst_ptr, dst_len);
    let seed32: &[u8; 32] = match core::slice::from_raw_parts(seed32_ptr, 32).try_into() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let Some(r) = scalar_from_seed32(seed32) else {
        return 0;
    };
    let b_proj = hash_msg_g1(msg, dst) * r;
    let b_aff = G1Affine::from(b_proj);
    if bool::from(b_aff.is_identity()) {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_b48_ptr, 48);
    out.copy_from_slice(&b_aff.to_compressed());
    1
}

/// Client-side unblinding AND offline `BLS12-381` pairing verification (`e(C, G2) == e(H_dst(msg), PK_G2)`):
/// Unblinds `C = r^-1 * C_` and verifies the signature against the mint's 96-byte `G2` denomination pubkey
/// BEFORE accepting the proof into browser `localStorage`!
#[no_mangle]
pub unsafe extern "C" fn wasm_unblind_and_verify(
    c_blind48_ptr: *const u8,
    seed32_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    dst_ptr: *const u8,
    dst_len: usize,
    pk_g2_96_ptr: *const u8,
    out_c48_ptr: *mut u8,
) -> u32 {
    let Ok(c_arr): Result<&[u8; 48], _> =
        core::slice::from_raw_parts(c_blind48_ptr, 48).try_into()
    else {
        return 0;
    };
    let Ok(seed32): Result<&[u8; 32], _> =
        core::slice::from_raw_parts(seed32_ptr, 32).try_into()
    else {
        return 0;
    };
    let Ok(pk_arr): Result<&[u8; 96], _> =
        core::slice::from_raw_parts(pk_g2_96_ptr, 96).try_into()
    else {
        return 0;
    };

    let c_blind_opt = G1Affine::from_compressed(c_arr);
    let pk_opt = G2Affine::from_compressed(pk_arr);
    if !bool::from(c_blind_opt.is_some()) || !bool::from(pk_opt.is_some()) {
        return 0;
    }
    let c_blind = c_blind_opt.unwrap();
    let pk_g2 = pk_opt.unwrap();
    if bool::from(c_blind.is_identity()) || bool::from(pk_g2.is_identity()) {
        return 0;
    }

    let Some(r) = scalar_from_seed32(seed32) else {
        return 0;
    };
    let r_inv_opt = r.invert();
    if !bool::from(r_inv_opt.is_some()) {
        return 0;
    }
    let c_unblind = G1Affine::from(G1Projective::from(c_blind) * r_inv_opt.unwrap());
    if bool::from(c_unblind.is_identity()) {
        return 0;
    }

    let msg = core::slice::from_raw_parts(msg_ptr, msg_len);
    let dst = core::slice::from_raw_parts(dst_ptr, dst_len);
    let h_aff = G1Affine::from(hash_msg_g1(msg, dst));

    // Offline bilinear pairing verification inside browser WASM!
    if pairing(&c_unblind, &G2Affine::generator()) != pairing(&h_aff, &pk_g2) {
        return 0;
    }

    let out = core::slice::from_raw_parts_mut(out_c48_ptr, 48);
    out.copy_from_slice(&c_unblind.to_compressed());
    1
}
