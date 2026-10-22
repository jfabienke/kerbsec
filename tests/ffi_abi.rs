//! Checks the hand-written FFI declarations in `kerbsec::ffi` against the
//! bindgen output of `libgssapi-sys`, which is generated from the real GSS-API
//! headers installed on the build machine. A mismatch here is memory unsafety at
//! the FFI boundary, so constants and struct layouts are compared, not re-typed.

#![cfg(unix)]

use kerbsec::ffi;
use libgssapi_sys as sys;
use std::mem::{align_of, offset_of, size_of};

#[test]
fn iov_buffer_type_constants_match_headers() {
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_EMPTY,
        sys::GSS_IOV_BUFFER_TYPE_EMPTY
    );
    assert_eq!(ffi::GSS_IOV_BUFFER_TYPE_DATA, sys::GSS_IOV_BUFFER_TYPE_DATA);
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_HEADER,
        sys::GSS_IOV_BUFFER_TYPE_HEADER
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_MECH_PARAMS,
        sys::GSS_IOV_BUFFER_TYPE_MECH_PARAMS
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
        sys::GSS_IOV_BUFFER_TYPE_TRAILER
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_PADDING,
        sys::GSS_IOV_BUFFER_TYPE_PADDING
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_STREAM,
        sys::GSS_IOV_BUFFER_TYPE_STREAM
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_TYPE_SIGN_ONLY,
        sys::GSS_IOV_BUFFER_TYPE_SIGN_ONLY
    );
    assert_eq!(
        ffi::GSS_IOV_BUFFER_FLAG_ALLOCATE,
        sys::GSS_IOV_BUFFER_FLAG_ALLOCATE
    );
}

#[test]
fn context_flag_constants_match_headers() {
    assert_eq!(ffi::GSS_C_DELEG_FLAG, sys::GSS_C_DELEG_FLAG);
    assert_eq!(ffi::GSS_C_MUTUAL_FLAG, sys::GSS_C_MUTUAL_FLAG);
    assert_eq!(ffi::GSS_C_REPLAY_FLAG, sys::GSS_C_REPLAY_FLAG);
    assert_eq!(ffi::GSS_C_SEQUENCE_FLAG, sys::GSS_C_SEQUENCE_FLAG);
    assert_eq!(ffi::GSS_C_CONF_FLAG, sys::GSS_C_CONF_FLAG);
    assert_eq!(ffi::GSS_C_INTEG_FLAG, sys::GSS_C_INTEG_FLAG);
    assert_eq!(ffi::GSS_C_ANON_FLAG, sys::GSS_C_ANON_FLAG);
    assert_eq!(ffi::GSS_C_PROT_READY_FLAG, sys::GSS_C_PROT_READY_FLAG);
    assert_eq!(ffi::GSS_C_TRANS_FLAG, sys::GSS_C_TRANS_FLAG);
    assert_eq!(ffi::GSS_C_DCE_STYLE, sys::GSS_C_DCE_STYLE);
}

#[test]
fn status_and_qop_constants_match_headers() {
    assert_eq!(ffi::GSS_S_COMPLETE, sys::GSS_S_COMPLETE);
    assert_eq!(
        ffi::GSS_C_SUPPLEMENTARY_MASK,
        sys::_GSS_C_SUPPLEMENTARY_MASK
    );
    assert_eq!(ffi::GSS_C_QOP_DEFAULT, sys::GSS_C_QOP_DEFAULT);
    assert_eq!(ffi::GSS_C_GSS_CODE, sys::GSS_C_GSS_CODE as i32);
    assert_eq!(ffi::GSS_C_MECH_CODE, sys::GSS_C_MECH_CODE as i32);
}

/// kerbsec only passes pointers to `gss_buffer_desc` values it created, so size and
/// field offsets must match the header; its alignment may be stricter. (Apple's
/// headers `#pragma pack(2)` these structs on Intel Macs, which lowers theirs.)
#[test]
fn gss_buffer_desc_layout_matches_headers() {
    assert_eq!(
        size_of::<ffi::gss_buffer_desc>(),
        size_of::<sys::gss_buffer_desc>()
    );
    assert!(align_of::<ffi::gss_buffer_desc>() >= align_of::<sys::gss_buffer_desc>());
    assert_eq!(
        offset_of!(ffi::gss_buffer_desc, length),
        offset_of!(sys::gss_buffer_desc, length)
    );
    assert_eq!(
        offset_of!(ffi::gss_buffer_desc, value),
        offset_of!(sys::gss_buffer_desc, value)
    );
}

/// The IOV calls, and so `gss_iov_buffer_desc` arrays, are only used on Linux. Apple
/// packs this struct on Intel Macs (20 bytes, not 24), so it must never be used there.
#[cfg(target_os = "linux")]
#[test]
fn gss_iov_buffer_desc_layout_matches_headers() {
    assert_eq!(
        size_of::<ffi::gss_iov_buffer_desc>(),
        size_of::<sys::gss_iov_buffer_desc>()
    );
    assert_eq!(
        align_of::<ffi::gss_iov_buffer_desc>(),
        align_of::<sys::gss_iov_buffer_desc>()
    );
    assert_eq!(
        offset_of!(ffi::gss_iov_buffer_desc, type_),
        offset_of!(sys::gss_iov_buffer_desc, type_)
    );
    assert_eq!(
        offset_of!(ffi::gss_iov_buffer_desc, buffer),
        offset_of!(sys::gss_iov_buffer_desc, buffer)
    );
}

#[test]
fn scalar_typedefs_match_headers() {
    assert_eq!(size_of::<ffi::OM_uint32>(), size_of::<sys::OM_uint32>());
    assert_eq!(size_of::<ffi::gss_qop_t>(), size_of::<sys::gss_qop_t>());
    assert_eq!(
        size_of::<ffi::gss_ctx_id_t>(),
        size_of::<sys::gss_ctx_id_t>()
    );
}
