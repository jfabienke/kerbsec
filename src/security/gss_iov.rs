//! Safe wrappers for GSS-API IOV operations
//!
//! This module provides safe Rust wrappers around the GSS-API IOV
//! (Input/Output Vector) functions for zero-copy message protection.
//!
//! # Platform Support
//!
//! - **Linux with the `iov` feature**: native `gss_wrap_iov`/`gss_unwrap_iov`
//! - **Otherwise (macOS, no `iov`)**: Falls back to regular `gss_wrap`/`gss_unwrap`; the whole
//!   token is returned in `IovWrap::header`
//!
//! # Confidentiality
//!
//! libgssapi discards `conf_state`, so every call here goes through our own FFI
//! and checks it. Requesting Privacy and getting an integrity-only token back is
//! an error ([`Error::ConfidentialityNotProvided`]), as is accepting an
//! unencrypted token when the caller requires Privacy.

// `&mut ClientCtx` is deliberate throughout: wrap/unwrap advance the context's
// sequence state inside GSS even though only the raw handle is touched here.
#![allow(clippy::needless_pass_by_ref_mut)]

use crate::error::{Error, Result};
use crate::ffi;
use crate::security::IovWrap;
use bytes::Bytes;
use libgssapi::context::ClientCtx;
use std::ptr;
use std::slice;
use zeroize::Zeroize;

#[cfg(feature = "trace")]
use tracing::{debug, error, instrument, warn};

/// Maximum sizes for IOV buffers based on RFC 4121 and common cipher suites.
/// These are generous upper bounds to handle all supported encryption types.
#[cfg(all(target_os = "linux", feature = "iov"))]
mod buffer_sizes {
    /// Maximum GSS header size (token header + encryption IV)
    /// AES-256 with 16-byte IV + GSS header overhead
    pub const MAX_HEADER_SIZE: usize = 256;

    /// Maximum padding size for block ciphers (AES block size = 16)
    pub const MAX_PADDING_SIZE: usize = 256;

    /// Maximum trailer size (checksum/MIC)
    /// SHA-384 based checksums can be up to 48 bytes + overhead
    pub const MAX_TRAILER_SIZE: usize = 256;
}

/// Get the raw GSS context handle from `ClientCtx`.
///
/// Uses the `raw_ctx` accessor of the vendored libgssapi (see
/// `vendor/libgssapi/README.md`), so nothing here depends on `ClientCtx`'s
/// field layout. The handle is owned by `ctx`; callers must only use it while
/// they hold the borrow and must never delete it.
///
/// # Errors
///
/// Returns [`Error::NotEstablished`] if no handle exists yet.
fn raw_handle(ctx: &ClientCtx) -> Result<ffi::gss_ctx_id_t> {
    let handle: ffi::gss_ctx_id_t = ctx.raw_ctx().cast();
    if handle.is_null() {
        return Err(Error::NotEstablished);
    }
    Ok(handle)
}

/// Fail if Privacy was requested but `conf_state` says it was not applied.
const fn require_conf_applied(
    conf_req: bool,
    conf_state: libc::c_int,
    what: &'static str,
) -> Result<()> {
    if conf_req && conf_state == 0 {
        return Err(Error::ConfidentialityNotProvided(what));
    }
    Ok(())
}

/// Wrap a PDU using GSS IOV for zero-copy operation
///
/// This is the real IOV implementation that avoids data copying on Linux.
/// On other platforms, it falls back to regular `gss_wrap` with the whole
/// token returned in the header.
///
/// `IovWrap::conf` reflects what the mechanism reported, not what was requested.
///
/// # Errors
///
/// Returns an error if:
/// - The GSS context is not established
/// - The wrap operation fails
/// - `conf_req` is set but confidentiality was not applied
/// - The mechanism requires padding, which the IOV layout here cannot carry
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(ctx),
    fields(conf_req, pdu_len = pdu.len())
))]
pub fn wrap_iov_real(ctx: &mut ClientCtx, pdu: &[u8], conf_req: bool) -> Result<IovWrap> {
    #[cfg(not(all(target_os = "linux", feature = "iov")))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV wrap not available on this platform, using fallback");

        wrap_iov_fallback(ctx, pdu, conf_req)
    }

    #[cfg(all(target_os = "linux", feature = "iov"))]
    {
        wrap_iov_native(ctx, pdu, conf_req)
    }
}

/// Native IOV wrap implementation for Linux
#[cfg(all(target_os = "linux", feature = "iov"))]
#[allow(clippy::too_many_lines)] // the four IOV descriptors are spelled out for clarity
fn wrap_iov_native(ctx: &mut ClientCtx, pdu: &[u8], conf_req: bool) -> Result<IovWrap> {
    use buffer_sizes::{MAX_HEADER_SIZE, MAX_PADDING_SIZE, MAX_TRAILER_SIZE};

    let ctx_handle = raw_handle(ctx)?;

    // Create IOV buffers with generous sizes based on RFC 4121
    let mut header_buf = vec![0u8; MAX_HEADER_SIZE];
    let mut data_buf = pdu.to_vec();
    let mut padding_buf = vec![0u8; MAX_PADDING_SIZE];
    let mut trailer_buf = vec![0u8; MAX_TRAILER_SIZE];

    let mut iov_descs = [
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER,
            buffer: ffi::gss_buffer_desc {
                length: header_buf.len(),
                value: header_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
            buffer: ffi::gss_buffer_desc {
                length: data_buf.len(),
                value: data_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING,
            buffer: ffi::gss_buffer_desc {
                length: padding_buf.len(),
                value: padding_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
            buffer: ffi::gss_buffer_desc {
                length: trailer_buf.len(),
                value: trailer_buf.as_mut_ptr().cast(),
            },
        },
    ];

    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;

    // SAFETY: All buffers are valid, live for the call, and sized as described;
    // `ctx_handle` is owned by `ctx`, which is mutably borrowed for the call.
    let major_status = unsafe {
        ffi::gss_wrap_iov(
            &mut minor_status,
            ctx_handle,
            i32::from(conf_req),
            ffi::GSS_C_QOP_DEFAULT,
            &mut conf_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        #[cfg(feature = "trace")]
        error!(
            target: "kerbsec::iov",
            major = format_args!("{:#x}", major_status),
            minor = format_args!("{:#x}", minor_status),
            "gss_wrap_iov failed"
        );
        data_buf.zeroize();
        return Err(gss_error(major_status, minor_status));
    }

    // Extract the actual used lengths (GSS updates these in-place)
    let header_len = iov_descs[0].buffer.length;
    let payload_len = iov_descs[1].buffer.length;
    let padding_len = iov_descs[2].buffer.length;
    let trailer_len = iov_descs[3].buffer.length;

    // Validate that GSS didn't try to write beyond our buffers
    if header_len > MAX_HEADER_SIZE
        || payload_len > data_buf.len()
        || padding_len > MAX_PADDING_SIZE
        || trailer_len > MAX_TRAILER_SIZE
    {
        data_buf.zeroize();
        return Err(Error::Iov(format!(
            "GSS returned unexpected sizes: header={header_len}, payload={payload_len}, padding={padding_len}, trailer={trailer_len}"
        )));
    }

    // `IovWrap` has no padding fragment, so a token that needs one would be
    // truncated and unverifiable by the peer. RFC 4121 (AES) never pads; this
    // only fires for legacy enctypes. Fail rather than emit a broken token.
    if padding_len != 0 {
        data_buf.zeroize();
        return Err(Error::Iov(format!(
            "mechanism produced {padding_len} bytes of IOV padding, which is not supported"
        )));
    }

    if let Err(e) = require_conf_applied(conf_req, conf_state, "gss_wrap_iov") {
        data_buf.zeroize();
        return Err(e);
    }

    header_buf.truncate(header_len);
    data_buf.truncate(payload_len);
    trailer_buf.truncate(trailer_len);

    let header = Bytes::from(header_buf);
    let payload = Bytes::from(data_buf);
    let trailer = Bytes::from(trailer_buf);

    #[cfg(feature = "trace")]
    debug!(
        target: "kerbsec::iov",
        conf = (conf_state != 0),
        pdu_len = pdu.len(),
        header_len = header.len(),
        payload_len = payload.len(),
        trailer_len = trailer.len(),
        "wrap_iov completed"
    );

    Ok(IovWrap {
        header,
        payload,
        trailer,
        conf: conf_state != 0,
    })
}

/// Fallback wrap implementation for platforms without IOV support (macOS, etc.)
///
/// Uses regular `gss_wrap`, observing `conf_state`, and returns the whole token
/// in `header` since the header/trailer split can't be recovered without IOV.
#[cfg_attr(all(target_os = "linux", feature = "iov"), allow(dead_code))]
fn wrap_iov_fallback(ctx: &mut ClientCtx, pdu: &[u8], conf_req: bool) -> Result<IovWrap> {
    let (token, conf_state) = wrap_token(ctx, pdu, conf_req)?;
    require_conf_applied(conf_req, conf_state, "gss_wrap")?;

    #[cfg(feature = "trace")]
    warn!(
        target: "kerbsec::iov",
        wrapped_len = token.len(),
        "fallback wrap: entire token in header, payload/trailer empty"
    );

    Ok(IovWrap {
        header: Bytes::from(token),
        payload: Bytes::new(),
        trailer: Bytes::new(),
        conf: conf_state != 0,
    })
}

/// Wrap `msg` into one `gss_wrap` token, returning it with the real `conf_state`.
///
/// # Errors
///
/// Returns an error if the context has no handle or `gss_wrap` fails.
pub(crate) fn wrap_token(
    ctx: &mut ClientCtx,
    msg: &[u8],
    conf_req: bool,
) -> Result<(Vec<u8>, libc::c_int)> {
    let ctx_handle = raw_handle(ctx)?;

    let mut input = ffi::gss_buffer_desc {
        length: msg.len(),
        value: msg.as_ptr().cast_mut().cast(),
    };
    let mut output = ffi::gss_buffer_desc {
        length: 0,
        value: ptr::null_mut(),
    };
    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;

    // SAFETY: `input` points at `msg`, which outlives the call and is only read;
    // `output` is filled by GSS and released below.
    let major_status = unsafe {
        ffi::gss_wrap(
            &mut minor_status,
            ctx_handle,
            i32::from(conf_req),
            ffi::GSS_C_QOP_DEFAULT,
            &mut input,
            &mut conf_state,
            &mut output,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        return Err(gss_error(major_status, minor_status));
    }

    Ok((take_gss_buffer(&mut output), conf_state))
}

/// Unwrap one `gss_wrap` token, requiring Privacy if `require_conf`.
///
/// Returns the plaintext. On a confidentiality failure the plaintext is wiped
/// and [`Error::ConfidentialityNotProvided`] is returned.
///
/// # Errors
///
/// Returns an error if the context has no handle, `gss_unwrap` fails (for
/// example integrity check failure), or the token was not encrypted while
/// `require_conf` is set.
pub(crate) fn unwrap_token(
    ctx: &mut ClientCtx,
    token: &[u8],
    require_conf: bool,
) -> Result<Vec<u8>> {
    let ctx_handle = raw_handle(ctx)?;

    let mut input = ffi::gss_buffer_desc {
        length: token.len(),
        value: token.as_ptr().cast_mut().cast(),
    };
    let mut output = ffi::gss_buffer_desc {
        length: 0,
        value: ptr::null_mut(),
    };
    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;
    let mut qop_state: ffi::gss_qop_t = 0;

    // SAFETY: `input` points at `token`, which outlives the call and is only
    // read; `output` is filled by GSS and released below.
    let major_status = unsafe {
        ffi::gss_unwrap(
            &mut minor_status,
            ctx_handle,
            &mut input,
            &mut output,
            &mut conf_state,
            &mut qop_state,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        return Err(gss_error(major_status, minor_status));
    }

    let mut plaintext = take_gss_buffer(&mut output);
    if let Err(e) = require_conf_applied(require_conf, conf_state, "gss_unwrap") {
        plaintext.zeroize();
        return Err(e);
    }
    Ok(plaintext)
}

/// Copy a GSS-allocated buffer into a `Vec`, wiping and releasing the original.
fn take_gss_buffer(buf: &mut ffi::gss_buffer_desc) -> Vec<u8> {
    let out = if buf.value.is_null() || buf.length == 0 {
        Vec::new()
    } else {
        // SAFETY: GSS reports `length` valid bytes at `value`.
        unsafe { slice::from_raw_parts(buf.value.cast::<u8>(), buf.length) }.to_vec()
    };

    if !buf.value.is_null() {
        // SAFETY: the buffer was allocated by GSS and may hold plaintext.
        unsafe {
            slice::from_raw_parts_mut(buf.value.cast::<u8>(), buf.length).zeroize();
            let mut minor_status: ffi::OM_uint32 = 0;
            ffi::gss_release_buffer(&mut minor_status, buf);
        }
    }
    out
}

/// Unwrap a token given as separate header, data and trailer fragments
///
/// If `require_conf` is set the data must have been encrypted; an
/// integrity-only token is rejected with [`Error::ConfidentialityNotProvided`].
///
/// # Errors
///
/// Returns an error if:
/// - The GSS context is not established
/// - The unwrap operation fails (e.g., integrity check failure)
/// - `require_conf` is set but the token was not encrypted
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(ctx),
    fields(
        header_len = header.len(),
        data_len = data.len(),
        trailer_len = trailer.len(),
        require_conf
    )
))]
pub fn unwrap_iov_real(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
    require_conf: bool,
) -> Result<Vec<u8>> {
    #[cfg(not(all(target_os = "linux", feature = "iov")))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV unwrap not available on this platform, using fallback");

        unwrap_iov_fallback(ctx, header, data, trailer, require_conf)
    }

    #[cfg(all(target_os = "linux", feature = "iov"))]
    {
        unwrap_iov_native(ctx, header, data, trailer, require_conf)
    }
}

/// Native IOV unwrap implementation for Linux
#[cfg(all(target_os = "linux", feature = "iov"))]
fn unwrap_iov_native(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
    require_conf: bool,
) -> Result<Vec<u8>> {
    let ctx_handle = raw_handle(ctx)?;

    // Reconstruct IOV buffers from the provided slices
    let mut header_buf = header.to_vec();
    let mut data_buf = data.to_vec();
    let mut padding_buf: Vec<u8> = Vec::new(); // wrap_iov_native rejects padding
    let mut trailer_buf = trailer.to_vec();

    let mut iov_descs = [
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER,
            buffer: ffi::gss_buffer_desc {
                length: header_buf.len(),
                value: header_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
            buffer: ffi::gss_buffer_desc {
                length: data_buf.len(),
                value: data_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING,
            buffer: ffi::gss_buffer_desc {
                length: padding_buf.len(),
                value: padding_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
            buffer: ffi::gss_buffer_desc {
                length: trailer_buf.len(),
                value: trailer_buf.as_mut_ptr().cast(),
            },
        },
    ];

    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;
    let mut qop_state: ffi::gss_qop_t = 0;

    // SAFETY: All buffers are valid and properly initialized; `ctx_handle` is
    // owned by `ctx`, which is mutably borrowed for the call.
    let major_status = unsafe {
        ffi::gss_unwrap_iov(
            &mut minor_status,
            ctx_handle,
            &mut conf_state,
            &mut qop_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        #[cfg(feature = "trace")]
        error!(
            target: "kerbsec::iov",
            major = format_args!("{:#x}", major_status),
            minor = format_args!("{:#x}", minor_status),
            "gss_unwrap_iov failed"
        );
        // Decryption is in place, so a failed call may leave partial plaintext.
        data_buf.zeroize();
        return Err(gss_error(major_status, minor_status));
    }

    if let Err(e) = require_conf_applied(require_conf, conf_state, "gss_unwrap_iov") {
        data_buf.zeroize();
        return Err(e);
    }

    #[cfg(feature = "trace")]
    debug!(
        target: "kerbsec::iov",
        plaintext_len = data_buf.len(),
        conf = (conf_state != 0),
        "unwrap_iov completed"
    );

    // Return the unwrapped data
    Ok(data_buf)
}

/// Fallback unwrap implementation for platforms without IOV support
#[cfg_attr(all(target_os = "linux", feature = "iov"), allow(dead_code))]
fn unwrap_iov_fallback(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
    require_conf: bool,
) -> Result<Vec<u8>> {
    // Reconstruct the complete token by concatenating header + data + trailer
    // This is the inverse of what wrap_iov_fallback produces
    let mut token = Vec::with_capacity(header.len() + data.len() + trailer.len());
    token.extend_from_slice(header);
    token.extend_from_slice(data);
    token.extend_from_slice(trailer);

    let plaintext = unwrap_token(ctx, &token, require_conf)?;

    #[cfg(feature = "trace")]
    warn!(
        target: "kerbsec::iov",
        token_len = token.len(),
        unwrapped_len = plaintext.len(),
        "fallback unwrap: reassembled token"
    );

    Ok(plaintext)
}

/// Get accurate wrap size limit using GSS-API
///
/// Given a maximum output (wrapped) size, calculates the maximum input
/// message size that can be wrapped without exceeding the limit. Uses
/// `gss_wrap_size_limit`, which is part of core GSS-API and available on all
/// platforms, so the answer accounts for the negotiated enctype.
///
/// # Arguments
///
/// * `ctx` - The GSS security context
/// * `conf_req` - Whether confidentiality (encryption) is requested
/// * `max_wrapped` - Maximum size of the wrapped output
///
/// # Returns
///
/// Maximum message size that can be wrapped, or an error if the query fails.
#[cfg_attr(
    feature = "trace",
    instrument(
        target = "kerbsec::iov",
        level = "debug",
        skip(ctx),
        fields(conf_req, max_wrapped)
    )
)]
pub fn wrap_size_limit_real(ctx: &ClientCtx, conf_req: bool, max_wrapped: usize) -> Result<usize> {
    let ctx_handle = raw_handle(ctx)?;

    let mut minor_status: ffi::OM_uint32 = 0;
    let mut max_input_size: ffi::OM_uint32 = 0;

    // SAFETY: All pointers are valid; `ctx_handle` is owned by `ctx`.
    let major_status = unsafe {
        ffi::gss_wrap_size_limit(
            &mut minor_status,
            ctx_handle,
            i32::from(conf_req),
            ffi::GSS_C_QOP_DEFAULT,
            ffi::OM_uint32::try_from(max_wrapped).unwrap_or(ffi::OM_uint32::MAX),
            &mut max_input_size,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        #[cfg(feature = "trace")]
        error!(
            target: "kerbsec::iov",
            major = format_args!("{:#x}", major_status),
            minor = format_args!("{:#x}", minor_status),
            "gss_wrap_size_limit failed"
        );
        return Err(gss_error(major_status, minor_status));
    }

    #[cfg(feature = "trace")]
    debug!(
        target: "kerbsec::iov",
        max_input = max_input_size,
        "wrap_size_limit calculated"
    );

    Ok(max_input_size as usize)
}

/// Convert GSS error to our Error type
fn gss_error(major: ffi::OM_uint32, minor: ffi::OM_uint32) -> Error {
    let text = display_gss_status(major, minor);

    #[cfg(feature = "trace")]
    error!(
        target: "kerbsec::iov",
        major = format_args!("{:#x}", major),
        minor = format_args!("{:#x}", minor),
        %text,
        "GSS IOV error"
    );

    Error::Gss { major, minor, text }
}

/// Get human-readable error message from GSS status codes
fn display_gss_status(major: ffi::OM_uint32, minor: ffi::OM_uint32) -> String {
    let mut messages = Vec::new();

    // Display the major status. The error (calling/routine) bits and the
    // supplementary bits are displayed separately: Heimdal (and so Apple's
    // GSS.framework) describes only the supplementary condition when both are
    // set, which would drop the actual error.
    let errors = major & !ffi::GSS_C_SUPPLEMENTARY_MASK;
    let supplementary = major & ffi::GSS_C_SUPPLEMENTARY_MASK;
    let parts: &[ffi::OM_uint32] = match (errors, supplementary) {
        (0, 0) => &[major],
        (0, s) => &[s],
        (e, 0) => &[e],
        _ => &[errors, supplementary],
    };
    for &code in parts {
        if let Some(msg) = display_status_code(code, ffi::GSS_C_GSS_CODE) {
            messages.push(msg);
        }
    }

    // Display minor status
    if minor != 0 {
        if let Some(msg) = display_status_code(minor, ffi::GSS_C_MECH_CODE) {
            messages.push(msg);
        }
    }

    if messages.is_empty() {
        format!("GSS error {major:#x}/{minor:#x}")
    } else {
        messages.join(": ")
    }
}

/// Display a single status code
///
/// Converts a GSS-API status code to a human-readable string. A major status
/// can carry several conditions (a routine error plus supplementary bits), which
/// `gss_display_status` returns one per call while `message_context` is
/// non-zero; all of them are collected and joined. Every GSS buffer is released.
fn display_status_code(code: ffi::OM_uint32, status_type: libc::c_int) -> Option<String> {
    // Guards against an implementation that never clears `message_context`
    const MAX_MESSAGES: usize = 16;

    let mut parts = Vec::new();
    let mut message_context: ffi::OM_uint32 = 0;

    for _ in 0..MAX_MESSAGES {
        let mut minor_status: ffi::OM_uint32 = 0;
        let mut status_string = ffi::gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };

        // SAFETY: All pointers are valid and properly initialized
        let major = unsafe {
            ffi::gss_display_status(
                &mut minor_status,
                code,
                status_type,
                ffi::GSS_C_NO_OID,
                &mut message_context,
                &mut status_string,
            )
        };

        if major != ffi::GSS_S_COMPLETE {
            // No buffer was allocated on failure, nothing to release
            break;
        }

        if !status_string.value.is_null() && status_string.length > 0 {
            // SAFETY: GSS reports `length` valid bytes at `value`
            let bytes = unsafe {
                slice::from_raw_parts(status_string.value.cast::<u8>(), status_string.length)
            };
            parts.push(String::from_utf8_lossy(bytes).into_owned());
        }

        // Always release the buffer, even if it held no message: GSS may still
        // have allocated it.
        // SAFETY: the buffer was filled by gss_display_status above
        unsafe { ffi::gss_release_buffer(&mut minor_status, &mut status_string) };

        if message_context == 0 {
            break;
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_includes_error_and_supplementary_condition() {
        // A routine error plus a supplementary bit. MIT returns both messages
        // over successive calls; Heimdal returns only the supplementary one
        // unless the two are displayed separately.
        let bad_sig = 6 << 16; // GSS_S_BAD_SIG
        let duplicate = 1 << 1; // GSS_S_DUPLICATE_TOKEN
        let error_text = display_status_code(bad_sig, ffi::GSS_C_GSS_CODE).expect("message");
        let supplementary_text =
            display_status_code(duplicate, ffi::GSS_C_GSS_CODE).expect("message");

        let text = display_gss_status(bad_sig | duplicate, 0);
        assert!(
            text.contains(error_text.trim()),
            "{text:?} lacks {error_text:?}"
        );
        assert!(
            text.contains(supplementary_text.trim()),
            "{text:?} lacks {supplementary_text:?}"
        );
    }
}
