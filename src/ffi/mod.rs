//! Minimal FFI bindings for GSS-API IOV operations
//!
//! This module provides the bare minimum FFI definitions needed for
//! IOV (Input/Output Vector) operations in GSS-API. We avoid bindgen
//! to keep the build simple and control exactly what we expose.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::{c_int, c_uint, c_void, size_t};

// GSS-API types

/// GSS-API unsigned 32-bit integer type
pub type OM_uint32 = c_uint;

/// GSS-API Quality of Protection type
pub type gss_qop_t = OM_uint32;

/// GSS-API security context handle
pub type gss_ctx_id_t = *mut c_void;

/// GSS-API name handle
pub type gss_name_t = *mut c_void;

/// GSS-API credential handle
pub type gss_cred_id_t = *mut c_void;

/// GSS-API Object Identifier pointer
pub type gss_OID = *mut gss_OID_desc;

/// GSS-API Object Identifier descriptor
#[repr(C)]
pub struct gss_OID_desc {
    /// Length of the OID in bytes
    pub length: OM_uint32,
    /// Pointer to the OID octets
    pub elements: *mut c_void,
}

/// GSS-API buffer descriptor for passing data
#[repr(C)]
pub struct gss_buffer_desc {
    /// Length of the buffer in bytes
    pub length: size_t,
    /// Pointer to the buffer data
    pub value: *mut c_void,
}

/// Pointer to a GSS-API buffer descriptor
pub type gss_buffer_t = *mut gss_buffer_desc;

// IOV buffer types

/// Empty IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_EMPTY: c_uint = 0;
/// Data IOV buffer type (message to protect)
pub const GSS_IOV_BUFFER_TYPE_DATA: c_uint = 1;
/// Header IOV buffer type (protection header)
pub const GSS_IOV_BUFFER_TYPE_HEADER: c_uint = 2;
/// Mechanism parameters IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_MECH_PARAMS: c_uint = 3;
/// Trailer IOV buffer type (protection trailer)
pub const GSS_IOV_BUFFER_TYPE_TRAILER: c_uint = 7;
/// Padding IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_PADDING: c_uint = 9;
/// Stream IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_STREAM: c_uint = 10;
/// Sign-only IOV buffer type (included in MIC but not encrypted)
pub const GSS_IOV_BUFFER_TYPE_SIGN_ONLY: c_uint = 11;

// Flags for IOV buffer types

/// Request GSS to allocate buffer space
pub const GSS_IOV_BUFFER_FLAG_ALLOCATE: c_uint = 0x0001_0000;
/// Buffer was allocated by GSS
pub const GSS_IOV_BUFFER_FLAG_ALLOCATED: c_uint = 0x0002_0000;

// IOV buffer descriptor

/// GSS-API IOV buffer descriptor for scatter-gather operations
///
/// Only valid where the IOV functions are declared (Linux). Apple's headers
/// `#pragma pack(2)` this struct on Intel Macs, so this layout would be wrong there.
#[repr(C)]
pub struct gss_iov_buffer_desc {
    /// Buffer type and flags (OR'd together)
    pub type_: OM_uint32,
    /// The actual buffer data
    pub buffer: gss_buffer_desc,
}

/// Pointer to an IOV buffer descriptor
pub type gss_iov_buffer_t = *mut gss_iov_buffer_desc;

// Context flags

/// Delegate credentials to remote peer
pub const GSS_C_DELEG_FLAG: OM_uint32 = 1;
/// Request mutual authentication
pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
/// Enable replay detection
pub const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
/// Enable sequence checking
pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
/// Enable confidentiality (encryption)
pub const GSS_C_CONF_FLAG: OM_uint32 = 16;
/// Enable integrity protection
pub const GSS_C_INTEG_FLAG: OM_uint32 = 32;
/// Anonymous authentication
pub const GSS_C_ANON_FLAG: OM_uint32 = 64;
/// Protection services available
pub const GSS_C_PROT_READY_FLAG: OM_uint32 = 128;
/// Transferable context
pub const GSS_C_TRANS_FLAG: OM_uint32 = 256;
/// DCE-style context (critical for DCE/RPC)
pub const GSS_C_DCE_STYLE: OM_uint32 = 0x1000;

// Status codes

/// GSS operation completed successfully
pub const GSS_S_COMPLETE: OM_uint32 = 0;
/// GSS operation needs continuation
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
/// Low 16 bits of a major status: supplementary information (duplicate, old,
/// unsequenced or gap token) rather than an error
pub const GSS_C_SUPPLEMENTARY_MASK: OM_uint32 = 0xffff;

// Error handling

/// GSS-API error code type
pub const GSS_C_GSS_CODE: c_int = 1;
/// Mechanism-specific error code type
pub const GSS_C_MECH_CODE: c_int = 2;
/// Null OID value - represents `GSS_C_NO_OID` in GSS-API
///
/// Using `std::ptr::null_mut()` is the idiomatic way to create null pointers in Rust.
pub const GSS_C_NO_OID: gss_OID = std::ptr::null_mut();
/// Null buffer value - represents `GSS_C_NO_BUFFER` in GSS-API
pub const GSS_C_NO_BUFFER: gss_buffer_t = std::ptr::null_mut();

// QOP values

/// Default quality of protection
pub const GSS_C_QOP_DEFAULT: gss_qop_t = 0;

// External functions - IOV operations (Linux only; `gss_wrap_size_limit` is core
// RFC 2744 and declared below for all platforms)
#[cfg(target_os = "linux")]
extern "C" {
    /// Wrap (sign/encrypt) message data using IOV buffers
    ///
    /// This function performs message protection using scatter-gather IOV buffers,
    /// allowing separate header, data, and trailer sections for DCE/RPC framing.
    ///
    /// # Parameters
    /// - `minor_status`: Output for mechanism-specific status code
    /// - `context_handle`: Established security context
    /// - `conf_req_flag`: Non-zero to request confidentiality (encryption)
    /// - `qop_req`: Quality of protection (use `GSS_C_QOP_DEFAULT`)
    /// - `conf_state`: Output indicating if confidentiality was applied
    /// - `iov`: Array of IOV buffer descriptors
    /// - `iov_count`: Number of IOV buffers
    pub fn gss_wrap_iov(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_req_flag: c_int,
        qop_req: gss_qop_t,
        conf_state: *mut c_int,
        iov: gss_iov_buffer_t,
        iov_count: c_int,
    ) -> OM_uint32;

    /// Unwrap (verify/decrypt) message data using IOV buffers
    ///
    /// This function verifies and/or decrypts message data that was protected
    /// using `gss_wrap_iov`.
    ///
    /// # Parameters
    /// - `minor_status`: Output for mechanism-specific status code
    /// - `context_handle`: Established security context
    /// - `conf_state`: Output indicating if confidentiality was applied
    /// - `qop_state`: Output for quality of protection used
    /// - `iov`: Array of IOV buffer descriptors
    /// - `iov_count`: Number of IOV buffers
    pub fn gss_unwrap_iov(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_state: *mut c_int,
        qop_state: *mut gss_qop_t,
        iov: gss_iov_buffer_t,
        iov_count: c_int,
    ) -> OM_uint32;
}

// External functions - Available on all platforms
extern "C" {
    /// Query the maximum message size for wrapped output
    ///
    /// Returns the maximum input message size that will fit in the requested
    /// output size after wrapping.
    ///
    /// # Parameters
    /// - `minor_status`: Output for mechanism-specific status code
    /// - `context_handle`: Established security context
    /// - `conf_req_flag`: Non-zero to request confidentiality
    /// - `qop_req`: Quality of protection
    /// - `req_output_size`: Desired maximum output size
    /// - `max_input_size`: Output for maximum input size
    pub fn gss_wrap_size_limit(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_req_flag: c_int,
        qop_req: gss_qop_t,
        req_output_size: OM_uint32,
        max_input_size: *mut OM_uint32,
    ) -> OM_uint32;

    /// Wrap (sign/encrypt) a message into a single token (RFC 2744 `gss_wrap`)
    ///
    /// `conf_state` reports whether confidentiality was actually applied, which
    /// may be false even when `conf_req_flag` was set.
    pub fn gss_wrap(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_req_flag: c_int,
        qop_req: gss_qop_t,
        input_message_buffer: gss_buffer_t,
        conf_state: *mut c_int,
        output_message_buffer: gss_buffer_t,
    ) -> OM_uint32;

    /// Verify and/or decrypt a wrapped token (RFC 2744 `gss_unwrap`)
    ///
    /// `conf_state` reports whether the token was encrypted.
    pub fn gss_unwrap(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        input_message_buffer: gss_buffer_t,
        output_message_buffer: gss_buffer_t,
        conf_state: *mut c_int,
        qop_state: *mut gss_qop_t,
    ) -> OM_uint32;
    /// Display a GSS-API status code as a human-readable string
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `status_value`: Status value to be converted
    /// - `status_type`: `GSS_C_GSS_CODE` or `GSS_C_MECH_CODE`
    /// - `mech_type`: Mechanism type (NULL for default)
    /// - `message_context`: Message context for multi-part messages
    /// - `status_string`: Output buffer for status string
    pub fn gss_display_status(
        minor_status: *mut OM_uint32,
        status_value: OM_uint32,
        status_type: c_int,
        mech_type: gss_OID,
        message_context: *mut OM_uint32,
        status_string: gss_buffer_t,
    ) -> OM_uint32;

    /// Release a GSS-API buffer
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `buffer`: Buffer to be released
    pub fn gss_release_buffer(minor_status: *mut OM_uint32, buffer: gss_buffer_t) -> OM_uint32;

    /// Release a GSS-API name
    pub fn gss_release_name(minor_status: *mut OM_uint32, name: *mut gss_name_t) -> OM_uint32;

    /// Inquire about a security context
    ///
    /// This function returns information about a security context,
    /// including the negotiated flags which tell us what protection
    /// was actually agreed upon (e.g., whether delegation succeeded).
    pub fn gss_inquire_context(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        src_name: *mut gss_name_t,
        targ_name: *mut gss_name_t,
        lifetime_rec: *mut OM_uint32,
        mech_type: *mut gss_OID,
        ctx_flags: *mut OM_uint32,
        locally_initiated: *mut c_int,
        open: *mut c_int,
    ) -> OM_uint32;
}

/// Check if IOV operations are available on this platform
///
/// The `gss_wrap_iov` family is declared only on Linux (MIT Kerberos). macOS
/// GSS.framework doesn't expose it, so other platforms use `gss_wrap`/`gss_unwrap`.
#[must_use]
pub const fn has_iov_support() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    // These mirror MIT's gssapi.h / gssapi_ext.h; a mismatch here is memory unsafety
    // at the FFI boundary, so pin the sizes the C ABI requires.
    #[test]
    fn gss_buffer_desc_layout() {
        assert_eq!(size_of::<gss_buffer_desc>(), 2 * size_of::<usize>());
        assert_eq!(offset_of!(gss_buffer_desc, length), 0);
        assert_eq!(offset_of!(gss_buffer_desc, value), size_of::<usize>());
    }

    #[test]
    fn gss_iov_buffer_desc_layout() {
        // { OM_uint32 type; gss_buffer_desc buffer; } - buffer aligned to usize
        assert_eq!(offset_of!(gss_iov_buffer_desc, type_), 0);
        assert_eq!(offset_of!(gss_iov_buffer_desc, buffer), align_of::<usize>());
        assert_eq!(size_of::<gss_iov_buffer_desc>(), 3 * size_of::<usize>());
        assert_eq!(size_of::<OM_uint32>(), 4);
    }
}
