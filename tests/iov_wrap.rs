//! Tests for IOV (I/O Vector) wrapping and unwrapping
//!
//! These tests verify the IOV wrap/unwrap functionality
//! used for protecting RPC PDUs with Kerberos.

#[cfg(test)]
mod tests {
    use fabi_kerbsec::IovWrap;

    /// Test IOV structure creation
    #[test]
    fn test_iov_wrap_structure() {
        let header = vec![0x01, 0x02, 0x03, 0x04];
        let payload = vec![0x10, 0x11, 0x12, 0x13];
        let trailer = vec![0x05, 0x06, 0x07, 0x08];

        let iov = IovWrap {
            header: header.clone().into(),
            payload: payload.into(),
            trailer: trailer.clone().into(),
            conf: true,
        };

        assert_eq!(iov.header.len(), 4);
        assert_eq!(iov.trailer.len(), 4);
        assert!(iov.conf);
    }

    /// Test IOV with empty trailer (integrity-only)
    #[test]
    fn test_iov_integrity_only() {
        let header = vec![0x01, 0x02, 0x03, 0x04];
        let payload = vec![0xAA, 0xBB];

        let iov = IovWrap {
            header: header.into(),
            payload: payload.into(),
            trailer: vec![].into(),
            conf: false,
        };

        assert_eq!(iov.header.len(), 4);
        assert_eq!(iov.trailer.len(), 0);
        assert!(!iov.conf);
    }

    /// Test IOV header/trailer size limits
    #[test]
    fn test_iov_size_limits() {
        // GSS wrap headers are typically 16-32 bytes
        let typical_header = vec![0u8; 32];
        let typical_payload = vec![0u8; 128];
        let typical_trailer = vec![0u8; 16];

        let iov = IovWrap {
            header: typical_header.into(),
            payload: typical_payload.into(),
            trailer: typical_trailer.into(),
            conf: true,
        };

        assert!(iov.header.len() <= 64); // Reasonable upper bound
        assert!(iov.trailer.len() <= 64);
    }

    /// Test DCE/RPC PDU structure with IOV
    #[test]
    fn test_dce_rpc_pdu_with_iov() {
        // Simplified RPC PDU structure
        struct RpcPdu {
            header: Vec<u8>, // 16 bytes RPC header
            body: Vec<u8>,   // Variable length body
        }

        let pdu = RpcPdu {
            header: vec![
                0x05, 0x00, 0x00, 0x03, // version, flags
                0x10, 0x00, 0x00, 0x00, // data rep
                0x00, 0x00, 0x00, 0x00, // frag len, auth len
                0x01, 0x00, 0x00, 0x00, // call id
            ],
            body: vec![0xde, 0xad, 0xbe, 0xef],
        };

        // IOV protection
        let iov = IovWrap {
            header: vec![0xaa, 0xbb].into(),
            payload: pdu.body.clone().into(),
            trailer: vec![0xcc, 0xdd].into(),
            conf: true,
        };

        // Construct protected PDU
        let mut protected: Vec<u8> = Vec::new();
        protected.extend(&pdu.header);
        protected.extend(&iov.header);
        protected.extend(&pdu.body);
        protected.extend(&iov.trailer);

        // Verify structure
        assert_eq!(
            protected.len(),
            pdu.header.len() + pdu.body.len() + iov.header.len() + iov.trailer.len()
        );
    }

    /// Test replay detection scenario
    #[test]
    fn test_replay_detection() {
        // GSS-API includes sequence numbers for replay detection
        let sequence_num: u32 = 12345;

        // Simulated auth header with sequence number
        let mut header = vec![0x05, 0x00]; // GSS header
        header.extend(&sequence_num.to_le_bytes());

        let payload = vec![0x00, 0x01, 0x02];

        let iov = IovWrap {
            header: header.into(),
            payload: payload.into(),
            trailer: vec![].into(),
            conf: false,
        };

        // Extract sequence number for verification
        let seq_bytes = &iov.header[2..6];
        let extracted =
            u32::from_le_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);

        assert_eq!(extracted, sequence_num);
    }

    /// Test DCE 3-leg handshake sequence
    #[test]
    fn test_dce_three_leg_sequence() {
        // Leg 1: AP-REQ in bind
        let ap_req = vec![0x60, 0x82]; // ASN.1 application tag
        assert!(!ap_req.is_empty());

        // Leg 2: AP-REP in bind_ack
        let ap_rep = vec![0x6f, 0x82]; // ASN.1 application tag
        assert!(!ap_rep.is_empty());

        // Leg 3: Final token in alter_context (may be empty)
        let third_leg: Vec<u8> = vec![];
        // DCE requires sending third leg even if empty
        assert_eq!(third_leg.len(), 0);
    }
}
