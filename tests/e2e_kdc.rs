//! End-to-end tests against a real KDC.
//!
//! Run with `scripts/e2e-kdc.sh`, which stands up a throwaway MIT KDC and a
//! `host/localhost` service keytab. The acceptor side is libgssapi's `ServerCtx`.

#![cfg(unix)]

use kerbsec::{AuthLevel, Context, Error, KerberosConfig};
use libgssapi::context::{CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::oid::{OidSet, GSS_MECH_KRB5};

fn config(auth: AuthLevel) -> KerberosConfig {
    KerberosConfig::builder()
        .realm("TEST.LOCAL")
        .target_host("localhost")
        // The test keytab holds `host/localhost` (MIT principals are case-sensitive)
        .spn_override(Some("host/localhost".to_owned()))
        .default_auth(auth)
        .build()
        .expect("config")
}

fn acceptor() -> ServerCtx {
    let mut mechs = OidSet::new().expect("oidset");
    mechs.add(&GSS_MECH_KRB5).expect("add mech");
    let cred = Cred::acquire(None, None, CredUsage::Accept, Some(&mechs)).expect("accept cred");
    ServerCtx::new(Some(cred))
}

/// Run the 3-leg handshake; returns the established (client, server) pair.
fn establish(auth: AuthLevel) -> (Context, ServerCtx) {
    let mut client = Context::new(config(auth)).expect("context");
    let mut server = acceptor();

    let ap_req = client.initial_token().expect("initial token");
    let ap_rep = server
        .step(&ap_req)
        .expect("server step 1")
        .expect("AP-REP");
    let third = client
        .accept_ap_rep(&ap_rep)
        .expect("accept_ap_rep")
        .expect("third leg");
    if !third.is_empty() && !server.is_complete() {
        server.step(&third).expect("server step 2");
    }
    assert!(client.established());
    (client, server)
}

fn concat(w: &kerbsec::IovWrap) -> Vec<u8> {
    [&w.header[..], &w.payload[..], &w.trailer[..]].concat()
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn privacy_roundtrip_both_directions() {
    let (mut client, mut server) = establish(AuthLevel::Privacy);

    let wrapped = client.wrap_iov(b"hello server").expect("wrap");
    assert!(wrapped.conf, "Privacy wrap must report confidentiality");
    let plain = server.unwrap(&concat(&wrapped)).expect("server unwrap");
    assert_eq!(&plain[..], b"hello server");

    let reply = server.wrap(true, b"hello client").expect("server wrap");
    let plain = client.unwrap_iov(&reply).expect("client unwrap");
    assert_eq!(plain, b"hello client");
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn privacy_context_rejects_integrity_only_token() {
    let (mut client, mut server) = establish(AuthLevel::Privacy);

    // A peer (or attacker) that signs but does not seal must not be accepted.
    let signed_only = server.wrap(false, b"not encrypted").expect("server wrap");
    let err = client.unwrap_iov(&signed_only).expect_err("must reject");
    assert!(
        matches!(err, Error::ConfidentialityNotProvided(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn integrity_context_accepts_both_token_kinds() {
    let (mut client, mut server) = establish(AuthLevel::Integrity);

    let signed_only = server.wrap(false, b"plain").expect("wrap");
    assert_eq!(client.unwrap_iov(&signed_only).expect("unwrap"), b"plain");
    let sealed = server.wrap(true, b"sealed").expect("wrap");
    assert_eq!(client.unwrap_iov(&sealed).expect("unwrap"), b"sealed");
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn per_call_privacy_works_on_integrity_context() {
    let (mut client, mut server) = establish(AuthLevel::Integrity);

    let sealed = client
        .wrap_iov_with(b"secret", AuthLevel::Privacy)
        .expect("per-call Privacy wrap");
    assert!(sealed.conf);
    assert_eq!(
        &server.unwrap(&concat(&sealed)).expect("unwrap")[..],
        b"secret"
    );

    let signed = client
        .wrap_iov_with(b"public", AuthLevel::Integrity)
        .expect("Integrity wrap");
    assert!(!signed.conf);
    assert_eq!(
        &server.unwrap(&concat(&signed)).expect("unwrap")[..],
        b"public"
    );
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn negotiated_flags_include_integrity_conf_mutual() {
    let (_client, mut server) = establish(AuthLevel::Privacy);
    let flags = server.flags().expect("flags");
    assert!(flags.contains(CtxFlags::GSS_C_INTEG_FLAG));
    assert!(flags.contains(CtxFlags::GSS_C_CONF_FLAG));
    assert!(flags.contains(CtxFlags::GSS_C_MUTUAL_FLAG));
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn wrap_size_limit_uses_the_mechanism() {
    let (client, _server) = establish(AuthLevel::Privacy);
    let limit = client.wrap_size_limit(1024, true);
    assert!(limit > 0 && limit < 1024, "limit = {limit}");
    // Integrity needs no more overhead than Privacy
    assert!(client.wrap_size_limit(1024, false) >= limit);
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn handshake_state_is_enforced() {
    let mut client = Context::new(config(AuthLevel::Privacy)).expect("context");

    // AP-REP before AP-REQ
    assert!(matches!(
        client.accept_ap_rep(b"x"),
        Err(Error::HandshakeState(_))
    ));

    let mut server = acceptor();
    let ap_req = client.initial_token().expect("initial token");

    // initial_token twice; bindings after the first leg
    assert!(matches!(
        client.initial_token(),
        Err(Error::HandshakeState(_))
    ));
    assert!(matches!(
        client.set_channel_bindings(None),
        Err(Error::HandshakeState(_))
    ));

    let ap_rep = server.step(&ap_req).expect("step").expect("AP-REP");
    client.accept_ap_rep(&ap_rep).expect("accept");
    assert!(matches!(
        client.accept_ap_rep(&ap_rep),
        Err(Error::HandshakeState(_))
    ));
}
