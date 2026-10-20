//! Example WMI client using kerbsec for DCE/RPC Kerberos authentication
//!
//! This example demonstrates the DCE/RPC 3-leg Kerberos handshake:
//! 1. Client sends AP-REQ in bind PDU
//! 2. Server responds with AP-REP in `bind_ack`
//! 3. Client sends third leg (even if empty) in `alter_context`
//!
//! Run with: `cargo run --example wmi_client --features dns,runtime,trace`

use fabi_kerbsec::{AuthLevel, Context};

#[cfg(not(feature = "trace"))]
use std::io::Write;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging if trace feature is enabled
    #[cfg(feature = "trace")]
    {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        // Available logging targets:
        // - kerbsec::ctx - Context creation and handshake
        // - kerbsec::gss - GSS-API operations
        // - kerbsec::dns - DNS canonicalization
        // - kerbsec::iov - IOV wrap/unwrap operations
        // - kerbsec::config - Configuration building
        //
        // Set RUST_LOG environment variable to control logging, e.g.:
        // RUST_LOG=kerbsec=trace for all kerbsec logs
        // RUST_LOG=kerbsec::gss=debug for just GSS operations
        // RUST_LOG=kerbsec::iov=trace,kerbsec::ctx=info for mixed levels

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "kerbsec=debug,wmi_client=debug".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        tracing::info!("Logging initialized with trace feature");
    }

    #[cfg(not(feature = "trace"))]
    {
        // Simple output without tracing
        let _ = writeln!(std::io::stdout(), "Starting WMI client example...");
    }

    // Build config with DNS canonicalization
    let cfg = Context::config_from_target("CONTOSO.COM", "wmi01.contoso.com").await?;

    // Create context
    let mut ctx = Context::new(cfg)?;

    // Leg 1: Generate AP-REQ for RPC bind
    let ap_req = ctx.initial_token()?;
    println!("AP-REQ token: {} bytes", ap_req.len());

    // Simulate server response with AP-REP
    let ap_rep = vec![0x60, 0x82, 0x01, 0x00]; // Mock AP-REP

    // Leg 2→3: Process AP-REP and get final token
    if let Some(final_leg) = ctx.accept_ap_rep(&ap_rep)? {
        println!("Final token for alter_context: {} bytes", final_leg.len());
        // Always send this in alter_context, even if empty
    }

    if ctx.established() {
        println!("Context established!");

        // Wrap a PDU
        let pdu = b"SELECT * FROM Win32_Process";
        let wrap = ctx.wrap_iov(pdu)?;
        println!("Wrapped PDU:");
        println!("  Header: {} bytes", wrap.header.len());
        println!("  Trailer: {} bytes", wrap.trailer.len());
        println!("  Encrypted: {}", wrap.conf);

        // Example of Integrity-only wrap
        let mic_only = ctx.wrap_iov_with(pdu, AuthLevel::Integrity)?;
        println!("MIC-only wrap:");
        println!("  Header: {} bytes", mic_only.header.len());
        println!("  Trailer: {} bytes", mic_only.trailer.len());
        println!("  Encrypted: {}", mic_only.conf);
    }

    Ok(())
}
