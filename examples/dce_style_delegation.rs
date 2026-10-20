//! Example demonstrating DCE-style and delegation configuration
//!
//! This example shows how to configure kerbsec with:
//! - DCE-style flag for DCE/RPC compatibility
//! - Credential delegation for S4U scenarios
//!
//! # Usage
//!
//! ```bash
//! cargo run --example dce_style_delegation --features dns,runtime
//! ```

use fabi_kerbsec::{AuthLevel, KerberosConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing if available
    #[cfg(feature = "trace")]
    {
        tracing_subscriber::fmt()
            .with_env_filter("kerbsec=debug")
            .init();
    }

    // Example 1: Standard DCE/RPC configuration (default)
    println!("=== Standard DCE/RPC Configuration ===");
    let config = KerberosConfig::builder()
        .realm("CORP.EXAMPLE.COM")
        .target_host("server.example.com") // In production, this would be canonicalized
        .default_auth(AuthLevel::Privacy)
        // DCE-style is enabled by default
        .build()?; // Using synchronous build to avoid DNS resolution for demo

    println!("DCE-style enabled: {}", config.enable_dce_style);
    println!("Delegation enabled: {}", config.enable_delegation);
    println!("Mutual auth required: {}", config.require_mutual_auth);

    // Example 2: Configuration with delegation enabled
    println!("\n=== Configuration with Delegation ===");
    let config_with_delegation = KerberosConfig::builder()
        .realm("CORP.EXAMPLE.COM")
        .target_host("trusted-server.example.com")
        .default_auth(AuthLevel::Privacy)
        .delegation(true) // Enable credential delegation
        .build()?;

    println!(
        "DCE-style enabled: {}",
        config_with_delegation.enable_dce_style
    );
    println!(
        "Delegation enabled: {}",
        config_with_delegation.enable_delegation
    );

    // Example 3: Non-DCE configuration (rare)
    println!("\n=== Non-DCE Configuration ===");
    let non_dce_config = KerberosConfig::builder()
        .realm("CORP.EXAMPLE.COM")
        .target_host("legacy.example.com")
        .default_auth(AuthLevel::Integrity)
        .dce_style(false) // Disable DCE-style (not recommended for DCE/RPC)
        .build()?;

    println!("DCE-style enabled: {}", non_dce_config.enable_dce_style);

    // Example 4: Using delegation in practice
    println!("\n=== Using Delegation ===");

    // Note: This would require actual Kerberos infrastructure
    // Here we show the API usage pattern

    /*
    let mut ctx = Context::new(config_with_delegation)?;

    // Perform authentication...
    let token = ctx.initial_token()?;
    // ... exchange tokens with server ...

    // After authentication, check for delegated credentials
    if ctx.has_delegated_credentials() {
        println!("Delegated credentials are available!");

        // Export them for use in impersonation scenarios
        match ctx.export_delegated_credentials() {
            Ok(creds) => {
                println!("Exported {} bytes of delegated credentials", creds.len());
                // These credentials can now be used for S4U2Self/S4U2Proxy
            }
            Err(e) => {
                println!("Could not export delegated credentials: {}", e);
            }
        }
    } else {
        println!("No delegated credentials available");
    }
    */

    println!("\n=== Configuration Summary ===");
    println!("DCE-style flag (GSS_C_DCE_STYLE):");
    println!("  - Disables GSS sequence number checking");
    println!("  - Allows out-of-order message processing");
    println!("  - Prevents GSS replay cache interference");
    println!("  - Enabled by default for DCE/RPC compatibility");

    println!("\nCredential Delegation (GSS_C_DELEG_FLAG):");
    println!("  - Allows server to impersonate client");
    println!("  - Used for S4U2Self/S4U2Proxy scenarios");
    println!("  - Disabled by default for security");
    println!("  - Only enable when you trust the server completely");

    Ok(())
}
