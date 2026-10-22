//! Demonstration of credential cache functionality
//!
//! This example shows how to use the credential cache subsystem to store
//! and retrieve Kerberos tickets using the FILE backend.
//!
//! Run with: cargo run --example `ccache_demo` --features ccache

use kerbsec::ccache::{
    create_cache, CacheBackend, CacheConfig, Credential, CredentialCache, EncType, KeyBlock,
    NameType, Principal, Times,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Kerberos Credential Cache Demo ===\n");

    // Configure cache with FILE backend
    let config = CacheConfig {
        backend: CacheBackend::File,
        atomic_writes: true,
        use_locking: true,
        file_mode: 0o600,
    };

    // Create cache instance
    let mut cache = create_cache(config)?;

    // Open cache file
    let cache_path = Path::new("/tmp/demo_krb5cc");
    println!("Opening cache at: {}", cache_path.display());
    cache.open(cache_path)?;

    // Create a test credential
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

    let credential = demo_credential(now);

    // Store the credential
    println!("\nStoring credential for: {}", credential.server);
    cache.store_ticket(credential.clone())?;

    // List all tickets
    print_tickets(cache.as_ref(), "Tickets in cache")?;

    // Retrieve specific ticket
    let spn = "host/server.example.com@EXAMPLE.COM";
    println!("\nRetrieving ticket for: {spn}");

    match cache.get_ticket(spn) {
        Ok(Some(retrieved)) => {
            println!("  Client: {}", retrieved.client);
            println!("  Server: {}", retrieved.server);
            println!("  Encryption: {:?}", retrieved.key_block.enctype);
            println!(
                "  Valid until: {} seconds from epoch",
                retrieved.times.end_time
            );

            let remaining = retrieved.times.end_time.saturating_sub(now);
            println!("  Time remaining: {} hours", remaining / 3600);
        }
        Ok(None) => {
            println!("  Ticket not found!");
        }
        Err(e) => {
            println!("  Error retrieving ticket: {e}");
            eprintln!("  Continuing demo despite error...");
        }
    }

    // Add an expired ticket to test purging
    let mut expired_cred = credential;
    expired_cred.server = Principal::new(
        NameType::ServiceInstance,
        "EXAMPLE.COM".to_string(),
        vec!["http".to_string(), "web.example.com".to_string()],
    );
    expired_cred.times.end_time = 1000; // Way in the past

    println!("\nAdding expired ticket for: {}", expired_cred.server);
    cache.store_ticket(expired_cred)?;

    print_tickets(cache.as_ref(), "Tickets before purge")?;

    // Purge expired tickets
    let purged = cache.purge_expired()?;
    println!("\nPurged {purged} expired ticket(s)");

    print_tickets(cache.as_ref(), "Tickets after purge")?;

    // Clean up
    println!("\nRemoving remaining tickets...");
    cache.remove_ticket(spn)?;

    print_tickets(cache.as_ref(), "Final cache contents")?;

    println!("\n✅ Demo completed successfully!");
    println!("\nNote: You can inspect the cache file with:");
    println!("  klist -c {}", cache_path.display());

    Ok(())
}

/// A ticket for `host/server.example.com`, valid for 10 hours from `now`
fn demo_credential(now: u32) -> Credential {
    Credential {
        client: Principal::new(
            NameType::Principal,
            "EXAMPLE.COM".to_string(),
            vec!["testuser".to_string()],
        ),
        server: Principal::new(
            NameType::ServiceInstance,
            "EXAMPLE.COM".to_string(),
            vec!["host".to_string(), "server.example.com".to_string()],
        ),
        key_block: KeyBlock {
            enctype: EncType::Aes256CtsHmacSha1_96 as u16,
            key_data: vec![0x00; 32], // Dummy key for demo
        },
        times: Times {
            auth_time: now,
            start_time: now,
            end_time: now + 36000,   // Valid for 10 hours
            renew_till: now + 86400, // Renewable for 24 hours
        },
        is_config: 0,
        ticket_flags: 0x40a1_0000, // Forwardable, proxiable, renewable
        addresses: Vec::new(),
        ticket: vec![0xde, 0xad, 0xbe, 0xef], // Dummy ticket
        second_ticket: Vec::new(),
        authdata: Vec::new(),
    }
}

/// Print the SPNs in `cache` under `label`
fn print_tickets(cache: &dyn CredentialCache, label: &str) -> kerbsec::Result<()> {
    println!("\n{label}:");
    let tickets = cache.list()?;
    if tickets.is_empty() {
        println!("  (empty)");
    }
    for spn in tickets {
        println!("  - {spn}");
    }
    Ok(())
}
