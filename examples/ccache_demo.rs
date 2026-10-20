//! Demonstration of credential cache functionality
//!
//! This example shows how to use the credential cache subsystem to store
//! and retrieve Kerberos tickets using the FILE backend.
//!
//! Run with: `cargo run --example ccache_demo --features ccache`

use fabi_kerbsec::ccache::{
    create_cache, CacheBackend, CacheConfig, Credential, EncType, KeyBlock, NameType, Principal,
    Times,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(clippy::too_many_lines)] // one linear walkthrough
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

    let credential = Credential {
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
    };

    // Store the credential
    println!("\nStoring credential for: {}", credential.server);
    cache.store_ticket(credential.clone())?;

    // List all tickets
    println!("\nTickets in cache:");
    for spn in cache.list()? {
        println!("  - {spn}");
    }

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

    println!("\nTickets before purge:");
    for spn in cache.list()? {
        println!("  - {spn}");
    }

    // Purge expired tickets
    let purged = cache.purge_expired()?;
    println!("\nPurged {purged} expired ticket(s)");

    println!("\nTickets after purge:");
    for spn in cache.list()? {
        println!("  - {spn}");
    }

    // Clean up
    println!("\nRemoving remaining tickets...");
    cache.remove_ticket(spn)?;

    println!("\nFinal cache contents:");
    let final_list = cache.list()?;
    if final_list.is_empty() {
        println!("  (empty)");
    } else {
        for spn in final_list {
            println!("  - {spn}");
        }
    }

    println!("\n✅ Demo completed successfully!");
    println!("\nNote: You can inspect the cache file with:");
    println!("  klist -c {}", cache_path.display());

    Ok(())
}
