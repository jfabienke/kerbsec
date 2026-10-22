# Integration Guide for kerbsec

This guide explains how to integrate kerbsec with various DCE/RPC transports and protocols.

## Table of Contents

- [Basic Integration](#basic-integration)
- [DCE/RPC Integration](#dcerpc-integration)
- [SMB/CIFS Integration](#smbcifs-integration)
- [WMI Integration](#wmi-integration)
- [Custom Transport](#custom-transport)
- [Testing Integration](#testing-integration)

## Basic Integration

### 1. Add Dependency

```toml
[dependencies]
kerbsec = { path = "../kerbsec", features = ["dns", "runtime", "iov"] }
```

### 2. Initialize Context

```rust
use kerbsec::{Context, KerberosConfig, AuthLevel};

async fn create_context(realm: &str, target: &str) -> Result<Context> {
    // Build config with DNS canonicalization
    let config = KerberosConfig::builder()
        .realm(realm)
        .target_host(target)
        .default_auth(AuthLevel::Privacy)
        .build_async()
        .await?;

    Ok(Context::new(config)?)
}
```

### 3. Perform Authentication

```rust
async fn authenticate(ctx: &mut Context, transport: &mut Transport) -> Result<()> {
    // Step 1: Send AP-REQ in bind request
    let ap_req = ctx.initial_token()?;
    let bind_response = transport.send_bind(ap_req).await?;

    // Step 2: Process AP-REP from bind_ack
    let ap_rep = extract_token(&bind_response)?;
    let third_leg = ctx.accept_ap_rep(&ap_rep)?;

    // Step 3: Send third leg in alter_context (even if empty)
    if let Some(token) = third_leg {
        transport.send_alter_context(token).await?;
    }

    Ok(())
}
```

## DCE/RPC Integration

### RPC PDU Structure

```rust
use bytes::{Bytes, BytesMut, BufMut};

struct RpcHeader {
    version: u8,        // 5
    version_minor: u8,  // 0
    packet_type: u8,    // BIND=11, ALTER=14, REQUEST=0
    flags: u8,
    auth_type: u8,      // SPNEGO=9, KRB5=10
    auth_level: u8,     // INTEGRITY=5, PRIVACY=6
    auth_pad: u8,
    auth_context_id: u32,
    // ... other fields
}

fn build_bind_pdu(ap_req: &[u8]) -> Bytes {
    let mut pdu = BytesMut::new();

    // Write RPC header
    pdu.put_u8(5);  // version
    pdu.put_u8(0);  // version_minor
    pdu.put_u8(11); // BIND
    // ... rest of header

    // Write auth trailer with AP-REQ
    pdu.put_u8(10); // AUTH_TYPE_KRB5
    pdu.put_u8(6);  // AUTH_LEVEL_PRIVACY
    pdu.extend_from_slice(ap_req);

    pdu.freeze()
}
```

### Message Protection

```rust
async fn send_protected_request(
    ctx: &mut Context,
    transport: &mut Transport,
    request: &[u8],
) -> Result<Response> {
    // Wrap the request PDU
    let wrapped = ctx.wrap_iov(request)?;

    // Build protected RPC PDU
    let mut pdu = BytesMut::new();

    // RPC header
    write_rpc_header(&mut pdu, PacketType::Request);

    // Protected data (may be encrypted)
    pdu.extend_from_slice(request);

    // Auth trailer
    pdu.put_u8(10); // AUTH_TYPE_KRB5
    pdu.put_u8(ctx.config.default_auth as u8);
    pdu.extend_from_slice(&wrapped.header);
    pdu.extend_from_slice(&wrapped.trailer);

    // Send and receive
    let response = transport.send_request(pdu.freeze()).await?;

    // Unwrap response
    let token = extract_auth_token(&response)?;
    let data = ctx.unwrap_iov(&token)?;

    Ok(parse_response(&data)?)
}
```

## SMB/CIFS Integration

### SMB Session Setup

```rust
use kerbsec::{Context, AuthLevel};

struct SmbClient {
    transport: TcpStream,
    context: Option<Context>,
}

impl SmbClient {
    async fn session_setup(&mut self, realm: &str, server: &str) -> Result<()> {
        // Create Kerberos context
        let config = KerberosConfig::builder()
            .realm(realm)
            .target_host(server)
            .spn_override(Some(format!("cifs/{}", server)))
            .default_auth(AuthLevel::Privacy)
            .build_async()
            .await?;

        let mut ctx = Context::new(config)?;

        // SMB2 SESSION_SETUP with GSS-API token
        let ap_req = ctx.initial_token()?;

        let setup_req = Smb2SessionSetup {
            security_mode: NEGOTIATE_SIGNING_ENABLED,
            capabilities: 0,
            security_buffer: ap_req,
            // ... other fields
        };

        let response = self.send_smb2(setup_req).await?;

        // Process response
        if response.status == STATUS_MORE_PROCESSING_REQUIRED {
            let ap_rep = &response.security_buffer;
            let third_leg = ctx.accept_ap_rep(ap_rep)?;

            if let Some(token) = third_leg {
                // Send final SESSION_SETUP
                let final_req = Smb2SessionSetup {
                    security_buffer: token,
                    // ... other fields
                };
                self.send_smb2(final_req).await?;
            }
        }

        self.context = Some(ctx);
        Ok(())
    }

    async fn send_signed(&mut self, command: SmbCommand) -> Result<SmbResponse> {
        let ctx = self.context.as_mut().ok_or("Not authenticated")?;

        // Serialize command
        let data = command.to_bytes();

        // Generate signature
        let wrapped = ctx.wrap_iov_with(&data, AuthLevel::Integrity)?;

        // Add signature to SMB header
        let mut pdu = BytesMut::new();
        write_smb_header(&mut pdu, &wrapped.header);
        pdu.extend_from_slice(&data);

        self.transport.send(pdu.freeze()).await
    }
}
```

## WMI Integration

### linux-wmi Integration

```rust
use kerbsec::{Context, AuthLevel};
use linux_wmi::{WmiClient, DcomTransport};

async fn wmi_with_kerberos(
    server: &str,
    realm: &str,
) -> Result<WmiClient> {
    // Create Kerberos context
    let config = KerberosConfig::builder()
        .realm(realm)
        .target_host(server)
        .spn_override(Some(format!("HOST/{}", server)))
        .default_auth(AuthLevel::Privacy)
        .build_async()
        .await?;

    let mut ctx = Context::new(config)?;

    // Create DCOM transport with Kerberos
    let transport = DcomTransport::builder()
        .server(server)
        .auth_callback(Box::new(move |stage| {
            match stage {
                AuthStage::Initial => ctx.initial_token(),
                AuthStage::Challenge(token) => {
                    ctx.accept_ap_rep(token)
                        .map(|t| t.unwrap_or_default())
                },
                AuthStage::Wrap(data, level) => {
                    ctx.wrap_iov_with(data, level)
                        .map(|w| (w.header.to_vec(), w.trailer.to_vec()))
                },
                AuthStage::Unwrap(token) => ctx.unwrap_iov(token),
            }
        }))
        .build()?;

    // Create WMI client
    let client = WmiClient::new(transport).await?;

    // Execute queries
    let processes = client
        .query("SELECT * FROM Win32_Process")
        .await?;

    Ok(client)
}
```

### Direct WMI Queries

```rust
async fn query_wmi(
    ctx: &mut Context,
    transport: &mut DcomTransport,
    query: &str,
) -> Result<Vec<WmiObject>> {
    // Authenticate
    authenticate(ctx, transport).await?;

    // Create WMI binding
    let binding = create_wmi_binding()?;

    // Execute query with protection
    let request = build_wmi_query(query);
    let wrapped = ctx.wrap_iov(&request)?;

    let response = transport.send_protected(
        binding,
        wrapped.header,
        &request,
        wrapped.trailer,
    ).await?;

    // Unwrap and parse response
    let data = ctx.unwrap_iov(&response)?;
    parse_wmi_response(&data)
}
```

## Custom Transport

### Transport Trait

```rust
use async_trait::async_trait;

#[async_trait]
trait KerberosTransport {
    /// Send bind request with auth token
    async fn send_bind(&mut self, token: Vec<u8>) -> Result<BindResponse>;

    /// Send alter_context with final token
    async fn send_alter(&mut self, token: Vec<u8>) -> Result<AlterResponse>;

    /// Send protected request
    async fn send_protected(
        &mut self,
        header: &[u8],
        data: &[u8],
        trailer: &[u8],
    ) -> Result<Vec<u8>>;
}

struct TcpTransport {
    stream: TcpStream,
    context: Option<Context>,
}

#[async_trait]
impl KerberosTransport for TcpTransport {
    async fn send_bind(&mut self, token: Vec<u8>) -> Result<BindResponse> {
        // Build and send BIND PDU
        let pdu = build_bind_pdu(token);
        self.stream.write_all(&pdu).await?;

        // Read response
        let response = read_pdu(&mut self.stream).await?;
        parse_bind_response(&response)
    }

    async fn send_protected(
        &mut self,
        header: &[u8],
        data: &[u8],
        trailer: &[u8],
    ) -> Result<Vec<u8>> {
        // Build PDU with auth protection
        let mut pdu = BytesMut::new();
        pdu.extend_from_slice(header);
        pdu.extend_from_slice(data);
        pdu.extend_from_slice(trailer);

        self.stream.write_all(&pdu).await?;
        read_pdu(&mut self.stream).await
    }
}
```

## Testing Integration

### Mock KDC Testing

```rust
#[cfg(test)]
mod tests {
    use kerbsec::{Context, KerberosConfig};

    #[tokio::test]
    async fn test_integration() {
        // Start mock KDC
        let kdc = MockKdc::new().await;
        kdc.add_principal("user@TEST.REALM").await;

        // Configure to use mock KDC
        std::env::set_var("KRB5_CONFIG", kdc.config_path());

        // Create context
        let config = KerberosConfig::builder()
            .realm("TEST.REALM")
            .target_host("server.test.realm")
            .build_async()
            .await
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        // Test authentication
        let token = ctx.initial_token().unwrap();
        assert!(!token.is_empty());

        // Simulate server response
        let ap_rep = kdc.generate_ap_rep(&token).await;
        let third = ctx.accept_ap_rep(&ap_rep).unwrap();
        assert!(ctx.established());
    }
}
```

### Integration Test Harness

```rust
use testcontainers::{clients, images::generic::GenericImage};

#[tokio::test]
async fn test_with_real_kdc() {
    // Start MIT KDC container
    let docker = clients::Cli::default();
    let kdc_image = GenericImage::new("kerberos/kdc", "latest")
        .with_env_var("REALM", "TEST.LOCAL")
        .with_env_var("KADMIN_PASSWORD", "admin123");

    let kdc = docker.run(kdc_image);
    let kdc_port = kdc.get_host_port(88).unwrap();

    // Configure client
    let krb5_conf = format!(
        "[realms]\nTEST.LOCAL = {{\n  kdc = localhost:{}\n}}\n",
        kdc_port
    );

    std::fs::write("/tmp/krb5_test.conf", krb5_conf).unwrap();
    std::env::set_var("KRB5_CONFIG", "/tmp/krb5_test.conf");

    // Run integration test
    test_kerberos_auth().await;
}
```

## Debugging Integration Issues

### Enable Trace Logging

```rust
// Initialize tracing
#[cfg(feature = "trace")]
tracing_subscriber::fmt()
    .with_env_filter("kerbsec=trace,my_app=debug")
    .init();

// Set Kerberos debug environment
std::env::set_var("KRB5_TRACE", "/tmp/krb5_trace.log");
```

### Common Integration Problems

| Issue                         | Cause               | Solution              |
|-------------------------------|---------------------|-----------------------|
| `GSS_S_NO_CRED`               | No Kerberos ticket  | Run `kinit`           |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Wrong SPN           | Check SPN format      |
| `GSS_S_FAILURE`               | Generic error       | Check KRB5_TRACE      |
| `WRONG_REALM`                 | Cross-realm issue   | Configure trust       |
| Sequence errors               | DCE vs GSS mismatch | Ensure DCE_STYLE flag |

### Wireshark Capture

```bash
# Capture Kerberos traffic
tshark -i any -f "port 88 or port 445 or portrange 49152-65535" \
    -w kerberos.pcap

# Analyze with Kerberos dissector
tshark -r kerberos.pcap -Y "kerberos or dcerpc or smb2"
```

## Best Practices

### 1. Context Lifecycle

```rust
// DO: Create context once per connection
let ctx = Context::new(config)?;
for request in requests {
    let wrapped = ctx.wrap_iov(&request)?;
    // ...
}

// DON'T: Create context per request
for request in requests {
    let ctx = Context::new(config)?; // Inefficient!
    // ...
}
```

### 2. Error Handling

```rust
// DO: Handle specific errors
match ctx.initial_token() {
    Ok(token) => send_token(token),
    Err(Error::Gss { major, .. }) if major == GSS_S_NO_CRED => {
        // Prompt for credentials
    },
    Err(e) => return Err(e),
}

// DON'T: Ignore errors
let token = ctx.initial_token().unwrap(); // Panics!
```

### 3. Security

```rust
// DO: Use strongest available protection
.default_auth(AuthLevel::Privacy)

// DON'T: Weaken the Kerberos library (krb5.conf allow_weak_crypto = true)
```

---

*Last updated: January 2025*
