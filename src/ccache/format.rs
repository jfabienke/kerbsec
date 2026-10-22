//! MIT Kerberos FILE format v5 (0x0504) parser and serializer
//!
//! This module implements parsing and serialization for the MIT Kerberos
//! credential cache file format version 5. The format is binary with
//! network byte order (big-endian) for multi-byte integers.
//!
//! # Format Structure
//!
//! ```text
//! FILE := VERSION HEADER PRINCIPAL CREDENTIALS*
//! VERSION := 0x05 0x04  (file format version 5.4)
//! HEADER := TAG* 0x00 0x00  (tagged header fields, terminated by null tag)
//! PRINCIPAL := NAME_TYPE COMPONENTS_COUNT REALM COMPONENTS*
//! CREDENTIAL := CLIENT SERVER KEY_BLOCK TIMES IS_CONFIG TICKET SECOND_TICKET AUTHDATA*
//! ```
//!
//! # Security
//!
//! All sensitive data (keys, tickets) are zeroized on drop using the `zeroize` crate.

use crate::error::{Error, Result};
use std::fmt;
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// MIT Kerberos file format version 5.4
pub const FILE_FORMAT_VERSION: u16 = 0x0504;

/// Header tag types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HeaderTag {
    /// Delta time (seconds)
    DeltaTime = 1,
    /// Unknown tag (for forward compatibility)
    Unknown(u16),
}

/// Kerberos principal name types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NameType {
    /// Unknown name type
    Unknown = 0,
    /// Principal name (e.g., user@REALM)
    Principal = 1,
    /// Service and instance (e.g., service/hostname@REALM)
    ServiceInstance = 2,
    /// Service with host (e.g., service/hostname@REALM)
    ServiceHost = 3,
    /// Service and host instance
    ServiceHostInstance = 4,
    /// Unique ID
    Uid = 5,
    /// X.500 principal
    X500Principal = 6,
    /// SMTP name
    SmtpName = 7,
    /// Enterprise principal (e.g., user@domain@REALM)
    Enterprise = 10,
    /// Wellknown principal
    Wellknown = 11,
    /// Microsoft Service Principal Name
    #[allow(clippy::cast_sign_loss)]
    MsSPN = -128i32 as u32,
}

/// Encryption types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EncType {
    /// NULL (no encryption)
    Null = 0,
    /// DES-CBC-CRC (deprecated)
    DesCbcCrc = 1,
    /// DES-CBC-MD4 (deprecated)
    DesCbcMd4 = 2,
    /// DES-CBC-MD5 (deprecated)
    DesCbcMd5 = 3,
    /// DES3-CBC-SHA1
    Des3CbcSha1 = 16,
    /// AES128-CTS-HMAC-SHA1-96
    Aes128CtsHmacSha1_96 = 17,
    /// AES256-CTS-HMAC-SHA1-96
    Aes256CtsHmacSha1_96 = 18,
    /// AES128-CTS-HMAC-SHA256-128
    Aes128CtsHmacSha256_128 = 19,
    /// AES256-CTS-HMAC-SHA384-192
    Aes256CtsHmacSha384_192 = 20,
    /// RC4-HMAC (deprecated)
    Rc4Hmac = 23,
    /// RC4-HMAC-EXP (deprecated)
    Rc4HmacExp = 24,
    /// Camellia128-CTS-CMAC
    Camellia128CtsCmac = 25,
    /// Camellia256-CTS-CMAC
    Camellia256CtsCmac = 26,
}

/// Kerberos principal
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Principal {
    /// Name type
    pub name_type: u32,
    /// Realm (e.g., "EXAMPLE.COM")
    pub realm: String,
    /// Components (e.g., `["user"]` or `["service", "hostname"]`)
    pub components: Vec<String>,
}

impl Principal {
    /// Create a new principal
    #[must_use]
    pub const fn new(name_type: NameType, realm: String, components: Vec<String>) -> Self {
        Self {
            name_type: name_type as u32,
            realm,
            components,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.components.join("/");
        write!(f, "{}@{}", name, self.realm)
    }
}

/// Kerberos key block
#[derive(Debug, Clone)]
pub struct KeyBlock {
    /// Encryption type
    pub enctype: u16,
    /// Key material (sensitive)
    pub key_data: Vec<u8>,
}

impl Drop for KeyBlock {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

impl Zeroize for KeyBlock {
    fn zeroize(&mut self) {
        self.enctype.zeroize();
        self.key_data.zeroize();
    }
}

/// Ticket times
#[derive(Debug, Clone, Copy)]
pub struct Times {
    /// Authentication time (Unix timestamp)
    pub auth_time: u32,
    /// Start time (Unix timestamp)
    pub start_time: u32,
    /// End time (Unix timestamp)
    pub end_time: u32,
    /// Renew till time (Unix timestamp)
    pub renew_till: u32,
}

/// Address information
#[derive(Debug, Clone)]
pub struct Address {
    /// Address type
    pub addr_type: u16,
    /// Address data
    pub addr_data: Vec<u8>,
}

/// Authorization data
#[derive(Debug, Clone)]
pub struct AuthData {
    /// Authorization data type
    pub ad_type: u16,
    /// Authorization data
    pub ad_data: Vec<u8>,
}

/// Kerberos credential
#[derive(Debug, Clone)]
pub struct Credential {
    /// Client principal
    pub client: Principal,
    /// Server principal
    pub server: Principal,
    /// Session key
    pub key_block: KeyBlock,
    /// Ticket times
    pub times: Times,
    /// Is this a configuration entry?
    pub is_config: u8,
    /// Ticket flags
    pub ticket_flags: u32,
    /// Addresses
    pub addresses: Vec<Address>,
    /// Ticket data (encrypted, sensitive)
    pub ticket: Vec<u8>,
    /// Second ticket (for user-to-user auth)
    pub second_ticket: Vec<u8>,
    /// Authorization data
    pub authdata: Vec<AuthData>,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.key_block.zeroize();
        self.ticket.zeroize();
        self.second_ticket.zeroize();
    }
}

/// Parser for FILE format v5
pub struct FileFormatParser<R: Read> {
    reader: R,
}

impl<R: Read> FileFormatParser<R> {
    /// Create a new parser
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Parse the file format version
    pub fn parse_version(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read version: {e}"),
            })?;
        Ok(u16::from_be_bytes(buf))
    }

    /// Parse a header tag
    pub fn parse_header_tag(&mut self) -> Result<Option<(HeaderTag, Vec<u8>)>> {
        let tag = self.read_u16()?;
        if tag == 0 {
            // Read and discard the length field for the null terminator
            let _len = self.read_u16()?;
            return Ok(None);
        }

        let len = self.read_u16()?;
        let mut data = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut data)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read header tag data: {e}"),
            })?;

        let header_tag = match tag {
            1 => HeaderTag::DeltaTime,
            _ => HeaderTag::Unknown(tag),
        };

        Ok(Some((header_tag, data)))
    }

    /// Parse the header section
    pub fn parse_header(&mut self) -> Result<Vec<(HeaderTag, Vec<u8>)>> {
        let mut tags = Vec::new();
        while let Some(tag) = self.parse_header_tag()? {
            tags.push(tag);
        }
        Ok(tags)
    }

    /// Parse a principal
    pub fn parse_principal(&mut self) -> Result<Principal> {
        let name_type = self.read_u32()?;
        let num_components = self.read_u32()?;
        let realm = self.read_counted_string()?;

        let mut components = Vec::with_capacity(num_components as usize);
        for _ in 0..num_components {
            components.push(self.read_counted_string()?);
        }

        Ok(Principal {
            name_type,
            realm,
            components,
        })
    }

    /// Parse a key block
    pub fn parse_key_block(&mut self) -> Result<KeyBlock> {
        let enctype = self.read_u16()?;
        let key_data = self.read_counted_octet_string()?;
        Ok(KeyBlock { enctype, key_data })
    }

    /// Parse times
    pub fn parse_times(&mut self) -> Result<Times> {
        Ok(Times {
            auth_time: self.read_u32()?,
            start_time: self.read_u32()?,
            end_time: self.read_u32()?,
            renew_till: self.read_u32()?,
        })
    }

    /// Parse addresses
    pub fn parse_addresses(&mut self) -> Result<Vec<Address>> {
        let count = self.read_u32()?;
        let mut addresses = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let addr_type = self.read_u16()?;
            let addr_data = self.read_counted_octet_string()?;
            addresses.push(Address {
                addr_type,
                addr_data,
            });
        }
        Ok(addresses)
    }

    /// Parse authorization data
    pub fn parse_authdata(&mut self) -> Result<Vec<AuthData>> {
        let count = self.read_u32()?;
        let mut authdata = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let ad_type = self.read_u16()?;
            let ad_data = self.read_counted_octet_string()?;
            authdata.push(AuthData { ad_type, ad_data });
        }
        Ok(authdata)
    }

    /// Parse a credential
    pub fn parse_credential(&mut self) -> Result<Credential> {
        let client = self.parse_principal()?;
        let server = self.parse_principal()?;
        let key_block = self.parse_key_block()?;
        let times = self.parse_times()?;
        let is_config = self.read_u8()?;
        let ticket_flags = self.read_u32()?;
        let addresses = self.parse_addresses()?;
        let authdata = self.parse_authdata()?;
        let ticket = self.read_counted_octet_string()?;
        let second_ticket = self.read_counted_octet_string()?;

        Ok(Credential {
            client,
            server,
            key_block,
            times,
            is_config,
            ticket_flags,
            addresses,
            ticket,
            second_ticket,
            authdata,
        })
    }

    /// Read a u8
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read u8: {e}"),
            })?;
        Ok(buf[0])
    }

    /// Read a big-endian u16
    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read u16: {e}"),
            })?;
        Ok(u16::from_be_bytes(buf))
    }

    /// Read a big-endian u32
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read u32: {e}"),
            })?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Read a counted string (length-prefixed UTF-8)
    fn read_counted_string(&mut self) -> Result<String> {
        let len = self.read_u32()?;
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read string data: {e}"),
            })?;
        String::from_utf8(buf).map_err(|e| Error::Ccache {
            text: format!("Invalid UTF-8 in string: {e}"),
        })
    }

    /// Read a counted octet string (length-prefixed bytes)
    fn read_counted_octet_string(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()?;
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| Error::Ccache {
                text: format!("Failed to read octet string: {e}"),
            })?;
        Ok(buf)
    }
}

/// Serializer for FILE format v5
pub struct FileFormatSerializer<W: Write> {
    writer: W,
}

impl<W: Write> FileFormatSerializer<W> {
    /// Create a new serializer
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write the file format version
    pub fn write_version(&mut self) -> Result<()> {
        self.write_u16(FILE_FORMAT_VERSION)
    }

    /// Write a header tag
    pub fn write_header_tag(&mut self, tag: HeaderTag, data: &[u8]) -> Result<()> {
        let tag_value = match tag {
            HeaderTag::DeltaTime => 1,
            HeaderTag::Unknown(v) => v,
        };
        self.write_u16(tag_value)?;
        self.write_u16(data.len() as u16)?;
        self.writer.write_all(data).map_err(|e| Error::Ccache {
            text: format!("Failed to write header tag data: {e}"),
        })
    }

    /// Write the header terminator
    pub fn write_header_terminator(&mut self) -> Result<()> {
        self.write_u16(0)?; // Null tag terminates header
        self.write_u16(0)
    }

    /// Write a principal
    pub fn write_principal(&mut self, principal: &Principal) -> Result<()> {
        self.write_u32(principal.name_type)?;
        self.write_u32(principal.components.len() as u32)?;
        self.write_counted_string(&principal.realm)?;
        for component in &principal.components {
            self.write_counted_string(component)?;
        }
        Ok(())
    }

    /// Write a key block
    pub fn write_key_block(&mut self, key_block: &KeyBlock) -> Result<()> {
        self.write_u16(key_block.enctype)?;
        self.write_counted_octet_string(&key_block.key_data)
    }

    /// Write times
    pub fn write_times(&mut self, times: &Times) -> Result<()> {
        self.write_u32(times.auth_time)?;
        self.write_u32(times.start_time)?;
        self.write_u32(times.end_time)?;
        self.write_u32(times.renew_till)
    }

    /// Write addresses
    pub fn write_addresses(&mut self, addresses: &[Address]) -> Result<()> {
        self.write_u32(addresses.len() as u32)?;
        for addr in addresses {
            self.write_u16(addr.addr_type)?;
            self.write_counted_octet_string(&addr.addr_data)?;
        }
        Ok(())
    }

    /// Write authorization data
    pub fn write_authdata(&mut self, authdata: &[AuthData]) -> Result<()> {
        self.write_u32(authdata.len() as u32)?;
        for ad in authdata {
            self.write_u16(ad.ad_type)?;
            self.write_counted_octet_string(&ad.ad_data)?;
        }
        Ok(())
    }

    /// Write a credential
    pub fn write_credential(&mut self, credential: &Credential) -> Result<()> {
        self.write_principal(&credential.client)?;
        self.write_principal(&credential.server)?;
        self.write_key_block(&credential.key_block)?;
        self.write_times(&credential.times)?;
        self.write_u8(credential.is_config)?;
        self.write_u32(credential.ticket_flags)?;
        self.write_addresses(&credential.addresses)?;
        self.write_authdata(&credential.authdata)?;
        self.write_counted_octet_string(&credential.ticket)?;
        self.write_counted_octet_string(&credential.second_ticket)
    }

    /// Write a u8
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.writer.write_all(&[value]).map_err(|e| Error::Ccache {
            text: format!("Failed to write u8: {e}"),
        })
    }

    /// Write a big-endian u16
    fn write_u16(&mut self, value: u16) -> Result<()> {
        self.writer
            .write_all(&value.to_be_bytes())
            .map_err(|e| Error::Ccache {
                text: format!("Failed to write u16: {e}"),
            })
    }

    /// Write a big-endian u32
    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.writer
            .write_all(&value.to_be_bytes())
            .map_err(|e| Error::Ccache {
                text: format!("Failed to write u32: {e}"),
            })
    }

    /// Write a counted string (length-prefixed UTF-8)
    fn write_counted_string(&mut self, s: &str) -> Result<()> {
        self.write_u32(s.len() as u32)?;
        self.writer
            .write_all(s.as_bytes())
            .map_err(|e| Error::Ccache {
                text: format!("Failed to write string data: {e}"),
            })
    }

    /// Write a counted octet string (length-prefixed bytes)
    fn write_counted_octet_string(&mut self, data: &[u8]) -> Result<()> {
        self.write_u32(data.len() as u32)?;
        self.writer.write_all(data).map_err(|e| Error::Ccache {
            text: format!("Failed to write octet string: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_principal_round_trip() {
        let principal = Principal::new(
            NameType::Principal,
            "EXAMPLE.COM".to_string(),
            vec!["user".to_string()],
        );

        let mut buf = Vec::new();
        let mut serializer = FileFormatSerializer::new(&mut buf);
        serializer.write_principal(&principal).unwrap();

        let mut parser = FileFormatParser::new(Cursor::new(buf));
        let parsed = parser.parse_principal().unwrap();

        assert_eq!(principal.name_type, parsed.name_type);
        assert_eq!(principal.realm, parsed.realm);
        assert_eq!(principal.components, parsed.components);
    }

    #[test]
    fn test_key_block_zeroization() {
        let key_data = vec![0x42u8; 32]; // Dummy key
        let key_block = KeyBlock {
            enctype: EncType::Aes256CtsHmacSha1_96 as u16,
            key_data,
        };

        // Manually drop and check zeroization
        drop(key_block);
        // Note: In real tests, we'd use a custom allocator to verify
        // that memory was actually zeroed
    }

    #[test]
    fn test_times_serialization() {
        let times = Times {
            auth_time: 1_234_567_890,
            start_time: 1_234_567_891,
            end_time: 1_234_567_892,
            renew_till: 1_234_567_893,
        };

        let mut buf = Vec::new();
        let mut serializer = FileFormatSerializer::new(&mut buf);
        serializer.write_times(&times).unwrap();

        let mut parser = FileFormatParser::new(Cursor::new(buf));
        let parsed = parser.parse_times().unwrap();

        assert_eq!(times.auth_time, parsed.auth_time);
        assert_eq!(times.start_time, parsed.start_time);
        assert_eq!(times.end_time, parsed.end_time);
        assert_eq!(times.renew_till, parsed.renew_till);
    }

    #[test]
    fn test_version_parsing() {
        let data = vec![0x05, 0x04]; // Version 5.4
        let mut parser = FileFormatParser::new(Cursor::new(data));
        let version = parser.parse_version().unwrap();
        assert_eq!(version, FILE_FORMAT_VERSION);
    }

    #[test]
    fn test_header_tags() {
        let mut buf = Vec::new();
        let mut serializer = FileFormatSerializer::new(&mut buf);

        // Write delta time tag
        serializer
            .write_header_tag(HeaderTag::DeltaTime, &[0, 0, 0, 60])
            .unwrap();
        serializer.write_header_terminator().unwrap();

        let mut parser = FileFormatParser::new(Cursor::new(buf));
        let tags = parser.parse_header().unwrap();

        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].0, HeaderTag::DeltaTime);
        assert_eq!(tags[0].1, vec![0, 0, 0, 60]);
    }
}
