use rustls::CipherSuite;
use rustls::ClientConfig as RustlsClientConfig;
use rustls::ExtensionType;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShortIdParseError {
    #[error("short_id is empty")]
    Empty,
    #[error("short_id must be exactly 8 bytes (16 hex chars), got {0} chars")]
    InvalidLength(usize),
    #[error("short_id contains non-hex character at index {0}")]
    InvalidHex(usize),
}

pub struct RealityConfig {
    pub profile: BrowserProfile,
    pub server_name: String,
    pub public_key: Option<[u8; 32]>,
    pub short_id: Option<[u8; 8]>,
}

impl BrowserProfile {
    pub fn get_extension_order(&self) -> Vec<ExtensionType> {
        match self {
            BrowserProfile::Chrome => vec![
                ExtensionType::ServerName,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::RenegotiationInfo,
                ExtensionType::EllipticCurves,
                ExtensionType::ECPointFormats,
                ExtensionType::SessionTicket,
                ExtensionType::ALProtocolNegotiation,
                ExtensionType::StatusRequest,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::SCT,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
                ExtensionType::SupportedVersions,
                ExtensionType::from(0x001B), // compress_certificate
                ExtensionType::from(0x4469), // application_settings
                ExtensionType::TransportParameters,
            ],
            BrowserProfile::Firefox => vec![
                ExtensionType::ServerName,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::RenegotiationInfo,
                ExtensionType::SupportedVersions,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::ALProtocolNegotiation,
                ExtensionType::StatusRequest,
                ExtensionType::SCT,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
                ExtensionType::EllipticCurves,
                ExtensionType::ECPointFormats,
                ExtensionType::SessionTicket,
                ExtensionType::TransportParameters,
            ],
            BrowserProfile::Safari => vec![
                ExtensionType::ServerName,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::RenegotiationInfo,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::StatusRequest,
                ExtensionType::ALProtocolNegotiation,
                ExtensionType::EllipticCurves,
                ExtensionType::ECPointFormats,
                ExtensionType::SessionTicket,
                ExtensionType::SupportedVersions,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
                ExtensionType::TransportParameters,
            ],
        }
    }

    pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
        match self {
            BrowserProfile::Chrome => vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            BrowserProfile::Firefox => vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            BrowserProfile::Safari => vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
        }
    }

    pub fn quic_alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self {
            BrowserProfile::Chrome | BrowserProfile::Firefox | BrowserProfile::Safari => {
                vec![b"h3".to_vec()]
            }
        }
    }

    pub fn tcp_alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self {
            BrowserProfile::Chrome | BrowserProfile::Firefox | BrowserProfile::Safari => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
        }
    }
}

impl RealityConfig {
    pub fn apply_to_rustls(&self, config: &mut RustlsClientConfig) {
        config.fixed_extension_order = Some(self.profile.get_extension_order());
        config.fixed_cipher_suite_order = Some(self.profile.get_cipher_suites());

        // Disable default SNI if we are borrowing a specific one.
        config.enable_sni = false;
    }
}

pub fn parse_short_id_hex(raw: &str) -> Result<[u8; 8], ShortIdParseError> {
    let normalized: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if normalized.is_empty() {
        return Err(ShortIdParseError::Empty);
    }
    if normalized.len() != 16 {
        return Err(ShortIdParseError::InvalidLength(normalized.len()));
    }

    let bytes = normalized.as_bytes();
    let mut out = [0u8; 8];
    for (idx, slot) in out.iter_mut().enumerate() {
        let h_idx = idx * 2;
        let l_idx = h_idx + 1;
        let hi = bytes[h_idx];
        let lo = bytes[l_idx];

        if !hi.is_ascii_hexdigit() {
            return Err(ShortIdParseError::InvalidHex(h_idx));
        }
        if !lo.is_ascii_hexdigit() {
            return Err(ShortIdParseError::InvalidHex(l_idx));
        }

        let pair = [hi as char, lo as char];
        let pair_str: String = pair.iter().collect();
        *slot =
            u8::from_str_radix(&pair_str, 16).map_err(|_| ShortIdParseError::InvalidHex(h_idx))?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_have_non_empty_fingerprints() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
        ] {
            assert!(!profile.get_extension_order().is_empty());
            assert!(!profile.get_cipher_suites().is_empty());
            assert!(!profile.quic_alpn_protocols().is_empty());
            assert!(!profile.tcp_alpn_protocols().is_empty());
        }
    }

    #[test]
    fn parse_short_id_hex_accepts_8_bytes() {
        let sid = parse_short_id_hex("0011223344556677").expect("valid short id");
        assert_eq!(sid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    #[test]
    fn parse_short_id_hex_rejects_invalid_length() {
        let err = parse_short_id_hex("00112233").expect_err("short id must be 8 bytes");
        assert_eq!(err, ShortIdParseError::InvalidLength(8));
    }

    #[test]
    fn parse_short_id_hex_rejects_invalid_hex() {
        let err = parse_short_id_hex("00112233445566zz").expect_err("invalid hex should fail");
        assert_eq!(err, ShortIdParseError::InvalidHex(14));
    }
}
