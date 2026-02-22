use rustls::ClientConfig as RustlsClientConfig;
use rustls::ExtensionType;
use rustls::CipherSuite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
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
            _ => vec![],
        }
    }

    pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
        match self {
            BrowserProfile::Chrome => vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ],
            _ => vec![],
        }
    }
}

impl RealityConfig {
    pub fn apply_to_rustls(&self, config: &mut RustlsClientConfig) {
        config.fixed_extension_order = Some(self.profile.get_extension_order());
        config.fixed_cipher_suite_order = Some(self.profile.get_cipher_suites());
        
        // Disable default SNI if we are borrowing a specific one
        config.enable_sni = false; 
    }
}
