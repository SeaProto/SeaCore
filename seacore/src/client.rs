use std::cmp::Reverse;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU8, Ordering};
use std::sync::Mutex as StdMutex;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;

use eyre::Result;
use quinn::Endpoint;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};
use uuid::Uuid;

use seacore_protocol::protocol::Address;
use seacore_protocol::quic::{side, Connection, Task};
use seacore_protocol::reality::{parse_short_id_hex, BrowserProfile};

use crate::metrics::ClientMetrics;
use crate::session_policy::SessionGovernancePolicy;

use rand::rngs::OsRng;
use rand::Rng;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::NamedGroup;
use x25519_dalek::{PublicKey, StaticSecret};

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::{ClientExtension, UnknownExtension};

fn get_grease_u16() -> u16 {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(0..16);
    (n << 12) | 0x0A0A
}

#[derive(Deserialize, Clone)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub uuid: Uuid,
    pub password: String,
    pub socks5_listen: SocketAddr,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    pub transport: Option<String>,
    pub congestion_control: Option<String>,
    pub max_idle_time_secs: Option<u64>,
    pub connection_idle_timeout_secs: Option<u64>,
    pub handshake_timeout_secs: Option<u64>,
    pub half_close_timeout_secs: Option<u64>,
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: Option<usize>,
    pub idle_session_check_interval_secs: Option<u64>,
    pub idle_session_timeout_secs: Option<u64>,
    pub min_idle_sessions: Option<usize>,
    pub insecure_skip_verify: Option<bool>,
    pub server_cert_sha256: Option<String>,
    pub max_inbound_connections: Option<usize>,
    pub max_uni_stream_tasks: Option<usize>,
    pub max_udp_associations: Option<usize>,
    pub metrics_listen: Option<SocketAddr>,
    pub reality: Option<RealitySettings>,
}

#[derive(Deserialize, Clone)]
pub struct RealitySettings {
    pub server_name: String,
    pub profile: String,
    pub public_key: Option<String>,
    #[allow(dead_code)]
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

fn default_server_name() -> String {
    "localhost".to_string()
}

type PacketSender = mpsc::Sender<(bytes::Bytes, Address)>;
type UdpRoutes = Arc<Mutex<HashMap<u16, PacketSender>>>;
type UdpRouteTouches = Arc<Mutex<HashMap<u16, Instant>>>;

#[derive(Clone)]
struct IdleSessionPolicy {
    check_interval: Duration,
    timeout: Duration,
    min_idle_sessions: usize,
}

fn idle_session_policy_from_client_config(config: &ClientConfig) -> IdleSessionPolicy {
    let check_secs = config.idle_session_check_interval_secs.unwrap_or(5).max(1);
    let timeout_secs = config.idle_session_timeout_secs.unwrap_or(10).max(2);
    let min_idle_sessions = config.min_idle_sessions.unwrap_or(0);

    IdleSessionPolicy {
        check_interval: Duration::from_secs(check_secs),
        timeout: Duration::from_secs(timeout_secs),
        min_idle_sessions,
    }
}

static NEXT_ASSOC_ID: AtomicU16 = AtomicU16::new(1);
static REALITY_CLIENT_SECRET: OnceLock<StdMutex<StaticSecret>> = OnceLock::new();
static REALITY_KX_GROUP: OnceLock<&'static dyn SupportedKxGroup> = OnceLock::new();
static REALITY_HANDSHAKE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 512;
const DEFAULT_MAX_UNI_STREAM_TASKS: usize = 256;
const DEFAULT_MAX_UDP_ASSOCIATIONS: usize = 1024;

fn reality_secret_store() -> &'static StdMutex<StaticSecret> {
    REALITY_CLIENT_SECRET.get_or_init(|| StdMutex::new(StaticSecret::random_from_rng(OsRng)))
}

fn rotate_reality_client_secret() -> StaticSecret {
    let mut guard = reality_secret_store()
        .lock()
        .expect("reality secret store poisoned");
    let next = StaticSecret::random_from_rng(OsRng);
    *guard = next.clone();
    next
}

fn current_reality_client_secret() -> StaticSecret {
    reality_secret_store()
        .lock()
        .expect("reality secret store poisoned")
        .clone()
}

fn reality_handshake_lock() -> &'static tokio::sync::Mutex<()> {
    REALITY_HANDSHAKE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Simulate Chrome's HTTP/3 initialization by opening Control, QPACK Encoder,
/// and QPACK Decoder unidirectional streams with appropriate settings.
fn encode_quic_varint(value: u64, out: &mut Vec<u8>) {
    if value <= 63 {
        out.push(value as u8);
        return;
    }
    if value <= 16_383 {
        let tagged = (value | 0x4000) as u16;
        out.extend_from_slice(&tagged.to_be_bytes());
        return;
    }
    if value <= 1_073_741_823 {
        let tagged = (value | 0x8000_0000) as u32;
        out.extend_from_slice(&tagged.to_be_bytes());
        return;
    }
    let tagged = value | 0xC000_0000_0000_0000;
    out.extend_from_slice(&tagged.to_be_bytes());
}

fn append_h3_setting(payload: &mut Vec<u8>, setting_id: u64, setting_value: u64) {
    encode_quic_varint(setting_id, payload);
    encode_quic_varint(setting_value, payload);
}

fn build_h3_control_stream_payload() -> Vec<u8> {
    // RFC 9114 control stream:
    //   stream_type(varint=0x00) + SETTINGS frame
    // SETTINGS frame:
    //   frame_type(varint=0x04) + frame_len(varint) + settings_payload
    let mut settings_payload = Vec::new();
    append_h3_setting(&mut settings_payload, 0x01, 0); // QPACK_MAX_TABLE_CAPACITY
    append_h3_setting(&mut settings_payload, 0x06, 262_144); // MAX_FIELD_SECTION_SIZE
    append_h3_setting(&mut settings_payload, 0x07, 100); // QPACK_BLOCKED_STREAMS
    append_h3_setting(&mut settings_payload, 0x33, 1); // H3_DATAGRAM

    let mut control = Vec::new();
    encode_quic_varint(0x00, &mut control); // stream type: control
    encode_quic_varint(0x04, &mut control); // frame type: SETTINGS
    encode_quic_varint(settings_payload.len() as u64, &mut control); // frame length
    control.extend_from_slice(&settings_payload);
    control
}

fn build_h3_uni_stream_type(stream_type: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_quic_varint(stream_type, &mut out);
    out
}

async fn send_h3_settings(conn: &quinn::Connection) {
    // 1. Control stream (type 0x00) with SETTINGS frame
    if let Ok(mut send) = conn.open_uni().await {
        let _ = send.write_all(&build_h3_control_stream_payload()).await;
        // Don't finish — Chrome keeps control stream open
    }

    // 2. QPACK Encoder stream (type 0x02)
    if let Ok(mut send) = conn.open_uni().await {
        let _ = send.write_all(&build_h3_uni_stream_type(0x02)).await;
        // Chrome keeps this open with no data
    }

    // 3. QPACK Decoder stream (type 0x03)
    if let Ok(mut send) = conn.open_uni().await {
        let _ = send.write_all(&build_h3_uni_stream_type(0x03)).await;
        // Chrome keeps this open with no data
    }
}

fn browser_profile_from_config(config: &ClientConfig) -> BrowserProfile {
    match config
        .reality
        .as_ref()
        .map(|r| r.profile.to_lowercase())
        .as_deref()
    {
        Some("firefox") => BrowserProfile::Firefox,
        Some("safari") => BrowserProfile::Safari,
        _ => BrowserProfile::Chrome,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RealityCertDecision {
    Unknown = 0,
    TemporaryTrusted = 1,
    RealCertificate = 2,
    LegacyAccepted = 3,
    Invalid = 4,
}

#[derive(Clone, Debug)]
struct RealityCertState {
    decision: Arc<AtomicU8>,
}

impl RealityCertState {
    fn new() -> Self {
        Self {
            decision: Arc::new(AtomicU8::new(RealityCertDecision::Unknown as u8)),
        }
    }

    fn reset(&self) {
        self.decision
            .store(RealityCertDecision::Unknown as u8, Ordering::Relaxed);
    }

    fn mark(&self, decision: RealityCertDecision) {
        self.decision.store(decision as u8, Ordering::Relaxed);
    }

    fn decision(&self) -> RealityCertDecision {
        match self.decision.load(Ordering::Relaxed) {
            1 => RealityCertDecision::TemporaryTrusted,
            2 => RealityCertDecision::RealCertificate,
            3 => RealityCertDecision::LegacyAccepted,
            4 => RealityCertDecision::Invalid,
            _ => RealityCertDecision::Unknown,
        }
    }

    fn saw_real_certificate(&self) -> bool {
        self.decision() == RealityCertDecision::RealCertificate
    }
}

fn build_tls_config(
    config: &ClientConfig,
) -> Result<(rustls::ClientConfig, Option<RealityCertState>)> {
    let profile = browser_profile_from_config(config);
    let mut provider = rustls::crypto::ring::default_provider();
    let mut custom_session_id_opt = None;
    let mut extra_exts = Vec::new();
    let mut reality_expected_cert_proof = None;
    let reality_mode = config.reality.is_some();
    let reality_cert_state = if reality_mode {
        Some(RealityCertState::new())
    } else {
        None
    };

    // 1. GREASE extension at the beginning
    let grease_ext_type = ExtensionType::from(get_grease_u16());
    extra_exts.push(ClientExtension::Unknown(UnknownExtension {
        typ: grease_ext_type,
        payload: Payload::empty(),
    }));

    if let Some(reality) = config.reality.as_ref() {
        use rustls::pki_types::DnsName;
        if let Ok(dns_name) = DnsName::try_from(reality.server_name.as_str()) {
            extra_exts.push(ClientExtension::make_sni(&dns_name));
        }
    }

    // 2. supported_versions with GREASE
    // Removed manual SupportedVersions extension as it conflicts with rustls native generation in TCP mode

    // 3. TLS Padding extension (Chrome typically pads ClientHello to match a certain size,
    // but here we just add a 128-byte padding as a common fingerprint)
    extra_exts.push(ClientExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Padding,
        payload: Payload::new(vec![0u8; 128]),
    }));

    if let Some(reality) = &config.reality {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let server_pub_b64 = reality.public_key.as_deref().unwrap_or("");
        let Ok(server_pub_bytes) = STANDARD.decode(server_pub_b64) else {
            return Err(eyre::eyre!("Invalid base64 public_key in reality config"));
        };
        if server_pub_bytes.len() != 32 {
            return Err(eyre::eyre!("Reality public_key must be 32 bytes"));
        };
        let mut server_pub_arr = [0u8; 32];
        server_pub_arr.copy_from_slice(&server_pub_bytes);
        let server_pub = PublicKey::from(server_pub_arr);

        // Rotate client X25519 secret for every handshake build to avoid
        // long-lived per-process key reuse fingerprints.
        let client_secret = rotate_reality_client_secret();
        let shared_secret = client_secret.diffie_hellman(&server_pub);
        let mut shared_secret_bytes = [0u8; 32];
        shared_secret_bytes.copy_from_slice(shared_secret.as_bytes());

        use ring::hmac;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut session_id = [0u8; 32];
        session_id[0..8].copy_from_slice(&now.to_be_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, shared_secret.as_bytes());
        let mut msg = Vec::new();
        msg.extend_from_slice(&now.to_be_bytes());
        msg.extend_from_slice(config.uuid.as_bytes());
        if let Some(short_id) = reality.short_id.as_ref() {
            let parsed_short_id = parse_short_id_hex(short_id)
                .map_err(|e| eyre::eyre!("invalid reality.short_id '{}': {}", short_id, e))?;
            msg.extend_from_slice(&parsed_short_id);
        }
        let tag = hmac::sign(&key, &msg);
        session_id[8..32].copy_from_slice(&tag.as_ref()[..24]);

        reality_expected_cert_proof = Some(seacore_protocol::reality::derive_temp_cert_proof(
            &shared_secret_bytes,
            &session_id,
            &reality.server_name,
        ));

        custom_session_id_opt = Some(session_id.into());

        let leaked_group: &'static dyn SupportedKxGroup = *REALITY_KX_GROUP.get_or_init(|| {
            Box::leak(Box::new(CustomX25519Group)) as &'static dyn SupportedKxGroup
        });
        provider.kx_groups.insert(0, leaked_group);
    }

    let insecure_skip_verify = config.insecure_skip_verify.unwrap_or(false);
    let cert_pin = config
        .server_cert_sha256
        .as_deref()
        .map(parse_cert_sha256_pin)
        .transpose()?;

    let allow_invalid_cert_chain = insecure_skip_verify || reality_mode;

    let mut client_crypto = if allow_invalid_cert_chain || cert_pin.is_some() {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let webpki = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| eyre::eyre!("failed to build WebPKI verifier: {}", e))?;

        let verifier = SeaCoreServerVerifier {
            webpki,
            allow_invalid_cert_chain,
            pinned_sha256: cert_pin,
            reality_mode,
            reality_expected_cert_proof,
            reality_cert_state: reality_cert_state.clone(),
        };

        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    client_crypto.alpn_protocols = profile.quic_alpn_protocols();
    client_crypto.extra_exts = extra_exts;
    client_crypto.custom_session_id = custom_session_id_opt;

    if let Some(reality) = &config.reality {
        let short_id = reality
            .short_id
            .as_deref()
            .map(parse_short_id_hex)
            .transpose()
            .map_err(|e| eyre::eyre!("invalid reality.short_id: {}", e))?;

        let reality_cfg = seacore_protocol::reality::RealityConfig {
            profile,
            server_name: reality.server_name.clone(),
            public_key: None,
            short_id,
        };

        reality_cfg.apply_to_rustls(&mut client_crypto);
    }

    Ok((client_crypto, reality_cert_state))
}

fn normalize_spider_path(spider_x: &str) -> String {
    let trimmed = spider_x.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

async fn run_reality_spider(
    tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    host: &str,
    spider_x: &str,
) -> Result<()> {
    let path = normalize_spider_path(spider_x);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n",
        path, host
    );

    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        tls_stream.write_all(request.as_bytes()),
    )
    .await;

    let mut sink = vec![0u8; 8192];
    let _ = tokio::time::timeout(Duration::from_secs(3), tls_stream.read(&mut sink)).await;
    let _ = tokio::time::timeout(Duration::from_millis(250), tls_stream.shutdown()).await;

    Ok(())
}

pub async fn run_client(config_path: &str) -> Result<()> {
    let config_str = fs::read_to_string(config_path)?;
    let config: Arc<ClientConfig> = Arc::new(serde_json::from_str(&config_str)?);
    let idle_policy = Arc::new(idle_session_policy_from_client_config(&config));
    let session_policy = Arc::new(SessionGovernancePolicy::from_config(
        config.handshake_timeout_secs,
        config.connection_idle_timeout_secs,
        config.max_idle_time_secs,
        config.half_close_timeout_secs,
    ));
    let max_inbound_connections = config
        .max_inbound_connections
        .unwrap_or(DEFAULT_MAX_INBOUND_CONNECTIONS)
        .max(1);
    let max_uni_stream_tasks = config
        .max_uni_stream_tasks
        .unwrap_or(DEFAULT_MAX_UNI_STREAM_TASKS)
        .max(1);
    let max_udp_associations = config
        .max_udp_associations
        .unwrap_or(DEFAULT_MAX_UDP_ASSOCIATIONS)
        .max(1);

    info!("Server: {}", config.server);
    info!("SOCKS5 listen: {}", config.socks5_listen);
    if config.reality.is_some() {
        info!(
            "REALITY mode enabled: client accepts temporary trusted certificates and enters spider mode on real-site certificates"
        );
    }

    if config.insecure_skip_verify.unwrap_or(false) {
        if config.server_cert_sha256.is_some() {
            warn!(
                "Certificate chain verification is disabled; relying on server_cert_sha256 pin only"
            );
        } else {
            warn!("TLS certificate verification is disabled (insecure_skip_verify=true)");
        }
    } else if config.server_cert_sha256.is_some() {
        info!("Server certificate pinning is enabled (server_cert_sha256)");
    }
    info!(
        "Idle session policy: check={}s timeout={}s min_idle={}",
        idle_policy.check_interval.as_secs(),
        idle_policy.timeout.as_secs(),
        idle_policy.min_idle_sessions
    );
    info!(
        "Limits: inbound={} uni_tasks={} udp_assoc={}",
        max_inbound_connections, max_uni_stream_tasks, max_udp_associations
    );
    info!(
        "Session governance: handshake={}s conn_idle={}s half_close={}s",
        session_policy.handshake_timeout.as_secs(),
        session_policy.connection_idle_timeout.as_secs(),
        session_policy.half_close_timeout.as_secs()
    );

    let metrics = Arc::new(ClientMetrics::default());
    if let Some(metrics_listen) = config.metrics_listen {
        crate::metrics::spawn_client_exporter(metrics_listen, metrics.clone());
    }

    let mut transport_config = quinn::TransportConfig::default();

    // --- Chrome 118+ QUIC Transport Parameters Emulation ---
    // These values match Chrome's default HTTP/3 transport parameters
    // to avoid fingerprinting by DPI systems.
    transport_config.receive_window(quinn::VarInt::from_u32(15728640)); // ~15MB
    transport_config.send_window(15728640);
    transport_config.stream_receive_window(quinn::VarInt::from_u32(6291456)); // 6MB
    transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
    transport_config.max_concurrent_uni_streams(quinn::VarInt::from_u32(100));
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

    // Apply unified session governance connection idle timeout
    if let Ok(timeout) = session_policy.connection_idle_timeout.try_into() {
        transport_config.max_idle_timeout(Some(timeout));
    }
    if let Some(cc) = &config.congestion_control {
        match cc.to_lowercase().as_str() {
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
            "cubic" => {} // Default
            _ => warn!(
                "Unknown congestion control algorithm: {}, using default",
                cc
            ),
        }
    }

    // QUIC Initial Padding: ensure Initial packets fill to 1200 bytes minimum
    transport_config.min_mtu(1200);
    // Note: quinn 0.11 enables grease_quic_bit by default (RFC 9287)

    let transport_config = Arc::new(transport_config);

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    // Start SOCKS5 listener (shared across reconnections)
    let listener = Arc::new(TcpListener::bind(config.socks5_listen).await?);
    info!("SOCKS5 listening on {}", config.socks5_listen);

    let inbound_handler_limiter = Arc::new(Semaphore::new(max_inbound_connections));
    let uni_stream_task_limiter = Arc::new(Semaphore::new(max_uni_stream_tasks));

    // Auto-reconnect loop with exponential backoff
    let mut backoff_secs = 1u64;
    const MAX_BACKOFF: u64 = 60;

    let transport_mode = config
        .transport
        .clone()
        .unwrap_or_else(|| "auto".to_string())
        .to_lowercase();
    let mut connect_iteration = 0u64;

    loop {
        if connect_iteration > 0 {
            metrics.inc_reconnects();
        }
        connect_iteration = connect_iteration.saturating_add(1);
        metrics.inc_connect_attempts();

        info!(
            event = "client_connect_attempt",
            server = %config.server,
            mode = %transport_mode,
            attempt = connect_iteration,
            "connecting to server"
        );

        let mut connected_inner = None;
        let mut tcp_read_half: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = None;

        {
            let _reality_handshake_guard = reality_handshake_lock().lock().await;

            // Refresh Reality token/session id on every reconnect attempt.
            let (base_tls_config, reality_cert_state) = build_tls_config(&config)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(base_tls_config.clone())?,
            ));
            client_config.transport_config(transport_config.clone());
            endpoint.set_default_client_config(client_config);

            let mut tcp_tls_config = base_tls_config;
            tcp_tls_config.alpn_protocols =
                browser_profile_from_config(&config).tcp_alpn_protocols();
            let handshake_timeout = session_policy.handshake_timeout;

            if transport_mode == "udp" || transport_mode == "auto" {
                if let Some(state) = &reality_cert_state {
                    state.reset();
                }
                match endpoint.connect(config.server, &config.server_name) {
                    Ok(connecting) => {
                        match tokio::time::timeout(handshake_timeout, connecting).await {
                            Ok(Ok(c)) => {
                                if reality_cert_state
                                    .as_ref()
                                    .map(RealityCertState::saw_real_certificate)
                                    .unwrap_or(false)
                                {
                                    warn!(
                                        "REALITY received a real site certificate on QUIC path; closing and retrying"
                                    );
                                    c.close(
                                        quinn::VarInt::from_u32(0x00),
                                        b"reality real certificate",
                                    );
                                } else {
                                    info!("Connected to server {} via QUIC (UDP)", config.server);
                                    connected_inner =
                                        Some(seacore_protocol::quic::InnerConn::Quic(c));
                                }
                            }
                            Ok(Err(e)) => {
                                if transport_mode == "udp" {
                                    warn!("QUIC connection failed: {}", e);
                                }
                            }
                            Err(_) => {
                                if transport_mode == "udp" {
                                    warn!(
                                        "QUIC connection timed out after {}s",
                                        handshake_timeout.as_secs()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if transport_mode == "udp" {
                            warn!("QUIC connect error: {}", e);
                        }
                    }
                }
            }

            if connected_inner.is_none() && (transport_mode == "tcp" || transport_mode == "auto") {
                if transport_mode == "auto" {
                    metrics.inc_fallback_attempts();
                    info!("QUIC (UDP) failed or timed out, falling back to TCP...");
                }

                if let Some(state) = &reality_cert_state {
                    state.reset();
                }

                let spider_host = config
                    .reality
                    .as_ref()
                    .map(|r| r.server_name.clone())
                    .unwrap_or_else(|| config.server_name.clone());
                let spider_x = config
                    .reality
                    .as_ref()
                    .and_then(|r| r.spider_x.as_deref())
                    .unwrap_or("/");

                // Connect TCP
                match tokio::time::timeout(
                    handshake_timeout,
                    tokio::net::TcpStream::connect(config.server),
                )
                .await
                {
                    Ok(Ok(tcp_stream)) => {
                        let _ = tcp_stream.set_nodelay(true);
                        let connector =
                            tokio_rustls::TlsConnector::from(Arc::new(tcp_tls_config.clone()));
                        let domain =
                            rustls::pki_types::ServerName::try_from(config.server_name.as_str())
                                .map_err(|e| eyre::eyre!("Invalid server name: {}", e))?
                                .to_owned();
                        match tokio::time::timeout(
                            handshake_timeout,
                            connector.connect(domain, tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(mut tls_stream)) => {
                                if reality_cert_state
                                    .as_ref()
                                    .map(RealityCertState::saw_real_certificate)
                                    .unwrap_or(false)
                                {
                                    warn!(
                                        "REALITY received real certificate on TCP path; entering spider mode"
                                    );
                                    let _ =
                                        run_reality_spider(&mut tls_stream, &spider_host, spider_x)
                                            .await;
                                } else {
                                    info!("Connected to server {} via TLS (TCP)", config.server);
                                    // We don't fully implement multiplexing over a single TCP stream yet for SeaCore connect/dissociate.
                                    // But for simple packet tunneling, wrapping it in InnerConn works. Needs a loop handling.
                                    let (r, w) = tokio::io::split(tls_stream);
                                    connected_inner = Some(seacore_protocol::quic::InnerConn::Tcp(
                                        Arc::new(tokio::sync::Mutex::new(Box::new(w))),
                                    ));
                                    tcp_read_half = Some(Box::new(r));
                                }
                            }
                            Ok(Err(e)) => {
                                warn!("TLS over TCP failed: {}", e);
                            }
                            Err(_) => warn!(
                                "TLS over TCP timed out after {}s",
                                handshake_timeout.as_secs()
                            ),
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("TCP connect error: {}", e);
                    }
                    Err(_) => warn!(
                        "TCP connect timed out after {}s",
                        handshake_timeout.as_secs()
                    ),
                }
            }
        }

        let conn = match connected_inner {
            Some(c) => c,
            None => {
                warn!(
                    "All connection attempts failed. Retrying in {}s...",
                    backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        let seacore_conn = Connection::<side::Client>::new(conn.clone());

        // Authenticate
        match tokio::time::timeout(
            session_policy.handshake_timeout,
            seacore_conn.authenticate(config.uuid, &config.password),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                metrics.inc_auth_failures();
                warn!(
                    "Authentication failed: {}. Retrying in {}s...",
                    e, backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                continue;
            }
            Err(_) => {
                metrics.inc_auth_failures();
                warn!(
                    "Authentication timed out after {}s. Retrying in {}s...",
                    session_policy.handshake_timeout.as_secs(),
                    backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                continue;
            }
        }
        info!("Authenticated as {}", config.uuid);
        metrics.inc_connect_success();

        // Reset backoff on successful connection
        backoff_secs = 1;

        // --- Phase 14: HTTP/3 SETTINGS frame simulation ---
        // Mimic Chrome's HTTP/3 initialization (Control + QPACK streams)
        if let seacore_protocol::quic::InnerConn::Quic(q) = &conn {
            send_h3_settings(q).await;
        }

        // Use a watch channel to signal reconnect when heartbeat/connection dies
        let (disconnect_tx, mut disconnect_rx) = tokio::sync::watch::channel(false);

        // Start heartbeat & ping
        let seacore_conn_hb = seacore_conn.clone();
        let disconnect_tx_hb = disconnect_tx.clone();
        let hb_task = tokio::spawn(async move {
            let mut seq_id = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                if let Err(e) = seacore_conn_hb.heartbeat().await {
                    warn!("Heartbeat failed: {}. Triggering reconnect.", e);
                    let _ = disconnect_tx_hb.send(true);
                    break;
                }

                if let Ok(duration) =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                {
                    let now = duration.as_millis() as u64;
                    if let Err(e) = seacore_conn_hb.ping(seq_id, now).await {
                        warn!("Ping failed: {}. Triggering reconnect.", e);
                        let _ = disconnect_tx_hb.send(true);
                        break;
                    }
                }
                seq_id = seq_id.wrapping_add(1);
            }
        });

        // --- Phase 14: Traffic padding/camouflage ---
        // Send random-sized heartbeats at random intervals to mimic browser idle traffic
        let seacore_conn_pad = seacore_conn.clone();
        let disconnect_tx_pad = disconnect_tx.clone();
        let pad_task = tokio::spawn(async move {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::from_entropy();
            loop {
                // Random interval: 2-8 seconds
                let delay = rng.gen_range(2..=8);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

                // Send a heartbeat as padding traffic
                if let Err(_) = seacore_conn_pad.heartbeat().await {
                    let _ = disconnect_tx_pad.send(true);
                    break;
                }
            }
        });

        let udp_routes: UdpRoutes = Arc::new(Mutex::new(HashMap::new()));
        let udp_route_touches: UdpRouteTouches = Arc::new(Mutex::new(HashMap::new()));

        // Background task for receiving server packets
        let bg_conn = conn.clone();
        let bg_seacore = seacore_conn.clone();
        let bg_routes = udp_routes.clone();
        let bg_route_touches = udp_route_touches.clone();
        let disconnect_tx_bg = disconnect_tx.clone();
        let uni_stream_task_limiter_bg = uni_stream_task_limiter.clone();
        let mut tcp_read = tcp_read_half;
        let bg_task = tokio::spawn(async move {
            match bg_conn {
                seacore_protocol::quic::InnerConn::Quic(q) => {
                    loop {
                        tokio::select! {
                            dg = q.read_datagram() => {
                                match dg {
                                    Ok(dg) => {
                                        if let Ok(task) = bg_seacore.accept_datagram(dg) {
                                            match task {
                                                Task::Packet(pkt) => {
                                                    let assoc_id = pkt.assoc_id();
                                                    let addr = pkt.addr().clone();
                                                    if let Ok(payload) = pkt.payload().await {
                                                        {
                                                            let mut touches = bg_route_touches.lock().await;
                                                            touches.insert(assoc_id, Instant::now());
                                                        }
                                                        let tx_opt = {
                                                            let routes = bg_routes.lock().await;
                                                            routes.get(&assoc_id).cloned()
                                                        };
                                                        if let Some(tx) = tx_opt {
                                                            let _ = tx.send((payload, addr)).await;
                                                        }
                                                    }
                                                }
                                                Task::Ping { seq_id, timestamp } => {
                                                    if let Ok(duration) = std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                    {
                                                        let now = duration.as_millis() as u64;
                                                        if now >= timestamp {
                                                            let rtt = now - timestamp;
                                                            info!("Ping seq {} RTT: {} ms", seq_id, rtt);
                                                        }
                                                    }
                                                }
                                                Task::Heartbeat => {
                                                    // Heartbeat received
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        let _ = disconnect_tx_bg.send(true);
                                        break;
                                    }
                                }
                            }
                            uni = q.accept_uni() => {
                                match uni {
                                    Ok(recv) => {
                                        let permit = match uni_stream_task_limiter_bg.clone().try_acquire_owned() {
                                            Ok(permit) => permit,
                                            Err(_) => {
                                                warn!(
                                                    "Dropping inbound uni-stream because max_uni_stream_tasks={} was reached",
                                                    max_uni_stream_tasks
                                                );
                                                continue;
                                            }
                                        };
                                        let bg_seacore_clone = bg_seacore.clone();
                                        let bg_routes_clone = bg_routes.clone();
                                        let bg_route_touches_clone = bg_route_touches.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            if let Ok(Task::Packet(pkt)) = bg_seacore_clone.accept_uni_stream(seacore_protocol::quic::SeaCoreReadStream::Quic(recv)).await {
                                                let assoc_id = pkt.assoc_id();
                                                let addr = pkt.addr().clone();
                                                if let Ok(payload) = pkt.payload().await {
                                                    {
                                                        let mut touches = bg_route_touches_clone.lock().await;
                                                        touches.insert(assoc_id, Instant::now());
                                                    }
                                                    let tx_opt = {
                                                        let routes = bg_routes_clone.lock().await;
                                                        routes.get(&assoc_id).cloned()
                                                    };
                                                    if let Some(tx) = tx_opt {
                                                        let _ = tx.send((payload, addr)).await;
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => {
                                        let _ = disconnect_tx_bg.send(true);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                seacore_protocol::quic::InnerConn::Tcp(_t) => {
                    if let Some(mut recv) = tcp_read.take() {
                        let bg_seacore_clone = bg_seacore.clone();
                        let bg_routes_clone = bg_routes.clone();
                        let bg_route_touches_clone = bg_route_touches.clone();
                        loop {
                            match bg_seacore_clone.next_tcp_task(recv.as_mut()).await {
                                Ok(task) => match task {
                                    Task::Packet(pkt) => {
                                        let assoc_id = pkt.assoc_id();
                                        let addr = pkt.addr().clone();
                                        if let Ok(payload) = pkt.payload().await {
                                            {
                                                let mut touches =
                                                    bg_route_touches_clone.lock().await;
                                                touches.insert(assoc_id, Instant::now());
                                            }
                                            let tx_opt = {
                                                let routes = bg_routes_clone.lock().await;
                                                routes.get(&assoc_id).cloned()
                                            };
                                            if let Some(tx) = tx_opt {
                                                let _ = tx.send((payload, addr)).await;
                                            }
                                        }
                                    }
                                    Task::Ping { seq_id, timestamp } => {
                                        if let Ok(duration) = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                        {
                                            let now = duration.as_millis() as u64;
                                            if now >= timestamp {
                                                let rtt = now - timestamp;
                                                info!("Ping seq {} RTT: {} ms", seq_id, rtt);
                                            }
                                        }
                                    }
                                    Task::Heartbeat => {}
                                    _ => {}
                                },
                                Err(e) => {
                                    warn!("TCP connection loop error: {}", e);
                                    let _ = disconnect_tx_bg.send(true);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        // AnyTLS-style idle session cleanup for UDP routes.
        let udp_routes_cleanup = udp_routes.clone();
        let udp_route_touches_cleanup = udp_route_touches.clone();
        let idle_policy_cleanup = idle_policy.clone();
        let mut janitor_disconnect_rx = disconnect_tx.subscribe();
        let janitor_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = janitor_disconnect_rx.changed() => {
                        break;
                    }
                    _ = tokio::time::sleep(idle_policy_cleanup.check_interval) => {
                        let now = Instant::now();
                        let mut routes = udp_routes_cleanup.lock().await;
                        let mut touches = udp_route_touches_cleanup.lock().await;

                        touches.retain(|assoc_id, _| routes.contains_key(assoc_id));

                        let mut entries: Vec<(u16, Instant)> = touches
                            .iter()
                            .map(|(assoc_id, ts)| (*assoc_id, *ts))
                            .collect();
                        entries.sort_by_key(|(_, ts)| Reverse(*ts));

                        let keep = idle_policy_cleanup.min_idle_sessions.min(entries.len());
                        for (idx, (assoc_id, last_active)) in entries.into_iter().enumerate() {
                            if idx < keep {
                                continue;
                            }
                            if now.saturating_duration_since(last_active) >= idle_policy_cleanup.timeout {
                                routes.remove(&assoc_id);
                                touches.remove(&assoc_id);
                            }
                        }
                    }
                }
            }
        });

        // Accept SOCKS5 connections until disconnect signal
        let listener_ref = listener.clone();
        let config_socks = config.clone();
        let idle_policy_socks = idle_policy.clone();
        let session_policy_socks = session_policy.clone();
        let inbound_handler_limiter_socks = inbound_handler_limiter.clone();
        let socks_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = disconnect_rx.changed() => {
                        break;
                    }
                    accept = listener_ref.accept() => {
                        match accept {
                            Ok((stream, peer_addr)) => {
                                let permit = match inbound_handler_limiter_socks.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        warn!(
                                            "Rejecting inbound {} because max_inbound_connections={} was reached",
                                            peer_addr,
                                            max_inbound_connections
                                        );
                                        continue;
                                    }
                                };
                                let sc = seacore_conn.clone();
                                let ur = udp_routes.clone();
                                let ut = udp_route_touches.clone();
                                let ip = idle_policy_socks.clone();
                                let sp = session_policy_socks.clone();
                                let cfg = config_socks.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = handle_inbound(stream, sc, peer_addr, ur, ut, ip, sp, cfg).await {
                                        warn!("Inbound handler error for {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("SOCKS5 accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Wait for any task to signal disconnect
        socks_task.await.ok();
        hb_task.abort();
        pad_task.abort();
        bg_task.abort();
        janitor_task.abort();
        if let seacore_protocol::quic::InnerConn::Quic(q) = &conn {
            q.close(quinn::VarInt::from_u32(0x00), b"reconnecting");
        }
        warn!("Connection lost. Reconnecting in {}s...", backoff_secs);
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
    }
}

async fn handle_inbound(
    mut stream: tokio::net::TcpStream,
    conn: Connection<side::Client>,
    peer_addr: SocketAddr,
    udp_routes: UdpRoutes,
    udp_route_touches: UdpRouteTouches,
    idle_policy: Arc<IdleSessionPolicy>,
    session_policy: Arc<SessionGovernancePolicy>,
    config: Arc<ClientConfig>,
) -> Result<()> {
    let mut version_buf = [0u8; 1];
    stream.read_exact(&mut version_buf).await?;

    match version_buf[0] {
        0x05 => {
            handle_socks5_logic(
                stream,
                conn,
                peer_addr,
                udp_routes,
                udp_route_touches,
                idle_policy,
                session_policy.clone(),
                config,
            )
            .await
        }
        0x04 => {
            handle_socks4(
                stream,
                conn,
                peer_addr,
                session_policy.connection_idle_timeout,
                session_policy.half_close_timeout,
                session_policy.handshake_timeout,
                config,
            )
            .await
        }
        v => Err(eyre::eyre!("unsupported proxy version: {}", v)),
    }
}

async fn relay_until_either_side_finishes<L, R>(
    left: L,
    right: R,
    relay_idle_timeout: Duration,
    half_close_timeout: Duration,
) -> std::io::Result<()>
where
    L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let mut left_buf = vec![0u8; 8192];
    let mut right_buf = vec![0u8; 8192];

    let relay_result = async {
        let mut left_closed = false;
        let mut right_closed = false;
        let mut half_close_deadline: Option<Instant> = None;

        loop {
            if left_closed && right_closed {
                return Ok(());
            }

            let wait_budget = match half_close_deadline {
                Some(deadline) => {
                    let remain = deadline.saturating_duration_since(Instant::now());
                    if remain.is_zero() {
                        return Ok(());
                    }
                    remain.min(relay_idle_timeout)
                }
                None => relay_idle_timeout,
            };

            tokio::select! {
                left_read_result = tokio::time::timeout(wait_budget, left_read.read(&mut left_buf)), if !left_closed => {
                    let n = match left_read_result {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Ok(()),
                    };
                    if n == 0 {
                        left_closed = true;
                        if half_close_deadline.is_none() {
                            half_close_deadline = Some(Instant::now() + half_close_timeout);
                        }
                        let _ = tokio::time::timeout(
                            Duration::from_millis(200),
                            tokio::io::AsyncWriteExt::shutdown(&mut right_write),
                        )
                        .await;
                        continue;
                    }
                    right_write.write_all(&left_buf[..n]).await?;
                }
                right_read_result = tokio::time::timeout(wait_budget, right_read.read(&mut right_buf)), if !right_closed => {
                    let n = match right_read_result {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Ok(()),
                    };
                    if n == 0 {
                        right_closed = true;
                        if half_close_deadline.is_none() {
                            half_close_deadline = Some(Instant::now() + half_close_timeout);
                        }
                        let _ = tokio::time::timeout(
                            Duration::from_millis(200),
                            tokio::io::AsyncWriteExt::shutdown(&mut left_write),
                        )
                        .await;
                        continue;
                    }
                    left_write.write_all(&right_buf[..n]).await?;
                }
            }
        }
    }
    .await;

    // On reset/abort paths (e.g. 10054), graceful TLS shutdown can become expensive.
    // Only try a bounded graceful close on normal EOF; otherwise drop halves directly.
    if relay_result.is_ok() {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tokio::io::AsyncWriteExt::shutdown(&mut left_write),
        )
        .await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tokio::io::AsyncWriteExt::shutdown(&mut right_write),
        )
        .await;
    }

    relay_result.map(|_| ())
}

fn is_expected_relay_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::TimedOut
    )
}

fn log_relay_error(prefix: &str, peer_addr: SocketAddr, err: std::io::Error) {
    if is_expected_relay_io_error(&err) {
        debug!("{} for {}: {}", prefix, peer_addr, err);
    } else {
        warn!("{} for {}: {}", prefix, peer_addr, err);
    }
}

async fn handle_socks4(
    mut stream: tokio::net::TcpStream,
    conn: Connection<side::Client>,
    peer_addr: SocketAddr,
    connection_idle_timeout: Duration,
    half_close_timeout: Duration,
    handshake_timeout: Duration,
    config: Arc<ClientConfig>,
) -> Result<()> {
    // SOCKS4 handshake (already read VN=0x04)
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf[..7]).await?;

    let cmd = buf[0];
    if cmd != 0x01 {
        // Only CONNECT supported
        stream
            .write_all(&[0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;
        return Err(eyre::eyre!("unsupported SOCKS4 command: {}", cmd));
    }

    let port = u16::from_be_bytes([buf[1], buf[2]]);
    let ip = std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);

    // Read USERID (NULL terminated)
    let mut userid = Vec::new();
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        userid.push(b[0]);
    }

    let addr =
        if ip.octets()[0] == 0 && ip.octets()[1] == 0 && ip.octets()[2] == 0 && ip.octets()[3] != 0
        {
            // SOCKS4a: Domain follows USERID
            let mut domain = Vec::new();
            loop {
                let mut b = [0u8; 1];
                stream.read_exact(&mut b).await?;
                if b[0] == 0 {
                    break;
                }
                domain.push(b[0]);
            }
            Address::DomainAddress(String::from_utf8_lossy(&domain).to_string(), port)
        } else {
            Address::SocketAddress(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        };

    // Choose transport
    let transport_mode = config.transport.as_deref().unwrap_or("auto").to_lowercase();

    if transport_mode == "tcp" {
        // 1:1 TCP fallback
        let server_addr = config.server;
        let tcp_stream = tokio::time::timeout(
            handshake_timeout,
            tokio::net::TcpStream::connect(server_addr),
        )
        .await
        .map_err(|_| {
            eyre::eyre!(
                "SOCKS4 TCP connect timed out after {}s",
                handshake_timeout.as_secs()
            )
        })??;
        let domain_sni = config
            .reality
            .as_ref()
            .map(|r| r.server_name.clone())
            .unwrap_or_else(|| "apple.com".into());
        let mut tls_stream = {
            let _reality_handshake_guard = reality_handshake_lock().lock().await;
            let (tcp_tls_config, reality_cert_state) = build_tls_config(&config)?;
            if let Some(state) = &reality_cert_state {
                state.reset();
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tcp_tls_config));
            let server_name =
                rustls::pki_types::ServerName::try_from(domain_sni.as_str())?.to_owned();
            let mut tls_stream = tokio::time::timeout(
                handshake_timeout,
                connector.connect(server_name, tcp_stream),
            )
            .await
            .map_err(|_| {
                eyre::eyre!(
                    "SOCKS4 TLS handshake timed out after {}s",
                    handshake_timeout.as_secs()
                )
            })??;

            if reality_cert_state
                .as_ref()
                .map(RealityCertState::saw_real_certificate)
                .unwrap_or(false)
            {
                warn!(
                    "SOCKS4 REALITY received real certificate for {}; entering spider mode",
                    domain_sni
                );
                let spider_x = config
                    .reality
                    .as_ref()
                    .and_then(|r| r.spider_x.as_deref())
                    .unwrap_or("/");
                let _ = run_reality_spider(&mut tls_stream, &domain_sni, spider_x).await;
                stream
                    .write_all(&[0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
                return Err(eyre::eyre!(
                    "REALITY rejected as real-site certificate; spider mode triggered"
                ));
            }

            tls_stream
        };

        // Authenticate
        let uuid = config.uuid;
        let model = seacore_protocol::model::Connection::<Vec<u8>>::new();
        let auth_data = model.send_authenticate(uuid, &config.password, None::<&NoExporter>);
        let header = seacore_protocol::protocol::Header::Authenticate(auth_data);
        header.async_marshal(&mut tls_stream).await?;

        // Connect
        let conn_data = model.send_connect(addr.clone());
        let header_conn = seacore_protocol::protocol::Header::Connect(conn_data);
        header_conn.async_marshal(&mut tls_stream).await?;

        info!("SOCKS4 TCP Fallback: {} -> {}", peer_addr, addr);

        // Reply: Granted
        stream
            .write_all(&[0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;

        if let Err(e) = relay_until_either_side_finishes(
            stream,
            tls_stream,
            connection_idle_timeout,
            half_close_timeout,
        )
        .await
        {
            log_relay_error("SOCKS4 TCP relay error", peer_addr, e);
        }
    } else {
        // QUIC mode
        match conn.connect(addr.clone()).await {
            Ok(bistream) => {
                info!("SOCKS4 QUIC: {} -> {}", peer_addr, addr);
                // Reply: Granted
                stream
                    .write_all(&[0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;

                if let Err(e) = relay_until_either_side_finishes(
                    stream,
                    bistream,
                    connection_idle_timeout,
                    half_close_timeout,
                )
                .await
                {
                    log_relay_error("SOCKS4 QUIC relay error", peer_addr, e);
                }
            }
            Err(e) => {
                warn!("SOCKS4 QUIC connection failed for {}: {}", addr, e);
                stream
                    .write_all(&[0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
            }
        }
    }

    Ok(())
}

async fn handle_socks5_logic(
    mut stream: tokio::net::TcpStream,
    conn: Connection<side::Client>,
    peer_addr: SocketAddr,
    udp_routes: UdpRoutes,
    udp_route_touches: UdpRouteTouches,
    idle_policy: Arc<IdleSessionPolicy>,
    session_policy: Arc<SessionGovernancePolicy>,
    config: Arc<ClientConfig>,
) -> Result<()> {
    // ── SOCKS5 handshake ──────────────────────────
    let mut buf = [0u8; 258];

    // Read method count (we already read version 0x05)
    stream.read_exact(&mut buf[..1]).await?;
    let nmethods = buf[0] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    // Reply: no authentication required
    stream.write_all(&[0x05, 0x00]).await?;

    // Read connect request
    stream.read_exact(&mut buf[..4]).await?;
    let cmd = buf[1];
    if buf[0] != 0x05 || (cmd != 0x01 && cmd != 0x03) {
        // Only CONNECT and UDP ASSOCIATE supported
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(eyre::eyre!("unsupported SOCKS5 command: {}", buf[1]));
    }

    let addr = match buf[3] {
        0x01 => {
            // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Address::SocketAddress(SocketAddr::from((ip, port)))
        }
        0x03 => {
            // Domain
            stream.read_exact(&mut buf[..1]).await?;
            let domain_len = buf[0] as usize;
            stream.read_exact(&mut buf[..domain_len + 2]).await?;
            let domain = String::from_utf8_lossy(&buf[..domain_len]).to_string();
            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);
            Address::DomainAddress(domain, port)
        }
        0x04 => {
            // IPv6
            stream.read_exact(&mut buf[..18]).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Address::SocketAddress(SocketAddr::from((ip, port)))
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(eyre::eyre!("unsupported address type: {}", buf[3]));
        }
    };

    if cmd == 0x03 {
        // UDP ASSOCIATE
        let current_udp_assocs = udp_routes.lock().await.len();
        let udp_assoc_limit = config
            .max_udp_associations
            .unwrap_or(DEFAULT_MAX_UDP_ASSOCIATIONS)
            .max(1);
        if current_udp_assocs >= udp_assoc_limit {
            warn!(
                "Rejecting UDP ASSOCIATE for {} because max_udp_associations={} was reached",
                peer_addr, udp_assoc_limit
            );
            stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(eyre::eyre!(
                "udp association limit reached ({})",
                udp_assoc_limit
            ));
        }

        let local_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let bind_addr = local_socket.local_addr()?;

        let mut reply = vec![0x05, 0x00, 0x00];
        match bind_addr {
            SocketAddr::V4(v4) => {
                reply.push(0x01);
                reply.extend_from_slice(&v4.ip().octets());
                reply.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                reply.push(0x04);
                reply.extend_from_slice(&v6.ip().octets());
                reply.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        stream.write_all(&reply).await?;

        // SOCKS5 UDP ASSOCIATE keeps this TCP control channel open.
        // If it is closed by upstream (e.g. Xray/browser), we must tear
        // down the UDP route promptly; otherwise stale routes accumulate.
        let (mut ctrl_read, _) = stream.into_split();
        let (ctrl_closed_tx, mut ctrl_closed_rx) = tokio::sync::watch::channel(false);
        let ctrl_watch_task = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            loop {
                match ctrl_read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = ctrl_closed_tx.send(true);
                        break;
                    }
                    Ok(_) => {
                        // Ignore unexpected control bytes and keep waiting for closure.
                    }
                    Err(_) => {
                        let _ = ctrl_closed_tx.send(true);
                        break;
                    }
                }
            }
        });

        let assoc_id = NEXT_ASSOC_ID.fetch_add(1, Ordering::SeqCst);
        let (tx, mut rx) = mpsc::channel(1024);
        udp_routes.lock().await.insert(assoc_id, tx);
        udp_route_touches
            .lock()
            .await
            .insert(assoc_id, Instant::now());

        let socket_arc = Arc::new(local_socket);
        let socket_recv = socket_arc.clone();

        let client_udp_addr = Arc::new(Mutex::new(None));
        let upload_client_addr = client_udp_addr.clone();
        let route_touches_upload = udp_route_touches.clone();

        let client_conn = conn.clone();
        // Task to read UDP from client and send over QUIC
        let upload_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket_recv.recv_from(&mut buf).await {
                    Ok((n, client_addr)) => {
                        *upload_client_addr.lock().await = Some(client_addr);
                        route_touches_upload
                            .lock()
                            .await
                            .insert(assoc_id, Instant::now());
                        let data = &buf[..n];
                        // Parse SOCKS5 UDP header
                        if data.len() < 10 || data[0] != 0 || data[1] != 0 {
                            continue; // Drop fragmented or invalid SOCKS5 UDP
                        }
                        let frag = data[2];
                        if frag != 0 {
                            continue; // We dont support SOCKS UDP fragmentation
                        }

                        let atyp = data[3];
                        let (dest_addr, payload_idx) = match atyp {
                            0x01 if data.len() >= 10 => {
                                let ip =
                                    std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                                let port = u16::from_be_bytes([data[8], data[9]]);
                                (Address::SocketAddress(SocketAddr::from((ip, port))), 10)
                            }
                            0x03 if data.len() >= 5 => {
                                let domain_len = data[4] as usize;
                                if data.len() >= 5 + domain_len + 2 {
                                    let domain = String::from_utf8_lossy(&data[5..5 + domain_len])
                                        .to_string();
                                    let port = u16::from_be_bytes([
                                        data[5 + domain_len],
                                        data[6 + domain_len],
                                    ]);
                                    (Address::DomainAddress(domain, port), 5 + domain_len + 2)
                                } else {
                                    continue;
                                }
                            }
                            0x04 if data.len() >= 22 => {
                                let mut ip_bytes = [0u8; 16];
                                ip_bytes.copy_from_slice(&data[4..20]);
                                let ip = std::net::Ipv6Addr::from(ip_bytes);
                                let port = u16::from_be_bytes([data[20], data[21]]);
                                (Address::SocketAddress(SocketAddr::from((ip, port))), 22)
                            }
                            _ => continue,
                        };

                        let payload = &data[payload_idx..];
                        // Send over QUIC/TCP-native transport.
                        if let Err(e) = client_conn
                            .packet_native(payload, dest_addr, assoc_id)
                            .await
                        {
                            debug!(
                                "UDP upstream send failed for assoc {} ({}): {}",
                                assoc_id, peer_addr, e
                            );
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Loop to receive from SeaCore and send back to SOCKS client.
        // Also stop on control-channel close or route idle timeout.
        let udp_assoc_idle_timeout = idle_policy.timeout;
        loop {
            tokio::select! {
                _ = ctrl_closed_rx.changed() => {
                    break;
                }
                maybe_item = tokio::time::timeout(udp_assoc_idle_timeout, rx.recv()) => {
                    let Some((payload, source_addr)) = (match maybe_item {
                        Ok(item) => item,
                        Err(_) => {
                            // Idle for too long, clean up this association.
                            debug!("UDP ASSOCIATE {} for {} hit idle timeout", assoc_id, peer_addr);
                            break;
                        }
                    }) else {
                        break;
                    };

                    // Build SOCKS5 UDP response header
                    let mut pkt = vec![0x00, 0x00, 0x00];
                    match source_addr {
                        Address::SocketAddress(SocketAddr::V4(v4)) => {
                            pkt.push(0x01);
                            pkt.extend_from_slice(&v4.ip().octets());
                            pkt.extend_from_slice(&v4.port().to_be_bytes());
                        }
                        Address::SocketAddress(SocketAddr::V6(v6)) => {
                            pkt.push(0x04);
                            pkt.extend_from_slice(&v6.ip().octets());
                            pkt.extend_from_slice(&v6.port().to_be_bytes());
                        }
                        Address::DomainAddress(domain, port) => {
                            pkt.push(0x03);
                            pkt.push(domain.len() as u8);
                            pkt.extend_from_slice(domain.as_bytes());
                            pkt.extend_from_slice(&port.to_be_bytes());
                        }
                        Address::None => continue,
                    }
                    pkt.extend_from_slice(&payload);

                    if let Some(caddr) = *client_udp_addr.lock().await {
                        udp_route_touches.lock().await.insert(assoc_id, Instant::now());
                        let _ = socket_arc.send_to(&pkt, caddr).await;
                    }
                }
            }
        }

        upload_task.abort();
        ctrl_watch_task.abort();
        let _ = conn.dissociate(assoc_id).await;
        udp_routes.lock().await.remove(&assoc_id);
        udp_route_touches.lock().await.remove(&assoc_id);

        return Ok(());
    }

    info!("SOCKS5 TCP connect {} -> {}", peer_addr, addr);

    let transport_mode = config.transport.as_deref().unwrap_or("auto").to_lowercase();

    let remote = if transport_mode == "tcp" {
        // --- Phase 19/15: 1:1 Transparent TCP TLS Fallback ---
        let server_addr = config.server;
        let tcp_stream = tokio::time::timeout(
            session_policy.handshake_timeout,
            tokio::net::TcpStream::connect(server_addr),
        )
        .await
        .map_err(|_| {
            eyre::eyre!(
                "SOCKS5 TCP connect timed out after {}s",
                session_policy.handshake_timeout.as_secs()
            )
        })??;

        let domain = config
            .reality
            .as_ref()
            .map(|r| r.server_name.clone())
            .unwrap_or_else(|| "apple.com".into());
        // 1. Establish TLS with Reality Tokens
        let mut tls_stream = {
            let _reality_handshake_guard = reality_handshake_lock().lock().await;
            let (tcp_tls_config, reality_cert_state) = build_tls_config(&config)?;
            if let Some(state) = &reality_cert_state {
                state.reset();
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tcp_tls_config));
            let server_name = rustls::pki_types::ServerName::try_from(domain.as_str())?.to_owned();
            let mut tls_stream = tokio::time::timeout(
                session_policy.handshake_timeout,
                connector.connect(server_name, tcp_stream),
            )
            .await
            .map_err(|_| {
                eyre::eyre!(
                    "SOCKS5 TLS handshake timed out after {}s",
                    session_policy.handshake_timeout.as_secs()
                )
            })??;

            if reality_cert_state
                .as_ref()
                .map(RealityCertState::saw_real_certificate)
                .unwrap_or(false)
            {
                warn!(
                    "SOCKS5 REALITY received real certificate for {}; entering spider mode",
                    domain
                );
                let spider_x = config
                    .reality
                    .as_ref()
                    .and_then(|r| r.spider_x.as_deref())
                    .unwrap_or("/");
                let _ = run_reality_spider(&mut tls_stream, &domain, spider_x).await;
                stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Err(eyre::eyre!(
                    "REALITY rejected as real-site certificate; spider mode triggered"
                ));
            }

            tls_stream
        };

        // 2. Send Authenticate Command manually over the raw TLS stream
        let uuid = config.uuid;
        let model = seacore_protocol::model::Connection::<Vec<u8>>::new();
        let auth_data = model.send_authenticate(uuid, &config.password, None::<&NoExporter>);
        let header = seacore_protocol::protocol::Header::Authenticate(auth_data);
        header.async_marshal(&mut tls_stream).await?;

        // 3. Send Connect Command
        let conn_data = model.send_connect(addr.clone());
        let header_conn = seacore_protocol::protocol::Header::Connect(conn_data);
        header_conn.async_marshal(&mut tls_stream).await?;

        info!("SOCKS5 TCP Fallback: {} -> {}", peer_addr, addr);

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        if let Err(e) = relay_until_either_side_finishes(
            stream,
            tls_stream,
            session_policy.connection_idle_timeout,
            session_policy.half_close_timeout,
        )
        .await
        {
            log_relay_error("SOCKS5 TCP relay error", peer_addr, e);
        }
        return Ok(());
    } else {
        // Open SeaCore Connect stream (QUIC multiplexed)
        match conn.connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Err(eyre::eyre!("SeaCore connect failed: {}", e));
            }
        }
    };

    // SOCKS5 success reply
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    if let Err(e) = relay_until_either_side_finishes(
        stream,
        remote,
        session_policy.connection_idle_timeout,
        session_policy.half_close_timeout,
    )
    .await
    {
        log_relay_error("SOCKS5 QUIC relay error", peer_addr, e);
    }

    Ok(())
}

fn parse_cert_sha256_pin(raw: &str) -> Result<[u8; 32]> {
    let normalized: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (idx, byte) in out.iter_mut().enumerate() {
            let hi = normalized
                .as_bytes()
                .get(idx * 2)
                .ok_or_else(|| eyre::eyre!("invalid pin length"))?;
            let lo = normalized
                .as_bytes()
                .get(idx * 2 + 1)
                .ok_or_else(|| eyre::eyre!("invalid pin length"))?;

            let pair = [*hi as char, *lo as char];
            let byte_str: String = pair.iter().collect();
            *byte = u8::from_str_radix(&byte_str, 16)
                .map_err(|_| eyre::eyre!("invalid hex in server_cert_sha256"))?;
        }
        return Ok(out);
    }

    use base64::{engine::general_purpose, Engine as _};
    let decoded = general_purpose::STANDARD
        .decode(&normalized)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(&normalized))
        .or_else(|_| general_purpose::URL_SAFE.decode(&normalized))
        .map_err(|_| {
            eyre::eyre!(
                "invalid server_cert_sha256 format (expected 64-char hex or base64-encoded SHA-256)"
            )
        })?;

    if decoded.len() != 32 {
        return Err(eyre::eyre!(
            "invalid server_cert_sha256 length {}, expected 32 bytes",
            decoded.len()
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[derive(Debug)]
struct SeaCoreServerVerifier {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    allow_invalid_cert_chain: bool,
    pinned_sha256: Option<[u8; 32]>,
    reality_mode: bool,
    reality_expected_cert_proof: Option<[u8; 32]>,
    reality_cert_state: Option<RealityCertState>,
}

fn extract_reality_temp_cert_proof(cert_der: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    cert.extensions()
        .iter()
        .find(|ext| {
            ext.oid.to_id_string() == seacore_protocol::reality::REALITY_TEMP_CERT_PROOF_OID_STR
        })
        .map(|ext| ext.value.to_vec())
}

impl SeaCoreServerVerifier {
    fn verify_pin(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        if let Some(expected_pin) = self.pinned_sha256 {
            let actual = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
            if actual.as_ref() != expected_pin.as_slice() {
                return Err(rustls::Error::General(
                    "server certificate SHA-256 pin mismatch".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl rustls::client::danger::ServerCertVerifier for SeaCoreServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.reality_mode {
            if let Some(expected_proof) = self.reality_expected_cert_proof {
                if let Some(actual_proof) = extract_reality_temp_cert_proof(end_entity.as_ref()) {
                    if actual_proof.as_slice() == &expected_proof {
                        if let Some(state) = &self.reality_cert_state {
                            state.mark(RealityCertDecision::TemporaryTrusted);
                        }
                        self.verify_pin(end_entity)?;
                        return Ok(rustls::client::danger::ServerCertVerified::assertion());
                    }
                }
            }

            let webpki_result = rustls::client::danger::ServerCertVerifier::verify_server_cert(
                self.webpki.as_ref(),
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
            if webpki_result.is_ok() {
                if let Some(state) = &self.reality_cert_state {
                    state.mark(RealityCertDecision::RealCertificate);
                }
                self.verify_pin(end_entity)?;
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }

            if self.allow_invalid_cert_chain {
                if let Some(state) = &self.reality_cert_state {
                    state.mark(RealityCertDecision::LegacyAccepted);
                }
                self.verify_pin(end_entity)?;
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }

            if let Some(state) = &self.reality_cert_state {
                state.mark(RealityCertDecision::Invalid);
            }
            return Err(rustls::Error::General(
                "REALITY certificate verification failed".to_string(),
            ));
        }

        if !self.allow_invalid_cert_chain {
            rustls::client::danger::ServerCertVerifier::verify_server_cert(
                self.webpki.as_ref(),
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        self.verify_pin(end_entity)?;

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::client::danger::ServerCertVerifier::verify_tls12_signature(
            self.webpki.as_ref(),
            message,
            cert,
            dss,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::client::danger::ServerCertVerifier::verify_tls13_signature(
            self.webpki.as_ref(),
            message,
            cert,
            dss,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::client::danger::ServerCertVerifier::supported_verify_schemes(self.webpki.as_ref())
    }
}

// --- Dummy Exporter for TCP Fallback ---
struct NoExporter;
impl seacore_protocol::model::KeyingMaterialExporter for NoExporter {
    fn export_keying_material(&self, _label: &[u8], _context: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }
}

// --- Custom X25519 Key Exchange ---

struct CustomX25519Group;

impl core::fmt::Debug for CustomX25519Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CustomX25519Group").finish()
    }
}

impl SupportedKxGroup for CustomX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = current_reality_client_secret();
        let pub_key = PublicKey::from(&secret);
        Ok(Box::new(CustomActiveKeyExchange {
            secret,
            pub_key: pub_key.to_bytes().to_vec(),
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct CustomActiveKeyExchange {
    secret: StaticSecret,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for CustomActiveKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        if peer_pub_key.len() != 32 {
            return Err(rustls::Error::General(
                "Invalid peer key length".to_string(),
            ));
        }
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(&peer_pub_key[..32]);
        let peer_key = PublicKey::from(peer_bytes);

        // ECDH with Server's Ephemeral Key
        let shared = self.secret.diffie_hellman(&peer_key);
        Ok(SharedSecret::from(shared.as_bytes().as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_varint(buf: &[u8], offset: &mut usize) -> u64 {
        let first = buf[*offset];
        let prefix = first >> 6;
        let len = match prefix {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };

        let mut value = (first & 0x3f) as u64;
        for i in 1..len {
            value = (value << 8) | (buf[*offset + i] as u64);
        }
        *offset += len;
        value
    }

    #[test]
    fn quic_varint_encoding_regression() {
        let mut out = Vec::new();
        encode_quic_varint(0, &mut out);
        encode_quic_varint(63, &mut out);
        encode_quic_varint(64, &mut out);
        encode_quic_varint(16_383, &mut out);
        encode_quic_varint(262_144, &mut out);

        let mut off = 0;
        assert_eq!(decode_varint(&out, &mut off), 0);
        assert_eq!(decode_varint(&out, &mut off), 63);
        assert_eq!(decode_varint(&out, &mut off), 64);
        assert_eq!(decode_varint(&out, &mut off), 16_383);
        assert_eq!(decode_varint(&out, &mut off), 262_144);
    }

    #[test]
    fn h3_control_payload_has_expected_settings_shape() {
        let payload = build_h3_control_stream_payload();
        let mut off = 0;

        let stream_type = decode_varint(&payload, &mut off);
        assert_eq!(stream_type, 0x00);

        let frame_type = decode_varint(&payload, &mut off);
        assert_eq!(frame_type, 0x04);

        let frame_len = decode_varint(&payload, &mut off) as usize;
        assert_eq!(frame_len, payload.len() - off);

        let mut setting_ids = Vec::new();
        let end = off + frame_len;
        while off < end {
            let setting_id = decode_varint(&payload, &mut off);
            let _setting_value = decode_varint(&payload, &mut off);
            setting_ids.push(setting_id);
        }

        assert!(setting_ids.contains(&0x01)); // QPACK_MAX_TABLE_CAPACITY
        assert!(setting_ids.contains(&0x06)); // MAX_FIELD_SECTION_SIZE
        assert!(setting_ids.contains(&0x07)); // QPACK_BLOCKED_STREAMS
        assert!(setting_ids.contains(&0x33)); // H3_DATAGRAM
    }

    #[test]
    fn spider_path_normalization() {
        assert_eq!(normalize_spider_path(""), "/");
        assert_eq!(normalize_spider_path("/"), "/");
        assert_eq!(normalize_spider_path("status"), "/status");
        assert_eq!(normalize_spider_path("/status"), "/status");
    }

    #[test]
    fn extract_reality_proof_extension_roundtrip() {
        let expected = vec![0xAB; 32];
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()])
            .expect("certificate params");
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                seacore_protocol::reality::REALITY_TEMP_CERT_PROOF_OID,
                expected.clone(),
            ));

        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self-signed cert");
        let extracted = extract_reality_temp_cert_proof(cert.der().as_ref())
            .expect("reality proof extension should exist");

        assert_eq!(extracted, expected);
    }
}
