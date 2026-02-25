use std::cmp::Reverse;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, Semaphore};

use eyre::Result;
use quinn::Endpoint;
use serde::Deserialize;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use seacore_protocol::protocol::Address;
use seacore_protocol::quic::{side, Connection, Task};
use seacore_protocol::reality::{
    derive_temp_cert_proof, parse_short_id_hex, REALITY_TEMP_CERT_PROOF_OID,
};

use crate::auth_limit::AuthRateLimiter;
use crate::metrics::ServerMetrics;
use crate::session_policy::SessionGovernancePolicy;

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub users: Vec<UserConfig>,
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
    pub max_quic_connections: Option<usize>,
    pub max_tcp_connections: Option<usize>,
    pub max_udp_associations_per_connection: Option<usize>,
    pub max_bi_stream_tasks_per_connection: Option<usize>,
    pub metrics_listen: Option<SocketAddr>,
    pub reality: Option<RealityServerSettings>,
}

#[derive(Deserialize, Clone)]
pub struct UserConfig {
    pub uuid: Uuid,
    pub password: String,
}

#[derive(Deserialize, Clone)]
pub struct RealityServerSettings {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
}

#[derive(Clone)]
struct IdleSessionPolicy {
    check_interval: Duration,
    timeout: Duration,
    min_idle_sessions: usize,
}

fn idle_session_policy_from_server_config(config: &ServerConfig) -> IdleSessionPolicy {
    let check_secs = config.idle_session_check_interval_secs.unwrap_or(5).max(1);
    let timeout_secs = config.idle_session_timeout_secs.unwrap_or(10).max(2);
    let min_idle_sessions = config.min_idle_sessions.unwrap_or(0);

    IdleSessionPolicy {
        check_interval: Duration::from_secs(check_secs),
        timeout: Duration::from_secs(timeout_secs),
        min_idle_sessions,
    }
}

const DEFAULT_MAX_QUIC_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_TCP_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_UDP_ASSOCIATIONS_PER_CONNECTION: usize = 1024;
const DEFAULT_MAX_BI_STREAM_TASKS_PER_CONNECTION: usize = 256;

/// Cache of recently seen REALITY auth tokens for replay protection.
/// Tokens are valid for ±30s, so we evict entries older than 120s.
struct ReplayCache {
    seen: HashMap<[u8; 32], Instant>,
}

impl ReplayCache {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    fn check_and_insert(&mut self, token: [u8; 32]) -> bool {
        self.evict_stale();
        if self.seen.contains_key(&token) {
            true
        } else {
            self.seen.insert(token, Instant::now());
            false
        }
    }

    fn evict_stale(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(120);
        self.seen.retain(|_, ts| *ts > cutoff);
    }
}

// Wrap a TcpStream with bytes already consumed from it (e.g. handshake sniffing).
// Reads drain `prefix` first, then continue from `inner`.
struct PrefixedTcpStream {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: tokio::net::TcpStream,
}

impl PrefixedTcpStream {
    fn new(prefix: Vec<u8>, inner: tokio::net::TcpStream) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let total_len = self.prefix.get_ref().len();
        let pos = self.prefix.position() as usize;
        if pos < total_len && buf.remaining() > 0 {
            let remain = &self.prefix.get_ref()[pos..];
            let take = remain.len().min(buf.remaining());
            buf.put_slice(&remain[..take]);
            self.prefix.set_position((pos + take) as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn build_reality_temporary_tls_config(
    server_name: &str,
    shared_secret: &[u8; 32],
    session_token: &[u8; 32],
) -> Result<rustls::ServerConfig> {
    let mut params = rcgen::CertificateParams::new(vec![server_name.to_string()])?;
    let proof = derive_temp_cert_proof(shared_secret, session_token, server_name);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            REALITY_TEMP_CERT_PROOF_OID,
            proof.to_vec(),
        ));

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| eyre::eyre!("failed to parse temporary reality private key: {}", e))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_crypto)
}

pub async fn run_server(config_path: &str) -> Result<()> {
    // Load config
    let config_str = fs::read_to_string(config_path)?;
    let config: ServerConfig = serde_json::from_str(&config_str)?;
    let idle_policy = Arc::new(idle_session_policy_from_server_config(&config));
    let session_policy = Arc::new(SessionGovernancePolicy::from_config(
        config.handshake_timeout_secs,
        config.connection_idle_timeout_secs,
        config.max_idle_time_secs,
        config.half_close_timeout_secs,
    ));
    let max_quic_connections = config
        .max_quic_connections
        .unwrap_or(DEFAULT_MAX_QUIC_CONNECTIONS)
        .max(1);
    let max_tcp_connections = config
        .max_tcp_connections
        .unwrap_or(DEFAULT_MAX_TCP_CONNECTIONS)
        .max(1);
    let max_udp_associations_per_connection = config
        .max_udp_associations_per_connection
        .unwrap_or(DEFAULT_MAX_UDP_ASSOCIATIONS_PER_CONNECTION)
        .max(1);
    let max_bi_stream_tasks_per_connection = config
        .max_bi_stream_tasks_per_connection
        .unwrap_or(DEFAULT_MAX_BI_STREAM_TASKS_PER_CONNECTION)
        .max(1);

    info!("Listening on {}", config.listen);
    info!("Loaded {} user(s)", config.users.len());
    info!(
        "Idle session policy: check={}s timeout={}s min_idle={}",
        idle_policy.check_interval.as_secs(),
        idle_policy.timeout.as_secs(),
        idle_policy.min_idle_sessions
    );
    info!(
        "Limits: quic_conn={} tcp_conn={} udp_assoc_per_conn={} bi_tasks_per_conn={}",
        max_quic_connections,
        max_tcp_connections,
        max_udp_associations_per_connection,
        max_bi_stream_tasks_per_connection
    );
    info!(
        "Session governance: handshake={}s conn_idle={}s half_close={}s",
        session_policy.handshake_timeout.as_secs(),
        session_policy.connection_idle_timeout.as_secs(),
        session_policy.half_close_timeout.as_secs()
    );

    let metrics = Arc::new(ServerMetrics::default());
    if let Some(metrics_listen) = config.metrics_listen {
        crate::metrics::spawn_server_exporter(metrics_listen, metrics.clone());
    }

    // Generate certificate. In Reality, we borrow the certificate of the dest host.
    // Here we generate a self-signed one with the borrowed names.
    let server_names = if let Some(reality) = &config.reality {
        reality.server_names.clone()
    } else {
        vec!["localhost".into()]
    };

    let cert = rcgen::generate_simple_self_signed(server_names)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| eyre::eyre!("failed to parse private key: {}", e))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let mut transport_config = quinn::TransportConfig::default();

    // --- Mirror Chrome Transport Parameters on server side ---
    transport_config.receive_window(quinn::VarInt::from_u32(15728640));
    transport_config.send_window(15728640);
    transport_config.stream_receive_window(quinn::VarInt::from_u32(6291456));
    transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
    transport_config.max_concurrent_uni_streams(quinn::VarInt::from_u32(100));
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.min_mtu(1200);
    // Note: quinn 0.11 enables grease_quic_bit by default (RFC 9287)

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

    server_config.transport_config(Arc::new(transport_config));

    let endpoint = if let Some(reality) = &config.reality {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut server_priv_key = [0u8; 32];
        let priv_b64 = reality.private_key.as_str();
        if let Ok(decoded) = STANDARD.decode(priv_b64) {
            if decoded.len() == 32 {
                server_priv_key.copy_from_slice(&decoded);
            } else {
                warn!("Reality private_key must be 32 bytes. Routing will fail.");
            }
        } else {
            warn!("Failed to decode Reality private_key as base64.");
        }

        let quinn_listen_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let endpoint = Endpoint::server(server_config, quinn_listen_addr)?;
        let actual_quinn_addr = endpoint.local_addr()?;

        // Resolve fallback addr
        let fallback_str = &reality.dest;
        let mut fallback_addrs = tokio::net::lookup_host(fallback_str).await?;
        let fallback_addr = fallback_addrs
            .next()
            .unwrap_or_else(|| "127.0.0.1:443".parse().expect("constant socket addr"));

        let short_ids: Vec<[u8; 8]> = reality
            .short_ids
            .iter()
            .map(|raw| {
                parse_short_id_hex(raw)
                    .map_err(|e| eyre::eyre!("invalid reality.short_ids entry '{}': {}", raw, e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let server_names = reality.server_names.clone();

        let router = crate::router::QuicRouter::new(
            config.listen,
            actual_quinn_addr,
            fallback_addr,
            server_priv_key,
            config.users.clone(),
            short_ids.clone(),
            server_names,
        )
        .await?;

        tokio::spawn(async move {
            if let Err(e) = router.run().await {
                error!("Router error: {}", e);
            }
        });

        // --- Phase 19: TCP REALITY Proxy Channel & Fallback ---
        let tcp_listen_addr = config.listen;
        let dest_str = reality.dest.clone();

        let mut server_priv_key_copy = [0u8; 32];
        let priv_b64 = reality.private_key.as_str();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(priv_b64) {
            if decoded.len() == 32 {
                server_priv_key_copy.copy_from_slice(&decoded);
            }
        }
        let users_clone = config.users.clone();
        let short_ids_clone = short_ids.clone();
        let server_names_clone = reality.server_names.clone();

        let config_clone_for_tcp = config.clone();
        let idle_policy_clone_for_tcp = idle_policy.clone();
        let session_policy_clone_for_tcp = session_policy.clone();
        let tcp_connection_limiter = Arc::new(Semaphore::new(max_tcp_connections));
        let tcp_replay_cache = Arc::new(Mutex::new(ReplayCache::new()));
        let tcp_auth_limiter = Arc::new(Mutex::new(AuthRateLimiter::default()));
        let server_metrics = metrics.clone();

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(tcp_listen_addr).await {
                Ok(listener) => {
                    info!("TCP REALITY Listener bound to {}", tcp_listen_addr);
                    loop {
                        match listener.accept().await {
                            Ok((client_stream, client_addr)) => {
                                let permit = match tcp_connection_limiter
                                    .clone()
                                    .try_acquire_owned()
                                {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        warn!(
                                            "Dropping TCP REALITY connection from {} because max_tcp_connections={} was reached",
                                            client_addr,
                                            max_tcp_connections
                                        );
                                        continue;
                                    }
                                };
                                let dest = dest_str.clone();
                                let priv_key = server_priv_key_copy.clone();
                                let users = users_clone.clone();
                                let s_ids = short_ids_clone.clone();
                                let s_names = server_names_clone.clone();
                                let config_inner = config_clone_for_tcp.clone();
                                let idle_policy_inner = idle_policy_clone_for_tcp.clone();
                                let session_policy_inner = session_policy_clone_for_tcp.clone();
                                let tcp_replay_cache_inner = tcp_replay_cache.clone();
                                let tcp_auth_limiter_inner = tcp_auth_limiter.clone();
                                let server_metrics_inner = server_metrics.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    // Read initial bytes once (event-driven, no spin/peek polling).
                                    // We keep consumed bytes and replay them into TLS acceptor/fallback.
                                    let mut client_stream = client_stream;
                                    let mut sniffed = Vec::with_capacity(4096);
                                    let mut chunk = [0u8; 4096];
                                    let mut need_len = 5usize;
                                    let mut is_tls_handshake = false;
                                    let deadline = std::time::Instant::now()
                                        + session_policy_inner.handshake_timeout;

                                    loop {
                                        if sniffed.len() >= need_len || sniffed.len() >= 20000 {
                                            break;
                                        }
                                        let now = std::time::Instant::now();
                                        if now >= deadline {
                                            break;
                                        }
                                        let remain = deadline.saturating_duration_since(now);
                                        let n = match tokio::time::timeout(
                                            remain,
                                            client_stream.read(&mut chunk),
                                        )
                                        .await
                                        {
                                            Ok(Ok(n)) => n,
                                            _ => break,
                                        };
                                        if n == 0 {
                                            break;
                                        }
                                        sniffed.extend_from_slice(&chunk[..n]);

                                        if sniffed.len() >= 5 {
                                            if sniffed[0] == 0x16 {
                                                is_tls_handshake = true;
                                                let record_len =
                                                    u16::from_be_bytes([sniffed[3], sniffed[4]])
                                                        as usize;
                                                let total = 5 + record_len;
                                                if total <= 20000 {
                                                    need_len = total;
                                                } else {
                                                    break;
                                                }
                                            } else {
                                                // Not TLS handshake traffic; route to fallback directly.
                                                break;
                                            }
                                        }
                                    }

                                    if sniffed.is_empty() {
                                        return;
                                    }

                                    server_metrics_inner.inc_reality_request();

                                    let auth_context = if is_tls_handshake {
                                        crate::sniffer::verify_tcp_reality_auth(
                                            &sniffed, &priv_key, &users, &s_ids, &s_names,
                                        )
                                    } else {
                                        None
                                    };

                                    let is_authenticated = if let Some(auth) = auth_context.as_ref()
                                    {
                                        let mut replay_cache = tcp_replay_cache_inner.lock().await;
                                        if replay_cache.check_and_insert(auth.token) {
                                            warn!(
                                                "TCP replay attack detected from {}, rejecting",
                                                client_addr
                                            );
                                            false
                                        } else {
                                            true
                                        }
                                    } else {
                                        false
                                    };
                                    server_metrics_inner.record_auth_attempt(is_authenticated);

                                    let auth_delay = {
                                        let mut limiter = tcp_auth_limiter_inner.lock().await;
                                        limiter
                                            .delay_for_attempt(client_addr.ip(), is_authenticated)
                                    };
                                    if !auth_delay.is_zero() {
                                        tokio::time::sleep(auth_delay).await;
                                    }

                                    let wrapped_stream =
                                        PrefixedTcpStream::new(sniffed, client_stream);

                                    if is_authenticated {
                                        debug!("TCP REALITY auth accepted for {}", client_addr);
                                        let Some(auth) = auth_context.as_ref() else {
                                            warn!(
                                                "TCP REALITY auth context missing for {}",
                                                client_addr
                                            );
                                            return;
                                        };

                                        let cert_name = auth
                                            .sni
                                            .as_deref()
                                            .filter(|name| {
                                                s_names.iter().any(|allowed| allowed == *name)
                                            })
                                            .or_else(|| s_names.first().map(|s| s.as_str()))
                                            .unwrap_or("localhost")
                                            .to_string();

                                        let server_crypto_inner =
                                            match build_reality_temporary_tls_config(
                                                &cert_name,
                                                &auth.shared_secret,
                                                &auth.token,
                                            ) {
                                                Ok(cfg) => cfg,
                                                Err(e) => {
                                                    warn!(
                                                        "Failed to build temporary REALITY certificate for {}: {}",
                                                        client_addr,
                                                        e
                                                    );
                                                    return;
                                                }
                                            };

                                        let acceptor = tokio_rustls::TlsAcceptor::from(
                                            std::sync::Arc::new(server_crypto_inner),
                                        );
                                        match tokio::time::timeout(
                                            session_policy_inner.handshake_timeout,
                                            acceptor.accept(wrapped_stream),
                                        )
                                        .await
                                        {
                                            Ok(Ok(tls_stream)) => {
                                                let (r, w) = tokio::io::split(tls_stream);
                                                let inner = seacore_protocol::quic::InnerConn::Tcp(
                                                    std::sync::Arc::new(tokio::sync::Mutex::new(
                                                        Box::new(w),
                                                    )),
                                                );
                                                let seacore_conn =
                                                    seacore_protocol::quic::Connection::<
                                                        seacore_protocol::quic::side::Server,
                                                    >::new(
                                                        inner
                                                    );
                                                let config_for_tcp = config_inner;
                                                let max_udp_assocs =
                                                    max_udp_associations_per_connection;
                                                let session_policy_for_tcp =
                                                    session_policy_inner.clone();

                                                tokio::spawn(async move {
                                                    if let Err(e) = handle_tcp_connection(
                                                        seacore_conn,
                                                        Box::new(r),
                                                        config_for_tcp,
                                                        idle_policy_inner.clone(),
                                                        session_policy_for_tcp,
                                                        max_udp_assocs,
                                                        server_metrics_inner.clone(),
                                                    )
                                                    .await
                                                    {
                                                        warn!("TCP connection error handling failed: {}", e);
                                                    }
                                                });
                                            }
                                            Ok(Err(e)) => {
                                                warn!(
                                                    "TCP REALITY Server TLS Accept failed: {}",
                                                    e
                                                );
                                            }
                                            Err(_) => {
                                                warn!(
                                                    "TCP REALITY Server TLS Accept timed out after {}s",
                                                    session_policy_inner.handshake_timeout.as_secs()
                                                );
                                            }
                                        }
                                    } else if let Ok(mut fallback_addrs) =
                                        tokio::net::lookup_host(&dest).await
                                    {
                                        server_metrics_inner.inc_reality_fallback();
                                        if let Some(target_addr) = fallback_addrs.next() {
                                            match tokio::time::timeout(
                                                session_policy_inner.handshake_timeout,
                                                tokio::net::TcpStream::connect(target_addr),
                                            )
                                            .await
                                            {
                                                Ok(Ok(target_stream)) => {
                                                    if let Err(e) =
                                                        relay_until_either_side_finishes(
                                                            wrapped_stream,
                                                            target_stream,
                                                            session_policy_inner
                                                                .connection_idle_timeout,
                                                            session_policy_inner.half_close_timeout,
                                                        )
                                                        .await
                                                    {
                                                        log_relay_error(
                                                            "TCP Fallback relay error",
                                                            Some(client_addr),
                                                            &e,
                                                        );
                                                    }
                                                }
                                                Ok(Err(e)) => {
                                                    warn!("TCP Fallback: Failed to connect to {} for client {}: {}", target_addr, client_addr, e);
                                                }
                                                Err(_) => {
                                                    warn!(
                                                        "TCP Fallback: connect to {} for client {} timed out after {}s",
                                                        target_addr,
                                                        client_addr,
                                                        session_policy_inner.handshake_timeout.as_secs()
                                                    );
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TCP REALITY Listener accept error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("TCP REALITY: Failed to bind to {}: {}", tcp_listen_addr, e);
                }
            }
        });

        endpoint
    } else {
        Endpoint::server(server_config, config.listen)?
    };

    let quic_connection_limiter = Arc::new(Semaphore::new(max_quic_connections));

    while let Some(incoming) = endpoint.accept().await {
        let permit = match quic_connection_limiter.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let config = config.clone();
        let idle_policy = idle_policy.clone();
        let session_policy = session_policy.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match incoming.await {
                Ok(conn) => {
                    info!("New connection from {}", conn.remote_address());
                    if let Err(e) = handle_connection(
                        conn,
                        config,
                        idle_policy,
                        session_policy,
                        max_udp_associations_per_connection,
                        max_bi_stream_tasks_per_connection,
                        metrics,
                    )
                    .await
                    {
                        error!("Connection error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Incoming connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

pub struct UdpAssoc {
    socket: Arc<tokio::net::UdpSocket>,
    task: tokio::task::JoinHandle<()>,
}

async fn handle_connection(
    conn: quinn::Connection,
    config: ServerConfig,
    idle_policy: Arc<IdleSessionPolicy>,
    session_policy: Arc<SessionGovernancePolicy>,
    max_udp_associations_per_connection: usize,
    max_bi_stream_tasks_per_connection: usize,
    metrics: Arc<ServerMetrics>,
) -> Result<()> {
    let seacore_conn =
        Connection::<side::Server>::new(seacore_protocol::quic::InnerConn::Quic(conn.clone()));
    let conn_for_streams = conn.clone();

    // 1. Wait for Authenticate command on a uni-stream
    let auth_success = match tokio::time::timeout(session_policy.handshake_timeout, async {
        if let Ok(recv) = conn_for_streams.accept_uni().await {
            if let Ok(Task::Authenticate(auth)) = seacore_conn
                .accept_uni_stream(seacore_protocol::quic::SeaCoreReadStream::Quic(recv))
                .await
            {
                let uuid = auth.uuid;
                if let Some(user) = config.users.iter().find(|u| u.uuid == uuid) {
                    if auth.validate(&user.password) {
                        return true;
                    } else {
                        warn!("Invalid token for user {}", uuid);
                    }
                } else {
                    warn!("Unknown user {}", uuid);
                }
            }
        }
        false
    })
    .await
    {
        Ok(res) => res,
        Err(_) => false,
    };
    metrics.record_auth_attempt(auth_success);

    if !auth_success {
        debug!(
            "Unauthenticated QUIC connection from {}, closing silently",
            conn.remote_address()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        conn.close(quinn::VarInt::from_u32(0x00), b"");
        return Ok(());
    }

    let _active_connection = metrics.track_active_connection();
    info!("User authenticated from {}", conn.remote_address());

    let udp_assocs: Arc<Mutex<HashMap<u16, UdpAssoc>>> = Arc::new(Mutex::new(HashMap::new()));
    let udp_assoc_touches: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let bi_stream_limiter = Arc::new(Semaphore::new(max_bi_stream_tasks_per_connection));

    let udp_assocs_cleanup = udp_assocs.clone();
    let udp_assoc_touches_cleanup = udp_assoc_touches.clone();
    let idle_policy_cleanup = idle_policy.clone();
    let metrics_janitor = metrics.clone();
    let udp_janitor = tokio::spawn(async move {
        loop {
            tokio::time::sleep(idle_policy_cleanup.check_interval).await;
            let now = Instant::now();
            let mut assocs = udp_assocs_cleanup.lock().await;
            let mut touches = udp_assoc_touches_cleanup.lock().await;

            touches.retain(|assoc_id, _| assocs.contains_key(assoc_id));

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
                    if let Some(assoc) = assocs.remove(&assoc_id) {
                        assoc.task.abort();
                        metrics_janitor.inc_udp_assoc_closed(1);
                        metrics_janitor.dec_udp_assoc_active(1);
                    }
                    touches.remove(&assoc_id);
                }
            }
        }
    });

    // Spawn datagram handler
    let seacore_conn_dg = seacore_conn.clone();
    let udp_assocs_dg = udp_assocs.clone();
    let udp_assoc_touches_dg = udp_assoc_touches.clone();
    let metrics_dg = metrics.clone();
    tokio::spawn(async move {
        loop {
            match conn.read_datagram().await {
                Ok(dg) => {
                    match seacore_conn_dg.accept_datagram(dg) {
                        Ok(Task::Heartbeat) => {
                            // Heartbeat received, connection kept alive
                        }
                        Ok(Task::Ping { seq_id, timestamp }) => {
                            // Echo ping back
                            let _ = seacore_conn_dg.ping(seq_id, timestamp).await;
                        }
                        Ok(Task::Packet(pkt)) => {
                            let assoc_id = pkt.assoc_id();
                            let addr = pkt.addr().clone();
                            if let Err(e) = handle_server_udp_packet(
                                pkt,
                                addr,
                                assoc_id,
                                udp_assocs_dg.clone(),
                                udp_assoc_touches_dg.clone(),
                                seacore_conn_dg.clone(),
                                max_udp_associations_per_connection,
                                metrics_dg.clone(),
                            )
                            .await
                            {
                                warn!("UDP packet handling error: {}", e);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Datagram error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    info!("Datagram channel closed: {}", e);
                    break;
                }
            }
        }
    });

    // Accept streams
    loop {
        tokio::select! {
            // Uni-stream (Packet, Dissociate)
            uni = conn_for_streams.accept_uni() => {
                match uni {
                    Ok(recv) => {
                        match seacore_conn
                            .accept_uni_stream(seacore_protocol::quic::SeaCoreReadStream::Quic(recv))
                            .await
                        {
                            Ok(Task::Authenticate(_auth)) => {
                                warn!("Received redundant or delayed Authenticate command");
                            }
                            Ok(Task::Dissociate(assoc_id)) => {
                                info!("Dissociate UDP session {}", assoc_id);
                                let mut assocs = udp_assocs.lock().await;
                                if let Some(assoc) = assocs.remove(&assoc_id) {
                                    assoc.task.abort();
                                    metrics.inc_udp_assoc_closed(1);
                                    metrics.dec_udp_assoc_active(1);
                                }
                                udp_assoc_touches.lock().await.remove(&assoc_id);
                            }
                            Ok(Task::Packet(pkt)) => {
                                let assoc_id = pkt.assoc_id();
                                let addr = pkt.addr().clone();
                                if let Err(e) = handle_server_udp_packet(
                                    pkt,
                                    addr,
                                    assoc_id,
                                    udp_assocs.clone(),
                                    udp_assoc_touches.clone(),
                                    seacore_conn.clone(),
                                    max_udp_associations_per_connection,
                                    metrics.clone(),
                                ).await {
                                    warn!("UDP packet handling error: {}", e);
                                }
                            }
                            Ok(_) => {}
                            // H3 SETTINGS/QPACK streams from client will fail to
                            // parse as SeaCore protocol — silently ignore them
                            Err(_) => {}
                        }
                    }
                    Err(e) => {
                        info!("Connection closed (uni): {}", e);
                        break;
                    }
                }
            }
            // Bi-stream (Connect)
            bi = conn_for_streams.accept_bi() => {
                match bi {
                    Ok((send, recv)) => {
                        let permit = match bi_stream_limiter.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(
                                    "Dropping bi-stream because max_bi_stream_tasks_per_connection={} was reached",
                                    max_bi_stream_tasks_per_connection
                                );
                                continue;
                            }
                        };
                        let seacore_conn = seacore_conn.clone();
                        let session_policy = session_policy.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            match seacore_conn.accept_bi_stream(
                                seacore_protocol::quic::SeaCoreWriteStream::Quic(send),
                                seacore_protocol::quic::SeaCoreReadStream::Quic(recv)
                            ).await {
                                Ok(Task::Connect(stream, addr)) => {
                                    info!("TCP connect request to {}", addr);
                                    let target_addr_str = match addr {
                                        Address::SocketAddress(sa) => sa.to_string(),
                                        Address::DomainAddress(domain, port) => format!("{}:{}", domain, port),
                                        Address::None => {
                                            warn!("Received Connect with Address::None");
                                            return;
                                        }
                                    };
                                    match tokio::net::TcpStream::connect(&target_addr_str).await {
                                        Ok(target) => {
                                            if let Err(e) = relay_until_either_side_finishes(
                                                stream,
                                                target,
                                                session_policy.connection_idle_timeout,
                                                session_policy.half_close_timeout,
                                            ).await {
                                                log_relay_error("TCP relay error", None, &e);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to connect to target {}: {}", target_addr_str, e);
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => warn!("Bi-stream error: {}", e),
                            }
                        });
                    }
                    Err(e) => {
                        info!("Connection closed (bi): {}", e);
                        break;
                    }
                }
            }
        }
    }

    udp_janitor.abort();

    let remaining = {
        let mut assocs = udp_assocs.lock().await;
        let remaining = assocs.len() as u64;
        for (_, assoc) in assocs.drain() {
            assoc.task.abort();
        }
        remaining
    };
    if remaining > 0 {
        metrics.inc_udp_assoc_closed(remaining);
        metrics.dec_udp_assoc_active(remaining as i64);
    }

    Ok(())
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
                        let _ = tokio::time::timeout(Duration::from_millis(200), right_write.shutdown()).await;
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
                        let _ = tokio::time::timeout(Duration::from_millis(200), left_write.shutdown()).await;
                        continue;
                    }
                    left_write.write_all(&right_buf[..n]).await?;
                }
            }
        }
    }.await;

    // On reset/abort paths (e.g. 10054), graceful TLS shutdown can become expensive.
    // Only try a bounded graceful close on normal EOF; otherwise drop halves directly.
    if relay_result.is_ok() {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), left_write.shutdown())
            .await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            right_write.shutdown(),
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

fn log_relay_error(prefix: &str, peer: Option<SocketAddr>, err: &std::io::Error) {
    if is_expected_relay_io_error(err) {
        if let Some(addr) = peer {
            debug!("{} for {}: {}", prefix, addr, err);
        } else {
            debug!("{}: {}", prefix, err);
        }
    } else if let Some(addr) = peer {
        warn!("{} for {}: {}", prefix, addr, err);
    } else {
        warn!("{}: {}", prefix, err);
    }
}

async fn handle_server_udp_packet(
    pkt: seacore_protocol::quic::PacketTask,
    addr: Address,
    assoc_id: u16,
    udp_assocs: Arc<Mutex<HashMap<u16, UdpAssoc>>>,
    udp_assoc_touches: Arc<Mutex<HashMap<u16, Instant>>>,
    seacore_conn: Connection<side::Server>,
    max_udp_associations: usize,
    metrics: Arc<ServerMetrics>,
) -> Result<()> {
    let payload: bytes::Bytes = pkt.payload().await?;
    udp_assoc_touches
        .lock()
        .await
        .insert(assoc_id, Instant::now());

    let target_addr_str = match &addr {
        Address::SocketAddress(sa) => sa.to_string(),
        Address::DomainAddress(domain, port) => format!("{}:{}", domain, port),
        Address::None => {
            return Err(eyre::eyre!("UDP Packet missing destination address"));
        }
    };

    let socket = {
        let mut assocs = udp_assocs.lock().await;
        if let Some(assoc) = assocs.get(&assoc_id) {
            assoc.socket.clone()
        } else {
            if assocs.len() >= max_udp_associations {
                return Err(eyre::eyre!(
                    "udp association limit reached ({})",
                    max_udp_associations
                ));
            }

            // Determine if we should bind IPv4 or IPv6 based on the target config? 0.0.0.0 is usually fine
            let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
            let socket_clone = socket.clone();
            let udp_assoc_touches_clone = udp_assoc_touches.clone();

            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((size, peer_addr)) => {
                            udp_assoc_touches_clone
                                .lock()
                                .await
                                .insert(assoc_id, Instant::now());
                            let data = &buf[..size];
                            let seacore_addr = Address::SocketAddress(peer_addr);
                            // We use packet_quic as a default reliable relay back, or datagram for speed
                            if let Err(e) = seacore_conn
                                .packet_native(data, seacore_addr, assoc_id)
                                .await
                            {
                                warn!("Failed to send UDP reply back to client: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("UDP recv_from error for assoc {}: {}", assoc_id, e);
                            break;
                        }
                    }
                }
            });

            assocs.insert(
                assoc_id,
                UdpAssoc {
                    socket: socket.clone(),
                    task,
                },
            );
            metrics.inc_udp_assoc_created();
            metrics.inc_udp_assoc_active();
            udp_assoc_touches
                .lock()
                .await
                .insert(assoc_id, Instant::now());
            socket
        }
    };

    // Note: for DomainAddress, tokio UdpSocket send_to handles resolving the domain internally!
    socket.send_to(&payload, target_addr_str).await?;
    Ok(())
}

async fn handle_tcp_connection(
    seacore_conn: Connection<side::Server>,
    mut recv: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    config: ServerConfig,
    idle_policy: Arc<IdleSessionPolicy>,
    session_policy: Arc<SessionGovernancePolicy>,
    max_udp_associations_per_connection: usize,
    metrics: Arc<ServerMetrics>,
) -> Result<()> {
    info!("Starting SeaCore TCP Connection Handler");

    // Auth timeout loop
    let auth_success = match tokio::time::timeout(session_policy.handshake_timeout, async {
        if let Ok(Task::Authenticate(auth)) = seacore_conn.next_tcp_task(recv.as_mut()).await {
            let uuid = auth.uuid;
            if let Some(user) = config.users.iter().find(|u| u.uuid == uuid) {
                if auth.validate(&user.password) {
                    return true;
                } else {
                    warn!("TCP Invalid token for user {}", uuid);
                }
            } else {
                warn!("TCP Unknown user {}", uuid);
            }
        }
        false
    })
    .await
    {
        Ok(res) => res,
        Err(_) => false,
    };
    metrics.record_auth_attempt(auth_success);

    if !auth_success {
        warn!("TCP connection authentication failed. Closing.");
        return Ok(());
    }

    let _active_connection = metrics.track_active_connection();
    info!("User authenticated via TCP");

    let udp_assocs: Arc<tokio::sync::Mutex<HashMap<u16, UdpAssoc>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let udp_assoc_touches: Arc<tokio::sync::Mutex<HashMap<u16, Instant>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let udp_assocs_cleanup = udp_assocs.clone();
    let udp_assoc_touches_cleanup = udp_assoc_touches.clone();
    let idle_policy_cleanup = idle_policy.clone();
    let metrics_janitor = metrics.clone();
    let udp_janitor = tokio::spawn(async move {
        loop {
            tokio::time::sleep(idle_policy_cleanup.check_interval).await;
            let now = Instant::now();
            let mut assocs = udp_assocs_cleanup.lock().await;
            let mut touches = udp_assoc_touches_cleanup.lock().await;

            touches.retain(|assoc_id, _| assocs.contains_key(assoc_id));

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
                    if let Some(assoc) = assocs.remove(&assoc_id) {
                        assoc.task.abort();
                        metrics_janitor.inc_udp_assoc_closed(1);
                        metrics_janitor.dec_udp_assoc_active(1);
                    }
                    touches.remove(&assoc_id);
                }
            }
        }
    });

    // Process remaining packets sequentially
    loop {
        match seacore_conn.next_tcp_task(recv.as_mut()).await {
            Ok(Task::Packet(pkt)) => {
                let assoc_id = pkt.assoc_id();
                let addr = pkt.addr().clone();
                if let Err(e) = handle_server_udp_packet(
                    pkt,
                    addr,
                    assoc_id,
                    udp_assocs.clone(),
                    udp_assoc_touches.clone(),
                    seacore_conn.clone(),
                    max_udp_associations_per_connection,
                    metrics.clone(),
                )
                .await
                {
                    warn!("TCP UDP packet handling error: {}", e);
                }
            }
            Ok(Task::Connect(_bistream, addr)) => {
                info!(
                    "TCP CONNECT request over authenticated Reality connection to {}",
                    addr
                );
                let target_addr_str = match &addr {
                    Address::SocketAddress(sa) => sa.to_string(),
                    Address::DomainAddress(domain, port) => format!("{}:{}", domain, port),
                    Address::None => continue,
                };

                match tokio::net::TcpStream::connect(&target_addr_str).await {
                    Ok(target_stream) => {
                        let (mut target_ri, mut target_wi) = target_stream.into_split();
                        let writer_conn = seacore_conn.conn.clone();
                        let relay_result = async {
                            let mut up_buf = vec![0u8; 8192];
                            let mut down_buf = vec![0u8; 8192];
                            let mut client_closed = false;
                            let mut target_closed = false;
                            let mut half_close_deadline: Option<Instant> = None;

                            // Hold the writer lock for the whole relay.
                            // Locking per chunk adds avoidable overhead under sustained traffic.
                            let mut client_writer =
                                if let seacore_protocol::quic::InnerConn::Tcp(t) = &writer_conn {
                                    Some(t.lock().await)
                                } else {
                                    None
                                };

                            loop {
                                if client_closed && target_closed {
                                    return Ok(());
                                }

                                let wait_budget = match half_close_deadline {
                                    Some(deadline) => {
                                        let remain = deadline.saturating_duration_since(Instant::now());
                                        if remain.is_zero() {
                                            return Ok(());
                                        }
                                        remain.min(session_policy.connection_idle_timeout)
                                    }
                                    None => session_policy.connection_idle_timeout,
                                };

                                tokio::select! {
                                    read_from_client = tokio::time::timeout(
                                        wait_budget,
                                        recv.read(&mut up_buf)
                                    ), if !client_closed => {
                                        let n = match read_from_client {
                                            Ok(Ok(n)) => n,
                                            Ok(Err(e)) => return Err(e),
                                            Err(_) => return Ok(()),
                                        };
                                        if n == 0 {
                                            client_closed = true;
                                            if half_close_deadline.is_none() {
                                                half_close_deadline = Some(Instant::now() + session_policy.half_close_timeout);
                                            }
                                            let _ = tokio::time::timeout(
                                                Duration::from_millis(200),
                                                target_wi.shutdown(),
                                            ).await;
                                            continue;
                                        }
                                        target_wi.write_all(&up_buf[..n]).await?;
                                    }
                                    read_from_target = tokio::time::timeout(
                                        wait_budget,
                                        target_ri.read(&mut down_buf)
                                    ), if !target_closed => {
                                        let n = match read_from_target {
                                            Ok(Ok(n)) => n,
                                            Ok(Err(e)) => return Err(e),
                                            Err(_) => return Ok(()),
                                        };
                                        if n == 0 {
                                            target_closed = true;
                                            if half_close_deadline.is_none() {
                                                half_close_deadline = Some(Instant::now() + session_policy.half_close_timeout);
                                            }
                                            if let Some(w) = client_writer.as_mut() {
                                                let _ = tokio::time::timeout(
                                                    Duration::from_millis(200),
                                                    w.shutdown(),
                                                ).await;
                                            }
                                            continue;
                                        }
                                        if let Some(w) = client_writer.as_mut() {
                                            w.write_all(&down_buf[..n]).await?;
                                        }
                                    }
                                }
                            }
                        }
                        .await;

                        if let Err(e) = relay_result {
                            log_relay_error("TCP CONNECT relay error", None, &e);
                        }

                        udp_janitor.abort();
                        let remaining = {
                            let mut assocs = udp_assocs.lock().await;
                            let remaining = assocs.len() as u64;
                            for (_, assoc) in assocs.drain() {
                                assoc.task.abort();
                            }
                            remaining
                        };
                        if remaining > 0 {
                            metrics.inc_udp_assoc_closed(remaining);
                            metrics.dec_udp_assoc_active(remaining as i64);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(
                            "TCP CONNECT: Failed to connect to {}: {}",
                            target_addr_str, e
                        );
                        udp_janitor.abort();
                        let remaining = {
                            let mut assocs = udp_assocs.lock().await;
                            let remaining = assocs.len() as u64;
                            for (_, assoc) in assocs.drain() {
                                assoc.task.abort();
                            }
                            remaining
                        };
                        if remaining > 0 {
                            metrics.inc_udp_assoc_closed(remaining);
                            metrics.dec_udp_assoc_active(remaining as i64);
                        }
                        return Ok(());
                    }
                }
            }
            Ok(Task::Dissociate(assoc_id)) => {
                let mut assocs = udp_assocs.lock().await;
                if let Some(assoc) = assocs.remove(&assoc_id) {
                    assoc.task.abort();
                    metrics.inc_udp_assoc_closed(1);
                    metrics.dec_udp_assoc_active(1);
                }
                udp_assoc_touches.lock().await.remove(&assoc_id);
            }
            Ok(Task::Heartbeat) => {}
            Ok(Task::Ping { seq_id, timestamp }) => {
                let _ = seacore_conn.ping(seq_id, timestamp).await;
            }
            Ok(_) => {}
            Err(e) => {
                info!("TCP connection closed: {}", e);
                break;
            }
        }
    }

    udp_janitor.abort();

    let remaining = {
        let mut assocs = udp_assocs.lock().await;
        let remaining = assocs.len() as u64;
        for (_, assoc) in assocs.drain() {
            assoc.task.abort();
        }
        remaining
    };
    if remaining > 0 {
        metrics.inc_udp_assoc_closed(remaining);
        metrics.dec_udp_assoc_active(remaining as i64);
    }

    Ok(())
}
