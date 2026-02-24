use std::fs;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::collections::HashMap;
use std::cmp::Reverse;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use eyre::Result;
use quinn::Endpoint;
use serde::Deserialize;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use seacore_protocol::protocol::Address;
use seacore_protocol::quic::{
    side, Connection, Task,
};

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub users: Vec<UserConfig>,
    pub congestion_control: Option<String>,
    pub max_idle_time_secs: Option<u64>,
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: Option<usize>,
    pub idle_session_check_interval_secs: Option<u64>,
    pub idle_session_timeout_secs: Option<u64>,
    pub min_idle_sessions: Option<usize>,
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

pub async fn run_server(config_path: &str) -> Result<()> {
    // Load config
    let config_str = fs::read_to_string(config_path)?;
    let config: ServerConfig = serde_json::from_str(&config_str)?;
    let idle_policy = Arc::new(idle_session_policy_from_server_config(&config));

    info!("Listening on {}", config.listen);
    info!("Loaded {} user(s)", config.users.len());
    info!(
        "Idle session policy: check={}s timeout={}s min_idle={}",
        idle_policy.check_interval.as_secs(),
        idle_policy.timeout.as_secs(),
        idle_policy.min_idle_sessions
    );

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

    let server_crypto_clone = server_crypto.clone();

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

    if let Some(secs) = config.max_idle_time_secs {
        if let Ok(timeout) = std::time::Duration::from_secs(secs).try_into() {
            transport_config.max_idle_timeout(Some(timeout));
        }
    } else {
        if let Ok(timeout) = std::time::Duration::from_secs(10).try_into() {
            transport_config.max_idle_timeout(Some(timeout));
        }
    }
    
    if let Some(cc) = &config.congestion_control {
        match cc.to_lowercase().as_str() {
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            }
            "cubic" => {} // Default
            _ => warn!("Unknown congestion control algorithm: {}, using default", cc),
        }
    }
    
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = if let Some(reality) = &config.reality {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
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
        let fallback_addr = fallback_addrs.next().unwrap_or_else(|| "127.0.0.1:443".parse().expect("constant socket addr"));

        let short_ids = reality.short_ids.clone();
        let server_names = reality.server_names.clone();

        let router = crate::router::QuicRouter::new(
            config.listen,
            actual_quinn_addr,
            fallback_addr,
            server_priv_key,
            config.users.clone(),
            short_ids,
            server_names,
        ).await?;

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
        let short_ids_clone = reality.short_ids.clone();
        let server_names_clone = reality.server_names.clone();

        let config_clone_for_tcp = config.clone();
        let idle_policy_clone_for_tcp = idle_policy.clone();

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(tcp_listen_addr).await {
                Ok(listener) => {
                    info!("TCP REALITY Listener bound to {}", tcp_listen_addr);
                    loop {
                        match listener.accept().await {
                            Ok((client_stream, client_addr)) => {
                                let dest = dest_str.clone();
                                let priv_key = server_priv_key_copy.clone();
                                let users = users_clone.clone();
                                let s_ids = short_ids_clone.clone();
                                let s_names = server_names_clone.clone();
                                let server_crypto_inner = server_crypto_clone.clone();
                                let config_inner = config_clone_for_tcp.clone();
                                let idle_policy_inner = idle_policy_clone_for_tcp.clone();

                                tokio::spawn(async move {
                                    // Read initial bytes once (event-driven, no spin/peek polling).
                                    // We keep consumed bytes and replay them into TLS acceptor/fallback.
                                    let mut client_stream = client_stream;
                                    let mut sniffed = Vec::with_capacity(4096);
                                    let mut chunk = [0u8; 4096];
                                    let mut need_len = 5usize;
                                    let mut is_tls_handshake = false;
                                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

                                    loop {
                                        if sniffed.len() >= need_len || sniffed.len() >= 20000 {
                                            break;
                                        }
                                        let now = std::time::Instant::now();
                                        if now >= deadline {
                                            break;
                                        }
                                        let remain = deadline.saturating_duration_since(now);
                                        let n = match tokio::time::timeout(remain, client_stream.read(&mut chunk)).await {
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
                                                let record_len = u16::from_be_bytes([sniffed[3], sniffed[4]]) as usize;
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

                                    let is_authenticated = is_tls_handshake
                                        && crate::sniffer::verify_tcp_reality_auth(
                                            &sniffed,
                                            &priv_key,
                                            &users,
                                            &s_ids,
                                            &s_names,
                                        )
                                        .is_some();

                                    let wrapped_stream = PrefixedTcpStream::new(sniffed, client_stream);

                                    if is_authenticated {
                                        info!("TCP REALITY Authentication SUCCESS from {} (Routing)", client_addr);
                                        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_crypto_inner));
                                        match acceptor.accept(wrapped_stream).await {
                                            Ok(tls_stream) => {
                                                let (r, w) = tokio::io::split(tls_stream);
                                                let inner = seacore_protocol::quic::InnerConn::Tcp(std::sync::Arc::new(tokio::sync::Mutex::new(Box::new(w))));
                                                let seacore_conn = seacore_protocol::quic::Connection::<seacore_protocol::quic::side::Server>::new(inner);
                                                let config_for_tcp = config_inner;

                                                tokio::spawn(async move {
                                                    if let Err(e) = handle_tcp_connection(seacore_conn, Box::new(r), config_for_tcp, idle_policy_inner.clone()).await {
                                                        warn!("TCP connection error handling failed: {}", e);
                                                    }
                                                });
                                            }
                                            Err(e) => {
                                                warn!("TCP REALITY Server TLS Accept failed: {}", e);
                                            }
                                        }
                                    } else if let Ok(mut fallback_addrs) = tokio::net::lookup_host(&dest).await {
                                        if let Some(target_addr) = fallback_addrs.next() {
                                            match tokio::net::TcpStream::connect(target_addr).await {
                                                Ok(target_stream) => {
                                                    if let Err(e) = relay_until_either_side_finishes(wrapped_stream, target_stream, idle_policy_inner.timeout).await {
                                                        log_relay_error("TCP Fallback relay error", Some(client_addr), &e);
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("TCP Fallback: Failed to connect to {} for client {}: {}", target_addr, client_addr, e);
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

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        let idle_policy = idle_policy.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    info!("New connection from {}", conn.remote_address());
                    if let Err(e) = handle_connection(conn, config, idle_policy).await {
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
) -> Result<()> {
    let seacore_conn = Connection::<side::Server>::new(seacore_protocol::quic::InnerConn::Quic(conn.clone()));
    let conn_for_streams = conn.clone();

    // 1. Wait up to 5 seconds for Authenticate command on a uni-stream
    let auth_success = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        if let Ok(recv) = conn_for_streams.accept_uni().await {
            if let Ok(Task::Authenticate(auth)) = seacore_conn.accept_uni_stream(seacore_protocol::quic::SeaCoreReadStream::Quic(recv)).await {
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
    }).await {
        Ok(res) => res,
        Err(_) => false,
    };

    if !auth_success {
        warn!("Unauthenticated QUIC connection from {}. (Note: should have been caught by UDP Router!)", conn.remote_address());
        conn.close(quinn::VarInt::from_u32(0x01), b"unauthorized");
        return Ok(());
    }

    info!("User authenticated from {}", conn.remote_address());
    
    let udp_assocs: Arc<Mutex<HashMap<u16, UdpAssoc>>> = Arc::new(Mutex::new(HashMap::new()));
    let udp_assoc_touches: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    let udp_assocs_cleanup = udp_assocs.clone();
    let udp_assoc_touches_cleanup = udp_assoc_touches.clone();
    let idle_policy_cleanup = idle_policy.clone();
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
                            ).await {
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
                        let seacore_conn = seacore_conn.clone();
                        let idle_policy = idle_policy.clone();
                        tokio::spawn(async move {
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
                                            if let Err(e) = relay_until_either_side_finishes(stream, target, idle_policy.timeout).await {
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
    Ok(())
}

async fn relay_until_either_side_finishes<L, R>(
    left: L,
    right: R,
    relay_idle_timeout: Duration,
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
        loop {
            tokio::select! {
                left_read_result = tokio::time::timeout(relay_idle_timeout, left_read.read(&mut left_buf)) => {
                    let n = match left_read_result {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Ok(()), // Idle timeout.
                    };
                    if n == 0 {
                        return Ok(());
                    }
                    right_write.write_all(&left_buf[..n]).await?;
                }
                right_read_result = tokio::time::timeout(relay_idle_timeout, right_read.read(&mut right_buf)) => {
                    let n = match right_read_result {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Ok(()), // Idle timeout.
                    };
                    if n == 0 {
                        return Ok(());
                    }
                    left_write.write_all(&right_buf[..n]).await?;
                }
            }
        }
    }.await;

    // On reset/abort paths (e.g. 10054), graceful TLS shutdown can become expensive.
    // Only try a bounded graceful close on normal EOF; otherwise drop halves directly.
    if relay_result.is_ok() {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            left_write.shutdown(),
        )
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
) -> Result<()> {
    let payload: bytes::Bytes = pkt.payload().await?;
    udp_assoc_touches.lock().await.insert(assoc_id, Instant::now());
    
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
            // Determine if we should bind IPv4 or IPv6 based on the target config? 0.0.0.0 is usually fine
            let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
            let socket_clone = socket.clone();
            let udp_assoc_touches_clone = udp_assoc_touches.clone();
            
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((size, peer_addr)) => {
                            udp_assoc_touches_clone.lock().await.insert(assoc_id, Instant::now());
                            let data = &buf[..size];
                            let seacore_addr = Address::SocketAddress(peer_addr);
                            // We use packet_quic as a default reliable relay back, or datagram for speed
                            if let Err(e) = seacore_conn.packet_native(data, seacore_addr, assoc_id).await {
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
            
            assocs.insert(assoc_id, UdpAssoc {
                socket: socket.clone(),
                task,
            });
            udp_assoc_touches.lock().await.insert(assoc_id, Instant::now());
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
) -> Result<()> {
    info!("Starting SeaCore TCP Connection Handler");
    
    // Auth timeout loop
    let auth_success = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    }).await {
        Ok(res) => res,
        Err(_) => false,
    };

    if !auth_success {
        warn!("TCP connection authentication failed. Closing.");
        return Ok(());
    }

    info!("User authenticated via TCP");

    let udp_assocs: Arc<tokio::sync::Mutex<HashMap<u16, UdpAssoc>>> = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let udp_assoc_touches: Arc<tokio::sync::Mutex<HashMap<u16, Instant>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let udp_assocs_cleanup = udp_assocs.clone();
    let udp_assoc_touches_cleanup = udp_assoc_touches.clone();
    let idle_policy_cleanup = idle_policy.clone();
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
                ).await {
                    warn!("TCP UDP packet handling error: {}", e);
                }
            }
            Ok(Task::Connect(_bistream, addr)) => {
                info!("TCP CONNECT request over authenticated Reality connection to {}", addr);
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

                            // Hold the writer lock for the whole relay.
                            // Locking per chunk adds avoidable overhead under sustained traffic.
                            let mut client_writer = if let seacore_protocol::quic::InnerConn::Tcp(t) = &writer_conn {
                                Some(t.lock().await)
                            } else {
                                None
                            };

                            loop {
                                tokio::select! {
                                    read_from_client = tokio::time::timeout(
                                        idle_policy.timeout,
                                        recv.read(&mut up_buf)
                                    ) => {
                                        let n = match read_from_client {
                                            Ok(Ok(n)) => n,
                                            Ok(Err(e)) => return Err(e),
                                            Err(_) => return Ok(()), // Idle timeout: close both sides.
                                        };
                                        if n == 0 {
                                            return Ok(());
                                        }
                                        target_wi.write_all(&up_buf[..n]).await?;
                                    }
                                    read_from_target = tokio::time::timeout(
                                        idle_policy.timeout,
                                        target_ri.read(&mut down_buf)
                                    ) => {
                                        let n = match read_from_target {
                                            Ok(Ok(n)) => n,
                                            Ok(Err(e)) => return Err(e),
                                            Err(_) => return Ok(()), // Idle timeout: close both sides.
                                        };
                                        if n == 0 {
                                            return Ok(());
                                        }
                                        if let Some(w) = client_writer.as_mut() {
                                            w.write_all(&down_buf[..n]).await?;
                                        }
                                    }
                                }
                            }
                        }.await;

                        if let Err(e) = relay_result {
                            log_relay_error("TCP CONNECT relay error", None, &e);
                        }

                        udp_janitor.abort();
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("TCP CONNECT: Failed to connect to {}: {}", target_addr_str, e);
                        udp_janitor.abort();
                        return Ok(());
                    }
                }
            }
            Ok(Task::Dissociate(assoc_id)) => {
                let mut assocs = udp_assocs.lock().await;
                if let Some(assoc) = assocs.remove(&assoc_id) {
                    assoc.task.abort();
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
    Ok(())
}

