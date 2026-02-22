use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

use eyre::Result;
use quinn::Endpoint;
use serde::Deserialize;
use tracing::{error, info, warn};
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

pub async fn run_server(config_path: &str) -> Result<()> {
    // Load config
    let config_str = fs::read_to_string(config_path)?;
    let config: ServerConfig = serde_json::from_str(&config_str)?;

    info!("Listening on {}", config.listen);
    info!("Loaded {} user(s)", config.users.len());

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
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

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
        
        // --- Phase 15: Pure Transparent TCP Fallback ---
        let tcp_listen_addr = config.listen;
        let dest_str = reality.dest.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(tcp_listen_addr).await {
                Ok(listener) => {
                    info!("TCP Fallback Listener bound to {}", tcp_listen_addr);
                    loop {
                        match listener.accept().await {
                            Ok((mut client_stream, client_addr)) => {
                                let dest = dest_str.clone();
                                tokio::spawn(async move {
                                    if let Ok(mut fallback_addrs) = tokio::net::lookup_host(&dest).await {
                                        if let Some(target_addr) = fallback_addrs.next() {
                                            match tokio::net::TcpStream::connect(target_addr).await {
                                                Ok(mut target_stream) => {
                                                    // Bidirectional pure copy
                                                    let (mut client_ri, mut client_wi) = client_stream.split();
                                                    let (mut target_ri, mut target_wi) = target_stream.split();
                                                    
                                                    let client_to_target = tokio::io::copy(&mut client_ri, &mut target_wi);
                                                    let target_to_client = tokio::io::copy(&mut target_ri, &mut client_wi);
                                                    
                                                    let _ = tokio::try_join!(client_to_target, target_to_client);
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
                                warn!("TCP Fallback Listener accept error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("TCP Fallback: Failed to bind to {}: {}", tcp_listen_addr, e);
                }
            }
        });
        
        endpoint
    } else {
        Endpoint::server(server_config, config.listen)?
    };

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    info!("New connection from {}", conn.remote_address());
                    if let Err(e) = handle_connection(conn, config).await {
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

async fn handle_connection(conn: quinn::Connection, config: ServerConfig) -> Result<()> {
    let seacore_conn = Connection::<side::Server>::new(conn.clone());
    let conn_for_streams = conn.clone();

    // 1. Wait up to 5 seconds for Authenticate command on a uni-stream
    let auth_success = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        if let Ok(recv) = conn_for_streams.accept_uni().await {
            if let Ok(Task::Authenticate(auth)) = seacore_conn.accept_uni_stream(recv).await {
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

    // Spawn datagram handler
    let seacore_conn_dg = seacore_conn.clone();
    let udp_assocs_dg = udp_assocs.clone();
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
                            let _ = seacore_conn_dg.ping(seq_id, timestamp);
                        }
                        Ok(Task::Packet(pkt)) => {
                            let assoc_id = pkt.assoc_id();
                            let addr = pkt.addr().clone();
                            let udp_assocs = udp_assocs_dg.clone();
                            let seacore_conn_clone = seacore_conn_dg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_server_udp_packet(pkt, addr, assoc_id, udp_assocs, seacore_conn_clone).await {
                                    warn!("UDP packet handling error: {}", e);
                                }
                            });
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
                        let seacore_conn = seacore_conn.clone();
                        let _config = config.clone();
                        let udp_assocs = udp_assocs.clone();
                        tokio::spawn(async move {
                            match seacore_conn.accept_uni_stream(recv).await {
                                Ok(Task::Authenticate(_auth)) => {
                                    warn!("Received redundant or delayed Authenticate command");
                                }
                                Ok(Task::Dissociate(assoc_id)) => {
                                    info!("Dissociate UDP session {}", assoc_id);
                                    let mut assocs = udp_assocs.lock().await;
                                    if let Some(assoc) = assocs.remove(&assoc_id) {
                                        assoc.task.abort();
                                    }
                                }
                                Ok(Task::Packet(pkt)) => {
                                    let assoc_id = pkt.assoc_id();
                                    let addr = pkt.addr().clone();
                                    let udp_assocs = udp_assocs.clone();
                                    let seacore_conn_clone = seacore_conn.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_server_udp_packet(pkt, addr, assoc_id, udp_assocs, seacore_conn_clone).await {
                                            warn!("UDP packet handling error: {}", e);
                                        }
                                    });
                                }
                                Ok(_) => {}
                                // H3 SETTINGS/QPACK streams from client will fail to
                                // parse as SeaCore protocol — silently ignore them
                                Err(_) => {}
                            }
                        });
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
                        tokio::spawn(async move {
                            match seacore_conn.accept_bi_stream(send, recv).await {
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
                                            let (mut ri, mut wi) = tokio::io::split(stream);
                                            let (mut ro, mut wo) = target.into_split();
                                            tokio::spawn(async move {
                                                let _ = tokio::io::copy(&mut ri, &mut wo).await;
                                            });
                                            tokio::spawn(async move {
                                                let _ = tokio::io::copy(&mut ro, &mut wi).await;
                                            });
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

    Ok(())
}

async fn handle_server_udp_packet(
    pkt: seacore_protocol::quic::PacketTask,
    addr: Address,
    assoc_id: u16,
    udp_assocs: Arc<Mutex<HashMap<u16, UdpAssoc>>>,
    seacore_conn: Connection<side::Server>,
) -> Result<()> {
    let payload: bytes::Bytes = pkt.payload().await?;
    
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
            
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((size, peer_addr)) => {
                            let data = &buf[..size];
                            let seacore_addr = Address::SocketAddress(peer_addr);
                            // We use packet_quic as a default reliable relay back, or datagram for speed
                            if let Err(e) = seacore_conn.packet_native(data, seacore_addr, assoc_id) {
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
            socket
        }
    };

    // Note: for DomainAddress, tokio UdpSocket send_to handles resolving the domain internally!
    socket.send_to(&payload, target_addr_str).await?;
    Ok(())
}

