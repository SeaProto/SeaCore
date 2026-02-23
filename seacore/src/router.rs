use eyre::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::sniffer;

enum SessionTarget {
    SeaCore(Arc<UdpSocket>),
    Fallback(Arc<UdpSocket>),
}

/// Cache of recently seen tokens for replay protection.
/// Tokens are valid for ±30s, so we evict entries older than 120s.
struct ReplayCache {
    seen: HashMap<[u8; 32], Instant>,
}

impl ReplayCache {
    fn new() -> Self {
        Self { seen: HashMap::new() }
    }

    /// Returns `true` if the token was already seen (replay detected).
    fn check_and_insert(&mut self, token: [u8; 32]) -> bool {
        self.evict_stale();
        if self.seen.contains_key(&token) {
            true // replay!
        } else {
            self.seen.insert(token, Instant::now());
            false
        }
    }

    fn evict_stale(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(120);
        self.seen.retain(|_, ts| *ts > cutoff);
    }
}

pub struct QuicRouter {
    public_listener: Arc<UdpSocket>,
    quinn_addr: SocketAddr,
    fallback_addr: SocketAddr,
    sessions: Arc<Mutex<HashMap<SocketAddr, SessionTarget>>>,
    server_priv_key: [u8; 32],
    users: Vec<crate::server::UserConfig>,
    short_ids: Vec<String>,
    server_names: Vec<String>,
    replay_cache: Arc<Mutex<ReplayCache>>,
}

impl QuicRouter {
    pub async fn new(
        listen_addr: SocketAddr,
        quinn_addr: SocketAddr,
        fallback_addr: SocketAddr,
        server_priv_key: [u8; 32],
        users: Vec<crate::server::UserConfig>,
        short_ids: Vec<String>,
        server_names: Vec<String>,
    ) -> Result<Self> {
        let public_listener = Arc::new(UdpSocket::bind(listen_addr).await?);
        info!(
            "QUIC Router listening on {}, forwarding valid clients to {} and fallback to {}",
            listen_addr, quinn_addr, fallback_addr
        );

        Ok(Self {
            public_listener,
            quinn_addr,
            fallback_addr,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            server_priv_key,
            users,
            short_ids,
            server_names,
            replay_cache: Arc::new(Mutex::new(ReplayCache::new())),
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, client_addr) = match self.public_listener.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    warn!("Router recv_from error: {}", e);
                    continue;
                }
            };

            let packet = &buf[..len];
            let mut sessions = self.sessions.lock().await;

            // Check if existing session
            if let Some(target) = sessions.get(&client_addr) {
                let sock = match target {
                    SessionTarget::SeaCore(s) => s,
                    SessionTarget::Fallback(s) => s,
                };
                if let Err(e) = sock.send(packet).await {
                    warn!("Failed to forward packet for existing session {}: {}", client_addr, e);
                }
                continue;
            }

            // New session, inspect QUIC Initial packet
            let auth_result = sniffer::verify_reality_auth(
                packet,
                &self.server_priv_key,
                &self.users,
                &self.short_ids,
                &self.server_names,
            );

            let is_valid = if let Some(token) = auth_result {
                // Check replay cache
                let mut cache = self.replay_cache.lock().await;
                if cache.check_and_insert(token) {
                    warn!("Replay attack detected from {}, rejecting", client_addr);
                    false
                } else {
                    true
                }
            } else {
                // If it's not a valid initial Auth packet, it might be an ongoing connection 
                // from before a server restart (short header packet).
                // Let's forward short headers to Quinn so Quinn can issue a Stateless Reset.
                // A short header in QUIC v1 starts with a 0 bit (so 0x80 bit is not set).
                if !packet.is_empty() && (packet[0] & 0x80) == 0 {
                    true // send to Quinn for stateless reset
                } else {
                    false
                }
            };

            let target_addr = if is_valid {
                info!("Reality QUIC Auth successful for {}", client_addr);
                self.quinn_addr
            } else {
                info!("Reality QUIC Auth failed for {}, routing to fallback", client_addr);
                self.fallback_addr
            };

            // Create a dedicated local socket for this client to ensure quinn replies uniquely
            // Bind to matching address family (IPv4 or IPv6) based on the target
            let bind_addr: SocketAddr = if target_addr.is_ipv6() {
                "[::]:0".parse().expect("constant addr")
            } else {
                "0.0.0.0:0".parse().expect("constant addr")
            };
            let local_sock = Arc::new(UdpSocket::bind(bind_addr).await?);
            local_sock.connect(target_addr).await?;
            
            // Forward the first packet
            if let Err(e) = local_sock.send(packet).await {
                warn!("Failed to forward initial packet for {}: {}", client_addr, e);
                continue;
            }

            let session = if is_valid {
                SessionTarget::SeaCore(local_sock.clone())
            } else {
                SessionTarget::Fallback(local_sock.clone())
            };

            sessions.insert(client_addr, session);

            // Spawn task to relay replies back to the client
            let public_listener = self.public_listener.clone();
            let sessions_map = self.sessions.clone();
            tokio::spawn(async move {
                let mut reply_buf = vec![0u8; 65535];
                loop {
                    match local_sock.recv(&mut reply_buf).await {
                        Ok(len) => {
                            if let Err(e) = public_listener.send_to(&reply_buf[..len], client_addr).await {
                                warn!("Failed to relay response to {}: {}", client_addr, e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Local relay socket closed for {}: {}", client_addr, e);
                            break;
                        }
                    }
                }
                sessions_map.lock().await.remove(&client_addr);
            });
        }
    }
}
