use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

#[derive(Default)]
pub struct ServerMetrics {
    active_connections: AtomicI64,
    auth_attempts_total: AtomicU64,
    auth_failures_total: AtomicU64,
    reality_requests_total: AtomicU64,
    reality_fallback_total: AtomicU64,
    udp_assoc_active: AtomicI64,
    udp_assoc_created_total: AtomicU64,
    udp_assoc_closed_total: AtomicU64,
}

impl ServerMetrics {
    pub fn track_active_connection(self: &Arc<Self>) -> ActiveConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveConnectionGuard {
            metrics: self.clone(),
        }
    }

    pub fn record_auth_attempt(&self, success: bool) {
        self.auth_attempts_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn inc_reality_request(&self) {
        self.reality_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reality_fallback(&self) {
        self.reality_fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_udp_assoc_created(&self) {
        self.udp_assoc_created_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_udp_assoc_closed(&self, by: u64) {
        if by > 0 {
            self.udp_assoc_closed_total.fetch_add(by, Ordering::Relaxed);
        }
    }

    pub fn inc_udp_assoc_active(&self) {
        self.udp_assoc_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_udp_assoc_active(&self, by: i64) {
        if by > 0 {
            self.udp_assoc_active.fetch_sub(by, Ordering::Relaxed);
        }
    }

    pub fn render_prometheus(&self) -> String {
        let active_connections = self.active_connections.load(Ordering::Relaxed).max(0);
        let auth_attempts_total = self.auth_attempts_total.load(Ordering::Relaxed);
        let auth_failures_total = self.auth_failures_total.load(Ordering::Relaxed);
        let reality_requests_total = self.reality_requests_total.load(Ordering::Relaxed);
        let reality_fallback_total = self.reality_fallback_total.load(Ordering::Relaxed);
        let udp_assoc_active = self.udp_assoc_active.load(Ordering::Relaxed).max(0);
        let udp_assoc_created_total = self.udp_assoc_created_total.load(Ordering::Relaxed);
        let udp_assoc_closed_total = self.udp_assoc_closed_total.load(Ordering::Relaxed);

        format!(
            "# HELP seacore_server_active_connections Current authenticated active connections.\n\
# TYPE seacore_server_active_connections gauge\n\
seacore_server_active_connections {}\n\
# HELP seacore_server_auth_attempts_total Total authentication attempts.\n\
# TYPE seacore_server_auth_attempts_total counter\n\
seacore_server_auth_attempts_total {}\n\
# HELP seacore_server_auth_failures_total Total authentication failures.\n\
# TYPE seacore_server_auth_failures_total counter\n\
seacore_server_auth_failures_total {}\n\
# HELP seacore_server_reality_requests_total Total TCP REALITY pre-auth requests inspected.\n\
# TYPE seacore_server_reality_requests_total counter\n\
seacore_server_reality_requests_total {}\n\
# HELP seacore_server_reality_fallback_total Total TCP REALITY requests routed to fallback.\n\
# TYPE seacore_server_reality_fallback_total counter\n\
seacore_server_reality_fallback_total {}\n\
# HELP seacore_server_udp_assoc_active Current active UDP associations.\n\
# TYPE seacore_server_udp_assoc_active gauge\n\
seacore_server_udp_assoc_active {}\n\
# HELP seacore_server_udp_assoc_created_total Total created UDP associations.\n\
# TYPE seacore_server_udp_assoc_created_total counter\n\
seacore_server_udp_assoc_created_total {}\n\
# HELP seacore_server_udp_assoc_closed_total Total closed UDP associations.\n\
# TYPE seacore_server_udp_assoc_closed_total counter\n\
seacore_server_udp_assoc_closed_total {}\n",
            active_connections,
            auth_attempts_total,
            auth_failures_total,
            reality_requests_total,
            reality_fallback_total,
            udp_assoc_active,
            udp_assoc_created_total,
            udp_assoc_closed_total,
        )
    }
}

pub struct ActiveConnectionGuard {
    metrics: Arc<ServerMetrics>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct ClientMetrics {
    reconnects_total: AtomicU64,
    connect_attempts_total: AtomicU64,
    connect_success_total: AtomicU64,
    fallback_attempts_total: AtomicU64,
    auth_failures_total: AtomicU64,
}

impl ClientMetrics {
    pub fn inc_reconnects(&self) {
        self.reconnects_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connect_attempts(&self) {
        self.connect_attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connect_success(&self) {
        self.connect_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fallback_attempts(&self) {
        self.fallback_attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_failures(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let reconnects_total = self.reconnects_total.load(Ordering::Relaxed);
        let connect_attempts_total = self.connect_attempts_total.load(Ordering::Relaxed);
        let connect_success_total = self.connect_success_total.load(Ordering::Relaxed);
        let fallback_attempts_total = self.fallback_attempts_total.load(Ordering::Relaxed);
        let auth_failures_total = self.auth_failures_total.load(Ordering::Relaxed);

        format!(
            "# HELP seacore_client_reconnects_total Total reconnect cycles after first attempt.\n\
# TYPE seacore_client_reconnects_total counter\n\
seacore_client_reconnects_total {}\n\
# HELP seacore_client_connect_attempts_total Total connection attempts.\n\
# TYPE seacore_client_connect_attempts_total counter\n\
seacore_client_connect_attempts_total {}\n\
# HELP seacore_client_connect_success_total Total successful authenticated connections.\n\
# TYPE seacore_client_connect_success_total counter\n\
seacore_client_connect_success_total {}\n\
# HELP seacore_client_fallback_attempts_total Total QUIC-to-TCP fallback attempts.\n\
# TYPE seacore_client_fallback_attempts_total counter\n\
seacore_client_fallback_attempts_total {}\n\
# HELP seacore_client_auth_failures_total Total authentication failures.\n\
# TYPE seacore_client_auth_failures_total counter\n\
seacore_client_auth_failures_total {}\n",
            reconnects_total,
            connect_attempts_total,
            connect_success_total,
            fallback_attempts_total,
            auth_failures_total,
        )
    }
}

pub fn spawn_server_exporter(listen: SocketAddr, metrics: Arc<ServerMetrics>) {
    spawn_exporter(listen, "server", move || metrics.render_prometheus());
}

pub fn spawn_client_exporter(listen: SocketAddr, metrics: Arc<ClientMetrics>) {
    spawn_exporter(listen, "client", move || metrics.render_prometheus());
}

fn spawn_exporter<F>(listen: SocketAddr, role: &'static str, render: F)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let render = Arc::new(render);
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(listen).await {
            Ok(listener) => listener,
            Err(e) => {
                warn!(
                    event = "metrics_exporter_bind_failed",
                    role,
                    listen = %listen,
                    error = %e,
                    "failed to bind metrics exporter"
                );
                return;
            }
        };
        info!(
            event = "metrics_exporter_started",
            role,
            listen = %listen,
            "prometheus metrics exporter started"
        );

        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    debug!(
                        event = "metrics_exporter_accept_error",
                        role,
                        error = %e,
                        "failed to accept metrics connection"
                    );
                    continue;
                }
            };

            let render = render.clone();
            tokio::spawn(async move {
                let mut req_buf = [0u8; 1024];
                let n =
                    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut req_buf))
                        .await
                    {
                        Ok(Ok(n)) => n,
                        _ => return,
                    };
                if n == 0 {
                    return;
                }

                let req_line = String::from_utf8_lossy(&req_buf[..n]);
                let first = req_line.lines().next().unwrap_or_default();
                let (status, body) =
                    if first.starts_with("GET /metrics") || first.starts_with("GET / ") {
                        ("200 OK", render())
                    } else {
                        ("404 Not Found", "not found\n".to_string())
                    };
                let content_type = if status == "200 OK" {
                    "text/plain; version=0.0.4; charset=utf-8"
                } else {
                    "text/plain; charset=utf-8"
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    content_type,
                    body.len(),
                    body
                );

                if let Err(e) = stream.write_all(response.as_bytes()).await {
                    debug!(
                        event = "metrics_exporter_write_error",
                        role,
                        peer = %peer,
                        error = %e,
                        "failed to write metrics response"
                    );
                    return;
                }

                let _ = stream.shutdown().await;
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_metrics_render_is_prometheus_compatible() {
        let metrics = Arc::new(ServerMetrics::default());
        let _guard = metrics.track_active_connection();
        metrics.record_auth_attempt(true);
        metrics.record_auth_attempt(false);
        metrics.inc_reality_request();
        metrics.inc_reality_fallback();
        metrics.inc_udp_assoc_created();
        metrics.inc_udp_assoc_active();
        metrics.inc_udp_assoc_closed(1);

        let out = metrics.render_prometheus();
        assert!(out.contains("# TYPE seacore_server_active_connections gauge"));
        assert!(out.contains("seacore_server_auth_attempts_total 2"));
        assert!(out.contains("seacore_server_auth_failures_total 1"));
        assert!(out.contains("seacore_server_reality_requests_total 1"));
        assert!(out.contains("seacore_server_reality_fallback_total 1"));
        assert!(out.contains("seacore_server_udp_assoc_created_total 1"));
        assert!(out.contains("seacore_server_udp_assoc_closed_total 1"));
    }

    #[test]
    fn server_metrics_clamps_negative_gauges_to_zero() {
        let metrics = ServerMetrics::default();
        metrics.dec_udp_assoc_active(3);

        let out = metrics.render_prometheus();
        assert!(
            out.contains("seacore_server_udp_assoc_active 0"),
            "render should never expose negative gauge values"
        );
    }

    #[test]
    fn client_metrics_render_includes_counters() {
        let metrics = ClientMetrics::default();
        metrics.inc_reconnects();
        metrics.inc_connect_attempts();
        metrics.inc_connect_success();
        metrics.inc_fallback_attempts();
        metrics.inc_auth_failures();

        let out = metrics.render_prometheus();
        assert!(out.contains("seacore_client_reconnects_total 1"));
        assert!(out.contains("seacore_client_connect_attempts_total 1"));
        assert!(out.contains("seacore_client_connect_success_total 1"));
        assert!(out.contains("seacore_client_fallback_attempts_total 1"));
        assert!(out.contains("seacore_client_auth_failures_total 1"));
    }
}
