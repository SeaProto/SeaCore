# Ecosystem Interop and Operations Runbook

This document provides practical chain templates and troubleshooting guidance for operating SeaCore with common proxy stacks.

## 1) SeaCore Baseline Templates

### Server (`server.json`)

```json
{
  "listen": "0.0.0.0:4430",
  "handshake_timeout_secs": 5,
  "connection_idle_timeout_secs": 10,
  "half_close_timeout_secs": 2,
  "max_quic_connections": 1024,
  "max_tcp_connections": 1024,
  "max_udp_associations_per_connection": 1024,
  "max_bi_stream_tasks_per_connection": 256,
  "metrics_listen": "127.0.0.1:9100",
  "users": [
    {
      "uuid": "your-uuid",
      "password": "your-password"
    }
  ],
  "reality": {
    "dest": "www.apple.com:443",
    "server_names": ["www.apple.com"],
    "private_key": "base64-32-byte-private-key",
    "short_ids": ["0011223344556677"]
  }
}
```

### Client (`client.json`)

```json
{
  "server": "server-ip:4430",
  "transport": "auto",
  "uuid": "your-uuid",
  "password": "your-password",
  "socks5_listen": "127.0.0.1:10800",
  "insecure_skip_verify": false,
  "server_cert_sha256": "optional-cert-pin",
  "handshake_timeout_secs": 5,
  "connection_idle_timeout_secs": 10,
  "half_close_timeout_secs": 2,
  "metrics_listen": "127.0.0.1:9101",
  "reality": {
    "profile": "chrome",
    "server_name": "www.apple.com",
    "public_key": "base64-32-byte-public-key",
    "short_id": "0011223344556677"
  }
}
```

## 2) sing-box Chain Template

Use SeaCore client as upstream SOCKS5 from sing-box.

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "to-seacore",
      "server": "127.0.0.1",
      "server_port": 10800,
      "version": "5"
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "to-seacore"
  }
}
```

## 3) Xray Chain Template

Use SeaCore client as SOCKS outbound in Xray.

```json
{
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "seacore-out",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 10800
          }
        ]
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "seacore-out"
      }
    ]
  }
}
```

## 4) Deployment Checklist

- Keep `metrics_listen` on loopback and scrape through local agent.
- Keep `insecure_skip_verify=false` in production.
- Use 16-hex-char REALITY `short_id` values (exactly 8 bytes).
- Keep process/file descriptor limits aligned with `max_*` caps.
- Run `cargo test -p seacore-protocol` and `python Test/test_matrix.py` before rollout.

## 5) Troubleshooting Playbook

| Symptom | Likely cause | Verify | Action |
| --- | --- | --- | --- |
| Handshake timeout spikes | path MTU / blocked UDP / wrong SNI | client logs + `seacore_client_connect_attempts_total` | switch to `transport: "tcp"` or `"auto"`, verify `reality.server_name` |
| Frequent fallback attempts | UDP path unstable | `seacore_client_fallback_attempts_total` | tune network path, keep `transport: "auto"` |
| Auth failures | uuid/password mismatch or clock skew | `seacore_server_auth_failures_total` + server logs | align credentials, sync time (NTP) |
| UDP intermittent drops | idle assoc cleanup or NAT churn | `seacore_server_udp_assoc_active` trends | increase `idle_session_timeout_secs`, validate NAT behavior with `test_matrix.py` |
| Reconnect storms | server restarts or network flap | `seacore_client_reconnects_total` | inspect server uptime, adjust restart policy and health checks |

## 6) Quick Verification Commands

```bash
curl -x socks5h://127.0.0.1:10800 https://example.com
curl http://127.0.0.1:9100/metrics
curl http://127.0.0.1:9101/metrics
```
