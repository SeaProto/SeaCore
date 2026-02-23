# SeaCore

![SeaCore Logo](Preview/logo_readme.png)

SeaCore is a high-performance, aggressively stealthy stealth proxy protocol and toolset built in Rust. It multiplexes TCP and UDP traffic natively over **HTTP/3 (QUIC)** while strictly emulating real-world browser fingerprints. 

To overcome active probing and Deep Packet Inspection (DPI), SeaCore incorporates a **REALITY-inspired** fallback architecture. To an unauthorized observer or scanner, SeaCore behaves 100% identically to a major tech company's CDN node.

## Features

*   **Multi-Protocol Inbound**: Built-in SOCKS5 and SOCKS4/SOCKS4a support with automatic protocol detection on the inbound port.
*   **Deep QUIC Masquerading (craftls)**: Emulates Chrome and Firefox's EXACT TLS 1.3 `ClientHello` structures, including GREASE extensions, padding, and ALPN variations.
*   **REALITY Fallback (Zero Active Probing Signature)**: The server acts as a transparent reverse proxy for a configured white-list domain (e.g., `apple.com`). Unauthorized QUIC/TCP connections are seamlessly relayed to the real destination without breaking the TLS handshake, fully masking the proxy's presence.
*   **Stable 1:1 TCP Reality Mapping**: When using TCP transport, SeaCore establishes a fresh, independent Reality-authenticated connection for *every* SOCKS5/SOCKS4 TCP request. This perfectly mimics real web-browsing behavior and defeats the statistical traffic analysis that often targets single, long-lived multiplexed connections.
*   **X25519 Authentication Token**: Uses raw elliptic-curve Diffie-Hellman to encrypt the authentication payload directly into the TLS `SessionID`, leaving absolutely zero protocol metadata on the wire.
*   **Pure Transparent TCP Fallback**: Listens on both TCP and UDP. Incoming TCP scans are blindly piped to the REALITY destination, ensuring port scanners see a flawless HTTPS/2 Web Server, avoiding "UDP-only" heuristic bans.
*   **Hybrid Transport Support**: Configure `transport` as `"udp"`, `"tcp"`, or `"auto"` to adapt to different network censorship environments (e.g., UDP QoS/blocking in China or Iran).
*   **Traffic Camouflage & H3 SETTINGS**: Injects randomized heartbeat datagrams and HTTP/3 initialization frames to defeat Machine Learning packet-size and timing analysis models.
*   **Reconnect Handshake Refresh**: After connection loss, client reconnects with a fresh TCP/TLS/REALITY auth context, avoiding stale-session handshake corruption.
*   **Relay Teardown Hardening**: On reset/abort paths (including `10054`), relay exits quickly with bounded shutdown to prevent long-lived CPU buildup.
*   **Configurable Idle Session Janitor**: Client and server both support idle route cleanup via `idle_session_check_interval_secs`, `idle_session_timeout_secs`, and `min_idle_sessions`.

## Compilation

The project is built as a unified Rust workspace combining `seacore` and its underlying `seacore-protocol`.
Build the project using standard Cargo commands:

```bash
cargo build --release
```

## Running SeaCore

SeaCore uses JSON configuration files and subcommands to determine whether it runs as a Client or Server.

### Server Mode

To start the server, you need a configuration file (`server.json`) and a generated REALITY Private Key.

*(You can use the provided `Test/generate_reality_keys.ps1` script to generate a secure X25519 keypair).*

```json
{
  "listen": "0.0.0.0:4430",
  "transport": "auto",
  "idle_session_check_interval_secs": 5,
  "idle_session_timeout_secs": 10,
  "min_idle_sessions": 0,
  "users": [
    {
      "uuid": "your-uuid-here",
      "password": "my-secure-password"
    }
  ],
  "reality": {
    "private_key": "base64_encoded_private_key_here",
    "short_ids": ["12345678", "abcdef12"],
    "server_names": ["www.apple.com", "apple.com"],
    "dest": "www.apple.com:443"
  }
}
```

Start the server process:
```bash
./target/release/seacore server -c server.json
```

### Client Mode

To start the client, you need a corresponding `client.json` with the matching `public_key`.

```json
{
    "server": "your_server_ip:4430",
    "transport": "udp",
    "idle_session_check_interval_secs": 5,
    "idle_session_timeout_secs": 10,
    "min_idle_sessions": 0,
    "uuid": "your-uuid-here",
    "password": "my-secure-password",
    "socks5_listen": "127.0.0.1:10800",
    "reality": {
        "profile": "chrome",
        "server_name": "www.apple.com",
        "public_key": "base64_encoded_public_key_here",
        "short_id": "12345678"
    }
}
```

Start the client process:
```bash
./target/release/seacore client -c client.json
```

## CPU/Session Tuning

Both client and server accept the same optional idle cleanup parameters:

*   `idle_session_check_interval_secs`: janitor sweep interval (default: `5`)
*   `idle_session_timeout_secs`: idle threshold before relay/assoc cleanup (default: `10`)
*   `min_idle_sessions`: always keep this many most-recent idle sessions (default: `0`)

Recommended baseline for low-resource VPS:

```json
{
  "idle_session_check_interval_secs": 2,
  "idle_session_timeout_secs": 6,
  "min_idle_sessions": 0
}
```

If you chain another local proxy layer (for example Xray -> SeaCore SOCKS), start with the defaults and then lower timeout/check interval gradually to reduce residual idle CPU cost.

## Usage (Proxy Inbound)

Once the client is running, you can connect your applications via the SOCKS inlet (SOCKS5/4/4a) defined in the `client.json` file.

### SOCKS5 Testing

```bash
curl -x socks5h://127.0.0.1:10800 https://example.com
```

### SOCKS4/4a Testing

```bash
# SOCKS4a (Domain resolution)
curl --socks4a 127.0.0.1:10800 https://example.com

# SOCKS4 (IP-only)
curl --socks4 127.0.0.1:10800 http://1.1.1.1
```

### UDP Testing (SOCKS5 only)

You can use standard SOCKS-compatible UDP tools to route DNS or internal UDP requests over SeaCore.
If you have a Python environment, you can use the built-in test script to verify UDP associative proxies:

```bash
python test_udp_proxy.py
```

## Warning
> Most of this project's code was written by AI and may contain security issues. Please use it with caution.  
> AI models used: Gemini, Claude
