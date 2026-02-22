# SeaCore

![SeaCore Logo](Preview/logo_readme.png)

SeaCore is a high-performance, aggressively stealthy stealth proxy protocol and toolset built in Rust. It multiplexes TCP and UDP traffic natively over **HTTP/3 (QUIC)** while strictly emulating real-world browser fingerprints. 

To overcome active probing and Deep Packet Inspection (DPI), SeaCore incorporates a **REALITY-inspired** fallback architecture. To an unauthorized observer or scanner, SeaCore behaves 100% identically to a major tech company's CDN node.

## Features

*   **Deep QUIC Masquerading (craftls)**: Emulates Chrome and Firefox's EXACT TLS 1.3 `ClientHello` structures, including GREASE extensions, padding, and ALPN variations.
*   **REALITY Fallback (Zero Active Probing Signature)**: The server acts as a transparent reverse proxy for a configured white-list domain (e.g., `apple.com`). Unauthorized QUIC/TCP connections are seamlessly relayed to the real destination without breaking the TLS handshake, fully masking the proxy's presence.
*   **X25519 Authentication Token**: Uses raw elliptic-curve Diffie-Hellman to encrypt the authentication payload directly into the TLS `SessionID`, leaving absolutely zero protocol metadata on the wire.
*   **Pure Transparent TCP Fallback**: Listens on both TCP and UDP. Incoming TCP scans are blindly piped to the REALITY destination, ensuring port scanners see a flawless HTTPS/2 Web Server, avoiding "UDP-only" heuristic bans.
*   **Traffic Camouflage & H3 SETTINGS**: Injects randomized heartbeat datagrams and HTTP/3 initialization frames to defeat Machine Learning packet-size and timing analysis models.
*   **Native SOCKS5 Proxy**: Built-in support for proxying TCP and UDP ASSOCIATE traffic transparently to your applications.

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

## Usage (SOCKS5 Proxy)

Once the client is running, you can connect your applications via the SOCKS5 inlet defined in the `client.json` file.

### TCP Testing

```bash
curl -x socks5h://127.0.0.1:10800 https://example.com
```

### UDP Testing

You can use standard SOCKS-compatible UDP tools to route DNS or internal UDP requests over SeaCore.
If you have a Python environment, you can use the built-in test script to verify UDP associative proxies:

```bash
python test_udp_proxy.py
```

## Warning
> Most of this project's code was written by AI and may contain security issues. Please use it with caution.  
> AI models used: Gemini, Claude
