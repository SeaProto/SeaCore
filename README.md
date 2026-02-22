# SeaCore Proxy

SeaCore is a simple, high-performance UDP/TCP proxy building on top of QUIC to multiplex connections efficiently across an inherently encrypted channel.

## Compilation

The project is built as a unified Rust workspace combining `seacore` and its underlying `seacore-protocol`.
Build the project using standard Cargo commands:

```bash
cargo build --release
```

## Running SeaCore

SeaCore uses JSON configuration files and subcommands to determine whether it runs as a Client or Server.

### Server Mode

To start the server, you need a configuration file (e.g., `server.json`):

```json
{
  "listen": "0.0.0.0:4430",
  "users": [
    {
      "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "password": "my-secure-password"
    }
  ]
}
```

Start the server process:
```bash
./target/release/seacore server -c server.json
```

### Client Mode

To start the client, you need a configuration file (e.g., `client.json`):

```json
{
    "server": "127.0.0.1:4430",
    "server_name": "localhost",
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "password": "my-secure-password",
    "socks5_listen": "127.0.0.1:10800"
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
curl --socks5 127.0.0.1:10800 https://example.com
```

### UDP Testing

You can use standard SOCKS-compatible UDP tools to route DNS or internal UDP requests over SeaCore.
If you have a Python environment, you can use the built-in test script to verify UDP associative proxies:

```bash
python test_udp.py
```
*(Make sure `test_udp.py` is configured with the correct `socks_port` as defined in your `client.json`)*
