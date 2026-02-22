#!/usr/bin/env python3
"""
SeaCore UDP Proxy Integration Test

Tests SOCKS5 UDP ASSOCIATE through the SeaCore proxy by performing a DNS query.
Usage: python test_udp_proxy.py [socks5_host] [socks5_port]
"""

import socket
import struct
import sys
import time

SOCKS5_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SOCKS5_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 10800
DNS_SERVER = "8.8.8.8"
DNS_PORT = 53
DOMAIN = "www.example.com"

def build_dns_query(domain: str) -> bytes:
    """Build a simple DNS A record query."""
    transaction_id = b'\x12\x34'
    flags = b'\x01\x00'  # Standard query, recursion desired
    questions = b'\x00\x01'
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'

    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

    # Build question section
    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    qtype = b'\x00\x01'   # A record
    qclass = b'\x00\x01'  # IN class

    return header + qname + qtype + qclass


def socks5_udp_associate(host: str, port: int):
    """
    Perform SOCKS5 handshake and UDP ASSOCIATE request.
    Returns (tcp_sock, relay_addr, relay_port).
    """
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10)
    tcp.connect((host, port))

    # Handshake: VER=5, NMETHODS=1, METHOD=0 (no auth)
    tcp.sendall(b'\x05\x01\x00')
    resp = tcp.recv(2)
    if resp != b'\x05\x00':
        raise Exception(f"SOCKS5 handshake failed: {resp.hex()}")

    # UDP ASSOCIATE: VER=5, CMD=3, RSV=0, ATYP=1, DST.ADDR=0.0.0.0, DST.PORT=0
    tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    reply = tcp.recv(10)
    if len(reply) < 10 or reply[1] != 0x00:
        raise Exception(f"UDP ASSOCIATE failed: {reply.hex()}")

    # Parse relay address from reply
    atyp = reply[3]
    if atyp == 0x01:  # IPv4
        relay_ip = socket.inet_ntoa(reply[4:8])
        relay_port = struct.unpack('!H', reply[8:10])[0]
    else:
        raise Exception(f"Unexpected ATYP: {atyp}")

    # If relay IP is 0.0.0.0, use the SOCKS5 server address
    if relay_ip == '0.0.0.0':
        relay_ip = host

    return tcp, relay_ip, relay_port


def build_socks5_udp_packet(dst_addr: str, dst_port: int, data: bytes) -> bytes:
    """Build a SOCKS5 UDP request header + data."""
    # RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
    header = b'\x00\x00'  # RSV
    header += b'\x00'      # FRAG
    header += b'\x01'      # ATYP = IPv4
    header += socket.inet_aton(dst_addr)
    header += struct.pack('!H', dst_port)
    return header + data


def parse_socks5_udp_response(data: bytes):
    """Parse SOCKS5 UDP response, return (src_addr, src_port, payload)."""
    if len(data) < 10:
        return None, None, None
    atyp = data[3]
    if atyp == 0x01:
        src_addr = socket.inet_ntoa(data[4:8])
        src_port = struct.unpack('!H', data[8:10])[0]
        payload = data[10:]
    elif atyp == 0x03:
        addr_len = data[4]
        src_addr = data[5:5+addr_len].decode()
        src_port = struct.unpack('!H', data[5+addr_len:7+addr_len])[0]
        payload = data[7+addr_len:]
    else:
        return None, None, data[4:]
    return src_addr, src_port, payload


def parse_dns_response(data: bytes) -> list:
    """Parse DNS response and extract A records."""
    if len(data) < 12:
        return []
    
    # Skip header (12 bytes)
    answer_count = struct.unpack('!H', data[6:8])[0]
    
    # Skip question section
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += 1 + data[offset]
    offset += 5  # null byte + QTYPE(2) + QCLASS(2)
    
    results = []
    for _ in range(answer_count):
        if offset + 12 > len(data):
            break
        # Skip name (pointer or labels)
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        
        rtype = struct.unpack('!H', data[offset:offset+2])[0]
        rdlength = struct.unpack('!H', data[offset+8:offset+10])[0]
        offset += 10
        
        if rtype == 1 and rdlength == 4:  # A record
            ip = socket.inet_ntoa(data[offset:offset+4])
            results.append(ip)
        offset += rdlength
    
    return results


def main():
    print(f"=== SeaCore UDP Proxy Test ===")
    print(f"SOCKS5 Proxy: {SOCKS5_HOST}:{SOCKS5_PORT}")
    print(f"DNS Query: {DOMAIN} -> {DNS_SERVER}:{DNS_PORT}")
    print()

    # Step 1: SOCKS5 UDP ASSOCIATE
    print("[1] Establishing SOCKS5 UDP ASSOCIATE...")
    try:
        tcp_sock, relay_ip, relay_port = socks5_udp_associate(SOCKS5_HOST, SOCKS5_PORT)
        print(f"    ✓ UDP relay at {relay_ip}:{relay_port}")
    except Exception as e:
        print(f"    ✗ FAILED: {e}")
        return 1

    # Step 2: Send DNS query through the UDP relay
    print(f"[2] Sending DNS query for {DOMAIN}...")
    dns_query = build_dns_query(DOMAIN)
    udp_packet = build_socks5_udp_packet(DNS_SERVER, DNS_PORT, dns_query)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(10)
    try:
        udp_sock.sendto(udp_packet, (relay_ip, relay_port))
        print(f"    ✓ Sent {len(udp_packet)} bytes to relay")
    except Exception as e:
        print(f"    ✗ Send FAILED: {e}")
        tcp_sock.close()
        return 1

    # Step 3: Receive DNS response
    print("[3] Waiting for DNS response...")
    try:
        resp_data, _ = udp_sock.recvfrom(4096)
        src_addr, src_port, dns_response = parse_socks5_udp_response(resp_data)
        print(f"    ✓ Received {len(resp_data)} bytes from {src_addr}:{src_port}")
    except socket.timeout:
        print("    ✗ TIMEOUT waiting for response")
        tcp_sock.close()
        udp_sock.close()
        return 1
    except Exception as e:
        print(f"    ✗ Receive FAILED: {e}")
        tcp_sock.close()
        udp_sock.close()
        return 1

    # Step 4: Parse DNS response
    print("[4] Parsing DNS response...")
    if dns_response:
        ips = parse_dns_response(dns_response)
        if ips:
            for ip in ips:
                print(f"    ✓ {DOMAIN} -> {ip}")
            print()
            print("=== UDP PROXY TEST PASSED ===")
            result = 0
        else:
            print(f"    ⚠ No A records found, but got response ({len(dns_response)} bytes)")
            print(f"    Response hex: {dns_response[:32].hex()}")
            result = 0  # Still a pass - we got a response through the proxy
    else:
        print("    ✗ No DNS payload in response")
        result = 1

    # Cleanup
    udp_sock.close()
    tcp_sock.close()
    return result


if __name__ == "__main__":
    sys.exit(main())
