#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use uuid::Uuid;

    use crate::protocol::*;

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    fn lcg_fill(state: &mut u64, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = (lcg_next(state) >> 56) as u8;
        }
    }

    fn random_domain(state: &mut u64) -> String {
        let len = (lcg_next(state) % 20 + 3) as usize;
        let mut domain = String::with_capacity(len + 4);
        for i in 0..len {
            let mut c = (b'a' + (lcg_next(state) % 26) as u8) as char;
            if i % 7 == 3 {
                c = (b'0' + (lcg_next(state) % 10) as u8) as char;
            }
            domain.push(c);
        }
        domain.push_str(".test");
        domain
    }

    fn random_address(state: &mut u64) -> Address {
        match lcg_next(state) % 4 {
            0 => Address::None,
            1 => {
                let ip = Ipv4Addr::new(
                    (lcg_next(state) & 0xff) as u8,
                    (lcg_next(state) & 0xff) as u8,
                    (lcg_next(state) & 0xff) as u8,
                    (lcg_next(state) & 0xff) as u8,
                );
                let port = (lcg_next(state) & 0xffff) as u16;
                Address::SocketAddress(SocketAddr::new(ip.into(), port))
            }
            2 => {
                let mut octets = [0u8; 16];
                lcg_fill(state, &mut octets);
                let ip = Ipv6Addr::from(octets);
                let port = (lcg_next(state) & 0xffff) as u16;
                Address::SocketAddress(SocketAddr::new(ip.into(), port))
            }
            _ => {
                let port = (lcg_next(state) & 0xffff) as u16;
                Address::DomainAddress(random_domain(state), port)
            }
        }
    }

    fn random_header(state: &mut u64) -> Header {
        match lcg_next(state) % 6 {
            0 => {
                let mut uuid_bytes = [0u8; 16];
                let mut token = [0u8; 32];
                lcg_fill(state, &mut uuid_bytes);
                lcg_fill(state, &mut token);
                let timestamp = lcg_next(state);
                Header::Authenticate(Authenticate::new(
                    Uuid::from_bytes(uuid_bytes),
                    timestamp,
                    token,
                ))
            }
            1 => Header::Connect(Connect::new(random_address(state))),
            2 => {
                let assoc_id = (lcg_next(state) & 0xffff) as u16;
                let pkt_id = (lcg_next(state) & 0xffff) as u16;
                let frag_total = ((lcg_next(state) % 15) + 1) as u8;
                let frag_id = (lcg_next(state) % frag_total as u64) as u8;
                let size = (lcg_next(state) % 4096) as u16;
                Header::Packet(Packet::new(
                    assoc_id,
                    pkt_id,
                    frag_total,
                    frag_id,
                    size,
                    random_address(state),
                ))
            }
            3 => {
                let assoc_id = (lcg_next(state) & 0xffff) as u16;
                Header::Dissociate(Dissociate::new(assoc_id))
            }
            4 => Header::Heartbeat(Heartbeat::new()),
            _ => {
                let seq_id = (lcg_next(state) & 0xffff) as u16;
                let timestamp = lcg_next(state);
                Header::Ping(Ping::new(seq_id, timestamp))
            }
        }
    }

    fn assert_header_eq(expected: &Header, actual: &Header) {
        match (expected, actual) {
            (Header::Authenticate(a), Header::Authenticate(b)) => {
                assert_eq!(a.uuid(), b.uuid());
                assert_eq!(a.timestamp(), b.timestamp());
                assert_eq!(a.token(), b.token());
            }
            (Header::Connect(a), Header::Connect(b)) => {
                assert_eq!(a.addr(), b.addr());
            }
            (Header::Packet(a), Header::Packet(b)) => {
                assert_eq!(a.assoc_id(), b.assoc_id());
                assert_eq!(a.pkt_id(), b.pkt_id());
                assert_eq!(a.frag_total(), b.frag_total());
                assert_eq!(a.frag_id(), b.frag_id());
                assert_eq!(a.size(), b.size());
                assert_eq!(a.addr(), b.addr());
            }
            (Header::Dissociate(a), Header::Dissociate(b)) => {
                assert_eq!(a.assoc_id(), b.assoc_id());
            }
            (Header::Heartbeat(_), Header::Heartbeat(_)) => {}
            (Header::Ping(a), Header::Ping(b)) => {
                assert_eq!(a.seq_id(), b.seq_id());
                assert_eq!(a.timestamp(), b.timestamp());
            }
            _ => panic!("header kind mismatch: expected {expected}, got {actual}"),
        }
    }

    #[test]
    fn test_address_ipv4_serialization() {
        let addr =
            Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080));
        let mut buf = Vec::new();
        addr.write(&mut buf);
        assert_eq!(addr.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Address::unmarshal(&mut cursor).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_ipv6_serialization() {
        let addr = Address::SocketAddress(SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(),
            443,
        ));
        let mut buf = Vec::new();
        addr.write(&mut buf);
        assert_eq!(addr.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Address::unmarshal(&mut cursor).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_domain_serialization() {
        let addr = Address::DomainAddress("example.com".to_string(), 443);
        let mut buf = Vec::new();
        addr.write(&mut buf);
        assert_eq!(addr.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Address::unmarshal(&mut cursor).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_none_serialization() {
        let addr = Address::None;
        let mut buf = Vec::new();
        addr.write(&mut buf);
        assert_eq!(addr.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Address::unmarshal(&mut cursor).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_authenticate_serialization() {
        let uuid = Uuid::new_v4();
        let timestamp = 1672531200_u64; // arbitrary timestamp
        let token = [0x42; 32];
        let auth = Authenticate::new(uuid, timestamp, token);
        let header = Header::Authenticate(auth);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Authenticate(decoded_auth) = decoded {
            assert_eq!(uuid, decoded_auth.uuid());
            assert_eq!(timestamp, decoded_auth.timestamp());
            assert_eq!(token, decoded_auth.token());
        } else {
            panic!("Expected Authenticate header");
        }
    }

    #[test]
    fn test_connect_serialization() {
        let addr = Address::DomainAddress("seacore.io".to_string(), 4430);
        let connect = Connect::new(addr.clone());
        let header = Header::Connect(connect);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Connect(decoded_conn) = decoded {
            assert_eq!(&addr, decoded_conn.addr());
        } else {
            panic!("Expected Connect header");
        }
    }

    #[test]
    fn test_packet_serialization() {
        let addr = Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53));
        let packet = Packet::new(1234, 5678, 4, 1, 1024, addr.clone());
        let header = Header::Packet(packet);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Packet(decoded_pkt) = decoded {
            assert_eq!(1234, decoded_pkt.assoc_id());
            assert_eq!(5678, decoded_pkt.pkt_id());
            assert_eq!(4, decoded_pkt.frag_total());
            assert_eq!(1, decoded_pkt.frag_id());
            assert_eq!(1024, decoded_pkt.size());
            assert_eq!(&addr, decoded_pkt.addr());
        } else {
            panic!("Expected Packet header");
        }
    }

    #[test]
    fn test_dissociate_serialization() {
        let dissoc = Dissociate::new(9999);
        let header = Header::Dissociate(dissoc);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Dissociate(decoded_dissoc) = decoded {
            assert_eq!(9999, decoded_dissoc.assoc_id());
        } else {
            panic!("Expected Dissociate header");
        }
    }

    #[test]
    fn test_heartbeat_serialization() {
        let hb = Heartbeat::new();
        let header = Header::Heartbeat(hb);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Heartbeat(_) = decoded {
            // successful
        } else {
            panic!("Expected Heartbeat header");
        }
    }

    #[test]
    fn test_ping_serialization() {
        let ping = Ping::new(42, 1234567890);
        let header = Header::Ping(ping);

        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(header.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Header::unmarshal(&mut cursor).unwrap();
        if let Header::Ping(decoded_ping) = decoded {
            assert_eq!(42, decoded_ping.seq_id());
            assert_eq!(1234567890, decoded_ping.timestamp());
        } else {
            panic!("Expected Ping header");
        }
    }

    #[test]
    fn deterministic_protocol_roundtrip_matrix() {
        let mut state = 0x5EA5_C0DE_F00D_BAAD;

        for _ in 0..2048 {
            let header = random_header(&mut state);
            let mut buf = Vec::new();
            header.write(&mut buf);

            let mut cursor = Cursor::new(buf);
            let decoded = Header::unmarshal(&mut cursor).expect("roundtrip decode should succeed");
            assert_header_eq(&header, &decoded);
            assert_eq!(cursor.position() as usize, cursor.get_ref().len());
        }
    }

    #[test]
    fn protocol_fuzz_unmarshal_never_panics() {
        let mut state = 0xA11C_EC0F_EE12_3123;

        for case_idx in 0..6000 {
            let len = (lcg_next(&mut state) % 384) as usize;
            let mut input = vec![0u8; len];
            lcg_fill(&mut state, &mut input);

            if !input.is_empty() {
                input[0] = if case_idx % 3 == 0 { VERSION } else { input[0] };
                if input.len() > 1 && case_idx % 5 == 0 {
                    input[1] = (lcg_next(&mut state) % 8) as u8;
                }
            }

            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut cursor = Cursor::new(input);
                let _ = Header::unmarshal(&mut cursor);
            }));

            assert!(result.is_ok(), "fuzz case {} triggered panic", case_idx);
        }
    }
}
