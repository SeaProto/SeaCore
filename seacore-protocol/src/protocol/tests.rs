#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use uuid::Uuid;

    use crate::protocol::*;

    #[test]
    fn test_address_ipv4_serialization() {
        let addr = Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080));
        let mut buf = Vec::new();
        addr.write(&mut buf);
        assert_eq!(addr.len(), buf.len());

        let mut cursor = Cursor::new(buf);
        let decoded = Address::unmarshal(&mut cursor).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_ipv6_serialization() {
        let addr = Address::SocketAddress(SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(), 443));
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
}
