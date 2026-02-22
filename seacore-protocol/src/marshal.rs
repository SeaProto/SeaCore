use std::net::SocketAddr;

use bytes::BufMut;

use crate::protocol::*;

impl Header {
    /// Write the header to a byte buffer
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(VERSION);
        buf.put_u8(self.type_code());
        match self {
            Self::Authenticate(auth) => auth.write(buf),
            Self::Connect(conn) => conn.write(buf),
            Self::Packet(pkt) => pkt.write(buf),
            Self::Dissociate(dissoc) => dissoc.write(buf),
            Self::Heartbeat(_) => {}
            Self::Ping(ping) => ping.write(buf),
        }
    }

    /// Async write the header to an AsyncWrite stream
    pub async fn async_marshal(&self, writer: &mut (impl tokio::io::AsyncWriteExt + Unpin)) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(self.len());
        self.write(&mut buf);
        writer.write_all(&buf).await
    }
}

impl Authenticate {
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.uuid().as_bytes());
        buf.put_u64(self.timestamp());
        buf.put_slice(&self.token());
    }
}

impl Connect {
    pub fn write(&self, buf: &mut impl BufMut) {
        self.addr().write(buf);
    }
}

impl Packet {
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
        buf.put_u16(self.pkt_id());
        buf.put_u8(self.frag_total());
        buf.put_u8(self.frag_id());
        buf.put_u16(self.size());
        self.addr().write(buf);
    }
}

impl Dissociate {
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
    }
}

impl Ping {
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.seq_id());
        buf.put_u64(self.timestamp());
    }
}

impl Address {
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.type_code());
        match self {
            Self::None => {}
            Self::DomainAddress(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }
    }
}
