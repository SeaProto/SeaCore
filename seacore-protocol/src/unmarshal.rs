use std::io::{self, Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};


use thiserror::Error;
use uuid::Uuid;

use crate::protocol::*;

/// Errors that can occur during unmarshalling
#[derive(Debug, Error)]
pub enum UnmarshalError {
    #[error("invalid protocol version: {0}")]
    InvalidVersion(u8),
    #[error("invalid command type: {0:#04x}")]
    InvalidCommandType(u8),
    #[error("invalid address type: {0:#04x}")]
    InvalidAddressType(u8),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("insufficient data")]
    InsufficientData,
}

impl Header {
    /// Synchronous unmarshal from a Read source (for datagrams)
    pub fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 2];
        read_exact(reader, &mut buf)?;

        let version = buf[0];
        if version != VERSION {
            return Err(UnmarshalError::InvalidVersion(version));
        }

        let type_code = buf[1];
        match type_code {
            0x00 => Ok(Header::Authenticate(Authenticate::unmarshal(reader)?)),
            0x01 => Ok(Header::Connect(Connect::unmarshal(reader)?)),
            0x02 => Ok(Header::Packet(Packet::unmarshal(reader)?)),
            0x03 => Ok(Header::Dissociate(Dissociate::unmarshal(reader)?)),
            0x04 => Ok(Header::Heartbeat(Heartbeat::new())),
            0x05 => Ok(Header::Ping(Ping::unmarshal(reader)?)),
            _ => Err(UnmarshalError::InvalidCommandType(type_code)),
        }
    }

    /// Async unmarshal from an AsyncRead source (for streams)
    pub async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;

        let version = buf[0];
        if version != VERSION {
            return Err(UnmarshalError::InvalidVersion(version));
        }

        let type_code = buf[1];
        match type_code {
            0x00 => Ok(Header::Authenticate(Authenticate::async_unmarshal(reader).await?)),
            0x01 => Ok(Header::Connect(Connect::async_unmarshal(reader).await?)),
            0x02 => Ok(Header::Packet(Packet::async_unmarshal(reader).await?)),
            0x03 => Ok(Header::Dissociate(Dissociate::async_unmarshal(reader).await?)),
            0x04 => Ok(Header::Heartbeat(Heartbeat::new())),
            0x05 => Ok(Header::Ping(Ping::async_unmarshal(reader).await?)),
            _ => Err(UnmarshalError::InvalidCommandType(type_code)),
        }
    }
}

impl Authenticate {
    fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut uuid_buf = [0u8; 16];
        let mut time_buf = [0u8; 8];
        let mut token_buf = [0u8; 32];
        read_exact(reader, &mut uuid_buf)?;
        read_exact(reader, &mut time_buf)?;
        read_exact(reader, &mut token_buf)?;
        Ok(Self::new(Uuid::from_bytes(uuid_buf), u64::from_be_bytes(time_buf), token_buf))
    }

    async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut uuid_buf = [0u8; 16];
        let mut time_buf = [0u8; 8];
        let mut token_buf = [0u8; 32];
        reader.read_exact(&mut uuid_buf).await?;
        reader.read_exact(&mut time_buf).await?;
        reader.read_exact(&mut token_buf).await?;
        Ok(Self::new(Uuid::from_bytes(uuid_buf), u64::from_be_bytes(time_buf), token_buf))
    }
}

impl Connect {
    fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let addr = Address::unmarshal(reader)?;
        Ok(Self::new(addr))
    }

    async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let addr = Address::async_unmarshal(reader).await?;
        Ok(Self::new(addr))
    }
}

impl Packet {
    fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 8];
        read_exact(reader, &mut buf)?;
        let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
        let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
        let frag_total = buf[4];
        let frag_id = buf[5];
        let size = u16::from_be_bytes([buf[6], buf[7]]);
        let addr = Address::unmarshal(reader)?;
        Ok(Self::new(assoc_id, pkt_id, frag_total, frag_id, size, addr))
    }

    async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
        let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
        let frag_total = buf[4];
        let frag_id = buf[5];
        let size = u16::from_be_bytes([buf[6], buf[7]]);
        let addr = Address::async_unmarshal(reader).await?;
        Ok(Self::new(assoc_id, pkt_id, frag_total, frag_id, size, addr))
    }
}

impl Dissociate {
    fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 2];
        read_exact(reader, &mut buf)?;
        Ok(Self::new(u16::from_be_bytes(buf)))
    }

    async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        Ok(Self::new(u16::from_be_bytes(buf)))
    }
}

impl Ping {
    fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 10];
        read_exact(reader, &mut buf)?;
        let seq_id = u16::from_be_bytes([buf[0], buf[1]]);
        let timestamp = u64::from_be_bytes([buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]);
        Ok(Self::new(seq_id, timestamp))
    }

    async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf).await?;
        let seq_id = u16::from_be_bytes([buf[0], buf[1]]);
        let timestamp = u64::from_be_bytes([buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]);
        Ok(Self::new(seq_id, timestamp))
    }
}

impl Address {
    pub fn unmarshal(reader: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, UnmarshalError> {
        let mut type_buf = [0u8; 1];
        read_exact(reader, &mut type_buf)?;

        match type_buf[0] {
            Self::TYPE_CODE_NONE => Ok(Self::None),
            Self::TYPE_CODE_DOMAIN => {
                let mut len_buf = [0u8; 1];
                read_exact(reader, &mut len_buf)?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                read_exact(reader, &mut domain_buf)?;
                let mut port_buf = [0u8; 2];
                read_exact(reader, &mut port_buf)?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| UnmarshalError::InvalidAddressType(Self::TYPE_CODE_DOMAIN))?;
                Ok(Self::DomainAddress(domain, u16::from_be_bytes(port_buf)))
            }
            Self::TYPE_CODE_IPV4 => {
                let mut addr_buf = [0u8; 4];
                let mut port_buf = [0u8; 2];
                read_exact(reader, &mut addr_buf)?;
                read_exact(reader, &mut port_buf)?;
                let addr = SocketAddrV4::new(
                    Ipv4Addr::from(addr_buf),
                    u16::from_be_bytes(port_buf),
                );
                Ok(Self::SocketAddress(SocketAddr::V4(addr)))
            }
            Self::TYPE_CODE_IPV6 => {
                let mut addr_buf = [0u8; 16];
                let mut port_buf = [0u8; 2];
                read_exact(reader, &mut addr_buf)?;
                read_exact(reader, &mut port_buf)?;
                let addr = SocketAddrV6::new(
                    Ipv6Addr::from(addr_buf),
                    u16::from_be_bytes(port_buf),
                    0,
                    0,
                );
                Ok(Self::SocketAddress(SocketAddr::V6(addr)))
            }
            t => Err(UnmarshalError::InvalidAddressType(t)),
        }
    }

    pub async fn async_unmarshal(
        reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> Result<Self, UnmarshalError> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf).await?;

        match type_buf[0] {
            Self::TYPE_CODE_NONE => Ok(Self::None),
            Self::TYPE_CODE_DOMAIN => {
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                reader.read_exact(&mut domain_buf).await?;
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf).await?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| UnmarshalError::InvalidAddressType(Self::TYPE_CODE_DOMAIN))?;
                Ok(Self::DomainAddress(domain, u16::from_be_bytes(port_buf)))
            }
            Self::TYPE_CODE_IPV4 => {
                let mut addr_buf = [0u8; 4];
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut addr_buf).await?;
                reader.read_exact(&mut port_buf).await?;
                let addr = SocketAddrV4::new(
                    Ipv4Addr::from(addr_buf),
                    u16::from_be_bytes(port_buf),
                );
                Ok(Self::SocketAddress(SocketAddr::V4(addr)))
            }
            Self::TYPE_CODE_IPV6 => {
                let mut addr_buf = [0u8; 16];
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut addr_buf).await?;
                reader.read_exact(&mut port_buf).await?;
                let addr = SocketAddrV6::new(
                    Ipv6Addr::from(addr_buf),
                    u16::from_be_bytes(port_buf),
                    0,
                    0,
                );
                Ok(Self::SocketAddress(SocketAddr::V6(addr)))
            }
            t => Err(UnmarshalError::InvalidAddressType(t)),
        }
    }
}

fn read_exact(reader: &mut Cursor<impl AsRef<[u8]>>, buf: &mut [u8]) -> Result<(), UnmarshalError> {
    Read::read_exact(reader, buf).map_err(|_| UnmarshalError::InsufficientData)
}
