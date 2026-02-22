use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem;
use std::net::SocketAddr;

/// Variable-length field that encodes the network address
///
/// ```plain
/// +------+----------+------+
/// | TYPE |   ADDR   | PORT |
/// +------+----------+------+
/// |  1   | Variable |  2   |
/// +------+----------+------+
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Default)]
pub enum Address {
    #[default]
    None,
    DomainAddress(String, u16),
    SocketAddress(SocketAddr),
}

impl Address {
    pub const TYPE_CODE_DOMAIN: u8 = 0x00;
    pub const TYPE_CODE_IPV4: u8 = 0x01;
    pub const TYPE_CODE_IPV6: u8 = 0x02;
    pub const TYPE_CODE_NONE: u8 = 0xff;

    pub const fn type_code(&self) -> u8 {
        match self {
            Self::None => Self::TYPE_CODE_NONE,
            Self::DomainAddress(..) => Self::TYPE_CODE_DOMAIN,
            Self::SocketAddress(addr) => match addr {
                SocketAddr::V4(_) => Self::TYPE_CODE_IPV4,
                SocketAddr::V6(_) => Self::TYPE_CODE_IPV6,
            },
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        1 + match self {
            Address::None => 0,
            Address::DomainAddress(addr, _) => 1 + addr.len() + 2,
            Address::SocketAddress(SocketAddr::V4(_)) => 4 + 2,
            Address::SocketAddress(SocketAddr::V6(_)) => 16 + 2,
        }
    }

    pub fn take(&mut self) -> Self {
        mem::take(self)
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Self::DomainAddress(_, _))
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::None => 0u16,
            Self::DomainAddress(_, port) => *port,
            Self::SocketAddress(addr) => addr.port(),
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => write!(f, "none"),
            Self::DomainAddress(addr, port) => write!(f, "{addr}:{port}"),
            Self::SocketAddress(addr) => write!(f, "{addr}"),
        }
    }
}
