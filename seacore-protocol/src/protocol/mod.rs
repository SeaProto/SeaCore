use std::fmt::{Display, Formatter, Result as FmtResult};

pub mod address;
pub mod authenticate;
pub mod connect;
pub mod dissociate;
pub mod heartbeat;
pub mod packet;
pub mod ping;
pub mod tests;

pub use self::{
    address::Address,
    authenticate::Authenticate,
    connect::Connect,
    dissociate::Dissociate,
    heartbeat::Heartbeat,
    packet::Packet,
    ping::Ping,
};

/// The SeaCore protocol version
pub const VERSION: u8 = 0x01;

/// The command header for negotiating tasks
///
/// ```plain
/// +-----+------+----------+
/// | VER | TYPE |   OPT    |
/// +-----+------+----------+
/// |  1  |  1   | Variable |
/// +-----+------+----------+
/// ```
///
/// ## Command Types
///
/// - `0x00` - `Authenticate` - authenticate the multiplexed connection
/// - `0x01` - `Connect` - establish a TCP relay
/// - `0x02` - `Packet` - relay a (fragmented) UDP packet
/// - `0x03` - `Dissociate` - terminate a UDP relaying session
/// - `0x04` - `Heartbeat` - keep the QUIC connection alive
/// - `0x05` - `Ping` - measure round-trip latency
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Header {
    Authenticate(Authenticate),
    Connect(Connect),
    Packet(Packet),
    Dissociate(Dissociate),
    Heartbeat(Heartbeat),
    Ping(Ping),
}

impl Header {
    pub const TYPE_CODE_AUTHENTICATE: u8 = Authenticate::type_code();
    pub const TYPE_CODE_CONNECT: u8 = Connect::type_code();
    pub const TYPE_CODE_PACKET: u8 = Packet::type_code();
    pub const TYPE_CODE_DISSOCIATE: u8 = Dissociate::type_code();
    pub const TYPE_CODE_HEARTBEAT: u8 = Heartbeat::type_code();
    pub const TYPE_CODE_PING: u8 = Ping::type_code();

    pub const fn type_code(&self) -> u8 {
        match self {
            Self::Authenticate(_) => Authenticate::type_code(),
            Self::Connect(_) => Connect::type_code(),
            Self::Packet(_) => Packet::type_code(),
            Self::Dissociate(_) => Dissociate::type_code(),
            Self::Heartbeat(_) => Heartbeat::type_code(),
            Self::Ping(_) => Ping::type_code(),
        }
    }

    /// Returns the serialized length of the command (including VER + TYPE)
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        2 + match self {
            Self::Authenticate(auth) => auth.len(),
            Self::Connect(conn) => conn.len(),
            Self::Packet(pkt) => pkt.len(),
            Self::Dissociate(dissoc) => dissoc.len(),
            Self::Heartbeat(hb) => hb.len(),
            Self::Ping(ping) => ping.len(),
        }
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Authenticate(_) => write!(f, "Authenticate"),
            Self::Connect(c) => write!(f, "Connect({})", c.addr()),
            Self::Packet(p) => write!(f, "Packet(assoc={}, pkt={})", p.assoc_id(), p.pkt_id()),
            Self::Dissociate(d) => write!(f, "Dissociate(assoc={})", d.assoc_id()),
            Self::Heartbeat(_) => write!(f, "Heartbeat"),
            Self::Ping(p) => write!(f, "Ping(seq={})", p.seq_id()),
        }
    }
}
