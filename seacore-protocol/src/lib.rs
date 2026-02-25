//! SeaCore Protocol - Core library
//!
//! This crate provides the protocol definitions, serialization, connection
//! model, and QUIC integration for the SeaCore proxy protocol.
//!
//! SeaCore combines TUIC's QUIC-native multiplexed architecture with
//! VLESS/Reality's anti-censorship capabilities.

pub mod marshal;
pub mod model;
pub mod protocol;
pub mod quic;
pub mod reality;
pub mod unmarshal;

pub use protocol::{
    Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, Ping, VERSION,
};
pub use unmarshal::UnmarshalError;
