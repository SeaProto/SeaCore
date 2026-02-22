
use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use quinn::{
    Connection as QuinnConnection, ConnectionError, RecvStream, SendDatagramError, SendStream,
    ClosedStream, ReadExactError,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;
use uuid::Uuid;

use crate::model::{Assemblable, AssembleError, Connection as ConnectionModel, KeyingMaterialExporter as KME};
use crate::protocol::{Address, Header};
use crate::unmarshal::UnmarshalError;

// ── Side markers ───────────────────────────────

pub mod side {
    #[derive(Clone, Debug)]
    pub struct Client;
    #[derive(Clone, Debug)]
    pub struct Server;
}

// ── Connection ─────────────────────────────────

/// The SeaCore Connection wrapping a `quinn::Connection`.
#[derive(Clone)]
pub struct Connection<Side> {
    conn: QuinnConnection,
    model: ConnectionModel<Bytes>,
    _marker: Side,
}

impl<Side> Connection<Side> {
    /// Sends a `Packet` using QUIC datagram (native mode, low latency)
    pub fn packet_native(&self, pkt: impl AsRef<[u8]>, addr: Address, assoc_id: u16) -> Result<(), Error> {
        let Some(max_pkt_size) = self.conn.max_datagram_size() else {
            return Err(Error::SendDatagram(SendDatagramError::Disabled));
        };

        let sender = self.model.send_packet(assoc_id, addr, max_pkt_size);
        for (header, frag) in sender.into_fragments(pkt.as_ref()) {
            let mut buf = BytesMut::with_capacity(header.len() + frag.len());
            header.write(&mut buf);
            buf.put_slice(frag);
            self.conn.send_datagram(Bytes::from(buf))?;
        }
        Ok(())
    }

    /// Sends a `Packet` using QUIC uni-stream (reliable mode)
    pub async fn packet_quic(&self, pkt: impl AsRef<[u8]>, addr: Address, assoc_id: u16) -> Result<(), Error> {
        let sender = self.model.send_packet(assoc_id, addr, u16::MAX as usize);
        for (header, frag) in sender.into_fragments(pkt.as_ref()) {
            let mut send = self.conn.open_uni().await?;
            header.async_marshal(&mut send).await?;
            send.write_all(frag).await?;
            send.finish().map_err(|e| Error::StreamClosed(e))?;
        }
        Ok(())
    }

    /// Sends a `Heartbeat` via QUIC datagram
    pub fn heartbeat(&self) -> Result<(), Error> {
        let header = self.model.send_heartbeat();
        let full_header = Header::Heartbeat(header);
        let mut buf = Vec::with_capacity(full_header.len());
        full_header.write(&mut buf);
        self.conn.send_datagram(Bytes::from(buf))?;
        Ok(())
    }

    /// Sends a `Ping` via QUIC datagram
    pub fn ping(&self, seq_id: u16, timestamp: u64) -> Result<(), Error> {
        let header = self.model.send_ping(seq_id, timestamp);
        let full_header = Header::Ping(header);
        let mut buf = Vec::with_capacity(full_header.len());
        full_header.write(&mut buf);
        self.conn.send_datagram(Bytes::from(buf))?;
        Ok(())
    }

    pub fn task_connect_count(&self) -> u16 {
        self.model.task_connect_count()
    }

    pub fn task_associate_count(&self) -> u16 {
        self.model.task_associate_count()
    }

    pub fn collect_garbage(&self, timeout: Duration) {
        self.model.collect_garbage(timeout);
    }

    fn keying_material_exporter(&self) -> KeyingMaterialExporter {
        KeyingMaterialExporter(self.conn.clone())
    }
}

// ── Client side ────────────────────────────────

impl Connection<side::Client> {
    /// Creates a new client-side connection
    pub fn new(conn: QuinnConnection) -> Self {
        Self {
            conn,
            model: ConnectionModel::new(),
            _marker: side::Client,
        }
    }

    /// Sends an `Authenticate` command via uni-stream
    pub async fn authenticate(&self, uuid: Uuid, password: impl AsRef<[u8]>) -> Result<(), Error> {
        let header_data = self.model.send_authenticate(uuid, password, &self.keying_material_exporter());
        let header = Header::Authenticate(header_data);
        let mut send = self.conn.open_uni().await?;
        header.async_marshal(&mut send).await?;
        send.finish().map_err(|e| Error::StreamClosed(e))?;
        Ok(())
    }

    /// Sends a `Connect` command via bi-stream, returns the stream pair
    pub async fn connect(&self, addr: Address) -> Result<BiStream, Error> {
        let header_data = self.model.send_connect(addr.clone());
        let header = Header::Connect(header_data);
        let (mut send, recv) = self.conn.open_bi().await?;
        header.async_marshal(&mut send).await?;
        Ok(BiStream { send, recv })
    }

    /// Sends a `Dissociate` command via uni-stream
    pub async fn dissociate(&self, assoc_id: u16) -> Result<(), Error> {
        let header_data = self.model.send_dissociate(assoc_id);
        let header = Header::Dissociate(header_data);
        let mut send = self.conn.open_uni().await?;
        header.async_marshal(&mut send).await?;
        send.finish().map_err(|e| Error::StreamClosed(e))?;
        Ok(())
    }

    /// Parse a uni-stream as a SeaCore command (Client side normally only receives Packets or Dissociate)
    pub async fn accept_uni_stream(&self, mut recv: RecvStream) -> Result<Task, Error> {
        let header = Header::async_unmarshal(&mut recv)
            .await
            .map_err(|e| Error::UnmarshalStream(e))?;

        match header {
            Header::Packet(pkt) => {
                let _model_pkt = self.model.recv_packet(pkt.clone());
                Ok(Task::Packet(PacketTask {
                    header: pkt,
                    source: PacketSource::Quic(recv),
                }))
            }
            Header::Dissociate(diss) => Ok(Task::Dissociate(diss.assoc_id())),
            other => Err(Error::BadCommand(format!("{} on uni_stream_client", other))),
        }
    }
}

// ── Server side ────────────────────────────────

impl Connection<side::Server> {
    /// Creates a new server-side connection
    pub fn new(conn: QuinnConnection) -> Self {
        Self {
            conn,
            model: ConnectionModel::new(),
            _marker: side::Server,
        }
    }

    /// Parse a uni-stream as a SeaCore command
    pub async fn accept_uni_stream(&self, mut recv: RecvStream) -> Result<Task, Error> {
        let header = Header::async_unmarshal(&mut recv)
            .await
            .map_err(|e| Error::UnmarshalStream(e))?;

        match header {
            Header::Authenticate(auth) => {
                let exporter = self.keying_material_exporter();
                Ok(Task::Authenticate(Authenticate {
                    uuid: auth.uuid(),
                    timestamp: auth.timestamp(),
                    token: auth.token(),
                    exporter,
                }))
            }
            Header::Packet(pkt) => {
                let _model_pkt = self.model.recv_packet(pkt.clone());
                Ok(Task::Packet(PacketTask {
                    header: pkt,
                    source: PacketSource::Quic(recv),
                }))
            }
            Header::Dissociate(dissoc) => {
                self.model.recv_dissociate(dissoc.clone());
                Ok(Task::Dissociate(dissoc.assoc_id()))
            }
            other => Err(Error::BadCommand(format!("{} on uni_stream", other))),
        }
    }

    /// Parse a bi-stream as a SeaCore command
    pub async fn accept_bi_stream(&self, send: SendStream, mut recv: RecvStream) -> Result<Task, Error> {
        let header = Header::async_unmarshal(&mut recv)
            .await
            .map_err(|e| Error::UnmarshalStream(e))?;

        match header {
            Header::Connect(conn) => {
                let addr = conn.addr().clone();
                let _model_conn = self.model.recv_connect(conn);
                Ok(Task::Connect(BiStream { send, recv }, addr))
            }
            other => Err(Error::BadCommand(format!("{} on bi_stream", other))),
        }
    }

    /// Validates an authenticate request
    pub fn validate_authenticate(
        &self,
        uuid: Uuid,
        timestamp: u64,
        token: [u8; 32],
        password: impl AsRef<[u8]>,
    ) -> bool {
        self.model.validate_authenticate(uuid, timestamp, token, password, &self.keying_material_exporter())
    }
}

impl<Side> Connection<Side> {
    /// Parse a QUIC datagram as a SeaCore command
    pub fn accept_datagram(&self, dg: Bytes) -> Result<Task, Error> {
        let mut cursor = Cursor::new(dg.clone());
        let header = Header::unmarshal(&mut cursor)
            .map_err(|e| Error::UnmarshalDatagram(e))?;

        match header {
            Header::Packet(pkt) => {
                let _model_pkt = self.model.recv_packet(pkt.clone());
                let pos = cursor.position() as usize;
                let size = pkt.size() as usize;
                if pos + size <= dg.len() {
                    let payload = dg.slice(pos..pos + size);
                    Ok(Task::Packet(PacketTask {
                        header: pkt,
                        source: PacketSource::Native(payload),
                    }))
                } else {
                    Err(Error::PayloadLength(size, dg.len() - pos))
                }
            }
            Header::Heartbeat(_) => Ok(Task::Heartbeat),
            Header::Ping(ping) => Ok(Task::Ping {
                seq_id: ping.seq_id(),
                timestamp: ping.timestamp(),
            }),
            other => Err(Error::BadCommand(format!("{} on datagram", other))),
        }
    }
}

// ── Supporting types ───────────────────────────

/// A bidirectional stream for Connect commands
pub struct BiStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// A received Authenticate command with an exporter for validation
pub struct Authenticate {
    pub uuid: Uuid,
    pub timestamp: u64,
    pub token: [u8; 32],
    exporter: KeyingMaterialExporter,
}

impl Authenticate {
    pub fn validate(&self, password: impl AsRef<[u8]>) -> bool {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if timestamp is within ±120 seconds (2 minutes)
        if now.abs_diff(self.timestamp) > 120 {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(password.as_ref());
        hasher.update(&self.timestamp.to_be_bytes());
        let context = hasher.finalize();

        let expected = self.exporter.export_keying_material(self.uuid.as_bytes(), &context);
        self.token == expected
    }
}

/// A received Packet command
pub struct PacketTask {
    pub header: crate::protocol::Packet,
    source: PacketSource,
}

enum PacketSource {
    Quic(RecvStream),
    Native(Bytes),
}

impl PacketTask {
    pub fn assoc_id(&self) -> u16 {
        self.header.assoc_id()
    }

    pub fn addr(&self) -> &Address {
        self.header.addr()
    }

    pub fn pkt_id(&self) -> u16 {
        self.header.pkt_id()
    }

    pub fn frag_total(&self) -> u8 {
        self.header.frag_total()
    }

    pub fn frag_id(&self) -> u8 {
        self.header.frag_id()
    }

    pub fn size(&self) -> u16 {
        self.header.size()
    }

    /// Reads the payload from the packet source
    pub async fn payload(self) -> Result<Bytes, Error> {
        match self.source {
            PacketSource::Native(data) => Ok(data),
            PacketSource::Quic(mut recv) => {
                let mut buf = vec![0u8; self.header.size() as usize];
                recv.read_exact(&mut buf).await.map_err(|e| Error::ReadExact(e))?;
                Ok(Bytes::from(buf))
            }
        }
    }
}

/// Types of task that can be received from the QUIC connection
#[non_exhaustive]
pub enum Task {
    Authenticate(Authenticate),
    Connect(BiStream, Address),
    Packet(PacketTask),
    Dissociate(u16),
    Heartbeat,
    Ping { seq_id: u16, timestamp: u64 },
}

// ── Keying Material Exporter ───────────────────

struct KeyingMaterialExporter(QuinnConnection);

impl KME for KeyingMaterialExporter {
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        if let Err(err) = self.0.export_keying_material(&mut buf, label, context) {
            warn!("export keying material error: {:#?}", err);
            buf = [0u8; 32];
        }
        buf
    }
}

// ── Errors ─────────────────────────────────────

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    SendDatagram(#[from] SendDatagramError),
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error("unmarshal stream: {0}")]
    UnmarshalStream(UnmarshalError),
    #[error("unmarshal datagram: {0}")]
    UnmarshalDatagram(UnmarshalError),
    #[error("bad command: {0}")]
    BadCommand(String),
    #[error("payload length mismatch: expected {0}, got {1}")]
    PayloadLength(usize, usize),
    #[error(transparent)]
    WriteError(#[from] quinn::WriteError),
    #[error(transparent)]
    ReadError(#[from] quinn::ReadError),
    #[error("stream closed: {0}")]
    StreamClosed(ClosedStream),
    #[error("read exact error: {0}")]
    ReadExact(ReadExactError),
}
