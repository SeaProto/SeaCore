use std::collections::HashMap;
use std::fmt::Debug;
use std::mem;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use thiserror::Error;
use uuid::Uuid;

use crate::protocol::{
    Address, Authenticate as AuthenticateHeader, Connect as ConnectHeader,
    Dissociate as DissociateHeader, Heartbeat as HeartbeatHeader, Packet as PacketHeader,
    Ping as PingHeader,
};

pub mod side {
    /// The side of a task that sends data
    pub struct Tx;
    /// The side of a task that receives data
    pub struct Rx;
}

/// Trait for QUIC TLS Keying Material Exporter
pub trait KeyingMaterialExporter {
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32];
}

/// An abstraction of a SeaCore connection with UDP session management
#[derive(Clone)]
pub struct Connection<B> {
    udp_sessions: Arc<Mutex<UdpSessions<B>>>,
    task_connect_count: Arc<AtomicU16>,
    task_associate_count: Arc<AtomicU16>,
}

impl<B> Connection<B>
where
    B: AsRef<[u8]>,
{
    pub fn new() -> Self {
        Self {
            udp_sessions: Arc::new(Mutex::new(UdpSessions::new())),
            task_connect_count: Arc::new(AtomicU16::new(0)),
            task_associate_count: Arc::new(AtomicU16::new(0)),
        }
    }

    // ── Authenticate ──────────────────────────────

    pub fn send_authenticate(
        &self,
        uuid: Uuid,
        password: impl AsRef<[u8]>,
        exporter: Option<&impl KeyingMaterialExporter>,
    ) -> AuthenticateHeader {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let token = if let Some(exp) = exporter {
            let context = {
                let mut hasher = Sha256::new();
                hasher.update(password.as_ref());
                hasher.update(&timestamp.to_be_bytes());
                hasher.finalize()
            };
            exp.export_keying_material(uuid.as_bytes(), &context)
        } else {
            // TCP mode fallback token: bind password + timestamp + uuid.
            let mut hasher = Sha256::new();
            hasher.update(password.as_ref());
            hasher.update(&timestamp.to_be_bytes());
            hasher.update(uuid.as_bytes());
            let digest = hasher.finalize();
            let mut token = [0u8; 32];
            token.copy_from_slice(&digest);
            token
        };
        AuthenticateHeader::new(uuid, timestamp, token)
    }

    pub fn validate_authenticate(
        &self,
        uuid: Uuid,
        timestamp: u64,
        token: [u8; 32],
        password: impl AsRef<[u8]>,
        exporter: Option<&impl KeyingMaterialExporter>,
    ) -> bool {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if timestamp is within ±120 seconds (2 minutes)
        if now.abs_diff(timestamp) > 120 {
            return false;
        }

        if let Some(exp) = exporter {
            let context = {
                let mut hasher = Sha256::new();
                hasher.update(password.as_ref());
                hasher.update(&timestamp.to_be_bytes());
                hasher.finalize()
            };
            let expected = exp.export_keying_material(uuid.as_bytes(), &context);
            token == expected
        } else {
            // TCP mode fallback token: bind password + timestamp + uuid.
            let mut hasher = Sha256::new();
            hasher.update(password.as_ref());
            hasher.update(&timestamp.to_be_bytes());
            hasher.update(uuid.as_bytes());
            let digest = hasher.finalize();
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&digest);
            token == expected
        }
    }

    // ── Connect ───────────────────────────────────

    pub fn send_connect(&self, addr: Address) -> ConnectHeader {
        self.task_connect_count.fetch_add(1, Ordering::AcqRel);
        ConnectHeader::new(addr)
    }

    pub fn recv_connect(&self, header: ConnectHeader) -> ConnectHeader {
        self.task_connect_count.fetch_add(1, Ordering::AcqRel);
        header
    }

    // ── Packet ────────────────────────────────────

    pub fn send_packet(&self, assoc_id: u16, addr: Address, max_pkt_size: usize) -> PacketSender {
        self.udp_sessions.lock().send_packet(
            assoc_id,
            addr,
            max_pkt_size,
            &self.task_associate_count,
        )
    }

    pub fn recv_packet(&self, header: PacketHeader) -> PacketHeader {
        let assoc_id = header.assoc_id();
        self.udp_sessions
            .lock()
            .ensure_session(assoc_id, &self.task_associate_count);
        header
    }

    // ── Dissociate ────────────────────────────────

    pub fn send_dissociate(&self, assoc_id: u16) -> DissociateHeader {
        self.udp_sessions.lock().remove_session(assoc_id);
        DissociateHeader::new(assoc_id)
    }

    pub fn recv_dissociate(&self, header: DissociateHeader) {
        self.udp_sessions.lock().remove_session(header.assoc_id());
    }

    // ── Heartbeat ─────────────────────────────────

    pub fn send_heartbeat(&self) -> HeartbeatHeader {
        HeartbeatHeader::new()
    }

    // ── Ping ──────────────────────────────────────

    pub fn send_ping(&self, seq_id: u16, timestamp: u64) -> PingHeader {
        PingHeader::new(seq_id, timestamp)
    }

    // ── Counters ──────────────────────────────────

    pub fn task_connect_count(&self) -> u16 {
        self.task_connect_count.load(Ordering::Acquire)
    }

    pub fn task_associate_count(&self) -> u16 {
        self.task_associate_count.load(Ordering::Acquire)
    }

    /// Removes fragments that cannot be reassembled within the specified timeout
    pub fn collect_garbage(&self, timeout: Duration) {
        self.udp_sessions.lock().collect_garbage(timeout);
    }
}

/// Helper for sending fragmented UDP packets
pub struct PacketSender {
    assoc_id: u16,
    pkt_id: u16,
    addr: Address,
    max_pkt_size: usize,
}

impl PacketSender {
    /// Split a payload into fragments and return (header, fragment_data) pairs
    pub fn into_fragments<'a>(
        &self,
        payload: &'a [u8],
    ) -> Vec<(crate::protocol::Header, &'a [u8])> {
        use crate::protocol::Header;

        if payload.is_empty() {
            let pkt = PacketHeader::new(self.assoc_id, self.pkt_id, 1, 0, 0, self.addr.clone());
            return vec![(Header::Packet(pkt), &[])];
        }

        // Calculate max fragment payload size
        let header_overhead = 2 + 8 + self.addr.len(); // VER+TYPE + packet fields + addr
        let max_frag_payload = if self.max_pkt_size > header_overhead {
            self.max_pkt_size - header_overhead
        } else {
            payload.len() // no fragmentation if we can't fit anything
        };

        let frag_total = ((payload.len() + max_frag_payload - 1) / max_frag_payload) as u8;
        let mut frags = Vec::with_capacity(frag_total as usize);

        for (i, chunk) in payload.chunks(max_frag_payload).enumerate() {
            let addr = if i == 0 {
                self.addr.clone()
            } else {
                Address::None
            };
            let pkt = PacketHeader::new(
                self.assoc_id,
                self.pkt_id,
                frag_total,
                i as u8,
                chunk.len() as u16,
                addr,
            );
            frags.push((Header::Packet(pkt), chunk));
        }
        frags
    }
}

// ── UDP Session Management ─────────────────────────

struct UdpSessions<B> {
    sessions: HashMap<u16, UdpSession<B>>,
}

impl<B> UdpSessions<B>
where
    B: AsRef<[u8]>,
{
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    fn send_packet(
        &mut self,
        assoc_id: u16,
        addr: Address,
        max_pkt_size: usize,
        counter: &Arc<AtomicU16>,
    ) -> PacketSender {
        let session = self.sessions.entry(assoc_id).or_insert_with(|| {
            counter.fetch_add(1, Ordering::AcqRel);
            UdpSession::new()
        });
        let pkt_id = session.next_pkt_id.fetch_add(1, Ordering::AcqRel);
        PacketSender {
            assoc_id,
            pkt_id,
            addr,
            max_pkt_size,
        }
    }

    fn ensure_session(&mut self, assoc_id: u16, counter: &Arc<AtomicU16>) {
        self.sessions.entry(assoc_id).or_insert_with(|| {
            counter.fetch_add(1, Ordering::AcqRel);
            UdpSession::new()
        });
    }

    fn remove_session(&mut self, assoc_id: u16) {
        self.sessions.remove(&assoc_id);
    }

    fn collect_garbage(&mut self, timeout: Duration) {
        for (_, session) in self.sessions.iter_mut() {
            session
                .pkt_buf
                .retain(|_, buf| buf.c_time.elapsed() < timeout);
        }
    }
}

struct UdpSession<B> {
    pkt_buf: HashMap<u16, PacketBuffer<B>>,
    next_pkt_id: AtomicU16,
}

impl<B> UdpSession<B>
where
    B: AsRef<[u8]>,
{
    fn new() -> Self {
        Self {
            pkt_buf: HashMap::new(),
            next_pkt_id: AtomicU16::new(0),
        }
    }
}

// ── Packet Reassembly ──────────────────────────────

struct PacketBuffer<B> {
    buf: Vec<Option<B>>,
    frag_total: u8,
    frag_received: u8,
    addr: Address,
    c_time: Instant,
}

impl<B> PacketBuffer<B>
where
    B: AsRef<[u8]>,
{
    fn new(frag_total: u8) -> Self {
        let mut buf = Vec::with_capacity(frag_total as usize);
        buf.resize_with(frag_total as usize, || None);
        Self {
            buf,
            frag_total,
            frag_received: 0,
            addr: Address::None,
            c_time: Instant::now(),
        }
    }

    fn insert(
        &mut self,
        frag_total: u8,
        frag_id: u8,
        addr: Address,
        data: B,
    ) -> Result<Option<Assemblable<B>>, AssembleError> {
        if frag_id >= frag_total {
            return Err(AssembleError::InvalidFragmentId(frag_total, frag_id));
        }

        if frag_id == 0 && addr.is_none() {
            return Err(AssembleError::InvalidAddress(
                "no address in first fragment",
            ));
        }

        if frag_id != 0 && !addr.is_none() {
            return Err(AssembleError::InvalidAddress(
                "address in non-first fragment",
            ));
        }

        if self.buf[frag_id as usize].is_some() {
            return Err(AssembleError::DuplicatedFragment(frag_id));
        }

        self.buf[frag_id as usize] = Some(data);
        self.frag_received += 1;

        if frag_id == 0 {
            self.addr = addr;
        }

        if self.frag_received == self.frag_total {
            Ok(Some(Assemblable {
                buf: mem::take(&mut self.buf),
                addr: self.addr.take(),
            }))
        } else {
            Ok(None)
        }
    }
}

/// A fully reassembled packet ready to be assembled into bytes
pub struct Assemblable<B> {
    buf: Vec<Option<B>>,
    addr: Address,
}

impl<B> Assemblable<B>
where
    B: AsRef<[u8]>,
{
    pub fn assemble(self) -> (Vec<u8>, Address) {
        let mut result = Vec::new();
        for frag in self.buf.into_iter() {
            if let Some(data) = frag {
                result.extend_from_slice(data.as_ref());
            }
        }
        (result, self.addr)
    }
}

/// Errors during packet reassembly
#[derive(Debug, Error)]
pub enum AssembleError {
    #[error("invalid fragment id {1} in total {0} fragments")]
    InvalidFragmentId(u8, u8),
    #[error("{0}")]
    InvalidAddress(&'static str),
    #[error("duplicated fragment: {0}")]
    DuplicatedFragment(u8),
}

/// Insert a received fragment and attempt reassembly
impl<B> Connection<B>
where
    B: AsRef<[u8]>,
{
    pub fn insert_packet_fragment(
        &self,
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        addr: Address,
        data: B,
    ) -> Result<Option<Assemblable<B>>, AssembleError> {
        let mut sessions = self.udp_sessions.lock();
        let session = sessions.sessions.entry(assoc_id).or_insert_with(|| {
            self.task_associate_count.fetch_add(1, Ordering::AcqRel);
            UdpSession::new()
        });
        let buffer = session
            .pkt_buf
            .entry(pkt_id)
            .or_insert_with(|| PacketBuffer::new(frag_total));

        let result = buffer.insert(frag_total, frag_id, addr, data)?;

        if result.is_some() {
            session.pkt_buf.remove(&pkt_id);
        }

        Ok(result)
    }
}
