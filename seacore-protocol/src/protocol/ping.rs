/// Command `Ping` - for latency measurement
///
/// ```plain
/// +--------+-----------+
/// | SEQ_ID | TIMESTAMP |
/// +--------+-----------+
/// |   2    |     8     |
/// +--------+-----------+
/// ```
#[derive(Clone, Debug)]
pub struct Ping {
    seq_id: u16,
    timestamp: u64,
}

impl Ping {
    const TYPE_CODE: u8 = 0x05;

    pub const fn new(seq_id: u16, timestamp: u64) -> Self {
        Self { seq_id, timestamp }
    }

    pub fn seq_id(&self) -> u16 {
        self.seq_id
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub const fn type_code() -> u8 {
        Self::TYPE_CODE
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        2 + 8
    }
}

impl From<Ping> for (u16, u64) {
    fn from(ping: Ping) -> Self {
        (ping.seq_id, ping.timestamp)
    }
}
