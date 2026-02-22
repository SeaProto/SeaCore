use uuid::Uuid;

/// Command `Authenticate`
///
/// ```plain
/// +------+-------+
/// | UUID | TOKEN |
/// +------+-------+
/// |  16  |  32   |
/// +------+-------+
/// ```
///
/// - `UUID` - client UUID
/// - `TIMESTAMP` - 64-bit UNIX epoch timestamp for replay protection
/// - `TOKEN` - 256-bit token derived via QUIC TLS Keying Material Exporter.
///   The `label` is the client UUID bytes, the `context` is SHA256(password).
#[derive(Clone, Debug)]
pub struct Authenticate {
    uuid: Uuid,
    timestamp: u64,
    token: [u8; 32],
}

impl Authenticate {
    const TYPE_CODE: u8 = 0x00;

    pub const fn new(uuid: Uuid, timestamp: u64, token: [u8; 32]) -> Self {
        Self { uuid, timestamp, token }
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn token(&self) -> [u8; 32] {
        self.token
    }

    pub const fn type_code() -> u8 {
        Self::TYPE_CODE
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        16 + 8 + 32
    }
}

impl From<Authenticate> for (Uuid, u64, [u8; 32]) {
    fn from(auth: Authenticate) -> Self {
        (auth.uuid, auth.timestamp, auth.token)
    }
}
