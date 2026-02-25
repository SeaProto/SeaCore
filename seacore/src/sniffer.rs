use ring::{aead, hkdf};
use std::convert::TryInto;

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub struct QuicKeys {
    pub header_key: aead::quic::HeaderProtectionKey,
    pub packet_key: aead::LessSafeKey,
    pub iv: [u8; 12],
}

struct QuicHkdfLen(usize);
impl hkdf::KeyType for QuicHkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(secret: &hkdf::Prk, label: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut info = Vec::with_capacity(3 + 8 + label.len() + 1); // 2 + 1 + 6 + 1
    info.push((out_len >> 8) as u8);
    info.push(out_len as u8);

    let full_label = format!("tls13 {}", std::str::from_utf8(label).ok()?);
    let full_label_bytes = full_label.as_bytes();
    info.push(full_label_bytes.len() as u8);
    info.extend_from_slice(full_label_bytes);
    info.push(0); // empty context

    let mut out = vec![0u8; out_len];
    let info_binding = [info.as_slice()];
    let okm = match secret.expand(&info_binding, QuicHkdfLen(out_len)) {
        Ok(o) => o,
        Err(_) => {
            tracing::debug!("hkdf_expand_label expand failed");
            return None;
        }
    };
    if okm.fill(&mut out).is_err() {
        tracing::debug!("hkdf_expand_label fill failed");
        return None;
    }
    Some(out)
}

pub fn derive_initial_keys(dcid: &[u8]) -> Option<QuicKeys> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &QUIC_V1_SALT);
    let initial_secret = salt.extract(dcid);

    let client_initial_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_initial_secret);

    let key = match hkdf_expand_label(&client_prk, b"quic key", 16) {
        Some(k) => k,
        None => {
            tracing::debug!("derive_initial_keys: quic key derivation failed");
            return None;
        }
    };
    let hp = match hkdf_expand_label(&client_prk, b"quic hp", 16) {
        Some(h) => h,
        None => {
            tracing::debug!("derive_initial_keys: quic hp derivation failed");
            return None;
        }
    };
    let iv_vec = match hkdf_expand_label(&client_prk, b"quic iv", 12) {
        Some(v) => v,
        None => {
            tracing::debug!("derive_initial_keys: quic iv derivation failed");
            return None;
        }
    };
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);

    let unbound_key = match aead::UnboundKey::new(&aead::AES_128_GCM, &key) {
        Ok(k) => k,
        Err(_) => {
            tracing::debug!(
                "derive_initial_keys: UnboundKey::new failed for key length {}",
                key.len()
            );
            return None;
        }
    };
    let packet_key = aead::LessSafeKey::new(unbound_key);
    let header_key = match aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp) {
        Ok(k) => k,
        Err(_) => {
            tracing::debug!(
                "derive_initial_keys: HeaderProtectionKey::new failed for hp length {}",
                hp.len()
            );
            return None;
        }
    };

    Some(QuicKeys {
        header_key,
        packet_key,
        iv,
    })
}

fn read_varint(buf: &[u8], offset: &mut usize) -> Option<u64> {
    if *offset >= buf.len() {
        return None;
    }
    let first = buf[*offset];
    let len = 1 << (first >> 6);
    if *offset + len > buf.len() {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | (buf[*offset + i] as u64);
    }
    *offset += len;
    Some(val)
}

/// Decrypts a QUIC Initial packet and extracts the TLS 1.3 ClientHello payload.
pub fn extract_client_hello(raw_packet: &[u8]) -> Option<Vec<u8>> {
    // Basic QUIC long header check
    if raw_packet.len() < 1200 {
        tracing::debug!(
            "extract_client_hello: packet too small {}",
            raw_packet.len()
        );
        return None;
    }
    if (raw_packet[0] & 0xC0) != 0xC0 {
        tracing::debug!("extract_client_hello: not long header");
        return None;
    }

    let version = u32::from_be_bytes([raw_packet[1], raw_packet[2], raw_packet[3], raw_packet[4]]);
    if version != 1 {
        tracing::debug!("extract_client_hello: not v1 {}", version);
        return None;
    }

    let dcid_len = raw_packet[5] as usize;
    if 6 + dcid_len > raw_packet.len() {
        tracing::debug!("extract_client_hello: dcid len out of bounds");
        return None;
    }
    let dcid = &raw_packet[6..6 + dcid_len];
    let mut offset = 6 + dcid_len;

    let scid_len = raw_packet[offset] as usize;
    offset += 1 + scid_len;
    if offset > raw_packet.len() {
        tracing::debug!("extract_client_hello: scid len out of bounds");
        return None;
    }

    // Read Token Length & Token
    let token_len = read_varint(raw_packet, &mut offset)? as usize;
    offset += token_len;
    if offset > raw_packet.len() {
        tracing::debug!("extract_client_hello: token out of bounds");
        return None;
    }

    // Read Payload Length
    let payload_len = read_varint(raw_packet, &mut offset)? as usize;
    if offset + payload_len > raw_packet.len() {
        tracing::debug!("extract_client_hello: payload out of bounds");
        return None;
    }

    let pn_offset = offset;
    let keys = match derive_initial_keys(dcid) {
        Some(k) => k,
        None => {
            tracing::debug!("extract_client_hello: derive_initial_keys failed");
            return None;
        }
    };

    // Header Protection
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > raw_packet.len() {
        tracing::debug!("extract_client_hello: sample out of bounds");
        return None;
    }

    let sample_slice: &[u8; 16] = &raw_packet[sample_offset..sample_offset + 16]
        .try_into()
        .ok()?;
    let mask = keys.header_key.new_mask(sample_slice).ok()?;

    let mut buf = raw_packet.to_vec(); // Create a mutable copy for in-place decryption

    // Unprotect first byte
    buf[0] ^= mask[0] & 0x0f;
    let pn_len = (buf[0] & 0x03) as usize + 1;

    // Unprotect Packet Number
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }

    let mut pn = 0u64;
    for i in 0..pn_len {
        pn = (pn << 8) | (buf[pn_offset + i] as u64);
    }

    let payload_offset = pn_offset + pn_len;
    let payload_len_actual = payload_len - pn_len;

    // Decrypt Payload (AEAD)
    let mut nonce = keys.iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    let (header, rest) = buf.split_at_mut(payload_offset);
    let aad = aead::Aad::from(&*header);
    let nonce_obj = aead::Nonce::assume_unique_for_key(nonce);

    // We decrypt in-place. `open_in_place` returns the slice of the decrypted data.
    let payload_tag = &mut rest[..payload_len_actual];
    let decrypted_payload = match keys.packet_key.open_in_place(nonce_obj, aad, payload_tag) {
        Ok(p) => p,
        Err(_) => {
            tracing::debug!("extract_client_hello: payload decryption failed");
            return None;
        }
    };

    // Parse QUIC Frames to find CRYPTO frame
    let mut p = 0;
    while p < decrypted_payload.len() {
        let frame_type = match read_varint(decrypted_payload, &mut p) {
            Some(ft) => ft,
            None => {
                tracing::debug!("extract_client_hello: failed to read frame type");
                return None;
            }
        };
        match frame_type {
            0x00 => continue, // PADDING
            0x06 => {
                // CRYPTO
                let _offset = match read_varint(decrypted_payload, &mut p) {
                    Some(o) => o,
                    None => {
                        tracing::debug!("extract_client_hello: failed to read crypto offset");
                        return None;
                    }
                };
                let len = match read_varint(decrypted_payload, &mut p) {
                    Some(l) => l as usize,
                    None => {
                        tracing::debug!("extract_client_hello: failed to read crypto len");
                        return None;
                    }
                };
                if p + len > decrypted_payload.len() {
                    tracing::debug!("extract_client_hello: crypto data out of bounds");
                    return None;
                }
                let crypto_data = &decrypted_payload[p..p + len];
                // Check if it's TLS Handshake ClientHello
                if crypto_data.is_empty() {
                    tracing::debug!("extract_client_hello: crypto data is empty");
                    return None;
                }
                if crypto_data[0] == 0x01 {
                    // ClientHello
                    return Some(crypto_data.to_vec());
                }
                tracing::debug!("extract_client_hello: not a ClientHello in CRYPTO frame");
                return None;
            }
            0x01 => {
                tracing::debug!("extract_client_hello: PING frame found, not ClientHello");
                return None;
            } // PING
            0x02 | 0x03 => {
                tracing::debug!("extract_client_hello: ACK frame found, not ClientHello");
                return None;
            } // ACK
            0x1c => {
                tracing::debug!("extract_client_hello: CONNECTION_CLOSE frame found, breaking");
                break;
            } // CONNECTION_CLOSE
            _ => {
                // Unknown frame in initial packet, typically indicates failure or padding
                break;
            }
        }
    }

    None
}

/// Parses a TLS ClientHello to extract the SessionID and X25519 KeyShare
pub fn parse_client_hello(ch: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Basic TLS Handshake header check
    // 1 byte msg_type (0x01 ClientHello), 3 bytes length
    if ch.len() < 4 || ch[0] != 0x01 {
        return None;
    }
    let mut offset = 4;

    // 2 bytes client_version
    offset += 2;
    // 32 bytes random
    offset += 32;
    if offset >= ch.len() {
        return None;
    }

    // session_id length + session_id
    let sid_len = ch[offset] as usize;
    offset += 1;
    if offset + sid_len > ch.len() {
        return None;
    }
    let session_id = ch[offset..offset + sid_len].to_vec();
    offset += sid_len;

    // cipher_suites
    if offset + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2 + cs_len;

    // compression_methods
    if offset + 1 > ch.len() {
        return None;
    }
    let cm_len = ch[offset] as usize;
    offset += 1 + cm_len;

    // extensions
    if offset + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2;

    let end = offset + ext_len;
    let mut key_share = None;

    while offset + 4 <= end.min(ch.len()) {
        let ext_type = u16::from_be_bytes([ch[offset], ch[offset + 1]]);
        let ext_len_item = u16::from_be_bytes([ch[offset + 2], ch[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len_item > ch.len() {
            break;
        }

        if ext_type == 0x0033 {
            // key_share
            // ClientHello KeyShare extension format:
            // 2 bytes client_shares length
            if ext_len_item >= 2 {
                let mut ks_offset = offset + 2;
                while ks_offset + 4 <= offset + ext_len_item {
                    let group = u16::from_be_bytes([ch[ks_offset], ch[ks_offset + 1]]);
                    let key_len =
                        u16::from_be_bytes([ch[ks_offset + 2], ch[ks_offset + 3]]) as usize;
                    ks_offset += 4;
                    if group == 0x001D {
                        // X25519
                        if ks_offset + key_len <= offset + ext_len_item && key_len == 32 {
                            key_share = Some(ch[ks_offset..ks_offset + key_len].to_vec());
                        }
                    }
                    ks_offset += key_len;
                }
            }
        }

        offset += ext_len_item;
    }

    match key_share {
        Some(ks) if session_id.len() >= 16 => Some((session_id, ks)),
        _ => None,
    }
}

/// Extracts the SNI (Server Name Indication) from a parsed TLS ClientHello.
pub fn parse_sni(ch: &[u8]) -> Option<String> {
    if ch.len() < 4 || ch[0] != 0x01 {
        return None;
    }
    let mut offset = 4;
    offset += 2; // client_version
    offset += 32; // random
    if offset >= ch.len() {
        return None;
    }
    let sid_len = ch[offset] as usize;
    offset += 1 + sid_len;
    if offset + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2 + cs_len;
    if offset + 1 > ch.len() {
        return None;
    }
    let cm_len = ch[offset] as usize;
    offset += 1 + cm_len;
    if offset + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2;
    let end = offset + ext_len;

    while offset + 4 <= end.min(ch.len()) {
        let ext_type = u16::from_be_bytes([ch[offset], ch[offset + 1]]);
        let ext_len_item = u16::from_be_bytes([ch[offset + 2], ch[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len_item > ch.len() {
            break;
        }

        if ext_type == 0x0000 {
            // SNI extension
            // SNI list: 2 bytes total length, then entries
            if ext_len_item >= 5 {
                let name_type = ch[offset + 2];
                if name_type == 0x00 {
                    // host_name
                    let name_len = u16::from_be_bytes([ch[offset + 3], ch[offset + 4]]) as usize;
                    if offset + 5 + name_len <= ch.len() {
                        let name = String::from_utf8_lossy(&ch[offset + 5..offset + 5 + name_len])
                            .to_string();
                        return Some(name);
                    }
                }
            }
        }
        offset += ext_len_item;
    }
    None
}

/// Verifies Reality Auth via X25519 KeyShare and HMAC Timestamp SessionID Injection.
/// Returns `Some(session_id_bytes)` on success for replay protection, or `None` on failure.
pub fn verify_reality_auth(
    raw_packet: &[u8],
    server_priv_key: &[u8; 32],
    users: &[crate::server::UserConfig],
    short_ids: &[[u8; 8]],
    server_names: &[String],
) -> Option<[u8; 32]> {
    let ch = match extract_client_hello(raw_packet) {
        Some(client_hello) => client_hello,
        None => {
            tracing::debug!("verify_reality_auth: extract_client_hello failed");
            return None;
        }
    };

    let (session_id, key_share) = match parse_client_hello(&ch) {
        Some((s, k)) => (s, k),
        None => {
            tracing::debug!("verify_reality_auth: parse_client_hello failed");
            return None;
        }
    };

    // Validate SNI against configured server_names (soft check: missing SNI is OK)
    if !server_names.is_empty() {
        if let Some(sni) = parse_sni(&ch) {
            if !server_names.iter().any(|n| n == &sni) {
                tracing::debug!("verify_reality_auth: SNI '{}' not in whitelist", sni);
                return None;
            }
        }
        // If no SNI found, we allow — some QUIC stacks may not include SNI in Initial
    }

    // We expect a 32 byte SessionID (Reality Token) and a 32 byte X25519 ephemeral public key
    if session_id.len() != 32 || key_share.len() != 32 {
        tracing::debug!(
            "verify_reality_auth: invalid len, session_id {}, key_share {}",
            session_id.len(),
            key_share.len()
        );
        return None;
    }

    use x25519_dalek::{PublicKey, StaticSecret};
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(server_priv_key);
    let static_sec = StaticSecret::from(priv_bytes);

    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&key_share);
    let peer_pub = PublicKey::from(peer_pub_bytes);

    // Compute original shared secret using Client's Ephemeral Key and Server's Identity Key
    let shared_secret = static_sec.diffie_hellman(&peer_pub);

    // In our simplified Reality over QUIC, session_id contains the Auth Token.
    // 0..8 = timestamp, 8..32 = HMAC(SharedSecret, Timestamp + UUID)
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&session_id[0..8]);
    let ts = u64::from_be_bytes(ts_bytes);

    // Replay Protection: Token is valid for +/- 30 seconds
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > ts + 30 || now < ts.saturating_sub(30) {
        tracing::debug!(
            "verify_reality_auth: timestamp failed. now {}, ts {}",
            now,
            ts
        );
        return None;
    }

    use ring::hmac;
    let hm_key = hmac::Key::new(hmac::HMAC_SHA256, shared_secret.as_bytes());

    for user in users {
        let mut matched = false;
        if short_ids.is_empty() {
            let mut msg = Vec::new();
            msg.extend_from_slice(&ts.to_be_bytes());
            msg.extend_from_slice(user.uuid.as_bytes());
            let expected_tag = hmac::sign(&hm_key, &msg);
            #[allow(deprecated)]
            if ring::constant_time::verify_slices_are_equal(
                &expected_tag.as_ref()[..24],
                &session_id[8..32],
            )
            .is_ok()
            {
                matched = true;
            }
        } else {
            for short_id in short_ids {
                let mut msg = Vec::new();
                msg.extend_from_slice(&ts.to_be_bytes());
                msg.extend_from_slice(user.uuid.as_bytes());
                msg.extend_from_slice(short_id);
                let expected_tag = hmac::sign(&hm_key, &msg);
                #[allow(deprecated)]
                if ring::constant_time::verify_slices_are_equal(
                    &expected_tag.as_ref()[..24],
                    &session_id[8..32],
                )
                .is_ok()
                {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            tracing::debug!("verify_reality_auth: SUCCESS for user {}", user.uuid);
            let mut token = [0u8; 32];
            token.copy_from_slice(&session_id);
            return Some(token);
        }
    }

    tracing::debug!("verify_reality_auth: hmac verify failed");
    None
}

/// Verifies Reality Auth via X25519 KeyShare and HMAC Timestamp SessionID Injection
/// for raw TCP TLS 1.3 connections. The `tcp_payload` is expected to be a TLS Record
/// containing a Handshake containing a ClientHello message.
pub fn verify_tcp_reality_auth(
    tcp_payload: &[u8],
    server_priv_key: &[u8; 32],
    users: &[crate::server::UserConfig],
    short_ids: &[[u8; 8]],
    server_names: &[String],
) -> Option<[u8; 32]> {
    // 1. Basic TLS Record Layer check
    // ContentType: Handshake (22 or 0x16)
    // Version: Legacy Record Version (0x03 0x01 or 0x03 0x03 usually)
    // Length: 2 bytes
    if tcp_payload.len() < 5 || tcp_payload[0] != 0x16 {
        tracing::debug!("verify_tcp_reality_auth: not a TLS handshake record");
        return None;
    }
    let record_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;
    if 5 + record_len > tcp_payload.len() {
        tracing::debug!("verify_tcp_reality_auth: incomplete TLS record");
        return None;
    }

    // Extract the Handshake message (which should be the ClientHello)
    let ch = &tcp_payload[5..5 + record_len];

    let (session_id, key_share) = match parse_client_hello(ch) {
        Some((s, k)) => (s, k),
        None => {
            tracing::debug!("verify_tcp_reality_auth: parse_client_hello failed");
            return None;
        }
    };

    // Validate SNI against configured server_names (soft check: missing SNI is OK)
    if !server_names.is_empty() {
        if let Some(sni) = parse_sni(ch) {
            if !server_names.iter().any(|n| n == &sni) {
                tracing::debug!("verify_tcp_reality_auth: SNI '{}' not in whitelist", sni);
                return None;
            }
        }
    }

    // We expect a 32 byte SessionID (Reality Token) and a 32 byte X25519 ephemeral public key
    if session_id.len() != 32 || key_share.len() != 32 {
        tracing::debug!(
            "verify_tcp_reality_auth: invalid len, session_id {}, key_share {}",
            session_id.len(),
            key_share.len()
        );
        return None;
    }

    use x25519_dalek::{PublicKey, StaticSecret};
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(server_priv_key);
    let static_sec = StaticSecret::from(priv_bytes);

    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&key_share);
    let peer_pub = PublicKey::from(peer_pub_bytes);

    // Compute original shared secret using Client's Ephemeral Key and Server's Identity Key
    let shared_secret = static_sec.diffie_hellman(&peer_pub);

    // 0..8 = timestamp, 8..32 = HMAC(SharedSecret, Timestamp + UUID)
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&session_id[0..8]);
    let ts = u64::from_be_bytes(ts_bytes);

    // Replay Protection: Token is valid for +/- 30 seconds
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > ts + 30 || now < ts.saturating_sub(30) {
        tracing::debug!(
            "verify_tcp_reality_auth: timestamp failed. now {}, ts {}",
            now,
            ts
        );
        return None;
    }

    use ring::hmac;
    let hm_key = hmac::Key::new(hmac::HMAC_SHA256, shared_secret.as_bytes());

    for user in users {
        let mut matched = false;
        if short_ids.is_empty() {
            let mut msg = Vec::new();
            msg.extend_from_slice(&ts.to_be_bytes());
            msg.extend_from_slice(user.uuid.as_bytes());
            let expected_tag = hmac::sign(&hm_key, &msg);
            #[allow(deprecated)]
            if ring::constant_time::verify_slices_are_equal(
                &expected_tag.as_ref()[..24],
                &session_id[8..32],
            )
            .is_ok()
            {
                matched = true;
            }
        } else {
            for short_id in short_ids {
                let mut msg = Vec::new();
                msg.extend_from_slice(&ts.to_be_bytes());
                msg.extend_from_slice(user.uuid.as_bytes());
                msg.extend_from_slice(short_id);
                let expected_tag = hmac::sign(&hm_key, &msg);
                #[allow(deprecated)]
                if ring::constant_time::verify_slices_are_equal(
                    &expected_tag.as_ref()[..24],
                    &session_id[8..32],
                )
                .is_ok()
                {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            tracing::debug!("verify_tcp_reality_auth: SUCCESS for user {}", user.uuid);
            let mut token = [0u8; 32];
            token.copy_from_slice(&session_id);
            return Some(token);
        }
    }

    tracing::debug!("verify_tcp_reality_auth: hmac verify failed");
    None
}
