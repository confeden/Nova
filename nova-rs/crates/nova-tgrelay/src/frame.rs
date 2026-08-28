//! Where MTProto frame boundaries fall inside an obfuscated TCP stream.
//!
//! The relay has to hand the upstream whole frames, so it keeps two buffers in
//! lockstep: the ciphertext it will forward untouched, and the plaintext it
//! decrypts purely to read lengths from. Only the plaintext is inspected; only
//! the ciphertext is emitted.

/// The 64 zero bytes the obfuscated transport advances the keystream by before
/// any payload is processed.
const ZERO_64: [u8; 64] = [0u8; 64];

/// Offsets of the AES key and IV inside a 64-byte init packet.
const KEY_RANGE: std::ops::Range<usize> = 8..40;
const IV_RANGE: std::ops::Range<usize> = 40..56;

/// Smallest init packet the key material can be taken from.
pub const MIN_INIT_LEN: usize = 56;

const TAG_ABRIDGED: u32 = 0xEFEF_EFEF;
const TAG_INTERMEDIATE: u32 = 0xEEEE_EEEE;
const TAG_PADDED_INTERMEDIATE: u32 = 0xDDDD_DDDD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitterError {
    /// The init packet is too short to carry key material.
    InitTooShort { len: usize },
}

impl std::fmt::Display for SplitterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitTooShort { len } => {
                write!(f, "init packet too short: {len} bytes, need {MIN_INIT_LEN}")
            }
        }
    }
}

impl std::error::Error for SplitterError {}

/// The keystream the obfuscated transport is decrypted with.
///
/// Abstracted rather than depending on a crypto crate so that the framing —
/// the part that decides where a boundary falls, and the only part with
/// interesting failure modes — is testable on its own.
pub trait KeyStream {
    /// Apply the keystream to `data`, advancing it by `data.len()` bytes.
    fn update(&mut self, data: &[u8]) -> Vec<u8>;
}

/// Key and IV slices of an init packet, or an error if it is too short.
pub fn init_material(init: &[u8]) -> Result<(&[u8], &[u8]), SplitterError> {
    if init.len() < MIN_INIT_LEN {
        return Err(SplitterError::InitTooShort { len: init.len() });
    }
    Ok((&init[KEY_RANGE], &init[IV_RANGE]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoType {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ProtoType {
    /// Map a wire tag, treating anything unrecognised as abridged — the lenient
    /// mapping the splitter uses.
    pub fn from_tag(tag: u32) -> Self {
        match tag {
            TAG_INTERMEDIATE => Self::Intermediate,
            TAG_PADDED_INTERMEDIATE => Self::PaddedIntermediate,
            _ => Self::Abridged,
        }
    }

    /// Strict mapping: `None` when the tag is not one of the three known ones.
    pub fn from_tag_checked(tag: u32) -> Option<Self> {
        match tag {
            TAG_ABRIDGED => Some(Self::Abridged),
            TAG_INTERMEDIATE => Some(Self::Intermediate),
            TAG_PADDED_INTERMEDIATE => Some(Self::PaddedIntermediate),
            _ => None,
        }
    }
}

/// What the plaintext prefix says about the next frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Peek {
    /// Not enough bytes yet to know.
    NeedMore,
    /// A zero-length payload. The stream stops being framed from here on.
    GiveUp,
    /// A complete frame of this many bytes is buffered.
    Frame(usize),
}

/// Splits an obfuscated MTProto stream into whole frames.
pub struct MsgSplitter<K: KeyStream> {
    stream: K,
    proto: ProtoType,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl<K: KeyStream> MsgSplitter<K> {
    /// The keystream is advanced past the 64 zero bytes here, as the transport
    /// requires, so callers cannot forget to.
    pub fn new(mut stream: K, proto: ProtoType) -> Self {
        let _ = stream.update(&ZERO_64);
        Self { stream, proto, cipher_buf: Vec::new(), plain_buf: Vec::new(), disabled: false }
    }

    /// True once a zero-length payload has been seen and framing gave up.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Feed ciphertext, get back whole frames of ciphertext.
    ///
    /// Once framing has given up, chunks pass through untouched — the stream is
    /// still forwarded, just no longer split.
    pub fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }

        self.cipher_buf.extend_from_slice(chunk);
        let plain = self.stream.update(chunk);
        self.plain_buf.extend_from_slice(&plain);

        let mut parts: Vec<Vec<u8>> = Vec::new();
        loop {
            match self.peek_packet_size() {
                Peek::NeedMore => return parts,
                Peek::GiveUp => {
                    parts.extend(self.flush());
                    self.disabled = true;
                    return parts;
                }
                Peek::Frame(len) => {
                    if self.cipher_buf.len() < len || self.plain_buf.len() < len {
                        return parts;
                    }
                    parts.push(self.cipher_buf.drain(..len).collect());
                    self.plain_buf.drain(..len);
                }
            }
        }
    }

    /// Hand back whatever ciphertext is buffered, whole.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }
        let tail = std::mem::take(&mut self.cipher_buf);
        self.plain_buf.clear();
        vec![tail]
    }

    fn peek_packet_size(&self) -> Peek {
        if self.plain_buf.is_empty() {
            return Peek::NeedMore;
        }
        match self.proto {
            ProtoType::Abridged => self.peek_abridged(),
            ProtoType::Intermediate | ProtoType::PaddedIntermediate => self.peek_intermediate(),
        }
    }

    fn peek_abridged(&self) -> Peek {
        let length_tag = self.plain_buf[0] & 0x7F;
        let (header_size, payload_size) = if length_tag == 0x7F {
            if self.plain_buf.len() < 4 {
                return Peek::NeedMore;
            }
            let payload = (self.plain_buf[1] as usize)
                | ((self.plain_buf[2] as usize) << 8)
                | ((self.plain_buf[3] as usize) << 16);
            (4usize, payload * 4)
        } else {
            (1usize, length_tag as usize * 4)
        };
        if payload_size == 0 {
            return Peek::GiveUp;
        }
        let frame_size = header_size + payload_size;
        if self.plain_buf.len() < frame_size {
            return Peek::NeedMore;
        }
        Peek::Frame(frame_size)
    }

    fn peek_intermediate(&self) -> Peek {
        if self.plain_buf.len() < 4 {
            return Peek::NeedMore;
        }
        let raw = u32::from_le_bytes([self.plain_buf[0], self.plain_buf[1], self.plain_buf[2], self.plain_buf[3]]);
        let payload_size = (raw & 0x7FFF_FFFF) as usize;
        if payload_size == 0 {
            return Peek::GiveUp;
        }
        let frame_size = 4 + payload_size;
        if self.plain_buf.len() < frame_size {
            return Peek::NeedMore;
        }
        Peek::Frame(frame_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity keystream: plaintext equals ciphertext, so a test can state the
    /// frame bytes directly and still exercise the real buffer bookkeeping.
    struct Identity {
        advanced: usize,
    }

    impl KeyStream for Identity {
        fn update(&mut self, data: &[u8]) -> Vec<u8> {
            self.advanced += data.len();
            data.to_vec()
        }
    }

    fn intermediate() -> MsgSplitter<Identity> {
        MsgSplitter::new(Identity { advanced: 0 }, ProtoType::Intermediate)
    }

    fn abridged() -> MsgSplitter<Identity> {
        MsgSplitter::new(Identity { advanced: 0 }, ProtoType::Abridged)
    }

    fn inter_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn the_keystream_is_advanced_past_the_64_zero_bytes_on_construction() {
        let mut stream = Identity { advanced: 0 };
        let _ = stream.update(&[]);
        let splitter = MsgSplitter::new(Identity { advanced: 0 }, ProtoType::Abridged);
        // Reach in through a fresh instance: construction alone must have moved it.
        assert_eq!(splitter.stream.advanced, 64);
    }

    #[test]
    fn intermediate_frames_split_on_their_length_prefix() {
        let mut s = intermediate();
        let mut wire = inter_frame(b"abcd");
        wire.extend(inter_frame(b"efghij"));
        let parts = s.split(&wire);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], inter_frame(b"abcd"));
        assert_eq!(parts[1], inter_frame(b"efghij"));
    }

    #[test]
    fn a_frame_arriving_in_pieces_is_held_until_complete() {
        let mut s = intermediate();
        let wire = inter_frame(b"abcdefgh");
        assert!(s.split(&wire[..3]).is_empty(), "length prefix incomplete");
        assert!(s.split(&wire[3..6]).is_empty(), "payload incomplete");
        let parts = s.split(&wire[6..]);
        assert_eq!(parts, vec![wire.clone()]);
    }

    #[test]
    fn an_empty_chunk_yields_nothing_and_changes_nothing() {
        let mut s = intermediate();
        assert!(s.split(b"").is_empty());
        assert!(!s.is_disabled());
    }

    #[test]
    fn a_zero_length_payload_gives_up_and_flushes_the_tail() {
        let mut s = intermediate();
        let mut wire = inter_frame(b"abcd");
        wire.extend_from_slice(&0u32.to_le_bytes()); // zero-length payload
        wire.extend_from_slice(b"trailing bytes");
        let parts = s.split(&wire);
        assert_eq!(parts[0], inter_frame(b"abcd"));
        // Everything from the zero-length header on comes back as one tail.
        let tail: Vec<u8> = parts[1..].concat();
        assert!(tail.ends_with(b"trailing bytes"));
        assert!(s.is_disabled());
    }

    #[test]
    fn once_disabled_chunks_pass_through_untouched() {
        let mut s = intermediate();
        let _ = s.split(&0u32.to_le_bytes());
        assert!(s.is_disabled());
        assert_eq!(s.split(b"raw"), vec![b"raw".to_vec()]);
        assert_eq!(s.split(b"more"), vec![b"more".to_vec()]);
    }

    #[test]
    fn the_high_bit_of_the_intermediate_length_is_masked_off() {
        let mut s = intermediate();
        let mut wire = (0x8000_0004u32).to_le_bytes().to_vec();
        wire.extend_from_slice(b"abcd");
        let parts = s.split(&wire);
        assert_eq!(parts.len(), 1, "0x80000004 must read as a 4-byte payload");
        assert_eq!(parts[0].len(), 8);
    }

    #[test]
    fn abridged_short_form_multiplies_the_tag_by_four() {
        let mut s = abridged();
        let mut wire = vec![2u8]; // 2 * 4 = 8 bytes of payload
        wire.extend_from_slice(b"abcdefgh");
        let parts = s.split(&wire);
        assert_eq!(parts, vec![wire.clone()]);
    }

    #[test]
    fn abridged_long_form_reads_three_little_endian_bytes() {
        let mut s = abridged();
        // 0x7F marks the long form; payload = 3 * 4 = 12
        let mut wire = vec![0x7F, 3, 0, 0];
        wire.extend_from_slice(&[b'x'; 12]);
        let parts = s.split(&wire);
        assert_eq!(parts, vec![wire.clone()]);
    }

    #[test]
    fn abridged_long_form_waits_for_its_own_header() {
        let mut s = abridged();
        assert!(s.split(&[0x7F, 3]).is_empty(), "header itself incomplete");
        assert!(!s.is_disabled());
    }

    #[test]
    fn an_abridged_zero_tag_gives_up() {
        let mut s = abridged();
        let parts = s.split(&[0u8, 1, 2, 3]);
        assert!(s.is_disabled());
        assert_eq!(parts.concat(), vec![0u8, 1, 2, 3]);
    }

    #[test]
    fn flush_on_an_empty_buffer_yields_nothing() {
        let mut s = intermediate();
        assert!(s.flush().is_empty());
    }

    #[test]
    fn init_material_takes_the_documented_offsets() {
        let init: Vec<u8> = (0..64u8).collect();
        let (key, iv) = init_material(&init).expect("64 bytes is enough");
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);
        assert_eq!(key[0], 8, "key starts at offset 8");
        assert_eq!(iv[0], 40, "iv starts at offset 40");
    }

    #[test]
    fn init_material_rejects_a_short_packet() {
        let init = vec![0u8; MIN_INIT_LEN - 1];
        assert_eq!(init_material(&init), Err(SplitterError::InitTooShort { len: MIN_INIT_LEN - 1 }));
    }

    #[test]
    fn proto_tags_map_both_leniently_and_strictly() {
        assert_eq!(ProtoType::from_tag(TAG_INTERMEDIATE), ProtoType::Intermediate);
        assert_eq!(ProtoType::from_tag(TAG_PADDED_INTERMEDIATE), ProtoType::PaddedIntermediate);
        assert_eq!(ProtoType::from_tag(TAG_ABRIDGED), ProtoType::Abridged);
        assert_eq!(ProtoType::from_tag(0x1234_5678), ProtoType::Abridged, "lenient mapping falls back to abridged");
        assert_eq!(ProtoType::from_tag_checked(0x1234_5678), None);
        assert_eq!(ProtoType::from_tag_checked(TAG_ABRIDGED), Some(ProtoType::Abridged));
    }

    #[test]
    fn padded_intermediate_frames_like_intermediate() {
        let mut s = MsgSplitter::new(Identity { advanced: 0 }, ProtoType::PaddedIntermediate);
        let wire = inter_frame(b"abcd");
        assert_eq!(s.split(&wire), vec![wire.clone()]);
    }
}
