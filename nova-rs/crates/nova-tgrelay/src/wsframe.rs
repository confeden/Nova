//! RFC 6455 framing, as a codec that never touches a socket.
//!
//! Layer 9 of the port out of `tgrelay/raw_websocket.py`. The Python module is
//! `RawWebSocket`, which mixes framing with the stream it reads from; here the
//! two are apart, so every frame the relay could receive can be constructed in a
//! test as a byte slice.
//!
//! Three rules carried over, and three added. Carried over:
//!
//! - **The reserved bits must be zero.** No extension is ever negotiated, so a
//!   set RSV1 means the peer is deflating. Reading past it is how a compressed
//!   frame gets handed on as though it were MTProto: no exception, no log line,
//!   just a stream the client cannot parse and cannot explain.
//! - **A close frame's first two bytes are echoed back** and nothing else.
//! - **Every frame this side sends is masked**, as a client must.
//!
//! Added, each because the Python's absence of it is a real hole:
//!
//! - **A payload cap.** `readexactly(length)` with a 63-bit length off the wire
//!   is a memory bomb that any peer can fire.
//! - **Control frames are validated.** RFC 6455 §5.5 forbids them from being
//!   fragmented or longer than 125 bytes; the Python accepts a 4 GiB ping.
//! - **Fragments are reassembled.** See [`MessageReader`] — this is the one
//!   deviation that changes what the relay delivers, and it is a fix.

use std::time::Duration;

/// The largest payload a single frame may declare.
///
/// Nothing legitimate on this path comes close: the relay's own uploads go out
/// in 64 KiB reads and Telegram's media frames are smaller still. The number
/// exists so a hostile or broken peer cannot ask for an allocation.
pub const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;

/// The largest message reassembled out of fragments.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// RFC 6455 §5.5: a control frame carries at most this much and is never
/// fragmented.
pub const MAX_CONTROL_PAYLOAD: u64 = 125;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    /// Everything RFC 6455 leaves unassigned.
    Reserved(u8),
}

impl Opcode {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x0F {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => Self::Reserved(other),
        }
    }

    pub fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
            Self::Reserved(bits) => bits & 0x0F,
        }
    }

    /// Control frames are `0x8`-`0xF`; data frames are `0x0`-`0x7`.
    pub fn is_control(self) -> bool {
        self.bits() & 0x08 != 0
    }
}

/// Why a frame could not be read. Every one of these ends the tunnel: none is
/// something a well-behaved peer produces, and continuing past any of them means
/// forwarding bytes whose meaning is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// An extension is in use that was never negotiated, so its payload cannot
    /// be decoded. Almost always permessage-deflate.
    ReservedBitsSet(u8),
    /// The declared length exceeds [`MAX_FRAME_PAYLOAD`].
    PayloadTooLarge(u64),
    /// A control frame longer than 125 bytes, or one with `FIN` clear.
    MalformedControlFrame,
    /// A continuation arrived with no message open, or a new data frame arrived
    /// while one was.
    UnexpectedContinuation,
    /// Reassembly exceeded [`MAX_MESSAGE`].
    MessageTooLarge,
    /// An opcode RFC 6455 does not define.
    UnknownOpcode(u8),
}

/// A frame's header, and how long it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    pub opcode: Opcode,
    pub mask: Option<[u8; 4]>,
    pub payload_len: u64,
    /// Bytes consumed by the header itself.
    pub header_len: usize,
}

impl FrameHeader {
    /// Total wire size of this frame.
    pub fn frame_len(&self) -> u64 {
        self.header_len as u64 + self.payload_len
    }
}

/// Parse a header. `Ok(None)` means "not enough bytes yet", never an error.
pub fn parse_header(buf: &[u8]) -> Result<Option<FrameHeader>, FrameError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let reserved = buf[0] & 0x70;
    if reserved != 0 {
        return Err(FrameError::ReservedBitsSet(reserved));
    }
    let fin = buf[0] & 0x80 != 0;
    let opcode = Opcode::from_bits(buf[0]);
    if let Opcode::Reserved(bits) = opcode {
        return Err(FrameError::UnknownOpcode(bits));
    }
    let masked = buf[1] & 0x80 != 0;
    let short_len = buf[1] & 0x7F;

    let (payload_len, mut offset) = match short_len {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            (u64::from_be_bytes(buf[2..10].try_into().expect("10 bytes")), 10)
        }
        n => (u64::from(n), 2),
    };

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::PayloadTooLarge(payload_len));
    }
    if opcode.is_control() && (payload_len > MAX_CONTROL_PAYLOAD || !fin) {
        return Err(FrameError::MalformedControlFrame);
    }

    let mask = if masked {
        if buf.len() < offset + 4 {
            return Ok(None);
        }
        let key: [u8; 4] = buf[offset..offset + 4].try_into().expect("4 bytes");
        offset += 4;
        Some(key)
    } else {
        None
    };

    Ok(Some(FrameHeader { fin, opcode, mask, payload_len, header_len: offset }))
}

/// XOR a payload with its 4-byte key, in place.
///
/// The Python does this as one big-integer XOR over the whole payload; the
/// result is byte-wise with the key repeating from index 0, which is what this
/// is. A parity test pins the two against each other.
pub fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

/// Where a frame's mask comes from.
///
/// Injectable for two reasons: a test can pin the exact bytes on the wire, and
/// the one place that needs operating-system randomness is named here instead of
/// being reached for from inside the codec — which is what let the Python's
/// `_build_frame` call `os.urandom` in a module that also owned a TLS context.
pub trait MaskSource {
    fn next_mask(&mut self) -> [u8; 4];
}

/// A mask that never changes. **Tests only.** A real client must not reuse one:
/// the mask exists so a hostile page cannot make a browser emit chosen plaintext
/// through a proxy, and a constant defeats it entirely.
#[derive(Debug, Clone, Copy)]
pub struct FixedMask(pub [u8; 4]);

impl MaskSource for FixedMask {
    fn next_mask(&mut self) -> [u8; 4] {
        self.0
    }
}

/// Build one frame. `FIN` is always set — this side never fragments.
pub fn build_frame(opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode.bits());
    let masked_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(masked_bit | len as u8);
    } else if len < 65536 {
        out.push(masked_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(masked_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(payload);
            apply_mask(&mut out[start..], key);
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// What the reader produced from the bytes it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// Feed more bytes.
    NeedMore,
    /// A complete data message, fragments already joined.
    Message(Vec<u8>),
    /// Answer with a pong carrying this payload, then keep reading.
    Ping(Vec<u8>),
    /// Nothing to do; keep reading.
    Pong,
    /// The peer is closing. The code, when it sent one.
    Close(Option<u16>),
}

/// Frames in, messages out.
///
/// **This is the one place the port changes what the relay delivers, and it is a
/// fix.** `RawWebSocket.recv` returns a frame's payload the moment its opcode is
/// `0x1` or `0x2`, without ever looking at `FIN`, and then `continue`s past every
/// `0x0` continuation. A fragmented message therefore arrives truncated to its
/// first fragment with the remainder silently discarded — and since MTProto has
/// its own framing on top, the client does not see an error, it sees a stream
/// that has quietly desynchronised. Nothing on the Cloudflare path is known to
/// fragment, which is why this has never been diagnosed rather than why it is
/// safe.
#[derive(Debug, Clone)]
pub struct MessageReader {
    buf: Vec<u8>,
    /// The opcode and bytes of a message still being assembled.
    partial: Option<(Opcode, Vec<u8>)>,
    max_message: usize,
}

impl Default for MessageReader {
    fn default() -> Self {
        Self::new(MAX_MESSAGE)
    }
}

impl MessageReader {
    pub fn new(max_message: usize) -> Self {
        Self { buf: Vec::new(), partial: None, max_message }
    }

    /// Bytes held pending a complete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// True while a fragmented message is open.
    pub fn is_mid_message(&self) -> bool {
        self.partial.is_some()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Take the next thing the peer said, if a whole frame has arrived.
    ///
    /// Called in a loop until it answers [`Incoming::NeedMore`]: one read off a
    /// socket can carry several frames, and stopping at the first would leave
    /// the rest sitting in the buffer until more bytes happened to arrive — a
    /// stall that looks exactly like a dead route.
    pub fn next_incoming(&mut self) -> Result<Incoming, FrameError> {
        let Some(header) = parse_header(&self.buf)? else {
            return Ok(Incoming::NeedMore);
        };
        if (self.buf.len() as u64) < header.frame_len() {
            return Ok(Incoming::NeedMore);
        }

        let start = header.header_len;
        let end = start + header.payload_len as usize;
        let mut payload = self.buf[start..end].to_vec();
        if let Some(key) = header.mask {
            apply_mask(&mut payload, key);
        }
        self.buf.drain(..end);

        match header.opcode {
            // Control frames may arrive *between* the fragments of a data
            // message, so they are answered without disturbing what is open.
            Opcode::Close => {
                let code = (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                Ok(Incoming::Close(code))
            }
            Opcode::Ping => Ok(Incoming::Ping(payload)),
            Opcode::Pong => Ok(Incoming::Pong),
            Opcode::Continuation => {
                let Some((_, buffered)) = self.partial.as_mut() else {
                    return Err(FrameError::UnexpectedContinuation);
                };
                if buffered.len() + payload.len() > self.max_message {
                    self.partial = None;
                    return Err(FrameError::MessageTooLarge);
                }
                buffered.extend_from_slice(&payload);
                if header.fin {
                    let (_, message) = self.partial.take().expect("checked");
                    Ok(Incoming::Message(message))
                } else {
                    Ok(Incoming::NeedMore)
                }
            }
            Opcode::Text | Opcode::Binary => {
                if self.partial.is_some() {
                    // A new data frame while a message is open is not something
                    // RFC 6455 allows, and guessing which one the caller wanted
                    // would be worse than saying so.
                    self.partial = None;
                    return Err(FrameError::UnexpectedContinuation);
                }
                if payload.len() > self.max_message {
                    return Err(FrameError::MessageTooLarge);
                }
                if header.fin {
                    Ok(Incoming::Message(payload))
                } else {
                    self.partial = Some((header.opcode, payload));
                    Ok(Incoming::NeedMore)
                }
            }
            Opcode::Reserved(bits) => Err(FrameError::UnknownOpcode(bits)),
        }
    }
}

/// Which endpoints took us up on the compression offer.
///
/// Nothing in the relay can decode a deflated frame, so the offer is withdrawn
/// for that endpoint and the next attempt goes out without it, rather than the
/// connection failing forever. The set only grows: an endpoint that once
/// deflated is assumed to still want to.
#[derive(Debug, Clone, Default)]
pub struct DeflateOffers {
    refused: std::collections::HashSet<String>,
}

impl DeflateOffers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn offers_deflate(&self, domain: &str) -> bool {
        !self.refused.contains(&domain.trim().to_ascii_lowercase())
    }

    pub fn note_unusable(&mut self, domain: &str) {
        let key = domain.trim().to_ascii_lowercase();
        if !key.is_empty() {
            self.refused.insert(key);
        }
    }
}

/// `set_sock_opts`' buffer size, kept beside the codec because that is where the
/// Python keeps it. The socket call itself belongs to the net crate.
pub const SOCKET_BUFFER_HINT: usize = 1024 * 1024;

/// How long the Python waits for a WebSocket writer to finish closing.
pub const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    fn server_frame(opcode: Opcode, payload: &[u8], fin: bool) -> Vec<u8> {
        let mut f = build_frame(opcode, payload, None);
        if !fin {
            f[0] &= 0x7F;
        }
        f
    }

    #[test]
    fn opcodes_round_trip_through_their_bits() {
        for op in [Opcode::Continuation, Opcode::Text, Opcode::Binary, Opcode::Close, Opcode::Ping, Opcode::Pong] {
            assert_eq!(Opcode::from_bits(op.bits()), op);
        }
        assert!(Opcode::Close.is_control() && Opcode::Ping.is_control() && Opcode::Pong.is_control());
        assert!(!Opcode::Binary.is_control() && !Opcode::Continuation.is_control());
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let mut data = b"telegram".to_vec();
        let original = data.clone();
        apply_mask(&mut data, KEY);
        assert_ne!(data, original);
        apply_mask(&mut data, KEY);
        assert_eq!(data, original);
    }

    #[test]
    fn the_three_length_encodings_are_used_at_their_boundaries() {
        assert_eq!(build_frame(Opcode::Binary, &[0u8; 125], None)[1], 125);
        assert_eq!(build_frame(Opcode::Binary, &[0u8; 126], None)[1], 126);
        assert_eq!(build_frame(Opcode::Binary, &[0u8; 65535], None)[1], 126);
        assert_eq!(build_frame(Opcode::Binary, &[0u8; 65536], None)[1], 127);
    }

    #[test]
    fn a_built_frame_parses_back_to_what_it_was_built_from() {
        for len in [0usize, 1, 125, 126, 1000, 65535, 65536] {
            let payload = vec![0xA5; len];
            let frame = build_frame(Opcode::Binary, &payload, Some(KEY));
            let header = parse_header(&frame).expect("valid").expect("complete");
            assert!(header.fin);
            assert_eq!(header.opcode, Opcode::Binary);
            assert_eq!(header.mask, Some(KEY));
            assert_eq!(header.payload_len, len as u64, "len {len}");
            assert_eq!(header.frame_len(), frame.len() as u64);
            let mut body = frame[header.header_len..].to_vec();
            apply_mask(&mut body, KEY);
            assert_eq!(body, payload);
        }
    }

    #[test]
    fn a_header_split_across_reads_asks_for_more_rather_than_guessing() {
        let frame = build_frame(Opcode::Binary, &[0u8; 70000], Some(KEY));
        for cut in [0usize, 1, 2, 3, 9, 10, 13] {
            assert_eq!(parse_header(&frame[..cut]), Ok(None), "cut at {cut}");
        }
        assert!(parse_header(&frame[..14]).expect("valid").is_some());
    }

    #[test]
    fn reserved_bits_are_refused_rather_than_read_past() {
        // The whole reason this check exists: a deflated payload handed on as
        // MTProto produces no error anywhere, just a stream the client cannot
        // parse and cannot explain.
        let mut frame = build_frame(Opcode::Binary, b"compressed", None);
        frame[0] |= 0x40; // RSV1
        assert_eq!(parse_header(&frame), Err(FrameError::ReservedBitsSet(0x40)));
    }

    #[test]
    fn a_declared_length_no_peer_could_mean_is_refused_before_allocating() {
        // `readexactly(2**63)` in the Python. Any peer can fire it.
        let mut frame = vec![0x82, 127];
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(parse_header(&frame), Err(FrameError::PayloadTooLarge(u64::MAX)));
    }

    #[test]
    fn an_oversized_or_fragmented_control_frame_is_refused() {
        let mut long_ping = vec![0x89, 126];
        long_ping.extend_from_slice(&200u16.to_be_bytes());
        assert_eq!(parse_header(&long_ping), Err(FrameError::MalformedControlFrame));

        let fragmented_close = vec![0x08, 0x00];
        assert_eq!(parse_header(&fragmented_close), Err(FrameError::MalformedControlFrame));
    }

    #[test]
    fn an_undefined_opcode_is_refused() {
        assert_eq!(parse_header(&[0x83, 0x00]), Err(FrameError::UnknownOpcode(0x3)));
    }

    #[test]
    fn a_whole_message_arrives_as_one() {
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Binary, b"mtproto", true));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"mtproto".to_vec())));
        assert_eq!(reader.next_incoming(), Ok(Incoming::NeedMore));
    }

    #[test]
    fn several_frames_in_one_read_all_come_out() {
        // A single socket read routinely carries more than one frame. Stopping
        // at the first would leave the rest waiting for bytes that may not come.
        let mut reader = MessageReader::default();
        let mut wire = server_frame(Opcode::Binary, b"one", true);
        wire.extend(server_frame(Opcode::Binary, b"two", true));
        wire.extend(server_frame(Opcode::Ping, b"p", true));
        reader.feed(&wire);
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"one".to_vec())));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"two".to_vec())));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Ping(b"p".to_vec())));
        assert_eq!(reader.next_incoming(), Ok(Incoming::NeedMore));
    }

    #[test]
    fn a_fragmented_message_is_joined_instead_of_truncated() {
        // The Python returns `"frag"` here and silently drops the rest, leaving
        // the MTProto stream desynchronised with nothing logged.
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Binary, b"frag", false));
        assert_eq!(reader.next_incoming(), Ok(Incoming::NeedMore));
        assert!(reader.is_mid_message());
        reader.feed(&server_frame(Opcode::Continuation, b"ment", false));
        assert_eq!(reader.next_incoming(), Ok(Incoming::NeedMore));
        reader.feed(&server_frame(Opcode::Continuation, b"ed", true));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"fragmented".to_vec())));
        assert!(!reader.is_mid_message());
    }

    #[test]
    fn a_control_frame_between_fragments_does_not_disturb_them() {
        // RFC 6455 explicitly allows this, and answering the ping must not lose
        // the half-assembled message.
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Binary, b"half", false));
        reader.next_incoming().expect("need more");
        reader.feed(&server_frame(Opcode::Ping, b"ping", true));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Ping(b"ping".to_vec())));
        assert!(reader.is_mid_message());
        reader.feed(&server_frame(Opcode::Continuation, b"done", true));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"halfdone".to_vec())));
    }

    #[test]
    fn a_continuation_with_nothing_open_is_an_error_not_a_silent_drop() {
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Continuation, b"orphan", true));
        assert_eq!(reader.next_incoming(), Err(FrameError::UnexpectedContinuation));
    }

    #[test]
    fn a_new_data_frame_while_a_message_is_open_is_an_error() {
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Binary, b"first", false));
        reader.next_incoming().expect("need more");
        reader.feed(&server_frame(Opcode::Binary, b"second", true));
        assert_eq!(reader.next_incoming(), Err(FrameError::UnexpectedContinuation));
    }

    #[test]
    fn reassembly_is_bounded() {
        let mut reader = MessageReader::new(8);
        reader.feed(&server_frame(Opcode::Binary, b"1234", false));
        reader.next_incoming().expect("need more");
        reader.feed(&server_frame(Opcode::Continuation, b"56789", true));
        assert_eq!(reader.next_incoming(), Err(FrameError::MessageTooLarge));
        assert!(!reader.is_mid_message(), "the half-message is dropped with the error");
    }

    #[test]
    fn a_close_frame_yields_its_code_when_it_carries_one() {
        let mut reader = MessageReader::default();
        reader.feed(&server_frame(Opcode::Close, &1000u16.to_be_bytes(), true));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Close(Some(1000))));

        let mut bare = MessageReader::default();
        bare.feed(&server_frame(Opcode::Close, b"", true));
        assert_eq!(bare.next_incoming(), Ok(Incoming::Close(None)));
    }

    #[test]
    fn a_masked_server_frame_is_still_unmasked_correctly() {
        // A server must not mask, but the Python accepts one that does and so
        // does this. Refusing it would be more correct and less useful.
        let mut reader = MessageReader::default();
        reader.feed(&build_frame(Opcode::Binary, b"masked", Some(KEY)));
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"masked".to_vec())));
    }

    #[test]
    fn a_partial_frame_is_held_rather_than_half_read() {
        let frame = server_frame(Opcode::Binary, b"payload", true);
        let mut reader = MessageReader::default();
        reader.feed(&frame[..4]);
        assert_eq!(reader.next_incoming(), Ok(Incoming::NeedMore));
        assert_eq!(reader.buffered(), 4);
        reader.feed(&frame[4..]);
        assert_eq!(reader.next_incoming(), Ok(Incoming::Message(b"payload".to_vec())));
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn a_deflating_endpoint_has_the_offer_withdrawn_and_never_regains_it() {
        let mut offers = DeflateOffers::new();
        assert!(offers.offers_deflate("kws2.nova-app.eu"));
        offers.note_unusable("  KWS2.Nova-App.eu ");
        assert!(!offers.offers_deflate("kws2.nova-app.eu"));
        assert!(offers.offers_deflate("kws2.pclead.co.uk"));
        offers.note_unusable("   ");
        assert!(offers.offers_deflate(""));
    }
}
