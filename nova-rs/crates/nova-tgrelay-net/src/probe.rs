//! The cheapest honest question one can ask an egress.
//!
//! Layer 19, the port of `_build_native_probe`. An obfuscated2 init packet plus
//! a `req_pq_multi`, framed for the abridged transport. Telegram answers it with
//! `resPQ` before any authorisation, so it asks not "does TCP open" but **"does
//! this data centre talk back through you"** — which is the difference between
//! an egress that is reachable and one that works, and the whole reason the
//! native health table exists.
//!
//! **The random 64 bytes are not merely random.** obfuscated2 requires that the
//! init packet cannot be mistaken for something else on the wire, so four
//! first-dwords are rejected because they spell `HEAD`, `POST`, `GET ` and
//! `OPTI`; two because they are the intermediate and padded-intermediate
//! transport tags; and `0x02010316` because those bytes are `16 03 01 02` — a
//! **TLS record header**. A first byte of `0xEF` is the abridged tag, and bytes
//! 4..8 must not be zero.

use nova_tgrelay::frame::KeyStream;

use crate::keystream::AesCtrKeyStream;

/// `PROTO_ABRIDGED`, written into the init packet at 56..60.
pub const PROTO_ABRIDGED: u32 = 0xEFEF_EFEF;
/// `req_pq_multi`'s constructor id.
pub const REQ_PQ_MULTI: u32 = 0xBE7E_8EF1;

/// First dwords an obfuscated2 init packet may not begin with.
///
/// Four are HTTP verbs, two are transport tags, and the last is a TLS record
/// header — each one a thing a middlebox would read the packet as if it were
/// allowed through.
pub const FORBIDDEN_FIRST_DWORDS: [u32; 7] =
    [0x4441_4548, 0x5453_4F50, 0x2054_4547, 0x4954_504F, 0xDDDD_DDDD, 0xEEEE_EEEE, 0x0201_0316];

/// How many candidate init packets are drawn before giving up.
///
/// The Python loops forever. With a working source the rejection rate is about
/// one in half a billion, so any number here is effectively never reached — but
/// a source that returns a constant would spin that loop until the process is
/// killed, and a bounded failure is easier to diagnose than a hang.
pub const MAX_INIT_DRAWS: usize = 64;

/// Where the probe's entropy comes from. Injectable so a test can pin the bytes.
pub trait ProbeRandom {
    fn fill(&mut self, out: &mut [u8]);
}

/// The operating system's source.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl ProbeRandom for OsRandom {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::fill(out).expect("the OS random source is unavailable");
    }
}

/// Whether these 64 bytes may be used as an init packet.
pub fn init_is_acceptable(buf: &[u8; 64]) -> bool {
    if buf[0] == 0xEF {
        return false;
    }
    let first = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if FORBIDDEN_FIRST_DWORDS.contains(&first) {
        return false;
    }
    u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) != 0
}

/// The `msg_id` Telegram expects: the second count in the high 32 bits.
pub fn msg_id_for(unix_seconds: u64) -> u64 {
    (unix_seconds << 32) & 0x7FFF_FFFF_FFFF_FFFF
}

/// Build one probe for `dc`.
///
/// `None` when the random source could not produce a usable init packet — see
/// [`MAX_INIT_DRAWS`].
pub fn build_native_probe(dc: i16, unix_seconds: u64, random: &mut impl ProbeRandom) -> Option<Vec<u8>> {
    let mut buf = [0u8; 64];
    let mut drawn = 0;
    loop {
        random.fill(&mut buf);
        if init_is_acceptable(&buf) {
            break;
        }
        drawn += 1;
        if drawn >= MAX_INIT_DRAWS {
            return None;
        }
    }
    buf[56..60].copy_from_slice(&PROTO_ABRIDGED.to_le_bytes());
    buf[60..62].copy_from_slice(&dc.to_le_bytes());

    let mut stream = AesCtrKeyStream::new(&buf[8..40], &buf[40..56])?;
    // The whole 64 bytes go through the cipher, but only the last eight of the
    // result travel: the key and IV must reach the far side in the clear, and
    // the tag and DC must not.
    let wire = stream.update(&buf);
    let mut probe = Vec::with_capacity(105);
    probe.extend_from_slice(&buf[..56]);
    probe.extend_from_slice(&wire[56..64]);

    let mut nonce = [0u8; 16];
    random.fill(&mut nonce);
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&REQ_PQ_MULTI.to_le_bytes());
    body.extend_from_slice(&nonce);

    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&0i64.to_le_bytes()); // auth_key_id: unauthorised
    payload.extend_from_slice(&msg_id_for(unix_seconds).to_le_bytes());
    payload.extend_from_slice(&(body.len() as i32).to_le_bytes());
    payload.extend_from_slice(&body);

    // Abridged framing: one byte carrying the payload's length in 4-byte words.
    let mut framed = Vec::with_capacity(41);
    framed.push((payload.len() / 4) as u8);
    framed.extend_from_slice(&payload);

    // The keystream is already 64 bytes in, which is exactly where the tunnel
    // payload starts — the same offset `MsgSplitter` skips to.
    probe.extend_from_slice(&stream.update(&framed));
    Some(probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stand-in the oracle used: `(i * 7 + call * 13) % 251`.
    struct Scripted {
        calls: u8,
    }

    impl ProbeRandom for Scripted {
        fn fill(&mut self, out: &mut [u8]) {
            self.calls += 1;
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = ((i * 7 + usize::from(self.calls) * 13) % 251) as u8;
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_probe_is_byte_for_byte_what_the_python_builds() {
        // Produced by executing `_build_native_probe` with the same scripted
        // entropy and a clock of 1_700_000_000.
        let mut probe = build_native_probe(2, 1_700_000_000, &mut Scripted { calls: 0 }).expect("probe");
        assert_eq!(probe.len(), 105, "64-byte init plus a 41-byte abridged frame");
        assert_eq!(
            hex(&probe[..56]),
            "0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf400070e151c232a31383f464d545b626970777e858c93"
        );
        assert_eq!(hex(&probe[56..64]), "59859a0bc6eaf95b", "the tag and DC, encrypted");
        assert_eq!(
            hex(&probe[64..]),
            "902ceae0508747e5053d9df9937dd902b62fbaddde3e1e770a936d3725627064cb38362a95090580d6"
        );
        probe.clear();
    }

    #[test]
    fn the_key_and_iv_travel_in_the_clear_and_the_tag_does_not() {
        // The far side needs the key material to decrypt anything at all, so
        // bytes 8..56 are the raw draw; 56..64 are encrypted because the tag and
        // DC are what a middlebox would read.
        let raw: Vec<u8> = (0..64usize).map(|i| ((i * 7 + 13) % 251) as u8).collect();
        let probe = build_native_probe(2, 1_700_000_000, &mut Scripted { calls: 0 }).expect("probe");
        assert_eq!(&probe[..56], &raw[..56]);
        assert_ne!(&probe[56..64], &[0xEF, 0xEF, 0xEF, 0xEF, 2, 0, raw[62], raw[63]][..]);
    }

    #[test]
    fn the_dc_number_lands_where_telegram_looks_for_it() {
        // Signed and little-endian: media DCs are the negative of the same
        // number, which is how `parse_transparent_init_info` reads them back.
        for dc in [1i16, 2, 5, -2, -4] {
            let probe = build_native_probe(dc, 1_700_000_000, &mut Scripted { calls: 0 }).expect("probe");
            // Undo the cipher over the encrypted tail to read the field back.
            let mut stream = AesCtrKeyStream::new(&probe[8..40], &probe[40..56]).expect("material");
            let mut full = probe[..56].to_vec();
            full.extend_from_slice(&[0u8; 8]);
            let keystream = stream.update(&full);
            let plain: Vec<u8> = probe[56..64].iter().zip(&keystream[56..64]).map(|(c, k)| c ^ k).collect();
            assert_eq!(u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]), PROTO_ABRIDGED);
            assert_eq!(i16::from_le_bytes([plain[4], plain[5]]), dc, "dc {dc}");
        }
    }

    #[test]
    fn the_forbidden_first_dwords_are_what_they_look_like() {
        // Four HTTP verbs, two transport tags, and a TLS record header. If one
        // of these ever reached the wire the packet would be read as that thing.
        let as_bytes = |v: u32| v.to_le_bytes();
        assert_eq!(&as_bytes(FORBIDDEN_FIRST_DWORDS[0]), b"HEAD");
        assert_eq!(&as_bytes(FORBIDDEN_FIRST_DWORDS[1]), b"POST");
        assert_eq!(&as_bytes(FORBIDDEN_FIRST_DWORDS[2]), b"GET ");
        assert_eq!(&as_bytes(FORBIDDEN_FIRST_DWORDS[3]), b"OPTI");
        assert_eq!(as_bytes(FORBIDDEN_FIRST_DWORDS[6]), [0x16, 0x03, 0x01, 0x02], "a TLS record header");
    }

    #[test]
    fn an_unacceptable_draw_is_refused() {
        let mut buf = [1u8; 64];
        assert!(init_is_acceptable(&buf));

        buf[0] = 0xEF;
        assert!(!init_is_acceptable(&buf), "the abridged tag");

        for forbidden in FORBIDDEN_FIRST_DWORDS {
            let mut candidate = [1u8; 64];
            candidate[..4].copy_from_slice(&forbidden.to_le_bytes());
            assert!(!init_is_acceptable(&candidate), "{forbidden:#010x}");
        }

        let mut zeroed = [1u8; 64];
        zeroed[4..8].copy_from_slice(&[0, 0, 0, 0]);
        assert!(!init_is_acceptable(&zeroed), "bytes 4..8 must not be zero");
    }

    #[test]
    fn a_source_that_never_produces_a_usable_packet_fails_instead_of_hanging() {
        // The Python's loop is `while True`. A constant source spins it until
        // the process is killed; a bounded failure is easier to diagnose.
        struct Constant;
        impl ProbeRandom for Constant {
            fn fill(&mut self, out: &mut [u8]) {
                out.fill(0xEF);
            }
        }
        assert!(build_native_probe(2, 1_700_000_000, &mut Constant).is_none());
    }

    #[test]
    fn the_msg_id_puts_the_clock_in_the_high_half() {
        assert_eq!(msg_id_for(1_700_000_000), 0x6553_F100_0000_0000);
        // The top bit is always clear, so the value stays positive when Telegram
        // reads it as a signed 64-bit integer.
        assert_eq!(msg_id_for(u64::MAX) & 0x8000_0000_0000_0000, 0);
    }

    #[test]
    fn the_frame_declares_its_own_length_in_words() {
        let probe = build_native_probe(2, 1_700_000_000, &mut Scripted { calls: 0 }).expect("probe");
        // The abridged length byte is encrypted, so read it back through the
        // keystream at offset 64.
        let mut stream = AesCtrKeyStream::new(&probe[8..40], &probe[40..56]).expect("material");
        let _ = stream.update(&[0u8; 64]);
        let plain = stream.update(&probe[64..]);
        assert_eq!(plain[0], 10, "40 bytes of payload is ten words");
        assert_eq!(plain.len(), 41);
        // auth_key_id zero — the probe is asked before any authorisation.
        assert_eq!(&plain[1..9], &[0u8; 8]);
        assert_eq!(u32::from_le_bytes([plain[21], plain[22], plain[23], plain[24]]), REQ_PQ_MULTI);
    }
}
