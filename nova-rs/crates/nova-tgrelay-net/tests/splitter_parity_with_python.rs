//! MTProto framing, against the real cipher and the real Python splitter.
//!
//! `MsgSplitter` was the first thing ported and, until the AES-CTR keystream
//! landed, the least verified: its unit tests run against an identity keystream,
//! so they prove the buffer bookkeeping and nothing about the two halves
//! agreeing on where a frame begins. A splitter that is out by one byte on a
//! real stream produces frames that decrypt to nothing, with no error anywhere.
//!
//! The expectations are what `TransparentMsgSplitter` returned when driven over
//! these exact streams — the class extracted from `transparent_relay.py` by AST
//! and given the same key, IV and chunking.

use nova_tgrelay::frame::{MsgSplitter, ProtoType};
use nova_tgrelay_net::keystream::AesCtrKeyStream;

/// `bytes(8) + key + iv + bytes(8)` — key at `8..40`, IV at `40..56`, exactly
/// where `init_material` looks.
fn init_packet() -> Vec<u8> {
    let mut init = vec![0u8; 64];
    init[8..40].copy_from_slice(&(0u8..32).collect::<Vec<_>>());
    init[40..56].copy_from_slice(&(0x10u8..0x20).collect::<Vec<_>>());
    init
}

/// Encrypt with the same keystream the splitter will decrypt with, including
/// the 64-byte skip the transport requires.
fn encrypt(plain: &[u8]) -> Vec<u8> {
    let mut stream = AesCtrKeyStream::from_init(&init_packet()).expect("material");
    use nova_tgrelay::frame::KeyStream;
    let _ = stream.update(&[0u8; 64]);
    stream.update(plain)
}

fn intermediate(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn abridged(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        let words = p.len() / 4;
        if words < 0x7F {
            out.push(words as u8);
        } else {
            out.push(0x7F);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(p);
    }
    out
}

/// Feed `plain`'s ciphertext in `chunk`-sized pieces and report the frame sizes.
fn frame_sizes(proto: ProtoType, plain: &[u8], chunk: usize) -> Vec<usize> {
    let cipher = encrypt(plain);
    let mut splitter = MsgSplitter::new(AesCtrKeyStream::from_init(&init_packet()).expect("material"), proto);
    let mut sizes = Vec::new();
    for piece in cipher.chunks(chunk) {
        sizes.extend(splitter.split(piece).iter().map(Vec::len));
    }
    sizes.extend(splitter.flush().iter().map(Vec::len));
    sizes
}

fn filled(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

#[test]
fn the_cipher_stream_is_the_one_the_python_produces() {
    // If these first bytes disagree, every frame boundary below is meaningless.
    let int3 = intermediate(&[&filled(b'A', 10), &filled(b'B', 1), &filled(b'C', 300)]);
    assert_eq!(int3.len(), 323);
    assert_eq!(hex(&encrypt(&int3)[..16]), "58be71bb320761d50cdd0dd707282bfb");

    let abr = abridged(&[&filled(b'A', 4), &filled(b'B', 508), &filled(b'C', 2048)]);
    assert_eq!(abr.len(), 2569);
    assert_eq!(hex(&encrypt(&abr)[..16]), "53ff30fa32395f944dde0ed4042b68b9");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn intermediate_frames_land_where_the_python_puts_them() {
    let plain = intermediate(&[&filled(b'A', 10), &filled(b'B', 1), &filled(b'C', 300)]);
    // Header plus payload: 4+10, 4+1, 4+300.
    for chunk in [10_000usize, 1, 7, 13] {
        assert_eq!(frame_sizes(ProtoType::Intermediate, &plain, chunk), [14, 5, 304], "chunk {chunk}");
    }
}

#[test]
fn abridged_frames_land_where_the_python_puts_them() {
    // 4 bytes is one word, so a one-byte header; 508 is 127 words, which is
    // exactly where the long form takes over; 2048 is 512 words.
    let plain = abridged(&[&filled(b'A', 4), &filled(b'B', 508), &filled(b'C', 2048)]);
    for chunk in [10_000usize, 1, 7] {
        assert_eq!(frame_sizes(ProtoType::Abridged, &plain, chunk), [5, 512, 2052], "chunk {chunk}");
    }
}

#[test]
fn a_zero_length_frame_makes_framing_give_up_and_pass_the_rest_through() {
    let mut plain = intermediate(&[&filled(b'A', 8)]);
    plain.extend_from_slice(&0u32.to_le_bytes());
    plain.extend_from_slice(b"trailing");
    assert_eq!(plain.len(), 24);

    // Fed whole: the frame, then everything after it in one piece.
    assert_eq!(frame_sizes(ProtoType::Intermediate, &plain, 10_000), [12, 12]);

    // Fed in threes, the give-up happens with six bytes already buffered — those
    // are flushed as one, and every chunk after that passes through untouched.
    // This is the shape a rewrite gets wrong: it is tempting to drop the buffer
    // on giving up, and the stream would then be missing six bytes with nothing
    // logged.
    assert_eq!(frame_sizes(ProtoType::Intermediate, &plain, 3), [12, 6, 3, 3]);
}

#[test]
fn the_two_chunkings_of_one_stream_produce_the_same_frames() {
    // Not just the same sizes: the same bytes. A splitter that is out by one on
    // a real stream still produces plausible-looking sizes.
    let plain = intermediate(&[&filled(b'A', 10), &filled(b'B', 1), &filled(b'C', 300)]);
    let cipher = encrypt(&plain);

    let collect = |chunk: usize| {
        let mut splitter = MsgSplitter::new(
            AesCtrKeyStream::from_init(&init_packet()).expect("material"),
            ProtoType::Intermediate,
        );
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for piece in cipher.chunks(chunk) {
            frames.extend(splitter.split(piece));
        }
        frames.extend(splitter.flush());
        frames
    };
    let whole = collect(10_000);
    assert_eq!(collect(1), whole);
    assert_eq!(collect(7), whole);
    // And together they are the ciphertext, entire and in order.
    assert_eq!(whole.concat(), cipher);
}
