//! The real AES-256-CTR keystream behind `nova_tgrelay::frame::KeyStream`.
//!
//! Layer 12, and the last stub in the protocol core. `MsgSplitter` was written
//! against a trait so the framing — where a message boundary falls, which is the
//! part with interesting failure modes — could be tested without a crypto
//! library in the picture. This is the implementation the running relay needs.
//!
//! **Why it lives here and not in `nova-tgrelay`.** That crate is deliberately
//! dependency-free; every dependency the relay needs lives in this one, where it
//! is visible. The trait stays there, the cipher comes from here.
//!
//! **Why RustCrypto and not `boring`.** BoringSSL is already in the workspace,
//! but only behind `nova-tls`'s `shape` feature, and for a stated reason:
//! building it needs a C toolchain plus NASM on Windows. Taking that dependency
//! here would make the relay unbuildable on a machine that only wants the relay.
//! `aes` + `ctr` are pure Rust with no build script.
//!
//! **What this is not.** Telegram's obfuscation layer is not a security boundary
//! Nova defends — the real cryptography is inside MTProto, between the client
//! and Telegram, and neither end is us. This keystream exists to *read message
//! boundaries*, which is why getting it wrong would show up as a desynchronised
//! stream rather than as a break in anyone's confidentiality. It is still not
//! hand-rolled: a subtly wrong AES would corrupt silently, which is the one
//! failure mode this whole port has been built to avoid.

use aes::cipher::{KeyIvInit, StreamCipher};
use nova_tgrelay::frame::{init_material, KeyStream, MsgSplitter, ProtoType, SplitterError};

/// AES-256 in counter mode, big-endian 128-bit counter — what
/// `cryptography`'s `Cipher(algorithms.AES(key), modes.CTR(iv))` builds for a
/// 32-byte key.
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// AES-256 needs 32 bytes of key…
pub const KEY_LEN: usize = 32;
/// …and CTR a 16-byte initial counter block.
pub const IV_LEN: usize = 16;

pub struct AesCtrKeyStream {
    cipher: Aes256Ctr,
}

impl std::fmt::Debug for AesCtrKeyStream {
    /// Deliberately opaque. A keystream that prints its own state into a log is
    /// how key material ends up in a bug report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCtrKeyStream(..)")
    }
}

impl AesCtrKeyStream {
    /// `None` for a key or IV of the wrong length, rather than padding or
    /// truncating one into place: either would produce a stream that decrypts to
    /// plausible-looking garbage.
    pub fn new(key: &[u8], iv: &[u8]) -> Option<Self> {
        if key.len() != KEY_LEN || iv.len() != IV_LEN {
            return None;
        }
        Some(Self { cipher: Aes256Ctr::new(key.into(), iv.into()) })
    }

    /// Build one from an MTProto init packet, taking the key and IV from the
    /// offsets `nova_tgrelay::frame` defines.
    pub fn from_init(init: &[u8]) -> Result<Self, SplitterError> {
        let (key, iv) = init_material(init)?;
        Self::new(key, iv).ok_or(SplitterError::InitTooShort { len: init.len() })
    }
}

impl KeyStream for AesCtrKeyStream {
    fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.cipher.apply_keystream(&mut out);
        out
    }
}

/// A splitter over the real cipher, ready for the wiring.
pub fn splitter_from_init(init: &[u8], proto: ProtoType) -> Result<MsgSplitter<AesCtrKeyStream>, SplitterError> {
    Ok(MsgSplitter::new(AesCtrKeyStream::from_init(init)?, proto))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38A, F.5.5 — AES-256-CTR, the standard test vector. Chosen
    /// over anything home-made because a keystream that is merely
    /// self-consistent is exactly the failure this is guarding against.
    const NIST_KEY: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35,
        0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ];
    const NIST_IV: [u8; 16] =
        [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
    const NIST_PLAINTEXT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d,
        0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f,
        0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ];
    const NIST_CIPHERTEXT: &str = "601ec313775789a5b7a7f504bbf3d228\
                                   f443e3ca4d62b59aca84e990cacaf5c5\
                                   2b0930daa23de94ce87017ba2d84988d\
                                   dfc9c58db67aada613c2dd08457941a6";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn it_is_aes_256_ctr_and_not_merely_self_consistent() {
        let mut stream = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid material");
        assert_eq!(hex(&stream.update(&NIST_PLAINTEXT)), NIST_CIPHERTEXT);
    }

    #[test]
    fn the_counter_carries_across_calls() {
        // The whole point of a stream: byte 17 must be encrypted the same way
        // whether it arrived in one read or two. A cipher rebuilt per call would
        // restart the counter and pass every self-consistency test there is.
        let mut whole = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        let one_go = whole.update(&NIST_PLAINTEXT);

        let mut split = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        let mut piecewise = split.update(&NIST_PLAINTEXT[..1]);
        piecewise.extend(split.update(&NIST_PLAINTEXT[1..17]));
        piecewise.extend(split.update(&NIST_PLAINTEXT[17..]));
        assert_eq!(piecewise, one_go);
    }

    #[test]
    fn it_agrees_with_the_relays_own_cipher_byte_for_byte() {
        // Not a spec check: `_new_ctr` was extracted from
        // `tgrelay/transparent_relay.py` by AST and run over these inputs, and
        // this is what it returned. The NIST vector above proves the algorithm;
        // this proves the two implementations agree, which is the question that
        // decides whether a ported relay can read a stream the shipped one wrote.
        let mut whole = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        assert_eq!(hex(&whole.update(&NIST_PLAINTEXT)), NIST_CIPHERTEXT);

        let mut init = vec![0u8; 64];
        init[8..40].copy_from_slice(&NIST_KEY);
        init[40..56].copy_from_slice(&NIST_IV);
        let mut from_init = AesCtrKeyStream::from_init(&init).expect("init");
        assert_eq!(hex(&from_init.update(b"obfuscated mtproto")), "64bd1b842a7477473bfeab78bc10b76d2e01");
    }

    #[test]
    fn applying_it_twice_returns_the_plaintext() {
        let mut encrypt = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        let mut decrypt = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        let ciphertext = encrypt.update(b"obfuscated mtproto");
        assert_eq!(decrypt.update(&ciphertext), b"obfuscated mtproto");
    }

    #[test]
    fn material_of_the_wrong_length_is_refused_not_padded() {
        // Padding or truncating would produce a stream that decrypts to
        // plausible-looking garbage, which is worse than not starting.
        assert!(AesCtrKeyStream::new(&NIST_KEY[..31], &NIST_IV).is_none());
        assert!(AesCtrKeyStream::new(&NIST_KEY, &NIST_IV[..15]).is_none());
        assert!(AesCtrKeyStream::new(&[], &[]).is_none());
        assert!(AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).is_some());
    }

    #[test]
    fn an_init_packet_yields_the_key_and_iv_at_the_offsets_the_frame_module_defines() {
        // Bytes 8..40 are the key and 40..56 the IV; a 64-byte init packet is the
        // shortest legal one.
        let mut init = vec![0u8; 64];
        init[8..40].copy_from_slice(&NIST_KEY);
        init[40..56].copy_from_slice(&NIST_IV);
        let mut from_init = AesCtrKeyStream::from_init(&init).expect("init");
        let mut direct = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        assert_eq!(from_init.update(&NIST_PLAINTEXT), direct.update(&NIST_PLAINTEXT));
    }

    #[test]
    fn the_init_packet_boundary_is_the_material_not_the_frame() {
        // 56 bytes is exactly key (8..40) plus IV (40..56), and that is all the
        // cipher needs. The Python's `parse_transparent_init_info` demands 64
        // before it will read a *protocol tag* — a different question, and
        // conflating the two would refuse a packet whose material is usable.
        let mut shortest = vec![0u8; nova_tgrelay::frame::MIN_INIT_LEN];
        shortest[8..40].copy_from_slice(&NIST_KEY);
        shortest[40..56].copy_from_slice(&NIST_IV);
        assert!(AesCtrKeyStream::from_init(&shortest).is_ok());

        let too_short = vec![0u8; nova_tgrelay::frame::MIN_INIT_LEN - 1];
        assert!(matches!(AesCtrKeyStream::from_init(&too_short), Err(SplitterError::InitTooShort { len: 55 })));
    }

    #[test]
    fn the_debug_output_carries_no_key_material() {
        let stream = AesCtrKeyStream::new(&NIST_KEY, &NIST_IV).expect("valid");
        let rendered = format!("{stream:?}");
        assert_eq!(rendered, "AesCtrKeyStream(..)");
        assert!(!rendered.contains("60"), "no key bytes in a log line");
    }

    #[test]
    fn a_splitter_can_be_built_straight_from_an_init_packet() {
        let mut init = vec![0u8; 64];
        init[8..40].copy_from_slice(&NIST_KEY);
        init[40..56].copy_from_slice(&NIST_IV);
        assert!(splitter_from_init(&init, ProtoType::Intermediate).is_ok());
        assert!(splitter_from_init(&[0u8; 10], ProtoType::Intermediate).is_err());
    }
}
