//! The attribution table, against the table the shipped Python produces.
//!
//! Layer 25. Every row below was produced by **executing** the running
//! program's own decision: `_attempt_signature` compiled out of
//! `tgrelay/transparent_relay.py` by AST, and the three branch conditions of
//! `_connect_websocket_target` located as the `test` of their `If` nodes,
//! unparsed and evaluated. The generator is `temp/attempt_oracle.py`.
//!
//! It is a table rather than a set of examples because the interesting cases are
//! the ones nobody would think to write: a poisoned resolver **penalises** the
//! egress while a dead one charges nothing, and every failure past
//! `HandshakeDone` credits the egress no matter how it ended — including a
//! certificate mismatch.

use nova_core::BlockSignature;
use nova_probe::{Ended, Reached};
use nova_tgrelay_net::attempt::{charge, signature, Charge, Failure};

/// `(reached, ended, since_hello_ms, signature, charge)` — the Python's answer.
#[allow(clippy::type_complexity)]
const TABLE: &[(Reached, Ended, Option<u32>, &str, Charge)] = &[
    (Reached::Nothing, Ended::Ok, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Ok, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Ok, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Ok, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Ok, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Timeout, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Timeout, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Timeout, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Timeout, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Timeout, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Reset, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Reset, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Reset, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Reset, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Reset, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Refused, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Refused, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Refused, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Refused, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Refused, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Closed, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Closed, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Closed, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Closed, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::Closed, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::CertificateMismatch, None, "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::CertificateMismatch, Some(10), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::CertificateMismatch, Some(40), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::CertificateMismatch, Some(41), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::CertificateMismatch, Some(500), "dns_failure", Charge::Nobody),
    (Reached::Nothing, Ended::ResolverStub, None, "dns_poisoned", Charge::Penalise),
    (Reached::Nothing, Ended::ResolverStub, Some(10), "dns_poisoned", Charge::Penalise),
    (Reached::Nothing, Ended::ResolverStub, Some(40), "dns_poisoned", Charge::Penalise),
    (Reached::Nothing, Ended::ResolverStub, Some(41), "dns_poisoned", Charge::Penalise),
    (Reached::Nothing, Ended::ResolverStub, Some(500), "dns_poisoned", Charge::Penalise),
    (Reached::Resolved, Ended::Ok, None, "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Ok, Some(10), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Ok, Some(40), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Ok, Some(41), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Ok, Some(500), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Timeout, None, "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Timeout, Some(10), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Timeout, Some(40), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Timeout, Some(41), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Timeout, Some(500), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Reset, None, "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Reset, Some(10), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Reset, Some(40), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Reset, Some(41), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Reset, Some(500), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Refused, None, "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Refused, Some(10), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Refused, Some(40), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Refused, Some(41), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Refused, Some(500), "connection_refused", Charge::Nobody),
    (Reached::Resolved, Ended::Closed, None, "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Closed, Some(10), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Closed, Some(40), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Closed, Some(41), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::Closed, Some(500), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::CertificateMismatch, None, "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::CertificateMismatch, Some(10), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::CertificateMismatch, Some(40), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::CertificateMismatch, Some(41), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::CertificateMismatch, Some(500), "blackholed", Charge::Penalise),
    (Reached::Resolved, Ended::ResolverStub, None, "dns_poisoned", Charge::Penalise),
    (Reached::Resolved, Ended::ResolverStub, Some(10), "dns_poisoned", Charge::Penalise),
    (Reached::Resolved, Ended::ResolverStub, Some(40), "dns_poisoned", Charge::Penalise),
    (Reached::Resolved, Ended::ResolverStub, Some(41), "dns_poisoned", Charge::Penalise),
    (Reached::Resolved, Ended::ResolverStub, Some(500), "dns_poisoned", Charge::Penalise),
    (Reached::Connected, Ended::Ok, None, "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Ok, Some(10), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Ok, Some(40), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Ok, Some(41), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Ok, Some(500), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Timeout, None, "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Timeout, Some(10), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Timeout, Some(40), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Timeout, Some(41), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Timeout, Some(500), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::Reset, None, "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Reset, Some(10), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Reset, Some(40), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Reset, Some(41), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Reset, Some(500), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Refused, None, "connection_refused", Charge::Nobody),
    (Reached::Connected, Ended::Refused, Some(10), "connection_refused", Charge::Nobody),
    (Reached::Connected, Ended::Refused, Some(40), "connection_refused", Charge::Nobody),
    (Reached::Connected, Ended::Refused, Some(41), "connection_refused", Charge::Nobody),
    (Reached::Connected, Ended::Refused, Some(500), "connection_refused", Charge::Nobody),
    (Reached::Connected, Ended::Closed, None, "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Closed, Some(10), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Closed, Some(40), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Closed, Some(41), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::Closed, Some(500), "blackholed", Charge::Penalise),
    (Reached::Connected, Ended::CertificateMismatch, None, "unknown", Charge::Penalise),
    (Reached::Connected, Ended::CertificateMismatch, Some(10), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::CertificateMismatch, Some(40), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::CertificateMismatch, Some(41), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::CertificateMismatch, Some(500), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::ResolverStub, None, "unknown", Charge::Penalise),
    (Reached::Connected, Ended::ResolverStub, Some(10), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::ResolverStub, Some(40), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::ResolverStub, Some(41), "unknown", Charge::Penalise),
    (Reached::Connected, Ended::ResolverStub, Some(500), "unknown", Charge::Penalise),
    (Reached::HelloSent, Ended::Ok, None, "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Ok, Some(10), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Ok, Some(40), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Ok, Some(41), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Ok, Some(500), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Timeout, None, "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Timeout, Some(10), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Timeout, Some(40), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Timeout, Some(41), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Timeout, Some(500), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Reset, None, "unknown", Charge::Penalise),
    (Reached::HelloSent, Ended::Reset, Some(10), "rst_immediate", Charge::Penalise),
    (Reached::HelloSent, Ended::Reset, Some(40), "rst_immediate", Charge::Penalise),
    (Reached::HelloSent, Ended::Reset, Some(41), "rst_after_server_hello", Charge::Penalise),
    (Reached::HelloSent, Ended::Reset, Some(500), "rst_after_server_hello", Charge::Penalise),
    (Reached::HelloSent, Ended::Refused, None, "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Refused, Some(10), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Refused, Some(40), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Refused, Some(41), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Refused, Some(500), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Closed, None, "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Closed, Some(10), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Closed, Some(40), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Closed, Some(41), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::Closed, Some(500), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::CertificateMismatch, None, "tls_certificate_mismatch", Charge::Penalise),
    (Reached::HelloSent, Ended::CertificateMismatch, Some(10), "tls_certificate_mismatch", Charge::Penalise),
    (Reached::HelloSent, Ended::CertificateMismatch, Some(40), "tls_certificate_mismatch", Charge::Penalise),
    (Reached::HelloSent, Ended::CertificateMismatch, Some(41), "tls_certificate_mismatch", Charge::Penalise),
    (Reached::HelloSent, Ended::CertificateMismatch, Some(500), "tls_certificate_mismatch", Charge::Penalise),
    (Reached::HelloSent, Ended::ResolverStub, None, "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::ResolverStub, Some(10), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::ResolverStub, Some(40), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::ResolverStub, Some(41), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HelloSent, Ended::ResolverStub, Some(500), "tunnel_handshake_ignored", Charge::Penalise),
    (Reached::HandshakeDone, Ended::Ok, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Ok, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Ok, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Ok, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Ok, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Timeout, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Timeout, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Timeout, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Timeout, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Timeout, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Reset, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Reset, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Reset, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Reset, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Reset, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Refused, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Refused, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Refused, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Refused, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Refused, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Closed, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Closed, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Closed, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Closed, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::Closed, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::CertificateMismatch, None, "tls_certificate_mismatch", Charge::Credit),
    (Reached::HandshakeDone, Ended::CertificateMismatch, Some(10), "tls_certificate_mismatch", Charge::Credit),
    (Reached::HandshakeDone, Ended::CertificateMismatch, Some(40), "tls_certificate_mismatch", Charge::Credit),
    (Reached::HandshakeDone, Ended::CertificateMismatch, Some(41), "tls_certificate_mismatch", Charge::Credit),
    (Reached::HandshakeDone, Ended::CertificateMismatch, Some(500), "tls_certificate_mismatch", Charge::Credit),
    (Reached::HandshakeDone, Ended::ResolverStub, None, "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::ResolverStub, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::ResolverStub, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::ResolverStub, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::HandshakeDone, Ended::ResolverStub, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Ok, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Ok, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Ok, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Ok, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Ok, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Timeout, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Timeout, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Timeout, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Timeout, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Timeout, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Reset, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Reset, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Reset, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Reset, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Reset, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Refused, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Refused, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Refused, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Refused, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Refused, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Closed, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Closed, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Closed, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Closed, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::Closed, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::CertificateMismatch, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::CertificateMismatch, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::CertificateMismatch, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::CertificateMismatch, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::CertificateMismatch, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::ResolverStub, None, "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::ResolverStub, Some(10), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::ResolverStub, Some(40), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::ResolverStub, Some(41), "tunnel_stalled", Charge::Credit),
    (Reached::Upgraded, Ended::ResolverStub, Some(500), "tunnel_stalled", Charge::Credit),
    (Reached::Carrying, Ended::Timeout, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Timeout, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Timeout, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Timeout, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Timeout, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Reset, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Reset, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Reset, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Reset, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Reset, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Refused, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Refused, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Refused, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Refused, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Refused, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Closed, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Closed, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Closed, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Closed, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::Closed, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::CertificateMismatch, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::CertificateMismatch, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::CertificateMismatch, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::CertificateMismatch, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::CertificateMismatch, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::ResolverStub, None, "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::ResolverStub, Some(10), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::ResolverStub, Some(40), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::ResolverStub, Some(41), "tunnel_severed", Charge::Credit),
    (Reached::Carrying, Ended::ResolverStub, Some(500), "tunnel_severed", Charge::Credit),
    (Reached::Nothing, Ended::HttpStatus { code: 101 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Nothing, Ended::HttpStatus { code: 403 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Nothing, Ended::HttpStatus { code: 421 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Nothing, Ended::HttpStatus { code: 502 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Resolved, Ended::HttpStatus { code: 101 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Resolved, Ended::HttpStatus { code: 403 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Resolved, Ended::HttpStatus { code: 421 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Resolved, Ended::HttpStatus { code: 502 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Connected, Ended::HttpStatus { code: 101 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Connected, Ended::HttpStatus { code: 403 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Connected, Ended::HttpStatus { code: 421 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Connected, Ended::HttpStatus { code: 502 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HelloSent, Ended::HttpStatus { code: 101 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HelloSent, Ended::HttpStatus { code: 403 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HelloSent, Ended::HttpStatus { code: 421 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HelloSent, Ended::HttpStatus { code: 502 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HandshakeDone, Ended::HttpStatus { code: 101 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HandshakeDone, Ended::HttpStatus { code: 403 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HandshakeDone, Ended::HttpStatus { code: 421 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::HandshakeDone, Ended::HttpStatus { code: 502 }, None, "tunnel_upgrade_rejected", Charge::Refused),
    (Reached::Upgraded, Ended::HttpStatus { code: 101 }, None, "tunnel_stalled", Charge::Refused),
    (Reached::Upgraded, Ended::HttpStatus { code: 403 }, None, "tunnel_stalled", Charge::Refused),
    (Reached::Upgraded, Ended::HttpStatus { code: 421 }, None, "tunnel_stalled", Charge::Refused),
    (Reached::Upgraded, Ended::HttpStatus { code: 502 }, None, "tunnel_stalled", Charge::Refused),
    (Reached::Carrying, Ended::HttpStatus { code: 101 }, None, "tunnel_severed", Charge::Refused),
    (Reached::Carrying, Ended::HttpStatus { code: 403 }, None, "tunnel_severed", Charge::Refused),
    (Reached::Carrying, Ended::HttpStatus { code: 421 }, None, "tunnel_severed", Charge::Refused),
    (Reached::Carrying, Ended::HttpStatus { code: 502 }, None, "tunnel_severed", Charge::Refused),
];

fn spelled(signature: BlockSignature) -> String {
    // The Python's signature strings are `BlockSignature`'s serde names by
    // construction — `tgrelay/phase.py` says so and this is what checks it.
    serde_json::to_value(signature).unwrap().as_str().unwrap().to_string()
}

#[test]
fn every_reached_ended_pair_is_named_and_charged_the_way_the_python_names_it() {
    let mut mismatches = Vec::new();
    for (reached, ended, hello_ms, expected_signature, expected_charge) in TABLE {
        let mut failure = Failure::new(*reached, *ended);
        if let Some(ms) = hello_ms {
            failure = failure.since_hello_ms(*ms);
        }
        let got_signature = spelled(signature(&failure));
        let got_charge = charge(&failure);
        if got_signature != *expected_signature || got_charge != *expected_charge {
            mismatches.push(format!(
                "{reached:?}/{ended:?}/hello={hello_ms:?}: python said {expected_signature}/{expected_charge:?},                  port says {got_signature}/{got_charge:?}"
            ));
        }
    }
    assert!(mismatches.is_empty(), "{} rows disagree:
{}", mismatches.len(), mismatches.join("
"));
}

#[test]
fn the_table_covers_every_milestone_and_every_ending() {
    // A table that silently lost a case would pass the comparison above while
    // testing nothing about it.
    for reached in [
        Reached::Nothing,
        Reached::Resolved,
        Reached::Connected,
        Reached::HelloSent,
        Reached::HandshakeDone,
        Reached::Upgraded,
        Reached::Carrying,
    ] {
        assert!(TABLE.iter().any(|row| row.0 == reached), "no row reached {reached:?}");
    }
    for ended in [
        Ended::Ok,
        Ended::Timeout,
        Ended::Reset,
        Ended::Refused,
        Ended::Closed,
        Ended::CertificateMismatch,
        Ended::ResolverStub,
        Ended::HttpStatus { code: 403 },
    ] {
        assert!(TABLE.iter().any(|row| row.1 == ended), "no row ended {ended:?}");
    }
}

#[test]
fn a_poisoned_resolver_is_charged_to_the_egress_and_a_dead_one_is_not() {
    // Stated on its own because it is the row that reads like a bug and is not:
    // neither attempt ever got an address, but a stub answer is something *this*
    // egress's resolver did, and another egress may well answer honestly.
    let poisoned = Failure::new(Reached::Nothing, Ended::ResolverStub);
    let dead = Failure::new(Reached::Nothing, Ended::Timeout);
    assert_eq!(charge(&poisoned), Charge::Penalise);
    assert_eq!(charge(&dead), Charge::Nobody);
    assert_eq!(signature(&poisoned), BlockSignature::DnsPoisoned);
    assert_eq!(signature(&dead), BlockSignature::DnsFailure);
}
