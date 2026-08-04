//! Cloudflare-aware routing.
//!
//! Most Russian ISPs filter Cloudflare's published CDN prefixes, which breaks a
//! long tail of sites that are on nobody's blocklist and that Nova therefore
//! never had an entry for. Curating that tail by hand does not scale — the set
//! changes whenever a site changes CDN.
//!
//! This crate closes the gap at runtime. It classifies a host from evidence
//! Nova is already collecting (the DNS answer, and the headers of a request it
//! was going to make anyway), decides whether the host is both Cloudflare-
//! fronted *and* being interfered with, and returns the routing action. The
//! answer is cached per registrable domain with a lifetime that reflects how
//! volatile the conclusion is, so the steady-state cost is a map lookup.
//!
//! The design deliberately separates three questions the Python code conflated:
//!
//! - *Is it Cloudflare?* — stable, cacheable for a day.
//! - *Is our path to it blocked?* — volatile, re-checked every fifteen minutes.
//! - *Is the origin behind it alive?* — someone else's outage, never actionable.
//!
//! Answering the third separately is what stops Nova from tunnelling traffic to
//! a site that is simply down, then reporting the tunnel as broken when the
//! site stays down.

#![forbid(unsafe_code)]

pub mod detect;
pub mod policy;
pub mod ranges;

pub use detect::{Classification, Confidence, Detector, Evidence};
pub use policy::{Action, Cache, Entry, decide};
pub use ranges::Ranges;
