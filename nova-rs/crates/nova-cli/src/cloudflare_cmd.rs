//! `nova-engine cloudflare-classify` — stateless classify-and-decide over
//! stdin/stdout, for a Python caller that gathered `Evidence` itself.
//!
//! `nova-cloudflare` deliberately carries no networking code (see its own
//! docs), so this is the only glue: read one JSON request, call
//! `Detector::classify` + `policy::decide`, print one JSON response, exit.
//! No corpus, no `strat/` tree, no state on disk — safe to invoke from any
//! working directory.

use std::io::Read;
use std::net::IpAddr;

use nova_cloudflare::{decide, Action, Classification, Detector, Evidence, Ranges};
use nova_core::{BlockSignature, Domain, Transport};

#[derive(serde::Deserialize)]
struct Request {
    host: String,
    #[serde(default)]
    addresses: Vec<IpAddr>,
    #[serde(default)]
    cname_chain: Vec<String>,
    #[serde(default)]
    server_header: Option<String>,
    #[serde(default)]
    cf_ray: bool,
    #[serde(default)]
    cf_mitigated: bool,
    #[serde(default)]
    status: Option<u16>,
    /// Snake-case `BlockSignature` variant name for the *baseline* probe's
    /// failure (e.g. `"blackholed"`, `"sni_timeout"`). Unrecognised or absent
    /// -> no failure evidence, same as a caller that never observed one.
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    warp_available: bool,
    #[serde(default)]
    bypass_available: bool,
}

#[derive(serde::Serialize)]
struct Response {
    host: String,
    classification: Classification,
    confidence: f32,
    action: &'static str,
    reason: Option<&'static str>,
    transport: Option<String>,
}

fn parse_block_signature(name: &str) -> Option<BlockSignature> {
    match name {
        "rst_immediate" => Some(BlockSignature::RstImmediate),
        "rst_after_server_hello" => Some(BlockSignature::RstAfterServerHello),
        "sni_timeout" => Some(BlockSignature::SniTimeout),
        "blackholed" => Some(BlockSignature::Blackholed),
        "connection_refused" => Some(BlockSignature::ConnectionRefused),
        "dns_poisoned" => Some(BlockSignature::DnsPoisoned),
        "dns_failure" => Some(BlockSignature::DnsFailure),
        _ => None,
    }
}

/// Runs the subcommand to completion and returns the process exit code.
/// Never panics on bad input — a malformed request is a clean exit 2, not a
/// crash, since a subprocess call is exactly where an unhandled panic is
/// easiest to lose track of on the Python side.
pub fn run() -> i32 {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("cloudflare-classify: failed to read stdin: {e}");
        return 2;
    }
    let request: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cloudflare-classify: bad JSON on stdin: {e}");
            return 2;
        }
    };
    let host = match Domain::parse(&request.host) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cloudflare-classify: bad host {:?}: {e}", request.host);
            return 2;
        }
    };

    let evidence = Evidence {
        addresses: request.addresses,
        cname_chain: request.cname_chain,
        server_header: request.server_header,
        cf_ray: request.cf_ray,
        cf_mitigated: request.cf_mitigated,
        status: request.status,
        failure: request.failure.as_deref().and_then(parse_block_signature),
    };

    let (classification, confidence) = Detector::new(Ranges::default()).classify(&host, &evidence);
    // A domain worth reporting has, by construction, no existing route (it is
    // not in any list yet) -> it currently resolves DIRECT.
    let action = decide(
        classification,
        confidence,
        &Transport::Direct,
        request.warp_available,
        request.bypass_available,
        evidence.failure,
    );

    let (action_name, reason, transport) = match action {
        Action::Keep => ("keep", None, None),
        Action::Reroute { to, reason } => ("reroute", Some(reason), Some(to.as_str().to_owned())),
    };

    let response = Response {
        host: request.host,
        classification,
        confidence: confidence.value(),
        action: action_name,
        reason,
        transport,
    };
    match serde_json::to_string(&response) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(e) => {
            eprintln!("cloudflare-classify: failed to serialize response: {e}");
            2
        }
    }
}
