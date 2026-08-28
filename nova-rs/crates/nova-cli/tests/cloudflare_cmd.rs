//! End-to-end coverage for `nova-engine cloudflare-classify`: spawns the
//! built binary itself (not just the library) so a regression in argument
//! dispatch, stdin/stdout wiring, or JSON (de)serialization is caught here,
//! not only in nova-cloudflare's own unit tests.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(request_json: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nova-engine"))
        .arg("cloudflare-classify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn nova-engine");
    child.stdin.take().unwrap().write_all(request_json.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn cf_ray_plus_a_failure_reroutes_to_warp() {
    let (code, stdout, _stderr) =
        run(r#"{"host":"example.com","cf_ray":true,"status":200,"failure":"blackholed","warp_available":true}"#);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout must be one JSON object");
    assert_eq!(value["classification"], "fronted_and_blocked");
    assert_eq!(value["action"], "reroute");
    assert_eq!(value["transport"], "warp");
}

#[test]
fn no_evidence_keeps_the_route() {
    let (code, stdout, _stderr) = run(r#"{"host":"ya.ru"}"#);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["classification"], "unknown");
    assert_eq!(value["action"], "keep");
}

#[test]
fn origin_down_never_reroutes_even_with_cf_ray() {
    let (code, stdout, _stderr) = run(r#"{"host":"example.com","cf_ray":true,"status":521,"warp_available":true}"#);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["classification"], "fronted_origin_down");
    assert_eq!(value["action"], "keep");
}

#[test]
fn warp_unavailable_and_no_bypass_keeps_the_route() {
    let (code, stdout, _stderr) = run(
        r#"{"host":"example.com","cf_ray":true,"failure":"blackholed","warp_available":false,"bypass_available":false}"#,
    );
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["classification"], "fronted_and_blocked");
    assert_eq!(value["action"], "keep");
}

#[test]
fn malformed_json_exits_nonzero_without_writing_to_stdout() {
    let (code, stdout, stderr) = run("not json");
    assert_ne!(code, 0);
    assert!(stdout.trim().is_empty());
    assert!(!stderr.trim().is_empty());
}

#[test]
fn empty_host_exits_nonzero() {
    let (code, _stdout, stderr) = run(r#"{"host":""}"#);
    assert_ne!(code, 0);
    assert!(!stderr.trim().is_empty());
}
