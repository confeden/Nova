//! gpu-snapshot / gpu-serve subprocess contract. Skipped when the engine reports no GL 3.3 (exit 3).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn engine() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nova-engine"));
    c.current_dir(std::env::temp_dir());
    c
}

/// Parse a binary PPM: (w, h, pixels).
fn ppm(bytes: &[u8]) -> (usize, usize, &[u8]) {
    let mut fields = Vec::new();
    let mut i = 0;
    while fields.len() < 4 {
        while bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        fields.push(std::str::from_utf8(&bytes[start..i]).unwrap().to_owned());
    }
    assert_eq!(fields[0], "P6");
    assert_eq!(fields[3], "255");
    (fields[1].parse().unwrap(), fields[2].parse().unwrap(), &bytes[i + 1..])
}

#[test]
fn snapshot_writes_a_non_uniform_ppm() {
    let out = engine()
        .args(["gpu-snapshot", "--texture", "cracks", "--time", "20", "--size", "96x72", "--accent", "31"])
        .output()
        .unwrap();
    if out.status.code() == Some(3) {
        eprintln!("skipping: no GL 3.3: {}", String::from_utf8_lossy(&out.stderr));
        return;
    }
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.starts_with(b"P6"));
    let (w, h, px) = ppm(&out.stdout);
    assert_eq!((w, h), (96, 72));
    assert_eq!(px.len(), w * h * 3);
    let (lo, hi) = px.iter().fold((255u8, 0u8), |(lo, hi), &v| (lo.min(v), hi.max(v)));
    assert!(hi - lo > 8, "uniform image {lo}..{hi}");
}

fn snap(extra: &[&str]) -> Option<Vec<u8>> {
    let mut args = vec!["gpu-snapshot", "--texture", "marble", "--time", "20", "--size", "96x72", "--accent", "31"];
    args.extend_from_slice(extra);
    let out = engine().args(args).output().unwrap();
    if out.status.code() == Some(3) {
        eprintln!("skipping: no GL 3.3");
        return None;
    }
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    Some(ppm(&out.stdout).2.to_vec())
}

#[test]
fn drift_changes_the_picture_only_when_asked() {
    let Some(off) = snap(&[]) else { return };
    assert_eq!(off, snap(&[]).unwrap(), "drift off must be deterministic");
    let on = snap(&["--drift"]).unwrap();
    assert_ne!(off, on, "drift on at t=20 must differ from the plain palette");
    assert_eq!(on, snap(&["--drift"]).unwrap());
}

#[test]
fn snapshot_rejects_unknown_texture() {
    let out = engine().args(["gpu-snapshot", "--texture", "nope", "--size", "8x8"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn serve_handshakes_renders_and_exits_on_stdin_close() {
    let mut child = engine()
        .arg("gpu-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    if ready["ready"] == false {
        assert_eq!(child.wait().unwrap().code(), Some(3));
        eprintln!("skipping: {}", ready["error"]);
        return;
    }
    assert!(ready["map"].as_str().unwrap().starts_with("NovaGpu-"));
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"cmd":"config","texture":"fractal","anim":true,"fps":120}}"#).unwrap();
    writeln!(stdin, r#"{{"cmd":"size","w":64,"h":48}}"#).unwrap();
    stdin.flush().unwrap();
    let mut last = 0;
    for _ in 0..5 {
        let v: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        let seq = v["frame"].as_u64().unwrap_or_else(|| panic!("{v}"));
        assert!(seq > last);
        last = seq;
    }
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
}
/// A gpu-serve child with a reader thread: `frames_within` counts `frame` lines for a while.
struct Serve {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    rx: std::sync::mpsc::Receiver<serde_json::Value>,
    ready: serde_json::Value,
}

impl Serve {
    fn start() -> Option<Serve> {
        let mut child = engine()
            .arg("gpu-serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready: serde_json::Value =
            serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        if ready["ready"] == false {
            eprintln!("skipping: {}", ready["error"]);
            let _ = child.wait();
            return None;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in lines.map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str(&l) {
                    if tx.send(v).is_err() {
                        return;
                    }
                }
            }
        });
        let stdin = child.stdin.take().unwrap();
        Some(Serve {
            child,
            stdin,
            rx,
            ready,
        })
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// Number of frames delivered during `ms`; other messages are collected into `errors`.
    fn frames_within(&mut self, ms: u64, errors: &mut Vec<serde_json::Value>) -> usize {
        let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        let mut n = 0;
        while let Some(left) = end.checked_duration_since(std::time::Instant::now()) {
            match self.rx.recv_timeout(left) {
                Ok(v) if v.get("frame").is_some() => n += 1,
                Ok(v) => errors.push(v),
                Err(_) => break,
            }
        }
        n
    }

    fn finish(mut self) {
        drop(self.stdin);
        assert!(self.child.wait().unwrap().success());
    }
}

#[test]
fn serve_announces_features_and_honours_speed_zero_and_hot() {
    let Some(mut s) = Serve::start() else { return };
    assert_eq!(s.ready["protocol"], 2);
    let feats: Vec<&str> = s.ready["features"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(feats, ["glass", "hot", "speed", "sat", "drift"]);
    let mut errs = Vec::new();
    s.send(r#"{"cmd":"size","w":160,"h":120}"#);
    s.send(r#"{"cmd":"config","texture":"marble","anim":true,"fps":60,"speed":100,"sat":80}"#);
    assert!(
        s.frames_within(600, &mut errs) >= 10,
        "animation should run"
    );
    // speed 0 freezes the frame: after the in-flight frame is delivered no more arrive (zero CPU idle)
    s.send(r#"{"cmd":"config","speed":0}"#);
    s.frames_within(300, &mut errs);
    assert_eq!(
        s.frames_within(500, &mut errs),
        0,
        "frozen frame must not keep rendering"
    );
    // hot on: frames resume at about 30 fps without animation, and stop again after the fade-out
    s.send(r#"{"cmd":"hot","rect":[10,10,90,70],"radius":12,"on":true}"#);
    let on = s.frames_within(600, &mut errs);
    assert!(on >= 12, "hover should produce ~30 fps, got {on} in 0.6 s");
    s.send(r#"{"cmd":"hot","on":false}"#);
    s.frames_within(700, &mut errs);
    assert_eq!(
        s.frames_within(500, &mut errs),
        0,
        "must go idle once the glow has faded"
    );
    // protocol errors: hot without a rect, glass overlay with the wrong byte count
    s.send(r#"{"cmd":"hot","on":true}"#);
    let path = std::env::temp_dir().join(format!("nova_glass_test_{}.rgba", std::process::id()));
    std::fs::write(&path, vec![0u8; 160 * 120 * 4]).unwrap();
    let cmd = serde_json::json!({"cmd":"overlay","path":path.to_str().unwrap(),"w":160,"h":120,"glass":true});
    s.send(&cmd.to_string());
    s.frames_within(300, &mut errs);
    let msgs: Vec<String> = errs
        .iter()
        .filter_map(|v| v["error"].as_str().map(str::to_owned))
        .collect();
    assert!(msgs.iter().any(|m| m.contains("rect")), "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("glass overlay")), "{msgs:?}");
    // a correct glass file (RGBA + mask) is accepted
    std::fs::write(&path, vec![0u8; 160 * 120 * 5]).unwrap();
    errs.clear();
    s.send(&cmd.to_string());
    s.frames_within(300, &mut errs);
    assert!(errs.iter().all(|v| v.get("error").is_none()), "{errs:?}");
    let _ = std::fs::remove_file(&path);
    s.finish();
}
