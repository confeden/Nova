//! Exercise the deployed subprocess contract, including stateless dispatch and binary output.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(request: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nova-engine"))
        .arg("render-fractal")
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn request() -> serde_json::Value {
    serde_json::json!({"version":1,"width":16,"height":12,"real":-0.75,"imaginary":0.1,
        "scale":0.2,"cosine":1.0,"sine":0.0,"iterations":200})
}

#[test]
fn stdout_is_exactly_one_bounded_pgm_without_a_banner() {
    let output = run(&request().to_string());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let header = b"P5\n16 12\n255\n";
    assert!(output.stdout.starts_with(header));
    assert_eq!(output.stdout.len(), header.len() + 16 * 12);
    assert!(output.stderr.is_empty());
}

#[test]
fn android_masks_match_original_kotlin_fixtures() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/android_fractal.json")).unwrap();
    for case in fixtures["cases"].as_array().unwrap() {
        let Some(hex) = case["pixels_hex"].as_str() else { continue };
        let request = serde_json::json!({"version":3, "width":case["width"], "height":case["height"],
            "variant":case["variant"], "source":[case["width"],case["height"]], "crop":[0,0,1,1]});
        let output = run(&request.to_string());
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let header = format!("P5\n{} {}\n255\n", case["width"], case["height"]);
        assert!(output.stdout.starts_with(header.as_bytes()));
        let expected: Vec<u8> =
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        assert_eq!(&output.stdout[header.len()..], expected);
    }
}

#[test]
fn android_rejects_invalid_crops_dimensions_and_variants() {
    let request =
        serde_json::json!({"version":3,"width":16,"height":12,"variant":0,"source":[16,12],"crop":[0,0,1,1]});
    for (key, value) in [
        ("width", serde_json::json!(1441)),
        ("variant", serde_json::json!(2147483648_u64)),
        ("source", serde_json::json!([0, 12])),
        ("crop", serde_json::json!([0, 0, 0, 1])),
    ] {
        let mut invalid = request.clone();
        invalid[key] = value;
        let output = run(&invalid.to_string());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn all_texture_protocols_emit_bounded_images_and_reject_bad_requests() {
    let texture = serde_json::json!({"version":4,"width":80,"height":60,"texture":"lightning","variant":197});
    let rain = serde_json::json!({"version":5,"width":80,"height":60,"variant":197,"time":65,
        "source":[80,60],"crop":[0,0,1,1],"alpha_scale":0.6});
    for request in [&texture, &rain] {
        let output = run(&request.to_string());
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let header = b"P5\n80 60\n255\n";
        assert!(output.stdout.starts_with(header));
        assert_eq!(output.stdout.len(), header.len() + 80 * 60);
        assert!(output.stdout[header.len()..].iter().any(|&alpha| alpha != 0));
        assert!(output.stderr.is_empty());
    }
    for (request, key, value) in [
        (&texture, "texture", serde_json::json!("substitute")),
        (&texture, "width", serde_json::json!(1441)),
        (&texture, "variant", serde_json::json!(2147483648_u64)),
        (&rain, "time", serde_json::json!(-1)),
        (&rain, "source", serde_json::json!([0, 60])),
        (&rain, "crop", serde_json::json!([0, 0, 0, 1])),
        (&rain, "alpha_scale", serde_json::json!(1.01)),
    ] {
        let mut invalid = request.clone();
        invalid[key] = value;
        let output = run(&invalid.to_string());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    for request in [texture, rain] {
        let mut invalid = request;
        invalid["trace"] = true.into();
        invalid["width"] = 257.into();
        let output = run(&invalid.to_string());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn malformed_oversized_and_unsupported_requests_emit_no_image() {
    for request in [
        "not json".to_owned(),
        " ".repeat(16385),
        {
            let mut r = request();
            r["version"] = 2.into();
            r.to_string()
        },
        {
            let mut r = request();
            r["width"] = 100_000.into();
            r.to_string()
        },
        {
            let mut r = request();
            r["iterations"] = 0.into();
            r.to_string()
        },
    ] {
        let output = run(&request);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn seeded_protocol_emits_a_bounded_word_receipt_and_an_image() {
    let mut state = vec![5489_u32; 625];
    for i in 1..624 {
        state[i] = 1812433253_u32.wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30)).wrapping_add(i as u32);
    }
    state[624] = 624;
    let request = serde_json::json!({"version":2,"width":16,"height":12,"random_state":state});
    let output = run(&request.to_string());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let end = output.stdout.iter().position(|b| *b == b'\n').unwrap();
    let receipt = std::str::from_utf8(&output.stdout[..end]).unwrap();
    let words: u32 = receipt.strip_prefix("NOVA-FRACTAL/2 ").unwrap().parse().unwrap();
    assert!((1..=8192).contains(&words));
    let header = b"P5\n16 12\n255\n";
    assert!(output.stdout[end + 1..].starts_with(header));
    assert_eq!(output.stdout.len(), end + 1 + header.len() + 16 * 12);
    for state in [vec![0_u32; 624], vec![625; 625]] {
        let bad = serde_json::json!({"version":2,"width":16,"height":12,"random_state":state});
        let output = run(&bad.to_string());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
