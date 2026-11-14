//! `gpu-snapshot`, `gpu-bench`, `gpu-serve`: the native light-lab renderer (crate nova-gpu).
//!
//! Exit code 3 = no usable GL 3.3 context (the caller falls back to the CPU renderer), 2 = bad arguments.

use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nova_gpu::{process_cpu_seconds, FrameMap, GlContext, Pacer, Params, Renderer};
use serde_json::{json, Value};

const NO_GL: i32 = 3;
const USAGE: i32 = 2;
const MAX_SIDE: usize = 1440;

fn args() -> Vec<String> {
    std::env::args().skip(2).collect()
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn parse_size(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let (w, h) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

/// Shared argument parsing for snapshot/bench; Err = message for stderr.
fn params_from(args: &[String]) -> Result<(Params, (u32, u32)), String> {
    let mut p = Params::default();
    if let Some(t) = opt(args, "--texture") {
        p.texture = t.to_owned();
    }
    let num = |name: &str, v: f32| -> Result<f32, String> {
        opt(args, name).map_or(Ok(v), |s| s.parse().map_err(|_| format!("{name}: not a number: {s:?}")))
    };
    p.t = num("--time", p.t)?;
    p.seed = num("--seed", p.seed)?;
    p.accent = num("--accent", p.accent as f32)?.clamp(0.0, 63.0) as u32;
    p.intensity = num("--intensity", p.intensity)?;
    p.glow = num("--glow", p.glow)?;
    p.warp = num("--warp", p.warp)?;
    p.drift = args.iter().any(|a| a == "--drift");
    let size = match opt(args, "--size") {
        Some(s) => parse_size(s).ok_or_else(|| format!("--size wants WxH, got {s:?}"))?,
        None => (1000, 700),
    };
    if !nova_gpu::texture_ids().any(|id| id == p.texture) {
        let ids: Vec<_> = nova_gpu::texture_ids().collect();
        return Err(format!("unknown texture {:?}; one of {}", p.texture, ids.join(" ")));
    }
    Ok((p, size))
}

fn open_renderer() -> Result<Renderer, String> {
    GlContext::new().and_then(Renderer::new)
}

/// `gpu-snapshot --texture ID --time T --size WxH [--accent N] [--seed N] [--drift] [--out FILE.ppm]`
pub fn snapshot() -> i32 {
    let args = args();
    let (p, (w, h)) = match params_from(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gpu-snapshot: {e}");
            return USAGE;
        }
    };
    let mut r = match open_renderer() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gpu-snapshot: {e}");
            return NO_GL;
        }
    };
    if let Err(e) = r.set_size(w, h) {
        eprintln!("gpu-snapshot: {e}");
        return 1;
    }
    let (fw, fh) = r.frame_size();
    let mut rgb = vec![0u8; (fw * fh * 3) as usize];
    let info = match r.render(&p, &mut rgb) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("gpu-snapshot: {e}");
            return 1;
        }
    };
    let ppm = nova_gpu::encode_ppm(info.w, info.h, &rgb);
    let written = match opt(&args, "--out") {
        Some(path) => std::fs::write(path, &ppm).map_err(|e| format!("{path}: {e}")),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(&ppm).and_then(|_| out.flush()).map_err(|e| e.to_string())
        }
    };
    if let Err(e) = written {
        eprintln!("gpu-snapshot: {e}");
        return 1;
    }
    0
}

/// `gpu-bench --texture ID --size WxH --frames N`: per-frame GPU time and process CPU time.
pub fn bench() -> i32 {
    let args = args();
    let (mut p, (w, h)) = match params_from(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gpu-bench: {e}");
            return USAGE;
        }
    };
    let frames: usize = opt(&args, "--frames").and_then(|s| s.parse().ok()).unwrap_or(300).max(1);
    let mut r = match open_renderer() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gpu-bench: {e}");
            return NO_GL;
        }
    };
    if let Err(e) = r.set_size(w, h).and_then(|_| r.prepare(&p.texture)) {
        eprintln!("gpu-bench: {e}");
        return 1;
    }
    let (fw, fh) = r.frame_size();
    let mut rgb = vec![0u8; (fw * fh * 3) as usize];
    // one warm-up frame so driver-side shader finalisation is not counted
    if let Err(e) = r.render(&p, &mut rgb) {
        eprintln!("gpu-bench: {e}");
        return 1;
    }
    let cpu0 = process_cpu_seconds();
    let wall0 = Instant::now();
    let mut gpu = Vec::with_capacity(frames);
    for _ in 0..frames {
        p.t += 1.0 / 60.0;
        match r.render(&p, &mut rgb) {
            Ok(info) => gpu.push(info.gpu_ms.unwrap_or(f64::NAN)),
            Err(e) => {
                eprintln!("gpu-bench: {e}");
                return 1;
            }
        }
    }
    r.finish();
    let wall = wall0.elapsed().as_secs_f64();
    let cpu = process_cpu_seconds() - cpu0;
    let mut sorted = gpu.clone();
    sorted.sort_by(f64::total_cmp);
    let mean = gpu.iter().sum::<f64>() / gpu.len() as f64;
    let pct = |q: f64| sorted[((sorted.len() - 1) as f64 * q).round() as usize];
    println!(
        "{}",
        json!({
            "texture": p.texture, "scene": [fw, fh], "grid": r.grid(), "frames": frames,
            "gpu_ms_mean": mean, "gpu_ms_p50": pct(0.5), "gpu_ms_p95": pct(0.95), "gpu_ms_max": pct(1.0),
            "wall_ms_per_frame": wall * 1000.0 / frames as f64,
            "cpu_s": cpu, "cpu_ms_per_frame": cpu * 1000.0 / frames as f64,
            "gl": r.gl_renderer(),
        })
    );
    0
}

enum Msg {
    Cmd(Value),
    Bad(String),
    Eof,
}

fn emit(v: &Value) {
    let mut out = std::io::stdout().lock();
    // A closed stdout means the parent is gone; stdin EOF ends the loop right after.
    let _ = writeln!(out, "{v}").and_then(|_| out.flush());
}

struct Serve {
    p: Params,
    fps: f64,
    anim: bool,
    /// animation speed percent, 0..300 (0 = frozen frame)
    speed: f64,
    /// clock of the hover shimmer: advances with the animation clock, or at wall speed when it is off
    fx_t: f32,
    paused: bool,
    dirty: bool,
    sized: bool,
    broken: bool,
    quit: bool,
}

impl Serve {
    fn apply(&mut self, r: &mut Renderer, msg: Msg) {
        let v = match msg {
            Msg::Cmd(v) => v,
            Msg::Bad(e) => return emit(&json!({ "error": e })),
            Msg::Eof => {
                self.quit = true;
                return;
            }
        };
        let f = |k: &str| v.get(k).and_then(Value::as_f64);
        match v.get("cmd").and_then(Value::as_str).unwrap_or("") {
            "config" => {
                if let Some(t) = v.get("texture").and_then(Value::as_str) {
                    if nova_gpu::texture_ids().any(|id| id == t) {
                        self.p.texture = t.to_owned();
                    } else {
                        emit(&json!({ "error": format!("unknown texture {t:?}") }));
                    }
                }
                if let Some(x) = f("seed") {
                    self.p.seed = x as f32;
                }
                if let Some(x) = f("accent") {
                    self.p.accent = x.clamp(0.0, 63.0) as u32;
                }
                if let Some(x) = f("intensity") {
                    self.p.intensity = x as f32;
                }
                if let Some(x) = f("glow") {
                    self.p.glow = x as f32;
                }
                if let Some(x) = f("warp") {
                    self.p.warp = x as f32;
                }
                if let Some(x) = f("fps") {
                    self.fps = x.clamp(1.0, 240.0);
                }
                if let Some(x) = v.get("anim").and_then(Value::as_bool) {
                    self.anim = x;
                }
                if let Some(x) = f("speed") {
                    self.speed = x.clamp(0.0, 300.0);
                }
                if let Some(x) = f("sat") {
                    self.p.sat = x.clamp(0.0, 200.0) as f32;
                }
                if let Some(x) = v.get("drift").and_then(Value::as_bool) {
                    self.p.drift = x;
                }
                if let Some(x) = f("t") {
                    self.p.t = x as f32;
                }
                self.dirty = true;
                self.broken = false;
            }
            "size" => {
                let (w, h) = (f("w").unwrap_or(0.0), f("h").unwrap_or(0.0));
                if w >= 1.0 && h >= 1.0 {
                    match r.set_size(w as u32, h as u32) {
                        Ok(()) => {
                            self.sized = true;
                            self.dirty = true;
                            self.broken = false;
                        }
                        Err(e) => emit(&json!({ "error": e })),
                    }
                }
            }
            "pointer" => {
                let inside = v.get("in").and_then(Value::as_bool).unwrap_or(true);
                r.set_pointer(f("x").unwrap_or(0.0) as f32, f("y").unwrap_or(0.0) as f32, inside);
                self.dirty = true;
            }
            "pause" => {
                self.paused = v.get("on").and_then(Value::as_bool).unwrap_or(true);
                self.dirty = true;
            }
            "overlay" => {
                if v.get("clear").and_then(Value::as_bool).unwrap_or(false) {
                    r.clear_overlay();
                } else {
                    let path = v.get("path").and_then(Value::as_str).unwrap_or("");
                    let (w, h) = (f("w").unwrap_or(0.0) as u32, f("h").unwrap_or(0.0) as u32);
                    let glass = v.get("glass").and_then(Value::as_bool).unwrap_or(false);
                    // read once; the caller may delete the file as soon as this returns
                    let res = std::fs::read(path).map_err(|e| format!("overlay {path:?}: {e}")).and_then(|bytes| {
                        let n4 = (w as usize) * (h as usize) * 4;
                        if glass && bytes.len() == n4 + (w as usize) * (h as usize) {
                            r.set_overlay_glass(w, h, &bytes[..n4], Some(&bytes[n4..]))
                        } else if glass {
                            Err(format!("glass overlay has {} bytes, want {}", bytes.len(), n4 / 4 * 5))
                        } else {
                            r.set_overlay(w, h, &bytes)
                        }
                    });
                    if let Err(e) = res {
                        emit(&json!({ "error": e }));
                    }
                }
                self.dirty = true;
            }
            "hot" => {
                let on = v.get("on").and_then(Value::as_bool).unwrap_or(true);
                let rect = v.get("rect").and_then(Value::as_array).and_then(|a| {
                    let n: Vec<f32> = a.iter().filter_map(Value::as_f64).map(|x| x as f32).collect();
                    (n.len() == 4 && a.len() == 4).then(|| [n[0], n[1], n[2], n[3]])
                });
                let color = v.get("color").and_then(Value::as_array).and_then(|a| {
                    let n: Vec<f32> = a.iter().filter_map(Value::as_f64).map(|x| (x / 255.0).clamp(0.0, 1.0) as f32).collect();
                    (n.len() == 3 && a.len() == 3).then(|| [n[0], n[1], n[2]])
                });
                if on && rect.is_none() {
                    emit(&json!({ "error": "hot: rect [l,t,r,b] required when on" }));
                } else {
                    r.set_hot(rect, f("radius").unwrap_or(12.0) as f32, f("reach").map(|x| x as f32), color, on);
                    self.dirty = true;
                }
            }
            "quit" => self.quit = true,
            other => emit(&json!({ "error": format!("unknown cmd {other:?}") })),
        }
    }

    /// The animation clock runs: `anim` on and not frozen by `speed` 0.
    fn animating(&self) -> bool {
        self.anim && self.speed > 0.0
    }

    /// The page's `if(!(st.anim||dirty||moving))`, plus pause/size/error gates; a hover glow keeps
    /// frames coming until it has faded out.
    fn active(&self, r: &Renderer) -> bool {
        self.sized
            && !self.paused
            && !self.broken
            && (self.animating() || self.dirty || r.pointer_moving() || r.hot_active())
    }
}

/// `gpu-serve`: persistent renderer driven by newline JSON on stdin, frames into a named mapping.
pub fn serve() -> i32 {
    let mut r = match open_renderer() {
        Ok(r) => r,
        Err(e) => {
            emit(&json!({ "ready": false, "error": e }));
            return NO_GL;
        }
    };
    let name = format!("NovaGpu-{}", std::process::id());
    let mut map = match FrameMap::create(&name, MAX_SIDE * MAX_SIDE * 3) {
        Ok(m) => m,
        Err(e) => {
            emit(&json!({ "ready": false, "error": e }));
            return 1;
        }
    };

    let (tx, rx) = mpsc::channel::<Msg>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let msg =
                serde_json::from_str::<Value>(&line).map_or_else(|e| Msg::Bad(format!("bad json: {e}")), Msg::Cmd);
            if tx.send(msg).is_err() {
                return;
            }
        }
        let _ = tx.send(Msg::Eof);
    });

    emit(
        &json!({ "ready": true, "protocol": 2, "has_overlay": true, "features": ["glass", "hot", "speed", "sat", "drift"], "map": name, "size": map.size(), "gl": r.gl_renderer(), "version": r.gl_version() }),
    );

    let mut s = Serve {
        p: Params::default(),
        fps: 60.0,
        anim: true,
        speed: 100.0,
        fx_t: 0.0,
        paused: false,
        dirty: true,
        sized: false,
        broken: false,
        quit: false,
    };
    let mut seq = 0u64;
    let mut last = Instant::now();
    let mut next_due: Option<Instant> = None;
    let pacer = Pacer::new();

    let publish = |map: &mut FrameMap, seq: &mut u64, info: nova_gpu::FrameInfo| {
        *seq += 1;
        map.publish(*seq, info.w, info.h);
        emit(&json!({ "frame": *seq, "ms": info.gpu_ms.map(|m| (m * 1000.0).round() / 1000.0) }));
    };

    while !s.quit {
        if !s.active(&r) {
            // deliver the frame still in flight before going idle
            match r.flush(map.pixels()) {
                Ok(Some(info)) => publish(&mut map, &mut seq, info),
                Ok(None) => {}
                Err(e) => emit(&json!({ "error": e })),
            }
            // idle: zero CPU until a command arrives (or stdin closes)
            match rx.recv() {
                Ok(m) => s.apply(&mut r, m),
                Err(_) => break,
            }
            last = Instant::now();
            next_due = None;
            continue;
        }
        while let Ok(m) = rx.try_recv() {
            s.apply(&mut r, m);
        }
        if s.quit || !s.active(&r) {
            continue;
        }
        // pace on an absolute deadline (high-resolution timer); commands wait at most one period
        // a hover glow alone needs 30 fps (never above the cap); animation / pointer run at the cap
        let hover_only = !s.animating() && !s.dirty && !r.pointer_moving();
        let period = Duration::from_secs_f64(1.0 / if hover_only { s.fps.min(30.0) } else { s.fps });
        if let Some(due) = next_due {
            if Instant::now() < due {
                pacer.sleep_until(due);
                while let Ok(m) = rx.try_recv() {
                    s.apply(&mut r, m);
                }
                if s.quit || !s.active(&r) {
                    continue;
                }
            }
        }
        let now = Instant::now();
        next_due = Some(match next_due {
            // on schedule: next slot; late by more than a period: resync from now
            Some(due) if now < due + period => due + period,
            _ => now + period,
        });
        let dt = now.duration_since(last).as_secs_f32().min(0.1);
        last = now;
        let k = if s.animating() { s.speed as f32 / 100.0 } else { 1.0 };
        if s.animating() {
            s.p.t += dt * k;
        }
        s.fx_t += dt * k;
        r.set_fx_time(s.fx_t);
        r.step_pointer(dt);
        r.step_hot(dt);
        s.dirty = false;
        match r.render_async(&s.p, map.pixels()) {
            Ok(Some(info)) => publish(&mut map, &mut seq, info),
            Ok(None) => {}
            Err(e) => {
                emit(&json!({ "error": e }));
                s.broken = true;
            }
        }
    }
    0
}
