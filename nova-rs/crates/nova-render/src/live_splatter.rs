//! Macro rain on dark water: the camera dollies forward over a perspective surface. Raindrops fall
//! as bright streaks, hit the surface, throw a small crown and many droplets along ballistic arcs
//! (far, shrinking, with trails); no rings. Everything is stateless per (cell, period) hash.
use crate::live::{hash, rand01, Live};
use crate::texture_canvas::Brush;
use std::f32::consts::TAU;

const F: f32 = 1.0;
const HC: f32 = 0.8; // camera height over the surface
const ZN: f32 = 0.5;
const ZF: f32 = 5.0;
const D: f32 = 0.45; // depth cell
const W: f32 = 0.6; // lane width
const T: f64 = 2.9; // period of one impact slot
const FALL_T: f64 = 0.5;
const SPLASH_T: f64 = 0.8;
const HMAX: f32 = 1.8;
const G: f32 = 2.7;
const SPEED: f64 = 0.14;
const DROP_R: f32 = 0.02;
const PROB: f32 = 0.9;
const STREAK_PROB: f32 = 0.12;

struct Cam {
    cx: f32,
    hy: f32,
    camx: f32,
    c: f64,
}

impl Cam {
    /// world (x, height, absolute depth) -> screen (x, y, scale)
    fn proj(&self, x: f32, h: f32, zw: f64) -> Option<(f32, f32, f32)> {
        let z = (zw - self.c) as f32;
        if z < ZN * 0.6 {
            return None;
        }
        let k = F / z;
        Some((self.cx + (x - self.camx) * k, self.hy + (HC - h) * k, k))
    }
}

fn sstep(a: f32, b: f32, x: f32) -> f32 {
    let t = ((x - a) / (b - a)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn depth_fade(k: f32) -> f32 {
    let z = 1.0 / k;
    sstep(ZF, ZF * 0.5, z) * sstep(ZN * 0.9, ZN * 2.6, z)
}

fn br(a: f32) -> Brush {
    Brush {
        alpha: (a * 255.0).clamp(0.0, 255.0) as i32,
        ..Brush::default()
    }
}

fn dot(l: &mut Live, x: f32, y: f32, r: f32, k: f32, a: f32) {
    if a < 0.01 || r < 0.0005 || x < -0.5 || y < -0.5 || x > l.aw + 0.5 || y > l.ah + 0.5 {
        return;
    }
    let blur = 0.010 * (k - 0.8).abs();
    if blur < r * 0.3 {
        l.canvas.circle(x, y, r, &br(a));
        return;
    }
    let q = (r / (r + blur)).powf(1.3);
    for (m, w) in [(0.0, 0.5), (0.55, 0.3), (1.1, 0.25)] {
        l.canvas.circle(x, y, r + blur * m, &br(a * q * w));
    }
}

fn stroke(l: &mut Live, p: (f32, f32), q: (f32, f32), w: f32, a: f32) {
    if a < 0.01 {
        return;
    }
    let b = Brush {
        alpha: (a * 255.0).clamp(0.0, 255.0) as i32,
        width: w.max(0.0012),
        stroke: true,
        round_cap: true,
        ..Brush::default()
    };
    l.canvas.line(p.0, p.1, q.0, q.1, &b);
}

fn impact(l: &mut Live, cam: &Cam, id: u32, n: u32, x: f32, zw: f64, sz: f32, t: f64) {
    let r0 = DROP_R * sz;
    if t < FALL_T {
        let tf = (t / FALL_T) as f32;
        let h = HMAX * (1.0 - tf * tf);
        let h2 = (h + 0.2 * (0.3 + tf)).min(HMAX);
        if let (Some(a), Some(b)) = (cam.proj(x, h, zw), cam.proj(x, h2, zw)) {
            let f = depth_fade(a.2) * sstep(0.0, 0.3, tf);
            stroke(l, (a.0, a.1), (b.0, b.1), 1.1 * r0 * a.2, 0.5 * f);
            dot(l, a.0, a.1, r0 * a.2, a.2, 0.8 * f);
            if let (Some(ra), Some(rb)) = (cam.proj(x, -h, zw), cam.proj(x, -h2, zw)) {
                stroke(l, (ra.0, ra.1), (rb.0, rb.1), 1.6 * r0 * ra.2, 0.14 * f);
            }
        }
        return;
    }
    let ts = (t - FALL_T) as f32;
    let Some(b0) = cam.proj(x, 0.0, zw) else {
        return;
    };
    let f = depth_fade(b0.2);
    if f < 0.01 {
        return;
    }
    // crown: a few short spikes flung up and outward
    if ts < 0.24 {
        let s = ts / 0.24;
        for k in 0..7u32 {
            let ph = (k as f32 + rand01(id, n, 20 + k)) / 7.0 * TAU;
            let rb = 0.018 * sz * (1.0 + 2.0 * s);
            let hh = 0.055 * sz * (s * TAU * 0.5).sin() * (0.6 + 0.8 * rand01(id, n, 40 + k));
            let (cp, sp) = (ph.cos(), ph.sin());
            let a = cam.proj(x + cp * rb, 0.0, zw + (sp * rb) as f64);
            let b = cam.proj(x + cp * rb * 1.8, hh, zw + (sp * rb * 1.8) as f64);
            if let (Some(a), Some(b)) = (a, b) {
                stroke(
                    l,
                    (a.0, a.1),
                    (b.0, b.1),
                    0.4 * r0 * a.2,
                    0.38 * f * (1.0 - s),
                );
            }
        }
    }
    // droplets (index 0 is the central jet drop)
    let cnt = 12 + hash(id, n, 5) % 10;
    for k in 0..cnt {
        let rr = |tag: u32| rand01(id, n, 100 + k * 8 + tag);
        let (vh, vv, rd, td, ph);
        if k == 0 {
            vh = 0.0;
            vv = 0.54 * sz;
            rd = r0 * 0.8;
            td = 0.05;
            ph = 0.0;
        } else {
            let q = rr(0);
            vh = (0.4 + 1.9 * q * q) * sz;
            vv = (0.14 + 0.40 * rr(1)) * sz.sqrt();
            rd = r0 * (0.25 + 0.35 * rr(2));
            td = 0.01 + 0.06 * rr(3);
            ph = rr(4) * TAU;
        }
        let tau = 2.0 * vv / G;
        let tt = ts - td;
        if tt < 0.0 || tt > tau {
            continue;
        }
        let pos = |t: f32| {
            let hor = vh * t;
            (
                x + ph.cos() * hor,
                (vv * t - 0.5 * G * t * t).max(0.0),
                zw + (ph.sin() * hor) as f64,
            )
        };
        let (px, ph_, pz) = pos(tt);
        let (qx, qh, qz) = pos((tt - 0.05).max(0.0));
        let (Some(a), Some(b)) = (cam.proj(px, ph_, pz), cam.proj(qx, qh, qz)) else {
            continue;
        };
        let life = tt / tau;
        let fa = depth_fade(a.2) * (1.0 - sstep(0.75, 1.0, life));
        let rad = rd * a.2 * (1.0 - 0.55 * life);
        stroke(l, (a.0, a.1), (b.0, b.1), 0.9 * rad, 0.3 * fa);
        dot(l, a.0, a.1, rad, a.2, 0.8 * fa);
        if let Some(ra) = cam.proj(px, -ph_, pz) {
            dot(l, ra.0, ra.1, rad * 0.8, ra.2, 0.16 * fa);
        }
        if k == 0 && ts < 0.18 {
            stroke(l, (b0.0, b0.1), (a.0, a.1), 0.9 * rad, 0.3 * fa);
        }
    }
}

pub(crate) fn render(l: &mut Live) {
    let (aw, ah) = (l.aw, l.ah);
    let hy = 0.10 * ah;
    let tm = l.time;
    let c = tm * SPEED;
    let camx = (0.12 * (tm * 0.09).rem_euclid(std::f64::consts::TAU).sin()) as f32;
    let cam = Cam {
        cx: aw * 0.5,
        hy,
        camx,
        c,
    };
    let seed = l.seed;

    // dark surface with a faint sheen near the horizon, drifting toward the camera
    let ph = (tm * 0.35).rem_euclid(TAU as f64) as f32;
    l.fill(|u, v| {
        let dv = v - hy;
        let sheen = 0.07 * (-(dv / 0.14).powi(2)).exp();
        let fl = if dv > 0.01 {
            let k = dv / HC;
            let zz = 1.0 / k;
            0.008 * (1.0 + (zz * 14.0 - ph * 3.0 + (u - aw * 0.5) * 3.0 * k).sin())
        } else {
            0.0
        };
        0.030 + sheen + fl
    });

    let i0 = ((c + ZN as f64 * 0.5) / D as f64).floor() as i64 - 1;
    let i1 = ((c + ZF as f64) / D as f64).floor() as i64 + 1;
    for i in (i0..=i1).rev() {
        let zc = ((i + 1) as f64 * D as f64 - c) as f32;
        let half = aw * 0.5 * zc.max(0.2) / F + 0.55;
        let j0 = ((camx - half) / W).floor() as i64;
        let j1 = ((camx + half) / W).ceil() as i64;
        for j in j0..=j1 {
            let id = hash(seed, i as u32, j as u32);
            // impact slot
            let q = (tm + rand01(id, 0, 1) as f64 * T) / T;
            let nn = q.floor();
            let t = (q - nn) * T;
            let n = nn as i64 as u32;
            if rand01(id, n, 2) < PROB * (1.4 / zc.max(1.4)) && t < FALL_T + SPLASH_T {
                let x = (j as f32 + rand01(id, n, 3)) * W;
                let zw = (i as f32 + rand01(id, n, 4)) as f64 * D as f64;
                let sz = 0.9 + 1.0 * rand01(id, n, 6).powi(2);
                impact(l, &cam, id, n, x, zw, sz, t);
            }
            // background streak slot: falls through, no landing
            let per = 0.55 + 0.3 * rand01(id, 50, 1) as f64;
            let q2 = (tm + rand01(id, 51, 1) as f64 * per) / per;
            let n2 = q2.floor();
            let tf = (q2 - n2) as f32;
            let m = n2 as i64 as u32;
            if rand01(id, m, 52) < STREAK_PROB {
                let x = (j as f32 + rand01(id, m, 53)) * W;
                let zw = (i as f32 + rand01(id, m, 54)) as f64 * D as f64;
                let h = HMAX * (1.0 - tf * tf);
                let h2 = (h + 0.2 * (0.3 + tf)).min(HMAX);
                if let (Some(a), Some(b)) = (cam.proj(x, h, zw), cam.proj(x, h2, zw)) {
                    let f = depth_fade(a.2) * sstep(0.0, 0.2, tf) * sstep(0.05, 0.3, h);
                    stroke(l, (a.0, a.1), (b.0, b.1), 0.9 * DROP_R * a.2, 0.3 * f);
                }
            }
        }
    }
}
