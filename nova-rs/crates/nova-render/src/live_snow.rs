//! Snow: a 3D snowfall volume. The camera glides forward through ~2200 hashed flakes (perspective,
//! parallax, sway, slow tumble); far flakes are soft dots, nearer ones get a hash-built 6-fold pattern
//! (dendrite, plate, star, needle, fern, stellar plate) and the closest are slightly defocused.
use crate::live::{rand01, Live};
use crate::texture_math::{perlin, Seed};
use std::f32::consts::{PI, TAU};

const NEAR: f32 = 0.4;
const FAR: f32 = 3.0;
const COUNT: u32 = 3000;
const PERIOD: f64 = 70.0; // seconds for one flake to travel far -> near
const C30: f32 = 0.866_025_4;

fn ss(a: f32, b: f32, x: f32) -> f32 {
    let t = ((x - a) / (b - a)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Segment (x0, y0, x1, y1, half width, weight) in flake-normalised units (radius = 1).
type Seg = [f32; 6];

struct Shape {
    kind: u8,
    n: usize,
    seg: [Seg; 12],
    hexr: f32,
    fill: f32,
    rings: [(f32, f32); 2], // (radius, half width); radius 0 = none
}

fn branch(sh: &mut Shape, s: f32, ang: f32, len: f32, hw: f32) {
    if sh.n + 2 > sh.seg.len() {
        return;
    }
    let (c, sn) = (ang.cos() * len, ang.sin() * len);
    sh.seg[sh.n] = [s, 0.0, s + c, sn, hw, 1.0];
    sh.seg[sh.n + 1] = [s, 0.0, s + c, sn, hw, 1.0];
    sh.n += 1; // the mirrored branch comes from the fold
}

fn build(seed: u32, i: u32) -> Shape {
    let r = |k: u32| rand01(seed, i, 100 + k);
    let pick = r(0);
    let mut sh = Shape {
        kind: 0,
        n: 0,
        seg: [[0.0; 6]; 12],
        hexr: 0.0,
        fill: 0.0,
        rings: [(0.0, 0.0); 2],
    };
    let hw = 0.04 + 0.03 * r(1);
    if pick < 0.3 {
        // stellar dendrite
        sh.seg[0] = [0.0, 0.0, 1.0, 0.0, hw, 1.0];
        sh.n = 1;
        let nb = 2 + (r(2) * 2.0) as usize;
        for k in 0..nb {
            let s = 0.2 + (k as f32 + 0.5 * r(3 + k as u32)) * 0.55 / nb as f32;
            branch(
                &mut sh,
                s,
                0.9 + 0.3 * r(8),
                (0.42 * (1.05 - s)) * (0.8 + 0.4 * r(9 + k as u32)) + 0.08,
                hw * 0.8,
            );
        }
        if r(14) < 0.6 {
            branch(&mut sh, 0.84, 0.8 + 0.3 * r(15), 0.17, hw * 0.7);
        }
        sh.hexr = 0.12 + 0.08 * r(16);
        sh.fill = 0.7;
    } else if pick < 0.5 {
        // sectored plate
        sh.kind = 1;
        sh.hexr = 0.82 + 0.15 * r(2);
        sh.fill = 0.26 + 0.12 * r(3);
        sh.rings = [
            (0.38 + 0.25 * r(4), 0.035),
            (if r(5) < 0.5 { 0.2 } else { 0.0 }, 0.03),
        ];
        let sp = 0.4 + 0.4 * r(6);
        sh.seg[0] = [0.0, 0.0, sp, 0.0, 0.035, 0.9];
        sh.n = 1;
        if r(7) < 0.5 {
            branch(&mut sh, sp * 0.9, 0.5, 0.25, 0.03);
        }
    } else if pick < 0.62 {
        // simple star
        sh.seg[0] = [0.0, 0.0, 1.0, 0.0, 0.085 + 0.04 * r(2), 1.0];
        sh.n = 1;
        if r(3) < 0.6 {
            branch(&mut sh, 0.45 + 0.2 * r(4), 1.0, 0.22, 0.05);
        }
        sh.hexr = 0.18;
        sh.fill = 0.8;
    } else if pick < 0.72 {
        // needle / column (2-fold)
        sh.kind = 3;
        let wid = 0.07 + 0.08 * r(2);
        sh.seg[0] = [-0.9, 0.0, 0.9, 0.0, wid, 0.34];
        sh.seg[1] = [-0.9, 0.0, 0.9, 0.0, 0.03, 1.0];
        sh.seg[2] = [0.9, -wid, 0.9, wid, 0.025, 0.9];
        sh.n = 3;
    } else if pick < 0.88 {
        // fern-like dendrite
        sh.seg[0] = [0.0, 0.0, 1.0, 0.0, 0.032 + 0.015 * r(2), 1.0];
        sh.n = 1;
        let nb = 5 + (r(3) * 2.0) as usize;
        for k in 0..nb {
            let s = 0.1 + 0.8 * k as f32 / nb as f32;
            let len = 0.34 * (PI * (0.12 + 0.8 * s)).sin().max(0.1) * (0.9 + 0.2 * r(4 + k as u32));
            branch(&mut sh, s, 0.75 + 0.25 * r(12), len, 0.026);
        }
    } else {
        // stellar plate: hexagon with arms
        sh.kind = 5;
        sh.hexr = 0.34 + 0.1 * r(2);
        sh.fill = 0.4;
        sh.rings = [(sh.hexr, 0.035), (0.0, 0.0)];
        sh.seg[0] = [0.0, 0.0, 1.0, 0.0, 0.045, 1.0];
        sh.n = 1;
        branch(&mut sh, 0.62 + 0.15 * r(3), 1.0, 0.26, 0.04);
    }
    sh
}

fn seg_dist(px: f32, py: f32, s: &Seg) -> f32 {
    let (ax, ay, bx, by) = (s[0], s[1], s[2], s[3]);
    let (dx, dy) = (bx - ax, by - ay);
    let t = (((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy).max(1e-6)).clamp(0.0, 1.0);
    (px - ax - dx * t).hypot(py - ay - dy * t)
}

/// Coverage 0..1 of the flake pattern at normalised point (px, py), `r` px radius, `soft` px blur.
fn pattern(sh: &Shape, px: f32, py: f32, r: f32, soft: f32) -> f32 {
    let (qx, qy) = if sh.kind == 3 {
        (px.abs(), py.abs())
    } else {
        let rad = px.hypot(py);
        let mut a = py.atan2(px).rem_euclid(PI / 3.0);
        if a > PI / 6.0 {
            a = PI / 3.0 - a;
        }
        (rad * a.cos(), rad * a.sin())
    };
    let cov = |dpx: f32| (0.5 - dpx / soft).clamp(0.0, 1.0);
    let mut best = 0.0f32;
    for s in &sh.seg[..sh.n] {
        let hwpx = (s[4] * r).max(0.72);
        best = best.max(s[5] * cov(seg_dist(qx, qy, s) * r - hwpx));
    }
    if sh.kind != 3 {
        let hexd = |rad: f32| qx * C30 + qy * 0.5 - rad * C30;
        if sh.fill > 0.0 {
            best = best.max(sh.fill * cov(hexd(sh.hexr) * r));
        }
        for &(rr, hw) in &sh.rings {
            if rr > 0.0 {
                best = best.max(0.9 * cov((hexd(rr).abs() - hw) * r - 0.0f32.max(0.72 - hw * r)));
            }
        }
        if sh.kind == 1 {
            best = best
                .max(0.95 * cov((hexd(sh.hexr).abs() - 0.06) * r - 0.0f32.max(0.72 - 0.06 * r)));
        }
    }
    best
}

pub(crate) fn render(l: &mut Live) {
    let (w, h) = (l.width as i32, l.height as i32);
    let span = l.span;
    let (aw, ah) = (l.aw, l.ah);
    let seed = l.seed;
    let t = l.time;

    // ground mist: low-res sum of exactly periodic travelling sines, bilinear upsampled
    {
        let ph = |hz: f64, off: f32| ((t * hz).rem_euclid(1.0) as f32 + off) * TAU;
        let ph1 = ph(0.013, 0.1);
        let ph2 = ph(0.021, 0.5);
        let ph3 = ph(0.034, 0.8);
        let _ = Seed(seed as i32);
        let _ = perlin;
        let (gw, gh) = (48usize, 30usize);
        let mut g = vec![0.0f32; (gw + 1) * (gh + 1)];
        for gy in 0..=gh {
            let v = gy as f32 / gh as f32 * ah;
            let vv = v / ah;
            let base = 0.045 + 0.11 * ss(0.35, 1.05, vv).powf(1.3);
            for gx in 0..=gw {
                let u = gx as f32 / gw as f32 * aw;
                let n = 0.5
                    + 0.22 * (1.7 * u + 0.9 * v + ph1).sin()
                    + 0.18 * (2.9 * u - 1.3 * v - ph2).sin()
                    + 0.12 * (0.8 * u + 3.3 * v + ph3).sin();
                g[gy * (gw + 1) + gx] = base * (0.35 + 1.1 * n);
            }
        }
        for y in 0..l.height {
            let fy = (y as f32 + 0.5) / l.height as f32 * gh as f32;
            let y0 = (fy as usize).min(gh - 1);
            let ty = fy - y0 as f32;
            for x in 0..l.width {
                let fx = (x as f32 + 0.5) / l.width as f32 * gw as f32;
                let x0 = (fx as usize).min(gw - 1);
                let tx = fx - x0 as f32;
                let i = y0 * (gw + 1) + x0;
                let a = g[i] + (g[i + 1] - g[i]) * tx;
                let b = g[i + gw + 1] + (g[i + gw + 2] - g[i + gw + 1]) * tx;
                l.field[y * l.width + x] = a + (b - a) * ty;
            }
        }
    }

    let tz = (t / PERIOD).rem_euclid(1.0) as f32;
    let cam_x = 0.07 * (((t * 0.047).rem_euclid(1.0) as f32) * TAU).sin();
    let cam_y = 0.035 * (((t * 0.031).rem_euclid(1.0) as f32 + 0.3) * TAU).sin();
    let rx = (FAR * aw * 0.5 * 1.2 + 0.1) as f64;
    let ry = (FAR * ah * 0.5 * 1.2 + 0.1) as f64;

    for i in 0..COUNT {
        let r = |k: u32| rand01(seed, i, k);
        let d = (r(0) - tz).rem_euclid(1.0);
        let dist = NEAR + d * (FAR - NEAR);
        let fade = ss(NEAR, NEAR + 0.3, dist) * (1.0 - ss(2.3, 3.0, dist));
        let a = (0.6 + 0.5 * r(8)).min(1.0) * fade * (1.0 - 0.45 * d);
        if a < 0.01 {
            continue;
        }
        let rw = 0.004 + 0.0085 * r(7).powf(2.4);
        let rpx = rw / dist * span;
        // world position: falls, drifts with the wind, sways
        let vy = 0.018 + 0.03 * r(3) as f64;
        let wind = 0.012 * (r(4) as f64 - 0.5);
        let y = (((r(2) as f64 * 2.0 - 1.0) * ry + vy * t + ry).rem_euclid(2.0 * ry) - ry) as f32;
        let sway = (0.02 + 0.05 * r(5))
            * (((t * (0.05 + 0.1 * r(6) as f64) + r(10) as f64).rem_euclid(1.0) as f32) * TAU)
                .sin();
        let x = (((r(1) as f64 * 2.0 - 1.0) * rx + wind * t + rx).rem_euclid(2.0 * rx) - rx) as f32
            + sway;
        let u = (aw * 0.5 + (x - cam_x) / dist) * span;
        let v = (ah * 0.5 + (y - cam_y) / dist) * span;
        let soft = 1.0 + (0.95 - dist).max(0.0) * 9.0;
        let m = ss(2.0, 3.3, rpx);
        let ext = rpx * 1.15 + soft * 1.2 + 2.0;
        if u < -ext || v < -ext || u > w as f32 + ext || v > h as f32 + ext {
            continue;
        }
        let (x0, x1) = (
            (u - ext).floor().max(0.0) as i32,
            ((u + ext).ceil() as i32).min(w - 1),
        );
        let (y0, y1) = (
            (v - ext).floor().max(0.0) as i32,
            ((v + ext).ceil() as i32).min(h - 1),
        );
        let comp = 1.0 / (1.0 + (soft - 1.0) * 0.18);
        if m < 1.0 {
            // soft anti-aliased dot, flux-conserving for sub-pixel flakes
            let rd = rpx.max(0.55);
            let k = (rpx / 0.75).min(1.0).powi(2) * (1.0 - m) * a * comp;
            for py in y0..=y1 {
                for px in x0..=x1 {
                    let dd = (px as f32 + 0.5 - u).hypot(py as f32 + 0.5 - v);
                    let c = ss(0.0, 1.0, (rd + 0.7 * soft - dd) / (1.4 * soft)) * k;
                    let f = &mut l.field[(py * w + px) as usize];
                    *f = 1.0 - (1.0 - *f) * (1.0 - c);
                }
            }
        }
        if m > 0.0 {
            let sh = build(seed, i);
            let ang = (((t * (0.01 + 0.03 * r(11) as f64) * if r(12) < 0.5 { 1.0 } else { -1.0 }
                + r(13) as f64)
                .rem_euclid(1.0)) as f32)
                * TAU;
            let (ca, sa) = (ang.cos(), ang.sin());
            let inv = 1.0 / rpx;
            for py in y0..=y1 {
                for px in x0..=x1 {
                    let dx = px as f32 + 0.5 - u;
                    let dy = py as f32 + 0.5 - v;
                    let (nx, ny) = ((dx * ca + dy * sa) * inv, (-dx * sa + dy * ca) * inv);
                    let c = pattern(&sh, nx, ny, rpx, soft) * m * a * comp;
                    if c > 0.002 {
                        let f = &mut l.field[(py * w + px) as usize];
                        *f = 1.0 - (1.0 - *f) * (1.0 - c);
                    }
                }
            }
        }
    }
}
