//! Live grass: a first-person stroll through a low meadow. A pinhole ground plane (camera height 1) moves
//! forward over a world grid; log-spaced depth bands of hashed cells hold grass tufts and detailed flowers
//! (daisy, five-petal, clover, bell) drawn back to front, the far field is per-pixel noise, plus a hazy sky.
use crate::live::{hash, rand01, Live};
use crate::texture_canvas::{oval, Brush, Path};
use crate::texture_math::smooth;
use std::f32::consts::TAU;

const Z0: f32 = 0.28;
const BANDS: usize = 6;
const C0: f32 = 0.115;
const SPEED: f64 = 0.36;

fn fill(a: f32) -> Brush {
    Brush {
        alpha: a.clamp(0.0, 255.0) as i32,
        ..Brush::default()
    }
}
fn erase(a: f32) -> Brush {
    Brush {
        alpha: a.clamp(0.0, 255.0) as i32,
        erase: true,
        ..Brush::default()
    }
}
fn stroke(a: f32, w: f32, erase: bool) -> Brush {
    Brush {
        alpha: a.clamp(0.0, 255.0) as i32,
        width: w,
        stroke: true,
        round_cap: true,
        erase,
        ..Brush::default()
    }
}

/// Smooth value noise over integer cells (f64 cell index so far-away worlds keep precision).
fn vnoise(seed: u32, x: f64, z: f64) -> f32 {
    let (xf, zf) = (x.floor(), z.floor());
    let (fx, fz) = ((x - xf) as f32, (z - zf) as f32);
    let (xi, zi) = (xf as i64 as u32, zf as i64 as u32);
    let (u, v) = (fx * fx * (3.0 - 2.0 * fx), fz * fz * (3.0 - 2.0 * fz));
    let h = |a: u32, b: u32| rand01(seed, xi.wrapping_add(a), zi.wrapping_add(b));
    let (a, b) = (
        h(0, 0) + (h(1, 0) - h(0, 0)) * u,
        h(0, 1) + (h(1, 1) - h(0, 1)) * u,
    );
    a + (b - a) * v
}

struct Cam {
    cx: f32,
    yh: f32,
    k: f32,
    hb: f32,
    x: f64,
    z: f64,
}

pub(crate) fn render(l: &mut Live) {
    let t = l.time;
    let cam = Cam {
        cx: l.aw * 0.5,
        yh: l.ah * 0.235,
        k: l.ah * 0.765 * 0.42,
        hb: 1.0 + 0.018 * (t * 6.2).rem_euclid(TAU as f64).sin() as f32,
        x: 0.06 * (t * 0.43).rem_euclid(std::f64::consts::TAU).sin()
            + 0.035 * (t * 0.97).rem_euclid(std::f64::consts::TAU).sin(),
        z: t * SPEED,
    };
    ground_field(l, &cam);
    let mut p = Path::new();
    for b in 0..BANDS {
        band(l, &cam, b, &mut p);
    }
}

fn ground_field(l: &mut Live, c: &Cam) {
    let (w, h, span) = (l.width, l.height, l.span);
    let seed = l.seed;
    let zoff = c.z;
    let cloud = (l.time * 0.004, l.time * 0.0016);
    for y in (0..h).step_by(2) {
        let v = (y as f32 + 1.0) / span;
        let row_v = v - c.yh;
        for x in (0..w).step_by(2) {
            let u = (x as f32 + 1.0) / span;
            let val = if row_v < 0.0 {
                let s = -row_v / c.yh; // 0 at horizon, 1 at top
                let glow = 0.095 * (1.0 - s).powi(3) + 0.012;
                let cl = vnoise(
                    seed ^ 11,
                    u as f64 * 2.2 + cloud.0,
                    s as f64 * 5.0 + cloud.1,
                );
                // distant tree line: darker than the sky haze
                let tl = 0.010
                    + 0.026 * vnoise(seed ^ 3, u as f64 * 9.0, 0.5)
                    + 0.012 * vnoise(seed ^ 4, u as f64 * 31.0, 0.5);
                let tree = smooth(-0.002, 0.003, tl * c.yh * 0.9 - (-row_v));
                glow * (1.0 - 0.8 * tree) * (0.75 + 0.5 * cl) + 0.022 * tree
            } else {
                let rv = row_v.max(0.0008);
                let d = c.k / rv;
                let wx = (u - c.cx) as f64 * d as f64 / c.k as f64 + c.x;
                let wz = zoff + d as f64;
                let fz = d * d / (c.k * span); // world z footprint of a pixel
                let ax = 1.0 - smooth(0.04, 0.16, d / (c.k * span) * 22.0);
                let az = 1.0 - smooth(0.2, 1.2, fz * 9.0);
                let n = vnoise(seed ^ 21, wx * 22.0, wz * 9.0) * 0.6
                    + vnoise(seed ^ 22, wx * 7.0, wz * 3.0) * 0.4;
                let tex = 1.0 + (n - 0.5) * 1.1 * ax.max(0.0) * az.max(0.0);
                let base = 0.030 + 0.105 * smooth(1.5, 14.0, d) * (1.0 - 0.0 * d);
                let haze = 0.05 * (1.0 - smooth(0.0, 0.5, rv / c.yh * 4.0));
                (base + haze) * tex
            };
            let val = val.clamp(0.0, 1.0);
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                if x + dx < w && y + dy < h {
                    l.field[(y + dy) * w + x + dx] = val;
                }
            }
        }
    }
}

fn band(l: &mut Live, c: &Cam, b: usize, p: &mut Path) {
    let sc = (1u32 << b) as f32;
    let cell = (C0 * sc) as f64;
    let (lo, hi) = (Z0 * sc, Z0 * sc * 2.0);
    let (dmin, dmax) = (if b == 0 { 0.2 } else { lo / 1.14 }, hi * 1.14);
    let hgt = 0.125 * sc.sqrt();
    let row_hi = ((c.z + dmax as f64) / cell).floor() as i64;
    let row_lo = ((c.z + dmin as f64) / cell).floor() as i64;
    let bandseed = l.seed ^ (b as u32 * 0x9E37);
    let t = l.time;
    for row in (row_lo..=row_hi).rev() {
        let rowu = row as u32;
        let dc = ((row as f64 + 0.5) * cell - c.z) as f32;
        let halfw = (l.aw * 0.5 + hgt * 0.5) * dc.max(0.1) / c.k + 0.3 * sc;
        let (c_lo, c_hi) = (
            ((c.x - halfw as f64) / cell).floor() as i64,
            ((c.x + halfw as f64) / cell).ceil() as i64,
        );
        for col in c_lo..=c_hi {
            let colu = col as u32;
            let h0 = hash(bandseed, rowu, colu);
            let jx = rand01(h0, 1, 0);
            let jz = rand01(h0, 2, 0);
            let wx = (col as f64 + jx as f64) * cell;
            let wz = (row as f64 + jz as f64) * cell;
            let d = (wz - c.z) as f32;
            if d < dmin * 0.9 || d > dmax {
                continue;
            }
            let wgt = (if b == 0 {
                1.0
            } else {
                smooth(lo / 1.14, lo, d)
            }) * (1.0 - smooth(hi, hi * 1.14, d));
            if wgt <= 0.01 {
                continue;
            }
            let fog = 1.0 - 0.45 * smooth(2.0, 18.0, d);
            let s = c.k / d;
            let sx = c.cx + (wx - c.x) as f32 * s;
            let sy = c.yh + s * c.hb;
            let ph = ((t * 1.25 + wx * 0.8 + wz * 0.5).rem_euclid(std::f64::consts::TAU)) as f32;
            let sway = ph.sin() * 0.7 + (ph * 2.3 + 1.0).sin() * 0.3;
            for tuft in 0..(if b < 1 { 2u32 } else { 1 }) {
                let th = hash(h0, 10 + tuft, 0);
                let tx = sx + (rand01(th, 0, 0) - 0.5) * (cell as f32 * s) * 1.2;
                let ty = sy + (rand01(th, 1, 0) - 0.5) * (cell as f32 * s) * 0.7;
                let blades = 3 + (th >> 28) as u32 % 3;
                p.clear();
                for k in 0..blades {
                    let bh = hash(th, k, 5);
                    let r = |i| rand01(bh, i, 9);
                    let height = hgt * (0.55 + 0.7 * r(0)) * s;
                    let bw = ((0.0055 + 0.003 * r(1)) * sc.sqrt() * s).max(1.4 / l.span);
                    let bx = tx + (r(2) - 0.5) * cell as f32 * s * 0.5;
                    let lean = (r(3) - 0.5) * 0.55 + sway * 0.22;
                    let tipx = bx + lean * height;
                    let tipy = ty - height * (1.0 - 0.15 * lean.abs());
                    let (c1x, c1y) = (bx + lean * height * 0.15, ty - height * 0.62);
                    
                    p.move_to(bx - bw, ty);
                    p.quad_to(c1x - bw * 0.5, c1y, tipx, tipy);
                    p.quad_to(c1x + bw * 0.5, c1y, bx + bw, ty);
                    p.close();
                    let _ = r(4);
                    if k + 1 == blades { l.canvas.path(p, &fill((55.0 + 60.0 * rand01(th, 3, 3)) * wgt * fog)); }
                }
            }
            // Flowers: sparse, brighter, above the grass.
            let fh = hash(h0, 77, 3);
            if rand01(fh, 0, 0) < 0.09 {
                let rr = |i| rand01(fh, i, 4);
                let wr = 0.075 * sc.powf(0.3) * (0.75 + 0.6 * rr(1));
                let stem = hgt * (2.2 + 1.3 * rr(2));
                let lean = (rr(3) - 0.5) * 0.25 + sway * 0.1;
                let hx = sx + lean * stem * s;
                let hy = sy - stem * s;
                let rad = wr * s;
                let kind = (fh >> 20) % 100;
                let kind = if kind < 36 {
                    0
                } else if kind < 62 {
                    1
                } else if kind < 78 {
                    2
                } else {
                    3
                };
                let a = wgt * fog.max(0.7);
                // stem + leaves
                p.clear();
                p.move_to(sx, sy);
                p.quad_to(sx + lean * stem * s * 0.1, sy - stem * s * 0.55, hx, hy);
                l.canvas.path(
                    p,
                    &stroke(95.0 * a, (0.0075 * s * sc.sqrt()).max(1.3 / l.span), false),
                );
                if rad > 0.008 {
                    for side in [-1.0f32, 1.0] {
                        let (lx, ly) = (
                            sx + lean * stem * s * 0.2 + side * rad * 0.9,
                            sy - stem * s * 0.28,
                        );
                        p.clear();
                        oval(p, lx, ly - rad * 0.5, rad * 0.75, rad * 0.16, side * -60.0);
                        l.canvas.path(p, &fill(85.0 * a));
                    }
                }
                flower(
                    l,
                    p,
                    kind,
                    hx,
                    hy,
                    rad,
                    0.62 + 0.3 * rr(5),
                    rr(6) * TAU,
                    a,
                    fh,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn flower(
    l: &mut Live,
    p: &mut Path,
    kind: u32,
    x: f32,
    y: f32,
    r: f32,
    q: f32,
    rot: f32,
    a: f32,
    h: u32,
) {
    let cv = &mut l.canvas;
    let detail = r > 0.011;
    if r < 0.0035 {
        cv.circle(x, y, r.max(0.0014), &fill(215.0 * a));
        return;
    }
    cv.save();
    cv.translate(x, y);
    if kind == 3 {
        cv.rotate(((rand01(h, 8, 8) - 0.5) * 0.7).to_degrees());
    } else {
        cv.scale(1.0, q);
        cv.rotate((rot).to_degrees());
        // halo: cut the grass behind the head so it reads
        cv.circle(0.0, 0.0, r * 1.3, &erase(150.0 * a));
    }
    match kind {
        0 => {
            let n = 9 + (h >> 3) % 5;
            for i in 0..n {
                let ang = i as f32 / n as f32 * TAU + (rand01(h, 20 + i, 1) - 0.5) * 0.12;
                let len = r * (0.88 + 0.2 * rand01(h, 40 + i, 2));
                cv.save();
                cv.rotate((ang).to_degrees());
                p.clear();
                p.move_to(r * 0.22, 0.0);
                p.cubic_to(r * 0.45, -r * 0.2, len * 0.72, -r * 0.2, len, 0.0);
                p.cubic_to(len * 0.72, r * 0.2, r * 0.45, r * 0.2, r * 0.22, 0.0);
                p.close();
                cv.path(p, &fill((200.0 + 35.0 * rand01(h, 60 + i, 3)) * a));
                if detail {
                    cv.line(
                        r * 0.4,
                        0.0,
                        len * 0.88,
                        0.0,
                        &stroke(110.0 * a, r * 0.035, true),
                    );
                }
                cv.restore();
            }
            cv.circle(0.0, 0.0, r * 0.3, &erase(255.0));
            cv.circle(0.0, 0.0, r * 0.26, &fill(190.0 * a));
            if detail {
                for i in 0..14 {
                    let rad = r * 0.24 * ((i as f32 + 0.5) / 14.0).sqrt();
                    let an = i as f32 * 2.399;
                    cv.circle(rad * an.cos(), rad * an.sin(), r * 0.03, &erase(200.0));
                }
                cv.circle(0.0, 0.0, r * 0.27, &stroke(130.0 * a, r * 0.04, false));
            }
        }
        1 => {
            for i in 0..5 {
                let ang = i as f32 / 5.0 * TAU;
                cv.save();
                cv.rotate((ang).to_degrees());
                p.clear();
                oval(p, r * 0.52, 0.0, r * 0.5, r * 0.36, 0.0);
                cv.path(p, &fill(200.0 * a));
                if detail {
                    cv.line(
                        r * 0.3,
                        0.0,
                        r * 0.88,
                        0.0,
                        &stroke(100.0 * a, r * 0.04, true),
                    );
                    cv.line(
                        r * 0.98,
                        -r * 0.05,
                        r * 0.98,
                        r * 0.05,
                        &stroke(120.0 * a, r * 0.05, true),
                    );
                }
                cv.restore();
            }
            cv.circle(0.0, 0.0, r * 0.2, &erase(255.0));
            cv.circle(0.0, 0.0, r * 0.14, &fill(235.0 * a));
            if detail {
                for i in 0..6 {
                    let an = i as f32 / 6.0 * TAU + 0.3;
                    cv.circle(
                        r * 0.27 * an.cos(),
                        r * 0.27 * an.sin(),
                        r * 0.05,
                        &fill(235.0 * a),
                    );
                }
            }
        }
        2 => {
            // clover head: rings of small florets
            for (ring, count, rad) in [(0u32, 9u32, 0.62f32), (1, 6, 0.36), (2, 1, 0.0)] {
                for i in 0..count {
                    let an = i as f32 / count as f32 * TAU + ring as f32 * 0.5;
                    cv.save();
                    cv.translate(rad * r * an.cos(), rad * r * an.sin());
                    cv.rotate((an).to_degrees());
                    p.clear();
                    oval(p, 0.0, 0.0, r * 0.32, r * 0.2, 0.0);
                    cv.path(p, &fill((185.0 + 30.0 * ring as f32) * a));
                    if detail {
                        cv.circle(-r * 0.12, 0.0, r * 0.04, &erase(170.0));
                    }
                    cv.restore();
                }
            }
        }
        _ => {
            for (i, (bx, by, sz)) in [(0.0f32, 0.0f32, 1.0f32), (r * 1.1, r * 0.5, 0.78)]
                .into_iter()
                .enumerate()
            {
                let w = r * sz;
                cv.save();
                cv.translate(bx, by);
                cv.rotate((i as f32 * 0.4).to_degrees());
                p.clear();
                p.move_to(-w * 0.2, 0.0);
                p.cubic_to(-w * 0.25, w * 0.7, -w * 0.45, w * 1.1, -w * 0.8, w * 1.55);
                p.quad_to(-w * 0.62, w * 1.95, -w * 0.3, w * 1.68);
                p.quad_to(0.0, w * 2.0, w * 0.3, w * 1.68);
                p.quad_to(w * 0.62, w * 1.95, w * 0.8, w * 1.55);
                p.cubic_to(w * 0.45, w * 1.1, w * 0.25, w * 0.7, w * 0.2, 0.0);
                p.close();
                cv.path(p, &fill(205.0 * a));
                if detail {
                    for s in [-0.3f32, 0.3] {
                        cv.line(
                            s * w * 0.55,
                            w * 0.35,
                            s * w * 1.0,
                            w * 1.5,
                            &stroke(100.0 * a, w * 0.04, true),
                        );
                    }
                    p.clear();
                    oval(p, 0.0, w * 1.6, w * 0.55, w * 0.14, 0.0);
                    cv.path(p, &erase(120.0 * a));
                }
                cv.restore();
            }
        }
    }
    cv.restore();
}
