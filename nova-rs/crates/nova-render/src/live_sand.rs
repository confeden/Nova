//! Live sand: a calm low flight over an endless dune desert. Perspective ground plane scrolled by
//! time; asymmetric dunes (gentle back, steep lit slip face, crisp crest) and forking sharp-crested
//! ripples, both with analytic slopes smoothed by screen-space period (no aliasing); fine grain
//! and sparkles; fogged dim horizon; low drifting dust dots and puffs.
use crate::live::{rand01, Live};
use crate::texture_canvas::Brush;

/// World Z period of the scroll (all noise/ripple frequencies tile it exactly).
const PERIOD: f64 = 3584.0;
const SPEED: f64 = 0.65;
const HAZE: f32 = 0.028;

fn lat(seed: u32, i: i32, j: i32) -> f32 {
    let h = crate::live::hash(seed, (i & 255) as u32, (j & 255) as u32);
    (h >> 8) as f32 / 8_388_608.0 - 1.0
}

/// Value noise in -1..1 with analytic gradient (quintic fade): (v, dv/dx, dv/dz).
fn vn(seed: u32, x: f32, z: f32) -> (f32, f32, f32) {
    let (xi, zi) = (x.floor(), z.floor());
    let (fx, fz) = (x - xi, z - zi);
    let (i, j) = (xi as i32, zi as i32);
    let q = |t: f32| t * t * t * (t * (t * 6.0 - 15.0) + 10.0);
    let dq = |t: f32| 30.0 * t * t * (t - 1.0) * (t - 1.0);
    let (a, b, c, d) = (
        lat(seed, i, j),
        lat(seed, i + 1, j),
        lat(seed, i, j + 1),
        lat(seed, i + 1, j + 1),
    );
    let (ux, uz, dux, duz) = (q(fx), q(fz), dq(fx), dq(fz));
    let k1 = b - a;
    let k2 = c - a;
    let k3 = a - b - c + d;
    (
        a + k1 * ux + k2 * uz + k3 * ux * uz,
        (k1 + k3 * uz) * dux,
        (k2 + k3 * ux) * duz,
    )
}

fn fade(lo: f32, hi: f32, x: f32) -> f32 {
    let t = ((x - lo) / (hi - lo)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn fh(a: i32, b: i32, s: u32) -> u32 {
    let mut h = s ^ (a as u32).wrapping_mul(0x9E37_79B1) ^ (b as u32).wrapping_mul(0x85EB_CA77);
    h ^= h >> 15;
    h = h.wrapping_mul(0x2C1B_3C6D);
    h ^= h >> 12;
    h = h.wrapping_mul(0x297A_2D39);
    h ^ (h >> 15)
}

/// Slope profile of an asymmetric saw (period 1): gentle back -1 over 0..0.7, steep face +2.33
/// over 0.7..1 ending in a crest at the wrap. Edges are smoothed by `w` (phase units).
fn saw(f: f32, w: f32) -> f32 {
    let up = fade(0.6, 0.92, f) * (1.0 - fade(1.0 - w, 1.0, f));
    -0.9 + 0.5 * f + 3.4 * up
}

pub(crate) fn render(l: &mut Live) {
    let (w, h) = (l.width, l.height);
    let span = l.span;
    let seed = l.seed;
    let (s1, s2, s4) = (seed, seed ^ 0x1234_5679, seed ^ 0x51ED_270B);
    let off = (l.time * SPEED).rem_euclid(PERIOD) as f32;
    let horizon = l.ah * 0.18;
    let cx = l.aw * 0.5;
    let (lx, ly, lz) = (-0.5f32, 0.62, -0.6);
    let ln = (lx * lx + ly * ly + lz * lz).sqrt();
    let (lx, ly, lz) = (lx / ln, ly / ln, lz / ln);
    let flat = ly;
    let inv = 1.0 / span;
    let tau = std::f32::consts::TAU;
    let k = tau / 0.125;
    for y in 0..h {
        let v = (y as f32 + 0.5) * inv;
        let row = &mut l.field[y * w..(y + 1) * w];
        let d = v - horizon;
        if d <= 0.0 {
            let t = (-d / horizon).min(1.0);
            row.fill(HAZE * (1.0 - 0.45 * t) + 0.004 * t * t);
            continue;
        }
        let z = 1.0 / d.max(1e-3);
        let zw = z + off;
        let fog = (-(z / 13.0).powf(1.35)).exp();
        let fog2 = fog * fog;
        if fog2 < 0.01 {
            row.fill(HAZE);
            continue;
        }
        let ppz = d * d * span; // px per world-Z unit
        let wd = (0.8 / (2.0 * ppz)).clamp(0.012, 0.25);
        let fdune = fade(1.5, 6.0, 2.0 * ppz);
        let g_fine = fade(0.9, 1.8, 0.004 * ppz);
        let g_coarse = fade(0.9, 1.8, 0.012 * ppz) * (1.0 - 0.6 * g_fine);
        let g_spark = fade(1.2, 2.5, 0.016 * ppz) * fog2;
        let zc_f = (zw / 0.004).floor() as i32;
        let zc_c = (zw / 0.012).floor() as i32;
        let zs = zw / 0.016;
        let zc_s = zs.floor();
        let zs_frac = zs - zc_s;
        let zc_s = zc_s as i32;
        for (x, px) in row.iter_mut().enumerate() {
            let u = (x as f32 + 0.5) * inv;
            let xw = (u - cx) * z;
            let (wv, wx, wz) = vn(s2, xw * 0.11, zw * (1.0 / 7.0));
            let (am, _, _) = vn(s1, xw * 0.22, zw * (1.0 / 7.0));
            let q = zw * 0.5 + 0.8 * wv;
            let dqz = 0.5 + 0.8 * wz * (1.0 / 7.0);
            let dqx = 0.11 * 0.8 * wx;
            let f = q - q.floor();
            let amp = 0.8 * (0.75 + 0.45 * wv + 0.35 * am) * fdune;
            let gd = saw(f, wd) * amp;
            let hz = gd * dqz;
            let hx = gd * dqx;
            // sharp irregular forking ripples: level sets of a strongly warped phase
            let (rn, rnx, rnz) = vn(s4, xw * 0.35, zw * (3.0 / 7.0));
            let phase = k * zw + 26.0 * rn + 5.0 * q;
            let pzt = k + 26.0 * rnz * (3.0 / 7.0) + 5.0 * dqz;
            let pxt = 26.0 * rnx * 0.35 + 5.0 * dqx;
            let pf = phase * (1.0 / tau);
            let rf = pf - pf.floor();
            let per_px = tau / pzt.abs().max(0.5) * ppz;
            let fr = fade(2.0, 6.0, per_px);
            let wr = (0.8 / per_px.max(1.0)).clamp(0.02, 0.25);
            let rs = saw(rf, wr) * 0.035 * fr * (0.55 + 0.45 * rn.abs().min(1.0));
            let rz = rs * pzt / tau;
            let rx = rs * pxt / tau;
            let gx = -(hx + rx);
            let gz = -(hz + rz);
            let dif = (gx * lx + ly + gz * lz) / (gx * gx + 1.0 + gz * gz).sqrt();
            let t = 3.0 * (dif - flat);
            let mut a = 0.2 * (1.0 + t + 0.5 * t * t).max(0.1);
            // fine and coarse grain
            let n1 = (fh((xw / 0.004).floor() as i32, zc_f, s1) >> 9) as f32 / 8_388_608.0 - 0.5;
            let n2 = (fh((xw / 0.012).floor() as i32, zc_c, s1 ^ 7) >> 9) as f32 / 8_388_608.0 - 0.5;
            a *= 1.0 + 0.4 * (n1 * g_fine + n2 * g_coarse);
            // rare sparkles of single grains
            let xs = xw / 0.008;
            let xs_c = xs.floor();
            let sh = fh(xs_c as i32, zc_s, s1 ^ 99);
            if sh & 63 == 0 && g_spark > 0.0 {
                let (fx, fz) = (xs - xs_c - 0.5, zs_frac - 0.5);
                let r2 = (fx * fx + fz * fz) * 4.0;
                if r2 < 1.0 {
                    let tw = 0.6 + 0.4 * ((sh >> 8) & 255) as f32 / 255.0;
                    a += 0.30 * (1.0 - r2) * (1.0 - r2) * tw * g_spark;
                }
            }
            *px = HAZE + (a.clamp(0.0, 0.5) - HAZE) * fog2;
        }
    }
    dust(l);
}

/// Low drifting grains (dots with a tiny trail) and a few soft puffs hugging the ground.
fn dust(l: &mut Live) {
    const N: u32 = 260;
    const P: f64 = 14.0;
    let horizon = l.ah * 0.18;
    let cx = l.aw * 0.5;
    let t = l.time;
    let px = 1.0 / l.span;
    for i in 0..N {
        let r = |k: u32| rand01(l.seed, i, 900 + k);
        let sp = SPEED + 0.25 * r(1) as f64;
        let z = ((r(0) as f64 * P) - t * sp).rem_euclid(P) as f32 + 0.35;
        let x0 = (r(2) - 0.5) * 24.0 + 0.8 * (t * 0.1).sin() as f32;
        let hgt = 0.01 + 0.16 * r(3) * r(3);
        let proj = |zz: f32| (cx + (x0 - 0.5 * (zz - z)) / zz, horizon + (1.0 - hgt) / zz);
        let (sx, sy) = proj(z);
        if sy <= horizon + 0.004 || sy > l.ah + 0.05 || sx < -0.05 || sx > l.aw + 0.05 {
            continue;
        }
        let env = fade(0.35, 1.6, z) * (1.0 - fade(7.0, 13.0, z));
        let depth = 1.0 / (1.0 + z * 0.3);
        let a = (200.0 * env * (0.3 + 0.7 * depth) * (0.4 + 0.6 * r(4))) as i32;
        if a < 6 {
            continue;
        }
        let rad = (0.55 + 0.9 * r(5)) * px * (0.8 + 0.5 * depth);
        let (ex, ey) = proj(z + 0.025 + 0.03 * r(6));
        let b = Brush {
            alpha: a,
            width: rad * 2.0,
            stroke: true,
            round_cap: true,
            round_join: true,
            erase: false,
            gradient: None,
        };
        l.canvas.line(ex, ey, sx, sy, &b);
        if r(7) < 0.18 {
            let soft = Brush { alpha: a / 6 + 2, width: 0.004 + 0.008 * r(8), stroke: true, round_cap: true, round_join: true, ..Default::default() };
            let (wx, wy) = proj(z + 0.25 + 0.4 * r(9));
            l.canvas.line(wx, wy, sx, sy, &soft);
        }
    }
}
