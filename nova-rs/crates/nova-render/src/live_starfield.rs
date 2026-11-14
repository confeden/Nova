//! Calm deep-space flight: ~5000 stars at 3D depths drift toward the viewer (perspective, parallax,
//! far ones fade in from nothing, near ones fade out), faint asymmetric milky-way haze, a few dim glints.
use crate::live::{rand01, Live};
use crate::texture_math::{fbm01, smooth, Seed};

const STARS: u32 = 7000;
const CYCLE: f64 = 120.0; // seconds for one star to fly from far to near
const ZF: f32 = 1.0;
const ZN: f32 = 0.16;

fn haze(l: &mut Live) {
    let seed = Seed(l.seed as i32);
    let tau = std::f64::consts::TAU;
    let ph = |period: f64| (l.time / period).rem_euclid(1.0) * tau;
    let (a1, a2, a3, a4) = (
        ph(517.0).sin() as f32,
        ph(311.0).cos() as f32,
        ph(433.0).sin() as f32,
        ph(683.0).cos() as f32,
    );
    let cell = 8usize;
    let (gw, gh) = (l.width / cell + 2, l.height / cell + 2);
    let mut grid = vec![0.0f32; gw * gh];
    let (ca, sa) = (0.42f32.cos(), 0.42f32.sin());
    for gy in 0..gh {
        for gx in 0..gw {
            let u = gx as f32 * cell as f32 / l.span;
            let v = gy as f32 * cell as f32 / l.span;
            // far layer: broad slow clouds; near layer: finer, drifts a bit more (parallax)
            let (ru, rv) = (u * ca + v * sa, -u * sa + v * ca);
            let n1 = fbm01(ru * 0.55 + 1.6 * a1 + 0.8 * a2, rv * 1.1 + 1.2 * a3, 4, seed);
            let n2 = fbm01(
                u * 1.9 + 2.4 * a2 + 5.0,
                v * 1.9 + 1.8 * a4 - 3.0,
                3,
                seed + 77,
            );
            // tilted soft band (milky way), off-centre and asymmetric
            let (cu, cv) = (u - l.aw * 0.55, v - l.ah * 0.42);
            let d = cu * -sa + cv * ca;
            let band = (-(d * d) / 0.11).exp();
            let a = smooth(0.38, 0.78, n1);
            let b = smooth(0.42, 0.85, n2);
            grid[gy * gw + gx] =
                0.03 + band * (0.12 * a + 0.07 * a * b) + 0.03 * a * a + 0.02 * b;
        }
    }
    let w = l.width;
    for y in 0..l.height {
        let fy = y as f32 / cell as f32;
        let (gy, ty) = (fy as usize, fy.fract());
        for x in 0..w {
            let fx = x as f32 / cell as f32;
            let (gx, tx) = (fx as usize, fx.fract());
            let i = gy * gw + gx;
            let top = grid[i] + (grid[i + 1] - grid[i]) * tx;
            let bot = grid[i + gw] + (grid[i + gw + 1] - grid[i + gw]) * tx;
            l.field[y * w + x] = top + (bot - top) * ty;
        }
    }
}

fn splat(l: &mut Live, px: f32, py: f32, sigma: f32, peak: f32) {
    let r = (sigma * 2.6).ceil().max(1.0) as i32;
    let (cx, cy) = (px.floor() as i32, py.floor() as i32);
    let k = -0.5 / (sigma * sigma);
    for y in cy - r..=cy + r {
        if y < 0 || y >= l.height as i32 {
            continue;
        }
        for x in cx - r..=cx + r {
            if x < 0 || x >= l.width as i32 {
                continue;
            }
            let (dx, dy) = (x as f32 + 0.5 - px, y as f32 + 0.5 - py);
            let v = peak * (k * (dx * dx + dy * dy)).exp();
            let f = &mut l.field[y as usize * l.width + x as usize];
            *f = (*f + v).min(1.0);
        }
    }
}

fn glint(l: &mut Live, px: f32, py: f32, len: f32, peak: f32) {
    let n = len.ceil() as i32;
    for s in 1..=n {
        let a = peak * (1.0 - s as f32 / (len + 1.0)).powi(2);
        for (dx, dy) in [(s, 0), (-s, 0), (0, s), (0, -s)] {
            let (x, y) = (px.floor() as i32 + dx, py.floor() as i32 + dy);
            if x >= 0 && y >= 0 && x < l.width as i32 && y < l.height as i32 {
                let f = &mut l.field[y as usize * l.width + x as usize];
                *f = (*f + a).min(1.0);
            }
        }
    }
}

pub(crate) fn render(l: &mut Live) {
    haze(l);
    let seed = l.seed;
    let tau = std::f64::consts::TAU;
    // vanishing point sways slowly, off-centre
    let ph = |p: f64| (l.time / p).rem_euclid(1.0) * tau;
    let vx = l.aw * 0.46 + 0.07 * (ph(397.0).sin() as f32) + 0.03 * (ph(151.0).cos() as f32);
    let vy = l.ah * 0.54 + 0.05 * (ph(443.0).cos() as f32) + 0.03 * (ph(173.0).sin() as f32);
    let (ex, ey) = (l.aw * 0.5 + 0.25, l.ah * 0.5 + 0.25);
    let tcyc = l.time / CYCLE;
    let span = l.span;
    for i in 0..STARS {
        let p = rand01(seed, i * 8, 0) as f64;
        let c = tcyc + p;
        let n = c.floor();
        let f = (c - n) as f32;
        let n = (n as u64 & 0xFFFF_FFFF) as u32;
        let z = ZF - (ZF - ZN) * f;
        let sx = (rand01(seed, i * 8 + 1, n) * 2.0 - 1.0) * ex;
        let sy = (rand01(seed, i * 8 + 2, n) * 2.0 - 1.0) * ey;
        let (px, py) = ((vx + sx / z) * span, (vy + sy / z) * span);
        let m = 12.0;
        if px < -m || py < -m || px > l.width as f32 + m || py > l.height as f32 + m {
            continue;
        }
        let u = rand01(seed, i * 8 + 3, n);
        let tw_f = 0.4 + 1.6 * rand01(seed, i * 8 + 4, n);
        let tw_p = rand01(seed, i * 8 + 5, n);
        let tw = 1.0
            + 0.09
                * (((l.time * tw_f as f64 * 0.5 + tw_p as f64 * 50.0).rem_euclid(1.0) * tau).sin()
                    as f32);
        let fade = smooth(0.0, 0.14, f) * (1.0 - smooth(0.80, 1.0, f));
        let near = 1.0 / z;
        let base = 0.07 + 0.8 * u.powi(11);
        let b = base * near.powf(0.55) * tw * fade;
        let sigma = 0.62 + 0.10 * (near - 1.0).min(4.0) + 0.25 * u.powi(14);
        let peak = b * 0.75 / (sigma * sigma + 0.1);
        splat(l, px, py, sigma, peak.min(0.95));
        if u > 0.99 && fade > 0.01 {
            let len = 3.0 + 2.5 * near.min(3.0);
            glint(l, px, py, len, 0.28 * b);
        }
    }
}
