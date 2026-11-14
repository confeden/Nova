//! Live morphing Julia set: c = λ/2 − λ²/4 with multiplier λ = r·e^{iθ} riding a seed-chosen loop along the
//! main cardioid's rim, so the shape itself keeps transforming while the camera breathes in toward the α point.
use crate::android::palette;
use crate::live::rand01;
use crate::texture_math::smooth;
use std::f64::consts::{PI, TAU};

/// Phase in turns of a periodic motion, reduced in f64 so t = 1e9 is as smooth as t = 10.
fn turn(time: f64, period: f64, offset: f64) -> f64 {
    ((time / period).rem_euclid(1.0) + offset) * TAU
}

struct View {
    cr: f64,
    ci: f64,
    /// Complex-plane point at the frame centre, half the short side, rotation.
    center: [f64; 2],
    half: f64,
    cos: f64,
    sin: f64,
}

fn view(seed: u32, time: f64) -> View {
    let r = |k: u32| rand01(seed, k, 7) as f64;
    let dir = if r(1) < 0.5 { -1.0 } else { 1.0 };
    // θ walks the whole rim (one loop in 5-9 min) with a slow wobble. |λ| rides just outside the cardioid
    // AND over every p/q bulb (radius ≈ 1/q² in λ), so c stays outside the Mandelbrot set: J_c is a
    // fully escaping spiral/dendrite dust with no flat interior, morphing as c slides along the rim.
    let loop_period = 480.0 + 240.0 * r(2);
    let theta =
        turn(time, loop_period, r(3)) * dir + 0.12 * turn(time, 71.0 + 30.0 * r(4), r(5)).sin();
    let margin = 0.055
        + 0.015 * turn(time, 61.0 + 20.0 * r(6), r(7)).sin()
        + 0.005 * turn(time, 41.0 + 15.0 * r(8), r(9)).sin();
    let radius = 1.0 + margin + bulb_lift(theta);
    let (lr, li) = (radius * theta.cos(), radius * theta.sin());
    // λ cannot leave M near the cusp (c = 1/4 is a critical value), so slide c right there in c-space.
    let cusp = ((theta + PI).rem_euclid(TAU) - PI) / 0.6;
    let cusp = if cusp.abs() < 1.0 {
        0.06 * (1.0 - cusp * cusp).powi(2)
    } else {
        0.0
    };
    let cr = 0.5 * lr - 0.25 * (lr * lr - li * li) + cusp;
    let ci = 0.5 * li - 0.5 * lr * li;
    // α = λ/2 is the repelling/indifferent fixed point at the heart of the spirals; zoom breathes toward it.
    let breathe = 0.5 - 0.5 * turn(time, 64.0 + 40.0 * r(10), r(11)).cos();
    let depth = breathe * breathe * (3.0 - 2.0 * breathe);
    let half = 0.95 * (-(1.0 + 0.4 * r(12)) * depth).exp();
    let pull = 0.4 * depth;
    let center = [0.5 * lr * pull, 0.5 * li * pull];
    let angle = turn(time, 420.0 + 300.0 * r(13), r(14)) * if r(15) < 0.5 { -1.0 } else { 1.0 };
    View {
        cr,
        ci,
        center,
        half,
        cos: angle.cos(),
        sin: angle.sin(),
    }
}

/// Radial lift in the multiplier plane that clears the p/q bulbs tangent to |λ| = 1 (q ≤ 12).
fn bulb_lift(theta: f64) -> f64 {
    let mut lift = 0.0_f64;
    for q in 2..=12_u32 {
        let rho = 1.0 / (q * q) as f64;
        let width = 2.6 * rho;
        for p in 1..q {
            if (2..=p).any(|d| p % d == 0 && q % d == 0) {
                continue;
            }
            let delta = (theta - TAU * p as f64 / q as f64 + PI).rem_euclid(TAU) - PI;
            if delta.abs() < width {
                lift = lift.max(2.3 * rho * (1.0 - (delta / width).powi(2)).powi(2));
            }
        }
    }
    lift
}

/// Smooth-escape colour of z0 under z² + c with distance-estimate anti-aliasing over `footprint`.
fn julia_color(mut zr: f64, mut zi: f64, cr: f64, ci: f64, limit: u32, footprint: f64) -> [f64; 3] {
    let inside = palette(-1.5);
    let (mut dr, mut di) = (1.0_f64, 0.0_f64);
    let (mut sr, mut si, mut next_save) = (zr, zi, 8_u32);
    for n in 0..limit {
        let (rr, ii) = (zr * zr, zi * zi);
        if rr + ii > 1e4 {
            let modulus = (rr + ii).sqrt();
            let nu = (n as f64 + 1.0 - modulus.ln().ln() / 2.0_f64.ln()) as f32;
            let distance = 0.5 * modulus.ln() * modulus / dr.hypot(di).max(1e-300);
            let coverage = smooth(0.0, 0.8, (distance / footprint) as f32) as f64;
            let color = palette(2.4 * nu + 8.0);
            return std::array::from_fn(|c| inside[c] + (color[c] - inside[c]) * coverage);
        }
        let next_dr = 2.0 * (zr * dr - zi * di);
        di = 2.0 * (zr * di + zi * dr);
        dr = next_dr;
        zi = 2.0 * zr * zi + ci;
        zr = rr - ii + cr;
        // Brent-style periodicity check: an orbit settling on an attracting cycle is interior.
        if (zr - sr).abs() + (zi - si).abs() < 1e-7 {
            return inside;
        }
        if n == next_save {
            (sr, si, next_save) = (zr, zi, next_save * 2);
        }
    }
    inside
}

pub(crate) fn render(
    width: usize,
    height: usize,
    seed: u32,
    time: f64,
) -> Result<Vec<u8>, &'static str> {
    if width < 2 || height < 2 {
        return Err("fractal frame too small");
    }
    let v = view(seed, time);
    let short = width.min(height) as f64;
    let (ax, ay) = (width as f64 / short, height as f64 / short);
    // Compute on a coarser grid, then upsample bilinearly (the app blurs the layer slightly anyway).
    let longest = 300.min(width.max(height));
    let (gw, gh) = (
        (longest * width / width.max(height)).max(2),
        (longest * height / width.max(height)).max(2),
    );
    let footprint = (2.0 * v.half * ax / (gw - 1) as f64).max(2.0 * v.half * ay / (gh - 1) as f64);
    let limit = 220;
    let mut grid = vec![[0.0; 3]; gw * gh];
    for gy in 0..gh {
        let py = (gy as f64 / (gh - 1) as f64 - 0.5) * 2.0 * v.half * ay;
        for gx in 0..gw {
            let px = (gx as f64 / (gw - 1) as f64 - 0.5) * 2.0 * v.half * ax;
            let zr = v.center[0] + px * v.cos - py * v.sin;
            let zi = v.center[1] + px * v.sin + py * v.cos;
            grid[gy * gw + gx] = julia_color(zr, zi, v.cr, v.ci, limit, footprint);
        }
    }
    // Gentle exposure control keeps the layer at a steady brightness whether J is sparse dust or dense.
    let mean = grid.iter().map(|p| p[0] + p[1] + p[2]).sum::<f64>() / (3 * grid.len()) as f64;
    let gain = (0.23 / mean.max(1e-3)).clamp(0.8, 1.6);
    let mut pixels = vec![0; width * height * 3];
    for y in 0..height {
        let gy = y as f64 * (gh - 1) as f64 / (height - 1) as f64;
        let iy = (gy as usize).min(gh - 2);
        let fy = gy - iy as f64;
        let (row0, row1) = (
            &grid[iy * gw..(iy + 1) * gw],
            &grid[(iy + 1) * gw..(iy + 2) * gw],
        );
        for x in 0..width {
            let gx = x as f64 * (gw - 1) as f64 / (width - 1) as f64;
            let ix = (gx as usize).min(gw - 2);
            let fx = gx - ix as f64;
            let w = [
                (1.0 - fx) * (1.0 - fy),
                fx * (1.0 - fy),
                (1.0 - fx) * fy,
                fx * fy,
            ];
            let s = [row0[ix], row0[ix + 1], row1[ix], row1[ix + 1]];
            for c in 0..3 {
                let value = s[0][c] * w[0] + s[1][c] * w[1] + s[2][c] * w[2] + s[3][c] * w[3];
                pixels[(y * width + x) * 3 + c] =
                    (value * gain * 255.0).clamp(0.0, 255.0).round() as u8;
            }
        }
    }
    Ok(pixels)
}
