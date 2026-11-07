//! Android's warped Milky Way, logarithmic spiral galaxies, dust and diffraction spikes.
use crate::android::KotlinRandom;
use crate::texture_canvas::{Brush, Canvas, Path};
use crate::texture_math::*;
use crate::textures::Sheet;
fn halo() -> Vec<(f32, u8)> {
    vec![(0.0, 255), (1.0, 0)]
}
fn band(u: f32, v: f32, ca: f32, sa: f32, offset: f32, seed: Seed) -> f32 {
    let along = u * ca + v * sa;
    let across = -u * sa + v * ca - offset;
    let bend = 0.16 * fbm(along * 1.2, 0.7, 3, seed + 3);
    1.0 - smooth(0.03, 0.36, abs(across + bend))
}
fn galaxy(
    canvas: &mut Canvas,
    rng: &mut KotlinRandom,
    cx: f32,
    cy: f32,
    r: f32,
    rot: f32,
    ratio: f32,
    spiral: bool,
    force: f32,
) {
    canvas.save();
    canvas.translate(cx, cy);
    canvas.rotate(rot);
    canvas.scale(r, r * ratio);
    if spiral {
        canvas.circle(
            0.0,
            0.0,
            1.0,
            &Brush {
                alpha: (255.0 * force) as i32,
                gradient: Some(vec![(0.0, 90), (0.25, 55), (0.6, 22), (1.0, 0)]),
                ..Brush::default()
            },
        );
        let tight = rng.range(0.17, 0.28);
        let turn = (11.0_f64.ln() as f32) / tight;
        let flip = if rng.boolean() { 1.0 } else { -1.0 };
        for arm in 0..2 {
            let off = arm as f32 * 3.1416;
            for _ in 0..70 {
                let th = rng.float() * turn;
                let rr = 0.09 * exp(tight * th);
                let a = flip * th + off;
                let rad = rng.range(0.05, 0.12);
                let alpha = (rng.range(12.0, 22.0) * force) as i32;
                canvas.save();
                canvas.translate(cos(a) * rr, sin(a) * rr);
                canvas.scale(rad, rad);
                canvas.circle(0.0, 0.0, 1.0, &Brush { alpha, gradient: Some(halo()), ..Brush::default() });
                canvas.restore();
            }
            for _ in 0..450 {
                let th = rng.float() * turn;
                let rr = 0.09 * exp(tight * th);
                let a = flip * th + off;
                let spread = (rng.float() + rng.float() - 1.0) * 0.07 * (0.4 + rr);
                let x = cos(a) * rr + spread * cos(a + 1.5708);
                let y = sin(a) * rr + spread * sin(a + 1.5708);
                let q = rng.float();
                let alpha = ((35.0 + 90.0 * rng.float()) * (1.0 - 0.5 * rr) * force) as i32;
                canvas.circle(x, y, 0.006 + q * q * q * 0.02, &Brush { alpha, ..Brush::default() });
            }
            for _ in 0..18 {
                let th = rng.float() * turn;
                let rr = 0.09 * exp(tight * th);
                let a = flip * th + off;
                let alpha = (rng.range(120.0, 210.0) * force) as i32;
                let size = rng.range(0.008, 0.016);
                canvas.circle(cos(a) * rr, sin(a) * rr, size, &Brush { alpha, ..Brush::default() });
            }
        }
        canvas.save();
        canvas.scale(0.28, 0.28);
        canvas.circle(
            0.0,
            0.0,
            1.0,
            &Brush {
                alpha: (255.0 * force) as i32,
                gradient: Some(vec![(0.0, 255), (0.35, 150), (1.0, 0)]),
                ..Brush::default()
            },
        );
        canvas.restore();
        canvas.circle(0.0, 0.0, 0.03, &Brush::default());
        if ratio < 0.45 {
            canvas.line(
                -0.85,
                0.0,
                0.85,
                0.0,
                &Brush { alpha: 130, stroke: true, width: 0.05, erase: true, ..Brush::default() },
            );
        }
    } else {
        canvas.circle(
            0.0,
            0.0,
            1.0,
            &Brush {
                alpha: (255.0 * force) as i32,
                gradient: Some(vec![(0.0, 255), (0.12, 200), (0.35, 100), (0.7, 30), (1.0, 0)]),
                ..Brush::default()
            },
        );
    }
    canvas.restore();
}
pub(crate) fn render(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let angle = 0.75 + s.rng.float() * 0.7;
    let (ca, sa) = (cos(angle), sin(angle));
    let offset = -(s.aw * 0.5 + (s.rng.float() - 0.5) * 0.3) * sa + (s.ah * 0.5 + (s.rng.float() - 0.5) * 0.3) * ca;
    s.fill(|u, v| {
        let qx = fbm(u * 1.3, v * 1.3, 4, seed);
        let qy = fbm(u * 1.3 + 4.7, v * 1.3 + 8.9, 4, seed + 13);
        let (wx, wy) = (u + 0.4 * qx, v + 0.4 * qy);
        let cloud = fbm01(wx * 1.7, wy * 1.7, 5, seed + 41);
        let clear = smooth(0.38, 0.72, cloud);
        let filament = ridged(wx * 2.6, wy * 2.6, 5, seed + 29);
        let b = band(u, v, ca, sa, offset, seed);
        let grain = fbm01(wx * 9.0, wy * 9.0, 4, seed + 59);
        let lane = smooth(0.55, 0.85, ridged(wx * 4.2 + 1.7, wy * 4.2, 4, seed + 71));
        let milky = b * (0.08 + 0.22 * grain * cloud + 0.10 * filament * filament) * (1.0 - 0.8 * lane * b);
        0.010 + 0.07 * clear * cloud + 0.12 * filament * filament * clear + milky
    });
    let area = s.aw * s.ah;
    let mut dust: [Vec<(f32, f32)>; 3] = std::array::from_fn(|_| Vec::new());
    for _ in 0..(14000.0 * area) as usize {
        let x = s.rng.float() * s.aw;
        let y = s.rng.float() * s.ah;
        if s.rng.float() >= 0.25 + 0.75 * band(x, y, ca, sa, offset, seed) {
            continue;
        }
        let class = s.rng.index(3);
        dust[class].push((x, y));
    }
    let mut small = Vec::new();
    let mut medium = Vec::new();
    for _ in 0..(3500.0 * area) as usize {
        let x = s.rng.float() * s.aw;
        let y = s.rng.float() * s.ah;
        if s.rng.float() >= 0.25 + 0.75 * band(x, y, ca, sa, offset, seed) {
            continue;
        }
        let q = s.rng.float();
        small.push([x, y, 0.0009 + q * q * 0.0012, 90.0 + q * 110.0]);
    }
    for _ in 0..(420.0 * area) as usize {
        let x = s.rng.float() * s.aw;
        let y = s.rng.float() * s.ah;
        if s.rng.float() >= 0.25 + 0.75 * band(x, y, ca, sa, offset, seed) {
            continue;
        }
        let q = s.rng.float();
        medium.push([x, y, 0.0016 + q * q * 0.002, 150.0 + q * 80.0]);
    }
    let mut bright = Vec::new();
    let count = 10 + s.rng.index(8);
    for _ in 0..count {
        bright.push([s.rng.float() * s.aw, s.rng.float() * s.ah, s.rng.range(0.003, 0.0055), 255.0]);
    }
    let mut placed: Vec<[f32; 2]> = Vec::new();
    let mut tries = 0;
    while placed.len() < 3 && tries < 60 {
        tries += 1;
        let x = s.aw * s.rng.range(0.12, 0.88);
        let y = s.ah * s.rng.range(0.08, 0.92);
        if placed.iter().any(|p| hypot(p[0] - x, p[1] - y) < 0.3) {
            continue;
        }
        placed.push([x, y]);
        let r = s.rng.range(0.07, 0.13);
        let rot = s.rng.range(0.0, 180.0);
        let ratio = s.rng.range(0.22, 0.9);
        let spiral = s.rng.float() < 0.7;
        let force = s.rng.range(0.75, 1.0);
        galaxy(&mut s.canvas, &mut s.rng, x, y, r, rot, ratio, spiral, force);
    }
    for _ in 0..4 {
        let x = s.rng.float() * s.aw;
        let y = s.rng.float() * s.ah;
        let r = s.rng.range(0.025, 0.05);
        let rot = s.rng.range(0.0, 180.0);
        let ratio = s.rng.range(0.3, 0.85);
        let spiral = s.rng.float() < 0.5;
        let force = s.rng.range(0.5, 0.85);
        galaxy(&mut s.canvas, &mut s.rng, x, y, r, rot, ratio, spiral, force);
    }
    for _ in 0..14 {
        let x = s.rng.float() * s.aw;
        let y = s.rng.float() * s.ah;
        let r = s.rng.range(0.008, 0.02);
        let rot = s.rng.range(0.0, 180.0);
        let ratio = s.rng.range(0.3, 0.9);
        let force = s.rng.range(0.25, 0.6);
        galaxy(&mut s.canvas, &mut s.rng, x, y, r, rot, ratio, false, force);
    }
    for star in &medium {
        s.canvas.save();
        s.canvas.translate(star[0], star[1]);
        let k = star[2] * 6.0;
        s.canvas.scale(k, k);
        s.canvas.circle(
            0.0,
            0.0,
            1.0,
            &Brush { alpha: (star[3] * 0.18) as i32, gradient: Some(halo()), ..Brush::default() },
        );
        s.canvas.restore();
    }
    for star in &bright {
        s.canvas.save();
        s.canvas.translate(star[0], star[1]);
        let k = star[2] * 9.0;
        s.canvas.scale(k, k);
        s.canvas.circle(0.0, 0.0, 1.0, &Brush { alpha: 130, gradient: Some(halo()), ..Brush::default() });
        s.canvas.restore();
    }
    let mut needle = Path::new();
    for star in &bright {
        let len = s.rng.range(0.035, 0.085);
        let tilt = s.rng.range(-12.0, 12.0);
        for pass in 0..2 {
            let reach = if pass == 0 { len } else { len * 0.45 };
            let base = reach * 0.014;
            let alpha = if pass == 0 { 190 } else { 110 };
            for arm in 0..4 {
                s.canvas.save();
                s.canvas.translate(star[0], star[1]);
                s.canvas.rotate(tilt + arm as f32 * 90.0 + pass as f32 * 45.0);
                needle.clear();
                needle.move_to(0.0, -base);
                needle.line_to(reach, 0.0);
                needle.line_to(0.0, base);
                needle.close();
                s.canvas.path(&needle, &Brush { alpha, ..Brush::default() });
                s.canvas.restore();
            }
        }
    }
    for (points, alpha) in dust.iter().zip([40, 70, 105]) {
        s.canvas.points(points, &Brush { alpha, width: 0.0011, stroke: true, round_cap: true, ..Brush::default() });
    }
    for star in small.iter().chain(&medium) {
        s.canvas.circle(star[0], star[1], star[2], &Brush { alpha: star[3] as i32, ..Brush::default() });
    }
    for star in bright {
        s.canvas.circle(star[0], star[1], star[2], &Brush::default());
    }
}
