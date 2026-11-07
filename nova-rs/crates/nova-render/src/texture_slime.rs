//! Android's recursive compact-support metaballs and analytic meniscus/gloss.
use crate::android::KotlinRandom;
use crate::texture_math::*;
use crate::textures::Sheet;
struct Blob {
    x: f32,
    y: f32,
    support: f32,
}
fn spawn(blobs: &mut Vec<Blob>, capacity: usize, rng: &mut KotlinRandom, x: f32, y: f32, r: f32, left: usize) {
    if blobs.len() >= capacity {
        return;
    }
    let support = r * 1.8;
    blobs.push(Blob { x, y, support: support * support });
    if left == 0 {
        return;
    }
    for _ in 0..2 {
        let angle = rng.float() * TAU;
        let step = r * 1.45 * (0.75 + rng.float() * 0.5);
        let radius = r * (0.55 + rng.float() * 0.17);
        spawn(blobs, capacity, rng, x + cos(angle) * step, y + sin(angle) * step, radius, left - 1);
    }
}
pub(crate) fn render(s: &mut Sheet) {
    let (cols, rows) = ((s.aw / 0.55) as usize + 1, (s.ah / 0.55) as usize + 1);
    let capacity = cols * rows * ((1 << 4) - 1);
    let mut blobs = Vec::with_capacity(capacity);
    for gy in 0..rows {
        for gx in 0..cols {
            let x = (gx as f32 + 0.15 + s.rng.float() * 0.7) * 0.55;
            let y = (gy as f32 + 0.15 + s.rng.float() * 0.7) * 0.55;
            let r = 0.085 + s.rng.float() * 0.055;
            spawn(&mut blobs, capacity, &mut s.rng, x, y, r, 3);
        }
    }
    let edge = 1.0_f32 - 1.0 / (1.8_f32 * 1.8);
    let level = edge * edge;
    s.fill(|u, v| {
        let (mut field, mut gx, mut gy) = (0.0, 0.0, 0.0);
        for b in &blobs {
            let dy = v - b.y;
            if dy * dy >= b.support {
                continue;
            }
            let dx = u - b.x;
            let d2 = dx * dx + dy * dy;
            if d2 >= b.support {
                continue;
            }
            let t = 1.0 - d2 / b.support;
            field += t * t;
            let g = -4.0 * t / b.support;
            gx += g * dx;
            gy += g * dy;
        }
        let df = field - level;
        let body = clamp(df * 16.0);
        let meniscus = 1.0 / (1.0 + 420.0 * df * df);
        let slope = hypot(gx, gy);
        let facing = if slope > 1e-6 { max(0.0, (gx * 0.6 + gy * 0.8) / slope) } else { 0.0 };
        let lit = facing * facing;
        let gloss = lit * lit * body;
        0.12 * body + 0.26 * meniscus + 0.40 * gloss
    });
}
