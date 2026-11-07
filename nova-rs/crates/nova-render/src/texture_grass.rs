//! The five meadow path layers from NovaTexturePatterns.grass.
use crate::android::KotlinRandom;
use crate::texture_canvas::{Brush, Path, oval};
use crate::texture_math::*;
use crate::textures::Sheet;

const HALF_PI: f32 = 1.5707964;
struct Meadow<'a> {
    rng: &'a mut KotlinRandom,
    seed: Seed,
    layers: [Path; 5],
}
fn ellipse(path: &mut Path, x: f32, y: f32, rx: f32, ry: f32, angle: f32) {
    oval(path, x, y, rx, ry, (angle as f64).to_degrees() as f32);
}
fn blade(path: &mut Path, x: f32, y: f32, len: f32, half: f32, angle: f32, bend: f32) {
    let (dx, dy) = (sin(angle), -cos(angle));
    let (nx, ny) = (-dy, dx);
    let (tx, ty) = (x + dx * len + nx * bend, y + dy * len + ny * bend);
    let (mx, my) = (x + dx * len * 0.5 + nx * bend * 0.35, y + dy * len * 0.5 + ny * bend * 0.35);
    let bulge = half * 1.1;
    path.move_to(x - nx * half, y - ny * half);
    path.quad_to(mx - nx * bulge, my - ny * bulge, tx, ty);
    path.quad_to(mx + nx * bulge, my + ny * bulge, x + nx * half, y + ny * half);
    path.close();
}
impl Meadow<'_> {
    fn wind(&self, x: f32, y: f32) -> f32 {
        0.35 * fbm(x * 1.4, y * 1.4, 2, self.seed + 5)
    }
    fn tuft(&mut self, tier: usize, x: f32, y: f32, len: f32, half: f32) {
        let lean = self.wind(x, y);
        let count = 4 + self.rng.index(3);
        for i in 0..count {
            let spread = (i as f32 / (count - 1) as f32 - 0.5) * 0.9;
            let angle = lean + spread + (self.rng.float() - 0.5) * 0.2;
            let l = len * (0.7 + 0.3 * self.rng.float()) * if spread.abs() < 0.2 { 1.0 } else { 0.85 };
            let origin = x + (self.rng.float() - 0.5) * half * 2.0;
            let width = half * (0.8 + 0.4 * self.rng.float());
            let bend = (self.rng.float() - 0.5) * len * 0.4;
            blade(&mut self.layers[tier], origin, y, l, width, angle, bend);
        }
    }
    fn clover(&mut self, x: f32, y: f32, size: f32) {
        let lean = (self.rng.float() - 0.5) * 0.6 + self.wind(x, y);
        let (tx, ty) = (x + sin(lean) * size * 1.4, y - cos(lean) * size * 1.4);
        self.layers[3].move_to(x, y);
        self.layers[3].line_to(tx, ty);
        for i in 0..3 {
            let a = lean + (i - 1) as f32 * 2.1;
            ellipse(
                &mut self.layers[1],
                tx + sin(a) * size * 0.45,
                ty - cos(a) * size * 0.45,
                size * 0.42,
                size * 0.36,
                a - HALF_PI,
            );
        }
    }
    fn fern(&mut self, x: f32, y: f32, len: f32) {
        let lean = (self.rng.float() - 0.5) * 0.5 + self.wind(x, y);
        let (tx, ty) = (x + sin(lean) * len, y - cos(lean) * len);
        let (cx, cy) = (x + sin(lean * 0.4) * len * 0.5, y - len * 0.5);
        self.layers[3].move_to(x, y);
        self.layers[3].quad_to(cx, cy, tx, ty);
        let pairs = 5 + self.rng.index(3);
        for j in 1..=pairs {
            let t = j as f32 / (pairs + 1) as f32;
            let (px, py) = (x + (tx - x) * t, y + (ty - y) * t);
            let size = len * (0.3 - 0.14 * t);
            for side in [-1.0, 1.0] {
                let a = lean + side * 0.95;
                ellipse(
                    &mut self.layers[1],
                    px + sin(a) * size * 0.5,
                    py - cos(a) * size * 0.5,
                    size * 0.5,
                    size * 0.16,
                    a - HALF_PI,
                );
            }
        }
    }
    fn flower(&mut self, kind: usize, x: f32, y: f32, stem: f32, r: f32) {
        self.layers[3].move_to(x, y);
        let y = y - stem;
        self.layers[3].line_to(x, y);
        let turn = if kind == 0 { 0.0 } else { self.rng.float() * TAU };
        let (count, step, reach, rx, ry) = match kind {
            0 => (8, TAU / 8.0, 1.0, 0.55, 0.22),
            1 => (4, HALF_PI, 0.5, 0.7, 0.62),
            2 => (5, TAU / 5.0, 0.6, 0.5, 0.36),
            _ => (6, TAU / 6.0, 0.7, 0.6, 0.2),
        };
        for i in 0..count {
            // Android multiplies before dividing; preserve that Float operation order.
            let a = if kind == 0 {
                i as f32 * TAU / 8.0
            } else if kind == 1 {
                turn + i as f32 * step
            } else if kind == 2 {
                turn + i as f32 * TAU / 5.0
            } else {
                turn + i as f32 * TAU / 6.0
            };
            let px = if kind == 0 { x + cos(a) * r } else { x + cos(a) * r * reach };
            let py = if kind == 0 { y + sin(a) * r } else { y + sin(a) * r * reach };
            ellipse(&mut self.layers[4], px, py, r * rx, r * ry, a);
        }
        if kind == 0 {
            ellipse(&mut self.layers[4], x, y, r * 0.3, r * 0.3, 0.0);
        }
        if kind == 3 {
            ellipse(&mut self.layers[4], x, y, r * 0.22, r * 0.22, 0.0);
        }
    }
}

pub(crate) fn render(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let area = s.aw * s.ah / 2.2;
    let h = s.ah;
    s.fill(|u, v| {
        let soil = fbm01(u * 3.6, v * 3.6, 3, seed);
        let root = smooth(h - 0.26, h + 0.02, v);
        0.03 + 0.07 * soil * soil + root * 0.16
    });
    let mut g = Meadow { rng: &mut s.rng, seed, layers: std::array::from_fn(|_| Path::new()) };
    for (tier, number, y0, ys, l0, ls, half) in
        [(0, 220.0, 0.22, 0.5, 0.05, 0.035, 0.006), (1, 130.0, 0.45, 0.47, 0.09, 0.05, 0.008)]
    {
        for _ in 0..(number * area) as usize {
            let x = g.rng.float() * s.aw;
            let y = s.ah * (y0 + ys * g.rng.float());
            let len = l0 + ls * g.rng.float();
            g.tuft(tier, x, y, len, half);
        }
    }
    for _ in 0..(26.0 * area) as usize {
        let x = g.rng.float() * s.aw;
        let y = s.ah * (0.5 + 0.4 * g.rng.float());
        let size = 0.035 + 0.02 * g.rng.float();
        g.clover(x, y, size);
    }
    for _ in 0..(22.0 * area) as usize {
        let x = g.rng.float() * s.aw;
        let y = s.ah * (0.55 + 0.4 * g.rng.float());
        let len = 0.12 + 0.06 * g.rng.float();
        g.fern(x, y, len);
    }
    for _ in 0..(70.0 * area) as usize {
        let x = g.rng.float() * s.aw;
        let y = s.ah * (0.78 + 0.27 * g.rng.float());
        let len = 0.16 + 0.08 * g.rng.float();
        g.tuft(2, x, y, len, 0.011);
    }
    for (kind, number, stem, spread, radius) in [
        (0, 34.0, 0.05, 0.04, 0.02),
        (1, 12.0, 0.04, 0.04, 0.025),
        (2, 18.0, 0.03, 0.03, 0.016),
        (3, 14.0, 0.06, 0.04, 0.018),
    ] {
        for _ in 0..(number * area) as usize {
            let x = g.rng.float() * s.aw;
            let y = s.ah * (0.4 + 0.5 * g.rng.float());
            let stem = stem + spread * g.rng.float();
            g.flower(kind, x, y, stem, radius);
        }
    }
    for (tier, alpha) in [(0, 70), (1, 130), (2, 205), (3, 170), (4, 240)] {
        s.canvas.path(
            &g.layers[tier],
            &Brush { alpha, stroke: tier == 3, width: 0.0032, round_cap: tier == 3, ..Brush::default() },
        );
    }
}
