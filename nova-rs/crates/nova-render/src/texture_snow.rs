//! Android's recursively branched sixfold dendrites, shared arm and hexagonal core.
use crate::android::KotlinRandom;
use crate::texture_canvas::{Brush, Path};
use crate::texture_math::*;
use crate::textures::Sheet;
fn spur(paths: &mut [Path; 3], rng: &mut KotlinRandom, ox: f32, oy: f32, dx: f32, dy: f32, len: f32, level: usize) {
    if level >= 3 || len < 0.0035 {
        return;
    }
    paths[level].move_to(ox, oy);
    paths[level].line_to(ox + dx * len, oy + dy * len);
    let stations = 2 + rng.index(3);
    for i in 1..=stations {
        let t = i as f32 / (stations + 1) as f32;
        let (px, py) = (ox + dx * len * t, oy + dy * len * t);
        let sub = len * (0.62 - 0.34 * t) * (0.75 + rng.float() * 0.4);
        for sn in [0.8660254, -0.8660254] {
            spur(paths, rng, px, py, dx * 0.5 - dy * sn, dx * sn + dy * 0.5, sub, level + 1);
        }
    }
}
struct Flake {
    x: f32,
    y: f32,
    radius: f32,
    turn: f32,
    arms: [Path; 3],
    core: Path,
    alpha: i32,
}
pub(crate) fn render(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    s.fill(|u, v| {
        let frost = fbm01(u * 2.8, v * 2.8, 5, seed);
        let needles = ridged(u * 8.5, v * 8.5, 4, seed + 31);
        0.02 + 0.09 * frost * frost + 0.06 * needles * needles * frost
    });
    let mut flakes = Vec::new();
    let (mut count, mut size, mut ink) = (3, 0.16_f32, 155);
    for _ in 0..3 {
        for _ in 0..count {
            let x = s.rng.float() * s.aw;
            let y = s.rng.float() * s.ah;
            let radius = size * (0.75 + s.rng.float() * 0.5);
            let mut arms = std::array::from_fn(|_| Path::new());
            spur(&mut arms, &mut s.rng, 0.0, 0.0, 0.0, -1.0, radius, 0);
            let mut core = Path::new();
            let plate = radius * 0.11;
            for i in 0..6 {
                let a = i as f32 * (TAU / 6.0);
                let (px, py) = (cos(a) * plate, sin(a) * plate);
                if i == 0 {
                    core.move_to(px, py);
                } else {
                    core.line_to(px, py);
                }
            }
            core.close();
            flakes.push(Flake { x, y, radius, turn: s.rng.float() * 60.0, arms, core, alpha: ink });
        }
        count *= 3;
        size *= 0.45;
        ink = (ink as f32 * 0.68) as i32;
    }
    for flake in flakes {
        s.canvas.save();
        s.canvas.translate(flake.x, flake.y);
        s.canvas.rotate(flake.turn);
        s.canvas.path(&flake.core, &Brush { alpha: flake.alpha, ..Brush::default() });
        for _ in 0..6 {
            for level in 0..3 {
                let width = (0.0016 + flake.radius * 0.020) / (level as f32 + 1.0);
                let alpha = (flake.alpha as f32 * (1.0 - level as f32 * 0.22)) as i32;
                s.canvas.path(
                    &flake.arms[level],
                    &Brush { width, alpha, stroke: true, round_cap: true, round_join: true, ..Brush::default() },
                );
            }
            s.canvas.rotate(60.0);
        }
        s.canvas.restore();
    }
}
