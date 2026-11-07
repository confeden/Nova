//! Android's forward-branching midpoint-displaced leaders and three glow passes.
use crate::android::KotlinRandom;
use crate::texture_canvas::{Brush, Path};
use crate::texture_math::*;
use crate::textures::Sheet;

fn channel(
    paths: &mut [Path; 4],
    rng: &mut KotlinRandom,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    depth: usize,
    generation: usize,
) {
    let (dx, dy) = (x1 - x0, y1 - y0);
    let len = hypot(dx, dy);
    if depth == 0 || len < 0.005 {
        paths[generation].move_to(x0, y0);
        paths[generation].line_to(x1, y1);
        return;
    }
    let shift = (rng.float() - 0.5) * len * 0.34;
    let (mx, my) = ((x0 + x1) * 0.5 - dy / len * shift, (y0 + y1) * 0.5 + dx / len * shift);
    channel(paths, rng, x0, y0, mx, my, depth - 1, generation);
    channel(paths, rng, mx, my, x1, y1, depth - 1, generation);
    if generation + 1 < 4 && depth >= 3 && rng.float() < 0.5 {
        let turn = (0.35 + rng.float() * 0.55) * if rng.boolean() { 1.0 } else { -1.0 };
        let (c, sn) = (cos(turn), sin(turn));
        let (bx, by) = ((dx * c - dy * sn) / len, (dx * sn + dy * c) / len);
        let reach = len * (0.5 + rng.float() * 0.6);
        channel(paths, rng, mx, my, mx + bx * reach, my + by * reach, depth - 1, generation + 1);
    }
}
pub(crate) fn render(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let mut paths = std::array::from_fn(|_| Path::new());
    s.fill(|u, v| {
        let qx = fbm(u * 1.2, v * 1.2, 4, seed);
        let cloud = fbm01(u * 1.9 + 0.4 * qx, v * 1.9, 6, seed + 23);
        let churn = ridged(u * 3.4, v * 3.4, 5, seed + 41);
        0.015 + 0.10 * cloud * cloud + 0.05 * churn * cloud
    });
    for _ in 0..3 {
        let x = s.aw * (0.15 + s.rng.float() * 0.7);
        let end = x + (s.rng.float() - 0.5) * s.aw * 0.8;
        let y = -0.05 - s.rng.float() * 0.1;
        let bottom = s.ah * (0.75 + s.rng.float() * 0.35);
        channel(&mut paths, &mut s.rng, x, y, end, bottom, 7, 0);
    }
    for pass in 0..3 {
        for generation in (0..4).rev() {
            let g = generation as f32;
            let (width, alpha) = match pass {
                0 => (0.030 / (g + 1.0), 16 - generation as i32 * 3),
                1 => (0.010 / (g + 1.0), 54 - generation as i32 * 10),
                _ => (0.0026 / (g + 1.0) + 0.0008, [245, 190, 140, 95][generation]),
            };
            s.canvas.path(
                &paths[generation],
                &Brush { width, alpha, stroke: true, round_cap: true, round_join: true, ..Brush::default() },
            );
        }
    }
}
