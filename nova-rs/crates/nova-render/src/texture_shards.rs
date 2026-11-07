//! Android's recursively chord-split plates, inset facets, edges and impact rays.
use crate::android::KotlinRandom;
use crate::texture_canvas::{Brush, Path};
use crate::texture_math::*;
use crate::textures::Sheet;
struct Glass<'a> {
    rng: &'a mut KotlinRandom,
    impact: [f32; 2],
    facets: [Path; 4],
    edges: Path,
    radials: Path,
}
impl Glass<'_> {
    fn emit(&mut self, poly: &[[f32; 2]]) {
        let (mut cx, mut cy) = (0.0, 0.0);
        for p in poly {
            cx += p[0];
            cy += p[1];
        }
        cx /= poly.len() as f32;
        cy /= poly.len() as f32;
        let face = &mut self.facets[self.rng.index(4)];
        for (i, p) in poly.iter().enumerate() {
            let (x, y) = (cx + (p[0] - cx) * 0.93, cy + (p[1] - cy) * 0.93);
            if i == 0 {
                face.move_to(x, y);
                self.edges.move_to(x, y);
            } else {
                face.line_to(x, y);
                self.edges.line_to(x, y);
            }
        }
        face.close();
        self.edges.close();
    }
    fn split(&mut self, poly: Vec<[f32; 2]>, depth: usize) {
        let n = poly.len();
        let (mut cross, mut cx, mut cy) = (0.0, 0.0, 0.0);
        for i in 0..n {
            let j = (i + 1) % n;
            cross += poly[i][0] * poly[j][1] - poly[j][0] * poly[i][1];
            cx += poly[i][0];
            cy += poly[i][1];
        }
        cx /= n as f32;
        cy /= n as f32;
        let area = abs(cross) * 0.5;
        let reach = hypot(cx - self.impact[0], cy - self.impact[1]);
        let floor = 0.00018 + reach * reach * 0.008;
        if depth == 0 || area < floor {
            self.emit(&poly);
            return;
        }
        let a = self.rng.index(n as u32);
        let off = 1 + self.rng.index((n - 2) as u32);
        let b = (a + off) % n;
        let ta = 0.22 + self.rng.float() * 0.56;
        let tb = 0.22 + self.rng.float() * 0.56;
        let (an, bn) = ((a + 1) % n, (b + 1) % n);
        let pa = [poly[a][0] + (poly[an][0] - poly[a][0]) * ta, poly[a][1] + (poly[an][1] - poly[a][1]) * ta];
        let pb = [poly[b][0] + (poly[bn][0] - poly[b][0]) * tb, poly[b][1] + (poly[bn][1] - poly[b][1]) * tb];
        let mut left = Vec::with_capacity(2 + off);
        left.push(pa);
        for k in 1..=off {
            left.push(poly[(a + k) % n]);
        }
        left.push(pb);
        let rest = n - off;
        let mut right = Vec::with_capacity(2 + rest);
        right.push(pb);
        for k in 1..=rest {
            right.push(poly[(b + k) % n]);
        }
        right.push(pa);
        self.split(left, depth - 1);
        self.split(right, depth - 1);
    }
}
pub(crate) fn render(s: &mut Sheet) {
    let impact = [s.aw * (0.25 + s.rng.float() * 0.5), s.ah * (0.2 + s.rng.float() * 0.6)];
    let mut g = Glass {
        rng: &mut s.rng,
        impact,
        facets: std::array::from_fn(|_| Path::new()),
        edges: Path::new(),
        radials: Path::new(),
    };
    let plate = 0.62_f32;
    let mut py = -plate * 0.5;
    while py < s.ah + plate * 0.5 {
        let mut px = -plate * 0.5;
        while px < s.aw + plate * 0.5 {
            let (cx, cy) = (px + plate * (0.3 + g.rng.float() * 0.4), py + plate * (0.3 + g.rng.float() * 0.4));
            let mut quad = Vec::new();
            for i in 0..4 {
                let angle = i as f32 * 1.5708 + (g.rng.float() - 0.5) * 0.8;
                let r = plate * (0.55 + g.rng.float() * 0.4);
                quad.push([cx + cos(angle) * r, cy + sin(angle) * r]);
            }
            g.split(quad, 7);
            px += plate;
        }
        py += plate;
    }
    for _ in 0..13 {
        let angle = g.rng.float() * TAU;
        let len = 0.35 + g.rng.float() * 0.75;
        let (mut x, mut y, mut a) = (impact[0], impact[1], angle);
        g.radials.move_to(x, y);
        for _ in 0..7 {
            a += (g.rng.float() - 0.5) * 0.30;
            x += cos(a) * len / 7.0;
            y += sin(a) * len / 7.0;
            g.radials.line_to(x, y);
        }
    }
    for (p, alpha) in g.facets.iter().zip([12, 21, 32, 46]) {
        s.canvas.path(p, &Brush { alpha, ..Brush::default() });
    }
    s.canvas.path(&g.edges, &Brush { stroke: true, width: 0.0016, alpha: 96, ..Brush::default() });
    s.canvas.path(&g.radials, &Brush { stroke: true, width: 0.0035, alpha: 150, ..Brush::default() });
}
