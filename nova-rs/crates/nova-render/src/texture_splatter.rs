//! Android's raster splats, filaments, crowns, streaks and smears (not polygon substitutes).
use crate::android::KotlinRandom;
use crate::texture_math::*;
use crate::textures::Sheet;
struct Ink<'a> {
    rng: &'a mut KotlinRandom,
    width: usize,
    height: usize,
    span: f32,
    field: Vec<f32>,
}
impl Ink<'_> {
    fn rnd(&mut self, a: f32, b: f32) -> f32 {
        a + (b - a) * self.rng.float()
    }
    fn splat(&mut self, cx: f32, cy: f32, r: f32, weight: f32) {
        let pr = r * self.span;
        if pr < 0.6 {
            return;
        }
        let (px, py) = (cx * self.span, cy * self.span);
        let x0 = ((px - pr) as i32).max(0);
        let x1 = ((px + pr) as i32 + 1).min(self.width as i32 - 1);
        let y0 = ((py - pr) as i32).max(0);
        let y1 = ((py + pr) as i32 + 1).min(self.height as i32 - 1);
        let r2 = pr * pr;
        for y in y0..=y1 {
            let dy = y as f32 - py;
            if r2 - dy * dy <= 0.0 {
                continue;
            }
            let row = y as usize * self.width;
            for x in x0..=x1 {
                let dx = x as f32 - px;
                let d2 = dx * dx + dy * dy;
                if d2 >= r2 {
                    continue;
                }
                let t = 1.0 - d2 / r2;
                self.field[row + x as usize] += t * t * weight;
            }
        }
    }
    fn chain(&mut self, x0: f32, y0: f32, x1: f32, y1: f32, r0: f32, r1: f32, weight: f32) {
        let len = hypot(x1 - x0, y1 - y0);
        let r_min = if r0 < r1 { r0 } else { r1 };
        let floor = if r_min < 0.0008 { 0.0008 } else { r_min };
        let n = ((len / (floor * 0.5)) as i32).clamp(2, 70);
        for i in 0..=n {
            let t = i as f32 / n as f32;
            self.splat(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, r0 + (r1 - r0) * t, weight);
        }
    }
    fn satellites(&mut self, cx: f32, cy: f32, r: f32, count: usize) {
        for _ in 0..count {
            let a = self.rng.float() * TAU;
            let q = self.rng.float();
            let d = r * (1.5 + 11.0 * q * q);
            let size = r * (0.05 + 0.28 * (1.0 - q) * self.rng.float() * self.rng.float());
            self.splat(cx + cos(a) * d, cy + sin(a) * d, size, 1.15);
        }
    }
    fn filament(&mut self, cx: f32, cy: f32, angle: f32, reach: f32, width: f32, curve: f32, beads: bool) {
        let (mut px, mut py, mut previous, mut end) = (cx, cy, width, angle);
        for i in 1..=12 {
            let t = i as f32 / 12.0;
            let a = angle + curve * t * t;
            end = a;
            let x = cx + cos(a) * reach * t + cos(a + 1.5708) * sin(t * 9.0) * reach * 0.015;
            let y = cy + sin(a) * reach * t + sin(a + 1.5708) * sin(t * 9.0) * reach * 0.015;
            let w = width * (1.0 - t) + width * 0.1;
            self.chain(px, py, x, y, previous, w, 1.0);
            if beads && (4..=9).contains(&i) && self.rng.float() < 0.22 {
                let r = width * self.rnd(0.35, 0.6);
                self.splat(x, y, r, 1.2);
            }
            px = x;
            py = y;
            previous = w;
        }
        let r = width * self.rnd(0.25, 0.6);
        self.splat(px, py, r, 1.3);
        if self.rng.float() < 0.4 {
            let r = width * self.rnd(0.12, 0.3);
            self.splat(px + cos(end) * width * 1.8, py + sin(end) * width * 1.8, r, 1.3);
        }
    }
    fn blob(&mut self, cx: f32, cy: f32, r: f32) {
        let count = 4 + self.rng.index(4);
        for _ in 0..count {
            let a = self.rng.float() * TAU;
            let d = r * self.rng.float() * 0.6;
            let radius = r * self.rnd(0.45, 0.95);
            self.splat(cx + cos(a) * d, cy + sin(a) * d, radius, 1.0);
        }
        let arms = 4 + self.rng.index(8);
        for _ in 0..arms {
            let angle = self.rng.float() * TAU;
            let reach = r * self.rnd(1.3, 5.2);
            let width = r * self.rnd(0.25, 0.55);
            let curve = (self.rng.float() - 0.5) * 1.1;
            self.filament(cx, cy, angle, reach, width, curve, true);
            if reach > r * 3.0 && self.rng.float() < 0.5 {
                let t = 0.55;
                let a = angle + curve * t * t;
                let side = if self.rng.boolean() { 0.7 } else { -0.7 };
                let length = reach * self.rnd(0.25, 0.45);
                self.filament(
                    cx + cos(a) * reach * t,
                    cy + sin(a) * reach * t,
                    a + side,
                    length,
                    width * 0.5,
                    side * 0.3,
                    false,
                );
            }
        }
        self.satellites(cx, cy, r, arms * 2);
    }
    fn streak(&mut self, cx: f32, cy: f32, r: f32) {
        let dir = self.rng.float() * TAU;
        let (dx, dy) = (cos(dir), sin(dir));
        let side = dir + 1.5708;
        self.chain(cx, cy, cx + dx * r * 1.8, cy + dy * r * 1.8, r * 0.9, r * 0.65, 1.0);
        let tail = r * self.rnd(4.0, 9.0);
        let bow = r * self.rnd(-0.8, 0.8);
        let (mut px, mut py) = (cx + dx * r * 1.8, cy + dy * r * 1.8);
        for i in 0..5 {
            let t = (i + 1) as f32 / 5.0;
            let x = cx + dx * tail * t + cos(side) * bow * sin(t * 3.1416);
            let y = cy + dy * tail * t + sin(side) * bow * sin(t * 3.1416);
            self.chain(px, py, x, y, r * (0.6 - 0.5 * i as f32 / 5.0), r * (0.6 - 0.5 * t), 1.0);
            px = x;
            py = y;
        }
        let count = 3 + self.rng.index(4);
        for _ in 0..count {
            let first = dir + self.rnd(-1.2, 1.2);
            let a = first + if self.rng.float() < 0.3 { 3.1416 } else { 0.0 };
            let reach = r * self.rnd(1.0, 2.8);
            let width = r * self.rnd(0.2, 0.4);
            let curve = self.rnd(-0.3, 0.3);
            self.filament(cx, cy, a, reach, width, curve, false);
        }
        let drops = 6 + self.rng.index(8);
        let mut d = tail;
        for i in 0..drops {
            d += r * self.rnd(0.6, 2.0) * (1.0 + i as f32 * 0.15);
            let lat = r * self.rnd(-0.5, 0.5);
            let mut size = r * (0.4 * (1.0 - i as f32 / drops as f32)) * self.rnd(0.5, 1.2);
            if size < r * 0.04 {
                size = r * 0.04;
            }
            let (x, y) = (cx + dx * d + cos(side) * lat, cy + dy * d + sin(side) * lat);
            self.chain(x, y, x + dx * size * 1.6, y + dy * size * 1.6, size, size * 0.6, 1.1);
        }
    }
    fn crown(&mut self, cx: f32, cy: f32, r: f32) {
        let ring = r * self.rnd(1.4, 2.1);
        let n = 18 + self.rng.index(8);
        for i in 0..n {
            if self.rng.float() < 0.1 {
                continue;
            }
            let a = i as f32 * TAU / n as f32;
            let rr = ring * self.rnd(0.88, 1.12);
            let size = r * self.rnd(0.28, 0.42);
            self.splat(cx + cos(a) * rr, cy + sin(a) * rr, size, 1.0);
        }
        let spikes = 9 + self.rng.index(8);
        for _ in 0..spikes {
            let a = self.rng.float() * TAU;
            let len = r * self.rnd(0.7, 2.6);
            let (x0, y0) = (cx + cos(a) * ring, cy + sin(a) * ring);
            let (x1, y1) = (cx + cos(a) * (ring + len), cy + sin(a) * (ring + len));
            self.chain(x0, y0, x1, y1, r * 0.3, r * 0.12, 1.0);
            let ball = r * self.rnd(0.18, 0.34);
            if self.rng.float() < 0.35 {
                self.splat(cx + cos(a) * (ring + len * 1.4), cy + sin(a) * (ring + len * 1.4), ball, 1.3);
            } else {
                self.splat(x1, y1, ball, 1.3);
            }
        }
        if self.rng.float() < 0.55 {
            let size = r * self.rnd(0.3, 0.6);
            self.splat(cx, cy, size, 1.2);
        }
        let count = 10 + self.rng.index(8);
        self.satellites(cx, cy, ring, count);
    }
    fn smear(&mut self, cx: f32, cy: f32, r: f32) {
        let mut heading = self.rng.float() * TAU;
        let turn = self.rnd(-0.12, 0.12);
        let length = r * self.rnd(6.0, 14.0);
        let (mut px, mut py, mut previous) = (cx, cy, r * 0.25);
        for i in 1..=16 {
            let t = i as f32 / 16.0;
            heading += turn + self.rnd(-0.05, 0.05);
            let x = px + cos(heading) * length / 16.0;
            let y = py + sin(heading) * length / 16.0;
            let bulge = (sin(t * 3.1416) as f64).powf(0.6) as f32;
            let w = r * (0.25 + 0.6 * bulge) * self.rnd(0.85, 1.15);
            self.chain(px, py, x, y, previous, w, 1.0);
            if i % 4 == 0 && self.rng.float() < 0.7 {
                let sign = if self.rng.boolean() { 1.0 } else { -1.0 };
                let a = heading + sign * self.rnd(0.6, 1.2);
                let reach = r * self.rnd(0.8, 2.2);
                let curve = self.rnd(-0.4, 0.4);
                self.filament(x, y, a, reach, w * 0.5, curve, false);
            }
            px = x;
            py = y;
            previous = w;
        }
        let size = r * self.rnd(0.15, 0.3);
        self.splat(px, py, size, 1.3);
        self.satellites(px, py, r, 6);
    }
}
pub(crate) fn render(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let (width, height, span, aw, ah) = (s.width, s.height, s.span, s.aw, s.ah);
    let mut ink = Ink { rng: &mut s.rng, width, height, span, field: vec![0.0; width * height] };
    let cell = 0.28;
    let mut row = 0;
    while row as f32 * cell < ah + cell {
        let mut col = 0;
        while col as f32 * cell < aw + cell {
            let count = if ink.rng.float() < 0.35 { 2 } else { 1 };
            for _ in 0..count {
                let cx = (col as f32 + 0.1 + ink.rng.float() * 0.8) * cell;
                let cy = (row as f32 + 0.1 + ink.rng.float() * 0.8) * cell;
                let q = ink.rng.float();
                let r = 0.011 + 0.03 * q * sqrt(q);
                let kind = ink.rng.float();
                if kind <= 0.30 {
                    ink.blob(cx, cy, r);
                } else if kind <= 0.55 {
                    ink.streak(cx, cy, r);
                } else if kind <= 0.75 {
                    ink.crown(cx, cy, r * 0.8);
                } else {
                    ink.smear(cx, cy, r);
                }
            }
            col += 1;
        }
        row += 1;
    }
    for _ in 0..(380.0 * aw * ah) as usize {
        let x = ink.rng.float() * aw;
        let y = ink.rng.float() * ah;
        if fbm01(x * 3.5, y * 3.5, 3, seed + 3) < 0.4 * ink.rng.float() + 0.2 {
            continue;
        }
        let q = ink.rng.float();
        ink.splat(x, y, 0.0018 + 0.009 * q * q * q, 1.15);
    }
    let field = ink.field;
    s.fill(|u, v| {
        let ix = ((u * span) as usize).clamp(1, width - 2);
        let iy = ((v * span) as usize).clamp(1, height - 2);
        let row = iy * width;
        let f = field[row + ix];
        let mist = fbm01(u * 5.5, v * 5.5, 5, seed);
        let haze = clamp((mist - 0.55) * 3.2);
        let body = smooth(0.5, 0.95, f);
        if body <= 0.0 {
            return 0.018 + 0.07 * haze * haze;
        }
        let gx = (field[row + ix + 1] - field[row + ix - 1]) * 0.5;
        let gy = (field[row + width + ix] - field[row - width + ix]) * 0.5;
        let slope = hypot(gx, gy);
        let rim = clamp(slope * 7.0) * body;
        let facing = if slope > 1e-6 { max(0.0, (gx * 0.62 + gy * 0.78) / slope) } else { 0.0 };
        let gloss = facing * facing * facing * body;
        let depth = 1.0 / (1.0 + f * 0.7);
        0.018 + 0.07 * haze * haze + 0.14 * body * depth + 0.40 * rim + 0.50 * gloss
    });
}
