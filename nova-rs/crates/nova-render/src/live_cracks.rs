//! Live "cracks": the camera glides through a row of glass panes. Each pane's fracture grows in spurts from its
//! impact point (wavy forking radials, bowed spider-web ring cracks, a crushed core) as it approaches, then passes.
use crate::live::{hash, Live};
use crate::texture_canvas::{Brush, Path};

/// Panes passed per second.
const SPEED: f64 = 0.16;
/// Farthest visible pane distance (in pane spacings).
const DEPTH: f32 = 4.6;
/// Screen units per local unit at distance 1.
const FOCAL: f32 = 0.62;
const TAU: f64 = std::f64::consts::TAU;

struct Rng(u32);
impl Rng {
    fn new(seed: u32, a: u32, b: u32) -> Self {
        Rng(hash(seed, a, b) | 1)
    }
    fn f(&mut self) -> f32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        (self.0 >> 8) as f32 / 16_777_216.0
    }
    fn s(&mut self) -> f32 {
        self.f() * 2.0 - 1.0
    }
}

fn ss(e0: f32, e1: f32, x: f32) -> f32 {
    let t = ((x - e0) / (e1 - e0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Monotone growth that runs in quick spurts and pauses, like glass cracking under stress.
fn spurt(x: f32, steps: f32, phase: f32) -> f32 {
    let y = x.clamp(0.0, 1.0) * steps + phase;
    let i = y.floor();
    let f = ss(0.0, 0.3, y - i);
    ((i + f - phase) / steps).clamp(0.0, 1.0)
}

/// A crack polyline with cumulative arc length; `shown` is how much of it has grown.
struct Crack {
    pts: Vec<(f32, f32)>,
    arc: Vec<f32>,
    shown: f32,
}

impl Crack {
    fn len(&self) -> f32 {
        *self.arc.last().unwrap_or(&0.0)
    }
    /// Emit the grown part; returns the tip if still growing.
    fn emit(&self, path: &mut Path) -> Option<(f32, f32)> {
        if self.shown <= 0.0 || self.pts.len() < 2 {
            return None;
        }
        path.move_to(self.pts[0].0, self.pts[0].1);
        for i in 1..self.pts.len() {
            let (a0, a1) = (self.arc[i - 1], self.arc[i]);
            if a1 <= self.shown {
                path.line_to(self.pts[i].0, self.pts[i].1);
            } else {
                let t = ((self.shown - a0) / (a1 - a0).max(1e-6)).clamp(0.0, 1.0);
                let (p, q) = (self.pts[i - 1], self.pts[i]);
                let tip = (p.0 + (q.0 - p.0) * t, p.1 + (q.1 - p.1) * t);
                path.line_to(tip.0, tip.1);
                return Some(tip);
            }
        }
        None
    }
    /// First grown point at distance >= r from the impact (origin).
    fn at_radius(&self, r: f32) -> Option<(f32, f32)> {
        self.pts
            .iter()
            .zip(&self.arc)
            .take_while(|(_, a)| **a <= self.shown)
            .find(|(p, _)| p.0 * p.0 + p.1 * p.1 >= r * r)
            .map(|(p, _)| *p)
    }
}

/// Wavy crack walk: drifting heading, gentle curvature, rare kinks. Fork candidates go to `forks`.
fn walk(
    rng: &mut Rng,
    start: (f32, f32),
    heading: f32,
    len: f32,
    forks: Option<&mut Vec<(f32, (f32, f32), f32)>>,
) -> Crack {
    let mut pts = vec![start];
    let mut arc = vec![0.0];
    let (mut x, mut y, mut s, mut dev) = (start.0, start.1, 0.0f32, 0.0f32);
    let bend = rng.s() * 0.3;
    let mut forks = forks;
    while s < len {
        let step = 0.022 + 0.022 * rng.f();
        dev = dev * 0.85 + rng.s() * 0.09;
        if rng.f() < 0.06 {
            dev += rng.s() * 0.45;
        }
        let h = heading + dev + bend * s;
        x += h.cos() * step;
        y += h.sin() * step;
        s += step;
        pts.push((x, y));
        arc.push(s);
        if let Some(f) = forks.as_deref_mut() {
            if s > 0.12 && s < len * 0.85 && rng.f() < 0.045 {
                f.push((s, (x, y), h));
            }
        }
    }
    Crack {
        pts,
        arc,
        shown: 0.0,
    }
}

struct Ink {
    main: Path,
    fine: Path,
    /// Glow dots: (x, y, strength 0..1).
    dots: Vec<(f32, f32, f32)>,
}

/// Build the fracture of pane `k` at age `a` (0 = just appeared far away, 1 = at the camera).
fn fracture(seed: u32, k: u32, a: f32, time: f64, ink: &mut Ink) {
    let mut rng = Rng::new(seed, k, 7);
    let n = 8 + (rng.f() * 7.0) as usize;
    let rot = rng.f() * 6.2832;
    let mut radials: Vec<Crack> = Vec::with_capacity(n);
    let mut branches: Vec<Crack> = Vec::new();
    for i in 0..n {
        let base = rot + 6.2832 * (i as f32 + rng.s() * 0.38) / n as f32;
        let len = 0.7 + 1.6 * rng.f() * rng.f() + 0.5 * rng.f();
        let delay = rng.f() * 0.22;
        let ph = rng.f();
        let r0 = 0.02 + rng.f() * 0.02;
        let mut forks = Vec::new();
        let mut c = walk(
            &mut rng,
            (base.cos() * r0, base.sin() * r0),
            base,
            len,
            Some(&mut forks),
        );
        let g = spurt((a - delay) / (0.85 - delay), 4.0 + (ph * 3.0).floor(), ph);
        c.shown = c.len() * g;
        for (fs, at, h) in forks.into_iter().take(3) {
            let side = if rng.f() < 0.5 { -1.0 } else { 1.0 };
            let blen = (len - fs) * (0.2 + 0.45 * rng.f());
            let turn = h + side * (0.35 + 0.45 * rng.f());
            let mut b = walk(&mut rng, at, turn, blen, None);
            b.shown = ((c.shown - fs) * 0.85).clamp(0.0, b.len());
            branches.push(b);
        }
        radials.push(c);
    }
    for c in &radials {
        if let Some(t) = c.emit(&mut ink.main) {
            ink.dots.push((t.0, t.1, 0.35));
        }
    }
    for b in &branches {
        b.emit(&mut ink.fine);
    }
    // Spider-web rings: per (radial, ring) radius jitter so neighbouring segments meet on the radial.
    let mut ring_r = [0.0f32; 7];
    let mut r = 0.06 + rng.f() * 0.03;
    for rr in ring_r.iter_mut() {
        *rr = r;
        r *= 1.42 + rng.f() * 0.3;
    }
    for (j, &rj) in ring_r.iter().enumerate() {
        let aj = 0.08 + j as f32 * 0.085 + rng.f() * 0.08;
        let skip = 0.12 + j as f32 * 0.06;
        for i in 0..n {
            let mut cr = Rng::new(seed ^ 0x51ED, k, (j * 64 + i) as u32);
            if cr.f() < skip {
                continue;
            }
            let ji = Rng::new(seed ^ 0xA77, k, (j * 64 + i) as u32).s();
            let jn = Rng::new(seed ^ 0xA77, k, (j * 64 + (i + 1) % n) as u32).s();
            let grow = ss(0.0, 1.0, (a - aj - cr.f() * 0.1) / 0.05);
            if grow <= 0.0 {
                continue;
            }
            let (Some(p), Some(q)) = (
                radials[i].at_radius(rj * (1.0 + 0.2 * ji)),
                radials[(i + 1) % n].at_radius(rj * (1.0 + 0.2 * jn)),
            ) else {
                continue;
            };
            let (p, q) = if cr.f() < 0.5 { (p, q) } else { (q, p) };
            let bow = 0.04 + 0.22 * cr.f() - 0.1 * (cr.f() < 0.2) as i32 as f32;
            let (mx, my) = ((p.0 + q.0) * 0.5, (p.1 + q.1) * 0.5);
            let (cx, cy) = (mx * (1.0 - bow), my * (1.0 - bow));
            let (dx, dy) = (q.0 - p.0, q.1 - p.1);
            let seg = (dx * dx + dy * dy).sqrt().max(1e-4);
            let wob = seg * (0.045 - 0.005 * j as f32).max(0.02);
            let steps = 7;
            let last = (grow * steps as f32).ceil() as i32;
            let path = if j < 3 { &mut ink.main } else { &mut ink.fine };
            path.move_to(p.0, p.1);
            for s in 1..=last.min(steps) {
                let t = (s as f32 / steps as f32).min(grow);
                let u = 1.0 - t;
                let e = if s < steps { cr.s() * wob } else { 0.0 };
                let x = u * u * p.0 + 2.0 * u * t * cx + t * t * q.0 - dy / seg * e;
                let y = u * u * p.1 + 2.0 * u * t * cy + t * t * q.1 + dx / seg * e;
                path.line_to(x, y);
            }
        }
    }
    // Crushed core: a tight mesh of tiny chips around the impact.
    let core = ss(0.0, 0.08, a + 0.02);
    let rc = 0.045 + rng.f() * 0.02;
    for _ in 0..(18.0 * core) as usize {
        let (ang, rad) = (rng.f() * 6.2832, rc * rng.f().sqrt());
        let (x, y) = (ang.cos() * rad, ang.sin() * rad);
        let h = rng.f() * 6.2832;
        let l2 = 0.008 + 0.018 * rng.f();
        ink.fine.move_to(x, y);
        ink.fine.line_to(x + h.cos() * l2, y + h.sin() * l2);
        ink.fine.line_to(
            x + (h + rng.s()).cos() * l2 * 1.8,
            y + (h + rng.s()).sin() * l2 * 1.8,
        );
    }
    ink.dots.push((0.0, 0.0, 0.9 * core));
    // Glints: a few points along grown cracks twinkle slowly.
    for g in 0..6u32 {
        let mut gr = Rng::new(seed ^ 0x611E, k, g);
        let c = &radials[(gr.f() * n as f32) as usize % n];
        let idx = (gr.f() * c.pts.len() as f32) as usize % c.pts.len();
        if c.arc[idx] > c.shown {
            continue;
        }
        let w = 0.35 + 0.5 * gr.f() as f64;
        let ph = ((time * w + gr.f() as f64 * TAU).rem_euclid(TAU)) as f32;
        let tw = ph.sin().max(0.0).powi(8);
        if tw > 0.02 {
            ink.dots.push((c.pts[idx].0, c.pts[idx].1, tw));
        }
    }
}

pub(crate) fn render(l: &mut Live) {
    let z = l.time * SPEED;
    let base = z.floor();
    let frac = (z - base) as f32;
    let base_k = base as i64;
    let t1 = (l.time * 0.031).rem_euclid(TAU) as f32;
    let t2 = (l.time * 0.047).rem_euclid(TAU) as f32;
    let t3 = (l.time * 0.019).rem_euclid(TAU) as f32;
    let cam = (0.1 * t1.sin(), 0.07 * (t2 + 1.0).sin());
    let roll = 7.0 * t3.sin();
    let (ccx, ccy) = (l.aw * 0.5, l.ah * 0.5);
    let px = 1.0 / l.span;
    let mut sheens: Vec<(f32, f32, f32, f32, f32)> = Vec::new();
    for m in (1..=(DEPTH.ceil() as i64 + 1)).rev() {
        let d = m as f32 - frac;
        if d <= 0.1 || d >= DEPTH {
            continue;
        }
        let k = (base_k + m) as u64 as u32;
        let a = (DEPTH - d) / DEPTH;
        let vis = ss(DEPTH, DEPTH - 1.4, d) * ss(0.12, 0.7, d) * (1.15 / (0.3 + 0.65 * d)).min(1.0);
        if vis <= 0.004 {
            continue;
        }
        let s = FOCAL / d;
        let mut pr = Rng::new(l.seed ^ 0x9A4E, k, 3);
        let (ox, oy) = (pr.s() * 0.6, pr.s() * 0.4);
        let spin = pr.f() * 360.0;
        // A soft reflection band sweeping across the nearer glass as it approaches.
        let shine = ss(2.6, 1.5, d) * ss(0.12, 0.6, d);
        if shine > 0.01 {
            let th = pr.f() * 6.2832;
            let (bx, by) = (pr.s() * 0.5 - cam.0, pr.s() * 0.4 - cam.1);
            sheens.push((ccx + bx * s, ccy + by * s, th.cos() / (0.16 * s), th.sin() / (0.16 * s), 0.045 * shine));
        }
        let mut ink = Ink {
            main: Path::new(),
            fine: Path::new(),
            dots: Vec::new(),
        };
        fracture(l.seed, k, a, l.time, &mut ink);
        let cv = &mut l.canvas;
        cv.save();
        cv.translate(ccx, ccy);
        cv.rotate(roll);
        cv.translate((ox - cam.0) * s, (oy - cam.1) * s);
        cv.scale(s, s);
        cv.rotate(spin);
        // Faint milky haze around the impact.
        cv.save();
        cv.scale(0.35, 0.35);
        cv.circle(
            0.0,
            0.0,
            1.0,
            &Brush {
                alpha: (40.0 * vis) as i32,
                gradient: Some(vec![(0.0, 255), (0.25, 70), (1.0, 0)]),
                ..Brush::default()
            },
        );
        cv.restore();
        let u = px / s;
        let line = |w: f32, alpha: f32| Brush {
            alpha: (alpha * vis) as i32,
            width: w * u,
            stroke: true,
            round_cap: true,
            round_join: false,
            ..Brush::default()
        };
        if d < 3.3 && d > 0.55 {
            cv.path(&ink.main, &line(4.5, 34.0));
        }
        cv.path(&ink.main, &line(1.35, 235.0));
        cv.path(&ink.fine, &line(0.95, 175.0));
        for &(x, y, st) in &ink.dots {
            cv.save();
            cv.translate(x, y);
            let r = (2.5 + 5.0 * st) * u;
            cv.scale(r, r);
            cv.circle(
                0.0,
                0.0,
                1.0,
                &Brush {
                    alpha: (255.0 * vis * st) as i32,
                    gradient: Some(vec![(0.0, 255), (0.2, 160), (1.0, 0)]),
                    ..Brush::default()
                },
            );
            cv.restore();
        }
        cv.restore();
    }
    // Field: dim haze at the vanishing point plus glass reflection bands. Smooth, so it is sampled
    // every STEP pixels along a row and interpolated.
    const STEP: usize = 8;
    let inv = 1.0 / l.span;
    let shade = |u: f32, v: f32| {
        let (du, dv) = (u - ccx, v - ccy);
        let mut val = 0.03 * (-(du * du + dv * dv) * 2.5).exp();
        for &(sx, sy, c, sn, amp) in &sheens {
            let q = (u - sx) * c + (v - sy) * sn;
            let b = 1.0 / (1.0 + q * q);
            let e = 1.0 / (1.0 + (q - 1.6) * (q - 1.6) * 6.0);
            val += amp * (b * b + 0.5 * e);
        }
        val
    };
    let w = l.width;
    for y in 0..l.height {
        let v = (y as f32 + 0.5) * inv;
        let row = &mut l.field[y * w..(y + 1) * w];
        let mut x0 = 0;
        let mut f0 = shade(0.5 * inv, v);
        while x0 + 1 < w {
            let x1 = (x0 + STEP).min(w - 1);
            let f1 = shade((x1 as f32 + 0.5) * inv, v);
            let span = (x1 - x0) as f32;
            for (i, f) in row[x0..x1].iter_mut().enumerate() {
                *f = f0 + (f1 - f0) * (i as f32 / span);
            }
            row[x1] = f1;
            x0 = x1;
            f0 = f1;
        }
        if w == 1 {
            row[0] = f0;
        }
    }
}
