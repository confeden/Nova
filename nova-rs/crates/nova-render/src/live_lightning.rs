//! Inside a storm: the camera drifts forward through dim churning cloud (cross-faded fbm octaves,
//! infinite zoom); stateless bolts grow from one hashed origin into tapered fractal branches,
//! flash and flicker while the cloud around them glows, then fade before the next one somewhere else.
use crate::live::{rand01, Live};
use crate::texture_canvas::{Brush, Path};
use crate::texture_math::{fbm, smooth, Seed};

/// Octaves of forward zoom per second (doubling every ~12 s).
const ZOOM: f64 = 0.085;
const LAYERS: usize = 4;
/// Bolt channels: (period s, start jitter fraction, chance a slot fires).
const CHANNELS: [(f64, f64, f32); 2] = [(2.1, 0.4, 0.95), (3.3, 0.55, 0.6)];

struct Rng {
    seed: u32,
    a: u32,
    n: u32,
}
impl Rng {
    fn f(&mut self) -> f32 {
        self.n = self.n.wrapping_add(1);
        rand01(self.seed, self.a, self.n)
    }
    fn range(&mut self, lo: f32, hi: f32) -> f32 {
        lo + (hi - lo) * self.f()
    }
}

/// One branch: points (x, y, path distance from the bolt origin), base width, depth.
struct Branch {
    pts: Vec<(f32, f32, f32)>,
    width: f32,
    depth: u8,
}

/// A bolt ready to draw at this instant.
struct Bolt {
    branches: Vec<Branch>,
    /// Revealed path distance (growth front).
    front: f32,
    /// Channel brightness 0..~1.
    level: f32,
    /// Cloud illumination amount.
    glow: f32,
    /// Camera magnification since birth and the vanishing point it expands from.
    mag: f32,
    origin: (f32, f32),
    centroid: (f32, f32),
    scale: f32,
}

fn grow_tree(rng: &mut Rng, ox: f32, oy: f32, sc: f32, aim: f32) -> Vec<Branch> {
    // (x, y, s, dir, length, width, depth)
    let mut todo: Vec<(f32, f32, f32, f32, f32, f32, u8)> = Vec::new();
    let primaries = 1 + (rng.f() * 2.6) as usize;
    let spread = rng.range(0.7, 1.3);
    for p in 0..primaries {
        let off = if primaries == 1 { 0.0 } else { (p as f32 / (primaries - 1) as f32 - 0.5) * 2.0 * spread };
        let dir = aim + off + rng.range(-0.35, 0.35);
        let len = sc * rng.range(0.35, 0.75) * if p == 0 { 1.25 } else { 0.85 };
        let w = sc * if p == 0 { 0.0075 } else { 0.0055 };
        todo.push((ox, oy, 0.0, dir, len, w, 0));
    }
    let mut out = Vec::new();
    while let Some((x0, y0, s0, dir, len, w, depth)) = todo.pop() {
        if out.len() >= 48 {
            break;
        }
        let step = sc * if depth == 0 { 0.032 } else { 0.022 };
        let n = ((len / step) as usize).clamp(3, 40);
        let (mut x, mut y, mut s, mut drift) = (x0, y0, s0, 0.0f32);
        let mut pts = vec![(x, y, s)];
        for j in 0..n {
            drift = (drift + rng.range(-0.22, 0.22)).clamp(-0.6, 0.6);
            let d = dir + drift + rng.range(-0.65, 0.65);
            let st = step * rng.range(0.55, 1.45);
            x += d.cos() * st;
            y += d.sin() * st;
            s += st;
            pts.push((x, y, s));
            let left = 1.0 - (j as f32 + 1.0) / n as f32;
            let chance = [0.32, 0.22, 0.12][depth.min(2) as usize];
            if depth < 3 && left > 0.15 && rng.f() < chance {
                let side = if rng.f() < 0.5 { -1.0 } else { 1.0 };
                let cd = d + side * rng.range(0.35, 1.0);
                let cl = len * left * rng.range(0.45, 0.9) + step * 2.0;
                todo.push((x, y, s, cd, cl, w * rng.range(0.45, 0.6), depth + 1));
            }
        }
        out.push(Branch {
            pts,
            width: w,
            depth,
        });
    }
    out
}

/// Brightness envelope of a bolt aged `a` s: (channel level, cloud glow, revealed fraction).
fn envelope(rng: &mut Rng, a: f32, grow: f32, life: f32) -> (f32, f32, f32) {
    if a < grow {
        let x = a / grow;
        let front = 1.0 - (1.0 - x) * (1.0 - x);
        return (0.32 + 0.25 * x, 0.06 * x, front);
    }
    let t = a - grow;
    let strokes = 1 + (rng.f() * 3.0) as usize;
    let mut flash = 0.0;
    let mut at = 0.0;
    for k in 0..3 {
        let amp = if k == 0 { 1.0 } else { rng.range(0.45, 0.85) };
        let gap = rng.range(0.11, 0.24);
        if k < strokes && t >= at {
            flash += amp * (-(t - at) / 0.075).exp();
        }
        at += gap;
    }
    let fade = smooth(life, life - 0.45, a);
    let level = ((flash + 0.55 * (-t / 0.42).exp()) * fade).min(1.0);
    (level, flash.min(1.2) * fade, 1.0)
}

fn bolts(l: &Live) -> Vec<Bolt> {
    let (cx, cy) = (l.aw * 0.5, l.ah * 0.5);
    let mut out = Vec::new();
    for (ci, &(period, jit, chance)) in CHANNELS.iter().enumerate() {
        let k = (l.time / period).floor() as i64;
        for slot in [k - 1, k] {
            let id = slot as u64;
            let a32 = (id as u32) ^ ((id >> 32) as u32).wrapping_mul(0x9E37_79B9);
            let mut rng = Rng {
                seed: l.seed ^ (ci as u32 + 1).wrapping_mul(0x51ED_270B),
                a: a32,
                n: 0,
            };
            let fires = rng.f() < chance;
            let start = slot as f64 * period + rng.f() as f64 * period * jit;
            let age = (l.time - start) as f32;
            let grow = rng.range(0.22, 0.4);
            let life = grow + rng.range(0.8, 1.15);
            let sc = rng.range(0.55, 1.25);
            let ox = rng.range(0.2, 0.8) * l.aw;
            let oy = rng.range(0.15, 0.8) * l.ah;
            if !fires || !(0.0..life).contains(&age) {
                continue;
            }
            let mut erng = Rng {
                seed: rng.seed,
                a: a32 ^ 0xA5A5_5A5A,
                n: 0,
            };
            let (level, glow, frac) = envelope(&mut erng, age, grow, life);
            let aim = (cy - oy).atan2(cx - ox) + rng.range(-1.1, 1.1);
            let branches = grow_tree(&mut rng, ox, oy, sc, aim);
            let total = branches
                .iter()
                .flat_map(|b| b.pts.iter())
                .fold(0.0f32, |m, p| m.max(p.2));
            let (mut sx, mut sy, mut sn) = (0.0f32, 0.0f32, 0.0f32);
            for p in branches.iter().flat_map(|b| b.pts.iter()) {
                sx += p.0;
                sy += p.1;
                sn += 1.0;
            }
            let mag = (2f64.powf(ZOOM * age as f64)) as f32;
            let place = |x: f32, y: f32| (cx + (x - cx) * mag, cy + (y - cy) * mag);
            let depth = (0.65 + 0.35 * (sc - 0.55) / 0.7).clamp(0.6, 1.0);
            out.push(Bolt {
                branches,
                front: if frac >= 1.0 { f32::MAX } else { total * frac },
                level: level * depth,
                glow: glow * depth,
                mag,
                origin: place(ox, oy),
                centroid: place(sx / sn.max(1.0), sy / sn.max(1.0)),
                scale: sc * mag,
            });
        }
    }
    out
}

/// Tapered polygon of one branch revealed up to `front`, widths multiplied by `k`. Butt ends, sharp tips.
fn branch_poly(b: &Branch, front: f32, k: f32, lead: f32) -> Option<Path> {
    let s0 = b.pts[0].2;
    let len = (b.pts[b.pts.len() - 1].2 - s0).max(1e-6);
    let mut v: Vec<(f32, f32, f32)> = Vec::with_capacity(b.pts.len());
    for (i, &(x, y, s)) in b.pts.iter().enumerate() {
        let (x, y, s) = if s <= front {
            (x, y, s)
        } else {
            if i == 0 {
                return None;
            }
            let (px, py, ps) = b.pts[i - 1];
            let t = (front - ps) / (s - ps).max(1e-6);
            (px + (x - px) * t, py + (y - py) * t, front)
        };
        let taper = (1.0 - (s - s0) / len).max(0.0).powf(0.75);
        // Channels flare out of the origin from a point; side branches widen out of their parent.
        let ramp = smooth(0.0, lead * 1.6, s - s0);
        let taper = taper * if b.depth == 0 { ramp.sqrt() } else { 0.45 + 0.55 * ramp };
        let point = if front == f32::MAX {
            1.0
        } else {
            smooth(0.0, lead, front - s)
        };
        v.push((x, y, b.width * k * taper * point * 0.5));
        if s >= front {
            break;
        }
    }
    if v.len() < 2 {
        return None;
    }
    let n = v.len();
    let seg_n = |i: usize| {
        let (dx, dy) = (v[i + 1].0 - v[i].0, v[i + 1].1 - v[i].1);
        let m = (dx * dx + dy * dy).sqrt().max(1e-7);
        (-dy / m, dx / m)
    };
    let mut side = Vec::with_capacity(n);
    for i in 0..n {
        let a = seg_n(i.saturating_sub(1).min(n - 2));
        let c = seg_n(i.min(n - 2));
        let (mx, my) = (a.0 + c.0, a.1 + c.1);
        let m = (mx * mx + my * my).sqrt().max(1e-4);
        let (mx, my) = (mx / m, my / m);
        let miter = 1.0 / (mx * c.0 + my * c.1).max(0.5);
        side.push((mx * miter * v[i].2, my * miter * v[i].2));
    }
    let mut p = Path::new();
    p.move_to(v[0].0 + side[0].0, v[0].1 + side[0].1);
    for i in 1..n {
        p.line_to(v[i].0 + side[i].0, v[i].1 + side[i].1);
    }
    for i in (0..n).rev() {
        p.line_to(v[i].0 - side[i].0, v[i].1 - side[i].1);
    }
    p.close();
    Some(p)
}

fn draw_bolts(l: &mut Live, list: &[Bolt]) {
    let (cx, cy) = (l.aw * 0.5, l.ah * 0.5);
    for b in list {
        l.canvas.save();
        l.canvas.translate(cx, cy);
        l.canvas.scale(b.mag, b.mag);
        l.canvas.translate(-cx, -cy);
        let lead = 0.05 * b.scale / b.mag;
        for (k, a) in [(18.0, 0.03), (11.0, 0.045), (6.5, 0.07), (3.8, 0.11), (2.2, 0.26), (1.0, 1.0)] {
            for br in &b.branches {
                if (k > 7.0 && br.depth >= 1) || (k > 3.0 && br.depth >= 2) {
                    continue;
                }
                let dim = [1.0, 0.72, 0.52, 0.4][br.depth.min(3) as usize];
                let alpha = (255.0 * a * b.level * dim) as i32;
                if alpha < 1 {
                    continue;
                }
                if let Some(p) = branch_poly(br, b.front, k, lead) {
                    l.canvas.path(
                        &p,
                        &Brush {
                            alpha,
                            ..Brush::default()
                        },
                    );
                }
            }
        }
        l.canvas.restore();
    }
}

fn clouds(l: &mut Live, list: &[Bolt]) {
    let z = l.time * ZOOM;
    let f = z.rem_euclid(1.0) as f32;
    let turn = (l.time * 0.021).rem_euclid(std::f64::consts::TAU) as f32;
    let (dx, dy) = (2.7 * turn.cos(), 2.7 * turn.sin());
    let seed = Seed((l.seed & 0x7FFF_FFFF) as i32);
    // Distant sheet lightning: slots of 1.6 s, soft wide flicker somewhere in the cloud.
    let sk = (l.time / 1.6).floor() as i64;
    let mut sheets: Vec<(f32, f32, f32, f32)> = Vec::new();
    for slot in [sk - 1, sk] {
        let id = slot as u64;
        let mut r = Rng {
            seed: l.seed ^ 0x3C6E_F372,
            a: (id as u32) ^ ((id >> 32) as u32).wrapping_mul(0x85EB_CA77),
            n: 0,
        };
        let start = slot as f64 * 1.6 + r.f() as f64 * 1.2;
        let age = (l.time - start) as f32;
        let (x, y, rad, amp) = (
            r.range(-0.1, 1.1) * l.aw,
            r.range(-0.1, 1.1) * l.ah,
            r.range(0.35, 0.8),
            r.range(0.04, 0.09),
        );
        let (f1, f2) = (r.range(9.0, 17.0), r.range(0.0, 6.0));
        if (0.0..0.9).contains(&age) && r.f() < 0.7 {
            let env = (age / 0.9 * std::f32::consts::PI).sin().powi(2)
                * (0.6 + 0.4 * (age * f1 + f2).sin());
            sheets.push((x, y, 1.0 / (rad * rad), amp * env));
        }
    }
    let glows: Vec<(f32, f32, f32, f32, f32, f32)> = list
        .iter()
        .map(|b| {
            (
                b.origin.0,
                b.origin.1,
                b.centroid.0,
                b.centroid.1,
                1.0 / (0.16 * b.scale * b.scale),
                b.glow,
            )
        })
        .collect();
    let (cx, cy) = (l.aw * 0.5, l.ah * 0.5);
    const STEP: usize = 5;
    let gw = l.width / STEP + 2;
    let gh = l.height / STEP + 2;
    let inv = 1.0 / l.span;
    let mut grid = vec![0.0f32; gw * gh];
    let layer_w: Vec<(f32, f32, f32)> = (0..LAYERS)
        .map(|i| {
            let s = i as f32 - f;
            let w = (std::f32::consts::PI * (s + 1.0) / LAYERS as f32)
                .sin()
                .powi(2);
            let freq = 2.3 * 2f32.powf(s - 1.0);
            let ang = 0.37 * s;
            (w / (LAYERS as f32 * 0.5), freq, ang)
        })
        .collect();
    for gy in 0..gh {
        let v = (gy * STEP) as f32 * inv;
        for gx in 0..gw {
            let u = (gx * STEP) as f32 * inv;
            let (px, py) = (u - cx, v - cy);
            let mut n = 0.0;
            for &(w, freq, ang) in &layer_w {
                let (sa, ca) = ang.sin_cos();
                let qx = (px * ca - py * sa) * freq + dx;
                let qy = (px * sa + py * ca) * freq + dy;
                n += w * fbm(qx, qy, 2, seed);
            }
            let dens = smooth(-0.22, 0.38, n);
            let r2 = px * px + py * py;
            let mut val = 0.035 + 0.22 * dens * dens * (0.7 + 0.4 * r2.min(1.0));
            for &(x, y, k, amp) in &sheets {
                let d2 = (u - x).powi(2) + (v - y).powi(2);
                val += amp * (0.3 + 0.7 * dens) * (-d2 * k).exp();
            }
            for &(ox, oy, mx, my, k, amp) in &glows {
                let d1 = (u - ox).powi(2) + (v - oy).powi(2);
                let d2 = (u - mx).powi(2) + (v - my).powi(2);
                let g = 0.6 * (-d1 * k * 1.5).exp() + 0.4 * (-d2 * k * 0.6).exp();
                val += amp * 0.55 * (0.2 + 0.8 * dens) * g;
            }
            grid[gy * gw + gx] = val;
        }
    }
    let rs = 1.0 / STEP as f32;
    for y in 0..l.height {
        let fy = y as f32 * rs;
        let y0 = fy as usize;
        let ty = fy - y0 as f32;
        for x in 0..l.width {
            let fx = x as f32 * rs;
            let x0 = fx as usize;
            let tx = fx - x0 as f32;
            let i = y0 * gw + x0;
            let a = grid[i] + (grid[i + 1] - grid[i]) * tx;
            let b = grid[i + gw] + (grid[i + gw + 1] - grid[i + gw]) * tx;
            l.field[y * l.width + x] = a + (b - a) * ty;
        }
    }
}

pub(crate) fn render(l: &mut Live) {
    let list = bolts(l);
    clouds(l, &list);
    draw_bolts(l, &list);
}
