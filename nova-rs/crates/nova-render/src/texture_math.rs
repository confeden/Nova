//! Float-precision fields from Nova Android's NovaTexturePatterns.kt.

use std::ops::{Add, AddAssign};
use std::sync::LazyLock;

pub const TAU: f32 = 6.2831855;
pub fn sin(x: f32) -> f32 {
    (x as f64).sin() as f32
}
pub fn cos(x: f32) -> f32 {
    (x as f64).cos() as f32
}
pub fn sqrt(x: f32) -> f32 {
    (x as f64).sqrt() as f32
}
pub fn hypot(x: f32, y: f32) -> f32 {
    (x as f64).hypot(y as f64) as f32
}
pub fn exp(x: f32) -> f32 {
    (x as f64).exp() as f32
}
pub fn floor(x: f32) -> f32 {
    x.floor()
}
pub fn abs(x: f32) -> f32 {
    x.abs()
}
pub fn max<T: PartialOrd + Copy>(a: T, b: T) -> T {
    if a > b { a } else { b }
}
pub fn clamp(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}
pub fn smooth(a: f32, b: f32, x: f32) -> f32 {
    if a == b {
        return if x < a { 0.0 } else { 1.0 };
    }
    let t = clamp((x - a) / (b - a));
    t * t * (3.0 - 2.0 * t)
}

#[derive(Clone, Copy)]
pub struct Seed(pub i32);
impl Add<i32> for Seed {
    type Output = Self;
    fn add(self, rhs: i32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}
impl AddAssign<i32> for Seed {
    fn add_assign(&mut self, rhs: i32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

pub fn hash(i: i32, j: i32, seed: Seed) -> u32 {
    let mut h = i
        .wrapping_mul(0x27D4EB2D)
        .wrapping_add(j.wrapping_mul(-0x61C88647))
        .wrapping_add(seed.0.wrapping_mul(0x165667B1)) as u32;
    h ^= h >> 15;
    h = h.wrapping_mul((-0x3361D2AF_i32) as u32);
    h ^= h >> 13;
    h = h.wrapping_mul((-0x7A143595_i32) as u32);
    h ^ (h >> 16)
}

static GRAD: LazyLock<[f32; 512]> = LazyLock::new(|| {
    let mut table = [0.0; 512];
    for i in 0..256 {
        let angle = i as f32 * (TAU / 256.0);
        table[i * 2] = cos(angle);
        table[i * 2 + 1] = sin(angle);
    }
    table
});

fn grad(i: i32, j: i32, seed: Seed, dx: f32, dy: f32) -> f32 {
    let k = (((hash(i, j, seed) >> 9) & 255) << 1) as usize;
    GRAD[k] * dx + GRAD[k + 1] * dy
}

pub fn perlin(x: f32, y: f32, seed: Seed) -> f32 {
    let (xi, yi) = (x.floor() as i32, y.floor() as i32);
    let (fx, fy) = (x - xi as f32, y - yi as f32);
    let u = fx * fx * fx * (fx * (fx * 6.0 - 15.0) + 10.0);
    let v = fy * fy * fy * (fy * (fy * 6.0 - 15.0) + 10.0);
    let n00 = grad(xi, yi, seed, fx, fy);
    let n10 = grad(xi + 1, yi, seed, fx - 1.0, fy);
    let n01 = grad(xi, yi + 1, seed, fx, fy - 1.0);
    let n11 = grad(xi + 1, yi + 1, seed, fx - 1.0, fy - 1.0);
    let a = n00 + (n10 - n00) * u;
    let b = n01 + (n11 - n01) * u;
    ((a + (b - a) * v) * 1.4).clamp(-1.0, 1.0)
}

pub fn fbm(x: f32, y: f32, octaves: usize, seed: Seed) -> f32 {
    let (mut sum, mut amp, mut norm, mut fx, mut fy, mut s) = (0.0, 1.0, 0.0, x, y, seed);
    for _ in 0..octaves.clamp(1, 10) {
        sum += amp * perlin(fx, fy, s);
        norm += amp;
        amp *= 0.5;
        fx = fx * 2.03 + 17.31;
        fy = fy * 2.03 - 9.47;
        s += 131;
    }
    sum / norm
}
pub fn fbm01(x: f32, y: f32, octaves: usize, seed: Seed) -> f32 {
    fbm(x, y, octaves, seed) * 0.5 + 0.5
}
pub fn ridged(x: f32, y: f32, octaves: usize, seed: Seed) -> f32 {
    let (mut sum, mut amp, mut norm, mut prev, mut fx, mut fy, mut s) = (0.0, 1.0, 0.0, 1.0, x, y, seed);
    for _ in 0..octaves.clamp(1, 10) {
        let mut n = 1.0 - perlin(fx, fy, s).abs();
        n *= n;
        sum += n * amp * prev;
        prev = n;
        norm += amp;
        amp *= 0.5;
        fx = fx * 2.03 + 11.7;
        fy = fy * 2.03 + 23.1;
        s += 197;
    }
    clamp(sum / norm)
}
pub fn turbulence(x: f32, y: f32, octaves: usize, seed: Seed) -> f32 {
    let (mut sum, mut amp, mut norm, mut fx, mut fy, mut s) = (0.0, 1.0, 0.0, x, y, seed);
    for _ in 0..octaves.clamp(1, 10) {
        sum += amp * perlin(fx, fy, s).abs();
        norm += amp;
        amp *= 0.5;
        fx = fx * 2.03 + 5.13;
        fy = fy * 2.03 + 31.7;
        s += 251;
    }
    sum / norm
}

#[derive(Default)]
pub struct Cellular {
    pub f1: f32,
    pub f2: f32,
    pub id: u32,
}
impl Cellular {
    pub fn at(&mut self, x: f32, y: f32, seed: Seed) {
        let (gx, gy) = (x.floor() as i32, y.floor() as i32);
        let (mut d1, mut d2, mut best) = (f32::MAX, f32::MAX, 0);
        for j in gy - 1..=gy + 1 {
            for i in gx - 1..=gx + 1 {
                let h = hash(i, j, seed);
                let px = i as f32 + ((h >> 8) & 255) as f32 / 255.0;
                let py = j as f32 + ((h >> 16) & 255) as f32 / 255.0;
                let (dx, dy) = (x - px, y - py);
                let d = dx * dx + dy * dy;
                if d < d1 {
                    d2 = d1;
                    d1 = d;
                    best = h;
                } else if d < d2 {
                    d2 = d;
                }
            }
        }
        self.f1 = sqrt(d1);
        self.f2 = sqrt(d2);
        self.id = best;
    }
    pub fn tone(&self) -> f32 {
        ((self.id >> 3) & 1023) as f32 / 1023.0
    }
}
