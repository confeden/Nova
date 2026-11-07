//! Nova Android's NovaTexturePatterns.fractal: Kotlin RNG, float field and palette.
//! Keep legacy v1/v2 kernels separate; their Python RNG contract is still supported.

use std::f64::consts::TAU;

const CENTRES: [(f64, f64, f64); 7] = [
    (-0.743643887037151, 0.131825904205330, 7.0),
    (-1.401155189092, 0.0, 6.5),
    (0.25, 0.0, 6.0),
    (-0.77568377, 0.13646737, 4.5),
    (-1.25066, 0.02012, 4.0),
    (-0.1011, 0.9563, 3.8),
    (-0.16070135, 1.0375665, 4.5),
];
const TAU32: f32 = 6.2831855;

pub(crate) struct KotlinRandom {
    state: [u32; 5],
    add: u32,
}

impl KotlinRandom {
    pub(crate) fn new(seed: u64) -> Self {
        let (lo, hi) = (seed as u32, (seed >> 32) as u32);
        let mut rng = Self { state: [lo, hi, 0, 0, !lo], add: (lo << 10) ^ (hi >> 4) };
        for _ in 0..64 {
            rng.word();
        }
        rng
    }
    pub(crate) fn word(&mut self) -> u32 {
        let [x, y, z, w, v] = self.state;
        let t = x ^ (x >> 2);
        let next = t ^ (t << 1) ^ v ^ (v << 4);
        self.state = [y, z, w, v, next];
        self.add = self.add.wrapping_add(362437);
        next.wrapping_add(self.add)
    }
    pub(crate) fn index(&mut self, bound: u32) -> usize {
        if bound.is_power_of_two() {
            let word = self.word();
            let bits = bound.trailing_zeros();
            return if bits == 0 { 0 } else { (word >> (32 - bits)) as usize };
        }
        loop {
            let bits = self.word() >> 1;
            let value = bits % bound;
            if bits.wrapping_sub(value).wrapping_add(bound - 1) as i32 >= 0 {
                return value as usize;
            }
        }
    }
    fn double(&mut self) -> f64 {
        let high = (self.word() >> 6) as u64;
        let low = (self.word() >> 5) as u64;
        ((high << 27) + low) as f64 / 9007199254740992.0
    }

    pub(crate) fn float(&mut self) -> f32 {
        (self.word() >> 8) as f32 / 16777216.0
    }
    pub(crate) fn boolean(&mut self) -> bool {
        self.word() >> 31 != 0
    }
    pub(crate) fn range(&mut self, a: f32, b: f32) -> f32 {
        a + self.float() * (b - a)
    }
}

fn orbit(cr: f64, ci: f64, limit: u32) -> f32 {
    let q = (cr - 0.25) * (cr - 0.25) + ci * ci;
    if q * (q + (cr - 0.25)) <= 0.25 * ci * ci || (cr + 1.0) * (cr + 1.0) + ci * ci <= 0.0625 {
        return -1.5;
    }
    let (mut zr, mut zi) = (0.0_f64, 0.0_f64);
    for n in 0..limit {
        let (rr, ii) = (zr * zr, zi * zi);
        if rr + ii > 1e4 {
            return (n as f64 + 1.0 - (rr + ii).sqrt().ln().ln() / 2.0_f64.ln()) as f32;
        }
        zi = 2.0 * zr * zi + ci;
        zr = rr - ii + cr;
    }
    -(1.0 + (zi.atan2(zr) / TAU + 0.5) as f32)
}

fn smooth(a: f32, b: f32, x: f32) -> f32 {
    let t = ((x - a) / (b - a)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn sin(x: f32) -> f32 {
    (x as f64).sin() as f32
}

#[derive(Clone, Copy)]
struct View {
    real: f64,
    imaginary: f64,
    scale: f64,
    cosine: f64,
    sine: f64,
    iterations: u32,
}

fn select(width: usize, height: usize, variant: u32) -> View {
    let mut rng = KotlinRandom::new(0x4E4F5641 + 15 * 7919 + u64::from(variant) * 6700417);
    let span = width.min(height) as f32;
    let (ax, ay) = ((width as f32 / span) as f64, (height as f32 / span) as f64);
    let mut view = View { real: 0.0, imaginary: 0.0, scale: 1.0, cosine: 1.0, sine: 0.0, iterations: 300 };
    for _ in 0..8 {
        let (re, im, maximum) = CENTRES[rng.index(7)];
        let depth = 3.0 + rng.double() * (maximum - 3.0).max(0.0);
        let scale = 10.0_f64.powf(-depth);
        let real = re + (rng.double() - 0.5) * scale * 0.8;
        let imaginary = im + (rng.double() - 0.5) * scale * 0.8;
        let angle = rng.double() * TAU;
        view = View {
            real,
            imaginary,
            scale,
            cosine: angle.cos(),
            sine: angle.sin(),
            iterations: ((180.0 + 50.0 * depth) as u32).min(420),
        };
        let (mut inside, mut rich) = (0, 0);
        for _ in 0..300 {
            let px = (rng.double() - 0.5) * scale * ax;
            let py = (rng.double() - 0.5) * scale * ay;
            let nu = orbit(
                real + px * view.cosine - py * view.sine,
                imaginary + px * view.sine + py * view.cosine,
                view.iterations,
            );
            if nu < 0.0 {
                inside += 1;
            } else if nu > 12.0 {
                rich += 1;
            }
        }
        if (inside as f64) < 300.0 * 0.55 && (rich as f64) >= 300.0 * 0.22 {
            break;
        }
    }
    view
}

/// At crop=[0,0,1,1] this is the Android static mask. A crop reevaluates the same
/// complex plane for inward animation, rather than enlarging an 8-bit thumbnail.
pub fn android_fractal(
    width: usize,
    height: usize,
    variant: u32,
    source: [usize; 2],
    crop: [f64; 4],
) -> Result<Vec<u8>, &'static str> {
    if width < 8
        || height < 8
        || width > 1440
        || height > 1440
        || source.iter().any(|&n| n < 8 || n > 4096)
        || variant > i32::MAX as u32
    {
        return Err("Android pattern dimensions must be 8..1440, source 8..4096, variant 0..2147483647");
    }
    if crop.iter().any(|n| !n.is_finite() || *n < 0.0 || *n > 1.0) || crop[2] <= crop[0] || crop[3] <= crop[1] {
        return Err("invalid normalized crop");
    }
    let view = select(source[0], source[1], variant);
    let span = source[0].min(source[1]) as f32;
    let (ax, ay) = (source[0] as f32 / span, source[1] as f32 / span);
    let (gw, gh) = if height >= width {
        (((380 * width) as f32 / height as f32) as usize, 380)
    } else {
        (380, ((380 * height) as f32 / width as f32) as usize)
    };
    let (gw, gh) = (gw.max(2), gh.max(2));
    let mut grid = vec![0.0_f32; gw * gh];
    for gy in 0..gh {
        let y = crop[1] + gy as f64 / (gh - 1) as f64 * (crop[3] - crop[1]);
        let py = (y - 0.5) * (view.scale * ay as f64);
        for gx in 0..gw {
            let x = crop[0] + gx as f64 / (gw - 1) as f64 * (crop[2] - crop[0]);
            let px = (x - 0.5) * (view.scale * ax as f64);
            grid[gy * gw + gx] = orbit(
                view.real + px * view.cosine - py * view.sine,
                view.imaginary + px * view.sine + py * view.cosine,
                view.iterations,
            );
        }
    }
    // Match Android's Float arithmetic before palette evaluation (including truncation to alpha).
    let output_span = width.min(height) as f32;
    let inv = 1.0_f32 / output_span;
    let (kx, ky) = ((gw - 1) as f32 / (width - 1) as f32, (gh - 1) as f32 / (height - 1) as f32);
    let mut pixels = vec![0; width * height];
    for y in 0..height {
        let v = y as f32 * inv;
        for x in 0..width {
            let u = x as f32 * inv;
            let gx = (u * output_span * kx).clamp(0.0, gw as f32 - 1.001);
            let gy = (v * output_span * ky).clamp(0.0, gh as f32 - 1.001);
            let (ix, iy) = (gx as usize, gy as usize);
            let (fx, fy) = (gx - ix as f32, gy - iy as f32);
            let a = grid[iy * gw + ix];
            let b = grid[iy * gw + ix + 1];
            let c = grid[(iy + 1) * gw + ix];
            let d = grid[(iy + 1) * gw + ix + 1];
            let nearest = if fy < 0.5 {
                if fx < 0.5 { a } else { b }
            } else if fx < 0.5 {
                c
            } else {
                d
            };
            let tone = if nearest < 0.0 {
                0.025 + 0.07 * (0.5 + 0.5 * sin(TAU32 * -(nearest + 1.0) * 3.0))
            } else {
                let weights = [(1.0 - fx) * (1.0 - fy), fx * (1.0 - fy), (1.0 - fx) * fy, fx * fy];
                let (mut sum, mut weight) = (0.0, 0.0);
                for (n, w) in [a, b, c, d].into_iter().zip(weights) {
                    if n >= 0.0 {
                        sum += n * w;
                        weight += w;
                    }
                }
                let nu = if weight > 1e-4 { sum / weight } else { nearest };
                let prox = smooth(1.5, 90.0, nu);
                let wide = 0.5 + 0.5 * sin(TAU32 * nu * 0.055);
                let fine = nu * 0.22 - (nu * 0.22).floor();
                let line = smooth(0.0, 0.18, fine) * smooth(0.5, 0.18, fine);
                let pu = ((crop[0] + x as f64 / width as f64 * (crop[2] - crop[0])) * ax as f64) as f32;
                let pv = ((crop[1] + y as f64 / height as f64 * (crop[3] - crop[1])) * ay as f64) as f32;
                // Preserve the original Float sample coordinates for exact uncropped parity.
                let (pu, pv) = if crop == [0.0, 0.0, 1.0, 1.0] { (u, v) } else { (pu, pv) };
                let distance = ((pu - ax * 0.5) as f64).hypot((pv - ay * 0.5) as f64) as f32;
                let vignette = 1.0 - 0.3 * smooth(0.2, 0.8, distance);
                (0.05 + (0.12 + 0.55 * prox) * (0.25 + 0.75 * wide) + 0.12 * line * prox) * vignette
            };
            pixels[y * width + x] = (tone * 255.0).clamp(0.0, 255.0) as u8;
        }
    }
    Ok(pixels)
}
