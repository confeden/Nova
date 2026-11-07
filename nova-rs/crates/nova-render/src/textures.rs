//! Procedural texture generators ported from Nova Android, without substitute patterns.
use crate::android::KotlinRandom;
use crate::texture_canvas::Canvas;
use crate::texture_math::*;

pub(crate) struct Sheet {
    pub width: usize,
    pub height: usize,
    pub span: f32,
    pub aw: f32,
    pub ah: f32,
    pub rng: KotlinRandom,
    pub canvas: Canvas,
}
#[path = "texture_grass.rs"]
mod grass;
#[path = "texture_lightning.rs"]
mod lightning;
#[path = "texture_matrix.rs"]
pub(crate) mod matrix;
#[path = "texture_shards.rs"]
mod shards;
#[path = "texture_slime.rs"]
mod slime;
#[path = "texture_snow.rs"]
mod snow;
#[path = "texture_splatter.rs"]
mod splatter;
#[path = "texture_starfield.rs"]
mod starfield;
impl Sheet {
    fn new(width: usize, height: usize, ordinal: u64, variant: u32) -> Result<Self, &'static str> {
        let span = width.min(height) as f32;
        Ok(Self {
            width,
            height,
            span,
            aw: width as f32 / span,
            ah: height as f32 / span,
            rng: KotlinRandom::new(0x4E4F5641 + ordinal * 7919 + u64::from(variant) * 6700417),
            canvas: Canvas::new(width, height, span)?,
        })
    }
    pub(crate) fn fill(&mut self, mut shade: impl FnMut(f32, f32) -> f32) {
        let inv = 1.0 / self.span;
        let pixels = self.canvas.pixels.data_mut();
        for y in 0..self.height {
            let v = y as f32 * inv;
            for x in 0..self.width {
                let a = (shade(x as f32 * inv, v) * 255.0).clamp(0.0, 255.0) as u8;
                pixels[(y * self.width + x) * 4..(y * self.width + x) * 4 + 4].fill(a);
            }
        }
    }
    pub(crate) fn relief(&self, mut height: impl FnMut(f32, f32) -> f32) -> Vec<f32> {
        let inv = 1.0 / self.span;
        let mut field = Vec::with_capacity(self.width * self.height);
        for y in 0..self.height {
            let v = y as f32 * inv;
            for x in 0..self.width {
                field.push(height(x as f32 * inv, v));
            }
        }
        field
    }
}

pub struct TextureFrame {
    pub pixels: Vec<u8>,
    pub base: Vec<u8>,
    pub events: Vec<crate::texture_canvas::Event>,
}
pub fn texture_mask(width: usize, height: usize, texture: &str, variant: u32) -> Result<Vec<u8>, &'static str> {
    Ok(texture_frame(width, height, texture, variant, false)?.pixels)
}
pub fn texture_frame(
    width: usize,
    height: usize,
    texture: &str,
    variant: u32,
    tracing: bool,
) -> Result<TextureFrame, &'static str> {
    if width < 8 || height < 8 || width > 1440 || height > 1440 || variant > i32::MAX as u32 {
        return Err("invalid Android texture bounds");
    }
    let ordinal = match texture {
        "none" => 0,
        "basalt" => 1,
        "marble" => 2,
        "wood" => 3,
        "sand" => 4,
        "grass" => 5,
        "cracks" => 6,
        "water" => 7,
        "smoke" => 8,
        "starfield" => 9,
        "slime" => 10,
        "shards" => 11,
        "splatter" => 12,
        "lightning" => 13,
        "snow" => 14,
        "fractal" => 15,
        "matrix" => 16,
        _ => return Err("unknown Android texture"),
    };
    if texture == "none" || texture == "fractal" {
        let pixels = if texture == "none" {
            vec![0; width * height]
        } else {
            crate::android_fractal(width, height, variant, [width, height], [0.0, 0.0, 1.0, 1.0])?
        };
        return Ok(TextureFrame { base: if tracing { pixels.clone() } else { vec![] }, pixels, events: vec![] });
    }
    let mut sheet = Sheet::new(width, height, ordinal, variant)?;
    sheet.canvas.tracing = tracing;
    match texture {
        "basalt" => basalt(&mut sheet),
        "marble" => marble(&mut sheet),
        "wood" => wood(&mut sheet),
        "sand" => sand(&mut sheet),
        "grass" => grass::render(&mut sheet),
        "cracks" => cracks(&mut sheet),
        "water" => water(&mut sheet),
        "smoke" => smoke(&mut sheet),
        "slime" => slime::render(&mut sheet),
        "splatter" => splatter::render(&mut sheet),
        "lightning" => lightning::render(&mut sheet),
        "snow" => snow::render(&mut sheet),
        "shards" => shards::render(&mut sheet),
        "starfield" => starfield::render(&mut sheet),
        "matrix" => matrix::render(&mut sheet),
        _ => unreachable!("validated texture name"),
    }
    let pixels = sheet.canvas.alpha();
    let base = if tracing { sheet.canvas.base.take().unwrap_or_else(|| pixels.clone()) } else { vec![] };
    Ok(TextureFrame { pixels, base, events: sheet.canvas.events })
}

fn basalt(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let mut cell = Cellular::default();
    s.fill(|u: f32, v: f32| {
        let qx = fbm(u * 1.7_f32, v * 1.7_f32, 4, seed + 401);
        let qy = fbm(u * 1.7_f32 + 4.2_f32, v * 1.7_f32 + 1.3_f32, 4, seed + 419);
        let wx = u + 0.085_f32 * qx + 0.026_f32 * fbm(u * 6.3_f32, v * 6.3_f32, 3, seed + 433);
        let wy = v + 0.085_f32 * qy + 0.026_f32 * fbm(u * 6.3_f32 + 2.7_f32, v * 6.3_f32, 3, seed + 449);
        let mut seam = 0.0_f32;
        let mut weight = 1.0_f32;
        let mut freq = 2.6_f32;
        let mut tone = 0.5_f32;
        for level in 0..3 {
            cell.at(wx * freq, wy * freq, seed + level * 71);
            seam += weight * (1.0_f32 - smooth(0.0_f32, 0.17_f32, cell.f2 - cell.f1));
            if level == 0 {
                tone = cell.tone();
            }
            weight *= 0.5_f32;
            freq *= 2.07_f32;
        }
        let lit = clamp(1.0_f32 - seam);
        let grain = fbm01(u * 22.0_f32, v * 22.0_f32, 3, seed + 91);
        let shade = 0.55_f32 + 0.45_f32 * fbm01(u * 0.9_f32, v * 0.9_f32, 3, seed + 113);
        lit * shade * (0.09_f32 + 0.21_f32 * tone + 0.13_f32 * grain)
    });
}

fn marble(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let dir_x = 1.3_f32 + s.rng.float() * 0.8_f32;
    let dir_y = 1.9_f32 + s.rng.float() * 1.0_f32;
    s.fill(|u: f32, v: f32| {
        let qx = fbm(u * 1.2_f32, v * 1.2_f32, 5, seed);
        let qy = fbm(u * 1.2_f32 + 5.2_f32, v * 1.2_f32 + 1.3_f32, 5, seed + 11);
        let rx = fbm(u * 2.3_f32 + 1.6_f32 * qx + 1.7_f32, v * 2.3_f32 + 1.6_f32 * qy + 9.2_f32, 4, seed + 23);
        let ry = fbm(u * 2.3_f32 + 1.6_f32 * qx + 8.3_f32, v * 2.3_f32 + 1.6_f32 * qy + 2.8_f32, 4, seed + 37);
        let wx = u + 0.42_f32 * qx + 0.17_f32 * rx;
        let wy = v + 0.42_f32 * qy + 0.17_f32 * ry;
        let turb = turbulence(wx * 3.1_f32, wy * 3.1_f32, 6, seed + 53);
        let mut vein = 0.0_f32;
        let mut amp = 1.0_f32;
        let mut wave = 1.0_f32;
        let mut push = 2.4_f32;
        for _generation in 0..3 {
            let phase = (wx * dir_x + wy * dir_y) * wave * TAU + turb * push;
            let si = 0.5_f32 + 0.5_f32 * sin(phase);
            let s2 = si * si;
            let s4 = s2 * s2;
            vein += amp * s4 * s4;
            amp *= 0.5_f32;
            wave *= 2.1_f32;
            push *= 0.6_f32;
        }
        let body = fbm01(wx * 2.2_f32, wy * 2.2_f32, 5, seed + 71);
        let grit = fbm01(u * 34.0_f32, v * 34.0_f32, 2, seed + 89);
        0.04_f32 + 0.15_f32 * body * body + 0.05_f32 * grit * body + 0.52_f32 * clamp(vein)
    });
}

fn cracks(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let mut cell = Cellular::default();
    s.fill(|u: f32, v: f32| {
        let qx = fbm(u * 1.8_f32, v * 1.8_f32, 4, seed + 3);
        let qy = fbm(u * 1.8_f32 + 5.3_f32, v * 1.8_f32 + 1.1_f32, 4, seed + 7);
        let wx = u + 0.045_f32 * qx;
        let wy = v + 0.045_f32 * qy;
        let wear = fbm01(wx * 2.2_f32, wy * 2.2_f32, 5, seed + 11);
        let gate = 0.40_f32 + fbm01(wx * 0.9_f32, wy * 0.9_f32, 2, seed + 23) * 0.24_f32;
        let bare = clamp((wear - gate) / 0.12_f32);
        let mut net = 0.0_f32;
        let mut weight = 1.0_f32;
        let mut freq = 7.5_f32;
        for level in 0..3 {
            cell.at(wx * freq + level as f32 * 13.7_f32, wy * freq, seed + level * 71);
            let seam = weight * (1.0_f32 - smooth(0.0_f32, 0.085_f32, cell.f2 - cell.f1));
            if seam > net {
                net = seam;
            }
            weight *= 0.74_f32;
            freq *= 2.15_f32;
        }
        cell.at(wx * 34.0_f32, wy * 34.0_f32, seed + 211);
        let hair = (1.0_f32 - smooth(0.0_f32, 0.05_f32, cell.f2 - cell.f1)) * 0.34_f32;
        if hair > net {
            net = hair;
        }
        let crack = net * (0.42_f32 + 0.58_f32 * bare);
        let grain = fbm01(u * 44.0_f32, v * 44.0_f32, 3, seed + 41);
        let patina = fbm01(wx * 6.5_f32, wy * 6.5_f32, 4, seed + 97);
        0.02_f32
            + 0.10_f32 * wear * wear
            + 0.09_f32 * bare * (0.4_f32 + 0.6_f32 * patina)
            + 0.05_f32 * grain * bare
            + 0.46_f32 * crack
    });
}

fn water(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    s.fill(|u: f32, v: f32| {
        let qx = fbm(u * 1.4_f32, v * 1.4_f32, 4, seed);
        let qy = fbm(u * 1.4_f32 + 7.1_f32, v * 1.4_f32 + 2.3_f32, 4, seed + 17);
        let wx = u + 0.20_f32 * qx;
        let wy = v + 0.20_f32 * qy;
        let c1 = clamp(ridged(wx * 4.2_f32, wy * 4.2_f32, 5, seed + 31) * 1.25_f32);
        let c2 = clamp(ridged(wx * 7.9_f32 + 3.3_f32, wy * 7.9_f32 - 1.7_f32, 4, seed + 53) * 1.15_f32);
        let caustic = c1 * c2;
        let sharp = caustic * caustic;
        let swell = 0.35_f32 + 0.65_f32 * fbm01(u * 1.1_f32, v * 1.1_f32, 3, seed + 71);
        0.035_f32 + 0.10_f32 * swell + 0.26_f32 * caustic * swell + 0.55_f32 * sharp * sharp * swell
    });
}

fn smoke(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let sheet_height = s.ah;
    s.fill(|u: f32, v: f32| {
        let qx = fbm(u * 1.3_f32, v * 0.75_f32, 5, seed);
        let qy = fbm(u * 1.3_f32 + 3.7_f32, v * 0.75_f32 + 9.1_f32, 5, seed + 13);
        let rx = fbm(u * 2.6_f32 + 1.6_f32 * qx + 1.9_f32, v * 1.5_f32 + 1.6_f32 * qy - 0.7_f32, 4, seed + 29);
        let ry = fbm(u * 2.6_f32 + 1.6_f32 * qx + 7.3_f32, v * 1.5_f32 + 1.6_f32 * qy + 2.1_f32, 4, seed + 37);
        let wx = u + 0.62_f32 * qx + 0.30_f32 * rx;
        let wy = v + 0.62_f32 * qy + 0.30_f32 * ry;
        let body = fbm01(wx * 1.8_f32, wy * 1.15_f32, 6, seed + 53);
        let wisp = ridged(wx * 3.6_f32, wy * 2.3_f32, 5, seed + 71);
        let puff = smooth(0.28_f32, 0.88_f32, body);
        let rise = 0.35_f32 + 0.65_f32 * (v / sheet_height);
        0.02_f32 + 0.62_f32 * puff * rise + 0.16_f32 * wisp * wisp * puff
    });
}

fn wood(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let pith_x = -1.8_f32 - s.rng.float() * 1.6;
    let pith_y = s.ah * (0.15 + s.rng.float() * 0.7);
    let tilt = (s.rng.float() - 0.5) * 0.3;
    let count = 2 + s.rng.index(2);
    let mut knots = Vec::with_capacity(count);
    for _ in 0..count {
        knots.push([
            s.aw * (0.1 + s.rng.float() * 0.8),
            s.ah * (0.1 + s.rng.float() * 0.8),
            0.022 + s.rng.float() * 0.03,
        ]);
    }
    s.fill(|u: f32, v: f32| {
        let wave = 0.05_f32 * fbm(u * 0.8_f32 + 3.0_f32, v * 0.5_f32, 4, seed)
            + 0.012_f32 * fbm(u * 2.4_f32, v * 9.0_f32, 3, seed + 31);
        let mut vv = v + wave + tilt * u;
        let mut knot_mask = 0.0_f32;
        let mut knot_phase = 0.0_f32;
        let mut knot_core = 0.0_f32;
        for k in &knots {
            let kx = (u - k[0]) * 0.5_f32;
            let ky = vv - k[1];
            let kr = hypot(kx, ky);
            let reach = k[2] * 3.6_f32;
            if kr < reach * 2.0_f32 {
                let q = 1.0_f32 - kr / (reach * 2.0_f32);
                vv += ky * q * q * 0.9_f32;
            }
            let m = 1.0_f32 - smooth(k[2] * 0.8_f32, k[2] * 2.4_f32, kr);
            if m > knot_mask {
                knot_mask = m;
                knot_phase = kr * 46.0_f32 + 1.3_f32 * wave * 20.0_f32;
            }
            let c = smooth(k[2] * 1.1_f32, k[2] * 0.35_f32, kr);
            if c > knot_core {
                knot_core = c;
            }
        }
        let dx = (u - pith_x) * 0.10_f32;
        let dy = vv - pith_y;
        let trunk = hypot(dx, dy);
        let main_phase = trunk * 17.0_f32 + 1.4_f32 * fbm(u * 0.6_f32, vv * 0.9_f32, 3, seed + 7);
        let phase = main_phase + (knot_phase - main_phase) * knot_mask;
        let t = phase - floor(phase);
        let ring = t * t * t * (1.0_f32 - smooth(0.94_f32, 1.0_f32, t));
        let contrast = 0.55_f32 + 0.45_f32 * fbm01(u * 1.1_f32, vv * 0.7_f32, 2, seed + 13);
        let streak = smooth(0.35_f32, 0.75_f32, fbm01(u * 2.3_f32, vv * 150.0_f32, 2, seed + 97));
        let porous = smooth(0.35_f32, 0.6_f32, fbm01(u * 1.5_f32, v * 1.5_f32, 2, seed + 41));
        let dash = smooth(0.38_f32, 0.6_f32, perlin(u * 38.0_f32, vv * 210.0_f32, seed + 83)) * porous;
        0.05_f32
            + 0.27_f32 * ring * contrast
            + 0.09_f32 * streak * (0.45_f32 + 0.55_f32 * (1.0_f32 - t))
            + 0.13_f32 * dash * (1.0_f32 - t)
            + 0.20_f32 * knot_core * (0.5_f32 + 0.5_f32 * ring)
    });
}

fn sand(s: &mut Sheet) {
    let seed = Seed(s.rng.word() as i32);
    let ripple_x = 6.1_f32 + s.rng.float() * 2.0_f32;
    let ripple_y = 2.4_f32 + s.rng.float() * 1.6_f32;
    let field = s.relief(|u: f32, v: f32| {
        let qx = fbm(u * 1.1_f32, v * 1.1_f32, 4, seed + 5);
        let qy = fbm(u * 1.1_f32 + 3.3_f32, v * 1.1_f32 + 8.1_f32, 4, seed + 9);
        let dune = ridged(u * 1.9_f32 + 0.42_f32 * qx, v * 1.9_f32 + 0.42_f32 * qy, 7, seed);
        let ripple = sin((u * ripple_x + v * ripple_y) * TAU + dune * 13.0_f32);
        let grit = fbm(u * 90.0_f32, v * 90.0_f32, 2, seed + 61);
        dune + ripple * 0.020_f32 + grit * 0.0025_f32
    });
    let width = s.width;
    let height_px = s.height;
    let span = s.span;
    s.fill(|u: f32, v: f32| {
        let mut ix = (u * span) as usize;
        let mut iy = (v * span) as usize;
        ix = ix.clamp(1, width - 2);
        iy = iy.clamp(1, height_px - 2);
        let row = iy * width;
        let du = (field[row + ix + 1] - field[row + ix - 1]) * span * 0.5_f32;
        let dv = (field[row + width + ix] - field[row - width + ix]) * span * 0.5_f32;
        let nx = -du * 0.09_f32;
        let ny = -dv * 0.09_f32;
        let inv = 1.0_f32 / sqrt(nx * nx + ny * ny + 1.0_f32);
        let lambert = clamp((nx * -0.48_f32 + ny * -0.60_f32 + 0.64_f32) * inv);
        let lit = lambert * lambert * sqrt(lambert);
        0.05_f32 + 0.34_f32 * lit + 0.09_f32 * field[row + ix]
    });
}
