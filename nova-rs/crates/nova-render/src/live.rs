//! Live immersive textures (D43). Owner-designed motion replaces the static Android masks for
//! these names. Every frame is a pure function of (texture, variant, time): the desktop renders
//! each frame in a separate short-lived process, so nothing may carry state between frames.
use crate::texture_canvas::Canvas;

#[path = "live_cracks.rs"]
mod cracks;
#[path = "live_fractal.rs"]
mod fractal;
#[path = "live_grass.rs"]
mod grass;
#[path = "live_lightning.rs"]
mod lightning;
#[path = "live_sand.rs"]
mod sand;
#[path = "live_snow.rs"]
mod snow;
#[path = "live_splatter.rs"]
mod splatter;
#[path = "live_starfield.rs"]
mod starfield;

/// Names rendered by this module. `fractal` is RGB, the rest are alpha masks.
pub const LIVE_TEXTURES: [&str; 8] =
    ["sand", "grass", "cracks", "starfield", "splatter", "lightning", "snow", "fractal"];

pub(crate) struct Live {
    pub width: usize,
    pub height: usize,
    /// min(width, height) in pixels; one canvas unit.
    pub span: f32,
    /// width / span and height / span: the canvas covers (0,0)..(aw,ah).
    pub aw: f32,
    pub ah: f32,
    /// Stable per (texture, variant); identical across frames.
    pub seed: u32,
    /// Seconds since the camera clock started, 0..=1e9. Reduce periodic phases in f64
    /// (`(time * speed).rem_euclid(period)`) before converting to f32.
    pub time: f64,
    /// tiny-skia canvas, transform = scale(span): draw in units. Only its alpha is used.
    pub canvas: Canvas,
    /// Per-pixel alpha 0..1, row-major width*height, combined with the canvas by screen blend.
    pub field: Vec<f32>,
}

impl Live {
    fn new(width: usize, height: usize, seed: u32, time: f64) -> Result<Self, &'static str> {
        let span = width.min(height) as f32;
        Ok(Self {
            width,
            height,
            span,
            aw: width as f32 / span,
            ah: height as f32 / span,
            seed,
            time,
            canvas: Canvas::new(width, height, span)?,
            field: vec![0.0; width * height],
        })
    }

    /// Set the per-pixel field from unit coordinates (u in 0..aw, v in 0..ah).
    #[allow(dead_code)]
    pub fn fill(&mut self, mut shade: impl FnMut(f32, f32) -> f32) {
        let inv = 1.0 / self.span;
        for y in 0..self.height {
            let v = (y as f32 + 0.5) * inv;
            for x in 0..self.width {
                self.field[y * self.width + x] = shade((x as f32 + 0.5) * inv, v);
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        let data = self.canvas.pixels.data();
        self.field
            .iter()
            .zip(data.chunks_exact(4))
            .map(|(&f, p)| {
                let a = p[3] as f32 / 255.0;
                let f = f.clamp(0.0, 1.0);
                ((1.0 - (1.0 - f) * (1.0 - a)) * 255.0 + 0.5) as u8
            })
            .collect()
    }
}

/// Avalanche hash for stateless per-object parameters.
#[allow(dead_code)]
pub(crate) fn hash(seed: u32, a: u32, b: u32) -> u32 {
    let mut h = seed ^ a.wrapping_mul(0x9E37_79B1) ^ b.wrapping_mul(0x85EB_CA77);
    h ^= h >> 16;
    h = h.wrapping_mul(0x7FEB_352D);
    h ^= h >> 15;
    h = h.wrapping_mul(0x846C_A68B);
    h ^ (h >> 16)
}

/// Uniform 0..1 from (seed, a, b).
#[allow(dead_code)]
pub(crate) fn rand01(seed: u32, a: u32, b: u32) -> f32 {
    (hash(seed, a, b) >> 8) as f32 / 16_777_216.0
}

pub struct LiveFrame {
    pub pixels: Vec<u8>,
    /// 3 for RGB (fractal), 1 for an alpha mask.
    pub channels: u8,
}

pub fn live_texture(width: usize, height: usize, texture: &str, variant: u32, time: f64) -> Result<LiveFrame, &'static str> {
    if width < 8 || height < 8 || width > 1440 || height > 1440 || variant > i32::MAX as u32 {
        return Err("invalid live texture bounds");
    }
    if !time.is_finite() || !(0.0..=1e9).contains(&time) {
        return Err("invalid live texture time");
    }
    let ordinal = LIVE_TEXTURES.iter().position(|&n| n == texture).ok_or("unknown live texture")? as u32;
    let seed = hash(0x4E4F_5641 ^ variant.wrapping_mul(6_700_417), ordinal.wrapping_add(101), variant);
    if texture == "fractal" {
        return Ok(LiveFrame { pixels: fractal::render(width, height, seed, time)?, channels: 3 });
    }
    let mut live = Live::new(width, height, seed, time)?;
    match texture {
        "sand" => sand::render(&mut live),
        "grass" => grass::render(&mut live),
        "cracks" => cracks::render(&mut live),
        "starfield" => starfield::render(&mut live),
        "splatter" => splatter::render(&mut live),
        "lightning" => lightning::render(&mut live),
        "snow" => snow::render(&mut live),
        _ => unreachable!("validated live texture name"),
    }
    Ok(LiveFrame { pixels: live.finish(), channels: 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_live_texture_is_deterministic_bounded_and_moves() {
        for name in LIVE_TEXTURES {
            let a = live_texture(96, 64, name, 197, 3.0).unwrap();
            assert_eq!(a.pixels.len(), 96 * 64 * a.channels as usize, "{name}");
            assert_eq!(a.pixels, live_texture(96, 64, name, 197, 3.0).unwrap().pixels, "{name} deterministic");
            let b = live_texture(96, 64, name, 197, 7.5).unwrap();
            assert_ne!(a.pixels, b.pixels, "{name} must change over time");
            let late = live_texture(96, 64, name, 197, 86_400.0 * 3.0).unwrap();
            assert!(late.pixels.iter().any(|&p| p > 8), "{name} still visible after days");
        }
    }

    #[test]
    fn invalid_requests_are_rejected() {
        assert!(live_texture(4, 64, "snow", 0, 0.0).is_err());
        assert!(live_texture(64, 64, "shards", 0, 0.0).is_err());
        assert!(live_texture(64, 64, "snow", 0, f64::NAN).is_err());
        assert!(live_texture(64, 64, "snow", 0, -1.0).is_err());
    }
}
