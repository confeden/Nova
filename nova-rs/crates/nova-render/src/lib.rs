//! Pure rendering kernels. No GUI, filesystem, networking or runtime dependencies.

use std::f64::consts::TAU;

mod android;
mod random;
pub use android::android_fractal;
mod texture_canvas;
mod texture_math;
mod textures;
pub use textures::{TextureFrame, texture_frame, texture_mask};
mod matrix_rain;
pub use matrix_rain::matrix_rain;
mod select;
pub use select::{Fractal, fractal};

#[derive(Clone, Copy, Debug)]
pub struct Mandelbrot {
    pub width: usize,
    pub height: usize,
    pub real: f64,
    pub imaginary: f64,
    pub scale: f64,
    pub cosine: f64,
    pub sine: f64,
    pub iterations: u32,
}

impl Mandelbrot {
    fn validate(self) -> Result<(), &'static str> {
        if self.width == 0 || self.height == 0 || self.width > 1024 || self.height > 1024 {
            return Err("dimensions must be within 1..1024");
        }
        if self.iterations == 0 || self.iterations > 1024 {
            return Err("iterations must be within 1..1024");
        }
        if !self.real.is_finite()
            || !self.imaginary.is_finite()
            || self.real.abs() > 4.0
            || self.imaginary.abs() > 4.0
            || !self.scale.is_finite()
            || self.scale <= 0.0
            || self.scale > 4.0
            || !self.cosine.is_finite()
            || !self.sine.is_finite()
            || self.cosine.abs() > 1.0
            || self.sine.abs() > 1.0
        {
            return Err("invalid complex viewport");
        }
        Ok(())
    }
}

fn orbit(real: f64, imaginary: f64, limit: u32) -> f64 {
    let q = (real - 0.25).powi(2) + imaginary * imaginary;
    if q * (q + real - 0.25) <= 0.25 * imaginary * imaginary
        || (real + 1.0).powi(2) + imaginary * imaginary <= 0.0625
    {
        return -1.5;
    }
    let (mut zr, mut zi) = (0.0_f64, 0.0_f64);
    for count in 0..limit {
        let (rr, ii) = (zr * zr, zi * zi);
        if rr + ii > 1e4 {
            return f64::from(count) + 1.0 - (rr + ii).sqrt().ln().log2();
        }
        zi = 2.0 * zr * zi + imaginary;
        zr = rr - ii + real;
    }
    -1.0 - (zi.atan2(zr) / TAU + 0.5)
}

/// Render the existing Python smooth-escape palette as an 8-bit grayscale mask.
pub fn mandelbrot(view: Mandelbrot) -> Result<Vec<u8>, &'static str> {
    view.validate()?;
    let minimum = view.width.min(view.height) as f64;
    let aspect_x = view.width as f64 / minimum;
    let aspect_y = view.height as f64 / minimum;
    let mut pixels = vec![0; view.width * view.height];
    for y in 0..view.height {
        let py = (y as f64 / view.height.saturating_sub(1).max(1) as f64 - 0.5) * view.scale * aspect_y;
        for x in 0..view.width {
            let px = (x as f64 / view.width.saturating_sub(1).max(1) as f64 - 0.5) * view.scale * aspect_x;
            let nu = orbit(
                view.real + px * view.cosine - py * view.sine,
                view.imaginary + px * view.sine + py * view.cosine,
                view.iterations,
            );
            let tone = if nu < 0.0 {
                0.025 + 0.07 * (0.5 + 0.5 * (TAU * -(nu + 1.0) * 3.0).sin())
            } else {
                let prox = ((nu - 1.5) / 88.5).clamp(0.0, 1.0);
                let prox = prox * prox * (3.0 - 2.0 * prox);
                let wide = 0.5 + 0.5 * (TAU * nu * 0.055).sin();
                let fine = (nu * 0.22) % 1.0;
                let line = (1.0 - (fine - 0.2).abs() / 0.2).max(0.0);
                0.05 + (0.12 + 0.55 * prox) * (0.25 + 0.75 * wide) + 0.12 * line * prox
            };
            let distance = (x as f64 / view.width as f64 - 0.5).hypot(y as f64 / view.height as f64 - 0.5);
            pixels[y * view.width + x] =
                (tone * 255.0 * (1.0 - 0.28 * distance)).round_ties_even().clamp(0.0, 255.0) as u8;
        }
    }
    Ok(pixels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> Mandelbrot {
        Mandelbrot {
            width: 32,
            height: 24,
            real: -0.75,
            imaginary: 0.1,
            scale: 0.2,
            cosine: 1.0,
            sine: 0.0,
            iterations: 200,
        }
    }

    #[test]
    fn invalid_dimensions_and_nonfinite_inputs_are_rejected_before_allocation() {
        for v in [
            Mandelbrot { width: 0, ..view() },
            Mandelbrot { height: usize::MAX, ..view() },
            Mandelbrot { scale: f64::NAN, ..view() },
            Mandelbrot { real: f64::INFINITY, ..view() },
            Mandelbrot { iterations: 0, ..view() },
            Mandelbrot { sine: 2.0, ..view() },
        ] {
            assert!(mandelbrot(v).is_err());
        }
    }

    #[test]
    fn deterministic_detailed_image_and_single_pixel_dimensions() {
        let first = mandelbrot(view()).unwrap();
        assert_eq!(first.len(), 32 * 24);
        assert_eq!(first, mandelbrot(view()).unwrap());
        assert!(first.iter().max().unwrap() - first.iter().min().unwrap() > 10);
        assert_eq!(mandelbrot(Mandelbrot { width: 1, height: 1, ..view() }).unwrap().len(), 1);
    }
}
