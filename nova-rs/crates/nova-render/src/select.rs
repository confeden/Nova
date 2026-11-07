//! Seeded viewport selection and rendering form one bounded native operation.

use crate::random::PythonRandom;
use crate::{Mandelbrot, mandelbrot, orbit};
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

pub struct Fractal {
    pub pixels: Vec<u8>,
    pub words_consumed: u32,
}

pub fn fractal(width: usize, height: usize, random_state: &[u32]) -> Result<Fractal, &'static str> {
    let mut view = Mandelbrot {
        width,
        height,
        real: 0.0,
        imaginary: 0.0,
        scale: 1.0,
        cosine: 1.0,
        sine: 0.0,
        iterations: 420,
    };
    view.validate()?;
    let mut rng = PythonRandom::from_state(random_state)?;
    let minimum = width.min(height) as f64;
    let (aspect_x, aspect_y) = (width as f64 / minimum, height as f64 / minimum);
    for _ in 0..8 {
        let (real, imaginary, maximum_depth) = CENTRES[rng.centre_index()?];
        let depth = rng.uniform(3.0, maximum_depth)?;
        let scale = 10.0_f64.powf(-depth);
        let real = real + rng.uniform(-0.4, 0.4)? * scale;
        let imaginary = imaginary + rng.uniform(-0.4, 0.4)? * scale;
        let angle = rng.random()? * TAU;
        view = Mandelbrot {
            width,
            height,
            real,
            imaginary,
            scale,
            cosine: angle.cos(),
            sine: angle.sin(),
            iterations: (180.0 + 50.0 * depth).round_ties_even().min(420.0) as u32,
        };
        let (mut inside, mut rich) = (0, 0);
        for _ in 0..80 {
            let x = rng.uniform(-0.5, 0.5)? * scale * aspect_x;
            let y = rng.uniform(-0.5, 0.5)? * scale * aspect_y;
            let value = orbit(
                real + x * view.cosine - y * view.sine,
                imaginary + x * view.sine + y * view.cosine,
                view.iterations,
            );
            inside += i32::from(value < 0.0);
            rich += i32::from(value > 12.0);
        }
        if inside < 44 && rich >= 18 {
            break;
        }
    }
    Ok(Fractal { pixels: mandelbrot(view)?, words_consumed: rng.words })
}
