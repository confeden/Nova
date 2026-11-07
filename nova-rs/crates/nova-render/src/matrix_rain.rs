//! The actual NovaMatrixRain live renderer used by Android's drawable, not its old static cache.
use crate::texture_canvas::Canvas;
use crate::texture_math::sqrt;
use crate::textures::TextureFrame;
use tiny_skia::Transform;

fn mix(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x7FEB352D);
    h ^= h >> 15;
    h = h.wrapping_mul((-0x7B935975_i32) as u32);
    h ^ (h >> 16)
}
fn unit(seed: u32, field: u32) -> f32 {
    (mix(seed.wrapping_add(field.wrapping_mul(0x632BE5AB))) >> 8) as f32 / 16777216.0
}

pub fn matrix_rain(
    width: usize,
    height: usize,
    variant: u32,
    time: f64,
    source: [usize; 2],
    crop: [f64; 4],
    alpha_scale: f32,
    tracing: bool,
) -> Result<TextureFrame, &'static str> {
    if width < 8
        || height < 8
        || width > 1440
        || height > 1440
        || source.iter().any(|&v| v < 8 || v > 4096)
        || variant > i32::MAX as u32
        || !time.is_finite()
        || !(0.0..=1e9).contains(&time)
    {
        return Err("invalid matrix rain parameters");
    }
    if crop.iter().any(|x| !x.is_finite() || *x < 0.0 || *x > 1.0) || crop[2] <= crop[0] || crop[3] <= crop[1] {
        return Err("invalid matrix camera crop");
    }
    if !alpha_scale.is_finite() || !(0.0..=1.0).contains(&alpha_scale) {
        return Err("invalid matrix alpha scale");
    }
    let mono = ttf_parser::Face::parse(crate::textures::matrix::MONO, 0).map_err(|_| "invalid mono font")?;
    let kana = ttf_parser::Face::parse(crate::textures::matrix::KANA, 0).map_err(|_| "invalid kana font")?;
    let mut pool: Vec<char> = (0xff66..=0xff9d)
        .filter_map(char::from_u32)
        .filter(|&c| mono.glyph_index(c).is_some() || kana.glyph_index(c).is_some())
        .collect();
    if pool.len() < 24 {
        pool.clear();
    }
    pool.extend("0123456789ZTSXEH:.=*+<>|".chars());
    let span = source[0].min(source[1]) as f32;
    let cols = (((source[0] as f32 / span) / 0.0185) as usize).max(1);
    let cw = source[0] as f32 / cols as f32;
    let ch = cw * 1.2;
    let rows = (source[1] as f32 / ch) as i32 + 1;
    let tail_max = ((rows as f32 * 0.6) as i32).max(4);
    let period = (rows + 2 * tail_max + 2) as f32;
    let (bw, bh) = ((cw as f64).ceil() as usize, (ch as f64).ceil() as usize);
    let mut atlas = Vec::with_capacity(pool.len());
    for &character in &pool {
        let (face, id) = if let Some(id) = mono.glyph_index(character) {
            (&mono, id)
        } else {
            (&kana, kana.glyph_index(character).ok_or("missing kana glyph")?)
        };
        let mut tile = Canvas::new(bw.max(1), bh.max(1), 1.0)?;
        tile.text(&character.to_string(), bw as f32 / 2.0, ch * 0.82, ch * 0.9, false, 255, face, id);
        atlas.push(tile.pixels);
    }
    let mut canvas = Canvas::new(width, height, 1.0)?;
    canvas.tracing = tracing;
    let sx = width as f32 / (source[0] as f64 * (crop[2] - crop[0])) as f32;
    let sy = height as f32 / (source[1] as f64 * (crop[3] - crop[1])) as f32;
    if !sx.is_finite() || !sy.is_finite() {
        return Err("matrix camera exceeds numeric precision");
    }
    canvas.transform = Transform::from_scale(sx, sy)
        .pre_translate(-(source[0] as f64 * crop[0]) as f32, -(source[1] as f64 * crop[1]) as f32);
    let seed = 0x4E4F5641_u32.wrapping_add(variant.wrapping_mul(6700417));
    let t = time as f32;
    for c in 0..cols {
        let column = mix(seed.wrapping_add((c as u32).wrapping_mul(73856093)));
        let speed = 0.7 + 1.5 * unit(column, 1);
        let phase = unit(column, 2) * period + speed * t;
        let cycle = (phase / period).floor() as i32;
        let pos = phase - cycle as f32 * period;
        let head = pos - (tail_max + 1) as f32;
        let state = mix(column.wrapping_add((cycle as u32).wrapping_mul(0x27D4EB2D)));
        if unit(state, 0) < 0.12 {
            continue;
        }
        let kind = unit(state, 1);
        let power = if kind < 0.18 {
            0.22 + 0.18 * unit(state, 3)
        } else if kind < 0.78 {
            0.6 + 0.25 * unit(state, 3)
        } else {
            0.9 + 0.1 * unit(state, 3)
        };
        let tail = 4 + (unit(state, 2) * (tail_max - 4) as f32) as i32;
        let head_row = head.floor() as i32;
        let x = c as f32 * cw;
        for n in 0..=tail {
            let row = head_row - n;
            if row < 0 {
                break;
            }
            if row >= rows {
                continue;
            }
            let cell = mix(column ^ ((row as u32).wrapping_mul(19349663)));
            let tick = (t * 0.6 + unit(cell, 9) * 7.0).floor() as i32;
            let glyph = (mix(cell.wrapping_add((tick as u32).wrapping_mul(83492791))) as i32)
                .rem_euclid(pool.len() as i32) as usize;
            let alpha = if n == 0 {
                255.0 * power
            } else {
                let k = 1.0 - n as f32 / tail as f32;
                255.0 * power * k * sqrt(k) * (0.55 + 0.45 * unit(cell, 5))
            };
            if n > 0 && alpha < 6.0 {
                continue;
            }
            canvas.bitmap(
                &atlas[glyph],
                x,
                row as f32 * ch,
                (alpha * alpha_scale).min(255.0) as i32,
                &pool[glyph].to_string(),
            );
        }
    }
    let pixels = canvas.alpha();
    let base = if tracing { canvas.base.take().unwrap_or_else(|| pixels.clone()) } else { vec![] };
    Ok(TextureFrame { pixels, base, events: canvas.events })
}
