//! Android's stable glyph grid, stream classes, gaps and bright leading glyphs.
use crate::texture_canvas::Brush;
use crate::textures::Sheet;
pub(crate) const MONO: &[u8] = include_bytes!("../assets/DroidSansMono.ttf");
pub(crate) const KANA: &[u8] = include_bytes!("../assets/NovaMatrixKana.otf");

fn glyph(
    s: &mut Sheet,
    pool: &[char],
    cells: &[usize],
    cols: usize,
    cw: f32,
    ch: f32,
    k: f32,
    col: usize,
    row: usize,
    alpha: i32,
    bold: bool,
    mono: &ttf_parser::Face<'_>,
    kana: &ttf_parser::Face<'_>,
) {
    if alpha < 6 {
        return;
    }
    let character = pool[cells[row * cols + col]];
    let (face, id) = if let Some(id) = mono.glyph_index(character) {
        (mono, id)
    } else {
        (kana, kana.glyph_index(character).expect("bundled Android kana"))
    };
    let size = ch * 0.9 * k;
    let baseline = ch * 0.82;
    s.canvas.text(
        &character.to_string(),
        (col as f32 + 0.5) * cw * k,
        (row as f32 * ch + baseline) * k,
        size,
        bold,
        alpha.min(255),
        face,
        id,
    );
}
pub(crate) fn render(s: &mut Sheet) {
    let mono = ttf_parser::Face::parse(MONO, 0).expect("valid bundled Android mono font");
    let kana = ttf_parser::Face::parse(KANA, 0).expect("valid bundled Android kana font");
    let mut pool: Vec<char> = (0xff66..=0xff9d)
        .filter_map(char::from_u32)
        .filter(|&c| mono.glyph_index(c).is_some() || kana.glyph_index(c).is_some())
        .collect();
    if pool.len() < 24 {
        pool.clear();
    }
    pool.extend("0123456789ZTSXEH:.=*+<>|".chars());
    let cols = ((s.aw / 0.0185) as usize).max(1);
    let cw = s.aw / cols as f32;
    let ch = cw * 1.2;
    let rows = (s.ah / ch) as usize + 1;
    let cells: Vec<usize> = (0..cols * rows).map(|_| s.rng.index(pool.len() as u32)).collect();
    let k = s.span;
    s.canvas.scale(1.0 / k, 1.0 / k);
    for row in 0..rows {
        for col in 0..cols {
            let alpha = 8 + s.rng.index(8) as i32;
            glyph(s, &pool, &cells, cols, cw, ch, k, col, row, alpha, false, &mono, &kana);
        }
    }
    for col in 0..cols {
        if s.rng.float() < 0.12 {
            continue;
        }
        let kind = s.rng.float();
        let power = if kind < 0.18 {
            0.22 + s.rng.float() * 0.18
        } else if kind < 0.78 {
            0.6 + s.rng.float() * 0.25
        } else {
            0.9 + s.rng.float() * 0.1
        };
        let mut head =
            rows as i32 - 1 + s.rng.index(8) as i32 - s.rng.index(((rows as f32 * 0.55) as u32).max(1)) as i32;
        while head > 1 {
            let len = 5 + s.rng.index((rows / 2 + 1) as u32);
            for n in 0..=len {
                let row = head - n as i32;
                if row < 0 {
                    break;
                }
                if row >= rows as i32 {
                    continue;
                }
                let t = 1.0 - n as f32 / len as f32;
                let mut a = 255.0 * power * (t as f64).powf(1.6) as f32 * (0.55 + 0.45 * s.rng.float());
                if n > 0 && s.rng.float() < 0.05 {
                    a *= 1.6;
                }
                if n == 0 {
                    s.canvas.circle(
                        (col as f32 + 0.5) * cw * k,
                        (row as f32 * ch + ch * 0.5) * k,
                        cw * 0.9 * k,
                        &Brush { alpha: (50.0 * power) as i32, ..Brush::default() },
                    );
                    glyph(s, &pool, &cells, cols, cw, ch, k, col, row as usize, 255, true, &mono, &kana);
                } else {
                    glyph(s, &pool, &cells, cols, cw, ch, k, col, row as usize, a as i32, false, &mono, &kana);
                }
            }
            head -= len as i32 + 2 + s.rng.index((rows / 3).max(1) as u32) as i32;
        }
    }
}
