//! Native port of the approved GPU light-lab pipeline (kb light-lab.md, "Porting to Nova").
//!
//! The shaders in `gpu/shaders` are the single source of truth shared with the lab page and
//! Android; this crate only wraps them. Pipeline per frame, exactly as the page's `draw()`:
//! scene pass (texture shader, MRT RGBA16F: s0 = emission+density with mips, s1 = albedo+height)
//! -> 5 radiance cascades ping-pong on a grid that follows the surface aspect -> composite into
//! RGBA8 -> readback as RGB8 top-down.

mod context;
mod renderer;
mod shm;

pub use context::GlContext;
pub use renderer::{FrameInfo, Renderer};
pub use shm::{process_cpu_seconds, FrameMap, Pacer};

/// Number of radiance cascades (manifest `cascades`).
pub const CASCADES: i32 = 5;
/// Cascade grid width; height follows the surface aspect (square texels).
pub const GRID_W: u32 = 768;
/// Longest side of the scene, as the page caps its canvas.
pub const SCENE_CAP: u32 = 1440;

pub(crate) const VS: &str = include_str!("../../../../gpu/shaders/vs.glsl");
pub(crate) const HEAD: &str = include_str!("../../../../gpu/shaders/head.glsl");
pub(crate) const TAIL: &str = include_str!("../../../../gpu/shaders/tail.glsl");
pub(crate) const CASC: &str = include_str!("../../../../gpu/shaders/casc.glsl");
pub(crate) const COMP: &str = include_str!("../../../../gpu/shaders/comp.glsl");
pub(crate) const FX: &str = include_str!("../../../../gpu/shaders/fx.glsl");
pub(crate) const MANIFEST: &str = include_str!("../../../../gpu/manifest.json");
/// Matrix glyph atlas, 384x256 R8, row 0 at the top (gpu/make_atlas.py).
pub(crate) const ATLAS: &[u8] = include_bytes!("../../../../gpu/atlas_matrix.r8");
pub(crate) const ATLAS_W: i32 = 384;
pub(crate) const ATLAS_H: i32 = 256;

/// Texture id -> body shader (HEAD + body + TAIL is the full fragment shader, like `getProg`).
pub const TEXTURES: [(&str, &str); 21] = [
    ("basalt", include_str!("../../../../gpu/shaders/tex/basalt.glsl")),
    ("marble", include_str!("../../../../gpu/shaders/tex/marble.glsl")),
    ("wood", include_str!("../../../../gpu/shaders/tex/wood.glsl")),
    ("sand", include_str!("../../../../gpu/shaders/tex/sand.glsl")),
    ("grass", include_str!("../../../../gpu/shaders/tex/grass.glsl")),
    ("cracks", include_str!("../../../../gpu/shaders/tex/cracks.glsl")),
    ("water", include_str!("../../../../gpu/shaders/tex/water.glsl")),
    ("ether", include_str!("../../../../gpu/shaders/tex/ether.glsl")),
    ("aurora", include_str!("../../../../gpu/shaders/tex/aurora.glsl")),
    ("smoke", include_str!("../../../../gpu/shaders/tex/smoke.glsl")),
    ("starfield", include_str!("../../../../gpu/shaders/tex/starfield.glsl")),
    ("constellation", include_str!("../../../../gpu/shaders/tex/constellation.glsl")),
    ("slime", include_str!("../../../../gpu/shaders/tex/slime.glsl")),
    ("rain", include_str!("../../../../gpu/shaders/tex/rain.glsl")),
    ("lightning", include_str!("../../../../gpu/shaders/tex/lightning.glsl")),
    ("snow", include_str!("../../../../gpu/shaders/tex/snow.glsl")),
    ("fractal", include_str!("../../../../gpu/shaders/tex/fractal.glsl")),
    ("fractal2", include_str!("../../../../gpu/shaders/tex/fractal2.glsl")),
    ("maze", include_str!("../../../../gpu/shaders/tex/maze.glsl")),
    ("matrix", include_str!("../../../../gpu/shaders/tex/matrix.glsl")),
    ("warp", include_str!("../../../../gpu/shaders/tex/warp.glsl")),
];

/// Texture ids in manifest order.
pub fn texture_ids() -> impl Iterator<Item = &'static str> {
    TEXTURES.iter().map(|(id, _)| *id)
}

pub(crate) fn texture_body(id: &str) -> Option<&'static str> {
    TEXTURES.iter().find(|(k, _)| *k == id).map(|(_, s)| *s)
}

/// Emission gain per texture from the manifest (`GAIN[key]||1` in the page).
pub fn gain(id: &str) -> f32 {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap_or_default();
    manifest["gain"][id].as_f64().map(|g| g as f32).filter(|g| *g != 0.0).unwrap_or(1.0)
}

/// Frame parameters, in the lab's units.
#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub texture: String,
    pub seed: f32,
    /// 0..63, one of 64 hues; 31 = the default teal.
    pub accent: u32,
    /// 0..100 (`sInt`, default 90).
    pub intensity: f32,
    /// 0..200 in the lab, 100 default (`sGlow`).
    pub glow: f32,
    /// 0..100 (`sPtr`, default 50); the shader gets value/50.
    pub warp: f32,
    /// Animation time in seconds.
    pub t: f32,
    /// Saturation percent, 0..200, 100 = unchanged (`uSatD` = sat/100 - 1 in comp.glsl).
    pub sat: f32,
    /// Slowly drifting second hue (see `palette_at`); off = the plain accent-only palette.
    pub drift: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self { texture: "fractal".into(), seed: 0.0, accent: 31, intensity: 90.0, glow: 100.0, warp: 50.0, t: 20.0, sat: 100.0, drift: false }
    }
}

/// The shader colours derived from one accent hue, already linear (`lin` = pow 2.2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Palette {
    pub bg0: [f32; 3],
    pub bg1: [f32; 3],
    pub bg2: [f32; 3],
    pub a: [f32; 3],
    pub b: [f32; 3],
    pub c: [f32; 3],
}

/// The page's `hsl(h,s,l)`, h in turns.
pub fn hsl(h: f64, s: f64, l: f64) -> [f64; 3] {
    let h = ((h % 1.0) + 1.0) % 1.0;
    let f = |n: f64| {
        let k = (n + h * 12.0) % 12.0;
        let a = s * l.min(1.0 - l);
        l - a * (-1.0f64).max((k - 3.0).min(9.0 - k).min(1.0))
    };
    [f(0.0), f(8.0), f(4.0)]
}

/// The page's `hue(c,deg)`: luminance-preserving hue rotation matrix, clamped.
pub fn hue_rotate(c: [f64; 3], deg: f64) -> [f64; 3] {
    let a = deg * std::f64::consts::PI / 180.0;
    let (cs, sn) = (a.cos(), a.sin());
    let k: f64 = 1.0 / 3.0;
    let q = k.sqrt();
    let m = [cs + (1.0 - cs) * k, k * (1.0 - cs) - q * sn, k * (1.0 - cs) + q * sn];
    [
        c[0] * m[0] + c[1] * m[1] + c[2] * m[2],
        c[0] * m[2] + c[1] * m[0] + c[2] * m[1],
        c[0] * m[1] + c[1] * m[2] + c[2] * m[0],
    ]
    .map(|v| v.clamp(0.0, 1.0))
}

fn lin(c: [f64; 3]) -> [f32; 3] {
    c.map(|v| v.powf(2.2) as f32)
}

/// Period of the opposite colour's swing, seconds of animation clock.
pub const DRIFT_C_PERIOD_S: f64 = 90.0;
/// Period of the secondary colour's swing (not a multiple of the other, so they never lock).
pub const DRIFT_B_PERIOD_S: f64 = 130.0;

/// Hue rotation of `uC` against the accent in degrees: 150 +- 55, i.e. always 95..205.
pub fn drift_c_degrees(t: f64) -> f64 {
    150.0 + 55.0 * (std::f64::consts::TAU * t / DRIFT_C_PERIOD_S).sin()
}

/// Hue offset of `uB` against the accent in turns: -.07 +- .03.
pub fn drift_b_offset(t: f64) -> f64 {
    -0.07 + 0.03 * (std::f64::consts::TAU * t / DRIFT_B_PERIOD_S + 1.0).sin()
}

/// The page's `setAccent(i)`.
pub fn palette(accent: u32) -> Palette {
    palette_at(accent, false, 0.0)
}

/// `palette` with the optional slow drift of the second hues. `t` is the engine animation clock
/// (it honours `speed` and stands still when animation is off), so a still picture never changes.
/// `drift = false` is exactly `palette(accent)`; the background tint never drifts.
pub fn palette_at(accent: u32, drift: bool, t: f64) -> Palette {
    let h = f64::from(accent.min(63)) / 64.0;
    let a = hsl(h, 0.68, 0.56);
    let (b_off, c_deg) = if drift { (drift_b_offset(t), drift_c_degrees(t)) } else { (-0.07, 150.0) };
    let b = hsl(h + b_off, 0.55, 0.78);
    Palette {
        bg0: lin(hsl(h, 0.3, 0.045)),
        bg1: lin(hsl(h, 0.3, 0.06)),
        bg2: lin(hsl(h, 0.3, 0.085)),
        a: lin(a),
        b: lin(b),
        c: lin(hue_rotate(a, c_deg)),
    }
}

/// Scene size for a surface of `w`x`h` px: longest side capped at 1440, floor 64x48 (page `resize`).
pub fn scene_size(w: u32, h: u32) -> (u32, u32) {
    let (w, h) = (f64::from(w.max(1)), f64::from(h.max(1)));
    let k = (f64::from(SCENE_CAP) / w.max(h)).min(1.0);
    (((w * k).round() as u32).max(64), ((h * k).round() as u32).max(48))
}

/// Cascade grid for a scene: width 768, height follows the surface aspect (square texels).
pub fn cascade_grid(sw: u32, sh: u32) -> (u32, u32) {
    let ch = (f64::from(GRID_W) * f64::from(sh) / f64::from(sw.max(1))).round() as u32;
    (GRID_W, ch.max(1))
}

/// Replace the ES header by the desktop one; the rest of the source is untouched.
pub(crate) fn desktop_glsl(src: &str) -> String {
    let lf = char::from(10u8);
    let rest = match src.find(lf) {
        Some(i) if src[..i].trim() == "#version 300 es" => &src[i..],
        _ => return src.to_owned(),
    };
    let mut out = String::with_capacity(src.len() + 8);
    out.push_str("#version 330 core");
    out.push_str(rest);
    out
}

/// Encode a top-down RGB8 frame as a binary PPM (P6).
pub fn encode_ppm(w: u32, h: u32, rgb: &[u8]) -> Vec<u8> {
    let lf = 10u8;
    let mut out = Vec::with_capacity(rgb.len() + 32);
    out.extend_from_slice(b"P6");
    out.push(lf);
    out.extend_from_slice(format!("{w} {h}").as_bytes());
    out.push(lf);
    out.extend_from_slice(b"255");
    out.push(lf);
    out.extend_from_slice(rgb);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb8(c: [f32; 3]) -> [u32; 3] {
        // back to sRGB-ish 0..255 so the expectation reads like the page's CSS accent
        c.map(|v| (f64::from(v).powf(1.0 / 2.2) * 255.0).round() as u32)
    }

    #[test]
    fn accent_31_matches_the_page_formulas() {
        // Reference values computed separately with a Python transcription of the page's JS
        // (hsl/hue/setAccent), before the pow(c,2.2): accent = #43dbcd.
        let p = palette(31);
        assert_eq!(rgb8(p.a), [0x43, 0xdb, 0xcd]);
        assert_eq!(rgb8(p.b), [0xa8, 0xe6, 0xc6]);
        assert_eq!(rgb8(p.bg1), [0x0b, 0x14, 0x13]);
        assert_eq!(rgb8(p.c), [0xf3, 0x4b, 0xac]);
        let close = |got: [f32; 3], want: [f64; 3]| {
            for i in 0..3 {
                assert!((f64::from(got[i]) - want[i].powf(2.2)).abs() < 1e-5, "{got:?} vs {want:?}");
            }
        };
        close(p.a, [0.2608, 0.8592, 0.8031]);
        close(p.b, [0.659, 0.901, 0.7766725]);
        close(p.bg1, [0.042, 0.078, 0.074625]);
        close(p.c, [0.9541303843148674, 0.2955469322502614, 0.6734226834348713]);
    }

    fn hue_deg(c: [f32; 3]) -> f64 {
        let v = c.map(|x| f64::from(x).powf(1.0 / 2.2));
        let (mx, mn) = (v[0].max(v[1]).max(v[2]), v[0].min(v[1]).min(v[2]));
        let d = mx - mn;
        let h = if d == 0.0 {
            0.0
        } else if mx == v[0] {
            ((v[1] - v[2]) / d).rem_euclid(6.0)
        } else if mx == v[1] {
            (v[2] - v[0]) / d + 2.0
        } else {
            (v[0] - v[1]) / d + 4.0
        };
        h * 60.0
    }

    fn hue_dist(a: f64, b: f64) -> f64 {
        let d = (a - b).rem_euclid(360.0);
        d.min(360.0 - d)
    }

    #[test]
    fn drift_off_is_the_plain_palette() {
        for acc in [0, 7, 31, 63] {
            for t in [0.0, 13.7, 500.0] {
                assert_eq!(palette_at(acc, false, t), palette(acc));
            }
        }
    }

    #[test]
    fn drift_moves_b_and_c_but_not_a_or_bg() {
        let (p0, p1) = (palette_at(31, true, 10.0), palette_at(31, true, 30.0));
        assert_ne!(p0.c, p1.c);
        assert_ne!(p0.b, p1.b);
        assert_eq!((p0.a, p0.bg0, p0.bg1, p0.bg2), (p1.a, p1.bg0, p1.bg1, p1.bg2));
        assert_eq!(palette_at(31, true, 12.0), palette_at(31, true, 12.0));
    }

    #[test]
    fn drift_keeps_c_far_from_the_accent() {
        assert!((drift_c_degrees(90.0 / 4.0) - 205.0).abs() < 1e-9);
        assert!((drift_c_degrees(3.0 * 90.0 / 4.0) - 95.0).abs() < 1e-9);
        for acc in [0, 9, 20, 31, 45, 63] {
            let (mut lo, mut hi) = (f64::MAX, 0.0f64);
            for i in 0..200 {
                let t = f64::from(i) * 0.9 + 0.3;
                let d = drift_c_degrees(t);
                assert!((95.0 - 1e-9..=205.0 + 1e-9).contains(&d), "{d}");
                assert!((-0.1 - 1e-9..=-0.04 + 1e-9).contains(&drift_b_offset(t)));
                let p = palette_at(acc, true, t);
                let dist = hue_dist(hue_deg(p.a), hue_deg(p.c));
                lo = lo.min(dist);
                hi = hi.max(dist);
            }
            // the rotation is applied in RGB (luma-preserving), so the measured HSV hue follows it loosely
            assert!(lo > 80.0 && hi < 215.0, "accent {acc}: measured hue distance {lo}..{hi}");
        }
    }

    #[test]
    fn drift_actually_changes_c_over_twenty_seconds() {
        let (a, b) = (palette_at(31, true, 5.0), palette_at(31, true, 25.0));
        assert!(hue_dist(hue_deg(a.c), hue_deg(b.c)) > 5.0);
    }

    #[test]
    fn hsl_primaries() {
        let r = hsl(0.0, 1.0, 0.5);
        assert!((r[0] - 1.0).abs() < 1e-12 && r[1].abs() < 1e-12 && r[2].abs() < 1e-12);
        let g = hsl(1.0 / 3.0 - 1.0, 1.0, 0.5);
        assert!(g[0].abs() < 1e-9 && (g[1] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn grid_follows_surface_aspect() {
        assert_eq!(cascade_grid(672, 504), (768, 576));
        assert_eq!(cascade_grid(1000, 700), (768, 538));
        assert_eq!(cascade_grid(1920, 1080), (768, 432));
        assert_eq!(scene_size(1920, 1080), (1440, 810));
        assert_eq!(scene_size(672, 504), (672, 504));
        assert_eq!(scene_size(10, 10), (64, 48));
        let (sw, sh) = scene_size(2560, 1440);
        assert_eq!((sw, sh), (1440, 810));
        assert_eq!(cascade_grid(sw, sh), (768, 432));
    }

    #[test]
    fn header_swap_only_touches_the_first_line() {
        let src = format!("#version 300 es{}precision highp float;", char::from(10u8));
        let out = desktop_glsl(&src);
        assert!(out.starts_with("#version 330 core"));
        assert!(out.ends_with("precision highp float;"));
        assert_eq!(desktop_glsl(VS).lines().count(), VS.lines().count());
        for (id, body) in TEXTURES {
            assert!(!body.contains("#version"), "{id}");
            assert!(gain(id) > 0.0);
        }
        assert_eq!(gain("snow"), 1.5);
        assert_eq!(ATLAS.len(), (ATLAS_W * ATLAS_H) as usize);
    }

    #[test]
    fn ppm_header() {
        let p = encode_ppm(2, 1, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&p[..11], b"P6\n2 1\n255\n");
        assert_eq!(p.len(), 17);
    }
}
