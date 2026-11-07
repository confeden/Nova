//! Android Canvas-equivalent path/gradient composition in pattern coordinates.
use tiny_skia::{
    BlendMode, Color, FillRule, GradientStop, LineCap, LineJoin, Paint, PathBuilder, Pixmap, Point, RadialGradient,
    SpreadMode, Stroke, Transform,
};
#[derive(Clone, Default)]
pub struct Path {
    builder: PathBuilder,
    pub ops: Vec<f32>,
}
impl Path {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn clear(&mut self) {
        self.builder.clear();
        self.ops.clear();
    }
    pub fn move_to(&mut self, x: f32, y: f32) {
        self.builder.move_to(x, y);
        self.ops.extend_from_slice(&[0.0, x, y]);
    }
    pub fn line_to(&mut self, x: f32, y: f32) {
        self.builder.line_to(x, y);
        self.ops.extend_from_slice(&[1.0, x, y]);
    }
    pub fn quad_to(&mut self, x: f32, y: f32, x1: f32, y1: f32) {
        self.builder.quad_to(x, y, x1, y1);
        self.ops.extend_from_slice(&[2.0, x, y, x1, y1]);
    }
    pub fn cubic_to(&mut self, x: f32, y: f32, x1: f32, y1: f32, x2: f32, y2: f32) {
        self.builder.cubic_to(x, y, x1, y1, x2, y2);
        self.ops.extend_from_slice(&[3.0, x, y, x1, y1, x2, y2]);
    }
    pub fn close(&mut self) {
        self.builder.close();
        self.ops.push(4.0);
    }
    pub fn push_circle(&mut self, x: f32, y: f32, r: f32) {
        self.builder.push_circle(x, y, r);
        self.ops.extend_from_slice(&[6.0, x, y, r]);
    }
}

#[derive(serde::Serialize)]
pub struct Event {
    pub kind: &'static str,
    pub values: Vec<f32>,
    pub paint: Option<PaintRecord>,
    pub text: Option<String>,
}
#[derive(serde::Serialize)]
pub struct PaintRecord {
    pub alpha: i32,
    pub width: f32,
    pub stroke: bool,
    pub round_cap: bool,
    pub round_join: bool,
    pub erase: bool,
    pub gradient: Option<Vec<(f32, u8)>>,
}

#[derive(Clone)]
pub struct Brush {
    pub alpha: i32,
    pub width: f32,
    pub stroke: bool,
    pub round_cap: bool,
    pub round_join: bool,
    pub erase: bool,
    pub gradient: Option<Vec<(f32, u8)>>,
}
impl Default for Brush {
    fn default() -> Self {
        Self {
            alpha: 255,
            width: 0.0,
            stroke: false,
            round_cap: false,
            round_join: false,
            erase: false,
            gradient: None,
        }
    }
}
pub struct Canvas {
    pub pixels: Pixmap,
    pub transform: Transform,
    stack: Vec<Transform>,
    pub tracing: bool,
    pub events: Vec<Event>,
    pub base: Option<Vec<u8>>,
}
impl Canvas {
    pub fn new(w: usize, h: usize, span: f32) -> Result<Self, &'static str> {
        Ok(Self {
            pixels: Pixmap::new(w as u32, h as u32).ok_or("invalid surface allocation")?,
            transform: Transform::from_scale(span, span),
            stack: Vec::new(),
            tracing: false,
            events: Vec::new(),
            base: None,
        })
    }
    fn record(&mut self, kind: &'static str, values: Vec<f32>, paint: Option<PaintRecord>, text: Option<String>) {
        if self.tracing {
            if self.base.is_none() {
                self.base = Some(self.alpha());
            }
            self.events.push(Event { kind, values, paint, text });
        }
    }
    pub fn save(&mut self) {
        self.record("save", vec![], None, None);
        self.stack.push(self.transform);
    }
    pub fn restore(&mut self) {
        self.record("restore", vec![], None, None);
        self.transform = self.stack.pop().expect("balanced Android canvas restore");
    }
    pub fn scale(&mut self, x: f32, y: f32) {
        self.record("scale", vec![x, y], None, None);
        self.transform = self.transform.pre_scale(x, y);
    }
    pub fn translate(&mut self, x: f32, y: f32) {
        self.record("translate", vec![x, y], None, None);
        self.transform = self.transform.pre_translate(x, y);
    }
    pub fn rotate(&mut self, angle: f32) {
        self.record("rotate", vec![angle], None, None);
        self.transform = self.transform.pre_rotate(angle);
    }
    pub fn path(&mut self, p: &Path, brush: &Brush) {
        if self.tracing {
            self.record("path", p.ops.clone(), Some(brush.record()), None);
        }
        self.raster(p, brush);
    }
    fn raster(&mut self, p: &Path, brush: &Brush) {
        let Some(path) = p.builder.clone().finish() else { return };
        let mut paint = Paint::default();
        paint.anti_alias = true;
        if let Some(stops) = &brush.gradient {
            let stops =
                stops.iter().map(|(at, a)| GradientStop::new(*at, Color::from_rgba8(255, 255, 255, *a))).collect();
            paint.shader = RadialGradient::new(
                Point::from_xy(0.0, 0.0),
                Point::from_xy(0.0, 0.0),
                1.0,
                stops,
                SpreadMode::Pad,
                Transform::identity(),
            )
            .expect("valid Android radial gradient");
            paint.shader.apply_opacity(brush.alpha.clamp(0, 255) as f32 / 255.0);
        } else {
            paint.set_color_rgba8(255, 255, 255, brush.alpha.clamp(0, 255) as u8);
        }
        if brush.erase {
            paint.blend_mode = BlendMode::DestinationOut;
        }
        if brush.stroke {
            let stroke = Stroke {
                width: brush.width,
                line_cap: if brush.round_cap { LineCap::Round } else { LineCap::Butt },
                line_join: if brush.round_join { LineJoin::Round } else { LineJoin::Miter },
                ..Stroke::default()
            };
            self.pixels.stroke_path(&path, &paint, &stroke, self.transform, None);
        } else {
            self.pixels.fill_path(&path, &paint, FillRule::Winding, self.transform, None);
        }
    }
    pub fn circle(&mut self, x: f32, y: f32, r: f32, brush: &Brush) {
        let mut p = Path::new();
        p.push_circle(x, y, r);
        self.path(&p, brush);
    }
    pub fn line(&mut self, x: f32, y: f32, x1: f32, y1: f32, brush: &Brush) {
        let mut p = Path::new();
        p.move_to(x, y);
        p.line_to(x1, y1);
        self.path(&p, brush);
    }
    pub fn points(&mut self, points: &[(f32, f32)], brush: &Brush) {
        for &(x, y) in points {
            self.circle(x, y, brush.width * 0.5, &Brush { stroke: false, ..brush.clone() });
        }
    }
    pub fn alpha(&self) -> Vec<u8> {
        self.pixels.data().chunks_exact(4).map(|p| p[3]).collect()
    }
    pub fn text(
        &mut self,
        text: &str,
        x: f32,
        y: f32,
        size: f32,
        bold: bool,
        alpha: i32,
        face: &ttf_parser::Face<'_>,
        glyph: ttf_parser::GlyphId,
    ) {
        self.record(
            "text",
            vec![x, y, size, if bold { 1.0 } else { 0.0 }],
            Some(Brush { alpha, ..Brush::default() }.record()),
            Some(text.to_owned()),
        );
        let scale = size / face.units_per_em() as f32;
        let advance = face.glyph_hor_advance(glyph).expect("bundled Android mono advance") as f32 * scale;
        struct Outline {
            path: Path,
            x: f32,
            y: f32,
            scale: f32,
        }
        impl ttf_parser::OutlineBuilder for Outline {
            fn move_to(&mut self, x: f32, y: f32) {
                self.path.move_to(self.x + x * self.scale, self.y - y * self.scale);
            }
            fn line_to(&mut self, x: f32, y: f32) {
                self.path.line_to(self.x + x * self.scale, self.y - y * self.scale);
            }
            fn quad_to(&mut self, x: f32, y: f32, x1: f32, y1: f32) {
                self.path.quad_to(
                    self.x + x * self.scale,
                    self.y - y * self.scale,
                    self.x + x1 * self.scale,
                    self.y - y1 * self.scale,
                );
            }
            fn curve_to(&mut self, x: f32, y: f32, x1: f32, y1: f32, x2: f32, y2: f32) {
                self.path.cubic_to(
                    self.x + x * self.scale,
                    self.y - y * self.scale,
                    self.x + x1 * self.scale,
                    self.y - y1 * self.scale,
                    self.x + x2 * self.scale,
                    self.y - y2 * self.scale,
                );
            }
            fn close(&mut self) {
                self.path.close();
            }
        }
        let mut outline = Outline { path: Path::new(), x: x - advance * 0.5, y, scale };
        face.outline_glyph(glyph, &mut outline).expect("bundled Android matrix outline");
        let brush = Brush { alpha, ..Brush::default() };
        self.raster(&outline.path, &brush);
        if bold {
            self.raster(&outline.path, &Brush { alpha, width: size / 24.0, stroke: true, ..Brush::default() });
        }
    }
    pub fn bitmap(&mut self, pixmap: &Pixmap, x: f32, y: f32, alpha: i32, text: &str) {
        self.record(
            "bitmap",
            vec![x, y, pixmap.width() as f32, pixmap.height() as f32],
            Some(Brush { alpha, ..Brush::default() }.record()),
            Some(text.to_owned()),
        );
        let paint = tiny_skia::PixmapPaint {
            opacity: alpha.clamp(0, 255) as f32 / 255.0,
            quality: tiny_skia::FilterQuality::Nearest,
            ..tiny_skia::PixmapPaint::default()
        };
        self.pixels.draw_pixmap(0, 0, pixmap.as_ref(), &paint, self.transform.pre_translate(x, y), None);
    }
}
impl Brush {
    fn record(&self) -> PaintRecord {
        PaintRecord {
            alpha: self.alpha.clamp(0, 255),
            width: if self.stroke { self.width } else { 0.0 },
            stroke: self.stroke,
            round_cap: self.stroke && self.round_cap,
            round_join: self.stroke && self.round_join,
            erase: self.erase,
            gradient: self.gradient.clone(),
        }
    }
}

pub fn oval(path: &mut Path, cx: f32, cy: f32, rx: f32, ry: f32, angle: f32) {
    let rect = tiny_skia::Rect::from_ltrb(-rx, -ry, rx, ry).expect("positive Android oval radii");
    let p = PathBuilder::from_oval(rect)
        .expect("valid oval")
        .transform(Transform::from_rotate(angle).post_translate(cx, cy))
        .expect("valid oval transform");
    path.builder.push_path(&p);
    path.ops.extend_from_slice(&[5.0, cx, cy, rx, ry, angle]);
}
