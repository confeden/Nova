//! The lab's `draw()` ported 1:1: scene MRT -> mips -> radiance cascades -> composite -> readback.

use std::collections::HashMap;

use glow::HasContext;

use crate::{
    cascade_grid, desktop_glsl, gain, palette_at, scene_size, texture_body, GlContext, Params, ATLAS, ATLAS_H,
    ATLAS_W, CASC, CASCADES, COMP, FX, HEAD, TAIL, VS,
};

/// What a returned frame is: its size (RGB8 top-down, stride w*3) and the GPU time it took.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrameInfo {
    pub w: u32,
    pub h: u32,
    pub gpu_ms: Option<f64>,
}

struct Prog {
    p: glow::Program,
    u: HashMap<&'static str, Option<glow::UniformLocation>>,
}

fn loc(gl: &glow::Context, prog: &mut Prog, name: &'static str) -> Option<glow::UniformLocation> {
    prog.u.entry(name).or_insert_with(|| unsafe { gl.get_uniform_location(prog.p, name) }).clone()
}

struct Slot {
    pbo: glow::Buffer,
    cap: usize,
    query: glow::Query,
    w: u32,
    h: u32,
    busy: bool,
}

/// Panel overlay textures: RGBA8 straight alpha plus an optional R8 glass mask (255 = fully frosted).
struct Overlay {
    tex: glow::Texture,
    mask: Option<glow::Texture>,
}

/// Hover glow state. `phase` is the linear progress 0..1 of the fade; strength = smoothstep(phase).
#[derive(Clone, Copy, Debug)]
struct Hot {
    /// l, t, r, b in frame px, top-down (remembered while fading out)
    rect: [f32; 4],
    radius: f32,
    reach: Option<f32>,
    color: Option<[f32; 3]>,
    on: bool,
    phase: f32,
}

const HOT_IN_S: f32 = 0.16;
const HOT_OUT_S: f32 = 0.28;

impl Hot {
    fn strength(&self) -> f32 {
        let p = self.phase.clamp(0.0, 1.0);
        p * p * (3.0 - 2.0 * p)
    }
}

/// Hue (turns) of an RGB colour, 0 for greys.
fn hue_of(c: [f32; 3]) -> f32 {
    let (mx, mn) = (c[0].max(c[1]).max(c[2]), c[0].min(c[1]).min(c[2]));
    let d = mx - mn;
    if d < 1e-6 {
        return 0.0;
    }
    let h = if mx == c[0] {
        ((c[1] - c[2]) / d).rem_euclid(6.0)
    } else if mx == c[1] {
        (c[2] - c[0]) / d + 2.0
    } else {
        (c[0] - c[1]) / d + 4.0
    };
    h / 6.0
}

/// Owns the GL context and the whole pipeline. Lives on the thread that created the context.
pub struct Renderer {
    ctx: GlContext,
    _vao: glow::VertexArray,
    casc: Prog,
    comp: Prog,
    over: Prog,
    fx: Prog,
    /// panel overlay, RGBA8 straight alpha, exactly the frame size; None = no extra pass
    overlay: Option<Overlay>,
    /// copy of the composited frame with a full mip chain (glass blur, halo luma); lazy, freed on resize
    blur: Option<glow::Texture>,
    hot: Hot,
    /// clock of the hover shimmer, seconds (set by the caller; never jumps)
    fx_t: f32,
    progs: HashMap<String, Result<Prog, String>>,
    atlas: glow::Texture,
    s0: Option<glow::Texture>,
    s1: Option<glow::Texture>,
    cas: Option<[glow::Texture; 2]>,
    out: Option<glow::Texture>,
    fb_scene: glow::Framebuffer,
    fb_cas: glow::Framebuffer,
    fb_out: glow::Framebuffer,
    sw: u32,
    sh: u32,
    cw: u32,
    ch: u32,
    slots: [Slot; 2],
    next: usize,
    scratch: Vec<u8>,
    /// eased pointer position + strength (`st.ptr`), and the real pointer (`st.tgt`)
    ptr: [f32; 3],
    tgt: [f32; 2],
    ptr_in: bool,
}

unsafe fn compile(gl: &glow::Context, fs: &str, name: &str) -> Result<glow::Program, String> {
    unsafe {
        let p = gl.create_program()?;
        let mut shaders = Vec::new();
        for (kind, src) in [(glow::VERTEX_SHADER, VS), (glow::FRAGMENT_SHADER, fs)] {
            let s = gl.create_shader(kind)?;
            gl.shader_source(s, &desktop_glsl(src));
            gl.compile_shader(s);
            if !gl.get_shader_compile_status(s) {
                let log = gl.get_shader_info_log(s);
                gl.delete_shader(s);
                for s in shaders {
                    gl.delete_shader(s);
                }
                gl.delete_program(p);
                let stage = if kind == glow::VERTEX_SHADER { "vertex" } else { "fragment" };
                return Err(format!("shader {name} ({stage}): {}", log.trim()));
            }
            gl.attach_shader(p, s);
            shaders.push(s);
        }
        gl.link_program(p);
        for s in shaders {
            gl.detach_shader(p, s);
            gl.delete_shader(s);
        }
        if !gl.get_program_link_status(p) {
            let log = gl.get_program_info_log(p);
            gl.delete_program(p);
            return Err(format!("program {name}: {}", log.trim()));
        }
        Ok(p)
    }
}

unsafe fn mk_tex(
    gl: &glow::Context,
    w: u32,
    h: u32,
    levels: i32,
    mip: bool,
    fmt: u32,
) -> Result<glow::Texture, String> {
    unsafe {
        let t = gl.create_texture()?;
        gl.bind_texture(glow::TEXTURE_2D, Some(t));
        gl.tex_storage_2d(glow::TEXTURE_2D, levels, fmt, w as i32, h as i32);
        let min = if mip { glow::LINEAR_MIPMAP_LINEAR } else { glow::LINEAR };
        gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MIN_FILTER, min as i32);
        gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MAG_FILTER, glow::LINEAR as i32);
        gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE as i32);
        gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE as i32);
        Ok(t)
    }
}

/// Overlay pass: fetch the top-down overlay texel for this pixel; blending does the maths.
const OVERLAY_FS: &str = "#version 330 core
uniform sampler2D uOv;
uniform int uH;
out vec4 o;
void main(){ivec2 p=ivec2(gl_FragCoord.xy);o=texelFetch(uOv,ivec2(p.x,uH-1-p.y),0);}
";

fn hsl_f32(h: f64, s: f64, l: f64) -> [f32; 3] {
    crate::hsl(h, s, l).map(|v| v as f32)
}

fn delete_overlay(gl: &glow::Context, o: Overlay) {
    unsafe {
        gl.delete_texture(o.tex);
        if let Some(m) = o.mask {
            gl.delete_texture(m);
        }
    }
}

fn levels_for(w: u32, h: u32) -> i32 {
    // Math.floor(Math.log2(Math.max(SW,SH)))+1
    (31 - w.max(h).max(1).leading_zeros()) as i32 + 1
}

impl Renderer {
    /// Build the fixed part of the pipeline (cascade + composite programs, atlas, FBOs, PBOs).
    pub fn new(ctx: GlContext) -> Result<Renderer, String> {
        unsafe {
            let gl = ctx.gl();
            let vao = gl.create_vertex_array()?;
            gl.bind_vertex_array(Some(vao));
            let casc = Prog { p: compile(gl, CASC, "casc")?, u: HashMap::new() };
            let comp = Prog { p: compile(gl, COMP, "comp")?, u: HashMap::new() };
            let over = Prog { p: compile(gl, OVERLAY_FS, "overlay")?, u: HashMap::new() };
            let fx = Prog { p: compile(gl, FX, "fx")?, u: HashMap::new() };

            let atlas = gl.create_texture()?;
            gl.active_texture(glow::TEXTURE3);
            gl.bind_texture(glow::TEXTURE_2D, Some(atlas));
            gl.pixel_store_i32(glow::UNPACK_ALIGNMENT, 1);
            gl.tex_image_2d(
                glow::TEXTURE_2D,
                0,
                glow::R8 as i32,
                ATLAS_W,
                ATLAS_H,
                0,
                glow::RED,
                glow::UNSIGNED_BYTE,
                glow::PixelUnpackData::Slice(Some(ATLAS)),
            );
            gl.generate_mipmap(glow::TEXTURE_2D);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MIN_FILTER, glow::LINEAR_MIPMAP_LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MAG_FILTER, glow::LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE as i32);
            gl.active_texture(glow::TEXTURE0);
            gl.pixel_store_i32(glow::PACK_ALIGNMENT, 1);

            let slot = |gl: &glow::Context| -> Result<Slot, String> {
                Ok(Slot { pbo: gl.create_buffer()?, cap: 0, query: gl.create_query()?, w: 0, h: 0, busy: false })
            };
            let slots = [slot(gl)?, slot(gl)?];
            let (fb_scene, fb_cas, fb_out) =
                (gl.create_framebuffer()?, gl.create_framebuffer()?, gl.create_framebuffer()?);
            let mut r = Renderer {
                _vao: vao,
                casc,
                comp,
                over,
                fx,
                overlay: None,
                blur: None,
                hot: Hot { rect: [0.0; 4], radius: 0.0, reach: None, color: None, on: false, phase: 0.0 },
                fx_t: 0.0,
                progs: HashMap::new(),
                atlas,
                s0: None,
                s1: None,
                cas: None,
                out: None,
                fb_scene,
                fb_cas,
                fb_out,
                sw: 0,
                sh: 0,
                cw: 0,
                ch: 0,
                slots,
                next: 0,
                scratch: Vec::new(),
                ptr: [0.0; 3],
                tgt: [0.0; 2],
                ptr_in: false,
                ctx,
            };
            r.set_size(640, 480)?;
            Ok(r)
        }
    }

    pub fn gl_renderer(&self) -> &str {
        self.ctx.renderer()
    }

    pub fn gl_version(&self) -> &str {
        self.ctx.version()
    }

    /// Output (= scene) size in px.
    pub fn frame_size(&self) -> (u32, u32) {
        (self.sw, self.sh)
    }

    /// Cascade grid in texels.
    pub fn grid(&self) -> (u32, u32) {
        (self.cw, self.ch)
    }

    /// Follow a surface of `w`x`h` client px: scene = client px capped at 1440, grid = surface aspect.
    pub fn set_size(&mut self, w: u32, h: u32) -> Result<(), String> {
        let (sw, sh) = scene_size(w, h);
        let (cw, ch) = cascade_grid(sw, sh);
        let gl = self.ctx.gl();
        unsafe {
            if (sw, sh) != (self.sw, self.sh) {
                for t in [self.s0.take(), self.s1.take(), self.out.take(), self.blur.take()].into_iter().flatten() {
                    gl.delete_texture(t);
                }
                let s0 = mk_tex(gl, sw, sh, levels_for(sw, sh), true, glow::RGBA16F)?;
                let s1 = mk_tex(gl, sw, sh, 1, false, glow::RGBA16F)?;
                let out = mk_tex(gl, sw, sh, 1, false, glow::RGBA8)?;
                gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fb_scene));
                gl.framebuffer_texture_2d(
                    glow::FRAMEBUFFER,
                    glow::COLOR_ATTACHMENT0,
                    glow::TEXTURE_2D,
                    Some(s0),
                    0,
                );
                gl.framebuffer_texture_2d(
                    glow::FRAMEBUFFER,
                    glow::COLOR_ATTACHMENT1,
                    glow::TEXTURE_2D,
                    Some(s1),
                    0,
                );
                gl.draw_buffers(&[glow::COLOR_ATTACHMENT0, glow::COLOR_ATTACHMENT1]);
                let st = gl.check_framebuffer_status(glow::FRAMEBUFFER);
                if st != glow::FRAMEBUFFER_COMPLETE {
                    return Err(format!("scene framebuffer incomplete: 0x{st:x}"));
                }
                gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fb_out));
                gl.framebuffer_texture_2d(
                    glow::FRAMEBUFFER,
                    glow::COLOR_ATTACHMENT0,
                    glow::TEXTURE_2D,
                    Some(out),
                    0,
                );
                let st = gl.check_framebuffer_status(glow::FRAMEBUFFER);
                if st != glow::FRAMEBUFFER_COMPLETE {
                    return Err(format!("output framebuffer incomplete: 0x{st:x}"));
                }
                gl.bind_framebuffer(glow::FRAMEBUFFER, None);
                (self.s0, self.s1, self.out, self.sw, self.sh) = (Some(s0), Some(s1), Some(out), sw, sh);
                // a stale overlay is never stretched: drop it until one of the new size arrives
                if let Some(o) = self.overlay.take() {
                    delete_overlay(gl, o);
                }
            }
            if (cw, ch) != (self.cw, self.ch) || self.cas.is_none() {
                if let Some(c) = self.cas.take() {
                    c.into_iter().for_each(|t| gl.delete_texture(t));
                }
                self.cas = Some([
                    mk_tex(gl, cw, ch, 1, false, glow::RGBA16F)?,
                    mk_tex(gl, cw, ch, 1, false, glow::RGBA16F)?,
                ]);
                (self.cw, self.ch) = (cw, ch);
            }
        }
        Ok(())
    }

    /// The real pointer moved (lab coordinates: height 1, centred, y up), as the page's `ptr()`
    /// and `pointerleave` handlers.
    pub fn set_pointer(&mut self, x: f32, y: f32, inside: bool) {
        if inside {
            self.tgt = [x, y];
            if !self.ptr_in && self.ptr[2] < 0.02 {
                self.ptr[0] = x;
                self.ptr[1] = y;
            }
        }
        self.ptr_in = inside;
    }

    /// The page's `moving` test: the eased pointer has not reached its target yet.
    pub fn pointer_moving(&self) -> bool {
        let target = if self.ptr_in { 1.0 } else { 0.0 };
        (self.ptr[2] - target).abs() > 0.002
            || (self.ptr[2] > 0.002 && (self.tgt[0] - self.ptr[0]).hypot(self.tgt[1] - self.ptr[1]) > 0.0005)
    }

    /// Advance the pointer easing by `dt` seconds (the page's frame(): strength dt*5, position dt*7).
    pub fn step_pointer(&mut self, dt: f32) {
        let target = if self.ptr_in { 1.0 } else { 0.0 };
        self.ptr[2] += (target - self.ptr[2]) * (dt * 5.0).min(1.0);
        let f = (dt * 7.0).min(1.0);
        self.ptr[0] += (self.tgt[0] - self.ptr[0]) * f;
        self.ptr[1] += (self.tgt[1] - self.ptr[1]) * f;
    }

/// Install a panel overlay: `rgba` is RGBA8 straight alpha, top-down, exactly w*h*4 bytes, and
/// w x h must equal `frame_size()` (no stretching).
pub fn set_overlay(&mut self, w: u32, h: u32, rgba: &[u8]) -> Result<(), String> {
    self.set_overlay_glass(w, h, rgba, None)
}

/// Like `set_overlay`, plus an optional glass mask: w*h bytes (R8, top-down, 255 = fully frosted)
/// that make the plate show a blurred, grained copy of the texture instead of the sharp one.
pub fn set_overlay_glass(
    &mut self,
    w: u32,
    h: u32,
    rgba: &[u8],
    mask: Option<&[u8]>,
) -> Result<(), String> {
    if (w, h) != (self.sw, self.sh) {
        return Err(format!(
            "overlay {w}x{h} does not match the frame {}x{}",
            self.sw, self.sh
        ));
    }
    if rgba.len() != (w * h * 4) as usize {
        return Err(format!(
            "overlay has {} bytes, want {}",
            rgba.len(),
            w * h * 4
        ));
    }
    if let Some(m) = mask {
        if m.len() != (w * h) as usize {
            return Err(format!("glass mask has {} bytes, want {}", m.len(), w * h));
        }
    }
    self.clear_overlay();
    let gl = self.ctx.gl();
    unsafe {
        let tex = gl.create_texture()?;
        gl.active_texture(glow::TEXTURE4);
        gl.bind_texture(glow::TEXTURE_2D, Some(tex));
        gl.tex_image_2d(
            glow::TEXTURE_2D,
            0,
            glow::RGBA8 as i32,
            w as i32,
            h as i32,
            0,
            glow::RGBA,
            glow::UNSIGNED_BYTE,
            glow::PixelUnpackData::Slice(Some(rgba)),
        );
        gl.tex_parameter_i32(
            glow::TEXTURE_2D,
            glow::TEXTURE_MIN_FILTER,
            glow::NEAREST as i32,
        );
        gl.tex_parameter_i32(
            glow::TEXTURE_2D,
            glow::TEXTURE_MAG_FILTER,
            glow::NEAREST as i32,
        );
        let mut mtex = None;
        if let Some(m) = mask {
            let mt = gl.create_texture()?;
            gl.active_texture(glow::TEXTURE5);
            gl.bind_texture(glow::TEXTURE_2D, Some(mt));
            gl.tex_image_2d(
                glow::TEXTURE_2D,
                0,
                glow::R8 as i32,
                w as i32,
                h as i32,
                0,
                glow::RED,
                glow::UNSIGNED_BYTE,
                glow::PixelUnpackData::Slice(Some(m)),
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MIN_FILTER,
                glow::NEAREST as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MAG_FILTER,
                glow::NEAREST as i32,
            );
            mtex = Some(mt);
        }
        gl.active_texture(glow::TEXTURE0);
        self.overlay = Some(Overlay { tex, mask: mtex });
    }
    Ok(())
}

/// Remove the panel overlay (the extra pass disappears with it; the blur copy too unless hover needs it).
pub fn clear_overlay(&mut self) {
    if let Some(o) = self.overlay.take() {
        delete_overlay(self.ctx.gl(), o);
    }
    self.free_blur_if_unused();
}

pub fn has_overlay(&self) -> bool {
    self.overlay.is_some()
}

/// True when the overlay carries a glass mask.
pub fn has_glass(&self) -> bool {
    self.overlay.as_ref().is_some_and(|o| o.mask.is_some())
}

fn free_blur_if_unused(&mut self) {
    if !self.has_glass() && !self.hot_active() {
        if let Some(t) = self.blur.take() {
            unsafe { self.ctx.gl().delete_texture(t) }
        }
    }
}

/// Hover glow on a rounded rect (frame px, top-down, same space as the overlay). `on=false` fades
/// out and keeps the remembered rect; `rect` may then be None. `color` 0..1 display space (None =
/// the current accent); `reach` in px (None = 7% of the short side, 26..60).
pub fn set_hot(
    &mut self,
    rect: Option<[f32; 4]>,
    radius: f32,
    reach: Option<f32>,
    color: Option<[f32; 3]>,
    on: bool,
) {
    if let Some(r) = rect {
        self.hot.rect = r;
        self.hot.radius = radius.max(0.0);
        self.hot.reach = reach.filter(|v| *v > 0.5);
        self.hot.color = color;
    }
    self.hot.on = on;
}

/// Hover glow is visible or about to be: the caller keeps producing frames while this holds.
pub fn hot_active(&self) -> bool {
    self.hot.on || self.hot.phase > 0.0
}

/// Advance the hover fade by `dt` seconds (~0.16 s in, ~0.28 s out, smoothstep).
pub fn step_hot(&mut self, dt: f32) {
    let h = &mut self.hot;
    if h.on {
        h.phase = (h.phase + dt / HOT_IN_S).min(1.0);
    } else {
        h.phase = (h.phase - dt / HOT_OUT_S).max(0.0);
    }
    self.free_blur_if_unused();
}

/// Current hover strength 0..1 (0 = the pass contributes nothing).
pub fn hot_strength(&self) -> f32 {
    self.hot.strength()
}

/// Clock of the hover shimmer in seconds.
pub fn set_fx_time(&mut self, t: f32) {
    self.fx_t = t;
}
    /// Compile (once) the program for a texture; Err carries the driver's log.
    pub fn prepare(&mut self, texture: &str) -> Result<(), String> {
        if !self.progs.contains_key(texture) {
            // Development hook: NOVA_GPU_SHADER_DIR=<gpu/shaders> reads tex/<id>.glsl from disk, so a shader can be
            // iterated without rebuilding the engine. Unset in production.
            let on_disk = std::env::var_os("NOVA_GPU_SHADER_DIR").and_then(|dir| {
                std::fs::read_to_string(std::path::Path::new(&dir).join("tex").join(format!("{texture}.glsl"))).ok()
            });
            let body: String = match on_disk {
                Some(text) => text,
                None => texture_body(texture).ok_or_else(|| format!("unknown texture {texture:?}"))?.to_owned(),
            };
            let gl = self.ctx.gl();
            let fs = format!("{HEAD}{body}{TAIL}");
            let prog = unsafe { compile(gl, &fs, texture) }.map(|p| Prog { p, u: HashMap::new() });
            self.progs.insert(texture.to_owned(), prog);
        }
        self.progs[texture].as_ref().map(|_| ()).map_err(Clone::clone)
    }

    unsafe fn draw(&mut self, p: &Params, query: glow::Query) -> Result<(), String> {
        self.prepare(&p.texture)?;
        let gl = self.ctx.gl();
        let Some(Ok(prog)) = self.progs.get_mut(&p.texture) else { unreachable!() };
        let (Some(s0), Some(s1), Some(cas), Some(_)) = (self.s0, self.s1, self.cas, self.out) else {
            return Err("renderer has no size".into());
        };
        let pal = palette_at(p.accent, p.drift, f64::from(p.t));
        let (sw, sh, cw, ch) = (self.sw as f32, self.sh as f32, self.cw as f32, self.ch as f32);
        unsafe {
            gl.begin_query(glow::TIME_ELAPSED, query);
            // scene pass
            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fb_scene));
            gl.viewport(0, 0, self.sw as i32, self.sh as i32);
            gl.use_program(Some(prog.p));
            gl.active_texture(glow::TEXTURE3);
            gl.bind_texture(glow::TEXTURE_2D, Some(self.atlas));
            gl.uniform_1_i32(loc(gl, prog, "uAtlas").as_ref(), 3);
            gl.uniform_2_f32(loc(gl, prog, "uRes").as_ref(), sw, sh);
            gl.uniform_1_f32(loc(gl, prog, "uT").as_ref(), p.t);
            gl.uniform_1_f32(loc(gl, prog, "uSeed").as_ref(), p.seed);
            gl.uniform_1_f32(loc(gl, prog, "uGain").as_ref(), gain(&p.texture));
            gl.uniform_3_f32_slice(loc(gl, prog, "uA").as_ref(), &pal.a);
            gl.uniform_3_f32_slice(loc(gl, prog, "uB").as_ref(), &pal.b);
            gl.uniform_3_f32_slice(loc(gl, prog, "uC").as_ref(), &pal.c);
            gl.uniform_3_f32_slice(loc(gl, prog, "uBg").as_ref(), &pal.bg1);
            let k = p.warp / 50.0;
            let ptr = self.ptr;
            gl.uniform_3_f32(loc(gl, prog, "uPtr").as_ref(), ptr[0], ptr[1], ptr[2] * k);
            gl.uniform_2_f32(
                loc(gl, prog, "uVel").as_ref(),
                (self.tgt[0] - ptr[0]) * ptr[2] * k,
                (self.tgt[1] - ptr[1]) * ptr[2] * k,
            );
            gl.draw_arrays(glow::TRIANGLES, 0, 3);
            gl.active_texture(glow::TEXTURE0);
            gl.bind_texture(glow::TEXTURE_2D, Some(s0));
            gl.generate_mipmap(glow::TEXTURE_2D);

            // radiance cascades, coarsest first, ping-pong
            let casc = &mut self.casc;
            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fb_cas));
            gl.viewport(0, 0, self.cw as i32, self.ch as i32);
            gl.use_program(Some(casc.p));
            gl.uniform_1_i32(loc(gl, casc, "uScene").as_ref(), 0);
            gl.uniform_1_i32(loc(gl, casc, "uUp").as_ref(), 1);
            gl.uniform_2_f32(loc(gl, casc, "uSz").as_ref(), cw, ch);
            gl.uniform_1_i32(loc(gl, casc, "uN").as_ref(), CASCADES);
            gl.uniform_1_f32(loc(gl, casc, "uLod").as_ref(), (sw / cw).log2());
            gl.uniform_1_f32(loc(gl, casc, "uL").as_ref(), (cw / 768.0).max(1.0));
            gl.uniform_1_f32(loc(gl, casc, "uGE").as_ref(), 9.0 * (p.glow / 100.0));
            let uc = loc(gl, casc, "uC");
            for c in (0..CASCADES as usize).rev() {
                gl.framebuffer_texture_2d(
                    glow::FRAMEBUFFER,
                    glow::COLOR_ATTACHMENT0,
                    glow::TEXTURE_2D,
                    Some(cas[c & 1]),
                    0,
                );
                gl.active_texture(glow::TEXTURE1);
                gl.bind_texture(glow::TEXTURE_2D, Some(cas[(c + 1) & 1]));
                gl.uniform_1_i32(uc.as_ref(), c as i32);
                gl.draw_arrays(glow::TRIANGLES, 0, 3);
            }

            // composite
            let comp = &mut self.comp;
            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fb_out));
            gl.viewport(0, 0, self.sw as i32, self.sh as i32);
            gl.use_program(Some(comp.p));
            gl.active_texture(glow::TEXTURE1);
            gl.bind_texture(glow::TEXTURE_2D, Some(s1));
            gl.active_texture(glow::TEXTURE2);
            gl.bind_texture(glow::TEXTURE_2D, Some(cas[0]));
            gl.active_texture(glow::TEXTURE0);
            gl.uniform_1_i32(loc(gl, comp, "uS0").as_ref(), 0);
            gl.uniform_1_i32(loc(gl, comp, "uS1").as_ref(), 1);
            gl.uniform_1_i32(loc(gl, comp, "uCas").as_ref(), 2);
            gl.uniform_2_f32(loc(gl, comp, "uRes").as_ref(), sw, sh);
            gl.uniform_2_f32(loc(gl, comp, "uSz").as_ref(), cw, ch);
            gl.uniform_3_f32_slice(loc(gl, comp, "uBg0").as_ref(), &pal.bg0);
            gl.uniform_3_f32_slice(loc(gl, comp, "uBg1").as_ref(), &pal.bg1);
            gl.uniform_3_f32_slice(loc(gl, comp, "uBg2").as_ref(), &pal.bg2);
            gl.uniform_1_f32(loc(gl, comp, "uInt").as_ref(), p.intensity / 100.0);
            gl.uniform_1_f32(loc(gl, comp, "uSatD").as_ref(), p.sat.clamp(0.0, 200.0) / 100.0 - 1.0);
            gl.draw_arrays(glow::TRIANGLES, 0, 3);
            let hot = self.hot.strength();
            let glass = self.overlay.as_ref().is_some_and(|o| o.mask.is_some());
            if glass || hot > 0.0 {
                // snapshot the composite (with mips) for the glass blur and the halo luma
                gl.active_texture(glow::TEXTURE6);
                let blur = match self.blur {
                    Some(b) => b,
                    None => {
                        let b = mk_tex(gl, self.sw, self.sh, levels_for(self.sw, self.sh), true, glow::RGBA8)?;
                        self.blur = Some(b);
                        b
                    }
                };
                gl.bind_texture(glow::TEXTURE_2D, Some(blur));
                gl.read_buffer(glow::COLOR_ATTACHMENT0);
                gl.copy_tex_sub_image_2d(glow::TEXTURE_2D, 0, 0, 0, 0, 0, self.sw as i32, self.sh as i32);
                gl.generate_mipmap(glow::TEXTURE_2D);
                let (otex, mtex) = match &self.overlay {
                    Some(o) => (o.tex, o.mask.unwrap_or(blur)),
                    None => (blur, blur),
                };
                gl.active_texture(glow::TEXTURE4);
                gl.bind_texture(glow::TEXTURE_2D, Some(otex));
                gl.active_texture(glow::TEXTURE5);
                gl.bind_texture(glow::TEXTURE_2D, Some(mtex));
                gl.active_texture(glow::TEXTURE0);
                let fx = &mut self.fx;
                gl.use_program(Some(fx.p));
                gl.uniform_1_i32(loc(gl, fx, "uBlur").as_ref(), 6);
                gl.uniform_1_i32(loc(gl, fx, "uOv").as_ref(), 4);
                gl.uniform_1_i32(loc(gl, fx, "uMask").as_ref(), 5);
                gl.uniform_2_f32(loc(gl, fx, "uRes").as_ref(), sw, sh);
                gl.uniform_1_i32(loc(gl, fx, "uHasOv").as_ref(), i32::from(self.overlay.is_some()));
                gl.uniform_1_i32(loc(gl, fx, "uHasMask").as_ref(), i32::from(glass));
                if glass {
                    // frosted plates: replace the masked pixels by the blurred copy
                    gl.uniform_1_i32(loc(gl, fx, "uMode").as_ref(), 0);
                    gl.uniform_1_f32(loc(gl, fx, "uHot").as_ref(), 0.0);
                    gl.draw_arrays(glow::TRIANGLES, 0, 3);
                }
            }
            if let Some(o) = &self.overlay {
                // panel overlay: after the composite and its dither, in display space, like
                // PIL alpha_composite over an opaque base: rgb = ov.rgb*ov.a + base.rgb*(1-ov.a)
                let over = &mut self.over;
                gl.use_program(Some(over.p));
                gl.active_texture(glow::TEXTURE4);
                gl.bind_texture(glow::TEXTURE_2D, Some(o.tex));
                gl.active_texture(glow::TEXTURE0);
                gl.uniform_1_i32(loc(gl, over, "uOv").as_ref(), 4);
                gl.uniform_1_i32(loc(gl, over, "uH").as_ref(), self.sh as i32);
                gl.enable(glow::BLEND);
                gl.blend_func_separate(glow::SRC_ALPHA, glow::ONE_MINUS_SRC_ALPHA, glow::ZERO, glow::ONE);
                gl.draw_arrays(glow::TRIANGLES, 0, 3);
                gl.disable(glow::BLEND);
            }
            if hot > 0.0 {
                // hover glow: additive light over everything drawn so far
                let fx = &mut self.fx;
                gl.use_program(Some(fx.p));
                gl.uniform_1_i32(loc(gl, fx, "uMode").as_ref(), 1);
                let h = self.hot;
                gl.uniform_1_f32(loc(gl, fx, "uHot").as_ref(), hot);
                gl.uniform_4_f32(loc(gl, fx, "uRect").as_ref(), h.rect[0], h.rect[1], h.rect[2], h.rect[3]);
                gl.uniform_1_f32(loc(gl, fx, "uRadius").as_ref(), h.radius);
                let reach = h.reach.unwrap_or_else(|| (0.07 * sw.min(sh)).clamp(26.0, 60.0));
                gl.uniform_1_f32(loc(gl, fx, "uReach").as_ref(), reach);
                let col = h.color.unwrap_or_else(|| hsl_f32(f64::from(p.accent.min(63)) / 64.0, 0.68, 0.56));
                gl.uniform_3_f32_slice(loc(gl, fx, "uCol").as_ref(), &col);
                gl.uniform_1_f32(loc(gl, fx, "uHue").as_ref(), hue_of(col));
                gl.uniform_1_f32(loc(gl, fx, "uTime").as_ref(), self.fx_t);
                gl.enable(glow::BLEND);
                gl.blend_func_separate(glow::ONE, glow::ONE, glow::ZERO, glow::ONE);
                gl.draw_arrays(glow::TRIANGLES, 0, 3);
                gl.disable(glow::BLEND);
            }
            gl.end_query(glow::TIME_ELAPSED);
            gl.bind_framebuffer(glow::READ_FRAMEBUFFER, Some(self.fb_out));
            gl.read_buffer(glow::COLOR_ATTACHMENT0);
        }
        Ok(())
    }

    /// Render one frame synchronously into `out` (RGB8 top-down, at least w*h*3 bytes).
    pub fn render(&mut self, p: &Params, out: &mut [u8]) -> Result<FrameInfo, String> {
        let (w, h) = (self.sw, self.sh);
        check_len(out, w, h)?;
        let query = self.slots[self.next].query;
        unsafe {
            self.draw(p, query)?;
            let gl = self.ctx.gl();
            self.scratch.resize((w * h * 3) as usize, 0);
            gl.bind_buffer(glow::PIXEL_PACK_BUFFER, None);
            gl.read_pixels(
                0,
                0,
                w as i32,
                h as i32,
                glow::RGB,
                glow::UNSIGNED_BYTE,
                glow::PixelPackData::Slice(Some(&mut self.scratch)),
            );
            let ns = gl.get_query_parameter_u64(query, glow::QUERY_RESULT);
            rgb_flipped(&self.scratch, w, h, out);
            Ok(FrameInfo { w, h, gpu_ms: Some(ns as f64 / 1e6) })
        }
    }

    /// Pipelined render: frame N is read into a PBO while frame N-1 (if any) is copied into `out`
    /// and returned. Call `flush` to get the last pending frame (e.g. before going idle).
    pub fn render_async(&mut self, p: &Params, out: &mut [u8]) -> Result<Option<FrameInfo>, String> {
        let cur = self.next;
        let prev = cur ^ 1;
        let (w, h) = (self.sw, self.sh);
        let query = self.slots[cur].query;
        unsafe {
            self.draw(p, query)?;
            let gl = self.ctx.gl();
            let slot = &mut self.slots[cur];
            let need = (w * h * 3) as usize;
            gl.bind_buffer(glow::PIXEL_PACK_BUFFER, Some(slot.pbo));
            if slot.cap < need {
                gl.buffer_data_size(glow::PIXEL_PACK_BUFFER, need as i32, glow::STREAM_READ);
                slot.cap = need;
            }
            gl.read_pixels(
                0,
                0,
                w as i32,
                h as i32,
                glow::RGB,
                glow::UNSIGNED_BYTE,
                glow::PixelPackData::BufferOffset(0),
            );
            gl.bind_buffer(glow::PIXEL_PACK_BUFFER, None);
            gl.flush();
            (slot.w, slot.h, slot.busy) = (w, h, true);
        }
        self.next = prev;
        if self.slots[prev].busy {
            self.collect(prev, out).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Deliver the frame still pending in a PBO, if any.
    pub fn flush(&mut self, out: &mut [u8]) -> Result<Option<FrameInfo>, String> {
        let last = self.next ^ 1;
        if self.slots[last].busy {
            self.collect(last, out).map(Some)
        } else {
            Ok(None)
        }
    }

    fn collect(&mut self, i: usize, out: &mut [u8]) -> Result<FrameInfo, String> {
        let gl = self.ctx.gl();
        let slot = &mut self.slots[i];
        slot.busy = false;
        let (w, h) = (slot.w, slot.h);
        check_len(out, w, h)?;
        let len = (w * h * 3) as usize;
        unsafe {
            gl.bind_buffer(glow::PIXEL_PACK_BUFFER, Some(slot.pbo));
            let ptr = gl.map_buffer_range(glow::PIXEL_PACK_BUFFER, 0, len as i32, glow::MAP_READ_BIT);
            if ptr.is_null() {
                gl.bind_buffer(glow::PIXEL_PACK_BUFFER, None);
                return Err("glMapBufferRange failed".into());
            }
            rgb_flipped(std::slice::from_raw_parts(ptr, len), w, h, out);
            gl.unmap_buffer(glow::PIXEL_PACK_BUFFER);
            gl.bind_buffer(glow::PIXEL_PACK_BUFFER, None);
            let ns = gl.get_query_parameter_u64(slot.query, glow::QUERY_RESULT);
            Ok(FrameInfo { w, h, gpu_ms: Some(ns as f64 / 1e6) })
        }
    }

    /// Block until the GPU is idle (benchmarks).
    pub fn finish(&self) {
        unsafe { self.ctx.gl().finish() }
    }
}

fn check_len(out: &[u8], w: u32, h: u32) -> Result<(), String> {
    let need = (w * h * 3) as usize;
    if out.len() < need {
        Err(format!("output buffer {} < {need} bytes", out.len()))
    } else {
        Ok(())
    }
}

/// GL rows are bottom-up; the caller wants top-down. The GPU already packed RGB (PACK_ALIGNMENT 1),
/// so this is one memcpy per row.
fn rgb_flipped(src: &[u8], w: u32, h: u32, out: &mut [u8]) {
    let row = w as usize * 3;
    let h = h as usize;
    for y in 0..h {
        out[y * row..(y + 1) * row].copy_from_slice(&src[(h - 1 - y) * row..(h - y) * row]);
    }
}

impl Drop for Renderer {
    fn drop(&mut self) {
        let gl = self.ctx.gl();
        unsafe {
            for (_, p) in self.progs.drain() {
                if let Ok(p) = p {
                    gl.delete_program(p.p);
                }
            }
            gl.delete_program(self.casc.p);
            gl.delete_program(self.comp.p);
            gl.delete_program(self.over.p);
            gl.delete_program(self.fx.p);
            if let Some(o) = self.overlay.take() {
                delete_overlay(gl, o);
            }
            for t in [self.s0.take(), self.s1.take(), self.out.take(), self.blur.take(), Some(self.atlas)]
                .into_iter()
                .flatten()
            {
                gl.delete_texture(t);
            }
            if let Some(c) = self.cas.take() {
                c.into_iter().for_each(|t| gl.delete_texture(t));
            }
            for s in &self.slots {
                gl.delete_buffer(s.pbo);
                gl.delete_query(s.query);
            }
            for f in [self.fb_scene, self.fb_cas, self.fb_out] {
                gl.delete_framebuffer(f);
            }
        }
    }
}
