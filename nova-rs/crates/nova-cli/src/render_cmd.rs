//! Versioned JSON request -> binary PGM. Errors never mix with image bytes on stdout.

use std::io::{Read, Write};

use nova_render::Mandelbrot;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    width: usize,
    height: usize,
    real: f64,
    imaginary: f64,
    scale: f64,
    cosine: f64,
    sine: f64,
    iterations: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeededRequest {
    version: u8,
    width: usize,
    height: usize,
    random_state: Vec<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidRequest {
    version: u8,
    width: usize,
    height: usize,
    variant: u32,
    source: [usize; 2],
    crop: [f64; 4],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextureRequest {
    version: u8,
    width: usize,
    height: usize,
    texture: String,
    variant: u32,
    #[serde(default)]
    trace: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RainRequest {
    version: u8,
    width: usize,
    height: usize,
    variant: u32,
    time: f64,
    source: [usize; 2],
    crop: [f64; 4],
    #[serde(default = "full_alpha")]
    alpha_scale: f32,
    #[serde(default)]
    trace: bool,
}
fn full_alpha() -> f32 {
    1.0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveRequest {
    version: u8,
    width: usize,
    height: usize,
    texture: String,
    variant: u32,
    time: f64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RenderRequest {
    Live(LiveRequest),
    Rain(RainRequest),
    Texture(TextureRequest),
    Android(AndroidRequest),
    Viewport(Request),
    Seeded(SeededRequest),
}

fn render() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input).map_err(|e| e.to_string())?;
    if input.len() > 16384 {
        return Err("request exceeds 16384 bytes".into());
    }
    let request: RenderRequest = serde_json::from_slice(&input).map_err(|e| e.to_string())?;
    let (width, height, pixels, words) = match request {
        RenderRequest::Live(request) if request.version == 7 => {
            // v7: live immersive texture frame; P6 for the RGB fractal, P5 otherwise.
            let frame = nova_render::live_texture(
                request.width, request.height, &request.texture, request.variant, request.time,
            ).map_err(str::to_owned)?;
            let mut output = std::io::stdout().lock();
            let kind = if frame.channels == 3 { 6 } else { 5 };
            write!(output, "P{kind}
{} {}
255
", request.width, request.height).map_err(|e| e.to_string())?;
            output.write_all(&frame.pixels).map_err(|e| e.to_string())?;
            return output.flush().map_err(|e| e.to_string());
        }
        RenderRequest::Android(request) if request.version == 6 => {
            let pixels = nova_render::smooth_fractal(
                request.width, request.height, request.variant, request.source, request.crop,
            ).map_err(str::to_owned)?;
            let mut output = std::io::stdout().lock();
            write!(output, "P6\n{} {}\n255\n", request.width, request.height).map_err(|e| e.to_string())?;
            output.write_all(&pixels).map_err(|e| e.to_string())?;
            return output.flush().map_err(|e| e.to_string());
        }
        RenderRequest::Rain(request) if request.version == 5 => {
            if request.trace && (request.width > 256 || request.height > 256) {
                return Err("trace is limited to 256 px".into());
            }
            let frame = nova_render::matrix_rain(
                request.width,
                request.height,
                request.variant,
                request.time,
                request.source,
                request.crop,
                request.alpha_scale,
                request.trace,
            )
            .map_err(str::to_owned)?;
            if request.trace {
                let mut output = std::io::stdout().lock();
                serde_json::to_writer(&mut output, &serde_json::json!({"base":frame.base,"events":frame.events}))
                    .map_err(|e| e.to_string())?;
                return output.flush().map_err(|e| e.to_string());
            }
            (request.width, request.height, frame.pixels, None)
        }
        RenderRequest::Texture(request) if request.version == 4 => {
            if request.trace && (request.width > 256 || request.height > 256) {
                return Err("trace is limited to 256 px".into());
            }
            let frame = nova_render::texture_frame(
                request.width,
                request.height,
                &request.texture,
                request.variant,
                request.trace,
            )
            .map_err(str::to_owned)?;
            if request.trace {
                let mut output = std::io::stdout().lock();
                serde_json::to_writer(&mut output, &serde_json::json!({"base":frame.base,"events":frame.events}))
                    .map_err(|e| e.to_string())?;
                return output.flush().map_err(|e| e.to_string());
            }
            (request.width, request.height, frame.pixels, None)
        }
        RenderRequest::Android(request) if request.version == 3 => {
            let pixels = nova_render::android_fractal(
                request.width,
                request.height,
                request.variant,
                request.source,
                request.crop,
            )
            .map_err(str::to_owned)?;
            (request.width, request.height, pixels, None)
        }
        RenderRequest::Viewport(request) if request.version == 1 => {
            let pixels = nova_render::mandelbrot(Mandelbrot {
                width: request.width,
                height: request.height,
                real: request.real,
                imaginary: request.imaginary,
                scale: request.scale,
                cosine: request.cosine,
                sine: request.sine,
                iterations: request.iterations,
            })
            .map_err(str::to_owned)?;
            (request.width, request.height, pixels, None)
        }
        RenderRequest::Seeded(request) if request.version == 2 => {
            let frame = nova_render::fractal(request.width, request.height, &request.random_state)
                .map_err(str::to_owned)?;
            (request.width, request.height, frame.pixels, Some(frame.words_consumed))
        }
        _ => return Err("unsupported protocol version".into()),
    };
    let mut output = std::io::stdout().lock();
    if let Some(words) = words {
        writeln!(output, "NOVA-FRACTAL/2 {words}").map_err(|e| e.to_string())?;
    }
    write!(output, "P5\n{width} {height}\n255\n").map_err(|e| e.to_string())?;
    output.write_all(&pixels).map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}

pub fn run() -> i32 {
    match render() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("render-fractal: {error}");
            2
        }
    }
}
