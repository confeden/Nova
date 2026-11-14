//! GPU tests: skipped (with a note on stderr) when no GL 3.3-core context can be created.

use nova_gpu::{texture_ids, GlContext, Params, Renderer};

fn renderer() -> Option<Renderer> {
    match GlContext::new().and_then(Renderer::new) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("skipping GPU test: {e}");
            None
        }
    }
}

fn spread(rgb: &[u8]) -> u8 {
    let (mut lo, mut hi) = (255u8, 0u8);
    for &v in rgb {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    hi - lo
}

#[test]
fn every_texture_compiles_and_renders_a_non_uniform_frame() {
    let Some(mut r) = renderer() else { return };
    r.set_size(160, 120).unwrap();
    assert_eq!(r.frame_size(), (160, 120));
    assert_eq!(r.grid(), (768, 576));
    let mut out = vec![0u8; 160 * 120 * 3];
    for id in texture_ids() {
        let p = Params { texture: id.into(), ..Params::default() };
        let info = r.render(&p, &mut out).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!((info.w, info.h), (160, 120));
        assert!(spread(&out) > 8, "{id} is uniform");
    }
    assert!(r.prepare("nope").is_err());
}

#[test]
fn pipelined_readback_returns_the_previous_frame() {
    let Some(mut r) = renderer() else { return };
    r.set_size(200, 100).unwrap();
    assert_eq!(r.grid(), (768, 384));
    let p = Params::default();
    let mut sync = vec![0u8; 200 * 100 * 3];
    r.render(&p, &mut sync).unwrap();
    let mut out = vec![0u8; 200 * 100 * 3];
    assert!(r.render_async(&p, &mut out).unwrap().is_none());
    let info = r.render_async(&p, &mut out).unwrap().expect("frame N-1");
    assert_eq!((info.w, info.h), (200, 100));
    assert_eq!(out, sync, "same params must give the same pixels through either path");
    assert!(r.flush(&mut out).unwrap().is_some());
    assert!(r.flush(&mut out).unwrap().is_none());
}

#[test]
fn pointer_easing_settles() {
    let Some(mut r) = renderer() else { return };
    assert!(!r.pointer_moving());
    r.set_pointer(0.1, 0.2, true);
    assert!(r.pointer_moving());
    for _ in 0..200 {
        r.step_pointer(0.05);
    }
    assert!(!r.pointer_moving());
    r.set_pointer(0.0, 0.0, false);
    assert!(r.pointer_moving());
}

#[test]
fn overlay_is_alpha_composited_after_the_dither() {
    let Some(mut r) = renderer() else { return };
    let (w, h) = (120u32, 90u32);
    r.set_size(w, h).unwrap();
    let p = Params { texture: "basalt".into(), ..Params::default() };
    let n = (w * h * 3) as usize;
    let mut base = vec![0u8; n];
    r.render(&p, &mut base).unwrap();
    // top half: half-transparent red; bottom half: fully transparent (checks orientation too)
    let mut ov = vec![0u8; (w * h * 4) as usize];
    for y in 0..h / 2 {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            ov[i..i + 4].copy_from_slice(&[255, 0, 0, 128]);
        }
    }
    assert!(r.set_overlay(w + 1, h, &ov).is_err());
    r.set_overlay(w, h, &ov).unwrap();
    let mut got = vec![0u8; n];
    r.render(&p, &mut got).unwrap();
    let a = 128.0 / 255.0;
    for y in 0..h as usize {
        for x in 0..w as usize {
            for c in 0..3 {
                let i = (y * w as usize + x) * 3 + c;
                let want = if y < h as usize / 2 {
                    let ov = if c == 0 { 255.0 } else { 0.0 };
                    (ov * a + f64::from(base[i]) * (1.0 - a)).round()
                } else {
                    f64::from(base[i])
                };
                assert!((f64::from(got[i]) - want).abs() <= 1.0, "px {x},{y} c{c}: {} vs {want}", got[i]);
            }
        }
    }
    // a new size drops the overlay; clearing restores the base exactly
    r.set_size(w, h + 2).unwrap();
    assert!(!r.has_overlay());
    r.set_size(w, h).unwrap();
    r.set_overlay(w, h, &ov).unwrap();
    r.clear_overlay();
    r.render(&p, &mut got).unwrap();
    assert_eq!(got, base);
}
/// A frame with real texture detail (basalt) and its base render, no overlay.
fn base_frame(r: &mut Renderer, w: u32, h: u32) -> (Params, Vec<u8>) {
    r.set_size(w, h).unwrap();
    let p = Params {
        texture: "basalt".into(),
        ..Params::default()
    };
    let mut base = vec![0u8; (w * h * 3) as usize];
    r.render(&p, &mut base).unwrap();
    (p, base)
}

/// (pixels differing where pred(x,y), pixels differing elsewhere)
fn diff_px(
    a: &[u8],
    b: &[u8],
    w: usize,
    mut pred: impl FnMut(usize, usize) -> bool,
) -> (usize, usize) {
    let (mut inside, mut outside) = (0, 0);
    for (i, (pa, pb)) in a.chunks(3).zip(b.chunks(3)).enumerate() {
        if pa != pb {
            if pred(i % w, i / w) {
                inside += 1;
            } else {
                outside += 1;
            }
        }
    }
    (inside, outside)
}

#[test]
fn glass_mask_changes_pixels_only_where_masked() {
    let Some(mut r) = renderer() else { return };
    let (w, h) = (200u32, 150u32);
    let (p, base) = base_frame(&mut r, w, h);
    let n = (w * h) as usize;
    // a translucent tint everywhere, so the old blend path is exercised too
    let mut ov = vec![0u8; n * 4];
    for px in ov.chunks_mut(4) {
        px.copy_from_slice(&[10, 40, 90, 70]);
    }
    let mut old = vec![0u8; n * 3];
    r.set_overlay(w, h, &ov).unwrap();
    r.render(&p, &mut old).unwrap();
    assert_ne!(old, base);

    // mask 0 everywhere: the glass path must equal the blended path
    let mut got = vec![0u8; n * 3];
    r.set_overlay_glass(w, h, &ov, Some(&vec![0u8; n])).unwrap();
    assert!(r.has_glass());
    r.render(&p, &mut got).unwrap();
    let max = old
        .iter()
        .zip(&got)
        .map(|(a, b)| a.abs_diff(*b))
        .max()
        .unwrap();
    assert_eq!(max, 0, "mask 0 must reproduce the blended overlay exactly");

    // mask 255 inside a rectangle only: pixels outside stay identical, inside they are frosted
    let (x0, y0, x1, y1) = (60usize, 40usize, 140usize, 110usize);
    let mut mask = vec![0u8; n];
    for y in y0..y1 {
        for x in x0..x1 {
            mask[y * w as usize + x] = 255;
        }
    }
    r.set_overlay_glass(w, h, &ov, Some(&mask)).unwrap();
    r.render(&p, &mut got).unwrap();
    let (inside, outside) = diff_px(&old, &got, w as usize, |x, y| {
        x >= x0 && x < x1 && y >= y0 && y < y1
    });
    assert_eq!(outside, 0, "glass leaked outside the mask");
    assert!(
        inside > (x1 - x0) * (y1 - y0) / 2,
        "only {inside} frosted pixels changed"
    );
    // frosting removes detail: the masked region is smoother than the sharp one
    let rough = |f: &[u8]| -> u64 {
        let mut s = 0u64;
        for y in y0..y1 {
            for x in x0..x1 - 1 {
                let i = (y * w as usize + x) * 3;
                s += u64::from(f[i + 1].abs_diff(f[i + 4]));
            }
        }
        s
    };
    assert!(
        rough(&got) < rough(&old),
        "glass should be smoother than the sharp texture"
    );
    // a bad mask length is rejected
    assert!(r.set_overlay_glass(w, h, &ov, Some(&mask[1..])).is_err());
    // clearing returns to the exact base frame
    r.clear_overlay();
    r.render(&p, &mut got).unwrap();
    assert_eq!(got, base);
}

#[test]
fn hot_glow_appears_near_the_rect_and_fades_back_to_the_exact_base() {
    let Some(mut r) = renderer() else { return };
    let (w, h) = (360u32, 260u32);
    let (p, base) = base_frame(&mut r, w, h);
    assert!(!r.hot_active());
    let rect = [20.0, 20.0, 100.0, 70.0];
    r.set_hot(Some(rect), 10.0, None, None, true);
    assert!(r.hot_active());
    assert_eq!(r.hot_strength(), 0.0);
    let mut got = vec![0u8; (w * h * 3) as usize];
    r.render(&p, &mut got).unwrap();
    assert_eq!(got, base, "strength 0 contributes exactly nothing");
    for _ in 0..4 {
        r.step_hot(0.05);
    }
    assert!((r.hot_strength() - 1.0).abs() < 1e-6);
    r.set_fx_time(1.0);
    r.render(&p, &mut got).unwrap();
    // reach = clamp(0.07*260, 26, 60) = 26 px; beyond 3*reach (78 px) from the rect nothing changes
    let near = |x: usize, y: usize| x < 100 + 78 && y < 70 + 78;
    let (inside, outside) = diff_px(&base, &got, w as usize, near);
    assert!(inside > 500, "hover glow changed only {inside} pixels");
    assert_eq!(outside, 0, "glow reached beyond 3x reach");
    // glow is additive light: no pixel gets darker
    assert!(base.iter().zip(&got).all(|(b, g)| g >= b));
    // fade out: half way it is still lit, at the end it is the exact base again
    r.set_hot(None, 0.0, None, None, false);
    r.step_hot(0.14);
    assert!(r.hot_strength() > 0.0 && r.hot_strength() < 1.0);
    assert!(r.hot_active());
    for _ in 0..10 {
        r.step_hot(0.05);
    }
    assert!(!r.hot_active());
    r.render(&p, &mut got).unwrap();
    assert_eq!(got, base);
}

#[test]
fn hot_shimmer_lives_inside_glass_and_halo_barely_tints_it() {
    let Some(mut r) = renderer() else { return };
    let (w, h) = (300u32, 220u32);
    let (p, _base) = base_frame(&mut r, w, h);
    let n = (w * h) as usize;
    let ov = vec![0u8; n * 4];
    let (x0, y0, x1, y1) = (60usize, 50usize, 220usize, 160usize);
    let mut mask = vec![0u8; n];
    for y in y0..y1 {
        for x in x0..x1 {
            mask[y * w as usize + x] = 255;
        }
    }
    r.set_overlay_glass(w, h, &ov, Some(&mask)).unwrap();
    let mut cold = vec![0u8; n * 3];
    r.render(&p, &mut cold).unwrap();
    r.set_hot(
        Some([x0 as f32, y0 as f32, x1 as f32, y1 as f32]),
        14.0,
        None,
        Some([1.0, 0.2, 0.8]),
        true,
    );
    for _ in 0..4 {
        r.step_hot(0.05);
    }
    let mut lit = vec![0u8; n * 3];
    r.set_fx_time(0.3);
    r.render(&p, &mut lit).unwrap();
    let mut lit2 = vec![0u8; n * 3];
    r.set_fx_time(2.1);
    r.render(&p, &mut lit2).unwrap();
    // inside the plate the shimmer moves with the clock and stays gentle
    let mut moved = 0;
    let mut max_up = 0u8;
    // the test mask is a plain square while the hot rect is rounded (r=14): keep out of the 4 px
    // corner pieces that lie outside the rounded rect, where the outline ring correctly shines
    for y in y0 + 5..y1 - 5 {
        for x in x0 + 5..x1 - 5 {
            let i = (y * w as usize + x) * 3;
            for c in 0..3 {
                if lit[i + c] != lit2[i + c] {
                    moved += 1;
                }
                max_up = max_up.max(lit[i + c].saturating_sub(cold[i + c]));
            }
        }
    }
    assert!(
        moved > 1000,
        "shimmer should animate, only {moved} samples moved"
    );
    assert!(max_up < 140, "plate interior lit too strongly: +{max_up}");
    // glass cleared while the hover is still on: the halo pass keeps working without a mask
    r.clear_overlay();
    r.render(&p, &mut lit).unwrap();
}

#[test]
fn zero_saturation_is_grey_and_default_is_untouched() {
    let Some(mut r) = renderer() else { return };
    r.set_size(160, 120).unwrap();
    let p = Params {
        texture: "marble".into(),
        ..Params::default()
    };
    let mut a = vec![0u8; 160 * 120 * 3];
    r.render(&p, &mut a).unwrap();
    assert!(
        a.chunks(3)
            .any(|px| px[0].abs_diff(px[1]) > 4 || px[1].abs_diff(px[2]) > 4),
        "marble must have colour"
    );
    let grey = Params {
        sat: 0.0,
        ..p.clone()
    };
    let mut g = vec![0u8; 160 * 120 * 3];
    r.render(&grey, &mut g).unwrap();
    assert!(
        g.chunks(3).all(|px| px[0] == px[1] && px[1] == px[2]),
        "sat 0 must be neutral grey"
    );
    let boost = Params {
        sat: 200.0,
        ..p.clone()
    };
    let mut b = vec![0u8; 160 * 120 * 3];
    r.render(&boost, &mut b).unwrap();
    let chroma = |f: &[u8]| -> u64 {
        f.chunks(3)
            .map(|px| u64::from(px[0].max(px[1]).max(px[2]) - px[0].min(px[1]).min(px[2])))
            .sum()
    };
    assert!(chroma(&b) > chroma(&a) && chroma(&a) > chroma(&g));
    let mut again = vec![0u8; 160 * 120 * 3];
    r.render(&Params { sat: 100.0, ..p }, &mut again).unwrap();
    assert_eq!(a, again);
}

#[test]
fn hover_outline_is_a_crisp_line_just_outside_the_plate() {
    let Some(mut r) = renderer() else { return };
    let (w, h) = (300u32, 220u32);
    let (p, base) = base_frame(&mut r, w, h);
    let (x0, y0, x1, y1) = (80usize, 60usize, 220usize, 160usize);
    // tiny reach: the soft halo is gone a few px out, so what remains next to the edge is the line
    r.set_hot(Some([x0 as f32, y0 as f32, x1 as f32, y1 as f32]), 14.0, Some(3.0), Some([0.2, 0.8, 1.0]), true);
    for _ in 0..4 {
        r.step_hot(0.05);
    }
    let mut lit = vec![0u8; base.len()];
    r.render(&p, &mut lit).unwrap();
    let y = (y0 + y1) / 2;
    let up = |x: usize| -> u32 {
        let i = (y * w as usize + x) * 3;
        (0..3).map(|c| u32::from(lit[i + c].saturating_sub(base[i + c]))).sum()
    };
    // pixel x0-2 has its centre 1.5 px outside the edge, x0-9 is 8.5 px out, x0+3 is inside
    let (ring, far) = (up(x0 - 2), up(x0 - 9));
    assert!(ring > 60, "outline too weak: +{ring}");
    assert!(far * 4 < ring, "outline must be crisp, +{ring} at 1.5 px but +{far} at 8.5 px");
    for x in x0..x0 + 12 {
        assert_eq!(up(x), 0, "nothing may be added inside the plate (x={x})");
    }
}
