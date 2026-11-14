"""Bake the Matrix glyph atlas (gpu/atlas_matrix.png) from the fonts already bundled in nova-render.

Layout is the lab's: 16 x 8 cells of 24 x 32, white glyph on black, 128 glyphs; every third glyph is a
digit/symbol (upright), the rest are half-width katakana drawn mirrored, as in the film. The shaders read the
red channel. Baking it once means neither the PC engine nor Android needs a Japanese system font.
Run: python gpu/make_atlas.py
"""
import pathlib

from PIL import Image, ImageDraw, ImageFont, ImageOps

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "nova-rs" / "crates" / "nova-render" / "assets"
KANA = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝｦ"
OTHER = "0123456789:.=*+-<>|Z#"  # the lab used a 日 here; the bundled kana subset has no CJK ideographs
CELL_W, CELL_H, COLS, ROWS = 24, 32, 16, 8


def glyph_table():
    table = []
    for i in range(128):
        if i % 3 == 2:
            table.append((OTHER[(i // 3) % len(OTHER)], False))
        else:
            table.append((KANA[(i - i // 3) % len(KANA)], True))
    return table


def main():
    kana_font = ImageFont.truetype(str(ASSETS / "NovaMatrixKana.otf"), 26)
    mono_font = ImageFont.truetype(str(ASSETS / "DroidSansMono.ttf"), 24)
    atlas = Image.new("L", (CELL_W * COLS, CELL_H * ROWS), 0)
    for i, (ch, mirrored) in enumerate(glyph_table()):
        font = kana_font if (mirrored or ord(ch) > 0x2000) else mono_font
        cell = Image.new("L", (CELL_W, CELL_H), 0)
        ImageDraw.Draw(cell).text((CELL_W / 2, CELL_H / 2), ch, fill=255, font=font, anchor="mm", stroke_width=1)
        if mirrored:
            cell = ImageOps.mirror(cell)
        atlas.paste(cell, ((i % COLS) * CELL_W, (i // COLS) * CELL_H))
    out = ROOT / "gpu" / "atlas_matrix.png"
    atlas.save(out, optimize=True)
    print("wrote", out, out.stat().st_size, "bytes")
    # Raw 8-bit copy of the same pixels (row 0 = top) for nova-gpu's include_bytes!: no PNG decoder in Rust.
    raw = ROOT / "gpu" / "atlas_matrix.r8"
    raw.write_bytes(atlas.tobytes())
    print("wrote", raw, raw.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
