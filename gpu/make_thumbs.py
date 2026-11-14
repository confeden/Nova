"""Bake the still previews of the appearance window (resources/nova_texture_thumbs.png).

One `nova-engine gpu-snapshot` per texture at the default hue, 192x144, laid out 4 columns wide in the
order of nova_gpu.TEXTURE_IDS. The window rotates the hue of these stills at run time, so nothing renders
while it is open. Run: python gpu/make_thumbs.py [path/to/nova-engine.exe]
"""
import pathlib
import subprocess
import sys
import tempfile

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "resources"))
import nova_gpu  # noqa: E402

THUMB_W, THUMB_H, COLUMNS = 192, 144, 4
# Scene time of the still, seconds: where each texture shows its character (most are fine anywhere).
TIMES = {"lightning": 9.2, "rain": 9.0, "cracks": 24.0, "snow": 9.0, "wood": 8.0, "aurora": 100.0, "maze": 30.0,
         "warp": 5.5, "sand": 10.0, "smoke": 40.0, "starfield": 20.0}
DEFAULT_TIME = 7.3


def main():
    exe = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "bin" / "nova-engine.exe"
    ids = nova_gpu.TEXTURE_IDS
    rows = (len(ids) + COLUMNS - 1) // COLUMNS
    atlas = Image.new("RGB", (THUMB_W * COLUMNS, THUMB_H * rows), (0, 0, 0))
    with tempfile.TemporaryDirectory() as work:
        for index, texture in enumerate(ids):
            out = pathlib.Path(work) / (texture + ".ppm")
            subprocess.run([str(exe), "gpu-snapshot", "--texture", texture, "--time",
                            str(TIMES.get(texture, DEFAULT_TIME)), "--size", "%dx%d" % (THUMB_W, THUMB_H),
                            "--accent", str(nova_gpu.DEFAULT_ACCENT), "--seed", "0", "--out", str(out)],
                           check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            with Image.open(out) as image:
                atlas.paste(image.convert("RGB"), ((index % COLUMNS) * THUMB_W, (index // COLUMNS) * THUMB_H))
    target = ROOT / "resources" / "nova_texture_thumbs.png"
    atlas.save(target, optimize=True)
    print("wrote", target, target.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
