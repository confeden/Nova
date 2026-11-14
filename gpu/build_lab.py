#!/usr/bin/env python3
"""Rebuild the light-lab prototype page from the shared shader files.

The ORIGINAL page is used as a template: only the bodies of the JS template
literals VS / HEAD / TAIL / SRC.<id> / CASC / COMP are replaced with the
contents of gpu/shaders/*.glsl (re-escaped for a JS template literal).
Everything else in the page is copied byte for byte.

    python gpu/build_lab.py OUT.html [--template PAGE.html]

An output path is required (nothing is printed to stdout).
"""
import argparse
import json
import sys
from pathlib import Path

BS = chr(92)  # backslash, built explicitly to survive tool-layer unescaping
GPU = Path(__file__).resolve().parent
SHADERS = GPU / "shaders"
DEFAULT_TEMPLATE = Path(r"D:\Claude\Nova PC\kb\light-lab\nova-light-lab.html")


def js_escape(text):
    """Escape text for use inside a JS template literal."""
    return (text.replace(BS, BS + BS)
                .replace("`", BS + "`")
                .replace("${", BS + "${"))


def read_shader(path):
    raw = path.read_bytes().decode("utf-8")
    if "\r" in raw:
        raise SystemExit("%s: CR in shader file, expected LF only" % path)
    return raw


def replace_body(page, start, end, body, nl):
    """Replace page[start:end] (a template-literal body) with escaped body."""
    return page[:start] + js_escape(body).replace("\n", nl) + page[end:]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", help="output html path (required)")
    ap.add_argument("--template", default=str(DEFAULT_TEMPLATE),
                    help="original page used as template")
    args = ap.parse_args()

    page = Path(args.template).read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in page else "\n"
    manifest = json.loads((GPU / "manifest.json").read_text(encoding="utf-8"))
    ids = [t["id"] for t in manifest["textures"]]

    def literal_span(open_marker):
        if page.count(open_marker) != 1:
            raise SystemExit("marker not found or not unique: %r" % open_marker)
        s = page.find(open_marker) + len(open_marker)
        e = page.find("`", s)
        if e < 0:
            raise SystemExit("unterminated template literal after %r" % open_marker)
        return s, e

    # Collect replacements as (start, end, body) and apply from the end.
    edits = []
    for const, fname in (("VS", "vs"), ("HEAD", "head"), ("TAIL", "tail"),
                         ("CASC", "casc"), ("COMP", "comp")):
        s, e = literal_span("const %s=`" % const)
        edits.append((s, e, read_shader(SHADERS / (fname + ".glsl"))))

    src_open = page.find("const SRC={")
    src_end = page.find(nl + "};", src_open)
    if src_open < 0 or src_end < 0:
        raise SystemExit("SRC block not found")
    for tid in ids:
        marker = nl + tid + ":`"
        i = page.find(marker, src_open, src_end)
        if i < 0 or page.find(marker, i + 1, src_end) >= 0:
            raise SystemExit("texture key not found or duplicated in SRC: " + tid)
        s = i + len(marker)
        e = page.find("`", s)
        if e < 0 or e > src_end:
            raise SystemExit("unterminated template for texture " + tid)
        edits.append((s, e, read_shader(SHADERS / "tex" / (tid + ".glsl"))))

    edits.sort(key=lambda x: x[0])
    for a, b in zip(edits, edits[1:]):
        if a[1] > b[0]:
            raise SystemExit("overlapping edits")
    for s, e, body in reversed(edits):
        page = replace_body(page, s, e, body, nl)

    Path(args.out).write_bytes(page.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
