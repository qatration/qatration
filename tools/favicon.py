#!/usr/bin/env python3
"""Generate the site's favicon set from one set of outlines.

WHY THIS IS A SCRIPT AND NOT THREE BINARY FILES. A checked-in `.ico` is a file nobody can diff,
review or re-derive: move the palette and the icon silently stops matching the site, with
nothing in the repository to say so. This is the rule the rest of the project runs on -- an
artifact you cannot regenerate is an artifact you cannot check -- so the design is data here
and the files are output.

ONE SOURCE OF GEOMETRY, WHICH IS NOT A STYLE POINT. The first version drew the letters as
strokes and rendered the vector and the raster separately, and the two did not agree: SVG
centres a stroke on its path while Pillow draws an ellipse outline INWARD from the bounding
box, so the `.svg` and the `.ico` carried different-sized letters. It surfaced as "why is the A
bigger than the Q" -- measured at 112px against 105px in a 256px render, the opposite of what
the code said it was doing. Both outputs now come from `GLYPHS`, so there is no second drawing
to drift.

NO FONT AT RUN TIME EITHER. The outlines were extracted once and baked in below. A font file
lives in a system directory that exists on one machine, and reading it would make fontTools a
dependency of a tool that draws one icon.

THE 16px PROBLEM IS REAL AND IS NOT SOLVED BY TRYING HARDER. Two letters across sixteen pixels
leaves each about seven, minus the gap, and the gap is what disappears first. So the 16px entry
in the `.ico` carries the Q alone, refitted to the square rather than shrunk. That is what
multi-size ICO is for. Most tabs on a HiDPI display ask for 32 and never see the 16.

    python tools/favicon.py

Writes site/favicon.svg, site/favicon.ico, site/apple-touch-icon.png.
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")

# A near-black tile with the DARK theme's `--accent` on it. The obvious choice was the light
# theme's accent as a solid tile, and it is the blue every other landing page uses; this pairs
# the site's own accent with a ground dark enough to carry it (6.6:1, measured) and reads as a tool
# rather than as something from an app store. `INK` must stay a colour the stylesheet defines --
# `redteam/test_readme.py` fails if the two drift apart.
TILE = "#0d1526"
INK = "#5c9bff"
CORNER = 0.22           # tile corner radius, as a fraction of the side

# Roboto Black, Version 2.137 -- Copyright 2011 Google Inc., Apache License 2.0. See NOTICE.
# Quadratic segments in a 100-unit grid: ('M', p) | ('L', p) | ('Q', control, end). TrueType is
# quadratic and SVG has a Q command, so the vector output is exact rather than a polygon
# approximation and the rasteriser flattens these same segments. A contour with negative signed
# area is a counter -- the hole in the Q, the triangle in the A.
GLYPHS = [
    [
        ("M", (47.37, 47.49)), ("Q", (47.37, 52.94), (45.56, 57.01)),
        ("Q", (43.75, 61.07), (40.56, 63.53)), ("L", (46.91, 68.55)), ("L", (41.05, 73.51)),
        ("L", (32.60, 66.71)), ("Q", (31.41, 66.87), (30.22, 66.87)),
        ("Q", (25.20, 66.87), (21.32, 64.55)), ("Q", (17.43, 62.23), (15.25, 57.91)),
        ("Q", (13.08, 53.59), (13.00, 47.98)), ("L", (13.00, 45.90)),
        ("Q", (13.00, 40.09), (15.12, 35.69)), ("Q", (17.24, 31.29), (21.17, 28.89)),
        ("Q", (25.09, 26.49), (30.17, 26.49)), ("Q", (35.16, 26.49), (39.08, 28.86)),
        ("Q", (42.99, 31.24), (45.17, 35.62)), ("Q", (47.34, 40.01), (47.37, 45.68))
    ],
    [
        ("M", (37.73, 45.84)), ("Q", (37.73, 39.98), (35.77, 36.95)),
        ("Q", (33.82, 33.91), (30.17, 33.91)), ("Q", (26.42, 33.91), (24.53, 36.91)),
        ("Q", (22.64, 39.90), (22.61, 45.68)), ("L", (22.61, 47.49)),
        ("Q", (22.61, 53.29), (24.53, 56.38)), ("Q", (26.44, 59.48), (30.22, 59.48)),
        ("Q", (33.84, 59.48), (35.77, 56.43)), ("Q", (37.70, 53.37), (37.73, 47.65))
    ],
    [
        ("M", (74.53, 58.99)), ("L", (61.54, 58.99)), ("L", (59.27, 66.33)),
        ("L", (49.15, 66.33)), ("L", (63.57, 27.03)), ("L", (72.48, 27.03)),
        ("L", (87.00, 66.33)), ("L", (76.82, 66.33))
    ],
    [
        ("M", (63.81, 51.67)), ("L", (72.26, 51.67)), ("L", (68.02, 38.04))
    ],
]
Q_ONLY = GLYPHS[:2]     # bowl and counter, for the 16px entry


def _points(contour):
    for seg in contour:
        for p in seg[1:]:
            yield p


def signed_area(contour):
    """Positive for an outer contour, negative for a counter, on the on-curve points."""
    pts = [seg[-1] for seg in contour]
    s = 0.0
    for i in range(len(pts)):
        x0, y0 = pts[i]
        x1, y1 = pts[(i + 1) % len(pts)]
        s += x0 * y1 - x1 * y0
    return s / 2.0


def refit(contours, pad):
    """Scale a set of contours to fill a 100-unit square with `pad` around it.

    Used for the Q on its own: shrinking the pair and cropping would leave it at the size it
    had while sharing the square, which is the size that does not survive sixteen pixels.
    """
    pts = [p for c in contours for p in _points(c)]
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    w, h = max(xs) - min(xs), max(ys) - min(ys)
    k = (100.0 - 2 * pad) / max(w, h)
    ox = (100.0 - w * k) / 2.0 - min(xs) * k
    oy = (100.0 - h * k) / 2.0 - min(ys) * k
    return [[(seg[0],) + tuple((p[0] * k + ox, p[1] * k + oy) for p in seg[1:]) for seg in c]
            for c in contours]


def svg(contours):
    """One path, `evenodd`, so the counters punch themselves exactly as a font does."""
    d = []
    for c in contours:
        for seg in c:
            if seg[0] == "M":
                d.append("M%.2f %.2f" % seg[1])
            elif seg[0] == "L":
                d.append("L%.2f %.2f" % seg[1])
            else:
                d.append("Q%.2f %.2f %.2f %.2f" % (seg[1] + seg[2]))
        d.append("Z")
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
        'width="100" height="100" role="img" aria-label="QAtration">\n'
        '  <rect width="100" height="100" rx="%.0f" ry="%.0f" fill="%s"/>\n'
        '  <path fill="%s" fill-rule="evenodd" d="%s"/>\n</svg>\n'
        % (CORNER * 100, CORNER * 100, TILE, INK, "".join(d))
    )


def _flatten(contour, k, steps=16):
    """The same segments as the SVG, as a polygon in device units."""
    out, cur = [], None
    for seg in contour:
        if seg[0] == "M":
            cur = seg[1]
            out.append((cur[0] * k, cur[1] * k))
        elif seg[0] == "L":
            cur = seg[1]
            out.append((cur[0] * k, cur[1] * k))
        else:
            c, e = seg[1], seg[2]
            for i in range(1, steps + 1):
                t = i / steps
                u = 1 - t
                x = u * u * cur[0] + 2 * u * t * c[0] + t * t * e[0]
                y = u * u * cur[1] + 2 * u * t * c[1] + t * t * e[1]
                out.append((x * k, y * k))
            cur = e
    return out


def raster(px, contours):
    """Drawn at 8x and downsampled: an icon rendered straight to 16 or 32 pixels is a staircase,
    and the antialiasing is most of what makes a small mark legible.

    Pillow has no even-odd polygon fill, so the counters are painted back in the tile colour
    rather than cut out. That is exact here because the tile is opaque; a transparent-ground
    variant would need real winding, and this is the line where that would have to change.
    """
    from PIL import Image, ImageDraw

    S = px * 8
    k = S / 100.0
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=CORNER * S, fill=TILE)
    for c in contours:
        if signed_area(c) > 0:
            d.polygon(_flatten(c, k), fill=INK)
    for c in contours:
        if signed_area(c) <= 0:
            d.polygon(_flatten(c, k), fill=TILE)
    return img.resize((px, px), Image.LANCZOS)


def write_ico(path, frames):
    """Write the ICO container directly, because Pillow silently wrote one frame.

    `Image.save(format="ICO", sizes=[...], append_images=[...])` accepted both arguments, raised
    nothing, and produced a file holding the 16px entry alone -- the 32, 48 and 64 frames were
    dropped without a word, and the script printed a byte count and looked like it had worked.
    Every size a browser actually asks for would have been an upscale of sixteen pixels.

    The format is small enough to write out and read back: a 6-byte header, one 16-byte entry
    per frame, then the payloads. PNG payloads rather than BMP -- every browser since IE11 reads
    them, they are a third of the size, and there is no mask plane to get wrong. The one trap is
    that a 256px entry writes its dimension as 0, hence the modulo.
    """
    import io as _io

    blobs = []
    for size, img in frames:
        buf = _io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        blobs.append((size, buf.getvalue()))

    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = len(header) + 16 * len(blobs)
    directory, payload = b"", b""
    for size, blob in blobs:
        directory += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                                 len(blob), offset)
        offset += len(blob)
        payload += blob

    with open(path, "wb") as f:
        f.write(header + directory + payload)

    # READ IT BACK. This function exists because a write that reported success had not done the
    # job, so the check is not optional and not a comment.
    from PIL import Image
    got = sorted(Image.open(path).ico.sizes())
    want = sorted((s, s) for s, _ in blobs)
    if got != want:
        raise SystemExit(f"the ico was written with {got}, not {want}")


def main():
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("pillow is needed to write the raster sizes: pip install pillow", file=sys.stderr)
        return 1

    out = []
    q_alone = refit(Q_ONLY, 15.0)

    p = os.path.join(SITE, "favicon.svg")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg(GLYPHS))
    out.append(p)

    p = os.path.join(SITE, "favicon.ico")
    write_ico(p, [(16, raster(16, q_alone)), (32, raster(32, GLYPHS)),
                  (48, raster(48, GLYPHS)), (64, raster(64, GLYPHS))])
    out.append(p)

    # iOS crops to its own rounded shape over an unknown wallpaper, so this one is opaque edge
    # to edge with no transparency to crop into.
    p = os.path.join(SITE, "apple-touch-icon.png")
    raster(180, GLYPHS).convert("RGB").save(p, format="PNG", optimize=True)
    out.append(p)

    for p in out:
        print("  %-28s %6d bytes" % (os.path.relpath(p, ROOT).replace("\\", "/"),
                                     os.path.getsize(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
