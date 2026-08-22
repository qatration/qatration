#!/usr/bin/env python3
"""Generate the site's favicon set from geometry, not from a font and not by hand.

WHY THIS IS A SCRIPT AND NOT THREE BINARY FILES. A checked-in `.ico` is a blob nobody can
diff, review or re-derive: change the accent colour and the icon silently stops matching the
site, and there is no way to tell by reading the repository. This is the same rule the rest of
the project runs on -- an artifact you cannot regenerate is an artifact you cannot check -- so
the design lives here as coordinates and the files are output.

NO FONT ANYWHERE. `<text>` in an SVG favicon renders with whatever the viewer has installed,
so the same file is a different mark on a different machine. The letters are drawn as strokes:
a ring with a tail, and a triangle with a crossbar. Identical everywhere, and the raster sizes
come from these same numbers rather than from a parallel drawing that can drift.

THE 16px PROBLEM IS REAL AND IS NOT SOLVED BY TRYING HARDER. Two letters across sixteen pixels
gives each about seven, minus the gap between them, and the gap is what disappears first: the
tail of the Q and the left leg of the A merge into one blue smudge. So the 16px entry in the
`.ico` carries the Q alone. That is what multi-size ICO is for, and the Q is the letter the
wordmark is built on. Everything from 32px up carries both. Most tabs on a HiDPI display ask
for 32 and never see the 16.

    python tools/favicon.py

Writes site/favicon.svg, site/favicon.ico, site/apple-touch-icon.png.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")

# The light theme's `--accent`, which is the darker of the two the stylesheet defines. A favicon
# sits on a tab bar the page does not control, so it has to hold up on both: white on `#1b57d6`
# is about 6.5:1, white on the dark theme's `#5c9bff` is about 2.2:1 and unreadable at any size.
TILE = "#1b57d6"
MARK = "#ffffff"

# --- the design, in a 100x100 square ---------------------------------------------------------
# One set of numbers. The SVG reads them and so does the rasteriser, because two drawings of one
# mark is the same defect as two implementations of one rule.
CORNER = 22.0           # tile corner radius
SW = 8.0                # stroke width for every letter part

# THE TAIL CROSSES THE RING. Drawn outside it, at forty-five degrees, this was a magnifying
# glass: a circle with a handle is the search icon every interface uses, and at 16px it read as
# "search" and not as a letter at all. What separates a Q from an O is that its tail starts
# INSIDE the bowl and cuts through the stroke, so the tail runs from radius 8 to radius 26
# about the same centre.
#
# AND THE ROUND LETTER OVERSHOOTS THE STRAIGHT ONE. Set to the same height the Q looked
# smaller than the A, which is why every typeface draws O taller than H. The ring's outer
# diameter is 46 against the A's outer height of 44.
Q_CX, Q_CY, Q_R = 31.0, 50.0, 19.0
_D = 0.7071                                     # cos 45, so the tail sits on the diagonal
Q_TAIL = ((Q_CX + 8 * _D, Q_CY + 8 * _D), (Q_CX + 26 * _D, Q_CY + 26 * _D))

A_APEX = (76.0, 32.0)
A_FEET = ((64.0, 68.0), (88.0, 68.0))
A_BAR = ((68.5, 57.0), (83.5, 57.0))

# The Q alone, centred, for the 16px entry: bigger than it is in the pair, because it is no
# longer sharing the square with anything.
Q1_CX, Q1_CY, Q1_R, Q1_SW = 50.0, 50.0, 26.0, 13.0
Q1_TAIL = ((Q1_CX + 11 * _D, Q1_CY + 11 * _D), (Q1_CX + 36 * _D, Q1_CY + 36 * _D))


def svg(pair=True):
    """The mark as SVG. `pair` false draws the Q alone."""
    if pair:
        letters = (
            f'  <circle cx="{Q_CX}" cy="{Q_CY}" r="{Q_R}" fill="none" '
            f'stroke="{MARK}" stroke-width="{SW}"/>\n'
            f'  <path d="M{Q_TAIL[0][0]} {Q_TAIL[0][1]} L{Q_TAIL[1][0]} {Q_TAIL[1][1]}" '
            f'fill="none" stroke="{MARK}" stroke-width="{SW}" stroke-linecap="round"/>\n'
            f'  <path d="M{A_FEET[0][0]} {A_FEET[0][1]} L{A_APEX[0]} {A_APEX[1]} '
            f'L{A_FEET[1][0]} {A_FEET[1][1]}" fill="none" stroke="{MARK}" '
            f'stroke-width="{SW}" stroke-linecap="round" stroke-linejoin="round"/>\n'
            f'  <path d="M{A_BAR[0][0]} {A_BAR[0][1]} L{A_BAR[1][0]} {A_BAR[1][1]}" '
            f'fill="none" stroke="{MARK}" stroke-width="{SW}" stroke-linecap="round"/>\n'
        )
    else:
        letters = (
            f'  <circle cx="{Q1_CX}" cy="{Q1_CY}" r="{Q1_R}" fill="none" '
            f'stroke="{MARK}" stroke-width="{Q1_SW}"/>\n'
            f'  <path d="M{Q1_TAIL[0][0]} {Q1_TAIL[0][1]} L{Q1_TAIL[1][0]} {Q1_TAIL[1][1]}" '
            f'fill="none" stroke="{MARK}" stroke-width="{Q1_SW}" stroke-linecap="round"/>\n'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
        'width="100" height="100" role="img" aria-label="QAtration">\n'
        f'  <rect width="100" height="100" rx="{CORNER}" ry="{CORNER}" fill="{TILE}"/>\n'
        + letters + '</svg>\n'
    )


def raster(px, pair=True):
    """The same geometry through Pillow, drawn large and downsampled.

    Pillow has no round line caps, so every stroke end gets a circle of its own diameter. Drawn
    at 8x and resized with LANCZOS: an icon rendered directly at 16 or 32 pixels is a staircase,
    and the antialiasing is most of what makes a small mark legible.
    """
    from PIL import Image, ImageDraw

    S = px * 8
    k = S / 100.0
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=CORNER * k, fill=TILE)

    def dot(x, y, w):
        r = w * k / 2.0
        d.ellipse([x * k - r, y * k - r, x * k + r, y * k + r], fill=MARK)

    def seg(p0, p1, w):
        d.line([p0[0] * k, p0[1] * k, p1[0] * k, p1[1] * k], fill=MARK, width=int(round(w * k)))
        dot(p0[0], p0[1], w)
        dot(p1[0], p1[1], w)

    def ring(cx, cy, r, w):
        d.ellipse([(cx - r) * k, (cy - r) * k, (cx + r) * k, (cy + r) * k],
                  outline=MARK, width=int(round(w * k)))

    if pair:
        ring(Q_CX, Q_CY, Q_R, SW)
        seg(*Q_TAIL, SW)
        seg(A_FEET[0], A_APEX, SW)
        seg(A_APEX, A_FEET[1], SW)
        seg(*A_BAR, SW)
    else:
        ring(Q1_CX, Q1_CY, Q1_R, Q1_SW)
        seg(*Q1_TAIL, Q1_SW)

    return img.resize((px, px), Image.LANCZOS)


def write_ico(path, frames):
    """Write the ICO container directly, because Pillow silently wrote one frame.

    `Image.save(format="ICO", sizes=[...], append_images=[...])` accepted both arguments,
    reported no error, and produced a file holding the 16px entry alone -- the 32, 48 and 64
    frames were dropped without a word. The script printed a byte count and looked like it had
    worked. That is this project's own defect class in its own tooling: an absence reported as
    a measurement, and it would have shipped a tab icon that was a blue smudge at every size
    the browser actually asks for.

    The format is small enough to write out and read back. A 6-byte header, one 16-byte
    directory entry per frame, then the payloads. PNG payloads rather than BMP: every browser
    since IE11 reads them, they are a third of the size, and there is no mask plane to get
    wrong. The one trap is that a 256px entry writes its dimension as 0, which is why the
    field is taken modulo 256 rather than assumed to fit.
    """
    import io as _io
    import struct

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

    # READ IT BACK. The whole reason this function exists is that a write which reported success
    # had not done the job, so the check is not optional and not a comment.
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

    p = os.path.join(SITE, "favicon.svg")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg(pair=True))
    out.append(p)

    # 16 carries the Q alone; see the module docstring for why that is a decision and not a
    # shortcut.
    frames = [(16, raster(16, pair=False)), (32, raster(32)),
              (48, raster(48)), (64, raster(64))]
    p = os.path.join(SITE, "favicon.ico")
    write_ico(p, frames)
    out.append(p)

    # iOS crops to its own rounded shape and puts the icon on an unknown wallpaper, so this one
    # is drawn edge to edge with no transparency to crop into.
    p = os.path.join(SITE, "apple-touch-icon.png")
    raster(180).convert("RGB").save(p, format="PNG", optimize=True)
    out.append(p)

    for p in out:
        print("  %-28s %6d bytes" % (os.path.relpath(p, ROOT).replace("\\", "/"),
                                     os.path.getsize(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
