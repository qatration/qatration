#!/usr/bin/env python3
"""Generate the link-preview card for the site.

WHAT IT IS FOR. Paste the site's URL into Slack, Reddit, Hacker News, LinkedIn or a chat and
the platform fetches `og:image` and renders a card. Without one the link is a bare blue URL,
which is the difference between somebody clicking and somebody scrolling past. This is the
image behind that card, and it is generated for the same reason the icon is: an artifact you
cannot regenerate is an artifact you cannot check, and a change to the palette should be one
edit rather than a hunt for whoever has the original file.

THE MARK COMES FROM `favicon.py`, imported rather than copied. Two drawings of one logo is the
defect that produced a `.svg` and an `.ico` with different-sized letters; there is no reason to
introduce a third.

THE WORDS COME FROM THE PAGE. Every line here is on `site/index.html` already, and
`redteam/test_readme.py` fails if the card claims something the page does not say. A preview
card that oversells the page it links to is a lie with a picture on it.

    python tools/og_card.py

Writes site/og-card.png at 1200x630, the size every platform crops from.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import favicon  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")

W, H = 1200, 630

# The site's own dark theme, so the card and the page a click later are the same object.
GROUND = "#060b16"
PANEL = "#101d33"
INK = "#e4ecf9"
MUTED = "#8496b6"
ACCENT = "#5c9bff"
LINE = "#1b2c48"

# Roboto: Apache 2.0, Copyright 2011 Google Inc. Credited in NOTICE alongside the glyph
# outlines in `favicon.py`. Rendered here rather than baked, because unlike the icon this
# output is a raster only and there is no vector to keep in step with it.
FONT_DIRS = [
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"),
    "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF",
    "/usr/share/fonts/truetype/roboto",
    "/Library/Fonts",
]

# EVERY LINE IS ON THE PAGE. Checked by `test_readme.py`, because a card is a claim.
HEADLINE = "Find out what an attacker can make your chatbot do."
# VERBATIM FROM THE PAGE, not a tidier version of it. The first draft paraphrased -- same
# meaning, fewer words -- and the gate refused it, correctly: a card is read by people who have
# not opened the page yet, so it may quote the page and may not improve on it. The capital
# letter is added at draw time so this stays an exact substring.
SUB = ("fires real prompt-injection attacks at your AI bot and gives you a plain-English "
       "report of what it leaked or did")
FOOT = "open source  ·  Apache 2.0  ·  qatration.com"
WORD_A, WORD_B = "QA", "tration"


def _font(name, size):
    from PIL import ImageFont
    for d in FONT_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    raise SystemExit(f"{name} not found; looked in: {', '.join(FONT_DIRS)}")


def _wrap(draw, text, font, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=font) <= width or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def build():
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (W, H), GROUND)
    d = ImageDraw.Draw(img)

    # A quiet panel rather than a flat field, so the card reads as a surface and not as a
    # screenshot of nothing.
    d.rounded_rectangle([40, 40, W - 40, H - 40], radius=28, fill=PANEL, outline=LINE, width=2)

    pad = 88
    y = 108

    # The mark, from the icon generator. Same glyphs, same tile, same corner radius.
    mark = favicon.raster(96, favicon.GLYPHS)
    img.paste(mark, (pad, y), mark)

    f_word_a = _font("Roboto-Black.ttf", 62)
    f_word_b = _font("Roboto-Regular.ttf", 62)
    wx = pad + 96 + 26
    d.text((wx, y + 8), WORD_A, font=f_word_a, fill=INK)
    wx += d.textlength(WORD_A, font=f_word_a)
    d.text((wx, y + 8), WORD_B, font=f_word_b, fill=MUTED)

    y += 96 + 54

    f_head = _font("Roboto-Black.ttf", 58)
    for line in _wrap(d, HEADLINE, f_head, W - 2 * pad):
        d.text((pad, y), line, font=f_head, fill=INK)
        y += 70

    y += 16
    f_sub = _font("Roboto-Regular.ttf", 31)
    for line in _wrap(d, SUB[0].upper() + SUB[1:], f_sub, W - 2 * pad):
        d.text((pad, y), line, font=f_sub, fill=MUTED)
        y += 42

    f_foot = _font("Roboto-Bold.ttf", 25)
    d.text((pad, H - 40 - 62), FOOT, font=f_foot, fill=ACCENT)

    return img


def main():
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("pillow is needed: pip install pillow", file=sys.stderr)
        return 1
    p = os.path.join(SITE, "og-card.png")
    build().save(p, format="PNG", optimize=True)
    print("  %-28s %6d bytes  %dx%d"
          % ("site/og-card.png", os.path.getsize(p), W, H))
    return 0


if __name__ == "__main__":
    sys.exit(main())
