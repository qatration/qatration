"""Translated copies of the landing page, generated from the English one.

WHY A GENERATOR AND NOT N HAND-WRITTEN PAGES. Every number on that page is recounted from
`out/` by `redteam/test_readme.py`, so a second copy of the page is a second copy of thirty
numbers that nothing recounts. The first time a figure is re-measured, the English page moves
and the other pages keep publishing yesterday's, in languages nobody here reads well enough
to notice. That is the same defect this project keeps finding in other people's work, and
writing it on purpose would be worse than finding it.

So: one source, `site/index.html`. A language is a dictionary from the English string to its
translation, and the pages are derived. The dictionary is keyed BY THE ENGLISH TEXT, which
means changing a sentence in English changes its key, the translation goes missing, and the
build says so. A key that survived an edit to the thing it translates is a stale translation
that looks current.

What is deliberately NOT translated: anything inside `code`, `pre`, `kbd` or `samp`. Those are
commands you type and output you read, and a localised `pip install` is a broken instruction.
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SITE = os.path.join(ROOT, "site")
SOURCE = os.path.join(SITE, "index.html")
DICT_DIR = os.path.join(SITE, "i18n")

# The opaque runs. A `<` inside the page's JavaScript is a comparison, not a tag, so the
# script and style bodies are lifted out whole before anything looks for a tag at all.
OPAQUE = re.compile(r"(?is)(<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->)")
TAG = re.compile(r"(?s)(<[^>]*>)")
NO_TRANSLATE = ("code", "pre", "kbd", "samp")
HAS_LETTER = re.compile(r"[A-Za-z]")

# Attributes that are read by a person or a search engine rather than by the browser.
ATTR_META = {"description", "og:title", "og:description", "og:image:alt",
             "twitter:title", "twitter:description"}
# `data-to-*` and `data-aria-*` are the theme button's two labels. They live in the markup
# precisely so this file can reach them: a label built inside the page's script is a string no
# generator sees, and the translated page reverts to English the moment the button repaints.
ATTR_PLAIN = ("alt", "aria-label", "placeholder",
              "data-to-light", "data-to-dark", "data-aria-light", "data-aria-dark")


def _tag_name(tag):
    m = re.match(r"</?\s*([a-zA-Z0-9-]+)", tag)
    return m.group(1).lower() if m else ""


def _meta_key(tag):
    """-> the name/property of a meta tag, or None if it is not one."""
    if _tag_name(tag) != "meta":
        return None
    m = re.search(r'(?:name|property)\s*=\s*"([^"]*)"', tag)
    return m.group(1) if m else None


def walk(html, on_text, on_attr):
    """Call `on_text(s)` for every translatable text node and `on_attr(tag, attr, s)` for every
    translatable attribute value, in document order. Both return a replacement or None.

    Returns the rebuilt document. One traversal serves extraction and rendering, so the set of
    strings a language file is asked for cannot drift from the set the renderer substitutes.
    """
    out, skip, in_title = [], [], False
    for chunk in OPAQUE.split(html):
        if OPAQUE.match(chunk or ""):
            out.append(chunk)
            continue
        for part in TAG.split(chunk or ""):
            if not part:
                continue
            if part.startswith("<"):
                name = _tag_name(part)
                # A STACK OF NAMES, not a counter. A counter closes on the first `</...>` it
                # meets whatever element that is, so one unbalanced tag inside a skipped block
                # hands the rest of the document back to the translator.
                if part.startswith("</"):
                    if skip and skip[-1] == name:
                        skip.pop()
                elif not part.rstrip().endswith("/>") and (
                        name in NO_TRANSLATE or ' translate="no"' in part):
                    skip.append(name)
                if name == "title":
                    in_title = not part.startswith("</")
                out.append(_rewrite_attrs(part, on_attr))
                continue
            if skip or (not HAS_LETTER.search(part)):
                out.append(part)
                continue
            out.append(_sub_text(part, on_text, in_title))
    return "".join(out)


def _sub_text(part, on_text, in_title):
    """Replace the text of a node, keeping the whitespace that surrounds it in the file."""
    lead = part[:len(part) - len(part.lstrip())]
    trail = part[len(part.rstrip()):]
    body = re.sub(r"\s+", " ", part.strip())
    if not body:
        return part
    rep = on_text(body)
    if rep is None:
        return part
    # Leading and trailing whitespace is layout, not language: `<b>46</b> attacks` needs the
    # space before `attacks` to survive, and rendering it away joins two words into one.
    return lead + rep + trail if not in_title else rep


def _rewrite_attrs(tag, on_attr):
    key = _meta_key(tag)
    attrs = []
    if key in ATTR_META:
        attrs.append("content")
    for a in ATTR_PLAIN:
        if re.search(r'\b%s\s*=\s*"' % a, tag):
            attrs.append(a)
    for a in attrs:
        m = re.search(r'(\b%s\s*=\s*")([^"]*)(")' % a, tag)
        if not m or not HAS_LETTER.search(m.group(2)):
            continue
        rep = on_attr(tag, a, m.group(2))
        if rep is not None:
            tag = tag[:m.start(2)] + rep + tag[m.end(2):]
    return tag


def extract(html):
    """-> the ordered, de-duplicated list of English strings a language file must supply."""
    seen, order = set(), []

    def note(s):
        if s not in seen:
            seen.add(s)
            order.append(s)
        return None

    walk(html, note, lambda _t, _a, s: note(s))
    return order


# ---------------------------------------------------------------- languages

# The alternates block is generated INTO THE ENGLISH PAGE TOO, between these markers. Adding a
# language otherwise means hand-editing the source that every other page derives from, and the
# day that edit is forgotten the English page advertises four languages and serves five.
MARK_OPEN = "<!-- i18n:alternates -->"
MARK_CLOSE = "<!-- /i18n:alternates -->"
SITE_URL = "https://qatration.com/"

# `x-default` is not a language. It tells a search engine which page to serve a reader whose
# own language is not among these, and without it the engine picks one, which for a tool whose
# every command is in English is a worse answer than English.
DEFAULT = "en"


def languages():
    """-> the language codes with a dictionary on disk, English first."""
    if not os.path.isdir(DICT_DIR):
        return [DEFAULT]
    got = sorted(f[:-len(".json")] for f in os.listdir(DICT_DIR) if f.endswith(".json"))
    return [DEFAULT] + [g for g in got if g != DEFAULT]


def load(lang):
    import json
    with io.open(os.path.join(DICT_DIR, "%s.json" % lang), encoding="utf-8") as f:
        d = json.load(f)
    return d.get("strings") or {}


def alternates(langs):
    rows = [MARK_OPEN]
    for code in langs:
        href = SITE_URL if code == DEFAULT else "%s%s/" % (SITE_URL, code)
        rows.append('<link rel="alternate" hreflang="%s" href="%s">' % (code, href))
    rows.append('<link rel="alternate" hreflang="x-default" href="%s">' % SITE_URL)
    rows.append(MARK_CLOSE)
    return "\n".join(rows)


def with_alternates(html, langs):
    block = alternates(langs)
    i, j = html.find(MARK_OPEN), html.find(MARK_CLOSE)
    if i < 0 or j < 0:
        raise SystemExit("site/index.html has no %s ... %s region to fill" % (MARK_OPEN, MARK_CLOSE))
    return html[:i] + block + html[j + len(MARK_CLOSE):]


def render(html, lang, table, langs):
    """-> the page for `lang`. A missing string stays in English rather than vanishing."""
    def sub(s):
        return table.get(s)

    out = walk(html, sub, lambda _t, _a, s: sub(s))
    out = with_alternates(out, langs)
    out = with_switcher(out, lang, langs)
    if lang != DEFAULT:
        # The canonical must name THIS page rather than the English one, or the translation
        # declares itself a duplicate of a page it is not and the engine drops it.
        #
        # Nothing rewrites the hrefs, and that is checked rather than assumed: every link in
        # the source is absolute or root-relative, so they all resolve the same from `/uk/` as
        # from `/`. Absolutising them looked tidier and hardcoded the production origin into
        # every page, which breaks a local preview and any deploy preview - a fix for a problem
        # that did not exist, introducing one that did.
        out = out.replace('<link rel="canonical" href="%s">' % SITE_URL,
                          '<link rel="canonical" href="%s%s/">' % (SITE_URL, lang))
        out = out.replace('<meta property="og:url" content="%s">' % SITE_URL,
                          '<meta property="og:url" content="%s%s/">' % (SITE_URL, lang))
    return '<html lang="%s">\n' % lang + out


# ------------------------------------------------------------------- numbers

# Thousands separators are language, the digits are not. `1,500` and `1 500` are the same
# measurement written two ways; `quarante-six` is a number that stopped being checkable.
_SEP = re.compile(r"(?<=\d)[,\u00a0\u202f ](?=\d\d\d\b)")
_NUM = re.compile(r"\d+(?:\.\d+)?")


def numbers(s):
    return sorted(_NUM.findall(_SEP.sub("", s)))


# ----------------------------------------------------------------- the build

def page_path(lang):
    return SOURCE if lang == DEFAULT else os.path.join(SITE, lang, "index.html")


def build(write=True):
    """Regenerate every page. -> list of (path, changed) so `--check` can refuse a hand edit."""
    src = io.open(SOURCE, encoding="utf-8").read()
    langs = languages()
    done = []
    want = sitemap(langs)
    have = io.open(SITEMAP, encoding="utf-8").read() if os.path.exists(SITEMAP) else None
    done.append((SITEMAP, have != want))
    if write and have != want:
        io.open(SITEMAP, "w", encoding="utf-8", newline="\n").write(want)
    for lang in langs:
        out = (with_switcher(with_alternates(src, langs), lang, langs) if lang == DEFAULT
               else render(src, lang, load(lang), langs))
        path = page_path(lang)
        old = io.open(path, encoding="utf-8").read() if os.path.exists(path) else None
        done.append((path, old != out))
        if write and old != out:
            d = os.path.dirname(path)
            if not os.path.isdir(d):
                os.makedirs(d)
            io.open(path, "w", encoding="utf-8", newline="\n").write(out)
    return done


def skeleton(lang):
    """Write (or top up) site/i18n/<lang>.json, leaving existing translations alone."""
    import json
    src = io.open(SOURCE, encoding="utf-8").read()
    path = os.path.join(DICT_DIR, "%s.json" % lang)
    have = load(lang) if os.path.exists(path) else {}
    table, missing = {}, 0
    for s in extract(src):
        table[s] = have.get(s, "")
        if not table[s]:
            missing += 1
    # STALE KEYS ARE DROPPED, not kept "in case". A translation of a sentence that no longer
    # exists is a file that looks complete and is not, and the one thing worse than a missing
    # translation is a full-looking file with a stale one in it.
    dropped = [k for k in have if k not in table]
    if not os.path.isdir(DICT_DIR):
        os.makedirs(DICT_DIR)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"language": lang, "strings": table},
                           ensure_ascii=False, indent=2, sort_keys=False))
        f.write("\n")
    return len(table), missing, dropped


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--extract", metavar="LANG",
                    help="create or top up site/i18n/LANG.json with every string the page "
                         "needs, keeping the translations already in it")
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and fail if any page on disk differs, which is "
                         "how a hand edit to a generated page is caught")
    args = ap.parse_args()

    if args.extract:
        total, missing, dropped = skeleton(args.extract)
        print("site/i18n/%s.json: %d strings, %d still to translate%s"
              % (args.extract, total, missing,
                 ", %d stale dropped" % len(dropped) if dropped else ""))
        return 0

    done = build(write=not args.check)
    stale = [p for p, changed in done if changed]
    if args.check:
        if stale:
            print("these pages are not what the source generates:", file=sys.stderr)
            for p in stale:
                print("   %s" % os.path.relpath(p, ROOT), file=sys.stderr)
            print("\nRun `python tools/i18n.py` to regenerate. A translated page is derived, "
                  "never edited: an edit here is lost on the next build and, until then, is a "
                  "sentence no gate has read.", file=sys.stderr)
            return 1
        print("%d page(s) match what the source generates." % len(done))
        return 0
    print("built %d page(s)%s" % (len(done),
          (": " + ", ".join(os.path.relpath(p, ROOT) for p in stale)) if stale else ", none changed"))
    return 0




# ---------------------------------------------------------------- the switch

MARK_SW_OPEN = "<!-- i18n:switcher -->"
MARK_SW_CLOSE = "<!-- /i18n:switcher -->"

# What each language calls itself, for the `title` a reader gets on hover and for screen
# readers. The visible label stays the two-letter code because the header has ten pixels of
# room at 375px, measured, and `Українська` needs eighty.
ENDONYM = {"en": "English", "uk": "Українська"}


def switcher(lang, langs):
    """-> the links to the OTHER languages. Nothing at all when there is only one."""
    others = [c for c in langs if c != lang]
    rows = [MARK_SW_OPEN]
    for code in others:
        href = "/" if code == DEFAULT else "/%s/" % code
        # `translate="no"` is not decoration here. This block is generated INTO the source
        # page, so the extractor reads it back and offers `UK` as a string to translate, and
        # the first honest answer to "how do you write UK in Ukrainian" makes the switch
        # unfindable to the reader it exists for.
        rows.append('<a class="lang" translate="no" href="%s" hreflang="%s" lang="%s" '
                    'title="%s">%s</a>'
                    % (href, code, code, ENDONYM.get(code, code), code.upper()))
    rows.append(MARK_SW_CLOSE)
    return "\n    ".join(rows)


def with_switcher(html, lang, langs):
    i, j = html.find(MARK_SW_OPEN), html.find(MARK_SW_CLOSE)
    if i < 0 or j < 0:
        raise SystemExit("site/index.html has no %s region to fill" % MARK_SW_OPEN)
    return html[:i] + switcher(lang, langs) + html[j + len(MARK_SW_CLOSE):]




# ---------------------------------------------------------------- the sitemap

SITEMAP = os.path.join(SITE, "sitemap.xml")

SITEMAP_HEAD = """<?xml version="1.0" encoding="UTF-8"?>
<!--
  GENERATED by tools/i18n.py. One entry per language, and no entry for anything else: anchors
  within a document, or the fixture PDFs robots.txt asks crawlers to leave alone, would be
  padding that does not help a crawler and contradicts the file next to it.

  This was a hand-written file saying, in a comment, that one page is the honest size of this
  site. It was true for as long as that was true. A second language made it false, and a file
  that describes the site is the wrong place for a fact maintained by memory.

  NO lastmod. A date here has to be maintained by hand or it lies, and a stale one is worse
  than none, because it tells a crawler nothing changed when something did. The site deploys
  from git on every push, and the HTTP response carries the truth.

  And no double hyphen anywhere in this comment, nor an angle bracket around a tag name:
  XML forbids the first outright. This file shipped invalid for a day because of one, and
  the check that was supposed to cover it matched loc elements with a regex, which is happy
  to read a document no parser will accept.
-->
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"""


def sitemap(langs):
    rows = [SITEMAP_HEAD]
    for code in langs:
        href = SITE_URL if code == DEFAULT else "%s%s/" % (SITE_URL, code)
        rows.append("  <url>\n    <loc>%s</loc>\n  </url>\n" % href)
    rows.append("</urlset>\n")
    return "".join(rows)


if __name__ == "__main__":
    sys.exit(main())
