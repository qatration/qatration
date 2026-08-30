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
# QUOTED VALUES ARE PART OF THE TAG. This was `<[^>]*>`, which cuts a tag at the first `>` it
# meets even inside an attribute: `<p aria-label="a > b">Sentence.</p>` yielded the key
# `b">Sentence.` and put the translation INSIDE the attribute. One `->` in a title or an alt
# was enough, and because the corruption is deterministic the disk matched the generator and
# the build stayed green.
#
# And a tag STARTS WITH A NAME. Without that, `fewer than < 5 findings` reads `< 5 findings
# here</p>` as a tag and silently swallows the rest of the text node.
TAG = re.compile(r"""(?s)(<[a-zA-Z!/?](?:[^>"']|"[^"]*"|'[^']*')*>)""")
NO_TRANSLATE = ("code", "pre", "kbd", "samp")
HAS_LETTER = re.compile(r"[A-Za-z]")
# ENTITIES ARE NOT WORDS, and their spelling is not language. `HAS_LETTER` matched the letters
# INSIDE one, so a node holding nothing but `&times;` was offered as a string to translate and
# the build then demanded a translation of a multiplication sign.
ENTITY = re.compile(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);")

# NO CLOSING TAG EVER COMES. The skip stack pushes on an opening tag and pops on its close, so
# a void element carrying `translate="no"` - a flag image in the language switch is the obvious
# one - would push and never pop, and every string after it stops being translatable. Measured
# on this page before the fix: 148 keys became 15, and the documented repair (`--extract`) then
# deleted 133 real translations and left every gate green on an English page served as `uk`.
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}

# WRITTEN AS A PATTERN, not as a substring. `' translate="no"' in tag` missed `translate='no'`,
# `TRANSLATE="no"`, and the same attribute preceded by a newline, and each miss puts generated
# text back into the key set.
NO_TR = re.compile(r"""(?i)\stranslate\s*=\s*['"]?no['"]?""")

# Attributes that are read by a person or a search engine rather than by the browser.
ATTR_META = {"description", "og:title", "og:description", "og:image:alt",
             "twitter:title", "twitter:description", "twitter:image:alt"}
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
    # THE FULL ELEMENT STACK, and a DEPTH at which skipping began. A stack of only the skipped
    # names keys on the tag name alone, so `<span translate="no">$<span>pip install</span>` had
    # its inner `</span>` close the outer one and handed the command straight back to the
    # translator - which is how `pip install qatration` was still a translatable string after
    # the element around it was marked. A stray close unwinds to its own name if it has one on
    # the stack and is ignored otherwise, so one malformed tag costs its own element and not
    # the rest of the document.
    out, stack, skip_at, in_title = [], [], None, False
    for chunk in OPAQUE.split(html):
        if OPAQUE.match(chunk or ""):
            out.append(chunk)
            continue
        for part in TAG.split(chunk or ""):
            if not part:
                continue
            if part.startswith("<"):
                name = _tag_name(part)
                if part.startswith("</"):
                    if name in stack:
                        while stack and stack.pop() != name:
                            pass
                    if skip_at is not None and len(stack) < skip_at:
                        skip_at = None
                else:
                    marked = name in NO_TRANSLATE or NO_TR.search(part)
                    if name in VOID or part.rstrip().endswith("/>"):
                        # A VOID ELEMENT HAS NO INSIDE, so it never enters the skip - and the
                        # first version of this therefore translated the `alt` of an `<img
                        # translate="no">`, which is the one attribute such a tag has and the
                        # whole reason it was marked. It is skipped in place instead.
                        if marked:
                            out.append(part)
                            in_title = False
                            continue
                    else:
                        stack.append(name)
                        if skip_at is None and marked:
                            skip_at = len(stack)
                # ONE TEXT NODE, not the rest of the document. `in_title` used to stay true
                # until a `</title>` arrived, so a missing one ran the whitespace-dropping
                # branch over every later string and joined words together.
                in_title = name == "title" and not part.startswith("</")
                # AND ATTRIBUTES OBEY THE SKIP. They did not, so `<input translate="no"
                # placeholder="Email">` still offered `Email` for translation - and the
                # generated language switch, whose whole point is to stay in its own language,
                # was safe only by the accident of `title` not being on the list.
                out.append(part if skip_at is not None
                           else _rewrite_attrs(part, on_attr))
                continue
            if skip_at is not None or not HAS_LETTER.search(ENTITY.sub("", part)):
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
    # A `<` in a translation is text, not the start of an element. Nothing else is escaped:
    # every key on this page carries entities already, so touching `&` would print them.
    rep = rep.replace("<", "&lt;")
    # Leading and trailing whitespace is layout, not language: `<b>46</b> attacks` needs the
    # space before `attacks` to survive, and rendering it away joins two words into one.
    return lead + rep + trail if not in_title else rep


def _esc_attr(s):
    """A translation goes into an attribute as text, never as markup.

    Substitution used to be a raw splice, so one `"` in a translated `og:description` closed
    the attribute early and the remainder of the sentence became a run of bogus attributes.
    `&` is left alone on purpose: the keys on this page carry `&mdash;` and `&amp;` already,
    and re-escaping them would print the entity instead of the character.
    """
    return s.replace('"', "&quot;").replace("<", "&lt;")


def _rewrite_attrs(tag, on_attr):
    key = _meta_key(tag)
    attrs = []
    if key in ATTR_META:
        attrs.append("content")
    # `(?<![\w-])`, NOT `\b`: a word boundary sits between `-` and a letter, so `\balt` matched
    # `data-alt` and `\baria-label` matched `data-aria-label`, translating attributes nobody
    # asked for and that nothing displays.
    for a in ATTR_PLAIN:
        if re.search(r'(?<![\w-])%s\s*=\s*"' % a, tag):
            attrs.append(a)
    for a in attrs:
        m = re.search(r'((?<![\w-])%s\s*=\s*")([^"]*)(")' % a, tag)
        if not m or not HAS_LETTER.search(ENTITY.sub("", m.group(2))):
            continue
        rep = on_attr(tag, a, m.group(2))
        if rep is not None:
            tag = tag[:m.start(2)] + _esc_attr(rep) + tag[m.end(2):]
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


def figures_differ(lang):
    """-> the keys where this language's figures do not line up with the English one for one.

    THE EXCEPTION IS DECLARED, NOT ASSUMED. Figures are compared in order, because `5 of 9` and
    `9 of 5` carry the same digits and opposite claims. Two things break that legitimately, and
    both were found by the check rather than guessed at: Japanese and Korean write `5 of 9` as
    `9 of which 5`, which is correct and reverses them; and both render an English number
    written as a word (`reports a zero`, `three tries`) as a digit, which adds figures the
    English side does not have.

    So a dictionary NAMES the strings where it happens, and for exactly those the demand drops
    to every English figure still being present. Nothing else is relaxed, the list is refused
    if it holds a key that did not need it, and a key it does not name is compared in order.
    """
    import json
    path = os.path.join(DICT_DIR, "%s.json" % lang)
    if not os.path.exists(path):
        return []
    with io.open(path, encoding="utf-8") as f:
        return json.load(f).get("figures_differ") or []


def alternates(langs):
    rows = [MARK_OPEN]
    for code in langs:
        href = SITE_URL if code == DEFAULT else "%s%s/" % (SITE_URL, code)
        rows.append('<link rel="alternate" hreflang="%s" href="%s">' % (code, href))
    rows.append('<link rel="alternate" hreflang="x-default" href="%s">' % SITE_URL)
    rows.append(MARK_CLOSE)
    return "\n".join(rows)


def _fill(html, open_mark, close_mark, block):
    """Replace one marked region. Refuses a region that is not a region.

    The order check is not pedantry: with the close marker first, `html[:i] + block +
    html[j+len:]` re-emits a slab of the document twice and still produces a page that parses.
    """
    i, j = html.find(open_mark), html.find(close_mark)
    if i < 0 or j < 0:
        raise SystemExit("site/index.html has no %s ... %s region to fill"
                         % (open_mark, close_mark))
    if j < i:
        raise SystemExit("%s comes before %s in site/index.html" % (close_mark, open_mark))
    return html[:i] + block + html[j + len(close_mark):]


def with_alternates(html, langs):
    return _fill(html, MARK_OPEN, MARK_CLOSE, alternates(langs))


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
    return out


# ------------------------------------------------------------------- numbers

# Thousands separators are language, the digits are not. `1,500` and `1 500` are the same
# measurement written two ways; `quarante-six` is a number that stopped being checkable.
_SEP = re.compile(r"(?<=\d)[,\u00a0\u202f ](?=\d\d\d\b)")
_NUM = re.compile(r"\d+(?:\.\d+)?")


def numbers(s):
    """-> the figures in a string, IN ORDER.

    Sorted, this compared a multiset, and `5 of 9` matched `9 of 5` while `61 of 138` matched
    `138 of 61`. Both of those are live sentences on this page, and both say something false
    when reversed. Order is the cheap half of the property, and a language that genuinely has
    to reorder two numbers should turn the gate red and be looked at.
    """
    return _NUM.findall(_SEP.sub("", s))


# ----------------------------------------------------------------- the build

def page_path(lang):
    return SOURCE if lang == DEFAULT else os.path.join(SITE, lang, "index.html")


# The English page IS the source, so it carries whatever the last build wrote at the top of it.
# Stripped before anything else runs, or every build prepends another `<html>` start tag.
HTML_OPEN = re.compile(r"(?is)\A<html[^>]*>\s*")


def build(write=True):
    """Regenerate every page. -> list of (path, changed) so `--check` can refuse a hand edit."""
    src = HTML_OPEN.sub("", io.open(SOURCE, encoding="utf-8").read())
    langs = languages()
    done = []
    want = sitemap(langs)
    have = io.open(SITEMAP, encoding="utf-8").read() if os.path.exists(SITEMAP) else None
    done.append((SITEMAP, have != want))
    if write and have != want:
        io.open(SITEMAP, "w", encoding="utf-8", newline="\n").write(want)
    for lang in langs:
        # EVERY PAGE DECLARES ITS LANGUAGE, English included. This was prepended only to
        # translations, so the English page shipped with no `lang` at all: a WCAG 3.1.1
        # failure at level A, and a screen reader pronouncing it in whichever voice the
        # visitor happens to have set.
        out = (with_switcher(with_alternates(src, langs), lang, langs) if lang == DEFAULT
               else render(src, lang, load(lang), langs))
        out = '<html lang="%s">\n' % lang + out
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
MARK_CUR_OPEN = "<!-- i18n:current -->"
MARK_CUR_CLOSE = "<!-- /i18n:current -->"
MARK_OF_OPEN = "<!-- i18n:offer -->"
MARK_OF_CLOSE = "<!-- /i18n:offer -->"
MARK_LC_OPEN = "<!-- i18n:locale -->"
MARK_LC_CLOSE = "<!-- /i18n:locale -->"

# What each language calls itself, for the `title` a reader gets on hover and for screen
# readers. The visible label stays the two-letter code because the header has ten pixels of
# room at 375px, measured, and `Українська` needs eighty.
# The territory each language is announced with to a link preview. `og:locale` wants a full
# locale, not a language code, and there is no way to derive one: `pt` could be pt_BR or pt_PT,
# and the choice here is Brazil because that is where the readers are. A language without an
# entry is refused rather than guessed at.
LOCALE = {
    "cs": "cs_CZ", "de": "de_DE", "en": "en_US", "es": "es_ES", "fr": "fr_FR",
    "id": "id_ID", "it": "it_IT", "ja": "ja_JP", "ko": "ko_KR", "nl": "nl_NL",
    "pl": "pl_PL", "pt": "pt_BR", "tr": "tr_TR", "uk": "uk_UA",
    "vi": "vi_VN", "zh": "zh_CN",
}

ENDONYM = {
    "en": "English",
    "cs": "Čeština",
    "de": "Deutsch",
    "es": "Español",
    "fr": "Français",
    "id": "Bahasa Indonesia",
    "it": "Italiano",
    "ja": "日本語",
    "ko": "한국어",
    "nl": "Nederlands",
    "pl": "Polski",
    "pt": "Português",
    "tr": "Türkçe",
    "uk": "Українська",
    "vi": "Tiếng Việt",
    "zh": "简体中文",
}


def switcher(lang, langs):
    """-> one entry per language, the current one marked. Every language, not just the others:
    a menu that hides the page you are on cannot tell you which page that is."""
    rows = [MARK_SW_OPEN]
    for code in langs:
        # A LANGUAGE WITHOUT A NAME FOR ITSELF IS A BUG, not a fallback. Falling back to the
        # code printed `FR` as the whole accessible name, and the affordance quietly stopped
        # working for exactly the reader it exists for.
        if code not in ENDONYM:
            raise SystemExit("no ENDONYM entry for %r in tools/i18n.py: a language switch "
                             "needs the name that language uses for itself" % code)
        href = "/" if code == DEFAULT else "/%s/" % code
        # THE NAME IS VISIBLE NOW, not off-screen. It was `sr-only`, which meant the reader
        # who most needs it - the one who cannot read the page this menu sits on - got two
        # letters, and `UK` read aloud is United Kingdom. Ten rows of two characters was also
        # a tall empty column, and this is the one thing that belongs in that space.
        rows.append('<a class="lang" translate="no" href="%s" hreflang="%s"%s>'
                    '<span class="lang-code">%s</span>'
                    '<span class="lang-name" lang="%s">%s</span></a>'
                    % (href, code, ' aria-current="page"' if code == lang else "",
                       code.upper(), code, ENDONYM[code]))
    rows.append(MARK_SW_CLOSE)
    return "\n      ".join(rows)


def current(lang):
    """-> the code shown on the closed disclosure."""
    return "%s%s%s" % (MARK_CUR_OPEN, lang.upper(), MARK_CUR_CLOSE)


def offer(langs):
    """-> the language list the offer bar reads, as JSON inside a script element.

    A `script` body is opaque to `walk`, which is the point: this is generated INTO the source
    page, so anything here that looked like prose would be read straight back out as a string
    to translate. Codes and the name each language uses for itself, and nothing else.
    """
    import json
    listing = json.dumps({c: ENDONYM[c] for c in langs}, ensure_ascii=False, sort_keys=True)
    # THE MARKERS STAY OUTSIDE THE ISLAND. Inside a `script` element an HTML comment is not a
    # comment: the parser hands the whole body through as text, so the marker pair landed
    # inside the JSON and `JSON.parse` threw. The offer bar then did nothing at all, silently,
    # because that parse is wrapped in the try/catch that keeps a locked-down browser working.
    # Found by opening the page, not by any check in this repository - which is why one now
    # parses the island offline.
    return ('%s\n  <script type="application/json" id="i18n-langs">%s</script>\n  %s'
            % (MARK_OF_OPEN, listing, MARK_OF_CLOSE))


def locales(lang, langs):
    """-> og:locale for this page and og:locale:alternate for the others."""
    missing = [c for c in langs if c not in LOCALE]
    if missing:
        raise SystemExit("no LOCALE entry for %s in tools/i18n.py: og:locale needs a full "
                         "locale and there is no way to derive one from a language code"
                         % ", ".join(missing))
    rows = [MARK_LC_OPEN,
            '<meta property="og:locale" content="%s">' % LOCALE[lang]]
    for code in langs:
        if code != lang:
            rows.append('<meta property="og:locale:alternate" content="%s">' % LOCALE[code])
    rows.append(MARK_LC_CLOSE)
    return "\n".join(rows)


def with_switcher(html, lang, langs):
    html = _fill(html, MARK_SW_OPEN, MARK_SW_CLOSE, switcher(lang, langs))
    html = _fill(html, MARK_CUR_OPEN, MARK_CUR_CLOSE, current(lang))
    html = _fill(html, MARK_LC_OPEN, MARK_LC_CLOSE, locales(lang, langs))
    return _fill(html, MARK_OF_OPEN, MARK_OF_CLOSE, offer(langs))




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
