use std::io::Cursor;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

/// The Graphviz SVG output vocabulary this sanitizer lets through
/// (besides `a`, which is unwrapped rather than allowed verbatim — see
/// [`UNWRAPPED_ELEMENTS`]): every element name a real Graphviz render
/// actually emits. Security MINOR fix: this replaced a deny-list of
/// just `script`/`foreignObject`/`image`, so an element Graphviz never
/// emits (`<iframe>`, `<embed>`, `<p>`, any other HTML element a label
/// or attribute value could smuggle in) is refused by default, including
/// its children, rather than requiring its own blacklist entry.
///
/// `style` is deliberately not here: the only `style` *attribute* value
/// a real Graphviz render emits (`stop-color:...;stop-opacity:...;` on
/// gradient `<stop>` elements) is handled by [`ALLOWED_ATTRIBUTES`] (only
/// `stop` lists `style` at all) and [`is_safe_stop_style_value`], and the
/// only `<style>` *element* Fabro's own output ever carries is the
/// dark-mode CSS [`crate::render::postprocess_svg`] adds — after
/// sanitizing, never before — so a `<style>` element reaching this
/// sanitizer is always attacker-controlled and is dropped like any
/// other disallowed element.
const ALLOWED_ELEMENTS: &[&[u8]] = &[
    b"svg",
    b"g",
    b"title",
    b"desc",
    b"polygon",
    b"polyline",
    b"path",
    b"ellipse",
    b"circle",
    b"line",
    b"rect",
    b"text",
    b"tspan",
    b"defs",
    b"lineargradient",
    b"radialgradient",
    b"stop",
];

/// Elements unwrapped: the open/close tags are dropped (so no `href` link
/// survives) but their children are kept, since `run-overview` and the
/// visualize page both depend on `<g class="node">`/`<title>` surviving
/// inside what Graphviz wraps in an anchor.
const UNWRAPPED_ELEMENTS: &[&[u8]] = &[b"a"];

/// Graphviz's own SVG attribute vocabulary, per element (matched by
/// [`ALLOWED_ELEMENTS`]'s lowercase local name): the exact attribute
/// names — full, including any namespace prefix, exactly as Graphviz
/// itself always spells them (SVG's own mixed-case names, e.g.
/// `viewBox`/`gradientUnits`, included) — a real render ever carries on
/// that element. Confirmed against `dot -Tsvg` across clusters, records,
/// HTML labels (including `<font>`/`<b>`/`<i>`/`<u>`/`<s>`/`<sub>`/
/// `<sup>` runs), linear and radial gradients, arrowheads, alpha-channel
/// colors (confirmed fix: Graphviz never writes an attribute value that
/// itself carries an alpha channel — `fontcolor="#ff000080"` splits into
/// a plain opaque `fill`/`stroke` color plus a separate `fill-opacity`/
/// `stroke-opacity`, both already listed below), tooltips/ids/classes
/// and edge (and edge-end) labels.
///
/// Matched case-sensitively against this exact spelling: a
/// differently-cased name is not one Graphviz itself ever writes, and is
/// dropped like anything else missing from its element's list. Security
/// MINOR fix: this replaces the previous open "keep everything except
/// `href`/`on*`/an unsafe `style`" policy. A presentation attribute like
/// `cursor`/`filter`/`mask` that a crafted `fontname`/`labelfontname`/
/// `stylesheet` breakout smuggled onto an otherwise-allowed element (see
/// `fabro_dot::graphviz`'s `RAW_TEXT_ATTRS` for the matching source-side
/// fix) is simply never in any element's list here, so it is always
/// dropped, regardless of its value — the browser-side outbound-load
/// channel (`image-set(...)`/`cursor: url(...)`/...) that value-level
/// pattern matching alone could miss is closed by construction instead.
///
/// `style` is further restricted beyond appearing in this list at all —
/// see [`is_safe_stop_style_value`]. Any kept value containing `url(` is
/// also restricted beyond being named here — see
/// [`is_local_fragment_url`]: only a same-document fragment reference
/// (`url(#<id>)`, e.g. a gradient-filled shape's `fill`) is kept; an
/// absolute or relative URL is not, since it can make a viewer's browser
/// fetch an attacker-chosen resource (SSRF/tracking) the moment the SVG
/// is embedded.
///
/// `labelaligned` edge labels — Graphviz's own curved/rotated edge-label
/// rendering, which wraps the label text in a `<textPath
/// xlink:href="#<path-id>">`/`<tspan dy="...">` that references a
/// sibling `<path>`'s own `id` — are a deliberate gap, not an oversight:
/// `textPath` is not in [`ALLOWED_ELEMENTS`] and `path` has no `id` in
/// its own list here, so a `labelaligned` label's `<textPath>` (and the
/// text nested inside it) is dropped like any other disallowed element.
/// Keeping it would mean carving an `xlink:href` exception into
/// [`filter_attributes`]'s belt-and-suspenders drop of every `href`
/// attribute regardless of element or value; this sanitizer keeps that
/// invariant exception-free instead, at the cost of a `labelaligned`
/// edge rendering with its label text silently missing — the edge
/// itself, and every non-`labelaligned` label, is unaffected.
const ALLOWED_ATTRIBUTES: &[(&[u8], &[&str])] = &[
    (b"svg", &[
        "width",
        "height",
        "viewBox",
        "xmlns",
        "xmlns:xlink",
    ]),
    (b"g", &["id", "class", "transform"]),
    (b"title", &[]),
    (b"desc", &[]),
    (b"polygon", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "points",
    ]),
    (b"polyline", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "points",
    ]),
    (b"path", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "d",
    ]),
    (b"ellipse", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "cx",
        "cy",
        "rx",
        "ry",
    ]),
    (b"circle", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "cx",
        "cy",
        "r",
    ]),
    (b"line", &[
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "stroke-opacity",
        "x1",
        "y1",
        "x2",
        "y2",
    ]),
    (b"rect", &[
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "fill-opacity",
        "stroke-opacity",
        "x",
        "y",
        "width",
        "height",
        "rx",
        "ry",
    ]),
    (b"text", &[
        "x",
        "y",
        "text-anchor",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "font-stretch",
        "text-decoration",
        "baseline-shift",
        "fill",
        "fill-opacity",
        "xml:space",
    ]),
    (b"tspan", &[
        "x",
        "y",
        "text-anchor",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "font-stretch",
        "text-decoration",
        "baseline-shift",
        "fill",
        "fill-opacity",
        "xml:space",
    ]),
    (b"defs", &[]),
    (b"lineargradient", &[
        "id",
        "gradientUnits",
        "x1",
        "y1",
        "x2",
        "y2",
    ]),
    (b"radialgradient", &[
        "id",
        "gradientUnits",
        "cx",
        "cy",
        "r",
        "fx",
        "fy",
    ]),
    (b"stop", &["offset", "style"]),
];

/// Sanitize untrusted-source SVG (from rendering a workflow loaded over a
/// URL) for safe embedding via `innerHTML`: re-emits only an explicit
/// allowlist of *events* — `Start`/`Empty`/`End` of an allowlisted
/// element (see [`ALLOWED_ELEMENTS`], attributes filtered through
/// [`filter_attributes`]), `Text`, and `GeneralRef` (an `&entity;`
/// reference inside text) — and drops everything else outright:
/// `Decl` (the `<?xml ...?>` declaration — quick-xml parses *any*
/// `<?xml ...?>` as `Decl`, not only a document's own leading one, and
/// innerHTML needs no declaration at all, so it is never kept, not even
/// the genuine leading one), `PI` (e.g. Graphviz's `stylesheet` graph
/// attribute emits `<?xml-stylesheet ...?>`), `Comment`, `CData` and
/// `DocType`. This was previously a deny-list of event *kinds* with a
/// catch-all passthrough for everything not explicitly named; the
/// catch-all let a `Decl` (or any future quick-xml event kind) through
/// verbatim. That mattered concretely for `Decl`: an HTML tokenizer
/// treats any `<?...?>` as a "bogus comment" ending at the first `>`,
/// so a value like `<?xml q="><img src=x onerror=1>"?>` — smuggled in,
/// e.g., through a node's `fontname` attribute, which Graphviz writes
/// unescaped into `font-family="..."` — was written back unescaped and
/// then ran as markup once inserted via `innerHTML`.
///
/// Single-root enforcement (MINOR security fix): only the *first*
/// top-level `Start`/`Empty` event is ever kept, as the sole root — this
/// is what `postprocess_svg`'s dark-mode-CSS insertion and the web app's
/// own `querySelector("svg")` both assume. Graphviz's `stylesheet`
/// attribute can put an attacker `<svg>` *before* Graphviz's own root
/// (via the malformed `<?xml-stylesheet ...?>` PI it is written into,
/// closed early), and a `fontname` breakout can close the real root and
/// open further top-level `<svg>`s *after* it; either way, everything
/// outside the first top-level element's own subtree is dropped —
/// non-whitespace text or another element before it, and everything
/// (well-formed or not) after its matching `End`. Whitespace text before
/// the root is kept (it has no effect once embedded).
///
/// The first top-level `Start`/`Empty` event's own tag name must
/// additionally be exactly `svg` — matched against the full name as
/// written, case-sensitively, with no namespace prefix (so neither a
/// `<g>` nor a `<svg:svg>` qualifies) — the one root tag a real
/// Graphviz render ever emits; anything else fails closed
/// (`Err(SanitizeError)`) rather than treating a non-`svg` root as
/// though it were safe to keep (filtered, unwrapped, or skipped) like
/// any other element.
///
/// `<script>` and `<foreignObject>` (arbitrary script/HTML), `<image>`
/// (an arbitrary, including local-filesystem, URL), `<style>` (see
/// [`ALLOWED_ELEMENTS`]'s doc comment), and any other HTML element are
/// dropped along with their children. Every kept element's attributes
/// are filtered down to [`ALLOWED_ATTRIBUTES`]'s per-element allowlist
/// (see [`filter_attributes`]) — `href`/`xlink:href` and any `on*`
/// event-handler attribute are additionally dropped outright, as a
/// defense-in-depth belt, even though the allowlist alone already
/// excludes them from every element. Every element and attribute name is
/// also checked against a strict allowlist (`^[A-Za-z_][A-Za-z0-9_.:-]*$`);
/// anything else — e.g. an attribute name containing `/`, which an HTML
/// tokenizer can split into a second, unfiltered attribute — is dropped
/// rather than copied verbatim. Every kept attribute value is decoded
/// then re-escaped before it is written back out, so a value that was
/// quoted differently than the output's always-double-quoted attributes
/// cannot break out of its quotes.
///
/// Fails closed: invalid XML input, an unparsable attribute, or an
/// attribute value that cannot be decoded and unescaped returns
/// `Err(SanitizeError)` rather than the raw or partially-filtered input.
/// Graphviz output is always well-formed, so this only matters
/// defensively — the caller must treat `Err` as a render failure and must
/// never fall back to the unsanitized bytes.
pub fn sanitize_svg(svg: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    let mut reader = Reader::from_reader(svg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    // Count of dropped-element open tags we are currently inside, including
    // nested same- or different-named dropped elements.
    let mut skip_depth: u32 = 0;
    // Single-root enforcement: the first top-level `Start`/`Empty` event
    // becomes the only element this function ever keeps. `root_depth`
    // counts open tags inside it (every `Start`/`End` is balanced in
    // well-formed XML, regardless of allowed/skipped status) so its own
    // matching `End` can be recognized; `done` is then set, and every
    // later event is dropped, along with anything that appeared before
    // the root was found (other than whitespace text).
    let mut root_found = false;
    let mut root_depth: u32 = 0;
    let mut done = false;

    loop {
        buf.clear();
        let event = match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(event) => event,
            Err(_) => return Err(SanitizeError),
        };

        if done {
            continue;
        }

        let is_root_start = !root_found && matches!(&event, Event::Start(_) | Event::Empty(_));
        if is_root_start {
            let root_name = match &event {
                Event::Start(start) | Event::Empty(start) => start.name(),
                _ => unreachable!("is_root_start is only true for Start/Empty events"),
            };
            if root_name.as_ref() != b"svg" {
                return Err(SanitizeError);
            }
            root_found = true;
        }
        if !root_found {
            if let Event::Text(text) = event {
                if (text.as_ref() as &[u8]).iter().all(u8::is_ascii_whitespace) {
                    writer
                        .write_event(Event::Text(text))
                        .map_err(|_| SanitizeError)?;
                }
            }
            continue;
        }

        match event {
            // Drop every event kind this sanitizer does not explicitly
            // re-emit below. See this function's doc comment for why
            // `Decl` (the `<?xml ...?>` declaration) is included here
            // rather than kept.
            Event::Decl(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::CData(_)
            | Event::DocType(_) => {}
            Event::Start(start) => {
                root_depth += 1;
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                let local = local_name_lower(&start);
                // `a` must be checked before the allowlist: it is
                // deliberately not in `ALLOWED_ELEMENTS` (its open/close
                // tags are unwrapped, not kept), not refused along with
                // its children like every other non-allowed element.
                if is_unwrapped(&local) {
                    continue;
                }
                if !is_allowed(&local) || !is_valid_name(start.name().as_ref()) {
                    skip_depth = 1;
                    continue;
                }
                let filtered = filter_attributes(&local, &start)?;
                writer
                    .write_event(Event::Start(filtered))
                    .map_err(|_| SanitizeError)?;
            }
            Event::Empty(start) => {
                if skip_depth == 0 {
                    let local = local_name_lower(&start);
                    if !is_unwrapped(&local)
                        && is_allowed(&local)
                        && is_valid_name(start.name().as_ref())
                    {
                        let filtered = filter_attributes(&local, &start)?;
                        writer
                            .write_event(Event::Empty(filtered))
                            .map_err(|_| SanitizeError)?;
                    }
                }
                if root_depth == 0 {
                    // This `Empty` event was the root itself
                    // (self-closing, e.g. a bare `<svg/>`): it has no
                    // separate `End` to wait for.
                    done = true;
                }
            }
            Event::End(end) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                } else {
                    let local = end.name().local_name().as_ref().to_ascii_lowercase();
                    if !is_unwrapped(&local) {
                        writer
                            .write_event(Event::End(end))
                            .map_err(|_| SanitizeError)?;
                    }
                }
                root_depth = root_depth.saturating_sub(1);
                if root_depth == 0 {
                    done = true;
                }
            }
            Event::Text(text) => {
                if skip_depth == 0 {
                    writer
                        .write_event(Event::Text(text))
                        .map_err(|_| SanitizeError)?;
                }
            }
            // An `&entity;`/`&#NN;` reference inside text content.
            // quick-xml splits these out of `Text` rather than leaving
            // them embedded in it; re-emit verbatim (wrapped back in
            // `&`/`;` by the writer) alongside the `Text` runs around it
            // when not inside a dropped element. The reader itself
            // refuses (fails the whole parse, so `sanitize_svg` returns
            // `Err` rather than any partially-filtered output) a
            // reference whose content reaches a `<` before its closing
            // `;`, so this can never smuggle in a tag.
            Event::GeneralRef(reference) => {
                if skip_depth == 0 {
                    writer
                        .write_event(Event::GeneralRef(reference))
                        .map_err(|_| SanitizeError)?;
                }
            }
            Event::Eof => unreachable!("Event::Eof is consumed by the read loop above"),
        }
    }

    Ok(writer.into_inner().into_inner())
}

/// Error returned by [`sanitize_svg`] on any parse, attribute, or encoding
/// failure. Carries no detail: the caller only needs to know the input
/// could not be safely sanitized.
#[derive(Debug)]
pub struct SanitizeError;

impl std::fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("svg sanitization failed: malformed or unparsable input")
    }
}

impl std::error::Error for SanitizeError {}

fn local_name_lower(start: &BytesStart<'_>) -> Vec<u8> {
    start.name().local_name().as_ref().to_ascii_lowercase()
}

fn is_allowed(local_name_lower: &[u8]) -> bool {
    ALLOWED_ELEMENTS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(local_name_lower))
}

fn is_unwrapped(local_name_lower: &[u8]) -> bool {
    UNWRAPPED_ELEMENTS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(local_name_lower))
}

/// `^[A-Za-z_][A-Za-z0-9_.:-]*$`: the strict XML/HTML name charset Graphviz
/// itself only ever emits. Anything outside it (e.g. a `/` embedded in an
/// attribute name) is rejected rather than copied verbatim, since an HTML
/// tokenizer parses tag/attribute boundaries differently than XML does.
fn is_valid_name(name: &[u8]) -> bool {
    match name.first() {
        Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' => {}
        _ => return false,
    }
    name[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

/// Whether `element_local_lower` lists `key` (the attribute's full name,
/// exactly as written, including any namespace prefix) in
/// [`ALLOWED_ATTRIBUTES`].
fn is_allowed_attribute(element_local_lower: &[u8], key: &str) -> bool {
    ALLOWED_ATTRIBUTES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(element_local_lower))
        .is_some_and(|(_, attrs)| attrs.contains(&key))
}

/// Whether a `<stop>` element's `style` value is exactly one or more
/// `;`-separated `stop-color:<token>`/`stop-opacity:<token>`
/// declarations — the only `style` value a real Graphviz render ever
/// emits (confirmed against `dot -Tsvg` across linear and radial
/// gradients). `<token>` is restricted to the charset a color name, a
/// `#rrggbb` hex color, or a decimal opacity ever needs, so it can never
/// carry a nested value expression: no `(`, `"`, `'`, `<`, `>`, `&`, or
/// backslash.
fn is_safe_stop_style_value(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    value.trim_end_matches(';').split(';').all(|declaration| {
        let Some((property, token)) = declaration.split_once(':') else {
            return false;
        };
        let property = property.trim();
        let token = token.trim();
        (property == "stop-color" || property == "stop-opacity")
            && !token.is_empty()
            && token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'#' | b'.' | b'%' | b'-' | b',' | b' ')
            })
    })
}

/// Whether `value` is exactly `url(#<id>)`, referencing a same-document
/// fragment (e.g. a `<linearGradient>`/`<radialGradient>`'s own `id`) —
/// the one real use of `url(...)` a Graphviz render's SVG carries
/// (`fill="url(#...)"` on a gradient-filled shape). `<id>` accepts any
/// non-empty run of characters other than `)`, `"`, `'`, `\`, or
/// whitespace — not a guess at Graphviz's own `id` charset, but exactly
/// what keeps this a single well-formed `url(#...)` value rather than a
/// seam a crafted `id` could use to smuggle something else through.
fn is_local_fragment_url(value: &str) -> bool {
    let Some(id) = value
        .strip_prefix("url(#")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    !id.is_empty()
        && !id
            .chars()
            .any(|ch| matches!(ch, ')' | '"' | '\'' | '\\') || ch.is_whitespace())
}

/// Whether a non-`style` attribute value is safe to keep. Rejected
/// outright if it contains any backslash — a value's only use for one
/// is a CSS escape (e.g. `\75 rl(`, spelling `url(` past a naive
/// substring check) trying to smuggle something a literal scan would
/// miss. Otherwise kept unless its *lowercased* form contains `url(` —
/// a real Graphviz render only ever writes a lowercase `url(`, so any
/// other case (`URL(`, `Url(`, ...) is already suspect — in which case
/// it is kept only when the value *as written* (not lowercased: an
/// `id` is case-sensitive, so a lowercased comparison could accept a
/// differently-cased reference that does not actually match any
/// in-document id) is exactly a local fragment reference — see
/// [`is_local_fragment_url`]. Anything else containing `url(`, in any
/// case — an absolute or relative URL, extra text around a
/// `url(...)`, or a differently-cased variant no real render ever
/// writes — is rejected: it can make a viewer's browser fetch an
/// attacker-chosen resource the moment the SVG is embedded.
fn is_safe_attribute_value(value: &str) -> bool {
    if value.contains('\\') {
        return false;
    }
    if !value.to_ascii_lowercase().contains("url(") {
        return true;
    }
    is_local_fragment_url(value)
}

/// Filter `start`'s attributes down to [`ALLOWED_ATTRIBUTES`]'s list for
/// `element_local_lower`, decoded then re-escaped so a value that was
/// quoted differently than the output's always-double-quoted attributes
/// cannot break out of its quotes. `href`/`xlink:href` (both have local
/// name `href`) and any `on*` event-handler attribute are dropped
/// outright, as a defense-in-depth belt, even though the allowlist alone
/// already excludes them from every element. `style` is kept only when
/// [`is_safe_stop_style_value`] accepts it — combined with the allowlist
/// only naming `style` on `stop` at all, this means it survives nowhere
/// else; every other kept value is dropped unless
/// [`is_safe_attribute_value`] accepts it (the `url(...)` restriction).
fn filter_attributes(
    element_local_lower: &[u8],
    start: &BytesStart<'_>,
) -> Result<BytesStart<'static>, SanitizeError> {
    let mut filtered = start.to_owned();
    filtered.clear_attributes();
    for attr in start.attributes() {
        let attr = attr.map_err(|_| SanitizeError)?;
        if !is_valid_name(attr.key.as_ref()) {
            continue;
        }
        let local_lower =
            String::from_utf8_lossy(attr.key.local_name().as_ref()).to_ascii_lowercase();
        if local_lower == "href" || local_lower.starts_with("on") {
            continue;
        }
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        if !is_allowed_attribute(element_local_lower, &key) {
            continue;
        }
        let value = attr.unescape_value().map_err(|_| SanitizeError)?;
        let keep = if key == "style" {
            is_safe_stop_style_value(&value)
        } else {
            is_safe_attribute_value(&value)
        };
        if !keep {
            continue;
        }
        filtered.push_attribute((key.as_str(), value));
    }
    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use quick_xml::Reader;
    use quick_xml::events::Event;

    use super::sanitize_svg;
    use crate::render::{RenderableDot, postprocess_svg, render_dot, render_raw_svg};

    fn sanitized(svg: &str) -> String {
        String::from_utf8(
            sanitize_svg(svg.as_bytes())
                .expect("sanitize_svg should not fail on well-formed input"),
        )
        .expect("sanitized output should be UTF-8")
    }

    /// Count of each lowercased local element name (`Start`+`Empty`
    /// occurrences; `End` is not separately counted, so this is one
    /// count per element instance) appearing in `svg`.
    fn element_name_counts(svg: &str) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        let mut reader = Reader::from_str(svg);
        let mut buf = Vec::new();
        loop {
            let event = reader
                .read_event_into(&mut buf)
                .unwrap_or_else(|err| panic!("failed to parse SVG: {err}\n{svg}"));
            match event {
                Event::Eof => break,
                Event::Start(start) | Event::Empty(start) => {
                    let name = String::from_utf8_lossy(start.name().local_name().as_ref())
                        .to_ascii_lowercase();
                    *counts.entry(name).or_insert(0) += 1;
                }
                _ => {}
            }
            buf.clear();
        }
        counts
    }

    /// Count of each `(lowercased local element name, full attribute
    /// name)` pair appearing in `svg`, excluding the `a` element
    /// entirely (it is unwrapped, not refused, by the real sanitizer —
    /// see [`super::UNWRAPPED_ELEMENTS`]) and the `href`/`xlink:href`/
    /// `target` attributes (dropped along with `a` itself; `target`
    /// only ever appears on `a` in a real Graphviz render).
    fn element_attribute_pair_counts(svg: &str) -> HashMap<(String, String), usize> {
        let mut counts = HashMap::new();
        let mut reader = Reader::from_str(svg);
        let mut buf = Vec::new();
        loop {
            let event = reader
                .read_event_into(&mut buf)
                .unwrap_or_else(|err| panic!("failed to parse SVG: {err}\n{svg}"));
            match event {
                Event::Eof => break,
                Event::Start(start) | Event::Empty(start) => {
                    let element = String::from_utf8_lossy(start.name().local_name().as_ref())
                        .to_ascii_lowercase();
                    if element != "a" {
                        for attr in start.attributes() {
                            let attr = attr.unwrap_or_else(|err| {
                                panic!("failed to parse attribute: {err}\n{svg}")
                            });
                            let name = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            if matches!(name.as_str(), "href" | "xlink:href" | "target") {
                                continue;
                            }
                            *counts.entry((element.clone(), name)).or_insert(0) += 1;
                        }
                    }
                }
                _ => {}
            }
            buf.clear();
        }
        counts
    }

    #[test]
    fn sanitize_svg_strips_links_scripts_and_handlers() {
        let raw = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<?xml-stylesheet href="dark.css" type="text/css"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(1)</script>
<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">hi</body></foreignObject>
<image href="file:///etc/hosts"/>
<g class="node" onclick="evil()">
<title>a</title>
<a xlink:href="javascript:alert(1)" target="_blank">
<polygon fill="white"/>
</a>
</g>
</svg>"#;

        let out = sanitized(raw);

        assert!(!out.contains("<script"));
        assert!(!out.contains("<foreignObject"));
        assert!(!out.contains("<image"));
        assert!(!out.contains("href="));
        assert!(!out.contains("xlink:href"));
        assert!(!out.contains("onclick"));
        assert!(!out.contains("<?xml-stylesheet"));
        assert!(!out.contains("<a "));
        assert!(!out.contains("</a>"));
        // The leading `<?xml version=...?>` declaration is dropped too:
        // quick-xml parses *any* `<?xml ...?>` as `Decl`, so this is not
        // special-cased to survive; innerHTML needs no declaration.
        assert!(!out.contains("<?xml"), "{out}");
        // Kept: the node's class/id and title.
        assert!(out.contains(r#"class="node""#));
        assert!(out.contains("<title>a</title>"));
        assert!(out.contains("<polygon"));
    }

    #[test]
    fn sanitize_svg_unwraps_anchor_children() {
        let raw = r#"<svg><g><a xlink:href="javascript:alert(1)"><title>n</title><polygon/></a></g></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("<a"));
        assert!(out.contains("<title>n</title>"));
        assert!(out.contains("<polygon/>"));
    }

    #[test]
    fn sanitize_svg_keeps_text_and_entity_references() {
        let raw = r"<svg><text>hello &amp; world</text></svg>";
        let out = sanitized(raw);
        assert!(out.contains("hello &amp; world"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_style_elements_entirely() {
        // MAJOR: `style` is no longer in the element allowlist at all —
        // its one legitimate use (Graphviz's own dark-mode CSS) is
        // injected by `postprocess_svg` after sanitizing, never
        // surviving from untrusted input — so no `@import` bypass
        // crafted to dodge a text-level at-rule stripper matters any
        // more: the whole element, and its text (including any entity
        // reference inside it), is dropped like any other disallowed
        // element's content.
        for bypass in [
            "@imp@import x;ort url(https://evil.example/a.css)",
            "@imp&#111;rt url(https://evil.example/a.css)",
            "@\\69mport url(https://evil.example/a.css)",
        ] {
            let raw = format!(r"<svg><style>{bypass}</style><text>kept</text></svg>");
            let out = sanitized(&raw);
            assert!(!out.contains("<style"), "{bypass}: {out}");
            assert!(!out.contains("evil.example"), "{bypass}: {out}");
            assert!(out.contains("<text>kept</text>"), "{bypass}: {out}");
        }
    }

    #[test]
    fn sanitize_svg_keeps_a_safe_style_attribute_value() {
        // The one `style` *attribute* value a real Graphviz render
        // emits (gradient `<stop>` elements' `stop-color`/`stop-opacity`)
        // must survive; it carries no `url(`/`(`/`"`/`<`/`>`/`&`/`\`.
        let raw = r#"<svg><defs><linearGradient id="g"><stop offset="0" style="stop-color:blue;stop-opacity:1.;"/></linearGradient></defs></svg>"#;
        let out = sanitized(raw);
        assert!(
            out.contains(r#"style="stop-color:blue;stop-opacity:1.;""#),
            "{out}"
        );
    }

    #[test]
    fn sanitize_svg_drops_an_unsafe_style_attribute_value() {
        // Security MINOR, belt and suspenders: the per-element
        // attribute allowlist already drops `style` everywhere except
        // `<stop>` (so every one of these would already be gone on
        // `<g>` regardless of value); `is_safe_stop_style_value` is the
        // second, value-level check for the one element that does list
        // it, so none of these survive there either.
        for value in [
            "background:url(https://evil.example/a.png)",
            "@import url(https://evil.example/a.css)",
            "background:\\75rl(https://evil.example/a.png)",
            "width:expression(alert(1))",
        ] {
            let raw = format!(r#"<svg><g style="{value}"><title>t</title></g></svg>"#);
            let out = sanitized(&raw);
            assert!(!out.contains("style="), "{value}: {out}");
            assert!(!out.contains("evil.example"), "{value}: {out}");

            let raw = format!(
                r#"<svg><defs><linearGradient id="g"><stop offset="0" style="{value}"/></linearGradient></defs></svg>"#
            );
            let out = sanitized(&raw);
            assert!(!out.contains("style="), "{value}: {out}");
            assert!(!out.contains("evil.example"), "{value}: {out}");
        }
    }

    #[test]
    fn sanitize_svg_drops_presentation_attributes_outside_the_allowlist() {
        // Security MINOR: a crafted `fontname`/`labelfontname`/
        // `stylesheet` breakout can smuggle an extra attribute onto an
        // otherwise-allowed element — `cursor`, `filter`, `mask`, a
        // `style` with `image-set(...)`/`-webkit-image-set(...)` — that
        // would make a viewer's browser fetch an attacker-chosen
        // resource the moment the SVG is embedded or hovered. None of
        // these are in any element's `ALLOWED_ATTRIBUTES` list, so they
        // are dropped regardless of value.
        let raw = r#"<svg><g><text style="mask-image:image-set('https://evil.example/a.png' 1x)" cursor="url(https://evil.example/b.png),auto">t</text><polygon style="background:-webkit-image-set(url(https://evil.example/c.png) 1x)" filter="url(https://evil.example/d.svg#f)" fill="black" points="0,0"/></g></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("evil.example"), "{out}");
        assert!(!out.contains("style="), "{out}");
        assert!(!out.contains("cursor="), "{out}");
        assert!(!out.contains("filter="), "{out}");
        assert!(out.contains(r#"fill="black""#), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_a_webkit_image_set_cursor_on_text() {
        // tests-r7 finding 1 guard: `cursor` is not in `<text>`'s own
        // `ALLOWED_ATTRIBUTES` entry regardless of value, so a
        // `-webkit-image-set(url(...))` breakout smuggled onto it as
        // `cursor` must still be dropped outright, not merely
        // value-filtered.
        let raw = r#"<svg><text cursor="-webkit-image-set(url(https://evil.example/a.png) 1x)">t</text></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("cursor="), "{out}");
        assert!(!out.contains("evil.example"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_an_uppercase_style_attribute_on_stop() {
        // tests-r7 finding 1 guard: `ALLOWED_ATTRIBUTES` lists `style`
        // (lowercase) on `<stop>` only; a differently-cased `STYLE`
        // attribute must not match it, since attribute names are
        // matched case-sensitively against the exact spelling Graphviz
        // itself writes.
        let raw = r#"<svg><defs><linearGradient id="g"><stop offset="0" STYLE="stop-color:red;stop-opacity:1.;"/></linearGradient></defs></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("STYLE"), "{out}");
        assert!(!out.contains("style="), "{out}");
    }

    #[test]
    fn sanitize_svg_keeps_a_local_gradient_fragment_url_but_drops_any_other() {
        let safe = r#"<svg><defs><linearGradient id="g"/></defs><polygon fill="url(#g)" points="0,0"/></svg>"#;
        let out = sanitized(safe);
        assert!(out.contains(r#"fill="url(#g)""#), "{out}");

        for unsafe_value in [
            r#"<svg><polygon fill="url(https://evil.example/x.svg#g)" points="0,0"/></svg>"#,
            r#"<svg><polygon fill="url(#g) extra" points="0,0"/></svg>"#,
            r#"<svg><polygon fill="URL(#g)" points="0,0"/></svg>"#,
            r#"<svg><polygon fill="Url(#g)" points="0,0"/></svg>"#,
            r#"<svg><polygon fill="\75 rl(#g)" points="0,0"/></svg>"#,
        ] {
            let out = sanitized(unsafe_value);
            assert!(!out.contains("fill="), "{unsafe_value}: {out}");
            assert!(!out.contains("evil.example"), "{unsafe_value}: {out}");
        }
    }

    #[test]
    fn sanitize_svg_keeps_only_the_first_top_level_svg_root() {
        // Security MINOR: Graphviz's `stylesheet` attribute can put an
        // attacker `<svg>` before Graphviz's own root (via the
        // malformed `<?xml-stylesheet ...?>` processing instruction it
        // is written into, closed early), and a `fontname` breakout can
        // close the real root and open further top-level `<svg>`s after
        // it. Either way, the output must stay single-rooted: whichever
        // top-level `Start`/`Empty` event comes first becomes the kept
        // root, and everything else at the top level is dropped.
        let pre_root = r"<svg><text>pre</text></svg><svg/>";
        let out = sanitized(pre_root);
        assert_eq!(out.matches("<svg").count(), 1, "{out}");

        let post_root = r#"<svg></svg><svg style="x"><text>post</text></svg>"#;
        let out = sanitized(post_root);
        assert_eq!(out.matches("<svg").count(), 1, "{out}");
    }

    #[test]
    fn sanitize_svg_fails_closed_when_the_root_is_not_svg() {
        // Hardening: the one root tag a real Graphviz render ever
        // writes is a bare `svg`, no namespace prefix. A crafted
        // top-level `<g>` must not be treated as a safe root to filter
        // like any other element, and a `<svg:svg>` (a prefixed root
        // no real render ever writes) must not be mistaken for the
        // genuine thing either, even though its *local* name is also
        // `svg` — the check is against the full, unprefixed name.
        for raw in [
            r"<g><title>t</title></g>",
            r#"<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><title>t</title></svg:svg>"#,
        ] {
            assert!(sanitize_svg(raw.as_bytes()).is_err(), "{raw}");
        }
    }

    #[test]
    fn sanitize_svg_keeps_whitespace_before_the_root_but_drops_other_content() {
        let raw = "  \n<svg><title>t</title></svg>";
        let out = sanitized(raw);
        assert!(out.contains("<title>t</title>"), "{out}");
        assert_eq!(out.matches("<svg").count(), 1, "{out}");

        let raw = "stray text<svg><title>t</title></svg>";
        let out = sanitized(raw);
        assert!(!out.contains("stray"), "{out}");
        assert!(out.contains("<title>t</title>"), "{out}");
        assert_eq!(out.matches("<svg").count(), 1, "{out}");
    }

    #[test]
    fn sanitize_svg_fails_closed_on_malformed_input() {
        // Round-1 risk finding: the sanitizer must never fall back to raw or
        // partially-filtered bytes on unparsable input. An attribute value
        // with an unrecognized XML entity cannot be unescaped and must
        // return `Err`, not a best-effort SVG.
        let raw = br#"<svg><g class="&notarealentity;"/></svg>"#;
        assert!(sanitize_svg(raw).is_err());
    }

    #[test]
    fn sanitize_svg_drops_an_attribute_whose_name_contains_a_slash() {
        // Security finding: an attribute name like `x/onclick` copied
        // verbatim survives into output an HTML tokenizer (which
        // `innerHTML` uses) can split into a second, unfiltered `onclick`
        // attribute. The name allowlist drops it instead.
        let raw = r#"<svg><g x/onclick="a"/></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("onclick"), "{out}");
        assert!(!out.contains("x/onclick"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_a_comment_an_html_parser_would_end_early() {
        // Security finding: quick-xml does not check comments by default,
        // so `<!-- --!><img src=x onerror=alert(1)> -->` parses as one
        // comment, but an HTML tokenizer ends a comment at `--!>` and
        // would run the rest as markup. Comments are dropped entirely,
        // never re-emitted.
        let raw = "<svg><!-- --!><img src=x onerror=alert(1)> --></svg>";
        let out = sanitized(raw);
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("onerror"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_cdata_inside_title() {
        // Security finding: SVG `<title>` is an HTML integration point,
        // where a CDATA section becomes a bogus comment ending at the
        // first `>`, so a literally re-emitted
        // `><img src=x onerror=1>` would run as markup. CDATA sections
        // are dropped entirely, never re-emitted.
        let raw = "<svg><title><![CDATA[><img src=x onerror=1>]]></title></svg>";
        let out = sanitized(raw);
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("CDATA"), "{out}");
        assert!(out.contains("<title></title>"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_the_xml_declaration_wherever_it_appears() {
        // CRITICAL: quick-xml parses *any* `<?xml ...?>` as `Decl`, not
        // only a document's genuine leading one — so a value like
        // `<?xml q="><img src=x onerror=1>"?>` smuggled into element
        // content (e.g. via a `fontname` attribute Graphviz writes
        // unescaped into `font-family="..."`) must not survive either.
        // An HTML tokenizer treats any `<?...?>` as a "bogus comment"
        // ending at the first `>`, so re-emitting this verbatim (the
        // previous `other =>` passthrough's bug) ran the rest as markup.
        let raw = r#"<svg><text font-family="F"><?xml q="><img src=x onerror=1>"?>x</text></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("onerror"), "{out}");
        assert!(!out.contains("<?"), "{out}");
    }

    #[test]
    fn sanitize_svg_drops_elements_outside_the_allowlist_and_their_children() {
        // Security MINOR: moving from a deny-list to an explicit element
        // allowlist means any element Graphviz never emits — `<p>`,
        // `<iframe>`, `<embed>`, ... — is refused by default, not only
        // the ones a deny-list happened to name. `<iframe srcdoc=...>`
        // and `<embed>` are both HTML-only script/plugin breakout
        // vectors with no role in Graphviz's own SVG output.
        let raw = r#"<svg><g><p>breakout</p><iframe srcdoc="<script>alert(1)</script>"></iframe><embed src="evil.swf"/><title>kept</title></g></svg>"#;
        let out = sanitized(raw);
        assert!(!out.contains("<p"), "{out}");
        assert!(!out.contains("<iframe"), "{out}");
        assert!(!out.contains("srcdoc"), "{out}");
        assert!(!out.contains("<embed"), "{out}");
        assert!(!out.contains("alert(1)"), "{out}");
        assert!(!out.contains("breakout"), "{out}");
        assert!(out.contains("<title>kept</title>"), "{out}");
    }

    #[test]
    fn sanitize_svg_keeps_every_element_a_real_graphviz_render_produces() {
        // Security MINOR: switching from a deny-list to an allowlist
        // must not regress a real Graphviz render — every element tag
        // it actually emits must be in `ALLOWED_ELEMENTS`, or sanitizing
        // a real workflow graph would silently drop structure (nodes,
        // edges, or their styling), not just the attacker-controlled
        // parts this sanitizer targets. Compares the raw render against
        // the sanitized output as an element-name multiset: they must be
        // equal apart from `a` (unwrapped, not refused — see
        // `UNWRAPPED_ELEMENTS`) disappearing; `style` must appear in
        // neither — it only ever reappears once `postprocess_svg` adds
        // Fabro's own dark-mode block, which happens after sanitizing in
        // the real `render-url` handler, not before.
        let dot = RenderableDot::from_fabro_source(
            r##"digraph X {
                start [shape=Mdiamond, label="Start"]
                exit  [shape=Msquare, label="Exit"]
                mid   [label="Mid", style=filled, fillcolor="#357f9e", URL="https://example.com/mid"]
                start -> mid -> exit
            }"##,
        );
        let raw = render_raw_svg(&dot).expect("a real Graphviz render should succeed");
        let raw_str = String::from_utf8(raw.clone()).expect("Graphviz output should be UTF-8");

        let sanitized_bytes =
            sanitize_svg(&raw).expect("sanitizing a real Graphviz render should not fail");
        let sanitized_str =
            String::from_utf8(sanitized_bytes.clone()).expect("sanitized output should be UTF-8");

        let mut raw_counts = element_name_counts(&raw_str);
        let a_count = raw_counts.remove("a").unwrap_or(0);
        assert!(
            a_count > 0,
            "fixture should exercise the unwrapped <a>: {raw_str}"
        );
        assert!(!raw_counts.contains_key("style"), "{raw_str}");

        let sanitized_counts = element_name_counts(&sanitized_str);
        assert_eq!(
            sanitized_counts, raw_counts,
            "sanitized element multiset should match the raw render's, apart from <a>\nraw: {raw_str}\nsanitized: {sanitized_str}"
        );

        assert!(out_contains_titles(&sanitized_str), "{sanitized_str}");
        assert!(sanitized_str.contains("Start"), "{sanitized_str}");
        assert!(sanitized_str.contains("Exit"), "{sanitized_str}");
        assert!(sanitized_str.contains("Mid"), "{sanitized_str}");
        // Known drops: Graphviz's own `<?xml-stylesheet?>` PI survives
        // being dropped without otherwise disturbing the output.
        assert!(
            !sanitized_str.contains("<?xml-stylesheet"),
            "{sanitized_str}"
        );

        // `style` only reappears once `postprocess_svg` runs, after
        // sanitizing — the real handler's order — and adds exactly
        // Fabro's own dark-mode block.
        let postprocessed = postprocess_svg(sanitized_bytes);
        let postprocessed_str =
            String::from_utf8(postprocessed).expect("postprocessed output should be UTF-8");
        assert_eq!(
            postprocessed_str.matches("<style").count(),
            1,
            "{postprocessed_str}"
        );
    }

    fn out_contains_titles(svg: &str) -> bool {
        svg.contains("<title>start</title>")
            && svg.contains("<title>exit</title>")
            && svg.contains("<title>mid</title>")
    }

    #[test]
    fn sanitize_svg_keeps_every_attribute_a_real_graphviz_render_produces() {
        // Security MINOR: the per-element attribute allowlist
        // (`ALLOWED_ATTRIBUTES`) must not regress a real render either —
        // every `(element, attribute)` pair it actually emits, on a
        // representative spread of Graphviz features (clusters, records,
        // an HTML label with fonts and a table, linear and radial
        // gradients, arrowheads, alpha-channel colors (a plain color
        // plus `fill-opacity`/`stroke-opacity`, never an alpha color
        // value itself) and a condensed `font-stretch`, non-ASCII node
        // ids, tooltips/ids/classes, and edge/edge-end labels), must
        // survive sanitizing with the same count, apart from `a`
        // (unwrapped, not refused) and its `href`/`xlink:href`/`target`.
        let fixtures = [
            r##"digraph X {
                bgcolor="white:lightblue"
                rankdir=LR
                subgraph cluster_0 {
                    label="Cluster"
                    style=filled
                    color=lightgrey
                    a [shape=record, label="{f0|f1|f2}"]
                    b [shape=Mdiamond]
                }
                c [shape=none margin=0 label=<
                    <table border="1" cellborder="0" cellspacing="0">
                      <tr><td bgcolor="yellow">html</td></tr>
                      <tr><td><font color="red"><b>bold</b> <i>italic</i></font></td></tr>
                    </table>
                >]
                d [style="radial" fillcolor="yellow:red" gradientangle=90]
                a -> b [arrowhead=diamond, label="edge", tooltip="tt", id="eid", class="ecls"]
                b -> c [style=dashed]
                c -> d [dir=both, arrowtail=inv, color="#0000ff80", penwidth=2]
            }"##,
            r#"digraph X {
                a [label="A"] b [label="B"]
                a -> b [headlabel="H", taillabel="T", labelfontname="Helvetica"]
            }"#,
            r##"digraph X {
                "nœud" [style="radial" fillcolor="yellow:red" gradientangle=90]
                a [label="A", fontcolor="#ff000080", fontname="Helvetica-Narrow"]
                "nœud" -> a
            }"##,
        ];

        for dot in fixtures {
            let rendered = RenderableDot::from_fabro_source(dot);
            let raw = render_raw_svg(&rendered).expect("a real Graphviz render should succeed");
            let raw_str = String::from_utf8(raw.clone()).expect("Graphviz output should be UTF-8");

            let sanitized_bytes =
                sanitize_svg(&raw).expect("sanitizing a real Graphviz render should not fail");
            let sanitized_str =
                String::from_utf8(sanitized_bytes).expect("sanitized output should be UTF-8");

            let raw_pairs = element_attribute_pair_counts(&raw_str);
            let sanitized_pairs = element_attribute_pair_counts(&sanitized_str);
            assert_eq!(
                sanitized_pairs, raw_pairs,
                "sanitized (element, attribute) pairs should match the raw render's, apart from <a>'s href/xlink:href/target\nraw: {raw_str}\nsanitized: {sanitized_str}"
            );
        }
    }

    #[test]
    fn sanitize_svg_keeps_a_real_graph_render_readable() {
        // Companion to the multiset comparison above: a real sanitized
        // render must still contain the structural/shape elements a
        // workflow page draws with.
        let svg = render_dot(
            r##"digraph X {
                start [shape=Mdiamond, label="Start"]
                exit  [shape=Msquare, label="Exit"]
                mid   [label="Mid", style=filled, fillcolor="#357f9e"]
                start -> mid -> exit
            }"##,
        )
        .expect("a real Graphviz render should succeed");
        let svg = String::from_utf8(svg).expect("Graphviz output should be UTF-8");

        let out = sanitized(&svg);

        for tag in ["<svg", "<g ", "<polygon", "<text", "<path", "<ellipse"] {
            assert!(out.contains(tag), "missing {tag} in {out}");
        }
    }
}
