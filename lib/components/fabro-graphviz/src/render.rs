use std::borrow::Cow;
use std::sync::LazyLock;

use anyhow::Context as _;
use fabro_dot::{last_root_rankdir, normalize_for_graphviz, render_url_source, with_root_rankdir};

/// Dark mode CSS injected into SVG output (leading newline included for
/// insertion).
const DARK_MODE_STYLE: &str = r##"
<style>
  @media (prefers-color-scheme: dark) {
    text { fill: #e0e0e0 !important; }
    [stroke="#357f9e"] { stroke: #5bb8d8; }
    [stroke="#666666"] { stroke: #999999; }
    polygon[fill="#357f9e"] { fill: #5bb8d8; }
    polygon[fill="#666666"] { fill: #999999; }
  }
</style>"##;

/// DOT graph-level defaults injected after the graph opening `{`.
const DOT_STYLE_DEFAULTS: &str = r##"
    bgcolor="transparent"
    node [color="#357f9e", fontname="Helvetica", fontsize=12, fontcolor="#1a1a1a"]
    edge [color="#666666", fontname="Helvetica", fontsize=10, fontcolor="#666666"]
"##;

static WHITE_BG_POLYGON_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"<polygon\b[^>]*fill="white"[^>]*stroke="none"[^>]*/>|<polygon\b[^>]*stroke="none"[^>]*fill="white"[^>]*/>"#,
    )
    .expect("hardcoded regex should compile")
});

/// Override `source`'s effective layout direction to `direction`: appends
/// a new root-scope `rankdir=<direction>` statement, via
/// `fabro_dot::with_root_rankdir`, guaranteed by DOT's own "last
/// assignment wins" rule to be what Graphviz actually draws with,
/// regardless of any earlier root-scope `rankdir` (quoted or not,
/// anywhere in the root graph) the source already carried. MAJOR
/// correctness fix: this previously rewrote the first `rankdir=...` a
/// raw-text regex happened to match, so a later root-scope assignment
/// (DOT's own tiebreak) still won at render time, and a `rankdir=...`
/// substring inside a string value (a prompt, a label, a comment) could
/// be rewritten even though it was never an attribute assignment at
/// all — in both cases the requested direction silently did not match
/// what Graphviz drew. Shared with the run-page graph handler (`GET
/// /runs/{id}/graph`); the fix applies there too.
#[must_use]
pub fn apply_direction<'a>(source: &'a str, direction: &str) -> Cow<'a, str> {
    with_root_rankdir(source, direction)
}

/// Prepare untrusted, URL-fetched DOT source for the render-url path:
/// in one parse (via `fabro_dot::render_url_source`), neutralize
/// Graphviz's raw-text attributes (`fontname`, `labelfontname`,
/// `stylesheet` — see `fabro_dot`'s own doc comment for which
/// characters break them out) wherever their value could break out of
/// the SVG attribute (or processing instruction) Graphviz writes them
/// into, and, when `direction` is given, override the effective
/// layout direction exactly as [`apply_direction`] does.
///
/// Security fix, source side: `fabro_graphviz::sanitize::sanitize_svg`
/// is the defense-in-depth backstop over the *rendered* SVG; this is
/// the matching fix over the *source* text, before Graphviz ever sees
/// it, for the one untrusted-DOT render path (`POST
/// /api/v1/graph/render-url`) that needs it — a manifest's own stored
/// workflow source, and a run's own graph, are already trusted.
#[must_use]
pub fn prepare_untrusted_source_for_render<'a>(
    source: &'a str,
    direction: Option<&str>,
) -> Cow<'a, str> {
    render_url_source(source, direction)
}

/// The DOT source's effective root-scope `rankdir` value: the *last*
/// one assigned at the root graph scope (quoted or not; a subgraph's
/// own `rankdir` is ignored — see `fabro_dot::last_root_rankdir`), only
/// when it exactly, case-sensitively matches one of the four values
/// Graphviz itself recognizes (`LR`/`TB`/`BT`/`RL`). Anything else —
/// wrong case (e.g. `lr`), an unrecognized word, or no `rankdir` at all
/// — is what Graphviz itself draws as `TB`, so it is reported as absent
/// here too, matching the drawing rather than the literal source text.
/// `render-url`'s handler uses this to compute its response's
/// `direction` field when the request did not ask for one explicitly.
#[must_use]
pub fn detect_rankdir(source: &str) -> Option<&'static str> {
    const RECOGNIZED: [&str; 4] = ["LR", "TB", "BT", "RL"];
    let value = last_root_rankdir(source)?;
    RECOGNIZED.into_iter().find(|candidate| *candidate == value)
}

/// Inject DOT graph-level style defaults, after normalizing Fabro DOT into
/// DOT Graphviz accepts.
#[must_use]
pub fn inject_dot_style_defaults(source: &str) -> String {
    let source = normalize_for_graphviz(source);
    inject_dot_style_defaults_raw(&source)
}

fn inject_dot_style_defaults_raw(source: &str) -> String {
    let Some(pos) = source.find('{') else {
        return source.to_string();
    };
    let (before, after) = source.split_at(pos + 1);
    format!("{before}{DOT_STYLE_DEFAULTS}{after}")
}

/// Post-process raw SVG output from Graphviz.
#[must_use]
pub fn postprocess_svg(raw: Vec<u8>) -> Vec<u8> {
    let mut svg = String::from_utf8(raw)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

    svg = WHITE_BG_POLYGON_RE.replace_all(&svg, "").into_owned();

    if let Some(svg_close) = svg
        .find("<svg")
        .and_then(|start| svg[start..].find('>').map(|end| start + end))
    {
        svg.insert_str(svg_close + 1, DARK_MODE_STYLE);
    }

    svg.into_bytes()
}

/// DOT source prepared for Graphviz rendering.
pub struct RenderableDot<'a> {
    source: Cow<'a, str>,
}

impl<'a> RenderableDot<'a> {
    /// Prepare Fabro DOT for Graphviz by applying render styling and
    /// normalizing Fabro-specific syntax such as dotted attribute keys.
    #[must_use]
    pub fn from_fabro_source(source: &'a str) -> Self {
        Self {
            source: Cow::Owned(inject_dot_style_defaults(source)),
        }
    }

    /// Return the DOT source that can be handed to Graphviz.
    #[must_use]
    pub fn as_graphviz_source(&self) -> &str {
        &self.source
    }
}

/// Render prepared DOT source into raw SVG via the vendored Graphviz library.
///
/// This is the only `graphviz_sys` boundary in the workspace.
pub fn render_raw_svg(dot: &RenderableDot<'_>) -> anyhow::Result<Vec<u8>> {
    graphviz_sys::render_dot_to_svg(dot.as_graphviz_source())
        .map_err(anyhow::Error::msg)
        .context("Graphviz rendering failed")
}

/// Render prepared DOT source into post-processed SVG.
pub fn render_svg(dot: &RenderableDot<'_>) -> anyhow::Result<Vec<u8>> {
    let raw = render_raw_svg(dot)?;
    Ok(postprocess_svg(raw))
}

/// Render Fabro DOT source into post-processed SVG.
pub fn render_dot(source: &str) -> anyhow::Result<Vec<u8>> {
    let dot = RenderableDot::from_fabro_source(source);
    render_svg(&dot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_direction_rewrites_rankdir() {
        let source = "digraph { rankdir=LR a -> b }";
        let rewritten = apply_direction(source, "TB");
        assert!(rewritten.contains("rankdir=TB"));
    }

    #[test]
    fn detect_rankdir_finds_the_existing_value() {
        assert_eq!(detect_rankdir("digraph { rankdir=LR a -> b }"), Some("LR"));
        assert_eq!(
            detect_rankdir("digraph { rankdir = BT a -> b }"),
            Some("BT")
        );
    }

    #[test]
    fn detect_rankdir_is_none_without_one() {
        assert_eq!(detect_rankdir("digraph { a -> b }"), None);
    }
    #[test]
    fn apply_direction_inserts_rankdir_when_absent() {
        let out = apply_direction("digraph { a -> b }", "LR");
        assert_eq!(detect_rankdir(&out), Some("LR"));
    }

    #[test]
    fn apply_direction_overrides_a_quoted_rankdir() {
        let source = r#"digraph { rankdir="LR" a -> b }"#;
        let out = apply_direction(source, "TB");
        assert_eq!(detect_rankdir(&out), Some("TB"));
    }

    #[test]
    fn detect_rankdir_reports_the_wrong_case_as_absent() {
        // Graphviz recognizes `rankdir` case-sensitively; a value like
        // `lr` draws the same `TB` layout as no `rankdir` at all, so it
        // must not be reported as the detected `LR`.
        assert_eq!(detect_rankdir("digraph { rankdir=lr a -> b }"), None);
    }

    #[test]
    fn rankdir_is_not_fooled_by_a_prompt_mentioning_rankdir() {
        // MAJOR correctness fix: a raw-text regex matched `rankdir=LR`
        // wherever it appeared in the source, including inside a quoted
        // string value (a prompt, a label, a comment) that was never an
        // attribute assignment at all.
        let source = r#"digraph { prompt="rankdir=LR" a -> b }"#;
        assert_eq!(detect_rankdir(source), None);

        let out = apply_direction(source, "TB");
        assert_eq!(detect_rankdir(&out), Some("TB"));
        assert!(out.contains(r#""rankdir=LR""#), "{out}");
    }

    #[test]
    fn inject_style_defaults_adds_graph_defaults() {
        let source = "digraph X { a -> b }";
        let styled = inject_dot_style_defaults(source);
        assert!(styled.contains("bgcolor=\"transparent\""));
        assert!(styled.contains("node [color=\"#357f9e\""));
    }

    #[test]
    fn postprocess_svg_removes_white_background() {
        let raw = br#"<svg><polygon fill="white" stroke="none" points="0,0"/><text>x</text></svg>"#
            .to_vec();
        let svg = String::from_utf8(postprocess_svg(raw)).unwrap();
        assert!(!svg.contains("fill=\"white\""));
        assert!(svg.contains("@media (prefers-color-scheme: dark)"));
    }

    #[test]
    fn render_dot_produces_svg() {
        let svg = render_dot("digraph { a -> b }").unwrap();
        assert!(String::from_utf8(svg).unwrap().contains("<svg"));
    }

    #[test]
    fn render_dot_accepts_leading_comment_with_template_braces() {
        let svg = render_dot(
            r#"// The goal is rendered into prompts as {{ goal }}.
digraph G {
    start [shape=Mdiamond]
    exit [shape=Msquare]
    a [label="A"]
    start -> a -> exit
}"#,
        )
        .unwrap();

        assert!(String::from_utf8(svg).unwrap().contains("<svg"));
    }

    #[test]
    fn render_dot_complex_graph() {
        let source = r#"digraph {
            subgraph cluster_0 {
                label = "process #1";
                a0 -> a1 -> a2 -> a3;
            }
            subgraph cluster_1 {
                label = "process #2";
                b0 -> b1 -> b2 -> b3;
            }
            start -> a0;
            start -> b0;
            a1 -> b3;
            b2 -> a3;
            a3 -> end;
            b3 -> end;
        }"#;
        let svg = render_dot(source).unwrap();
        let svg_str = String::from_utf8(svg).unwrap();
        assert!(svg_str.contains("<svg"));
        assert!(svg_str.contains("process #1"));
        assert!(svg_str.contains("process #2"));
    }

    #[test]
    fn render_dot_invalid_source_returns_error() {
        let result = render_dot("not valid dot {{{");
        assert!(result.is_err());
    }

    #[test]
    fn render_dot_accepts_fabro_dotted_attribute_keys() {
        let svg = render_dot(
            r#"digraph X {
                start [shape=Mdiamond]
                exit [shape=Msquare]
                a [label="A", acp.command="codex"]
                start -> a -> exit
            }"#,
        )
        .unwrap();

        assert!(String::from_utf8(svg).unwrap().contains("<svg"));
    }

    #[test]
    fn renderable_dot_normalizes_fabro_source_for_graphviz() {
        let dot = RenderableDot::from_fabro_source(
            r#"digraph X {
                a [label="A", acp.command="codex"]
            }"#,
        );

        assert!(
            dot.as_graphviz_source()
                .contains(r#""acp.command"="codex""#)
        );
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "unit test reads checked-in DOT compatibility fixtures synchronously"
    )]
    #[test]
    fn render_dot_compatibility_corpus_produces_svg() {
        let fixtures = dot_compatibility_fixtures();

        assert_eq!(
            fixtures.len(),
            3,
            "dot compatibility corpus should stay intentionally small"
        );

        for fixture in fixtures {
            let source = std::fs::read_to_string(&fixture)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture.display()));
            let dot = RenderableDot::from_fabro_source(&source);
            let svg = render_svg(&dot)
                .unwrap_or_else(|err| panic!("failed to render {}: {err:#}", fixture.display()));
            let svg = String::from_utf8(svg)
                .unwrap_or_else(|err| panic!("SVG was not UTF-8 for {}: {err}", fixture.display()));

            assert!(
                svg.contains("<svg"),
                "expected SVG output for {}, got: {}",
                fixture.display(),
                &svg[..svg.len().min(200)]
            );
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "unit test helper enumerates checked-in DOT compatibility fixtures synchronously"
    )]
    fn dot_compatibility_fixtures() -> Vec<std::path::PathBuf> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test/dot-compatibility");
        let mut fixtures = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
            .map(|entry| {
                entry
                    .unwrap_or_else(|err| {
                        panic!("failed to read entry in {}: {err}", dir.display())
                    })
                    .path()
            })
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("fabro"))
            .collect::<Vec<_>>();
        fixtures.sort();
        fixtures
    }

    #[test]
    fn prepare_untrusted_source_for_render_neutralizes_a_fontname_breakout() {
        let source = r#"digraph X { a [fontname="F\"bad", label="A"] }"#;
        let out = prepare_untrusted_source_for_render(source, None);
        assert!(!out.contains("bad"), "{out}");
    }

    #[test]
    fn prepare_untrusted_source_for_render_applies_direction() {
        let out = prepare_untrusted_source_for_render("digraph { a -> b }", Some("LR"));
        assert_eq!(detect_rankdir(&out), Some("LR"));
    }
}
