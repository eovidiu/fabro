//! Fabro DOT re-emitted as DOT Graphviz accepts.
//!
//! Graphviz rejects unquoted dotted attribute keys such as `acp.command`,
//! which Fabro's language allows. The render paths parse the source with
//! Petri's parser and print it back with every id quoted that needs quoting.

use std::borrow::Cow;

use petri_frontend_attractor::dot::{
    self, AstValue, Attr, AttrBlock, DotGraph, EdgeStmt, NodeStmt, Statement, SubgraphStmt,
};

use crate::limits::root_graph_closing_brace;

/// Convert Fabro DOT into DOT Graphviz accepts.
///
/// If the source is outside the subset Petri parses, it is returned unchanged
/// so Graphviz can judge it itself: it may be valid Graphviz that is not a
/// workflow.
#[must_use]
pub fn normalize_for_graphviz(source: &str) -> Cow<'_, str> {
    match dot::parse("workflow.fabro", source) {
        Ok(graph) => Cow::Owned(emit_graph(&graph)),
        Err(_) => Cow::Borrowed(source),
    }
}

/// The DOT source's root-scope `rankdir` value exactly as written
/// (quoted or not), the *last* one assigned at the root graph scope —
/// a bare `rankdir = ...;` statement or inside a `graph [...]`
/// attribute block — ignoring any set inside a subgraph (Graphviz
/// draws the whole graph by its root scope's own `rankdir` alone). The
/// attribute *key* is matched case-sensitively: Graphviz attribute
/// names are case-sensitive (`RANKDIR=LR` draws `TB`, matching none of
/// Graphviz's own recognized names), so a differently-cased key is
/// never mistaken for `rankdir` here either — matching what Graphviz
/// itself looks for, not just what the value it finds then has to
/// match. Working from the parsed graph rather than a raw-text regex
/// means a `rankdir=...` substring inside a string value (a prompt, a
/// label, a comment) is never mistaken for an assignment: it is never
/// a `Statement` at all. `None` when the source has no root-scope
/// `rankdir`, or is outside the subset this crate's parser accepts
/// (Graphviz can still judge it itself).
#[must_use]
pub fn last_root_rankdir(source: &str) -> Option<String> {
    let graph = dot::parse("workflow.fabro", source).ok()?;
    last_rankdir_in(&graph.statements)
}

fn last_rankdir_in(statements: &[Statement]) -> Option<String> {
    let mut found = None;
    for statement in statements {
        match statement {
            Statement::GraphAttrs(attrs) => {
                for attr in attrs {
                    // Correctness fix: Graphviz attribute names are
                    // case-sensitive, so the key must match exactly,
                    // not case-insensitively — see this function's
                    // caller's doc comment.
                    if attr.key == "rankdir" {
                        found = Some(attr.value.as_text());
                    }
                }
            }
            Statement::GraphAttr(attr) if attr.key == "rankdir" => {
                found = Some(attr.value.as_text());
            }
            // A subgraph's own `rankdir`, and every other statement kind,
            // never changes the root graph's effective layout direction.
            Statement::GraphAttr(_)
            | Statement::NodeDefaults(_)
            | Statement::EdgeDefaults(_)
            | Statement::Subgraph(_)
            | Statement::Node(_)
            | Statement::Edge(_) => {}
        }
    }
    found
}

/// `source` re-emitted (via this crate's own DOT parser, the same one
/// [`normalize_for_graphviz`] uses) with a `rankdir=<direction>`
/// statement appended as the graph's *last* root-scope statement —
/// guaranteed, by DOT's own "last assignment wins" rule, to be the
/// graph's effective `rankdir` regardless of any earlier root-scope
/// `rankdir` (quoted or not, anywhere in the root graph) the source
/// already carried, and unfooled by a `rankdir=...` substring inside a
/// string value (a prompt, a label, a comment): those are never
/// `Statement`s, so this never touches them.
///
/// When `source` is outside the subset this crate's parser accepts —
/// Graphviz-valid DOT this crate cannot re-emit, e.g. an HTML label or
/// a `strict` graph — correctness fix: falls back to inserting
/// `rankdir=<direction>;` as plain text immediately before the root
/// graph's own closing `}` — found by
/// [`crate::limits::root_graph_closing_brace`]'s comment/string-aware scan, not
/// merely `source`'s textual last `}`, so a trailing `// }`-style comment or a
/// `}` inside a quoted label after the real close is never mistaken for it —
/// (DOT's "last assignment wins" rule still applies, so this is still the
/// effective direction), rather than leaving `direction` silently unapplied as
/// before. `source` unchanged only when it carries no matched
/// root-scope `{`/`}` pair at all, so there is nowhere to insert
/// before.
#[must_use]
pub fn with_root_rankdir<'a>(source: &'a str, direction: &str) -> Cow<'a, str> {
    match dot::parse("workflow.fabro", source) {
        Ok(graph) => {
            let mut emitted = emit_graph(&graph);
            append_rankdir(&mut emitted, direction);
            Cow::Owned(emitted)
        }
        Err(_) => match root_graph_closing_brace(source) {
            Some(pos) => Cow::Owned(insert_rankdir_before_brace(source, pos, direction)),
            None => Cow::Borrowed(source),
        },
    }
}

/// Truncate `emitted`'s trailing root-graph `"}\n"` (always present and
/// never nested — see [`emit_graph`]) and append a `rankdir=<direction>`
/// statement as the new last root-scope statement before closing again.
fn append_rankdir(emitted: &mut String, direction: &str) {
    debug_assert!(emitted.ends_with("}\n"));
    emitted.truncate(emitted.len() - "}\n".len());
    emitted.push_str("    rankdir=");
    emitted.push_str(&dot_id(direction));
    emitted.push_str(";\n}\n");
}

/// Text-level fallback for [`with_root_rankdir`] when `source` cannot be
/// parsed: insert a `rankdir=<direction>;` statement as plain text
/// right before `source[pos..]` (`pos` is the byte offset of the root
/// graph's own closing `}`, from [`crate::limits::root_graph_closing_brace`]).
fn insert_rankdir_before_brace(source: &str, pos: usize, direction: &str) -> String {
    let mut out = String::with_capacity(source.len() + direction.len() + 16);
    out.push_str(&source[..pos]);
    out.push_str("rankdir=");
    out.push_str(&dot_id(direction));
    out.push_str(";\n");
    out.push_str(&source[pos..]);
    out
}

/// Raw-text attribute names Graphviz writes unescaped straight into its
/// SVG output: `fontname`/`labelfontname` into a `font-family="..."`
/// attribute, and the graph-level `stylesheet` into an
/// `<?xml-stylesheet href="..."?>` processing instruction before the
/// SVG root. Confirmed against `dot -Tsvg`: every other attribute this
/// crate has probed (`id`, `class`, `URL`/`href`, `tooltip`, labels
/// themselves, ...) is properly XML-escaped. A value containing `"`,
/// `<`, `>` or `&` can break out of the attribute (or, for
/// `stylesheet`, the processing instruction itself) it is written
/// into — see `fabro_graphviz::sanitize` for the matching
/// defense-in-depth fix over the *rendered* SVG.
const RAW_TEXT_ATTRS: [&str; 3] = ["fontname", "labelfontname", "stylesheet"];

/// Drop every [`RAW_TEXT_ATTRS`] attribute, at every scope that accepts
/// one — the root graph, a node, an edge, a `node`/`edge`/`graph`
/// default block, and a subgraph (recursively, both its own defaults
/// and its nested statements) — whenever its value contains `"`, `<`,
/// `>` or `&`.
fn neutralize_unsafe_text_attributes(statements: &mut Vec<Statement>) {
    statements.retain_mut(|statement| match statement {
        Statement::GraphAttrs(attrs)
        | Statement::NodeDefaults(attrs)
        | Statement::EdgeDefaults(attrs) => {
            attrs.retain(|attr| !is_unsafe_text_attr(attr));
            true
        }
        Statement::Node(node) => {
            if let Some(attrs) = &mut node.attrs {
                attrs.retain(|attr| !is_unsafe_text_attr(attr));
            }
            true
        }
        Statement::Edge(edge) => {
            if let Some(attrs) = &mut edge.attrs {
                attrs.retain(|attr| !is_unsafe_text_attr(attr));
            }
            true
        }
        Statement::Subgraph(subgraph) => {
            neutralize_unsafe_text_attributes(&mut subgraph.statements);
            true
        }
        Statement::GraphAttr(attr) => !is_unsafe_text_attr(attr),
    });
}

fn is_unsafe_text_attr(attr: &Attr) -> bool {
    RAW_TEXT_ATTRS.contains(&attr.key.as_str())
        && attr.value.as_text().contains(['"', '<', '>', '&'])
}

/// `source` re-emitted (one parse, via this crate's own DOT parser)
/// with every [`RAW_TEXT_ATTRS`] attribute neutralized everywhere (see
/// [`neutralize_unsafe_text_attributes`]) and, when `direction` is
/// given, a root-scope `rankdir=<direction>` statement appended in the
/// same parse (see [`with_root_rankdir`]/[`append_rankdir`]).
///
/// Source-side security fix for the one untrusted-DOT render path
/// (`POST /api/v1/graph/render-url`): falls back to `source` unchanged
/// — neither neutralized nor direction-applied — when outside the
/// subset this crate's parser accepts; the caller's own SVG-output
/// sanitizer (`fabro_graphviz::sanitize::sanitize_svg`) is the
/// defense-in-depth backstop for that case, as it is for every other
/// render path.
#[must_use]
pub fn render_url_source<'a>(source: &'a str, direction: Option<&str>) -> Cow<'a, str> {
    let Ok(mut graph) = dot::parse("workflow.fabro", source) else {
        return Cow::Borrowed(source);
    };
    neutralize_unsafe_text_attributes(&mut graph.statements);
    let mut emitted = emit_graph(&graph);
    if let Some(direction) = direction {
        append_rankdir(&mut emitted, direction);
    }
    Cow::Owned(emitted)
}

fn emit_graph(graph: &DotGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph");
    if !graph.name.name.is_empty() {
        out.push(' ');
        out.push_str(&dot_id(&graph.name.name));
    }
    out.push_str(" {\n");
    emit_statements(&mut out, &graph.statements, 1);
    out.push_str("}\n");
    out
}

fn emit_statements(out: &mut String, statements: &[Statement], indent: usize) {
    for statement in statements {
        emit_statement(out, statement, indent);
    }
}

fn emit_statement(out: &mut String, statement: &Statement, indent: usize) {
    match statement {
        Statement::GraphAttrs(attrs) => emit_defaults(out, "graph", attrs, indent),
        Statement::NodeDefaults(attrs) => emit_defaults(out, "node", attrs, indent),
        Statement::EdgeDefaults(attrs) => emit_defaults(out, "edge", attrs, indent),
        Statement::Subgraph(subgraph) => emit_subgraph(out, subgraph, indent),
        Statement::Node(node) => emit_node(out, node, indent),
        Statement::Edge(edge) => emit_edge(out, edge, indent),
        Statement::GraphAttr(attr) => {
            push_indent(out, indent);
            emit_attr(out, attr);
            out.push_str(";\n");
        }
    }
}

fn emit_defaults(out: &mut String, keyword: &str, attrs: &AttrBlock, indent: usize) {
    push_indent(out, indent);
    out.push_str(keyword);
    out.push(' ');
    emit_attr_block(out, attrs);
    out.push_str(";\n");
}

fn emit_subgraph(out: &mut String, subgraph: &SubgraphStmt, indent: usize) {
    push_indent(out, indent);
    out.push_str("subgraph");
    if let Some(name) = &subgraph.name {
        out.push(' ');
        out.push_str(&dot_id(&name.name));
    }
    out.push_str(" {\n");
    emit_statements(out, &subgraph.statements, indent + 1);
    push_indent(out, indent);
    out.push_str("}\n");
}

fn emit_node(out: &mut String, node: &NodeStmt, indent: usize) {
    push_indent(out, indent);
    out.push_str(&dot_id(&node.id.name));
    if let Some(attrs) = &node.attrs {
        out.push(' ');
        emit_attr_block(out, attrs);
    }
    out.push_str(";\n");
}

fn emit_edge(out: &mut String, edge: &EdgeStmt, indent: usize) {
    push_indent(out, indent);
    let mut nodes = edge.nodes.iter();
    if let Some(first) = nodes.next() {
        out.push_str(&dot_id(&first.name));
        for node in nodes {
            out.push_str(" -> ");
            out.push_str(&dot_id(&node.name));
        }
    }
    if let Some(attrs) = &edge.attrs {
        out.push(' ');
        emit_attr_block(out, attrs);
    }
    out.push_str(";\n");
}

fn emit_attr_block(out: &mut String, attrs: &AttrBlock) {
    out.push('[');
    for (index, attr) in attrs.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        emit_attr(out, attr);
    }
    out.push(']');
}

fn emit_attr(out: &mut String, attr: &Attr) {
    out.push_str(&dot_id(&attr.key));
    out.push('=');
    out.push_str(&dot_value(&attr.value));
}

fn dot_value(value: &AstValue) -> String {
    match value {
        AstValue::Str(value) => quoted_dot_string(value),
        AstValue::Int(value) => value.to_string(),
        AstValue::Float(value) => value.to_string(),
        AstValue::Bool(value) => value.to_string(),
        AstValue::Ident(value) => dot_id(value),
    }
}

fn dot_id(value: &str) -> String {
    if is_plain_dot_id(value) && !is_dot_keyword(value) {
        value.to_string()
    } else {
        quoted_dot_string(value)
    }
}

fn quoted_dot_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            // Correctness fix: a CR falls through to here (pushed
            // raw, unescaped) rather than its own `"\\r"`-pushing arm
            // as every other control character above gets: Petri's
            // lexer does not recognize `\r` as an escape at all
            // (unlike `\n`/`\t`), so escaping a raw CR as the
            // two-character text `\r` was not a fixed point under
            // repeated parse+emit — re-parsing it kept the backslash
            // and the `r` as two literal characters (Petri's "unknown
            // escape, keep verbatim" rule) rather than reconstructing
            // a CR, so a second emit (e.g. `with_root_rankdir`
            // re-emitting what `normalize_for_graphviz` already
            // emitted) escaped the backslash again — turning one `\r`
            // into `\\r`, which Graphviz draws as the literal text
            // `\r`, not the original line break. Emitting the raw CR
            // byte unescaped instead *is* a fixed point: it is not a
            // recognized escape's trigger character, so the lexer's
            // default "push the byte as-is" rule (this same `_` arm,
            // on the second parse) reproduces it exactly, on any
            // number of round trips.
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn is_plain_dot_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_dot_keyword(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "digraph" | "edge" | "graph" | "node" | "strict" | "subgraph"
    )
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("    ");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        dot, last_root_rankdir, normalize_for_graphviz, render_url_source, with_root_rankdir,
    };

    #[test]
    fn quotes_dotted_attribute_keys() {
        let source = r#"digraph X {
            a [label="A", acp.command="codex"]
        }"#;

        let normalized = normalize_for_graphviz(source);

        assert!(normalized.contains(r#""acp.command"="codex""#));
    }

    #[test]
    fn quotes_known_fabro_dotted_attribute_keys() {
        let source = r#"digraph X {
            approve [human.default_choice="deploy"]
            child [stack.child_workflow="child.fabro", manager.max_cycles=50]
            approve -> child
        }"#;

        let normalized = normalize_for_graphviz(source);

        assert!(normalized.contains(r#""human.default_choice"="deploy""#));
        assert!(normalized.contains(r#""stack.child_workflow"="child.fabro""#));
        assert!(normalized.contains(r#""manager.max_cycles"=50"#));
    }

    #[test]
    fn preserves_subgraphs_defaults_and_bare_graph_attributes() {
        let source = r##"digraph X {
            rankdir=LR
            node [color="#357f9e"]
            subgraph cluster_loop {
                label="Loop"
                a [acp.command="codex"]
            }
        }"##;

        let normalized = normalize_for_graphviz(source);

        assert!(normalized.contains("rankdir=LR;"));
        assert!(normalized.contains("node ["));
        assert!(normalized.contains("subgraph cluster_loop"));
        assert!(normalized.contains(r#""acp.command"="codex""#));
    }

    #[test]
    fn quotes_ids_that_collide_with_keywords_or_need_escaping() {
        let source = r#"digraph X {
            "my node" [label="say \"hi\""]
            "my node" -> Node
        }"#;

        let normalized = normalize_for_graphviz(source);

        assert!(normalized.contains(r#""my node" [label="say \"hi\""]"#));
        assert!(normalized.contains(r#""my node" -> "Node""#));
    }

    #[test]
    fn source_outside_the_subset_passes_through_unchanged() {
        let source = "graph G { a -- b }";
        assert_eq!(normalize_for_graphviz(source), source);
    }

    #[test]
    fn last_root_rankdir_finds_the_last_root_scope_assignment() {
        assert_eq!(
            last_root_rankdir("digraph { rankdir=LR a -> b }").as_deref(),
            Some("LR")
        );
        assert_eq!(
            last_root_rankdir(r#"digraph { rankdir="BT" a -> b }"#).as_deref(),
            Some("BT")
        );
        assert_eq!(last_root_rankdir("digraph { a -> b }"), None);
        // Last root-scope assignment wins, whichever form it was written in.
        assert_eq!(
            last_root_rankdir("digraph { rankdir=LR graph [rankdir=TB] a -> b }").as_deref(),
            Some("TB")
        );
    }

    #[test]
    fn last_root_rankdir_ignores_a_subgraph_and_a_string_value() {
        let source = r#"digraph {
            prompt = "rankdir=LR"
            subgraph cluster_0 { rankdir = RL a }
            a -> b
        }"#;
        assert_eq!(last_root_rankdir(source), None);
    }

    #[test]
    fn with_root_rankdir_overrides_an_existing_assignment() {
        let out = with_root_rankdir("digraph { rankdir=LR a -> b }", "TB");
        assert_eq!(last_root_rankdir(&out).as_deref(), Some("TB"));
    }

    #[test]
    fn with_root_rankdir_inserts_one_when_absent() {
        let out = with_root_rankdir("digraph { a -> b }", "LR");
        assert_eq!(last_root_rankdir(&out).as_deref(), Some("LR"));
    }

    #[test]
    fn with_root_rankdir_is_not_fooled_by_a_prompt_mentioning_rankdir() {
        let source = r#"digraph { prompt = "rankdir=LR" a -> b }"#;
        let out = with_root_rankdir(source, "LR");
        assert_eq!(last_root_rankdir(&out).as_deref(), Some("LR"));
        assert!(out.contains(r#""rankdir=LR""#), "{out}");
    }

    #[test]
    fn last_root_rankdir_requires_an_exact_case_key() {
        // Correctness finding: Graphviz attribute names are
        // case-sensitive (`RANKDIR=LR` draws `TB`, matching none of
        // its recognized `rankdir` names), so a differently-cased key
        // must be reported as absent here too, matching what Graphviz
        // itself draws.
        assert_eq!(last_root_rankdir("digraph { RANKDIR=LR a -> b }"), None);
    }

    #[test]
    fn last_root_rankdir_ignores_an_uppercase_graph_attrs_block() {
        // Correctness finding: same case-sensitivity rule as the bare
        // `RANKDIR=LR` form above, but through a `graph [...]`
        // attribute block instead of a bare assignment.
        assert_eq!(
            last_root_rankdir("digraph { graph [RANKDIR=LR] a -> b }"),
            None
        );
    }

    #[test]
    fn with_root_rankdir_round_trips_a_label_containing_cr() {
        // Correctness finding: applying a direction re-parses and
        // re-emits the DOT (once here, once more inside the render
        // subprocess's own `normalize_for_graphviz` pass); a CR inside
        // a quoted label must survive both passes identically to the
        // single pass the no-direction path takes, or requesting a
        // direction silently redraws label text that has nothing to do
        // with layout.
        let source = "digraph { a [label=\"x\ry\"] }";

        let mut expected = normalize_for_graphviz(source).into_owned();
        assert!(expected.ends_with("}\n"), "{expected:?}");
        expected.truncate(expected.len() - "}\n".len());
        expected.push_str("    rankdir=LR;\n}\n");

        let with_direction = with_root_rankdir(source, "LR");
        let actual = normalize_for_graphviz(&with_direction);
        assert_eq!(actual, expected);
        assert!(actual.contains('\r'), "{actual:?}");
    }

    #[test]
    fn with_root_rankdir_falls_back_to_text_insertion_when_unparsable() {
        // Correctness finding: `fabro graph --allow-invalid` can reach
        // Graphviz-valid DOT this crate's own parser rejects (an HTML
        // label, here). Before this fix, `--direction` was silently
        // ignored for such a source; now the direction is still
        // inserted as plain text, right before the source's own last
        // `}`.
        let source = "digraph { a [label=<<b>bold</b>>] a -> b }";
        assert!(
            dot::parse("workflow.fabro", source).is_err(),
            "fixture should be outside this crate's parsed subset"
        );

        let out = with_root_rankdir(source, "LR");

        assert!(out.contains("rankdir=LR;"), "{out}");
        assert!(out.trim_end().ends_with('}'), "{out}");
        assert!(out.contains("label=<<b>bold</b>>"), "{out}");
    }

    #[test]
    fn with_root_rankdir_falls_back_past_a_trailing_line_comment() {
        // Hardening: the text-level fallback's insertion point is the
        // root graph's own closing `}`, found by a comment-aware scan —
        // not merely the source's textual *last* `}`, which a trailing
        // `// }`-style comment after the real close would otherwise be
        // mistaken for, inserting the statement after the comment
        // (outside the graph's own braces) instead of right before it.
        let source = "digraph { a [label=<<b>bold</b>>] a -> b } // trailing comment with a }\n";
        assert!(
            dot::parse("workflow.fabro", source).is_err(),
            "fixture should be outside this crate's parsed subset"
        );

        let out = with_root_rankdir(source, "LR");

        let real_close = out
            .find("} //")
            .expect("real close should stay directly before the trailing comment");
        let insertion = out
            .find("rankdir=LR;")
            .expect("direction should be inserted");
        assert!(insertion < real_close, "{out}");
    }

    #[test]
    fn with_root_rankdir_falls_back_keeps_last_assignment_winning_over_an_existing_rankdir() {
        // Correctness: DOT's "last assignment wins" rule means the
        // fallback's appended `rankdir=LR;` must land *after* any
        // earlier root-scope `rankdir` the source already carried
        // (here `TB`, before the HTML label that puts this source
        // outside the parseable subset), not merely anywhere before
        // the closing brace.
        let source = "digraph { rankdir=TB a [label=<<b>bold</b>>] a -> b }";
        assert!(
            dot::parse("workflow.fabro", source).is_err(),
            "fixture should be outside this crate's parsed subset"
        );

        let out = with_root_rankdir(source, "LR");

        let tb_pos = out
            .find("rankdir=TB")
            .expect("existing rankdir should survive");
        let lr_pos = out
            .find("rankdir=LR")
            .expect("direction should be inserted");
        assert!(lr_pos > tb_pos, "{out}");
    }

    #[test]
    fn render_url_source_neutralizes_unsafe_fontname_everywhere() {
        // Security fix, source side: Graphviz writes `fontname`/
        // `labelfontname`/`stylesheet` unescaped straight into SVG
        // output at every scope; a value containing `"`, `<`, `>` or
        // `&` can break out of the attribute (or PI) it lands in, so
        // it is dropped before Graphviz ever sees it — at the root
        // graph, a node, an edge, every default block, and inside a
        // subgraph.
        let source = r#"digraph X {
            fontname="GF\"bad"
            stylesheet="SS<bad"
            node [fontname="NF&bad"]
            edge [fontname="EF>bad"]
            subgraph cluster_0 {
                fontname="SUBF\"bad"
                a [fontname="NODEF\"bad", label="A"]
            }
            b [label="B"]
            a -> b [fontname="EDGEF\"bad", labelfontname="LF<bad"]
        }"#;

        let out = render_url_source(source, None);

        for needle in ["GF", "SS", "NF", "EF", "SUBF", "NODEF", "LF"] {
            assert!(!out.contains(needle), "{needle}: {out}");
        }
        assert!(out.contains(r#""A""#), "{out}");
        assert!(out.contains(r#""B""#), "{out}");
    }

    #[test]
    fn render_url_source_keeps_a_safe_fontname() {
        let source = r#"digraph X { a [fontname="Helvetica", label="A"] }"#;
        let out = render_url_source(source, None);
        assert!(out.contains("Helvetica"), "{out}");
    }

    #[test]
    fn render_url_source_applies_direction_in_the_same_parse() {
        let source = r#"digraph X { a [fontname="F\"bad", label="A"] a -> b }"#;
        let out = render_url_source(source, Some("LR"));
        assert!(!out.contains("bad"), "{out}");
        assert_eq!(last_root_rankdir(&out).as_deref(), Some("LR"));
    }

    #[test]
    fn render_url_source_falls_back_unchanged_when_unparsable() {
        let source = "digraph { a [label=<<b>bold</b>>] }";
        assert_eq!(render_url_source(source, None), source);
    }
}
