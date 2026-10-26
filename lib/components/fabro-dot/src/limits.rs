//! Graph-size limits, checked from the raw DOT AST before Petri builds its
//! model (see `WorkflowGraph`, this crate's full walker, for the model-level
//! view). Every function here stays linear in the input's length and never
//! calls `petri_frontend_attractor::model::build`, so a request this module
//! refuses never pays the cost the limits exist to bound: validating a
//! parsed workflow measured 2026-10-25 to grow memory roughly with the
//! square of its node count (1,709 nodes took 1.5 GB).
//!
//! [`scan_nesting_depth`] runs first and never parses: Petri's
//! recursive-descent DOT parser has no depth limit of its own and a
//! sufficiently nested input (observed: 50,000 levels) can overflow its
//! stack before [`measure_graph`] would ever see a parsed graph.

use std::collections::{HashMap, HashSet};

use petri_frontend_attractor::dot::{self, AstValue, DotGraph, Statement};

/// At most 500 nodes (declared or edge-only), counted after parsing and
/// before validation. Owner decision 2026-10-25 (revised from an initial
/// 1,000 after a Linux measurement: validating a 1,000-node chain under
/// the 1 GiB RLIMIT_AS cap aborted; 500 nodes fits in about 260 MB).
pub const MAX_NODES: u64 = 500;
/// At most 2,000 edges; an edge statement `a -> b -> c` contributes `k - 1`
/// edges for its `k` chained endpoints, counted the same way.
pub const MAX_EDGES: u64 = 2_000;
/// At most 20,000 statements total, across the entrypoint and every nested
/// subgraph.
pub const MAX_STATEMENTS: u64 = 20_000;
/// At most 3 MiB of attribute text once `node [...]`/`edge [...]` defaults
/// are applied to every node and edge (Petri copies the defaults into each
/// node and edge before validating).
pub const MAX_ATTRIBUTE_BYTES: u64 = 3 * 1024 * 1024;
/// Subgraphs may nest at most 8 levels deep (Petri copies defaults and the
/// subtree at every level, and its recursive parser has no depth limit).
/// The entrypoint graph's own braces are level 0 (not a subgraph); only
/// `subgraph { ... }` blocks increment this count.
pub const MAX_NESTING_DEPTH: u32 = 8;

/// Which measured dimension a [`GraphLimitViolation`] names; also the API's
/// `graph_too_large` error `meta.max` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphLimitKind {
    Nodes,
    Edges,
    Statements,
    AttributeBytes,
    Nesting,
}

impl GraphLimitKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Statements => "statements",
            Self::AttributeBytes => "attribute_text",
            Self::Nesting => "nesting_depth",
        }
    }
}

/// A measured dimension exceeded its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphLimitViolation {
    pub kind:  GraphLimitKind,
    pub limit: u64,
    pub count: u64,
}

/// The first dimension (nodes, then edges, then statements, then attribute
/// bytes — the order [`GraphMeasurement::first_violation`] uses) that is
/// *currently* over its limit in `counters`' state, if any. Correctness
/// note: because [`walk_statements`] stops as soon as any one dimension
/// crosses its limit (via [`find_violation`]), the dimension this names
/// is the first one that crossed its limit in walk order, which is not
/// necessarily the same dimension a hypothetical full (non-stopping)
/// walk's final [`GraphMeasurement::first_violation`] would report: a
/// full walk picks by this priority order among every dimension's
/// *final* totals, while an early-stopped walk only ever sees whichever
/// dimension happened to cross first.
fn first_violation_of(
    nodes: u64,
    edges: u64,
    statements: u64,
    attribute_bytes: u64,
) -> Option<GraphLimitViolation> {
    if nodes > MAX_NODES {
        return Some(GraphLimitViolation {
            kind:  GraphLimitKind::Nodes,
            limit: MAX_NODES,
            count: nodes,
        });
    }
    if edges > MAX_EDGES {
        return Some(GraphLimitViolation {
            kind:  GraphLimitKind::Edges,
            limit: MAX_EDGES,
            count: edges,
        });
    }
    if statements > MAX_STATEMENTS {
        return Some(GraphLimitViolation {
            kind:  GraphLimitKind::Statements,
            limit: MAX_STATEMENTS,
            count: statements,
        });
    }
    if attribute_bytes > MAX_ATTRIBUTE_BYTES {
        return Some(GraphLimitViolation {
            kind:  GraphLimitKind::AttributeBytes,
            limit: MAX_ATTRIBUTE_BYTES,
            count: attribute_bytes,
        });
    }
    None
}

/// Counts from a linear walk of the raw DOT AST: never builds Petri's
/// model, which copies node/edge defaults and subgraph subtrees onto every
/// node and so costs roughly the square of the node count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GraphMeasurement {
    pub nodes:           u64,
    pub edges:           u64,
    pub statements:      u64,
    /// Attribute key+value text, with `node []`/`edge []` defaults applied
    /// to every node/edge they cover, plus (conservatively, since matching
    /// its selectors needs the model this walk avoids building) the
    /// `model_stylesheet` graph attribute's text once per node.
    pub attribute_bytes: u64,
}

impl GraphMeasurement {
    /// The first dimension (in this order) that exceeds its limit, if any.
    #[must_use]
    pub fn first_violation(&self) -> Option<GraphLimitViolation> {
        first_violation_of(
            self.nodes,
            self.edges,
            self.statements,
            self.attribute_bytes,
        )
    }
}

/// A linear, one-pass scan of the raw text for subgraph nesting depth, run
/// *before* parsing. Tracks double-quoted string and `//`/`#`/`/* */`
/// comment state so braces written inside them are not counted. The
/// entrypoint graph's own `{`/`}` is depth 0 (it is not a subgraph); only
/// `subgraph { ... }` blocks increment the depth this function reports and
/// checks. Returns as soon as the depth exceeds [`MAX_NESTING_DEPTH`], so a
/// pathologically deep input (observed: 50,000 levels) is refused without
/// scanning the rest of it and without ever invoking Petri's parser.
pub fn scan_nesting_depth(text: &str) -> Result<u32, GraphLimitViolation> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        Str,
        StrEscape,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    // Raw, unadjusted brace depth (includes the entrypoint graph's own
    // opening brace). The subgraph nesting depth this function reports is
    // one less: the graph's own `{` is level 0.
    let mut raw_depth: u32 = 0;
    let mut max_subgraph_depth: u32 = 0;
    // `#` is a comment only as the first non-whitespace character on its
    // line (mirroring Petri's lexer, `at_line_start`); mid-line it is an
    // ordinary character, so a mid-line `#` before a brace must not hide
    // that brace from this scan.
    let mut at_line_start = true;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let was_at_line_start = at_line_start;
        match state {
            State::Normal => {
                at_line_start = match c {
                    '\n' => true,
                    ' ' | '\t' | '\r' => was_at_line_start,
                    _ => false,
                };
            }
            // A line comment ends at `\n`; the character right after it
            // starts a new line, so a `#` there is a comment too.
            State::LineComment if c == '\n' => at_line_start = true,
            _ => {}
        }
        state = match state {
            State::Normal => match c {
                '"' => State::Str,
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    State::LineComment
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    State::BlockComment
                }
                '#' if was_at_line_start => State::LineComment,
                '{' => {
                    raw_depth += 1;
                    let subgraph_depth = raw_depth.saturating_sub(1);
                    max_subgraph_depth = max_subgraph_depth.max(subgraph_depth);
                    if subgraph_depth > MAX_NESTING_DEPTH {
                        return Err(GraphLimitViolation {
                            kind:  GraphLimitKind::Nesting,
                            limit: u64::from(MAX_NESTING_DEPTH),
                            count: u64::from(subgraph_depth),
                        });
                    }
                    State::Normal
                }
                '}' => {
                    raw_depth = raw_depth.saturating_sub(1);
                    State::Normal
                }
                _ => State::Normal,
            },
            State::Str => match c {
                '\\' => State::StrEscape,
                '"' => State::Normal,
                _ => State::Str,
            },
            State::StrEscape => State::Str,
            State::LineComment => {
                if c == '\n' {
                    State::Normal
                } else {
                    State::LineComment
                }
            }
            State::BlockComment => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    State::Normal
                } else {
                    State::BlockComment
                }
            }
        };
    }
    Ok(max_subgraph_depth)
}

/// Byte offset of the root graph's own closing `}` — the brace that
/// matches its first, root-scope `{` — found by a linear,
/// comment/string-aware scan in the same spirit as
/// [`scan_nesting_depth`]'s (double-quoted strings and `//`/`#`-at-
/// line-start/`/* */` comments are skipped, so a `}` written inside one
/// — e.g. a trailing `// }` comment after the real close, or a label
/// string that happens to contain `}` — is never mistaken for the real
/// one). A stray `}` reached before any `{` (depth already 0) is
/// likewise skipped rather than mistaken for the root's own close.
/// `None` when the source has no root-scope `{` at all, or its `{` is
/// never matched by a `}` (an unterminated/truncated graph). This is
/// `fabro_dot::graphviz`'s `with_root_rankdir` text-level fallback's
/// insertion point when `source` is outside the subset this crate's
/// own parser accepts.
pub(crate) fn root_graph_closing_brace(text: &str) -> Option<usize> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        Str,
        StrEscape,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    let mut depth: u32 = 0;
    let mut at_line_start = true;
    let mut chars = text.char_indices().peekable();
    while let Some((idx, c)) = chars.next() {
        let was_at_line_start = at_line_start;
        match state {
            State::Normal => {
                at_line_start = match c {
                    '\n' => true,
                    ' ' | '\t' | '\r' => was_at_line_start,
                    _ => false,
                };
            }
            State::LineComment if c == '\n' => at_line_start = true,
            _ => {}
        }
        state = match state {
            State::Normal => match c {
                '"' => State::Str,
                '/' if matches!(chars.peek(), Some((_, '/'))) => {
                    chars.next();
                    State::LineComment
                }
                '/' if matches!(chars.peek(), Some((_, '*'))) => {
                    chars.next();
                    State::BlockComment
                }
                '#' if was_at_line_start => State::LineComment,
                '{' => {
                    depth += 1;
                    State::Normal
                }
                '}' => {
                    if depth > 0 {
                        depth -= 1;
                        if depth == 0 {
                            return Some(idx);
                        }
                    }
                    State::Normal
                }
                _ => State::Normal,
            },
            State::Str => match c {
                '\\' => State::StrEscape,
                '"' => State::Normal,
                _ => State::Str,
            },
            State::StrEscape => State::Str,
            State::LineComment => {
                if c == '\n' {
                    State::Normal
                } else {
                    State::LineComment
                }
            }
            State::BlockComment => {
                if c == '*' && matches!(chars.peek(), Some((_, '/'))) {
                    chars.next();
                    State::Normal
                } else {
                    State::BlockComment
                }
            }
        };
    }
    None
}

fn attr_text_len(value: &AstValue) -> u64 {
    value.as_text().len() as u64
}

/// An undoable edit to one key of [`DefaultAttrs`]'s node or edge map,
/// recording the entry's previous value (`None` if the key was absent) so
/// [`DefaultAttrs::undo_to`] can restore it exactly when a subgraph scope
/// that set it closes.
enum DefaultEdit {
    Node { key: String, prev: Option<u64> },
    Edge { key: String, prev: Option<u64> },
}

/// In-scope `node [...]`/`edge [...]` defaults, as a key -> "key bytes +
/// value bytes" map, plus a running total of that map's values so charging
/// a node or edge never has to sum the map (the quadratic hot path review
/// round 3 found: summing an O(k)-key map once per of O(n) nodes). A later
/// `node [k=...]`/`edge [k=...]` for the same key in the same scope
/// replaces the earlier one (AC19), updating the total in place.
///
/// Entering a subgraph mutates these maps and totals directly rather than
/// cloning them (the other half of review round 3's finding), and
/// [`undo_to`](Self::undo_to) restores the exact prior state — map entries
/// and totals both — once that subgraph's statements are done, so a
/// sibling scope never sees it.
#[derive(Default)]
struct DefaultAttrs {
    node:       HashMap<String, u64>,
    edge:       HashMap<String, u64>,
    node_bytes: u64,
    edge_bytes: u64,
}

impl DefaultAttrs {
    fn set_node(&mut self, key: String, value_len: u64, undo: &mut Vec<DefaultEdit>) {
        let entry_bytes = key.len() as u64 + value_len;
        let prev = self.node.insert(key.clone(), entry_bytes);
        self.node_bytes = self.node_bytes - prev.unwrap_or(0) + entry_bytes;
        undo.push(DefaultEdit::Node { key, prev });
    }

    fn set_edge(&mut self, key: String, value_len: u64, undo: &mut Vec<DefaultEdit>) {
        let entry_bytes = key.len() as u64 + value_len;
        let prev = self.edge.insert(key.clone(), entry_bytes);
        self.edge_bytes = self.edge_bytes - prev.unwrap_or(0) + entry_bytes;
        undo.push(DefaultEdit::Edge { key, prev });
    }

    /// Reverts every edit recorded in `undo` back to index `mark` (a
    /// length captured before a subgraph's statements were walked), in
    /// reverse order, restoring both the map entries and the running
    /// totals to exactly their state at `mark`.
    fn undo_to(&mut self, undo: &mut Vec<DefaultEdit>, mark: usize) {
        while undo.len() > mark {
            // `undo.len() > mark` was just checked, so a pop here always
            // yields a value.
            let Some(edit) = undo.pop() else {
                break;
            };
            match edit {
                DefaultEdit::Node { key, prev } => {
                    let current = self.node.get(&key).copied().unwrap_or(0);
                    self.node_bytes -= current;
                    match prev {
                        Some(bytes) => {
                            self.node_bytes += bytes;
                            self.node.insert(key, bytes);
                        }
                        None => {
                            self.node.remove(&key);
                        }
                    }
                }
                DefaultEdit::Edge { key, prev } => {
                    let current = self.edge.get(&key).copied().unwrap_or(0);
                    self.edge_bytes -= current;
                    match prev {
                        Some(bytes) => {
                            self.edge_bytes += bytes;
                            self.edge.insert(key, bytes);
                        }
                        None => {
                            self.edge.remove(&key);
                        }
                    }
                }
            }
        }
    }
}

struct Counters {
    nodes:                 HashSet<String>,
    edges:                 u64,
    statements:            u64,
    attribute_bytes:       u64,
    stylesheet_text_bytes: u64,
}

/// [`first_violation_of`] against `counters`' current (possibly
/// in-progress) state, so [`walk_statements`] can stop as soon as any
/// dimension crosses its limit instead of finishing the walk first.
/// Correctness note: this means the violation reported is the first one
/// (in walk order) that crossed its limit, not necessarily the same
/// dimension a full, non-stopping walk's final
/// `GraphMeasurement::first_violation` would report — see
/// [`first_violation_of`].
fn find_violation(counters: &Counters) -> Option<GraphLimitViolation> {
    let node_count = counters.nodes.len() as u64;
    let attribute_bytes = counters
        .attribute_bytes
        .saturating_add(counters.stylesheet_text_bytes.saturating_mul(node_count));
    first_violation_of(
        node_count,
        counters.edges,
        counters.statements,
        attribute_bytes,
    )
}

/// Walks `statements` (one subgraph scope), returning the set of node ids
/// declared or referenced anywhere within it (including nested
/// subgraphs) — its *members*, for charging a `label` on this scope once
/// per member (AC19(d)). `defaults` is the in-scope node/edge default
/// state shared with the caller: a nested subgraph's own `node
/// [...]`/`edge [...]` statements mutate it in place and are undone via
/// `undo` before this function returns, so they never leak to a sibling.
///
/// Returns `Err` as soon as [`find_violation`] finds any dimension over
/// its limit, stopping the walk early (the rest of `statements`, and any
/// calling scope's remaining statements, are never visited).
fn walk_statements(
    statements: &[Statement],
    defaults: &mut DefaultAttrs,
    undo: &mut Vec<DefaultEdit>,
    counters: &mut Counters,
    is_root: bool,
) -> Result<HashSet<String>, GraphLimitViolation> {
    let mut members: HashSet<String> = HashSet::new();
    // The *maximum* label length seen in this scope: Petri's model build
    // copies only the first `label` it sees onto each member, so charging
    // the max of every `label` written in the scope is an upper bound on
    // what it actually copies (review round 3: charging the *last* one
    // written let an attacker bypass the limit with `label="x"; label=
    // "<huge>"` reordered so the huge one is not last).
    let mut label_len: Option<u64> = None;
    for statement in statements {
        counters.statements += 1;
        match statement {
            Statement::GraphAttrs(attrs) => {
                for attr in attrs {
                    if attr.key == "model_stylesheet" {
                        counters.stylesheet_text_bytes += attr_text_len(&attr.value);
                    }
                    if attr.key == "label" {
                        let len = attr_text_len(&attr.value);
                        label_len = Some(label_len.unwrap_or(0).max(len));
                    }
                }
            }
            Statement::GraphAttr(attr) => {
                if attr.key == "model_stylesheet" {
                    counters.stylesheet_text_bytes += attr_text_len(&attr.value);
                }
                if attr.key == "label" {
                    let len = attr_text_len(&attr.value);
                    label_len = Some(label_len.unwrap_or(0).max(len));
                }
            }
            Statement::NodeDefaults(attrs) => {
                for attr in attrs {
                    defaults.set_node(attr.key.clone(), attr_text_len(&attr.value), undo);
                }
            }
            Statement::EdgeDefaults(attrs) => {
                for attr in attrs {
                    defaults.set_edge(attr.key.clone(), attr_text_len(&attr.value), undo);
                }
            }
            Statement::Node(node) => {
                members.insert(node.id.name.clone());
                // Petri's ensure_node charges the in-scope node defaults
                // once, the first time an id is seen, whether declared
                // here or only ever referenced as an edge endpoint.
                let first_seen = counters.nodes.insert(node.id.name.clone());
                let mut bytes = if first_seen { defaults.node_bytes } else { 0 };
                if let Some(attrs) = &node.attrs {
                    for attr in attrs {
                        bytes += attr.key.len() as u64 + attr_text_len(&attr.value);
                    }
                }
                counters.attribute_bytes += bytes;
            }
            Statement::Edge(edge) => {
                for id in &edge.nodes {
                    members.insert(id.name.clone());
                    if counters.nodes.insert(id.name.clone()) {
                        counters.attribute_bytes += defaults.node_bytes;
                    }
                }
                let hop_count = edge.nodes.len().saturating_sub(1) as u64;
                counters.edges += hop_count;
                let mut bytes = defaults.edge_bytes;
                if let Some(attrs) = &edge.attrs {
                    for attr in attrs {
                        bytes += attr.key.len() as u64 + attr_text_len(&attr.value);
                    }
                }
                counters.attribute_bytes += bytes.saturating_mul(hop_count.max(1));
            }
            Statement::Subgraph(sub) => {
                let mark = undo.len();
                let sub_members =
                    walk_statements(&sub.statements, defaults, undo, counters, false)?;
                defaults.undo_to(undo, mark);
                members.extend(sub_members);
            }
        }
        if let Some(violation) = find_violation(counters) {
            return Err(violation);
        }
    }
    // The root graph's own `label` is a workflow attribute Petri reads
    // directly (not copied onto every node), so only a subgraph's label
    // is charged here (AC19(d)).
    if !is_root {
        if let Some(len) = label_len {
            counters.attribute_bytes = counters
                .attribute_bytes
                .saturating_add(len.saturating_mul(members.len() as u64));
            if let Some(violation) = find_violation(counters) {
                return Err(violation);
            }
        }
    }
    Ok(members)
}

/// Measure a parsed DOT graph. Linear in the number of AST nodes (the
/// in-scope default maps are charged from a running total, never summed
/// per node or edge, and a subgraph's local defaults are applied and
/// undone in place rather than cloned); recursion depth is bounded by
/// [`scan_nesting_depth`], which every caller must run first. Stops as
/// soon as any dimension exceeds its limit, so a pathologically large
/// input is refused without walking the rest of it.
#[must_use]
pub fn measure_graph(dot: &DotGraph) -> GraphMeasurement {
    let mut counters = Counters {
        nodes:                 HashSet::new(),
        edges:                 0,
        statements:            0,
        attribute_bytes:       0,
        stylesheet_text_bytes: 0,
    };
    let mut defaults = DefaultAttrs::default();
    let mut undo = Vec::new();
    // An `Err` here just means the walk stopped early; `counters` already
    // holds everything needed to report the same violation below.
    let _ = walk_statements(
        &dot.statements,
        &mut defaults,
        &mut undo,
        &mut counters,
        true,
    );
    let node_count = counters.nodes.len() as u64;
    let attribute_bytes = counters
        .attribute_bytes
        .saturating_add(counters.stylesheet_text_bytes.saturating_mul(node_count));
    GraphMeasurement {
        nodes: node_count,
        edges: counters.edges,
        statements: counters.statements,
        attribute_bytes,
    }
}

/// Nesting scan, then (only if that passes) a parse and [`measure_graph`]
/// against every limit. A parse failure is not this function's job to
/// diagnose — it returns `Ok(())` and leaves `not_parsable` reporting to
/// the full validation pipeline, which parses again with diagnostics.
pub fn check_graph_limits(text: &str) -> Result<(), GraphLimitViolation> {
    scan_nesting_depth(text)?;
    let Ok(parsed) = dot::parse("workflow.fabro", text) else {
        return Ok(());
    };
    match measure_graph(&parsed).first_violation() {
        Some(violation) => Err(violation),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
