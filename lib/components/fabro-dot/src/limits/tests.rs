#![expect(
    clippy::default_trait_access,
    reason = "test AST fixtures need a `dot::ast::Attr`/`Ident`/`SubgraphStmt` span; `Span`'s \
              defining crate (`frontend`) is a transitive dependency not re-exported by \
              petri_frontend_attractor, so it cannot be named here."
)]
use std::time::{Duration, Instant};

use petri_frontend_attractor::dot::{
    AstValue, Attr, DotGraph, EdgeStmt, Ident, NodeStmt, Statement, SubgraphStmt,
};

use super::*;

fn ident(name: &str) -> Ident {
    Ident {
        name: name.to_string(),
        span: Default::default(),
    }
}

fn attr(key: &str, value: &str) -> Attr {
    Attr {
        key:   key.to_string(),
        value: AstValue::Str(value.to_string()),
        span:  Default::default(),
    }
}

fn graph(name: &str, statements: Vec<Statement>) -> DotGraph {
    DotGraph {
        name: ident(name),
        statements,
    }
}

#[test]
fn measure_graph_counts_nodes_including_edge_only_ids() {
    // `b` and `c` are only ever referenced as edge endpoints; they must
    // still count as nodes, without a separate `NodeStmt`.
    let g = graph("G", vec![
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
        Statement::Edge(EdgeStmt {
            nodes: vec![ident("a"), ident("b"), ident("c")],
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.nodes, 3);
}

#[test]
fn measure_graph_counts_edges_as_k_minus_one_per_statement() {
    // `a -> b -> c -> d` is one statement but three edges.
    let g = graph("G", vec![Statement::Edge(EdgeStmt {
        nodes: vec![ident("a"), ident("b"), ident("c"), ident("d")],
        attrs: None,
    })]);
    let m = measure_graph(&g);
    assert_eq!(m.edges, 3);
    assert_eq!(m.statements, 1);
}

#[test]
fn measure_graph_sums_statements_across_subgraphs() {
    let g = graph("G", vec![
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
        Statement::Subgraph(SubgraphStmt {
            name:       None,
            statements: vec![
                Statement::Node(NodeStmt {
                    id:    ident("b"),
                    attrs: None,
                }),
                Statement::Node(NodeStmt {
                    id:    ident("c"),
                    attrs: None,
                }),
            ],
            span:       Default::default(),
        }),
    ]);
    let m = measure_graph(&g);
    // 1 top-level node + 1 subgraph statement (counted itself) + 2 nested nodes.
    assert_eq!(m.statements, 4);
    assert_eq!(m.nodes, 3);
}

#[test]
fn measure_graph_counts_an_ac19_e_example_as_six_statements() {
    // AC19(e): `digraph { node [a=1]; x; y -> z -> w; subgraph s { q; r=1 } }`
    // = 6 statements: the attribute statement, x, the edge statement, the
    // subgraph (counted once for itself), q, and the `r=1` assignment.
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr("a", "1")]),
        Statement::Node(NodeStmt {
            id:    ident("x"),
            attrs: None,
        }),
        Statement::Edge(EdgeStmt {
            nodes: vec![ident("y"), ident("z"), ident("w")],
            attrs: None,
        }),
        Statement::Subgraph(SubgraphStmt {
            name:       Some(ident("s")),
            statements: vec![
                Statement::Node(NodeStmt {
                    id:    ident("q"),
                    attrs: None,
                }),
                Statement::GraphAttr(attr("r", "1")),
            ],
            span:       Default::default(),
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.statements, 6);
}

#[test]
fn measure_graph_charges_default_attribute_bytes_to_each_node_and_edge() {
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr("shape", "box")]),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
        Statement::Node(NodeStmt {
            id:    ident("b"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    // "shape" (5) + "box" (3) = 8 bytes, copied onto each of the 2 nodes.
    assert_eq!(m.attribute_bytes, 16);
}

#[test]
fn measure_graph_charges_node_defaults_to_edge_only_nodes() {
    // Petri's ensure_node charges the in-scope node defaults to an id the
    // first time it is seen, whether declared with a `Node` statement or
    // only ever referenced as an edge endpoint.
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr("p", "xxxxxxxxxx")]),
        Statement::Edge(EdgeStmt {
            nodes: vec![ident("a"), ident("b"), ident("c")],
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    // "p" (1) + "xxxxxxxxxx" (10) = 11 bytes, charged once per of the 3
    // edge-only nodes (a, b, c): >= 33.
    assert!(m.attribute_bytes >= 33, "{}", m.attribute_bytes);
}

#[test]
fn measure_graph_charges_edge_defaults_once_per_edge_pair() {
    // `edge [w=<10 B>]; a -> b -> c` is 2 edge pairs (a->b, b->c), each
    // charged the 10-byte-value default once.
    let g = graph("G", vec![
        Statement::EdgeDefaults(vec![attr("w", "xxxxxxxxxx")]),
        Statement::Edge(EdgeStmt {
            nodes: vec![ident("a"), ident("b"), ident("c")],
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    // "w" (1) + "xxxxxxxxxx" (10) = 11 bytes, charged twice (2 pairs): 22.
    assert_eq!(m.attribute_bytes, 22);
}

#[test]
fn measure_graph_charges_a_nodes_own_attributes() {
    let g = graph("G", vec![Statement::Node(NodeStmt {
        id:    ident("a"),
        attrs: Some(vec![attr("shape", "box")]),
    })]);
    let m = measure_graph(&g);
    // "shape" (5) + "box" (3) = 8 bytes, with no defaults in play.
    assert_eq!(m.attribute_bytes, 8);
}

#[test]
fn measure_graph_charges_an_edges_own_attributes() {
    let g = graph("G", vec![Statement::Edge(EdgeStmt {
        nodes: vec![ident("a"), ident("b")],
        attrs: Some(vec![attr("w", "x")]),
    })]);
    let m = measure_graph(&g);
    // "w" (1) + "x" (1) = 2 bytes, for the single a->b pair.
    assert_eq!(m.attribute_bytes, 2);
}

#[test]
fn measure_graph_stops_applying_subgraph_scoped_defaults_after_it_closes() {
    // `subgraph { node [p=x]; a } b` — `b` is declared outside the
    // subgraph, after it closes, so it must not be charged `p`'s bytes.
    let g = graph("G", vec![
        Statement::Subgraph(SubgraphStmt {
            name:       None,
            statements: vec![
                Statement::NodeDefaults(vec![attr("p", "x")]),
                Statement::Node(NodeStmt {
                    id:    ident("a"),
                    attrs: None,
                }),
            ],
            span:       Default::default(),
        }),
        Statement::Node(NodeStmt {
            id:    ident("b"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.nodes, 2);
    // "p" (1) + "x" (1) = 2 bytes, charged only to `a`; `b` gets none.
    assert_eq!(m.attribute_bytes, 2);
}

#[test]
fn measure_graph_replaces_a_repeated_default_key_in_the_same_scope() {
    // `node [p=1]; node [p=22]; a` counts `p=22` once, not `p=1` + `p=22`.
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr("p", "1")]),
        Statement::NodeDefaults(vec![attr("p", "22")]),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    // "p" (1) + "22" (2) = 3 bytes, once.
    assert_eq!(m.attribute_bytes, 3);
}

#[test]
fn measure_graph_charges_a_subgraph_label_once_per_member_node() {
    let g = graph("G", vec![Statement::Subgraph(SubgraphStmt {
        name:       None,
        statements: vec![
            Statement::GraphAttr(attr("label", "xxxxxxxxxx")),
            Statement::Node(NodeStmt {
                id:    ident("a"),
                attrs: None,
            }),
            Statement::Node(NodeStmt {
                id:    ident("b"),
                attrs: None,
            }),
            // Listing `a` again must not double-charge its label.
            Statement::Node(NodeStmt {
                id:    ident("a"),
                attrs: None,
            }),
        ],
        span:       Default::default(),
    })]);
    let m = measure_graph(&g);
    // "xxxxxxxxxx" (10 bytes) once per of the 2 distinct members (a, b): 20.
    assert_eq!(m.attribute_bytes, 20);
}

#[test]
fn measure_graph_charges_the_max_of_two_bare_labels_in_a_subgraph() {
    // Petri's model build copies only the *first* `label` it sees onto
    // each member; charging the max of every label written in the scope
    // is an upper bound on that, regardless of write order.
    let g = graph("G", vec![Statement::Subgraph(SubgraphStmt {
        name:       None,
        statements: vec![
            Statement::GraphAttr(attr("label", "xxxxxxxxxx")),
            Statement::GraphAttr(attr("label", "y")),
            Statement::Node(NodeStmt {
                id:    ident("a"),
                attrs: None,
            }),
            Statement::Node(NodeStmt {
                id:    ident("b"),
                attrs: None,
            }),
        ],
        span:       Default::default(),
    })]);
    let m = measure_graph(&g);
    // max(10, 1) = 10 bytes, once per of the 2 members: >= 20.
    assert!(m.attribute_bytes >= 20, "{}", m.attribute_bytes);
}

#[test]
fn measure_graph_charges_the_max_of_two_labels_in_one_graph_attrs_block() {
    // Same as above, but both `label`s are written in one `graph [...]`
    // block rather than as two bare assignments.
    let g = graph("G", vec![Statement::Subgraph(SubgraphStmt {
        name:       None,
        statements: vec![
            Statement::GraphAttrs(vec![attr("label", "xxxxxxxxxx"), attr("label", "y")]),
            Statement::Node(NodeStmt {
                id:    ident("a"),
                attrs: None,
            }),
            Statement::Node(NodeStmt {
                id:    ident("b"),
                attrs: None,
            }),
        ],
        span:       Default::default(),
    })]);
    let m = measure_graph(&g);
    assert!(m.attribute_bytes >= 20, "{}", m.attribute_bytes);
}

#[test]
fn measure_graph_does_not_charge_a_root_graph_label() {
    // A `label` written on the entrypoint graph itself (not inside a
    // subgraph) is a workflow attribute Petri reads directly; it is not
    // copied onto every node, so it must not be charged here.
    let g = graph("G", vec![
        Statement::GraphAttr(attr("label", "xxxxxxxxxx")),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
        Statement::Node(NodeStmt {
            id:    ident("b"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.attribute_bytes, 0);
}

#[test]
fn measure_graph_charges_model_stylesheet_bytes_once_per_node() {
    let stylesheet = "x".repeat(50);
    let g = graph("G", vec![
        Statement::GraphAttrs(vec![attr("model_stylesheet", &stylesheet)]),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
        Statement::Node(NodeStmt {
            id:    ident("b"),
            attrs: None,
        }),
        Statement::Node(NodeStmt {
            id:    ident("c"),
            attrs: None,
        }),
        Statement::Node(NodeStmt {
            id:    ident("d"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.nodes, 4);
    // 50 bytes x 4 nodes = 200.
    assert_eq!(m.attribute_bytes, 200);
}

#[test]
fn measure_graph_accepts_exactly_the_node_limit() {
    let statements: Vec<Statement> = (0..MAX_NODES)
        .map(|i| {
            Statement::Node(NodeStmt {
                id:    ident(&format!("n{i}")),
                attrs: None,
            })
        })
        .collect();
    let g = graph("G", statements);
    let m = measure_graph(&g);
    assert_eq!(m.nodes, MAX_NODES);
    assert!(m.first_violation().is_none(), "{m:?}");
}

#[test]
fn measure_graph_detects_a_violation_over_the_node_limit() {
    let statements: Vec<Statement> = (0..=MAX_NODES)
        .map(|i| {
            Statement::Node(NodeStmt {
                id:    ident(&format!("n{i}")),
                attrs: None,
            })
        })
        .collect();
    let g = graph("G", statements);
    let m = measure_graph(&g);
    let violation = m.first_violation().expect("should exceed MAX_NODES");
    assert_eq!(violation.kind, GraphLimitKind::Nodes);
    assert_eq!(violation.limit, MAX_NODES);
    assert_eq!(violation.count, MAX_NODES + 1);
}

#[test]
fn measure_graph_accepts_exactly_the_edge_limit() {
    // One edge statement with MAX_EDGES+1 endpoints alternating a/b:
    // exactly MAX_EDGES edges (hop count = endpoints - 1), only 2
    // distinct nodes, so this stays within every limit.
    let ids: Vec<Ident> = (0..=MAX_EDGES)
        .map(|i| ident(if i % 2 == 0 { "a" } else { "b" }))
        .collect();
    let g = graph("G", vec![Statement::Edge(EdgeStmt {
        nodes: ids,
        attrs: None,
    })]);
    let m = measure_graph(&g);
    assert_eq!(m.edges, MAX_EDGES);
    assert!(m.first_violation().is_none(), "{m:?}");
}

#[test]
fn measure_graph_detects_a_violation_over_the_edge_limit() {
    // Alternate between 2 ids for MAX_EDGES+2 hops: MAX_EDGES+1 edges, but
    // only 2 distinct nodes, so this trips the edge limit without also
    // tripping the (lower-numbered, checked-first) node limit.
    let ids: Vec<Ident> = (0..=MAX_EDGES + 1)
        .map(|i| ident(if i % 2 == 0 { "a" } else { "b" }))
        .collect();
    let g = graph("G", vec![Statement::Edge(EdgeStmt {
        nodes: ids,
        attrs: None,
    })]);
    let m = measure_graph(&g);
    let violation = m.first_violation().expect("should exceed MAX_EDGES");
    assert_eq!(violation.kind, GraphLimitKind::Edges);
    assert_eq!(violation.limit, MAX_EDGES);
}

#[test]
fn measure_graph_detects_a_violation_over_the_statement_limit() {
    // Statements that add no node or edge (an arbitrary top-level
    // assignment), so this trips only the statement limit, not the
    // (lower-numbered, checked-first) node limit.
    let statements: Vec<Statement> = (0..=MAX_STATEMENTS)
        .map(|_| Statement::GraphAttr(attr("note", "x")))
        .collect();
    let g = graph("G", statements);
    let m = measure_graph(&g);
    let violation = m.first_violation().expect("should exceed MAX_STATEMENTS");
    assert_eq!(violation.kind, GraphLimitKind::Statements);
    assert_eq!(violation.limit, MAX_STATEMENTS);
    assert_eq!(violation.count, MAX_STATEMENTS + 1);
    assert_eq!(m.nodes, 0);
}

#[test]
fn measure_graph_detects_a_violation_over_the_attribute_text_limit() {
    let big_value = "x".repeat(usize::try_from(MAX_ATTRIBUTE_BYTES + 1).unwrap());
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr("p", &big_value)]),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    let violation = m
        .first_violation()
        .expect("should exceed MAX_ATTRIBUTE_BYTES");
    assert_eq!(violation.kind, GraphLimitKind::AttributeBytes);
    assert_eq!(violation.limit, MAX_ATTRIBUTE_BYTES);
}

#[test]
fn measure_graph_accepts_up_to_the_attribute_text_limit() {
    // AC20(b) at-limit case, measured at the fabro-dot level only (never
    // through Petri's validation, which is unsafe to run on a 3 MiB
    // single-value input on this machine outside a watchdog): exactly
    // MAX_ATTRIBUTE_BYTES is accepted, one byte more (above) is not.
    let key = "p";
    let value_len = usize::try_from(MAX_ATTRIBUTE_BYTES).unwrap() - key.len();
    let value = "x".repeat(value_len);
    let g = graph("G", vec![
        Statement::NodeDefaults(vec![attr(key, &value)]),
        Statement::Node(NodeStmt {
            id:    ident("a"),
            attrs: None,
        }),
    ]);
    let m = measure_graph(&g);
    assert_eq!(m.attribute_bytes, MAX_ATTRIBUTE_BYTES);
    assert!(m.first_violation().is_none(), "{m:?}");
}

#[test]
fn measure_graph_stays_fast_with_many_node_defaults_and_many_nodes() {
    // Linearity guard: `node [a0=1,...,a49999=1]` (50,000 default keys)
    // plus 50,000 node statements. The pre-fix per-node full-map scan
    // would be O(nodes x keys); this must stay fast regardless. The
    // 50,000-key default map's total bytes alone exceed
    // MAX_ATTRIBUTE_BYTES well before 500 distinct nodes are seen, so
    // this always stops early (on nodes or attribute bytes, whichever
    // the walk reaches first) long before the 50,000th statement.
    let defaults: Vec<Attr> = (0..50_000).map(|i| attr(&format!("a{i}"), "1")).collect();
    let mut statements: Vec<Statement> = Vec::with_capacity(50_001);
    statements.push(Statement::NodeDefaults(defaults));
    statements.extend((0..50_000).map(|i| {
        Statement::Node(NodeStmt {
            id:    ident(&format!("n{i}")),
            attrs: None,
        })
    }));
    let g = graph("G", statements);

    let start = Instant::now();
    let m = measure_graph(&g);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "measure_graph took {elapsed:?}, expected well under 1s"
    );
    assert!(
        m.first_violation().is_some(),
        "a 50,000-key default map applied to many nodes should exceed some limit"
    );
    assert!(
        m.nodes < 50_000,
        "the walk should have stopped early, well short of 50,000 nodes"
    );
}

#[test]
fn measure_graph_stays_fast_entering_many_subgraphs_under_a_large_default_map() {
    // Linearity guard for subgraph scopes: 100,000 node-default keys, then
    // 19,000 empty `subgraph {}` statements (19,001 statements, under
    // MAX_STATEMENTS, and no node is ever declared, so nothing stops the
    // walk early). Copying the in-scope defaults on every subgraph entry
    // costs 19,000 x 100,000 map entries; restoring scopes from an undo
    // log of that scope's own edits costs nothing here.
    let defaults: Vec<Attr> = (0..100_000).map(|i| attr(&format!("a{i}"), "1")).collect();
    let mut statements: Vec<Statement> = Vec::with_capacity(19_001);
    statements.push(Statement::NodeDefaults(defaults));
    statements.extend((0..19_000).map(|_| {
        Statement::Subgraph(SubgraphStmt {
            name:       None,
            statements: vec![],
            span:       Default::default(),
        })
    }));
    let g = graph("G", statements);

    let start = Instant::now();
    let m = measure_graph(&g);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "measure_graph took {elapsed:?}, expected well under 1s"
    );
    assert_eq!(m.statements, 19_001);
    assert_eq!(m.nodes, 0);
    assert!(m.first_violation().is_none(), "{m:?}");
}

#[test]
fn measure_graph_stays_fast_charging_many_edge_endpoints_under_a_large_default_map() {
    // Linearity guard for per-node charges inside one statement: 100,000
    // node-default keys, then a single edge statement through 100,000
    // distinct nodes. The limits are checked between statements, so this
    // one statement is walked to its end. Summing the default map on each
    // new endpoint costs 100,000 x 100,000; a running total costs one add.
    let defaults: Vec<Attr> = (0..100_000).map(|i| attr(&format!("a{i}"), "1")).collect();
    let chain: Vec<Ident> = (0..100_000).map(|i| ident(&format!("n{i}"))).collect();
    let g = graph("G", vec![
        Statement::NodeDefaults(defaults),
        Statement::Edge(EdgeStmt {
            nodes: chain,
            attrs: None,
        }),
    ]);

    let start = Instant::now();
    let m = measure_graph(&g);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "measure_graph took {elapsed:?}, expected well under 1s"
    );
    assert_eq!(m.nodes, 100_000);
    assert_eq!(
        m.first_violation().map(|v| v.kind),
        Some(GraphLimitKind::Nodes)
    );
}

#[test]
fn graph_limit_constants() {
    assert_eq!(MAX_NODES, 500);
    assert_eq!(MAX_EDGES, 2_000);
    assert_eq!(MAX_STATEMENTS, 20_000);
    assert_eq!(MAX_ATTRIBUTE_BYTES, 3 * 1024 * 1024);
    assert_eq!(MAX_NESTING_DEPTH, 8);
}

#[test]
fn nesting_scan_allows_exactly_eight_levels() {
    let text =
        "digraph G {".to_string() + &"subgraph { ".repeat(8) + "a } ".repeat(8).as_str() + "}";
    assert_eq!(scan_nesting_depth(&text), Ok(8));
}

#[test]
fn nesting_scan_treats_mid_line_hash_as_an_ordinary_character() {
    // Petri's lexer only treats `#` as a comment at the start of a line;
    // mid-line it is an ordinary character (e.g. inside a color value), so
    // a brace after a mid-line `#` must still be counted.
    let text = "digraph G { a [color=\"#fff\"] subgraph {{{{{{{{{ b } } } } } } } } }\n}";
    let err = scan_nesting_depth(text).expect_err("the braces after the mid-line # should count");
    assert_eq!(err.kind, GraphLimitKind::Nesting);
}

#[test]
fn nesting_scan_refuses_a_true_mid_line_hash_followed_by_braces() {
    // A minimal version of the above: `#` preceded by `a ` on the same
    // line is not a comment, so the braces right after it must count and
    // push nesting past the limit.
    let text = "digraph G { a # ".to_string() + &"{".repeat(9) + " }";
    let err = scan_nesting_depth(&text).expect_err("mid-line # must not hide the braces");
    assert_eq!(err.kind, GraphLimitKind::Nesting);
    assert_eq!(err.count, 9);
}

#[test]
fn nesting_scan_treats_a_line_start_hash_as_a_comment() {
    let text = "digraph G {\n# {{{{{{{{{\n}";
    assert_eq!(scan_nesting_depth(text), Ok(0));
}

#[test]
fn nesting_scan_treats_hash_right_after_a_line_comment_as_a_comment_too() {
    // A `//` line comment ends at `\n`; the very next character starts a
    // new line, so a `#` there is a comment too (previously this reset
    // was missed, leaving the scanner thinking it was still mid-line).
    let text = "// c\n# {{{{{{{{{";
    assert_eq!(scan_nesting_depth(text), Ok(0));
}

#[test]
fn nesting_scan_refuses_nine_levels() {
    let text =
        "digraph G {".to_string() + &"subgraph { ".repeat(9) + "a } ".repeat(9).as_str() + "}";
    let err = scan_nesting_depth(&text).expect_err("9 levels should be refused");
    assert_eq!(err.kind, GraphLimitKind::Nesting);
    assert_eq!(err.count, 9);
}

#[test]
fn nesting_scan_refuses_fifty_thousand_levels_without_parsing() {
    // This feeds the scan alone (never `dot::parse`, Petri's
    // recursive-descent parser, which has no depth limit of its own and
    // would be unsafe to run on input this deep on this machine): the
    // whole point of the pre-parse scan is to refuse before the parser
    // would ever see this input.
    let text = "{".repeat(50_000);
    let err = scan_nesting_depth(&text).expect_err("50,000 levels should be refused");
    assert_eq!(err.kind, GraphLimitKind::Nesting);
    assert_eq!(err.limit, u64::from(MAX_NESTING_DEPTH));
}

#[test]
fn nesting_scan_ignores_braces_inside_strings_and_comments() {
    let text = r#"digraph G { a [label="{{{{{{{{{{"] // {{{{{{{{{{
    }"#;
    assert_eq!(scan_nesting_depth(text), Ok(0));
}

#[test]
fn nesting_scan_ignores_braces_after_an_escaped_quote_in_a_string() {
    // `"\"{{{{{{{{{"`: an escaped quote followed by 9 braces, still
    // inside the (still-open) string, so none of them count.
    let text = format!("\"\\\"{}\"", "{".repeat(9));
    assert_eq!(scan_nesting_depth(&text), Ok(0));
}

#[test]
fn nesting_scan_ignores_braces_inside_a_block_comment() {
    let text = format!("/* {} */", "{".repeat(9));
    assert_eq!(scan_nesting_depth(&text), Ok(0));
}

#[test]
fn subgraph_depth_violation_reports_exceeded_count() {
    let text =
        "digraph G {".to_string() + &"subgraph { ".repeat(10) + "a } ".repeat(10).as_str() + "}";
    let err = scan_nesting_depth(&text).expect_err("10 levels should be refused");
    // the scan returns as soon as depth exceeds MAX_NESTING_DEPTH (8), at
    // the 9th subgraph open brace, rather than scanning the rest of the
    // input.
    assert_eq!(err.count, 9);
}
