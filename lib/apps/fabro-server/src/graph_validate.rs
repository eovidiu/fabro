//! The core "build a one-file `RunManifest` from DOT source and validate
//! it" logic `POST /graph/render-url` needs, run only inside the bounded
//! `fabro __validate-workflow` subprocess (see `validation_runner`): the
//! admission and registry passes [`validate_workflow_source`] reaches copy
//! node/edge defaults onto every node and cost roughly the square of the
//! node count (measured 2026-10-25: 1,709 nodes took 1.5 GB). AC29: the
//! axum handler (`server::handler::graph_url`) never calls this directly
//! on request input, only through `validation_runner`'s bounded subprocess.

use std::collections::HashMap;

use fabro_api::types;
use fabro_config::RunLayer;
use fabro_dot::limits;
use serde::{Deserialize, Serialize};

use crate::{manifest_validation, petri_check, run_manifest};

/// The single entrypoint key every render-url manifest uses: there is
/// exactly one file, so no real workflow path is meaningful.
const ENTRYPOINT: &str = "workflow.fabro";

/// The one JSON object the `fabro __validate-workflow` subprocess writes to
/// stdout (AC24).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidateWorkflowResult {
    /// Parsed within every graph limit and validated. `diagnostics` is the
    /// full, unpartitioned list; `handler::graph_url` splits it into
    /// notices/errors/warnings.
    Ok {
        diagnostics: Vec<types::WorkflowDiagnostic>,
    },
    /// AC20: a measured dimension (nodes, edges, statements,
    /// attribute_text, or nesting_depth) exceeded its limit. Never reaches
    /// the expensive validation pass. `limit` names which dimension;
    /// `count` is the value measured when the check stopped (at least
    /// `max + 1`, but the walk stops at the first dimension it finds
    /// over its limit, not necessarily this one's true final total — see
    /// `fabro_dot::limits`); `max` is the allowed maximum.
    GraphTooLarge {
        message: String,
        limit:   String,
        count:   u64,
        max:     u64,
    },
    /// The file is not a parsable Graphviz DOT / UTF-8 workflow.
    NotParsable { message: String },
}

/// Check graph limits (AC19-20, AC23), then — only if the graph is within
/// every limit — build a one-file [`types::RunManifest`] from `source` and
/// validate it under render-url's offline semantics (no model catalog, an
/// unbound input is a warning). Never partitions notices from errors: the
/// caller does that.
///
/// CPU- and memory-bound by the parsed graph's size up to the checked
/// limits; see the module doc for why callers outside the bounded
/// subprocess must not run this on untrusted input directly.
#[must_use]
pub fn validate_workflow_source(source: &str) -> ValidateWorkflowResult {
    if let Err(violation) = limits::check_graph_limits(source) {
        return ValidateWorkflowResult::GraphTooLarge {
            message: format!(
                "the workflow has more than {} {}",
                violation.limit,
                violation.kind.as_str()
            ),
            limit:   violation.kind.as_str().to_string(),
            count:   violation.count,
            max:     violation.limit,
        };
    }

    let manifest_run_defaults = RunLayer::default();
    let manifest = types::RunManifest {
        version:   1,
        parent_id: None,
        title:     None,
        cwd:       "/".to_string(),
        git:       None,
        goal:      None,
        args:      None,
        target:    types::ManifestTarget {
            path: ENTRYPOINT.to_string(),
        },
        configs:   Vec::new(),
        workflows: HashMap::from([(ENTRYPOINT.to_string(), types::ManifestWorkflow {
            source: source.to_string(),
            config: None,
            files:  HashMap::new(),
        })]),
    };

    let Ok(prepared) = run_manifest::prepare_manifest_with_environment_defaults(
        &manifest_run_defaults,
        &fabro_environment::seeded_catalog_layer(),
        &HashMap::new(),
        &manifest,
    ) else {
        return ValidateWorkflowResult::NotParsable {
            message: "the workflow could not be parsed".to_string(),
        };
    };

    let Ok(check) = run_manifest::validate_prepared_manifest(
        &prepared,
        &HashMap::new(),
        petri_check::launch_without_catalog(&prepared.settings),
        manifest_validation::offline_runtime(Some(&manifest_run_defaults)),
        true,
        true,
    ) else {
        return ValidateWorkflowResult::NotParsable {
            message: "the workflow could not be parsed".to_string(),
        };
    };

    let validated = run_manifest::validate_response(&prepared, &check);
    ValidateWorkflowResult::Ok {
        diagnostics: validated.workflow.diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn validate_workflow_source_reports_graph_too_large_before_validating() {
        let mut source = String::from("digraph G {\n");
        for i in 0..=limits::MAX_NODES {
            let _ = writeln!(source, "n{i}");
        }
        source.push('}');

        match validate_workflow_source(&source) {
            ValidateWorkflowResult::GraphTooLarge {
                limit, count, max, ..
            } => {
                assert_eq!(limit, "nodes");
                assert_eq!(count, limits::MAX_NODES + 1);
                assert_eq!(max, limits::MAX_NODES);
            }
            other => panic!("expected GraphTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validate_workflow_source_accepts_a_small_valid_workflow() {
        const DOT: &str = r#"digraph Test {
            graph [goal="Test"]
            start [shape=Mdiamond]
            exit  [shape=Msquare]
            start -> exit
        }"#;
        match validate_workflow_source(DOT) {
            ValidateWorkflowResult::Ok { diagnostics } => {
                assert!(
                    diagnostics
                        .iter()
                        .all(|d| d.severity != types::WorkflowDiagnosticSeverity::Error),
                    "{diagnostics:?}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn validate_workflow_result_round_trips_through_json() {
        // 501/500: the real shape this takes in production (one over
        // `fabro_dot::limits::MAX_NODES`), not an arbitrary round number.
        let result = ValidateWorkflowResult::GraphTooLarge {
            message: "too big".to_string(),
            limit:   "nodes".to_string(),
            count:   501,
            max:     500,
        };
        let json = serde_json::to_string(&result).expect("should serialize");
        let decoded: ValidateWorkflowResult =
            serde_json::from_str(&json).expect("should deserialize");
        match decoded {
            ValidateWorkflowResult::GraphTooLarge {
                message,
                limit,
                count,
                max,
            } => {
                assert_eq!(message, "too big");
                assert_eq!(limit, "nodes");
                assert_eq!(count, 501);
                assert_eq!(max, 500);
            }
            other => panic!("expected GraphTooLarge, got {other:?}"),
        }
    }
}
