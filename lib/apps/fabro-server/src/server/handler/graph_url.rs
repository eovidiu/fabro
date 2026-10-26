//! `POST /api/v1/graph/render-url`: load a single raw `.fabro` workflow file
//! from an https URL and render its graph, without creating a run or
//! storing anything. See `crate::graph_url_fetch` for the SSRF-safe fetch
//! and `crate::manifest_validation` for the offline validation semantics
//! this reuses (no model catalog, an unbound input is a warning).

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fabro_api::types;
use fabro_config::RunLayer;
use fabro_dot::limits;
use fabro_graphviz::render::{
    detect_rankdir, postprocess_svg, prepare_untrusted_source_for_render,
};
use fabro_graphviz::sanitize::sanitize_svg;
use serde_json::{Map, Value};

use super::super::{
    ApiError, AppState, IntoResponse, Json, RequiredUser, Response, Router, State, StatusCode, post,
};
use super::graph::render_dot_subprocess_with_limits;
use super::pull_requests::server_github_context;
use crate::{graph_url_fetch, graph_validate, run_manifest, validation_runner};

/// The single entrypoint key every render-url manifest uses: there is
/// exactly one file, so no real workflow path is meaningful.
const ENTRYPOINT: &str = "workflow.fabro";

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/graph/render-url", post(render_graph_from_url))
}

async fn render_graph_from_url(
    _auth: RequiredUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<types::RenderWorkflowGraphFromUrlRequest>,
) -> Response {
    let policy = state.graph_url_fetch_policy();
    let credentials = credential_resolver(&state);

    let bytes = match graph_url_fetch::fetch_workflow(&req.url, &policy, &credentials).await {
        Ok(bytes) => bytes,
        Err(err) => return fetch_error_response(err),
    };
    let Ok(source) = String::from_utf8(bytes) else {
        return not_parsable_response("the workflow file is not valid UTF-8");
    };

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
            source,
            config: None,
            files: HashMap::new(),
        })]),
    };

    let Ok(prepared) = run_manifest::prepare_manifest_with_environment_defaults(
        &manifest_run_defaults,
        &fabro_environment::seeded_catalog_layer(),
        &HashMap::new(),
        &manifest,
    ) else {
        return not_parsable_response("the workflow could not be parsed");
    };

    // Security/AC23 fix: the nesting scan is O(depth) over raw text with
    // no parse step, so it runs here — before any validation slot is
    // taken or subprocess spawned — rather than only inside the bounded
    // `fabro __validate-workflow` child. A graph over the nesting limit
    // is refused immediately, with no slot held and no subprocess
    // started; everything else still goes through the subprocess, which
    // re-checks it along with every other graph limit.
    if let Err(violation) = limits::scan_nesting_depth(&prepared.root_source) {
        return graph_too_large_response(
            format!(
                "the workflow has more than {} {}",
                violation.limit,
                violation.kind.as_str()
            ),
            violation.kind.as_str().to_string(),
            violation.count,
            violation.limit,
        );
    }

    // AC29: the handler never runs the admission/registry validation
    // passes itself (they copy node/edge defaults onto every node and cost
    // roughly the square of the node count, measured 2026-10-25); it only
    // reaches them through the bounded `fabro __validate-workflow`
    // subprocess, which checks graph limits (AC19-20, AC23) first.
    let (validation_exe, validation_permit_wait, validation_kill_after) =
        state.graph_url_validation_limits();
    let validation = match validation_runner::validate_dot_source(
        &prepared.root_source,
        validation_exe.as_deref(),
        validation_permit_wait,
        validation_kill_after,
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            // Risk-low fix: the subprocess's stdout/stderr can carry a lot
            // of detail (up to the 16 MiB/64 KiB caps); log it server-side
            // and send the client a short, fixed message rather than the
            // raw child output.
            tracing::warn!(error = %err, "render-url validation subprocess failed");
            return render_failed_response(
                "the workflow could not be checked right now; try again",
            );
        }
    };

    let diagnostics = match validation {
        graph_validate::ValidateWorkflowResult::Ok { diagnostics } => diagnostics,
        graph_validate::ValidateWorkflowResult::GraphTooLarge {
            message,
            limit,
            count,
            max,
        } => return graph_too_large_response(message, limit, count, max),
        graph_validate::ValidateWorkflowResult::NotParsable { message } => {
            return not_parsable_response(message);
        }
    };

    let (notices, errors, warnings) = partition_diagnostics(diagnostics);
    if errors.iter().any(|error| error.rule.starts_with("dot.")) {
        return not_parsable_response("the workflow is not a parsable Graphviz DOT file");
    }
    if !errors.is_empty() {
        return validation_failed_response(&errors);
    }

    let direction = req.direction.as_ref().map(|direction| match direction {
        types::RenderWorkflowGraphDirection::Lr => "LR",
        types::RenderWorkflowGraphDirection::Tb => "TB",
    });
    // Security fix, source side: neutralize Graphviz's raw-text
    // attributes (`fontname`/`labelfontname`/`stylesheet`) before
    // rendering, in the same parse that applies `direction` — see
    // `fabro_graphviz::render::prepare_untrusted_source_for_render`.
    // This is the untrusted-URL path, unlike `run_manifest::graph_source`
    // (used by the already-trusted manifest-render and run-page graph
    // paths), so it alone needs this.
    let dot_source =
        prepare_untrusted_source_for_render(&prepared.root_source, direction).into_owned();

    // Shared contract: report the graph's effective layout direction —
    // the request's own `direction` when it sent one; otherwise the
    // source's own `rankdir` (detected via
    // `fabro_graphviz::render::detect_rankdir`, which works from the
    // parsed graph rather than a raw-text regex and only ever reports
    // an exact, case-sensitive `LR`/`TB`/`BT`/`RL` — matching what
    // Graphviz itself draws) when it is `LR`/`TB`; `tb` when the
    // source has no root-scope `rankdir` at all, or one Graphviz would
    // not recognize (e.g. wrong case) and so draws as its own `TB`
    // default; omitted when the source's `rankdir` is something this
    // field cannot represent (`BT`/`RL`).
    let response_direction = match req.direction {
        Some(direction) => Some(direction),
        None => match detect_rankdir(&prepared.root_source) {
            Some("LR") => Some(types::RenderWorkflowGraphDirection::Lr),
            Some("TB") | None => Some(types::RenderWorkflowGraphDirection::Tb),
            Some(_) => None,
        },
    };

    let (permit_wait, kill_after) = state.graph_url_render_limits();
    let render_exe = state.graph_url_render_exe();
    let raw_svg = match render_dot_subprocess_with_limits(
        &dot_source,
        render_exe.as_deref(),
        Some(permit_wait),
        Some(kill_after),
    )
    .await
    {
        Ok(raw) => raw,
        Err(err) => {
            tracing::warn!(error = %err, "render-url Graphviz render subprocess failed");
            return render_failed_response("the workflow could not be drawn right now; try again");
        }
    };
    // MAJOR fix: sanitize the raw Graphviz output first, then
    // postprocess — so Fabro's own `DARK_MODE_STYLE` `<style>` block is
    // added *after* filtering, never passed through the untrusted-input
    // sanitizer itself (which no longer allows `<style>` elements at
    // all; see `fabro_graphviz::sanitize`). Doing it in the other
    // order, as before, would have stripped Fabro's own dark-mode block
    // right back out.
    let Ok(sanitized) = sanitize_svg(&raw_svg) else {
        return render_failed_response("rendered SVG could not be safely sanitized");
    };
    let svg_bytes = postprocess_svg(sanitized);
    // Security MINOR fix: `from_utf8_lossy` would silently replace
    // invalid bytes with U+FFFD rather than fail closed, like every
    // other `sanitize_svg`/parse failure on this path must.
    let Ok(svg) = String::from_utf8(svg_bytes) else {
        return render_failed_response("rendered SVG could not be safely sanitized");
    };

    (
        StatusCode::OK,
        Json(types::RenderWorkflowGraphFromUrlResponse {
            svg,
            notices,
            warnings,
            direction: response_direction,
        }),
    )
        .into_response()
}

/// Splits validated diagnostics into `(notices, errors, warnings)`: a
/// diagnostic about a reference the single-file render never fetched
/// (`@file` prompts or schemas, imports, child workflows) is a notice
/// regardless of severity; every remaining `Error` diagnostic blocks
/// rendering; everything else is a non-blocking warning.
fn partition_diagnostics(
    diagnostics: Vec<types::WorkflowDiagnostic>,
) -> (
    Vec<types::WorkflowDiagnostic>,
    Vec<types::WorkflowDiagnostic>,
    Vec<types::WorkflowDiagnostic>,
) {
    let mut notices = Vec::new();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for diagnostic in diagnostics {
        if is_unresolved_reference_notice(&diagnostic) {
            notices.push(diagnostic);
        } else if diagnostic.severity == types::WorkflowDiagnosticSeverity::Error {
            errors.push(diagnostic);
        } else {
            warnings.push(diagnostic);
        }
    }
    (notices, errors, warnings)
}

/// An error diagnostic counts as a notice about an unresolved reference
/// (not a validation error) only for the specific rules a single-file
/// render is expected to trip: a missing `@file` prompt/schema or child
/// workflow file, or an import whose target was not loaded.
fn is_unresolved_reference_notice(diagnostic: &types::WorkflowDiagnostic) -> bool {
    match diagnostic.rule.as_str() {
        "attractor.file_not_found" | "attractor.child_workflow_not_found" => true,
        "attractor.import" => diagnostic.message.contains("file not found"),
        _ => false,
    }
}

/// The test-only credential stub when `AppState` carries one, else the
/// production resolver.
#[expect(
    clippy::disallowed_types,
    reason = "The render-url credential resolver matches hosts on the raw reqwest::Url it is called with; no URL is logged here."
)]
fn credential_resolver(state: &Arc<AppState>) -> graph_url_fetch::CredentialResolver {
    if let Some((host, header_value)) = state.graph_url_credential_stub() {
        return Arc::new(move |url: fabro_http::Url| {
            let host = host.clone();
            let header_value = header_value.clone();
            Box::pin(async move {
                if url.host_str() == Some(host.as_str()) {
                    Some(header_value)
                } else {
                    None
                }
            })
        });
    }
    production_credential_resolver(Arc::clone(state))
}

/// An `Authorization` header for `raw.githubusercontent.com` URLs when the
/// server has GitHub read credentials for the URL's `owner/repo`; `None`
/// for every other host, or when the server has no GitHub credentials
/// configured.
#[expect(
    clippy::disallowed_types,
    reason = "The render-url credential resolver matches hosts on the raw reqwest::Url it is called with; no URL is logged here."
)]
fn production_credential_resolver(state: Arc<AppState>) -> graph_url_fetch::CredentialResolver {
    Arc::new(move |url: fabro_http::Url| {
        let state = Arc::clone(&state);
        Box::pin(async move {
            let (owner, repo) = graph_url_fetch::raw_github_owner_repo(&url)?;
            let settings = state.server_settings();
            let credentials = state
                .github_credentials(&settings.server.integrations.github)
                .await
                .ok()
                .flatten()?;
            let context = server_github_context(&state, &credentials).ok()?;
            let clone_credentials =
                fabro_github::resolve_read_only_clone_credentials(&context, &owner, &repo)
                    .await
                    .ok()?;
            let encoded = BASE64_STANDARD.encode(format!(
                "{}:{}",
                clone_credentials.username(),
                clone_credentials.password()
            ));
            fabro_http::HeaderValue::from_str(&format!("Basic {encoded}")).ok()
        })
    })
}

fn fetch_error_response(err: graph_url_fetch::FetchError) -> Response {
    use graph_url_fetch::FetchErrorKind;
    match err.kind {
        FetchErrorKind::InvalidUrl => {
            ApiError::with_code(StatusCode::BAD_REQUEST, err.detail, "invalid_url")
        }
        FetchErrorKind::SchemeNotHttps => {
            ApiError::with_code(StatusCode::BAD_REQUEST, err.detail, "scheme_not_https")
        }
        FetchErrorKind::HostNotAllowed => {
            ApiError::with_code(StatusCode::BAD_REQUEST, err.detail, "host_not_allowed")
        }
        FetchErrorKind::Unreachable => {
            ApiError::with_code(StatusCode::BAD_GATEWAY, err.detail, "unreachable")
        }
        FetchErrorKind::Timeout => {
            ApiError::with_code(StatusCode::GATEWAY_TIMEOUT, err.detail, "timeout")
        }
        FetchErrorKind::HttpStatus(status) => {
            let mut meta = Map::new();
            meta.insert("status".to_string(), Value::from(status));
            ApiError::with_code_and_meta(StatusCode::BAD_GATEWAY, err.detail, "http_status", meta)
        }
        FetchErrorKind::TooLarge => {
            ApiError::with_code(StatusCode::PAYLOAD_TOO_LARGE, err.detail, "too_large")
        }
    }
    .into_response()
}

fn not_parsable_response(detail: impl Into<String>) -> Response {
    ApiError::with_code(StatusCode::BAD_REQUEST, detail, "not_parsable").into_response()
}

/// AC20: a measured dimension (nodes, edges, statements, attribute_text,
/// or nesting_depth) exceeded its limit, reported with `meta.limit`
/// naming which dimension, `meta.count` the value measured when the
/// check stopped (at least `meta.max + 1`, not necessarily the graph's
/// true total for that dimension — the walk stops at the first
/// dimension it finds over its limit), and `meta.max` the allowed
/// maximum.
fn graph_too_large_response(message: String, limit: String, count: u64, max: u64) -> Response {
    let mut meta = Map::new();
    meta.insert("limit".to_string(), Value::from(limit));
    meta.insert("count".to_string(), Value::from(count));
    meta.insert("max".to_string(), Value::from(max));
    ApiError::with_code_and_meta(
        StatusCode::PAYLOAD_TOO_LARGE,
        message,
        "graph_too_large",
        meta,
    )
    .into_response()
}

fn validation_failed_response(errors: &[types::WorkflowDiagnostic]) -> Response {
    let mut meta = Map::new();
    meta.insert(
        "diagnostics".to_string(),
        serde_json::to_value(errors).unwrap_or(Value::Array(Vec::new())),
    );
    ApiError::with_code_and_meta(
        StatusCode::UNPROCESSABLE_ENTITY,
        "The workflow failed validation.",
        "validation_failed",
        meta,
    )
    .into_response()
}

fn render_failed_response(detail: impl Into<String>) -> Response {
    ApiError::with_code(StatusCode::SERVICE_UNAVAILABLE, detail, "render_failed").into_response()
}
