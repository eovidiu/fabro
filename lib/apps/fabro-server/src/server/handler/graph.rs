use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::super::{
    ApiError, AppState, AsyncWriteExt, Command, EnvVars, IntoResponse, Json, LazyLock, Path,
    PathBuf, Query, RenderWorkflowGraphDirection, RenderWorkflowGraphRequest, RequiredUser,
    Response, Router, RunId, Semaphore, State, StatusCode, Stdio, apply_render_graph_env, get,
    parse_run_id_path, post, run_manifest,
};
use crate::validation_runner::truncate_excerpt;

pub(super) fn manifest_routes() -> Router<Arc<AppState>> {
    Router::new().route("/graph/render", post(render_graph_from_manifest))
}

pub(super) fn run_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/runs/{id}/graph", get(get_graph))
        .route("/runs/{id}/graph/source", get(get_graph_source))
}

const RENDER_ERROR_PREFIX: &[u8] = b"RENDER_ERROR:";
const GRAPHVIZ_RENDER_CONCURRENCY_LIMIT: usize = 4;
/// Security fix: the render-url child's stdout is capped so a tiny DOT
/// file amplified by a Graphviz attribute (e.g. `peripheries`) cannot grow
/// the server's memory past this many bytes; hitting the cap stops
/// draining immediately and kills the child (via
/// `fabro_proc::capture_with_stdin_opts`'s `kill_on_stdout_cap`) rather
/// than buffering more or waiting out the kill timeout, so the shared
/// [`GRAPHVIZ_RENDER_SEMAPHORE`] permit is released promptly; the request
/// then fails with `render_failed` (503). Only applied to render-url
/// (identified by `kill_after` being set); the manifest-render and
/// run-page graph paths, which render already-validated workflow sources
/// with no size amplification concern, stay unbounded.
pub(in crate::server) const RENDER_URL_MAX_SVG_BYTES: usize = 16 * 1024 * 1024;
/// The same 64 KiB stderr cap `validation_runner` uses for its own bounded
/// subprocess.
const RENDER_URL_MAX_STDERR_BYTES: usize = 64 * 1024;

pub(in crate::server) static GRAPHVIZ_RENDER_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(GRAPHVIZ_RENDER_CONCURRENCY_LIMIT));

#[derive(Debug, thiserror::Error)]
pub(in crate::server) enum RenderSubprocessError {
    #[error("failed to spawn render subprocess: {0}")]
    SpawnFailed(String),
    #[error("render subprocess crashed: {0}")]
    ChildCrashed(String),
    #[error("render subprocess returned invalid output: {0}")]
    ProtocolViolation(String),
    #[error("{0}")]
    RenderFailed(String),
    #[error("render permit wait timed out")]
    PermitTimeout,
    #[error("render subprocess did not finish before the kill timeout")]
    Killed,
    #[error("render subprocess output exceeded the size limit")]
    OutputTooLarge,
}

async fn render_graph_from_manifest(
    _auth: RequiredUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenderWorkflowGraphRequest>,
) -> Response {
    let manifest_run_defaults = state.manifest_run_defaults();
    let manifest_environment_defaults = state.environment_store().catalog_layer();
    let manifest_mcp_server_catalog = state.mcp_server_store().catalog_settings();
    let prepared = match run_manifest::prepare_manifest_with_environment_defaults(
        manifest_run_defaults.as_ref(),
        manifest_environment_defaults.as_ref(),
        &manifest_mcp_server_catalog,
        &req.manifest,
    ) {
        Ok(prepared) => prepared,
        Err(err) => return ApiError::bad_request(err.to_string()).into_response(),
    };
    let vars = match state.stores.variables.value_map().await {
        Ok(vars) => vars,
        Err(err) => {
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response();
        }
    };
    let (_, ready_providers) = state.resolve_llm_client_with_ready_ids().await;
    let check = match run_manifest::check_prepared_manifest(
        &state,
        &prepared,
        vars,
        &ready_providers,
    )
    .await
    {
        Ok(check) => check,
        Err(err) => return ApiError::bad_request(err.to_string()).into_response(),
    };
    if check.has_errors() {
        return ApiError::bad_request("Validation failed").into_response();
    }

    let direction = req.direction.as_ref().map(|direction| match direction {
        RenderWorkflowGraphDirection::Lr => "LR",
        RenderWorkflowGraphDirection::Tb => "TB",
    });
    let dot_source = run_manifest::graph_source(&prepared, direction);
    render_graph_bytes(&dot_source).await
}

#[expect(
    clippy::disallowed_methods,
    reason = "Render-graph subprocess startup resolves Cargo's test binary env override when present."
)]
fn render_graph_subprocess_exe(
    exe_override: Option<&std::path::Path>,
) -> Result<PathBuf, RenderSubprocessError> {
    if let Some(path) = exe_override {
        Ok(path.to_path_buf())
    } else {
        if let Some(path) = std::env::var_os(EnvVars::CARGO_BIN_EXE_FABRO).map(PathBuf::from) {
            return Ok(path);
        }

        let current = std::env::current_exe()
            .map_err(|err| RenderSubprocessError::SpawnFailed(err.to_string()))?;
        let current_name = current.file_stem().and_then(|name| name.to_str());
        if current_name == Some("fabro") {
            return Ok(current);
        }

        let candidate = current
            .parent()
            .and_then(|parent| parent.parent())
            .map(|parent| parent.join(if cfg!(windows) { "fabro.exe" } else { "fabro" }));
        if let Some(candidate) = candidate.filter(|path| path.is_file()) {
            return Ok(candidate);
        }

        Ok(current)
    }
}

/// MINOR fix: `ChildCrashed` (like `validation_runner`'s own
/// `ChildCrashed`/`ProtocolViolation`) caps the stderr excerpt it embeds
/// at `truncate_excerpt`'s 4 KiB rather than logging the subprocess's
/// full output verbatim.
fn render_subprocess_failure(
    status: std::process::ExitStatus,
    stderr: &[u8],
) -> RenderSubprocessError {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            let stderr = truncate_excerpt(stderr);
            let detail = if stderr.is_empty() {
                format!("terminated by signal {signal}")
            } else {
                format!("terminated by signal {signal}: {stderr}")
            };
            return RenderSubprocessError::ChildCrashed(detail);
        }
    }

    let stderr = truncate_excerpt(stderr);
    let detail = match status.code() {
        Some(code) if stderr.is_empty() => format!("exited with status {code}"),
        Some(code) => format!("exited with status {code}: {stderr}"),
        None if stderr.is_empty() => "child exited unsuccessfully".to_string(),
        None => format!("child exited unsuccessfully: {stderr}"),
    };
    RenderSubprocessError::ChildCrashed(detail)
}

pub(in crate::server) async fn render_dot_subprocess(
    dot_source: &str,
    exe_override: Option<&std::path::Path>,
) -> Result<Vec<u8>, RenderSubprocessError> {
    render_dot_subprocess_with_limits(dot_source, exe_override, None, None).await
}

/// Like [`render_dot_subprocess`], but bounds how long to wait for a render
/// permit (`permit_wait`, else `503 render_failed`) and how long the
/// subprocess may run before it is killed (`kill_after`, via
/// `kill_on_drop`). `None` preserves the unbounded waits the manifest-render
/// path uses.
pub(in crate::server) async fn render_dot_subprocess_with_limits(
    dot_source: &str,
    exe_override: Option<&std::path::Path>,
    permit_wait: Option<Duration>,
    kill_after: Option<Duration>,
) -> Result<Vec<u8>, RenderSubprocessError> {
    let _permit = match permit_wait {
        Some(wait) => match timeout(wait, GRAPHVIZ_RENDER_SEMAPHORE.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(err)) => return Err(RenderSubprocessError::SpawnFailed(err.to_string())),
            Err(_) => return Err(RenderSubprocessError::PermitTimeout),
        },
        None => GRAPHVIZ_RENDER_SEMAPHORE
            .acquire()
            .await
            .map_err(|err| RenderSubprocessError::SpawnFailed(err.to_string()))?,
    };
    let exe = render_graph_subprocess_exe(exe_override)?;
    let mut cmd = Command::new(exe);
    apply_render_graph_env(&mut cmd);
    cmd.arg("__render-graph")
        .env(EnvVars::FABRO_TELEMETRY, "off");
    // Risk-low fix: on Linux, where the server runs, cap the render
    // subprocess's address space at 1 GiB too — only for render-url (the
    // untrusted-input path), identified here by `kill_after` being set
    // (the manifest-render path passes `None` and keeps today's
    // unbounded behavior). macOS's RLIMIT_AS does not actually cap
    // process memory, so this is a no-op there by construction.
    #[cfg(target_os = "linux")]
    if kill_after.is_some() {
        fabro_proc::pre_exec_rlimit_as(cmd.as_std_mut(), 1024 * 1024 * 1024);
    }

    let output = if let Some(limit) = kill_after {
        // Security fix: render-url is the untrusted-input path, where
        // a Graphviz attribute like `peripheries` can amplify a tiny
        // DOT file into a multi-hundred-MB SVG. Cap stdout/stderr and
        // kill the child the moment the deadline passes, through the
        // same bounded-capture primitive `validation_runner` uses for
        // its own subprocess, so the server never buffers more than
        // the caps allow; a truncated stdout fails the request
        // outright rather than returning a partial SVG.
        let cancel = CancellationToken::new();
        match fabro_proc::capture_with_stdin_opts(
            &mut cmd,
            dot_source.as_bytes(),
            Some(limit),
            &cancel,
            Some(RENDER_URL_MAX_SVG_BYTES),
            Some(RENDER_URL_MAX_STDERR_BYTES),
            true,
        )
        .await
        {
            Ok(captured) if captured.stdout_truncated => {
                return Err(RenderSubprocessError::OutputTooLarge);
            }
            Ok(captured) => captured.output,
            Err(fabro_proc::ProcessError::OutputTooLarge) => {
                return Err(RenderSubprocessError::OutputTooLarge);
            }
            Err(fabro_proc::ProcessError::TimedOut | fabro_proc::ProcessError::Cancelled) => {
                return Err(RenderSubprocessError::Killed);
            }
            Err(fabro_proc::ProcessError::Io(err)) => {
                return Err(RenderSubprocessError::SpawnFailed(err.to_string()));
            }
        }
    } else {
        cmd.kill_on_drop(false)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|err| RenderSubprocessError::SpawnFailed(err.to_string()))?;

        // Round-1 risk finding: the stdin write must share the same
        // deadline as the rest of the child's lifetime. The
        // manifest-render and run-page graph paths render trusted,
        // already-validated sources with no deadline; this just keeps
        // the write and wait together.
        let dot_bytes = dot_source.as_bytes();
        let mut stdin = child.stdin.take().ok_or_else(|| {
            RenderSubprocessError::SpawnFailed("render subprocess stdin was not piped".to_string())
        })?;
        if let Err(err) = stdin.write_all(dot_bytes).await {
            drop(stdin);
            let output = child
                .wait_with_output()
                .await
                .map_err(|wait_err| RenderSubprocessError::SpawnFailed(wait_err.to_string()))?;
            return Err(RenderSubprocessError::ChildCrashed(format!(
                "failed writing DOT to child stdin: {err}; {}",
                render_subprocess_failure(output.status, &output.stderr)
            )));
        }
        drop(stdin);
        child
            .wait_with_output()
            .await
            .map_err(|err| RenderSubprocessError::SpawnFailed(err.to_string()))?
    };

    if !output.status.success() {
        return Err(render_subprocess_failure(output.status, &output.stderr));
    }

    if let Some(error) = output.stdout.strip_prefix(RENDER_ERROR_PREFIX) {
        return Err(RenderSubprocessError::RenderFailed(truncate_excerpt(error)));
    }

    if output.stdout.starts_with(b"<?xml") || output.stdout.starts_with(b"<svg") {
        return Ok(output.stdout);
    }

    Err(RenderSubprocessError::ProtocolViolation(format!(
        "stdout did not contain SVG or error protocol (stdout: {:?}, stderr: {:?})",
        truncate_excerpt(&output.stdout),
        truncate_excerpt(&output.stderr)
    )))
}

async fn render_graph_response(
    dot_source: &str,
    exe_override: Option<&std::path::Path>,
) -> Response {
    use fabro_graphviz::render::postprocess_svg;

    match render_dot_subprocess(dot_source, exe_override).await {
        Ok(raw) => {
            let bytes = postprocess_svg(raw);
            (StatusCode::OK, [("content-type", "image/svg+xml")], bytes).into_response()
        }
        Err(RenderSubprocessError::RenderFailed(err)) => {
            ApiError::new(StatusCode::BAD_REQUEST, err).into_response()
        }
        Err(err) => {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

pub(crate) async fn render_graph_bytes(dot_source: &str) -> Response {
    render_graph_response(dot_source, None).await
}

#[cfg(test)]
pub(in crate::server) async fn render_graph_bytes_with_exe_override(
    dot_source: &str,
    exe_override: Option<&std::path::Path>,
) -> Response {
    render_graph_response(dot_source, exe_override).await
}

#[derive(serde::Deserialize)]
struct GraphParams {
    #[serde(default)]
    direction: Option<String>,
}

async fn load_run_dot_source(state: &AppState, id: &RunId) -> Result<String, Response> {
    let live_dot_source = {
        let runs = state.runs.lock().expect("runs lock poisoned");
        runs.get(id)
            .map(|managed_run| managed_run.dot_source.clone())
    };

    let dot_source = if let Some(dot) = live_dot_source.filter(|d| !d.is_empty()) {
        Some(dot)
    } else {
        state
            .load_run_projection(id)
            .await
            .map_err(IntoResponse::into_response)?
            .spec
            .graph_source
            .clone()
    };

    dot_source
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Graph not found.").into_response())
}

async fn get_graph(
    _auth: RequiredUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<GraphParams>,
) -> Response {
    let id = match parse_run_id_path(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };

    let dot = match load_run_dot_source(&state, &id).await {
        Ok(dot) => dot,
        Err(response) => return response,
    };

    let dot = match params.direction.as_deref() {
        Some(dir @ ("LR" | "TB" | "BT" | "RL")) => {
            use fabro_graphviz::render;
            render::apply_direction(&dot, dir).into_owned()
        }
        _ => dot,
    };

    render_graph_bytes(&dot).await
}

async fn get_graph_source(
    _auth: RequiredUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let id = match parse_run_id_path(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };

    match load_run_dot_source(&state, &id).await {
        Ok(dot) => (StatusCode::OK, [("content-type", "text/vnd.graphviz")], dot).into_response(),
        Err(response) => response,
    }
}
