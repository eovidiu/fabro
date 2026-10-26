//! Runs `fabro __validate-workflow` (the hidden CLI subcommand in
//! `fabro-cli::commands::validate_workflow`, mirroring `__render-graph`) in
//! a bounded subprocess: at most 2 validations run at once (AC21), each
//! under one 10 s deadline covering spawn, the stdin write, and reading
//! stdout/stderr (AC25), with stdout capped at 16 MiB and stderr at 64 KiB.
//! On Linux, where the server runs, the child's virtual address space is
//! additionally capped at 1 GiB via `fabro_proc::pre_exec_rlimit_as`
//! (AC26); on other platforms (including this Mac) only the time limit
//! applies, since `RLIMIT_AS`/`ulimit -v` does not actually cap memory
//! there.
//!
//! `handler::graph_url` is the only caller: AC29 means the axum handler
//! itself never calls `graph_validate::validate_workflow_source` directly
//! on request input, only through this bounded subprocess.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use fabro_static::EnvVars;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::graph_validate::ValidateWorkflowResult;
use crate::spawn_env::apply_render_graph_env;

pub(crate) const VALIDATION_CONCURRENCY_LIMIT: usize = 2;
/// AC21: a request waits at most 5 s for a slot, then fails with
/// `render_failed` (503).
pub(crate) const VALIDATION_PERMIT_WAIT: Duration = Duration::from_secs(5);
/// AC25: one 10 s deadline for the whole subprocess lifetime.
pub(crate) const VALIDATION_KILL_TIMEOUT: Duration = Duration::from_secs(10);
/// AC26: 1 GiB, enforced on Linux only (`fabro_proc::pre_exec_rlimit_as` is
/// Linux-only, since `RLIMIT_AS`/`ulimit -v` does not actually cap process
/// memory on macOS).
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only read by pre_exec_rlimit_as, which is Linux-only"
    )
)]
pub(crate) const VALIDATION_MEMORY_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const VALIDATION_STDOUT_CAP: usize = 16 * 1024 * 1024;
const VALIDATION_STDERR_CAP: usize = 64 * 1024;
/// Risk-low fix: `ChildCrashed`/`ProtocolViolation` log the subprocess's
/// stdout/stderr verbatim (`handler::graph_url` only forwards a fixed
/// message to the client, but `tracing::warn!` still writes the full
/// `Display` to the server's own logs); cap each excerpt at a few KiB so
/// a crash or malformed-output child cannot flood the log with up to the
/// 16 MiB/64 KiB captured caps' worth of attacker-influenced bytes.
/// Shared with `handler::graph` (MINOR fix): the render path's own
/// `RenderFailed`/`ProtocolViolation`/`ChildCrashed` excerpts use the
/// same cap and marker, rather than a second copy of this logic.
const LOG_EXCERPT_CAP: usize = 4 * 1024;

/// The first `LOG_EXCERPT_CAP` bytes of `bytes`, lossily decoded and
/// trimmed, with a marker appended when it was actually truncated.
pub(crate) fn truncate_excerpt(bytes: &[u8]) -> String {
    let cap = bytes.len().min(LOG_EXCERPT_CAP);
    let excerpt = String::from_utf8_lossy(&bytes[..cap]).trim().to_string();
    if bytes.len() > cap {
        format!("{excerpt}... (truncated, {} bytes total)", bytes.len())
    } else {
        excerpt
    }
}

pub(crate) static VALIDATION_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(VALIDATION_CONCURRENCY_LIMIT));

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidationSubprocessError {
    #[error("validation permit wait timed out")]
    PermitTimeout,
    #[error("failed to spawn validation subprocess: {0}")]
    SpawnFailed(String),
    #[error("validation subprocess did not finish before the kill timeout")]
    Killed,
    #[error("validation subprocess crashed: {0}")]
    ChildCrashed(String),
    #[error("validation subprocess returned invalid output: {0}")]
    ProtocolViolation(String),
    #[error("validation subprocess output exceeded the size limit")]
    OutputTooLarge,
}

#[expect(
    clippy::disallowed_methods,
    reason = "Validation-subprocess startup resolves Cargo's test binary env override when present."
)]
fn validation_subprocess_exe(
    exe_override: Option<&Path>,
) -> Result<PathBuf, ValidationSubprocessError> {
    if let Some(path) = exe_override {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os(EnvVars::CARGO_BIN_EXE_FABRO).map(PathBuf::from) {
        return Ok(path);
    }
    let current = std::env::current_exe()
        .map_err(|err| ValidationSubprocessError::SpawnFailed(err.to_string()))?;
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

/// Validate `source` (raw DOT text) in the bounded subprocess, waiting at
/// most `permit_wait` for one of the [`VALIDATION_SEMAPHORE`]'s slots and
/// killing the child after `kill_after`.
pub(crate) async fn validate_dot_source(
    source: &str,
    exe_override: Option<&Path>,
    permit_wait: Duration,
    kill_after: Duration,
) -> Result<ValidateWorkflowResult, ValidationSubprocessError> {
    validate_dot_source_with_caps(
        source,
        exe_override,
        permit_wait,
        kill_after,
        VALIDATION_STDOUT_CAP,
        VALIDATION_STDERR_CAP,
    )
    .await
}

/// Like [`validate_dot_source`], but with the stdout/stderr caps
/// overridable — the production caller always uses the constants above;
/// tests use this to exercise the cap being hit without a multi-MiB
/// fixture.
pub(crate) async fn validate_dot_source_with_caps(
    source: &str,
    exe_override: Option<&Path>,
    permit_wait: Duration,
    kill_after: Duration,
    stdout_cap: usize,
    stderr_cap: usize,
) -> Result<ValidateWorkflowResult, ValidationSubprocessError> {
    let _permit = match timeout(permit_wait, VALIDATION_SEMAPHORE.acquire()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(err)) => return Err(ValidationSubprocessError::SpawnFailed(err.to_string())),
        Err(_) => return Err(ValidationSubprocessError::PermitTimeout),
    };

    let exe = validation_subprocess_exe(exe_override)?;
    let mut cmd = Command::new(exe);
    apply_render_graph_env(&mut cmd);
    cmd.arg("__validate-workflow")
        .env(EnvVars::FABRO_TELEMETRY, "off");
    #[cfg(target_os = "linux")]
    fabro_proc::pre_exec_rlimit_as(cmd.as_std_mut(), VALIDATION_MEMORY_LIMIT_BYTES);

    let cancel = CancellationToken::new();
    let captured = fabro_proc::capture_with_stdin(
        &mut cmd,
        source.as_bytes(),
        Some(kill_after),
        &cancel,
        Some(stdout_cap),
        Some(stderr_cap),
    )
    .await;

    let captured = match captured {
        Ok(captured) => captured,
        Err(fabro_proc::ProcessError::TimedOut) => return Err(ValidationSubprocessError::Killed),
        Err(fabro_proc::ProcessError::Cancelled) => {
            return Err(ValidationSubprocessError::Killed);
        }
        Err(fabro_proc::ProcessError::Io(err)) => {
            return Err(ValidationSubprocessError::SpawnFailed(err.to_string()));
        }
        // Unreachable: this caller uses plain `capture_with_stdin`, never
        // `capture_with_stdin_opts`'s `kill_on_stdout_cap`, which is the
        // only path that ever constructs this variant.
        Err(fabro_proc::ProcessError::OutputTooLarge) => {
            return Err(ValidationSubprocessError::OutputTooLarge);
        }
    };

    // Security MINOR: check this before looking at the exit status or
    // trying to parse stdout as JSON — a truncated stdout is never valid
    // JSON, so skipping straight to a fixed `OutputTooLarge` avoids
    // logging (via `ProtocolViolation`, in `handler::graph_url`'s
    // `tracing::warn!`) a multi-KiB garbled excerpt of what is just the
    // cap being hit.
    if captured.stdout_truncated {
        return Err(ValidationSubprocessError::OutputTooLarge);
    }

    if !captured.output.status.success() {
        let stderr = truncate_excerpt(&captured.output.stderr);
        return Err(ValidationSubprocessError::ChildCrashed(stderr));
    }

    serde_json::from_slice::<ValidateWorkflowResult>(&captured.output.stdout).map_err(|err| {
        ValidationSubprocessError::ProtocolViolation(format!(
            "{err} (stdout: {:?}, stderr: {:?})",
            truncate_excerpt(&captured.output.stdout),
            truncate_excerpt(&captured.output.stderr),
        ))
    })
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "test fixtures stage a fake fabro executable with sync std::fs writes"
)]
mod tests;
