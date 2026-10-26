use std::path::PathBuf;

use super::*;

#[cfg(unix)]
fn write_test_executable(script: &str) -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("temp dir should exist");
    let path = dir.path().join("fake-fabro");
    std::fs::write(&path, script).expect("script should be written");
    let mut perms = std::fs::metadata(&path)
        .expect("script metadata should read")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("script should be made executable");
    (dir, path)
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_returns_ok_for_a_valid_json_object() {
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"status\":\"ok\",\"diagnostics\":[]}'\nexit 0\n",
    );

    let result = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect("should succeed");

    match result {
        ValidateWorkflowResult::Ok { diagnostics } => assert!(diagnostics.is_empty()),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(
        VALIDATION_SEMAPHORE.available_permits(),
        VALIDATION_CONCURRENCY_LIMIT
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_reports_child_crashed_for_nonzero_exit() {
    let (_dir, script_path) = write_test_executable("#!/bin/sh\ncat >/dev/null\nexit 1\n");

    let err = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect_err("should fail");

    assert!(matches!(err, ValidationSubprocessError::ChildCrashed(_)));
    assert_eq!(
        VALIDATION_SEMAPHORE.available_permits(),
        VALIDATION_CONCURRENCY_LIMIT
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_reports_protocol_violation_for_invalid_json() {
    let (_dir, script_path) =
        write_test_executable("#!/bin/sh\ncat >/dev/null\nprintf 'not json'\nexit 0\n");

    let err = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect_err("should fail");

    assert!(matches!(
        err,
        ValidationSubprocessError::ProtocolViolation(_)
    ));
    assert_eq!(
        VALIDATION_SEMAPHORE.available_permits(),
        VALIDATION_CONCURRENCY_LIMIT
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_kills_a_child_that_outlives_the_deadline() {
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nsleep 5\nprintf '{\"status\":\"ok\",\"diagnostics\":[]}'\n",
    );

    let started = std::time::Instant::now();
    let err = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        std::time::Duration::from_millis(200),
    )
    .await
    .expect_err("should time out");

    assert!(matches!(err, ValidationSubprocessError::Killed));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        VALIDATION_SEMAPHORE.available_permits(),
        VALIDATION_CONCURRENCY_LIMIT,
        "the permit must be returned once the child is killed and reaped"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_kills_a_child_that_never_reads_a_large_stdin_within_the_deadline() {
    // Never reads stdin: the write blocks once the pipe buffer fills,
    // proving the stdin write shares the same deadline as the rest of the
    // child's lifetime (round-1 risk finding fixed for the render
    // subprocess; the validation subprocess was built this way from the
    // start).
    let (_dir, script_path) = write_test_executable("#!/bin/sh\nsleep 5\n");
    let large_input = format!("digraph {{ {} }}", "a ".repeat(60_000));
    assert!(large_input.len() > 100_000);

    let started = std::time::Instant::now();
    let err = validate_dot_source(
        &large_input,
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        std::time::Duration::from_millis(200),
    )
    .await
    .expect_err("should time out");

    assert!(matches!(err, ValidationSubprocessError::Killed));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "took {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_reports_child_crashed_for_sigabrt() {
    let (_dir, script_path) = write_test_executable("#!/bin/sh\ncat >/dev/null\nkill -s ABRT $$\n");

    let err = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect_err("should fail");

    assert!(matches!(err, ValidationSubprocessError::ChildCrashed(_)));
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_stops_reading_near_the_stdout_cap() {
    // Security MINOR: 5,000 bytes of non-JSON output against a 1 KiB
    // cap. Past round 3's fix, hitting the cap is checked before any
    // attempt to parse stdout as JSON, so this fails as a fixed
    // `OutputTooLarge`, not a `ProtocolViolation` carrying an excerpt of
    // whatever garbage happened to fill the capped buffer.
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nyes x | tr -d '\\n' | head -c 5000\nprintf 'ZZZEND-MARKER-NEVER-REACHED'\n",
    );

    let err = validate_dot_source_with_caps(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
        1024,
        1024,
    )
    .await
    .expect_err("output over the cap should be refused");

    let message = err.to_string();
    assert!(matches!(err, ValidationSubprocessError::OutputTooLarge));
    assert!(
        !message.contains("ZZZEND-MARKER-NEVER-REACHED"),
        "the capped read should never reach the tail of a 5,000-byte stream: {message}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn validation_runner_reports_protocol_violation_for_an_unknown_status() {
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"status\":\"not_a_real_status\"}'\n",
    );

    let err = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect_err("an unrecognized status should fail to parse");

    assert!(matches!(
        err,
        ValidationSubprocessError::ProtocolViolation(_)
    ));
}

#[cfg(unix)]
#[tokio::test]
#[expect(
    unsafe_code,
    reason = "test sets a process env var in its own (nextest-isolated) process to verify it \
              is not inherited by the allowlisted subprocess"
)]
async fn validation_runner_only_passes_the_render_graph_env_allowlist() {
    // The script echoes back an env var the test sets in its own process;
    // it must not reach the child (env_clear + allowlist, shared with the
    // render subprocess; see spawn_env::RENDER_GRAPH_ENV_ALLOWLIST and its
    // own exhaustive test).
    // SAFETY: nextest runs each test in its own process.
    unsafe {
        std::env::set_var("FABRO_TEST_VALIDATION_RUNNER_SECRET", "leak-me");
    }
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"status\":\"not_parsable\",\"message\":\"%s\"}' \"$FABRO_TEST_VALIDATION_RUNNER_SECRET\"\n",
    );

    let result = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect("should succeed");
    // SAFETY: nextest runs each test in its own process.
    unsafe {
        std::env::remove_var("FABRO_TEST_VALIDATION_RUNNER_SECRET");
    }

    match result {
        ValidateWorkflowResult::NotParsable { message } => {
            assert_eq!(message, "", "a disallowed env var reached the child");
        }
        other => panic!("expected NotParsable, got {other:?}"),
    }
}

/// AC26: on Linux, where the server runs, the validation subprocess's
/// virtual address space is capped at 1 GiB (1,048,576 KiB, what `ulimit
/// -v` reports) via `fabro_proc::pre_exec_rlimit_as`. macOS's `ulimit
/// -v`/`RLIMIT_AS` does not actually cap process memory there, so this is
/// Linux-only by construction: it would not prove anything on this Mac.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn validation_runner_applies_rlimit_as_on_linux() {
    let (_dir, script_path) = write_test_executable(
        "#!/bin/sh\ncat >/dev/null\nL=$(ulimit -v)\nprintf '{\"status\":\"not_parsable\",\"message\":\"%s\"}' \"$L\"\n",
    );

    let result = validate_dot_source(
        "digraph { a -> b }",
        Some(&script_path),
        VALIDATION_PERMIT_WAIT,
        VALIDATION_KILL_TIMEOUT,
    )
    .await
    .expect("should succeed");

    match result {
        ValidateWorkflowResult::NotParsable { message } => assert_eq!(message, "1048576"),
        other => panic!("expected NotParsable, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_the_validation_future_kills_the_child() {
    let dir = tempfile::tempdir().expect("temp dir should exist");
    let marker = dir.path().join("finished");
    let started_marker = dir.path().join("started");
    let (_script_dir, script_path) = write_test_executable(&format!(
        "#!/bin/sh\ncat >/dev/null\ntouch {}\nsleep 2\ntouch {}\nprintf '{{\"status\":\"ok\",\"diagnostics\":[]}}'\n",
        started_marker.display(),
        marker.display(),
    ));

    let handle = tokio::spawn(async move {
        let _ = validate_dot_source(
            "digraph { a -> b }",
            Some(&script_path),
            VALIDATION_PERMIT_WAIT,
            std::time::Duration::from_secs(10),
        )
        .await;
    });
    // Poll for the script's own "started" marker (written only after it has
    // read all of stdin) rather than a fixed sleep, so the abort below is
    // never raced against the spawn under load.
    let poll_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !started_marker.exists() {
        assert!(
            std::time::Instant::now() < poll_deadline,
            "script never reached its started marker"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    handle.abort();
    let _ = handle.await;

    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;
    assert!(
        !marker.exists(),
        "dropping the validation future should have killed the child before it finished"
    );
}

#[test]
fn validation_runner_production_constants() {
    assert_eq!(VALIDATION_MEMORY_LIMIT_BYTES, 1024 * 1024 * 1024);
    assert_eq!(VALIDATION_KILL_TIMEOUT, std::time::Duration::from_secs(10));
    assert_eq!(VALIDATION_PERMIT_WAIT, std::time::Duration::from_secs(5));
    assert_eq!(VALIDATION_STDOUT_CAP, 16 * 1024 * 1024);
    assert_eq!(VALIDATION_STDERR_CAP, 64 * 1024);
}

#[test]
fn truncate_excerpt_caps_a_large_excerpt_with_a_marker() {
    let stderr = vec![b'a'; 10 * 1024];

    let excerpt = truncate_excerpt(&stderr);

    assert!(excerpt.len() <= LOG_EXCERPT_CAP + 64, "{}", excerpt.len());
    assert!(excerpt.contains("truncated"), "{excerpt}");
    assert!(excerpt.contains(&(10 * 1024).to_string()), "{excerpt}");
}

#[test]
fn truncate_excerpt_keeps_a_small_excerpt_unmarked() {
    let excerpt = truncate_excerpt(b"a short error");
    assert_eq!(excerpt, "a short error");
}
