//! AC27/AC28: Linux-only. Applies `RLIMIT_AS` to the real `__validate-workflow`
//! subprocess the same way `fabro-server::validation_runner` does
//! (`fabro_proc::pre_exec_rlimit_as`) and proves the cap is enforced by the
//! kernel. Must not compile on macOS: `ulimit -v`/`RLIMIT_AS` does not
//! actually cap process memory there, so a macOS run would prove nothing
//! and risks running an amplification template unbounded on this machine.
#![cfg(target_os = "linux")]
#![expect(
    clippy::disallowed_methods,
    reason = "Linux-only integration tests spawn the real fabro binary directly to apply \
              RLIMIT_AS exactly like fabro-server::validation_runner does."
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration tests write DOT to the spawned child's stdin via std::io::Write"
)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fabro_test::test_context;

const RLIMIT_AS_BYTES: u64 = 1024 * 1024 * 1024;
const KILL_AFTER: Duration = Duration::from_secs(10);

struct RunResult {
    output:         std::process::Output,
    /// Whether this test had to SIGKILL the child itself (its own 10 s
    /// backstop), as opposed to the child ending on its own.
    killed_by_test: bool,
    elapsed:        Duration,
}

/// Spawns `__validate-workflow` with `RLIMIT_AS` applied via
/// `fabro_proc::pre_exec_rlimit_as` (exactly as `validation_runner` does in
/// production), writes `source` to stdin, closes stdin so the child's
/// `read_to_string` can see EOF, and waits for it to exit on its own —
/// falling back to a SIGKILL backstop only so a broken case cannot hang the
/// test suite forever (`killed_by_test` tells callers whether that backstop
/// fired, so they can tell a real kill under RLIMIT_AS from a hung test).
fn spawn_rlimited(context: &fabro_test::TestContext, source: &str) -> RunResult {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fabro"));
    fabro_test::apply_test_isolation(&mut cmd, &context.home_dir);
    cmd.current_dir(&context.temp_dir);
    cmd.arg("__validate-workflow")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Exactly what validation_runner does in production, applied here
    // directly rather than through the subprocess runner, per the review
    // request: a worst case the kernel itself must stop.
    fabro_proc::pre_exec_rlimit_as(&mut cmd, RLIMIT_AS_BYTES);

    let mut child = cmd.spawn().expect("__validate-workflow should spawn");
    // Drain stdout and stderr while waiting: a valid 500-node workflow
    // prints ~90 KB of warnings, more than a pipe buffer holds, and a child
    // blocked on a full pipe would look like a hang to the poll loop below.
    let mut stdout_pipe = child.stdout.take().expect("stdout should be piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut bytes);
        bytes
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr should be piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut bytes);
        bytes
    });
    {
        let mut stdin = child.stdin.take().expect("stdin should be piped");
        // A short write; if it fails because the child already died (e.g.
        // RLIMIT_AS made even startup fail), that is still a valid outcome
        // for the caller to assert on, not a test bug.
        let _ = stdin.write_all(source.as_bytes());
    } // stdin dropped and closed here: the child's read_to_string now sees EOF.

    let started = Instant::now();
    let mut killed_by_test = false;
    loop {
        if child.try_wait().expect("try_wait should succeed").is_some() {
            break;
        }
        if started.elapsed() > KILL_AFTER {
            let _ = child.kill();
            killed_by_test = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = started.elapsed();
    let status = child.wait().expect("child should be reaped");
    let output = std::process::Output {
        status,
        stdout: stdout_reader
            .join()
            .expect("stdout reader should not panic"),
        stderr: stderr_reader
            .join()
            .expect("stderr reader should not panic"),
    };
    RunResult {
        output,
        killed_by_test,
        elapsed,
    }
}

fn assert_killed_by_rlimit_not_by_the_test(result: &RunResult) {
    assert!(
        !result.killed_by_test,
        "the test's own 10 s backstop fired; the child never ended on its own, so this proves \
         nothing about RLIMIT_AS (elapsed {:?})",
        result.elapsed
    );
    assert!(
        result.elapsed < KILL_AFTER,
        "took {:?}, expected well under the 10 s deadline",
        result.elapsed
    );
    assert!(
        !result.output.status.success(),
        "the amplification template should end the child abnormally, not exit 0"
    );
    let stdout = String::from_utf8_lossy(&result.output.stdout);
    assert!(
        !stdout.contains("\"status\":\"ok\""),
        "the child must never print a checked/ok outcome: {stdout}"
    );
    // Abnormal here means either a fatal signal (SIGKILL/SIGABRT/SIGSEGV
    // from an allocation failure) or a nonzero exit (e.g. Rust's own OOM
    // abort handler); either proves the kernel actually stopped it rather
    // than it exiting cleanly for an unrelated reason.
    let signaled = result.output.status.signal().is_some();
    let nonzero_exit = result.output.status.code().is_some_and(|code| code != 0);
    assert!(
        signaled || nonzero_exit,
        "expected a signal or nonzero exit, got {:?}",
        result.output.status
    );
}

/// AC27: a graph-level `goal` whose template amplifies (`{{ 'x' *
/// 10000000000 }}`) must end the child abnormally under the 1 GiB cap
/// within the 10 s deadline, never printing an `ok`/well-formed JSON
/// outcome. This test process itself never renders the template — it is
/// only ever written as a string literal into the child's stdin.
#[test]
fn amplification_template_in_graph_goal_is_killed_under_rlimit_as() {
    const DOT: &str = r#"digraph Bomb {
        graph [goal="{{ 'x' * 10000000000 }}"]
        start [shape=Mdiamond]
        exit  [shape=Msquare]
        start -> exit
    }"#;
    let context = test_context!();
    assert!(DOT.len() < 200);

    let result = spawn_rlimited(&context, DOT);
    assert_killed_by_rlimit_not_by_the_test(&result);
}

/// AC27, second case: the same amplification template, but reached via a
/// node's `prompt` rather than the graph's `goal`.
#[test]
fn amplification_template_in_node_prompt_is_killed_under_rlimit_as() {
    const DOT: &str = r#"digraph Bomb {
        start [shape=Mdiamond]
        work [prompt="{{ 'x' * 10000000000 }}"]
        exit [shape=Msquare]
        start -> work -> exit
    }"#;
    let context = test_context!();
    assert!(DOT.len() < 200);

    let result = spawn_rlimited(&context, DOT);
    assert_killed_by_rlimit_not_by_the_test(&result);
}

/// AC28: an ordinary 500-node, 499-edge linear chain (~14 KB) must
/// validate successfully under the same 1 GiB cap, within the 10 s
/// deadline. Prints the child's peak RSS (`getrusage(RUSAGE_CHILDREN)`) to
/// stdout for the reviewer to record; do not run this input on macOS.
#[test]
#[expect(
    unsafe_code,
    clippy::print_stdout,
    reason = "reads getrusage(RUSAGE_CHILDREN) and prints the child's peak RSS for review"
)]
fn a_500_node_linear_chain_validates_under_rlimit_as() {
    let context = test_context!();
    // Exactly 500 nodes (n0..n499) and 499 edges: `start`/`exit` are
    // shape markers reusing n0/n499 rather than adding two more nodes, so
    // the graph stays at the MAX_NODES boundary rather than over it. A
    // 1,000-node chain was measured on Linux to abort under the 1 GiB
    // RLIMIT_AS cap; the owner lowered MAX_NODES to 500 (fits in ~260 MB)
    // rather than raising the memory cap.
    let mut dot = String::from("digraph Chain {\n    n0 [shape=Mdiamond]\n");
    for i in 1..499u32 {
        let _ = writeln!(dot, "    n{i} [shape=box]");
    }
    let _ = writeln!(dot, "    n499 [shape=Msquare]");
    let _ = write!(dot, "    n0");
    for i in 1..500u32 {
        let _ = write!(dot, " -> n{i}");
    }
    dot.push_str("\n}\n");
    assert!(
        dot.len() > 10_000 && dot.len() < 30_000,
        "len={}",
        dot.len()
    );

    let result = spawn_rlimited(&context, &dot);

    let stdout = String::from_utf8_lossy(&result.output.stdout);
    assert!(
        !result.killed_by_test,
        "the test's own 10 s backstop fired instead of the child finishing on its own \
         (elapsed {:?})",
        result.elapsed
    );
    assert!(
        result.output.status.success(),
        "a 500-node chain should validate within the 1 GiB cap; status: {:?}, stderr: {}",
        result.output.status,
        String::from_utf8_lossy(&result.output.stderr)
    );
    assert!(stdout.contains("\"status\":\"ok\""), "{stdout}");

    // SAFETY: a plain zeroed-then-filled-by-the-kernel struct read; no
    // pointers or lifetimes are held past this call.
    let peak_rss_kb = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        let result = libc::getrusage(libc::RUSAGE_CHILDREN, &raw mut usage);
        assert_eq!(result, 0, "getrusage should succeed");
        usage.ru_maxrss
    };
    println!("AC28 child peak RSS (RUSAGE_CHILDREN.ru_maxrss): {peak_rss_kb} KiB");
}

/// AC28(b): a record-only measurement, not a pass/fail gate. A denser
/// 500-node, ~2,000-edge workflow (each node linked to its next 4, under
/// 50 KB) may or may not fit under the 1 GiB cap — this only records
/// whether it ended ok or abnormally, how long it took, and the child's
/// peak RSS, for the reviewer. It still must not hang: stdin is closed
/// (as `spawn_rlimited` always does) and the usual 10 s backstop applies.
#[test]
#[expect(
    unsafe_code,
    clippy::print_stdout,
    reason = "reads getrusage(RUSAGE_CHILDREN) and prints the child's peak RSS for review"
)]
fn validate_workflow_records_peak_rss_for_a_500_node_dense_edge_workflow() {
    let context = test_context!();
    let mut dot = String::from("digraph Dense {\n");
    for i in 0..500u32 {
        let shape = if i == 0 {
            "Mdiamond"
        } else if i == 499 {
            "Msquare"
        } else {
            "box"
        };
        let _ = writeln!(dot, "    n{i} [shape={shape}]");
    }
    for i in 0..500u32 {
        for d in 1..=4u32 {
            let j = i + d;
            if j < 500 {
                let _ = writeln!(dot, "    n{i} -> n{j};");
            }
        }
    }
    dot.push('}');
    assert!(dot.len() < 50_000, "len={}", dot.len());

    let result = spawn_rlimited(&context, &dot);
    let stdout = String::from_utf8_lossy(&result.output.stdout);
    let outcome = if result.output.status.success() && stdout.contains("\"status\":\"ok\"") {
        "ok"
    } else {
        "abnormal end"
    };

    // SAFETY: a plain zeroed-then-filled-by-the-kernel struct read; no
    // pointers or lifetimes are held past this call.
    let peak_rss_kb = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        let rc = libc::getrusage(libc::RUSAGE_CHILDREN, &raw mut usage);
        assert_eq!(rc, 0, "getrusage should succeed");
        usage.ru_maxrss
    };
    println!(
        "AC28(b) 500-node/dense-edge record: outcome={outcome}, killed_by_test={}, elapsed={:?}, peak RSS (RUSAGE_CHILDREN.ru_maxrss)={peak_rss_kb} KiB",
        result.killed_by_test, result.elapsed
    );
}
