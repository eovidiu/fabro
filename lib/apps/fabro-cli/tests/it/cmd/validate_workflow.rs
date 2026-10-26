#![expect(
    clippy::disallowed_methods,
    reason = "These CLI integration tests intentionally spawn the real fabro binary and stream \
              DOT over stdio to verify the internal validate-workflow subprocess contract."
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration tests write DOT to the spawned child's stdin via std::io::Write"
)]

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

use fabro_test::{fabro_snapshot, test_context};

fn validate_workflow_command(context: &fabro_test::TestContext) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fabro"));
    fabro_test::apply_test_isolation(&mut cmd, &context.home_dir);
    cmd.current_dir(&context.temp_dir);
    cmd
}

/// Spawns `__validate-workflow`, writes `source` to its stdin, and parses
/// its stdout as the one JSON object it must produce (AC24).
fn run(source: &str) -> serde_json::Value {
    let context = test_context!();
    let mut cmd = validate_workflow_command(&context);
    cmd.args(["__validate-workflow"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .expect("validate-workflow subprocess should spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(source.as_bytes())
        .expect("stdin write should succeed");

    let output = child
        .wait_with_output()
        .expect("validate-workflow subprocess should exit");
    assert!(
        output.status.success(),
        "exit status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout should be one JSON object: {err}; stdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn hidden_from_help() {
    let context = test_context!();
    let mut cmd = context.command();
    cmd.arg("--help");
    let output = cmd.output().expect("fabro --help should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("validate-workflow"), "{stdout}");
}

#[test]
fn help() {
    let context = test_context!();
    let mut cmd = context.command();
    cmd.args(["__validate-workflow", "--help"]);
    fabro_snapshot!(context.filters(), cmd, @"
    success: true
    exit_code: 0
    ----- stdout -----
    Validate a workflow's DOT source, within graph-size limits (internal)

    Usage: fabro __validate-workflow [OPTIONS]

    Options:
          --json              Output as JSON [env: FABRO_JSON=]
          --debug             Enable DEBUG-level logging (default is INFO) [env: FABRO_DEBUG=]
          --no-upgrade-check  Disable automatic upgrade check [env: FABRO_NO_UPGRADE_CHECK=true]
          --quiet             Suppress non-essential output [env: FABRO_QUIET=]
          --verbose           Enable verbose output [env: FABRO_VERBOSE=]
      -h, --help              Print help
    ----- stderr -----
    ");
}

#[test]
fn matches_in_process_validate_workflow_source_for_a_valid_workflow() {
    const DOT: &str = r#"digraph Test {
        graph [goal="Test"]
        start [shape=Mdiamond]
        exit  [shape=Msquare]
        start -> exit
    }"#;
    let json = run(DOT);
    assert_eq!(json["status"], "ok");

    let in_process = fabro_server::graph_validate::validate_workflow_source(DOT);
    let expected = serde_json::to_value(&in_process).expect("should serialize");
    assert_eq!(json, expected);
}

/// AC6: an `@file` prompt, an `@file` output_schema, an `import`, and a
/// `stack.child_workflow`, none of them loaded by this single-file check,
/// each produce one reference diagnostic.
#[test]
fn reports_the_four_ac6_reference_diagnostics() {
    const DOT: &str = r#"digraph Demo {
        start [shape=Mdiamond]
        prompt [prompt="@prompts/plan.md"]
        schema [type="agent", prompt="schema", output_schema="@schemas/output.json"]
        imported [import="imports/shared.fabro"]
        child [shape=house, stack.child_workflow="../child/workflow.fabro"]
        exit [shape=Msquare]
        start -> prompt -> schema -> imported -> child -> exit
    }"#;
    let json = run(DOT);
    assert_eq!(json["status"], "ok");
    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics should be an array");
    let rules: Vec<&str> = diagnostics
        .iter()
        .map(|d| d["rule"].as_str().expect("rule should be a string"))
        .collect();
    assert_eq!(
        rules
            .iter()
            .filter(|rule| **rule == "attractor.file_not_found")
            .count(),
        2,
        "{rules:?}"
    );
    assert!(rules.contains(&"attractor.import"), "{rules:?}");
    assert!(
        rules.contains(&"attractor.child_workflow_not_found"),
        "{rules:?}"
    );
}

#[test]
fn non_dot_stdin_reports_not_parsable() {
    // `validate_workflow_source` doesn't itself special-case a `dot.`
    // diagnostic as not_parsable; `handler::graph_url` does that mapping
    // on the returned diagnostics. Accept either shape here.
    let json = run("this is not a dot file at all {{{");
    let status = json["status"].as_str().unwrap_or_default();
    if status == "not_parsable" {
        return;
    }
    assert_eq!(status, "ok", "{json:?}");
    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics should be an array");
    assert!(
        diagnostics.iter().any(|d| d["rule"]
            .as_str()
            .is_some_and(|rule| rule.starts_with("dot."))),
        "expected a `dot.` diagnostic for unparsable input: {diagnostics:?}"
    );
}

#[test]
fn a_graph_over_the_node_limit_is_refused_before_validating() {
    // 501 nodes, over fabro_dot::limits::MAX_NODES (500): refused as
    // graph_too_large, never reaching validate_workflow_source's
    // validation pass.
    let mut source = String::from("digraph TooBig {\n");
    for i in 0..=500u32 {
        let _ = writeln!(source, "n{i}");
    }
    source.push('}');

    let json = run(&source);
    assert_eq!(json["status"], "graph_too_large");
    assert_eq!(json["limit"], "nodes");
    assert_eq!(json["count"], 501);
    assert_eq!(json["max"], 500);
}
