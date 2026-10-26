#![expect(
    clippy::disallowed_types,
    reason = "sync CLI `validate-workflow` command: reads DOT from stdin and writes JSON to \
              stdout via blocking std::io"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "sync CLI `validate-workflow` command: uses blocking std::io::stdin/stdout"
)]

use std::io::{Read, Write};

use fabro_server::graph_validate::validate_workflow_source;

/// AC24: read DOT text from stdin, validate it (graph limits first, then
/// render-url's offline validation semantics if the graph is within every
/// limit), and write exactly one JSON object to stdout. The caller
/// (`fabro-server::validation_runner`) runs this in a bounded subprocess so
/// the quadratic-memory validation pass this reaches never runs in the
/// server's own process (AC29).
pub(crate) fn execute() -> i32 {
    let mut source = String::new();
    if std::io::stdin().read_to_string(&mut source).is_err() {
        return 1;
    }

    let result = validate_workflow_source(&source);
    let Ok(json) = serde_json::to_string(&result) else {
        return 1;
    };
    if std::io::stdout().write_all(json.as_bytes()).is_err() {
        return 1;
    }
    0
}
