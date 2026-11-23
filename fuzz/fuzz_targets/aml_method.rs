//! Fuzz target: the AML (DSDT/SSDT) namespace builder.
//!
//! Surface: `narf_aml::__parse_body_for_test` — the namespace
//! build over a raw AML byte stream (no SDT header), the same
//! entry the crate's synthetic-body unit tests use. AML arrives
//! from firmware tables the kernel has no reason to trust: the
//! byte stream carries its own lengths (PkgLength), name strings,
//! and nesting, which is the classic shape for length-arithmetic
//! and recursion bugs. The build is bounded by construction:
//! namespace nesting is capped at `MAX_NAMESPACE_DEPTH` (16),
//! predicate skipping at `MAX_EVAL_NESTING` (32), and the method
//! evaluator (not run here — namespace build only skips method
//! bodies) at `MAX_METHOD_CALL_DEPTH` (16), so a hostile stream
//! cannot recurse or loop without bound; libFuzzer's `-timeout`
//! is the backstop that reports it if one ever does.
//!
//! The parser keeps its namespace in a process-global store, so
//! the harness resets it before every input
//! (`__reset_for_test`); without the reset the 4 MiB store cap
//! would fill and every later input would fail closed.
//!
//! Invariant: never panic, never read out of bounds, for any byte
//! string. `AmlError` is the correct outcome for a malformed
//! stream; a partial namespace (malformed objects skipped, the
//! rest registered) is the parser's documented behaviour.

#![no_main]

use libfuzzer_sys::fuzz_target;
use narf_fuzz::host;

/// Cap the stream size at the AML store cap's quarter: namespace
/// risk lives in nesting/length arithmetic, not in bulk bytes.
const MAX_AML: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_AML {
        return;
    }
    host::init();

    narf_aml::__reset_for_test();
    let _ = narf_aml::__parse_body_for_test(data, "\\");
});
