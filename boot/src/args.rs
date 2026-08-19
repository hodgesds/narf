//! Structured kernel command-line parser.
//!
//! The bootloader hands the kernel a single flat command-line string
//! ([`crate::cmdline`]). Historically every consumer re-split that
//! string with `split_ascii_whitespace()` and matched tokens with
//! `starts_with(...)` inline, so the tokenizing + key/value rules were
//! duplicated across `frame/`, `filesystem/`, and `bpf/`. This module
//! is the single place those rules live.
//!
//! [`KernelCmdline`] is a zero-copy view over the raw string: it holds
//! only the borrowed `&str` and tokenizes lazily on each accessor call.
//! No allocation, so it is usable from the earliest boot stages and
//! from `#![no_std]` leaf crates alike. Obtain the live one with
//! [`crate::args`]; construct arbitrary ones with [`KernelCmdline::new`]
//! (used by the unit tests).
//!
//! # Token grammar
//!
//! Tokens are whitespace-separated (`split_ascii_whitespace`). A token
//! is either a **bare flag** (`nosmp`) or a **`key=value`** pair
//! (`root=PARTLABEL=NARF_ROOT` — only the *first* `=` splits key from
//! value, so the value may itself contain `=`).
//!
//! # Init argv / environ (Linux convention)
//!
//! [`KernelCmdline::init_argv`] / [`KernelCmdline::init_environ`]
//! implement the split `init/main.c` performs before it `exec`s the
//! init process:
//!
//! - a standalone `--` token separates kernel params from init params;
//! - **before** `--`: bare words → init **argv**, `key=value` → init
//!   **environment**;
//! - **after** `--`: every token → init **argv** (verbatim).
//!
//! Linux additionally subtracts the params the kernel itself consumed;
//! NARF does not (its own flags are consumed structurally and init
//! reads `/proc/cmdline` directly), so callers wiring these into a real
//! init spawn should filter kernel-recognized keys first. NARF does not
//! yet thread argv/env into PID 1 — see the module docs in
//! `userspace/src/init.rs`.

use core::str::FromStr;

/// A parsed, zero-copy view over the kernel command line.
///
/// Cheap to copy (it is just a borrowed `&str`); parsing happens
/// lazily inside the accessors, so there is no eager token table to
/// keep in sync.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KernelCmdline<'a> {
    raw: &'a str,
}

impl<'a> KernelCmdline<'a> {
    /// Wrap a raw command-line string. `narf_boot::args()` wraps the
    /// live bootloader cmdline; tests wrap literals.
    #[must_use]
    pub const fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    /// The full, original command line — exactly as the bootloader
    /// supplied it. This is what `/proc/cmdline` must echo so userspace
    /// (systemd's `systemd.*` params, etc.) can read its own tokens.
    #[must_use]
    pub const fn raw(&self) -> &'a str {
        self.raw
    }

    /// Iterate the whitespace-separated tokens, in order.
    pub fn tokens(&self) -> impl Iterator<Item = &'a str> {
        self.raw.split_ascii_whitespace()
    }

    /// True iff a token is exactly `name` — a bare flag with no `=`.
    ///
    /// Use this for boolean switches like `nosmp`, `systemd_pid1`,
    /// `no_redis`, `bpf_bench`. A `name=...` token does **not** match.
    #[must_use]
    pub fn has_flag(&self, name: &str) -> bool {
        self.tokens().any(|t| t == name)
    }

    /// True iff `name` appears either as a bare flag (`name`) or as the
    /// key of a `name=value` token.
    ///
    /// Mirrors Linux booleans that accept both spellings (e.g.
    /// `safe_mode` and `safe_mode=1` are equivalent).
    #[must_use]
    pub fn has_key(&self, name: &str) -> bool {
        self.tokens()
            .any(|t| t == name || t.split_once('=').is_some_and(|(k, _)| k == name))
    }

    /// The value of the **first** `name=value` token, or `None`.
    ///
    /// Only the first `=` splits, so `root=PARTLABEL=X` yields
    /// `PARTLABEL=X`.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&'a str> {
        self.tokens().find_map(|t| {
            t.split_once('=')
                .and_then(|(k, v)| (k == name).then_some(v))
        })
    }

    /// Every value for repeated `name=value` tokens, in order. Used
    /// where "last / min wins" semantics matter across duplicates.
    pub fn values<'k>(&self, name: &'k str) -> impl Iterator<Item = &'a str> + 'k
    where
        'a: 'k,
    {
        let raw = self.raw;
        raw.split_ascii_whitespace().filter_map(move |t| {
            t.split_once('=')
                .and_then(|(k, v)| (k == name).then_some(v))
        })
    }

    /// Parse the first `name=value` token's value as `T`. Returns
    /// `None` when the key is absent or its value fails to parse — it
    /// does **not** skip a malformed first value to try a later
    /// duplicate (matching the historical `key=N` helper).
    #[must_use]
    pub fn parse_value<T: FromStr>(&self, name: &str) -> Option<T> {
        self.value(name).and_then(|v| v.parse::<T>().ok())
    }

    /// Init argv per the Linux convention (see module docs): bare words
    /// before a standalone `--`, then every token after it.
    pub fn init_argv(&self) -> impl Iterator<Item = &'a str> {
        self.raw
            .split_ascii_whitespace()
            .scan(false, |after_sep, tok| {
                if *after_sep {
                    return Some(Some(tok));
                }
                if tok == "--" {
                    *after_sep = true;
                    return Some(None);
                }
                // Before `--`: bare words are argv, key=value is environ.
                Some(if tok.contains('=') { None } else { Some(tok) })
            })
            .flatten()
    }

    /// Init environment per the Linux convention: `key=value` tokens
    /// that appear **before** a standalone `--` separator.
    pub fn init_environ(&self) -> impl Iterator<Item = &'a str> {
        self.raw
            .split_ascii_whitespace()
            .take_while(|&t| t != "--")
            .filter(|t| t.contains('='))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // The real CachyOS / systemd-pid1 boot cmdline shape, plus the
    // hardware root selector — the regression fixture.
    const REAL: &str =
        "quiet root=PARTLABEL=NARF_ROOT trace_comm=plasmalogin systemd_pid1 nosmp mt_echo_threads=4";

    fn smoke_recognizes_flags_and_values() -> TestResult {
        let a = KernelCmdline::new(REAL);
        // Bare flags present.
        if !a.has_flag("systemd_pid1") {
            return TestResult::Fail("systemd_pid1 flag not recognized");
        }
        if !a.has_flag("nosmp") {
            return TestResult::Fail("nosmp flag not recognized");
        }
        if !a.has_flag("quiet") {
            return TestResult::Fail("quiet flag not recognized");
        }
        // key=value values (first `=` splits, value may contain `=`).
        if a.value("root") != Some("PARTLABEL=NARF_ROOT") {
            return TestResult::Fail("root= value wrong");
        }
        if a.value("trace_comm") != Some("plasmalogin") {
            return TestResult::Fail("trace_comm= value wrong");
        }
        if a.parse_value::<usize>("mt_echo_threads") != Some(4) {
            return TestResult::Fail("mt_echo_threads did not parse to 4");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_recognizes_flags_and_values);

    fn smoke_negative_absent_tokens() -> TestResult {
        let a = KernelCmdline::new(REAL);
        // Absent flag → false; absent value → None.
        if a.has_flag("no_redis") {
            return TestResult::Fail("no_redis absent yet reported present");
        }
        if a.value("hugepages_2m").is_some() {
            return TestResult::Fail("absent hugepages_2m yielded a value");
        }
        // A key present as key=value must NOT match has_flag (bare only).
        if a.has_flag("root") {
            return TestResult::Fail("has_flag matched a key=value token");
        }
        // A bare flag has no value.
        if a.value("systemd_pid1").is_some() {
            return TestResult::Fail("bare flag yielded a key=value value");
        }
        // Unparseable / absent numeric → None.
        if a.parse_value::<usize>("root").is_some() {
            return TestResult::Fail("non-numeric root parsed as usize");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_negative_absent_tokens);

    fn smoke_has_key_vs_has_flag() -> TestResult {
        // safe_mode accepts both bare and =N spellings via has_key.
        let bare = KernelCmdline::new("foo safe_mode bar");
        let valued = KernelCmdline::new("foo safe_mode=1 bar");
        if !bare.has_key("safe_mode") || !valued.has_key("safe_mode") {
            return TestResult::Fail("has_key must match bare and key=value");
        }
        // has_flag is bare-only.
        if bare.has_flag("safe_mode") == valued.has_flag("safe_mode") {
            return TestResult::Fail("has_flag must distinguish bare from key=value");
        }
        if valued.has_flag("safe_mode") {
            return TestResult::Fail("has_flag matched safe_mode=1");
        }
        if KernelCmdline::new("").has_key("safe_mode") {
            return TestResult::Fail("empty cmdline reported safe_mode present");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_has_key_vs_has_flag);

    fn smoke_first_and_repeated_values() -> TestResult {
        let a = KernelCmdline::new("stop_at=late stop_at=core root=/dev/a root=/dev/b");
        // value() takes the first.
        if a.value("root") != Some("/dev/a") {
            return TestResult::Fail("value() must take the first match");
        }
        // values() yields all in order.
        let mut it = a.values("stop_at");
        if it.next() != Some("late") || it.next() != Some("core") || it.next().is_some() {
            return TestResult::Fail("values() must yield every match in order");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_first_and_repeated_values);

    fn smoke_whitespace_and_empty_edges() -> TestResult {
        // Leading / trailing / interior runs of whitespace collapse.
        let a = KernelCmdline::new("   \t nosmp   root=x  \n ");
        if !a.has_flag("nosmp") || a.value("root") != Some("x") {
            return TestResult::Fail("whitespace-padded tokens not parsed");
        }
        let mut n = 0;
        for _ in a.tokens() {
            n += 1;
        }
        if n != 2 {
            return TestResult::Fail("whitespace runs did not collapse to 2 tokens");
        }
        // Empty cmdline: no tokens, no flags, no values.
        let e = KernelCmdline::new("");
        if e.tokens().count() != 0 || e.has_flag("nosmp") || e.value("root").is_some() {
            return TestResult::Fail("empty cmdline yielded tokens");
        }
        // Whitespace-only cmdline behaves like empty.
        if KernelCmdline::new("  \t  ").tokens().count() != 0 {
            return TestResult::Fail("whitespace-only cmdline yielded tokens");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_whitespace_and_empty_edges);

    fn smoke_init_argv_environ_split() -> TestResult {
        // Before `--`: bare words → argv, key=value → environ.
        // After `--`: everything → argv.
        let a = KernelCmdline::new("ro FOO=bar single -- init=/bin/sh BAZ=qux extra");

        let argv: [&str; 4] = ["ro", "single", "init=/bin/sh", "BAZ=qux"];
        let mut ai = a.init_argv();
        for want in argv {
            if ai.next() != Some(want) {
                return TestResult::Fail("init_argv classification wrong");
            }
        }
        if ai.next() != Some("extra") || ai.next().is_some() {
            return TestResult::Fail("init_argv tail wrong");
        }

        // environ = pre-`--` key=value only (BAZ=qux is post-`--` → argv).
        let mut ei = a.init_environ();
        if ei.next() != Some("FOO=bar") || ei.next().is_some() {
            return TestResult::Fail("init_environ must be pre-`--` key=value only");
        }

        // No separator: environ = all key=value, argv = all bare words.
        let b = KernelCmdline::new("quiet root=X debug");
        let mut bargv = b.init_argv();
        if bargv.next() != Some("quiet") || bargv.next() != Some("debug") || bargv.next().is_some()
        {
            return TestResult::Fail("init_argv without `--` wrong");
        }
        let mut benv = b.init_environ();
        if benv.next() != Some("root=X") || benv.next().is_some() {
            return TestResult::Fail("init_environ without `--` wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/args", smoke_init_argv_environ_split);
}
