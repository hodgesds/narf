//! NARF shell command parser.
//!
//! Tokenises a raw input line and builds a `Cmd` AST in fixed-size
//! stack storage (no heap — the shell binary is `#![no_std]`).
//!
//! Grammar (loosest to tightest binding):
//!
//! ```text
//! line      = sequence
//! sequence  = and_or ( ';' and_or )* [ ';' ] [ '&' ]
//! and_or    = pipeline ( ('&&' | '||') pipeline )*
//! pipeline  = simple ( '|' simple )*
//! simple    = WORD+ redirect*
//! redirect  = ('<' | '>' | '>>') WORD
//! ```
//!
//! Capacity limits (all compile-time constants):
//!
//! | limit                   | value | reason               |
//! |-------------------------|-------|----------------------|
//! | `MAX_ARGV`              |    16 | argv per simple cmd  |
//! | `MAX_REDIRS`            |     4 | redirects per cmd    |
//! | `MAX_PIPE_STAGES`       |     8 | stages per pipeline  |
//! | `MAX_SEQUENCE`          |     8 | cmds in a `;` list   |
//! | `MAX_WORD_LEN`          |   128 | bytes per word       |
//!
//! Word storage is embedded inside the AST nodes so no separate
//! heap is needed.
//!
//! Operator precedence is implemented as a straightforward
//! recursive-descent parser following dash/src/parser.c's shape
//! (IEEE Std 1003.1-2017 §2.10).
//!
//! Limitations (deferred):
//! - No `$(...)` command substitution.
//! - No `${VAR}` parameter expansion.
//! - No `~` tilde expansion.
//! - No glob expansion.
//! - No heredocs (`<<`).
//! - No multi-line input.

// ── Types ─────────────────────────────────────────────────────────────

/// Maximum bytes in a single quoted/unquoted word token.
pub const MAX_WORD_LEN: usize = 128;
/// Maximum number of argv words in a single `Simple` command.
pub const MAX_ARGV: usize = 16;
/// Maximum number of redirections attached to one `Simple` command.
pub const MAX_REDIRS: usize = 4;
/// Maximum stages in a single `Pipeline`.
pub const MAX_PIPE_STAGES: usize = 8;
/// Maximum commands in a `Sequence` or a chain of `&&`/`||` ops.
pub const MAX_SEQUENCE: usize = 8;

/// A fixed-length word (no heap). The valid range is `[0..len]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Word {
    pub bytes: [u8; MAX_WORD_LEN],
    pub len: usize,
}

impl Word {
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_WORD_LEN],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for Word {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(self.as_bytes()).unwrap_or("<utf8-err>"))
    }
}

/// A single I/O redirection attached to a `Simple` command.
#[derive(Clone, Copy, Debug)]
pub enum Redir {
    StdinFrom(Word),    // < file
    StdoutTo(Word),     // > file  (truncate)
    StdoutAppend(Word), // >> file
}

/// The full AST node. All variants own their storage inline.
///
/// `Box` is unavailable (no alloc), so deeper nesting than
/// `And`/`Or` uses `Background(Box<Cmd>)` only when we can keep
/// it on the stack via a fixed layout.  To stay heap-free `And`
/// and `Or` are modelled as flat linear chains up to `MAX_SEQUENCE`
/// entries; see `AndOrChain`.
#[derive(Debug)]
pub enum Cmd {
    /// Empty — produced by empty input. Shell ignores it.
    Empty,
    /// A single command with arguments + redirections.
    Simple {
        /// argv[0] is the command name.
        argv: [Word; MAX_ARGV],
        argc: usize,
        /// Redirections attached directly to this command.
        redirs: [Option<Redir>; MAX_REDIRS],
        redir_count: usize,
    },
    /// `cmd1 | cmd2 | cmd3` — a chain of `Simple` commands.
    /// Only `Simple` commands appear as pipeline stages
    /// (the grammar doesn't allow nested pipelines).
    Pipeline {
        stages: [SimpleCmd; MAX_PIPE_STAGES],
        count: usize,
    },
    /// `a ; b ; c` — execute in order, ignore exit codes.
    Sequence {
        cmds: [SequenceEntry; MAX_SEQUENCE],
        count: usize,
    },
    /// `a && b` — run b only if a succeeded.
    And(SimpleCmd, SimpleCmd),
    /// `a || b` — run b only if a failed.
    Or(SimpleCmd, SimpleCmd),
    /// `cmd &` — run cmd in the background; shell doesn't wait.
    Background(SimpleCmd),
    /// Parse error.
    Error(&'static str),
}

/// Inline `Simple`-command storage used where `Cmd::Simple` would
/// be recursive.  This is identical in layout to the `Simple`
/// variant's fields.
#[derive(Clone, Copy, Debug)]
pub struct SimpleCmd {
    pub argv: [Word; MAX_ARGV],
    pub argc: usize,
    pub redirs: [Option<Redir>; MAX_REDIRS],
    pub redir_count: usize,
}

impl SimpleCmd {
    pub const fn empty() -> Self {
        Self {
            argv: [Word::empty(); MAX_ARGV],
            argc: 0,
            redirs: [None; MAX_REDIRS],
            redir_count: 0,
        }
    }
}

/// An entry in a `Sequence` list — either a bare command, a
/// background command, an `&&` or `||` pair, or a pipeline.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Background is reserved for `cmd ; othercmd &` parsing
pub enum SequenceEntry {
    Cmd(SimpleCmd),
    Pipeline {
        stages: [SimpleCmd; MAX_PIPE_STAGES],
        count: usize,
    },
    And(SimpleCmd, SimpleCmd),
    Or(SimpleCmd, SimpleCmd),
    Background(SimpleCmd),
}

// ── Tokeniser ──────────────────────────────────────────────────────────

/// Raw token produced by `Lexer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    Word(Word),
    Pipe,       // |
    Semicolon,  // ;
    And,        // &&
    Or,         // ||
    Ampersand,  // &   (background)
    Redir(RedirOp),
    Eof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirOp {
    In,     // <
    Out,    // >
    Append, // >>
}

/// Capacity for the token ring produced by `lex`.
/// A 256-byte line can have at most ~128 tokens (pairs of
/// word/op), so 64 is ample for any realistic input.
const MAX_TOKENS: usize = 64;

/// Lex `input` into a flat token array.  Returns the token slice
/// and the count of valid tokens (including a final `Eof`).
pub fn lex(input: &[u8]) -> ([Tok; MAX_TOKENS], usize) {
    let mut out = [Tok::Eof; MAX_TOKENS];
    let mut count = 0usize;
    let mut i = 0usize;

    macro_rules! push {
        ($t:expr) => {{
            if count < MAX_TOKENS - 1 {
                out[count] = $t;
                count += 1;
            }
        }};
    }

    while i < input.len() {
        let b = input[i];
        // Skip whitespace (except the newline, which doesn't reach
        // here — the line editor strips it before calling dispatch).
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        match b {
            b'|' => {
                if i + 1 < input.len() && input[i + 1] == b'|' {
                    push!(Tok::Or);
                    i += 2;
                } else {
                    push!(Tok::Pipe);
                    i += 1;
                }
            }
            b'&' => {
                if i + 1 < input.len() && input[i + 1] == b'&' {
                    push!(Tok::And);
                    i += 2;
                } else {
                    push!(Tok::Ampersand);
                    i += 1;
                }
            }
            b';' => {
                push!(Tok::Semicolon);
                i += 1;
            }
            b'>' => {
                if i + 1 < input.len() && input[i + 1] == b'>' {
                    push!(Tok::Redir(RedirOp::Append));
                    i += 2;
                } else {
                    push!(Tok::Redir(RedirOp::Out));
                    i += 1;
                }
            }
            b'<' => {
                push!(Tok::Redir(RedirOp::In));
                i += 1;
            }
            _ => {
                // Collect a word token.
                let mut w = Word::empty();
                i = lex_word(input, i, &mut w);
                if w.len > 0 {
                    push!(Tok::Word(w));
                }
            }
        }
    }
    // Final Eof sentinel.
    out[count] = Tok::Eof;
    count += 1;
    (out, count)
}

/// Scan one word (possibly quoted) from `input` starting at
/// position `start`.  Populates `w` and returns the new index.
///
/// Quoting rules:
/// - `'...'` — single-quote: every byte is literal, no escapes.
/// - `"..."` — double-quote: `\"` → `"`, all other bytes literal.
/// - outside quotes: `\x` → `x` (single-char escape).
fn lex_word(input: &[u8], start: usize, w: &mut Word) -> usize {
    let mut i = start;
    while i < input.len() {
        let b = input[i];
        match b {
            // Whitespace or operator terminates an unquoted word.
            b' ' | b'\t' | b'|' | b'&' | b';' | b'>' | b'<' => break,
            // Single-quote: read until the next `'`; everything literal.
            b'\'' => {
                i += 1; // consume opening quote
                while i < input.len() && input[i] != b'\'' {
                    push_byte(w, input[i]);
                    i += 1;
                }
                if i < input.len() {
                    i += 1; // consume closing quote
                }
            }
            // Double-quote: `\"` is an escaped quote; all else literal.
            b'"' => {
                i += 1; // consume opening quote
                while i < input.len() && input[i] != b'"' {
                    if input[i] == b'\\' && i + 1 < input.len() && input[i + 1] == b'"' {
                        push_byte(w, b'"');
                        i += 2;
                    } else {
                        push_byte(w, input[i]);
                        i += 1;
                    }
                }
                if i < input.len() {
                    i += 1; // consume closing quote
                }
            }
            // Backslash outside quotes.
            b'\\' => {
                if i + 1 < input.len() {
                    push_byte(w, input[i + 1]);
                    i += 2;
                } else {
                    i += 1; // trailing backslash — discard
                }
            }
            _ => {
                push_byte(w, b);
                i += 1;
            }
        }
    }
    i
}

fn push_byte(w: &mut Word, b: u8) {
    if w.len < MAX_WORD_LEN {
        w.bytes[w.len] = b;
        w.len += 1;
    }
}

// ── Parser ─────────────────────────────────────────────────────────────

struct Parser<'a> {
    tokens: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Tok {
        if self.pos < self.tokens.len() {
            self.tokens[self.pos]
        } else {
            Tok::Eof
        }
    }

    fn consume(&mut self) -> Tok {
        let t = self.peek();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), Tok::Eof)
    }

    /// Parse `pipeline = simple ( '|' simple )*` → `SequenceEntry`.
    fn parse_pipeline_as_entry(&mut self) -> SequenceEntry {
        let first = self.parse_simple();
        if self.peek() != Tok::Pipe {
            return SequenceEntry::Cmd(first);
        }
        let mut stages: [SimpleCmd; MAX_PIPE_STAGES] = [SimpleCmd::empty(); MAX_PIPE_STAGES];
        let mut count = 0usize;
        stages[count] = first;
        count += 1;
        while self.peek() == Tok::Pipe {
            self.consume(); // eat `|`
            if count >= MAX_PIPE_STAGES {
                break; // silently drop extra stages
            }
            stages[count] = self.parse_simple();
            count += 1;
        }
        SequenceEntry::Pipeline { stages, count }
    }

    /// Parse `and_or = pipeline ( ('&&' | '||') pipeline )*`.
    fn parse_and_or_as_entry_v2(&mut self) -> SequenceEntry {
        let left_entry = self.parse_pipeline_as_entry();
        match self.peek() {
            Tok::And => {
                self.consume();
                // LHS must be a single command for && semantics.
                let left_sc = entry_to_simple(left_entry);
                let right_entry = self.parse_pipeline_as_entry();
                let right_sc = entry_to_simple(right_entry);
                SequenceEntry::And(left_sc, right_sc)
            }
            Tok::Or => {
                self.consume();
                let left_sc = entry_to_simple(left_entry);
                let right_entry = self.parse_pipeline_as_entry();
                let right_sc = entry_to_simple(right_entry);
                SequenceEntry::Or(left_sc, right_sc)
            }
            _ => left_entry,
        }
    }

    /// Parse `simple = WORD+ redirect*`
    fn parse_simple(&mut self) -> SimpleCmd {
        let mut sc = SimpleCmd::empty();
        // Collect word/redirect pairs.
        loop {
            match self.peek() {
                Tok::Word(w) => {
                    self.consume();
                    if sc.argc < MAX_ARGV {
                        sc.argv[sc.argc] = w;
                        sc.argc += 1;
                    }
                }
                Tok::Redir(op) => {
                    self.consume();
                    // Next token must be a word (the file).
                    let target = match self.peek() {
                        Tok::Word(w) => {
                            self.consume();
                            w
                        }
                        _ => {
                            // No file after redirect operator —
                            // leave a sentinel empty word; exec
                            // will report the error at runtime.
                            Word::empty()
                        }
                    };
                    if sc.redir_count < MAX_REDIRS {
                        sc.redirs[sc.redir_count] = Some(match op {
                            RedirOp::In     => Redir::StdinFrom(target),
                            RedirOp::Out    => Redir::StdoutTo(target),
                            RedirOp::Append => Redir::StdoutAppend(target),
                        });
                        sc.redir_count += 1;
                    }
                }
                // Any other token terminates the simple command.
                _ => break,
            }
        }
        sc
    }
}

/// Parse a single input line into a `Cmd` AST.
pub fn parse_line(input: &[u8]) -> Cmd {
    let (tokens, count) = lex(input);
    if count == 0 {
        return Cmd::Empty;
    }
    let token_slice = &tokens[..count];
    let mut p = Parser { tokens: token_slice, pos: 0 };

    if p.at_eof() {
        return Cmd::Empty;
    }

    // Parse the top-level sequence using the corrected v2 path.
    p.parse_sequence_v2()
}

impl<'a> Parser<'a> {
    /// Top-level sequence parser using the corrected `_v2` helpers.
    fn parse_sequence_v2(&mut self) -> Cmd {
        if self.at_eof() {
            return Cmd::Empty;
        }

        let first = self.parse_and_or_as_entry_v2();

        let next = self.peek();
        if next == Tok::Eof {
            return entry_to_cmd(first);
        }
        if next == Tok::Ampersand {
            self.consume();
            return Cmd::Background(entry_to_simple(first));
        }
        if next != Tok::Semicolon {
            return entry_to_cmd(first);
        }

        // Build a sequence.
        let mut seq: [SequenceEntry; MAX_SEQUENCE] =
            [SequenceEntry::Cmd(SimpleCmd::empty()); MAX_SEQUENCE];
        let mut count = 0usize;
        seq[count] = first;
        count += 1;

        while self.peek() == Tok::Semicolon {
            self.consume(); // eat `;`
            if self.at_eof() || self.peek() == Tok::Semicolon {
                break;
            }
            if count >= MAX_SEQUENCE {
                return Cmd::Error("sequence too long");
            }
            let entry = self.parse_and_or_as_entry_v2();
            seq[count] = entry;
            count += 1;
            if self.peek() == Tok::Ampersand {
                self.consume();
                break;
            }
        }

        if count == 1 {
            return entry_to_cmd(seq[0]);
        }
        Cmd::Sequence { cmds: seq, count }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Convert a `SequenceEntry` to the top-level `Cmd` type.
fn entry_to_cmd(e: SequenceEntry) -> Cmd {
    match e {
        SequenceEntry::Cmd(sc) => {
            if sc.argc == 0 {
                Cmd::Empty
            } else {
                Cmd::Simple {
                    argv: sc.argv,
                    argc: sc.argc,
                    redirs: sc.redirs,
                    redir_count: sc.redir_count,
                }
            }
        }
        SequenceEntry::Pipeline { stages, count } => {
            if count == 1 {
                let sc = stages[0];
                Cmd::Simple {
                    argv: sc.argv,
                    argc: sc.argc,
                    redirs: sc.redirs,
                    redir_count: sc.redir_count,
                }
            } else {
                Cmd::Pipeline { stages, count }
            }
        }
        SequenceEntry::And(l, r) => Cmd::And(l, r),
        SequenceEntry::Or(l, r)  => Cmd::Or(l, r),
        SequenceEntry::Background(sc) => Cmd::Background(sc),
    }
}

/// Extract a `SimpleCmd` from a `SequenceEntry`.  Pipeline entries
/// are collapsed to their first stage (used for `&&`/`||` operands
/// where the LHS of a compound is a pipeline; the full pipeline is
/// represented internally as a `SequenceEntry::Pipeline` and you'd
/// only collapse it if you need a single `SimpleCmd`).
fn entry_to_simple(e: SequenceEntry) -> SimpleCmd {
    match e {
        SequenceEntry::Cmd(sc) => sc,
        SequenceEntry::Pipeline { stages, count } => {
            if count > 0 { stages[0] } else { SimpleCmd::empty() }
        }
        SequenceEntry::And(l, _) => l,
        SequenceEntry::Or(l, _)  => l,
        SequenceEntry::Background(sc) => sc,
    }
}
