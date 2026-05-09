//! AML method evaluator.
//!
//! Walks AML opcode sequences inside a Method body and returns a Value.
//! Implements the subset of ACPI 6.5 §20 needed to evaluate _STA / _PIC /
//! _OSC and common math/logic patterns.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::{AmlError, AmlNode, NameValue, NodeKind, Value};

// ── Opcode constants ─────────────────────────────────────────────────────────

const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const BYTE_PREFIX: u8 = 0x0A;
const WORD_PREFIX: u8 = 0x0B;
const DWORD_PREFIX: u8 = 0x0C;
const STRING_PREFIX: u8 = 0x0D;
const QWORD_PREFIX: u8 = 0x0E;
const BUFFER_OP: u8 = 0x11;
const PACKAGE_OP: u8 = 0x12;
const CONTINUE_OP: u8 = 0x9F;
const STORE_OP: u8 = 0x70;
const ADD_OP: u8 = 0x72;
const SUBTRACT_OP: u8 = 0x74;
const INCREMENT_OP: u8 = 0x75;
const DECREMENT_OP: u8 = 0x76;
const MULTIPLY_OP: u8 = 0x77;
const DIVIDE_OP: u8 = 0x78;
const SHIFT_LEFT_OP: u8 = 0x79;
const SHIFT_RIGHT_OP: u8 = 0x7A;
const AND_OP: u8 = 0x7B;
const NAND_OP: u8 = 0x7C;
const OR_OP: u8 = 0x7D;
const NOR_OP: u8 = 0x7E;
const XOR_OP: u8 = 0x7F;
const NOT_OP: u8 = 0x80;
const LAND_OP: u8 = 0x90;
const LOR_OP: u8 = 0x91;
const LNOT_OP: u8 = 0x92;
const LEQUAL_OP: u8 = 0x93;
const LGREATER_OP: u8 = 0x94;
const LLESS_OP: u8 = 0x95;
const IF_OP: u8 = 0xA0;
const ELSE_OP: u8 = 0xA1;
const WHILE_OP: u8 = 0xA2;
const NOOP_OP: u8 = 0xA3;
const RETURN_OP: u8 = 0xA4;
const BREAK_OP: u8 = 0xA5;

const ROOT_CHAR: u8 = b'\\';
const PARENT_PREFIX: u8 = b'^';
const DUAL_NAME_PREFIX: u8 = 0x2E;
const MULTI_NAME_PREFIX: u8 = 0x2F;

const MAX_WHILE_ITERATIONS: u32 = 1_000_000;

// ── Evaluator state ───────────────────────────────────────────────────────────

/// Control-flow signal returned from inner TermList walks.
#[derive(Debug)]
enum Signal {
    /// Normal: keep going.
    None,
    /// `Return(v)` — unwind all the way to `evaluate_method`.
    Return(Value),
    /// `Break` inside a While — exit the loop, not the method.
    Break,
    /// `Continue` inside a While — restart the loop predicate.
    Continue,
}

struct EvalState {
    locals: [Value; 8],
    args: Vec<Value>,
}

impl EvalState {
    fn new(args: &[Value]) -> Self {
        // Rust doesn't let us `[Value::Integer(0); 8]` (non-Copy), so build
        // the array manually.
        Self {
            locals: [
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
                Value::Integer(0),
            ],
            args: args.to_vec(),
        }
    }

    fn local(&self, idx: usize) -> Value {
        self.locals[idx].clone()
    }
    fn arg(&self, idx: usize) -> Value {
        self.args.get(idx).cloned().unwrap_or(Value::Integer(0))
    }
    fn set_local(&mut self, idx: usize, v: Value) {
        self.locals[idx] = v;
    }
    fn set_arg(&mut self, idx: usize, v: Value) {
        if idx < self.args.len() {
            self.args[idx] = v;
        }
        // Silently ignore out-of-range arg stores.
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Evaluate an AML method at the given fully-qualified namespace path.
///
/// Fetches the method body from the AML store, sets up evaluator state with
/// the caller-supplied arguments, walks the TermList, and returns the value
/// produced by `Return(...)` or `Value::Integer(0)` if the body falls through.
pub fn evaluate_method(path: &str, args: &[Value]) -> Result<Value, AmlError> {
    // 1. Look up the node.
    let node: AmlNode = crate::find_node(path).ok_or(AmlError::MethodNotFound)?;
    if node.kind != NodeKind::Method {
        return Err(AmlError::MethodNotFound);
    }

    // 2. Pull body bytes from the AML store.
    let (offset, length) = node.method_body;
    if length == 0 {
        return Ok(Value::Integer(0));
    }
    let mut body = alloc::vec![0u8; length];
    let copied = crate::copy_aml_bytes(offset, &mut body);
    if copied < length {
        return Err(AmlError::Truncated);
    }

    // 3. Evaluate.
    let mut state = EvalState::new(args);
    let mut cur = 0usize;
    match walk_term_list(&body, &mut cur, body.len(), &mut state)? {
        Signal::Return(v) => Ok(v),
        _ => Ok(Value::Integer(0)),
    }
}

/// Decode a single AML term-arg from a byte slice as a `Value`.
///
/// This is the stateless variant of the inner `eval_term_arg`
/// loop — useful for decoding `Name(X, Package(...))` bodies that
/// the namespace builder stores as `NameValue::Unparsed{offset,
/// length}`. There are no Locals / Args, so any opcode that needs
/// per-frame state (Local0..Local7, Arg0..Arg6) returns
/// `Value::Integer(0)`.
pub fn decode_value(bytes: &[u8]) -> Result<Value, AmlError> {
    let mut state = EvalState::new(&[]);
    let mut cur = 0usize;
    eval_term_arg(bytes, &mut cur, &mut state)
}

// ── Core walker ──────────────────────────────────────────────────────────────

/// Walk a TermList bounded by `end` (exclusive index into `buf`).
/// Returns when we hit `end`, `ReturnOp`, `BreakOp`, or `ContinueOp`.
fn walk_term_list(
    buf: &[u8],
    cur: &mut usize,
    end: usize,
    state: &mut EvalState,
) -> Result<Signal, AmlError> {
    while *cur < end {
        let sig = eval_term(buf, cur, end, state)?;
        match sig {
            Signal::None => {}
            other => return Ok(other),
        }
    }
    Ok(Signal::None)
}

/// Evaluate the next single TermObj at `*cur`, advancing the cursor.
fn eval_term(
    buf: &[u8],
    cur: &mut usize,
    end: usize,
    state: &mut EvalState,
) -> Result<Signal, AmlError> {
    let op = next_u8(buf, cur)?;
    match op {
        // ── Constants ──────────────────────────────────────────────────────
        ZERO_OP | ONE_OP | 0xFF /* ONES_OP */ => {
            // These are TermArgs consumed as stand-alone statements —
            // the value is discarded.
            *cur -= 1;
            eval_term_arg(buf, cur, state)?;
        }
        BYTE_PREFIX | WORD_PREFIX | DWORD_PREFIX | QWORD_PREFIX | STRING_PREFIX => {
            *cur -= 1;
            eval_term_arg(buf, cur, state)?;
        }

        // ── Locals / Args as statements (value discarded) ──────────────────
        0x60..=0x67 => { /* Local0..7 read, discard */ }
        0x68..=0x6E => { /* Arg0..6 read, discard */ }

        // ── NoopOp ────────────────────────────────────────────────────────
        NOOP_OP => {}

        // ── ReturnOp ──────────────────────────────────────────────────────
        RETURN_OP => {
            let v = eval_term_arg(buf, cur, state)?;
            return Ok(Signal::Return(v));
        }

        // ── BreakOp / ContinueOp ──────────────────────────────────────────
        BREAK_OP    => return Ok(Signal::Break),
        CONTINUE_OP => return Ok(Signal::Continue),

        // ── StoreOp ───────────────────────────────────────────────────────
        STORE_OP => {
            let src = eval_term_arg(buf, cur, state)?;
            write_target(buf, cur, src, state)?;
        }

        // ── Math: binary (op, TermArg, TermArg, Target) ───────────────────
        ADD_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_add(b));
            write_target(buf, cur, r, state)?;
        }
        SUBTRACT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_sub(b));
            write_target(buf, cur, r, state)?;
        }
        MULTIPLY_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_mul(b));
            write_target(buf, cur, r, state)?;
        }
        DIVIDE_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            // Remainder target.
            let rem = if b == 0 { 0 } else { a % b };
            let quot = if b == 0 { 0 } else { a / b };
            // Consume & write remainder target (often NullName).
            write_target(buf, cur, Value::Integer(rem), state)?;
            // Quotient target.
            write_target(buf, cur, Value::Integer(quot), state)?;
        }
        SHIFT_LEFT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = if b >= 64 { 0 } else { a << b };
            write_target(buf, cur, Value::Integer(r), state)?;
        }
        SHIFT_RIGHT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = if b >= 64 { 0 } else { a >> b };
            write_target(buf, cur, Value::Integer(r), state)?;
        }
        AND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(a & b), state)?;
        }
        NAND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(!(a & b)), state)?;
        }
        OR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(a | b), state)?;
        }
        NOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(!(a | b)), state)?;
        }
        XOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(a ^ b), state)?;
        }

        // ── Math: unary (op, SuperName → read-modify-write) ───────────────
        INCREMENT_OP => {
            let (old, name) = read_super_name_value(buf, cur, state)?;
            let r = Value::Integer(old.as_integer().wrapping_add(1));
            write_super_name_back(name, r, state);
        }
        DECREMENT_OP => {
            let (old, name) = read_super_name_value(buf, cur, state)?;
            let r = Value::Integer(old.as_integer().wrapping_sub(1));
            write_super_name_back(name, r, state);
        }
        NOT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            write_target(buf, cur, Value::Integer(!a), state)?;
        }

        // ── Logic (no target, result is the value itself) ─────────────────
        LAND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            // Return value — discard at statement level.
            let _ = Value::Integer(if a != 0 && b != 0 { 1 } else { 0 });
        }
        LOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let _ = Value::Integer(if a != 0 || b != 0 { 1 } else { 0 });
        }
        LNOT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let _ = Value::Integer(if a == 0 { 1 } else { 0 });
        }
        LEQUAL_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let _ = Value::Integer(if a == b { 1 } else { 0 });
        }
        LGREATER_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let _ = Value::Integer(if a > b { 1 } else { 0 });
        }
        LLESS_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let _ = Value::Integer(if a < b { 1 } else { 0 });
        }

        // ── Buffer / Package ───────────────────────────────────────────────
        BUFFER_OP => {
            *cur -= 1;
            eval_term_arg(buf, cur, state)?;
        }
        PACKAGE_OP => {
            *cur -= 1;
            eval_term_arg(buf, cur, state)?;
        }

        // ── IfOp ──────────────────────────────────────────────────────────
        IF_OP => {
            let pkg_start = *cur;
            let pkg_len   = read_pkg_length(buf, cur)?;
            let pkg_end   = pkg_start + pkg_len;
            if pkg_end > end { return Err(AmlError::OutOfPkg); }

            let pred = eval_term_arg(buf, cur, state)?.as_integer();
            if pred != 0 {
                // Execute the If body.
                let sig = walk_term_list(buf, cur, pkg_end, state)?;
                *cur = pkg_end;
                // Skip an Else block if present.
                if *cur < end && *cur < buf.len() && buf[*cur] == ELSE_OP {
                    *cur += 1;
                    let else_start = *cur;
                    let else_len   = read_pkg_length(buf, cur)?;
                    *cur = else_start + else_len;
                }
                match sig {
                    Signal::None => {}
                    other => return Ok(other),
                }
            } else {
                // Skip If body.
                *cur = pkg_end;
                // Execute Else body if present.
                if *cur < end && *cur < buf.len() && buf[*cur] == ELSE_OP {
                    *cur += 1;
                    let else_start = *cur;
                    let else_len   = read_pkg_length(buf, cur)?;
                    let else_end   = else_start + else_len;
                    let sig = walk_term_list(buf, cur, else_end, state)?;
                    *cur = else_end;
                    match sig {
                        Signal::None => {}
                        other => return Ok(other),
                    }
                }
            }
        }

        // ── WhileOp ───────────────────────────────────────────────────────
        WHILE_OP => {
            let pkg_start = *cur;
            let pkg_len   = read_pkg_length(buf, cur)?;
            let pkg_end   = pkg_start + pkg_len;
            if pkg_end > end { return Err(AmlError::OutOfPkg); }

            // Remember where the predicate starts (just after PkgLength).
            let pred_start = *cur;
            let mut iters: u32 = 0;
            loop {
                if iters >= MAX_WHILE_ITERATIONS {
                    // Refuse infinite loop — break out.
                    break;
                }
                iters += 1;

                // Re-evaluate predicate each iteration.
                *cur = pred_start;
                let pred = eval_term_arg(buf, cur, state)?.as_integer();
                if pred == 0 { break; }

                // Walk body.
                let sig = walk_term_list(buf, cur, pkg_end, state)?;
                match sig {
                    Signal::None => {}
                    Signal::Continue => {
                        // Restart predicate evaluation — the outer loop
                        // will reset *cur = pred_start at the top.
                        continue;
                    }
                    Signal::Break => break,
                    Signal::Return(v) => {
                        *cur = pkg_end;
                        return Ok(Signal::Return(v));
                    }
                }
            }
            *cur = pkg_end;
        }

        // ── NotifyOp (0x86): SuperName TermArg ────────────────────────────
        0x86 => {
            let target = read_name_string(buf, cur, "\\")?;
            let value  = eval_term_arg(buf, cur, state)?.as_integer();
            crate::sync::dispatch_notify(&target, value);
        }

        // ── Extended opcodes (0x5B prefix) ────────────────────────────────
        0x5B => {
            let ext = next_u8(buf, cur)?;
            match ext {
                // StallOp: 0x5B 0x21  TermArg(microseconds)
                0x21 => {
                    let us = eval_term_arg(buf, cur, state)?.as_integer();
                    crate::sync::stall(us as u32);
                }
                // SleepOp: 0x5B 0x22  TermArg(milliseconds)
                0x22 => {
                    let ms = eval_term_arg(buf, cur, state)?.as_integer();
                    crate::sync::sleep(ms as u32);
                }
                // AcquireOp: 0x5B 0x23  SuperName  u16-timeout
                0x23 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let lo   = next_u8(buf, cur)? as u16;
                    let hi   = next_u8(buf, cur)? as u16;
                    let timeout = lo | (hi << 8);
                    // Result (0=acquired, 1=timeout) is discarded at
                    // statement level.
                    let _ = crate::sync::acquire(&name, timeout);
                }
                // SignalOp: 0x5B 0x24  SuperName
                0x24 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::signal(&name);
                }
                // WaitOp: 0x5B 0x25  SuperName  TermArg(timeout)
                0x25 => {
                    let name    = read_name_string(buf, cur, "\\")?;
                    let timeout = eval_term_arg(buf, cur, state)?.as_integer();
                    // Result discarded at statement level.
                    let _ = crate::sync::wait(&name, timeout as u16);
                }
                // ResetOp: 0x5B 0x26  SuperName
                0x26 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::reset(&name);
                }
                // ReleaseOp: 0x5B 0x27  SuperName
                0x27 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::release(&name);
                }
                // FatalOp: 0x5B 0x32  u8-type  u32-code  TermArg
                0x32 => {
                    let _ftype = next_u8(buf, cur)?;
                    // 4-byte code (little-endian).
                    let mut code = 0u32;
                    for i in 0..4u32 {
                        code |= (next_u8(buf, cur)? as u32) << (i * 8);
                    }
                    let _arg = eval_term_arg(buf, cur, state)?.as_integer();
                    // Log and continue — don't halt.
                    let _ = code;
                }
                // Unknown extended op — skip (best-effort).
                _ => {}
            }
        }

        // ── NameString as statement (method call or name access) ──────────
        b if is_name_lead(b) => {
            // Put byte back so read_name_string can consume it.
            *cur -= 1;
            let name = read_name_string(buf, cur, "\\")?;
            // If it resolves to a namespace node, it's either a method
            // invocation or a name access used as a statement.  We treat
            // both as a no-op at statement level (the value is discarded).
            let _ = name;
        }

        // ── Unknown: skip one byte ─────────────────────────────────────────
        _ => {
            // Best-effort: skip unrecognized opcodes.
        }
    }
    Ok(Signal::None)
}

/// Evaluate the next TermArg at `*cur`, returning its Value.
/// This is the recursive descent entry — it handles any opcode that
/// produces a value.
fn eval_term_arg(buf: &[u8], cur: &mut usize, state: &mut EvalState) -> Result<Value, AmlError> {
    let op = next_u8(buf, cur)?;
    let v = match op {
        // Constants
        ZERO_OP => Value::Integer(0),
        ONE_OP => Value::Integer(1),
        0xFF => Value::Integer(u64::MAX), // OnesOp

        BYTE_PREFIX => {
            let b = next_u8(buf, cur)?;
            Value::Integer(b as u64)
        }
        WORD_PREFIX => {
            let lo = next_u8(buf, cur)? as u64;
            let hi = next_u8(buf, cur)? as u64;
            Value::Integer(lo | (hi << 8))
        }
        DWORD_PREFIX => {
            let mut v = 0u64;
            for i in 0..4u64 {
                v |= (next_u8(buf, cur)? as u64) << (i * 8);
            }
            Value::Integer(v)
        }
        QWORD_PREFIX => {
            let mut v = 0u64;
            for i in 0..8u64 {
                v |= (next_u8(buf, cur)? as u64) << (i * 8);
            }
            Value::Integer(v)
        }
        STRING_PREFIX => {
            let mut s = String::new();
            loop {
                let c = next_u8(buf, cur)?;
                if c == 0 {
                    break;
                }
                s.push(c as char);
            }
            Value::String(s)
        }

        // Locals
        0x60 => state.local(0),
        0x61 => state.local(1),
        0x62 => state.local(2),
        0x63 => state.local(3),
        0x64 => state.local(4),
        0x65 => state.local(5),
        0x66 => state.local(6),
        0x67 => state.local(7),

        // Args
        0x68 => state.arg(0),
        0x69 => state.arg(1),
        0x6A => state.arg(2),
        0x6B => state.arg(3),
        0x6C => state.arg(4),
        0x6D => state.arg(5),
        0x6E => state.arg(6),

        // StoreOp as TermArg — (src → dest) → returns stored value
        STORE_OP => {
            let src = eval_term_arg(buf, cur, state)?;
            let r = src.clone();
            write_target(buf, cur, src, state)?;
            r
        }

        // Math as TermArg
        ADD_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_add(b));
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        SUBTRACT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_sub(b));
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        MULTIPLY_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a.wrapping_mul(b));
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        DIVIDE_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let rem = if b == 0 { 0 } else { a % b };
            let quot = if b == 0 { 0 } else { a / b };
            write_target(buf, cur, Value::Integer(rem), state)?;
            let r = Value::Integer(quot);
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        SHIFT_LEFT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(if b >= 64 { 0 } else { a << b });
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        SHIFT_RIGHT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(if b >= 64 { 0 } else { a >> b });
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        AND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a & b);
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        NAND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(!(a & b));
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        OR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a | b);
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        NOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(!(a | b));
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        XOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(a ^ b);
            write_target(buf, cur, r.clone(), state)?;
            r
        }
        // Increment/Decrement: DefIncrement := IncrementOp SuperName
        // The SuperName is both the source and the destination.
        INCREMENT_OP => {
            let (old, name) = read_super_name_value(buf, cur, state)?;
            let r = Value::Integer(old.as_integer().wrapping_add(1));
            write_super_name_back(name, r.clone(), state);
            r
        }
        DECREMENT_OP => {
            let (old, name) = read_super_name_value(buf, cur, state)?;
            let r = Value::Integer(old.as_integer().wrapping_sub(1));
            write_super_name_back(name, r.clone(), state);
            r
        }
        NOT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let r = Value::Integer(!a);
            write_target(buf, cur, r.clone(), state)?;
            r
        }

        // Logic
        LAND_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a != 0 && b != 0 { 1 } else { 0 })
        }
        LOR_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a != 0 || b != 0 { 1 } else { 0 })
        }
        LNOT_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a == 0 { 1 } else { 0 })
        }
        LEQUAL_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a == b { 1 } else { 0 })
        }
        LGREATER_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a > b { 1 } else { 0 })
        }
        LLESS_OP => {
            let a = eval_term_arg(buf, cur, state)?.as_integer();
            let b = eval_term_arg(buf, cur, state)?.as_integer();
            Value::Integer(if a < b { 1 } else { 0 })
        }

        // Buffer: BufferOp PkgLength SizeTermArg ByteList
        BUFFER_OP => {
            let pkg_start = *cur;
            let pkg_len = read_pkg_length(buf, cur)?;
            let pkg_end = pkg_start + pkg_len;
            // Size is a TermArg (may be any integer).
            let _size = eval_term_arg(buf, cur, state)?.as_integer();
            // Collect remaining bytes as the buffer payload.
            let data_len = pkg_end.saturating_sub(*cur);
            let mut data = Vec::with_capacity(data_len);
            for _ in 0..data_len {
                if *cur >= buf.len() {
                    break;
                }
                data.push(buf[*cur]);
                *cur += 1;
            }
            *cur = pkg_end.min(buf.len());
            Value::Buffer(data)
        }

        // Package: PackageOp PkgLength NumElements TermList
        PACKAGE_OP => {
            let pkg_start = *cur;
            let pkg_len = read_pkg_length(buf, cur)?;
            let pkg_end = pkg_start + pkg_len;
            let num_elems = next_u8(buf, cur)? as usize;
            let mut items = Vec::with_capacity(num_elems);
            // Evaluate up to num_elems TermArgs within pkg bounds.
            while *cur < pkg_end && items.len() < num_elems {
                let item = eval_term_arg(buf, cur, state)?;
                items.push(item);
            }
            *cur = pkg_end.min(buf.len());
            Value::Package(items)
        }

        // IfOp as TermArg (unusual but handle gracefully).
        IF_OP => {
            let pkg_start = *cur;
            let pkg_len = read_pkg_length(buf, cur)?;
            let pkg_end = pkg_start + pkg_len;
            let pred = eval_term_arg(buf, cur, state)?.as_integer();
            if pred != 0 {
                // Return last value produced by body — walk and collect.
                let mut last = Value::Integer(0);
                while *cur < pkg_end {
                    last = eval_term_arg(buf, cur, state)?;
                }
                *cur = pkg_end;
                if *cur < buf.len() && buf[*cur] == ELSE_OP {
                    *cur += 1;
                    let es = *cur;
                    let el = read_pkg_length(buf, cur)?;
                    *cur = es + el;
                }
                last
            } else {
                *cur = pkg_end;
                let mut last = Value::Integer(0);
                if *cur < buf.len() && buf[*cur] == ELSE_OP {
                    *cur += 1;
                    let es = *cur;
                    let el = read_pkg_length(buf, cur)?;
                    let ee = es + el;
                    while *cur < ee {
                        last = eval_term_arg(buf, cur, state)?;
                    }
                    *cur = ee;
                }
                last
            }
        }

        // NameString as TermArg — namespace lookup.
        b if is_name_lead(b) => {
            *cur -= 1;
            let name = read_name_string(buf, cur, "\\")?;
            // Look up the node and return its value. For Unparsed
            // bodies (Buffer / Package literals stored in Name
            // nodes) we follow the (offset, length) into the AML
            // store and run the stateless `decode_value` so a
            // `Return (PRTP)` after a `Method(_PRT)` returns the
            // actual Package, not Integer(0).
            //
            // The eval doesn't currently propagate the caller method's
            // scope down here, so a relative lookup of `PRTP` from
            // inside `\_SB.PCI0._PRT` first tries `\PRTP` (which
            // misses) and falls back to a suffix search across the
            // namespace. ACPI 6.5 §5.3 actually defines a
            // root-then-walk-parents algorithm; this approximation is
            // good enough for the patterns we see in QEMU + EDK2
            // firmware (PRTA / PRTP / PIR* siblings of `_PRT`) and
            // tightens up when full scope tracking lands.
            let resolved = crate::find_node(&name)
                .or_else(|| crate::find_node_by_suffix(&name));
            match resolved {
                Some(node) => match node.value {
                    Some(NameValue::Integer(v)) => Value::Integer(v),
                    Some(NameValue::String(s)) => Value::String(s),
                    Some(NameValue::Unparsed { offset, length }) if length > 0 => {
                        let mut body = alloc::vec![0u8; length];
                        let n = crate::copy_aml_bytes(offset, &mut body);
                        if n < length {
                            Value::Integer(0)
                        } else {
                            decode_value(&body).unwrap_or(Value::Integer(0))
                        }
                    }
                    _ => Value::Integer(0),
                },
                None => Value::Integer(0),
            }
        }

        // ── NotifyOp (0x86) as TermArg ────────────────────────────────────
        0x86 => {
            let target = read_name_string(buf, cur, "\\")?;
            let value = eval_term_arg(buf, cur, state)?.as_integer();
            crate::sync::dispatch_notify(&target, value);
            Value::Integer(0)
        }

        // ── Extended opcodes (0x5B prefix) as TermArg ─────────────────────
        0x5B => {
            let ext = next_u8(buf, cur)?;
            match ext {
                // StallOp: 0x5B 0x21  TermArg
                0x21 => {
                    let us = eval_term_arg(buf, cur, state)?.as_integer();
                    crate::sync::stall(us as u32);
                    Value::Integer(0)
                }
                // SleepOp: 0x5B 0x22  TermArg
                0x22 => {
                    let ms = eval_term_arg(buf, cur, state)?.as_integer();
                    crate::sync::sleep(ms as u32);
                    Value::Integer(0)
                }
                // AcquireOp: 0x5B 0x23  SuperName  u16-timeout
                // Returns Integer(0) = acquired, Integer(1) = timeout (ACPI spec).
                0x23 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let lo = next_u8(buf, cur)? as u16;
                    let hi = next_u8(buf, cur)? as u16;
                    let timeout = lo | (hi << 8);
                    match crate::sync::acquire(&name, timeout) {
                        Ok(true) => Value::Integer(0),  // acquired
                        Ok(false) => Value::Integer(1), // timeout
                        Err(_) => Value::Integer(1),
                    }
                }
                // SignalOp: 0x5B 0x24  SuperName
                0x24 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::signal(&name);
                    Value::Integer(0)
                }
                // WaitOp: 0x5B 0x25  SuperName  TermArg(timeout)
                // Returns Integer(0) = signaled, Integer(1) = timeout (ACPI spec).
                0x25 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let timeout = eval_term_arg(buf, cur, state)?.as_integer();
                    match crate::sync::wait(&name, timeout as u16) {
                        Ok(true) => Value::Integer(0),  // signaled
                        Ok(false) => Value::Integer(1), // timeout
                        Err(_) => Value::Integer(1),
                    }
                }
                // ResetOp: 0x5B 0x26  SuperName
                0x26 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::reset(&name);
                    Value::Integer(0)
                }
                // ReleaseOp: 0x5B 0x27  SuperName
                0x27 => {
                    let name = read_name_string(buf, cur, "\\")?;
                    let _ = crate::sync::release(&name);
                    Value::Integer(0)
                }
                // FatalOp: 0x5B 0x32  u8-type  u32-code  TermArg
                0x32 => {
                    let _ftype = next_u8(buf, cur)?;
                    let mut code = 0u32;
                    for i in 0..4u32 {
                        code |= (next_u8(buf, cur)? as u32) << (i * 8);
                    }
                    let _arg = eval_term_arg(buf, cur, state)?.as_integer();
                    let _ = code;
                    Value::Integer(0)
                }
                // Unknown — return 0.
                _ => Value::Integer(0),
            }
        }

        // Default: return 0.
        _ => Value::Integer(0),
    };
    Ok(v)
}

/// A reference to a SuperName (LocalN, ArgN, or named path).
/// Used by `Increment`/`Decrement` which need a read-modify-write.
enum SuperNameRef {
    Local(usize),
    Arg(usize),
    Named(String),
    Null,
}

/// Read the current value of a SuperName at `*cur` and consume the
/// SuperName specifier. Returns `(current_value, ref_for_write_back)`.
fn read_super_name_value(
    buf: &[u8],
    cur: &mut usize,
    state: &mut EvalState,
) -> Result<(Value, SuperNameRef), AmlError> {
    if *cur >= buf.len() {
        return Err(AmlError::Truncated);
    }
    let b = buf[*cur];
    match b {
        0x00 => {
            *cur += 1;
            Ok((Value::Integer(0), SuperNameRef::Null))
        }
        0x60..=0x67 => {
            let idx = (b - 0x60) as usize;
            *cur += 1;
            Ok((state.local(idx), SuperNameRef::Local(idx)))
        }
        0x68..=0x6E => {
            let idx = (b - 0x68) as usize;
            *cur += 1;
            Ok((state.arg(idx), SuperNameRef::Arg(idx)))
        }
        b if is_name_lead(b) => {
            let name = read_name_string(buf, cur, "\\")?;
            let val = match crate::find_node(&name) {
                Some(node) => match node.value {
                    Some(NameValue::Integer(v)) => Value::Integer(v),
                    Some(NameValue::String(s)) => Value::String(s),
                    _ => Value::Integer(0),
                },
                None => Value::Integer(0),
            };
            Ok((val, SuperNameRef::Named(name)))
        }
        _ => {
            *cur += 1;
            Ok((Value::Integer(0), SuperNameRef::Null))
        }
    }
}

/// Write back to a SuperNameRef (after read-modify-write).
fn write_super_name_back(name: SuperNameRef, value: Value, state: &mut EvalState) {
    match name {
        SuperNameRef::Local(i) => state.set_local(i, value),
        SuperNameRef::Arg(i) => state.set_arg(i, value),
        SuperNameRef::Named(p) => update_node_value(&p, value),
        SuperNameRef::Null => {}
    }
}

/// Write a value to the target encoded at `*cur`.
///
/// Target grammar: NullName (0x00) | LocalN | ArgN | NameString.
fn write_target(
    buf: &[u8],
    cur: &mut usize,
    value: Value,
    state: &mut EvalState,
) -> Result<(), AmlError> {
    if *cur >= buf.len() {
        return Err(AmlError::Truncated);
    }
    let b = buf[*cur];
    match b {
        0x00 => {
            *cur += 1;
        } // NullName — discard.
        0x60..=0x67 => {
            *cur += 1;
            state.set_local((b - 0x60) as usize, value);
        }
        0x68..=0x6E => {
            *cur += 1;
            state.set_arg((b - 0x68) as usize, value);
        }
        b if is_name_lead(b) => {
            // Named target — resolve and update namespace node value.
            let name = read_name_string(buf, cur, "\\")?;
            update_node_value(&name, value);
        }
        _ => {
            // Unexpected target byte — skip it.
            *cur += 1;
        }
    }
    Ok(())
}

/// Update a `Name` node's value in the global namespace.
fn update_node_value(path: &str, value: Value) {
    let nv = match value {
        Value::Integer(v) => NameValue::Integer(v),
        Value::String(s) => NameValue::String(s),
        Value::Buffer(b) => NameValue::Unparsed {
            offset: 0,
            length: b.len(),
        },
        Value::Package(p) => NameValue::Unparsed {
            offset: 0,
            length: p.len(),
        },
    };
    crate::update_name_value(path, nv);
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

#[inline]
fn next_u8(buf: &[u8], cur: &mut usize) -> Result<u8, AmlError> {
    buf.get(*cur)
        .copied()
        .map(|b| {
            *cur += 1;
            b
        })
        .ok_or(AmlError::Truncated)
}

/// PkgLength: 1-4 bytes. Returns the total length (including the PkgLength
/// bytes themselves). Mirrors the implementation in lib.rs.
fn read_pkg_length(buf: &[u8], cur: &mut usize) -> Result<usize, AmlError> {
    let first = next_u8(buf, cur)?;
    let extra = (first >> 6) & 0x3;
    let mut len: usize = if extra == 0 {
        (first & 0x3F) as usize
    } else {
        (first & 0x0F) as usize
    };
    for i in 0..extra {
        let next = next_u8(buf, cur)?;
        len |= (next as usize) << (4 + 8 * i as usize);
    }
    Ok(len)
}

/// True for bytes that can start a NameString (root char, parent prefix,
/// dual/multi name prefix, or first char of a NameSeg).
#[inline]
fn is_name_lead(b: u8) -> bool {
    matches!(
        b,
        ROOT_CHAR | PARENT_PREFIX | DUAL_NAME_PREFIX | MULTI_NAME_PREFIX
    ) || b.is_ascii_uppercase()
        || b == b'_'
}

/// Parse a NameString from `buf[*cur..]`, relative to `parent`.
/// Advances `*cur` past the consumed bytes.
fn read_name_string(buf: &[u8], cur: &mut usize, parent: &str) -> Result<String, AmlError> {
    let mut s = String::new();

    let first = *buf.get(*cur).ok_or(AmlError::Truncated)?;
    if first == ROOT_CHAR {
        *cur += 1;
        s.push('\\');
    } else {
        // Handle parent prefixes.
        let mut up = 0usize;
        while *cur < buf.len() && buf[*cur] == PARENT_PREFIX {
            *cur += 1;
            up += 1;
        }
        // Build absolute prefix by popping `up` segments off parent.
        let mut base = if parent.is_empty() {
            String::from("\\")
        } else {
            String::from(parent)
        };
        for _ in 0..up {
            if let Some(dot) = base.rfind('.') {
                base.truncate(dot);
            } else if base.len() > 1 {
                base.truncate(1);
            }
        }
        s.push_str(&base);
    }

    // Decode name-path portion.
    let pfx = *buf.get(*cur).ok_or(AmlError::Truncated)?;
    let (segs, consumed_pfx) = if pfx == DUAL_NAME_PREFIX {
        (2usize, 1usize)
    } else if pfx == MULTI_NAME_PREFIX {
        if *cur + 1 >= buf.len() {
            return Err(AmlError::Truncated);
        }
        let count = buf[*cur + 1] as usize;
        (count, 2usize)
    } else if pfx == 0x00 {
        // NullName.
        *cur += 1;
        return Ok(s);
    } else {
        (1usize, 0usize)
    };
    *cur += consumed_pfx;

    for i in 0..segs {
        if *cur + 4 > buf.len() {
            return Err(AmlError::Truncated);
        }
        let bytes = &buf[*cur..*cur + 4];
        *cur += 4;
        let c0 = bytes[0];
        if !(c0.is_ascii_uppercase() || c0 == b'_') {
            return Err(AmlError::BadNameSegment);
        }
        if i == 0 && !s.ends_with('\\') && !s.is_empty() {
            s.push('.');
        } else if i > 0 {
            s.push('.');
        }
        let mut end = 4;
        while end > 0 && bytes[end - 1] == b'_' {
            end -= 1;
        }
        if end == 0 {
            end = 1;
        }
        for c in &bytes[..end] {
            s.push(*c as char);
        }
    }
    Ok(s)
}
