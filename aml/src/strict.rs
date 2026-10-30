//! Bounded AML execution for callers that need a real firmware receipt.
//!
//! The compatibility evaluator remains unchanged. This opt-in interpreter
//! supports integer control/bit operations, exact scoped names, ordinary
//! methods, literal data and checked plain Fields. Unsupported semantics,
//! helper failures and hardware-access failures are errors, never zero/no-op.

use alloc::{string::String, vec::Vec};

use crate::{AmlError, AmlNode, NameValue, NodeKind, Value};

const FUEL: usize = 8192;
const DEPTH: usize = 16;
const MAX_BYTES: usize = 65_536;
const MAX_ELEMENTS: usize = 256;
const DEADLINE_NS: u64 = 5_000_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Aml(AmlError),
    Unsupported,
    Missing,
    Uninitialized,
    NoReturnValue,
    Arguments,
    Bounds,
    Budget,
    Field(crate::oregion::FieldAccessError),
}

impl From<AmlError> for Error {
    fn from(error: AmlError) -> Self {
        Self::Aml(error)
    }
}

/// A completed void firmware method is distinct from Return(Integer0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    Void,
    Value(Value),
}

impl Completion {
    fn required_value(self) -> Result<Value, Error> {
        match self {
            Self::Value(value) => Ok(value),
            Self::Void => Err(Error::NoReturnValue),
        }
    }
}

pub fn evaluate_object(path: &str, args: &[Value]) -> Result<Value, Error> {
    let node = crate::find_node(path).ok_or(Error::Missing)?;
    Context::new()?.node(node, args)?.required_value()
}

pub fn evaluate_method(path: &str, args: &[Value]) -> Result<Completion, Error> {
    let node = crate::find_node(path).ok_or(Error::Missing)?;
    if node.kind != NodeKind::Method {
        return Err(Error::Unsupported);
    }
    Context::new()?.node(node, args)
}

struct Context {
    fuel: usize,
    depth: usize,
    start: u64,
}

struct Frame {
    scope: String,
    args: Vec<Value>,
    locals: [Option<Value>; 8],
}

impl Frame {
    fn new(scope: &str, args: &[Value]) -> Self {
        Self {
            scope: String::from(scope),
            args: args.to_vec(),
            locals: core::array::from_fn(|_| None),
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            end: bytes.len(),
        }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let value = *self
            .bytes
            .get(self.pos)
            .filter(|_| self.pos < self.end)
            .ok_or(Error::Bounds)?;
        self.pos += 1;
        Ok(value)
    }

    fn package(&mut self) -> Result<usize, Error> {
        let start = self.pos;
        let length = super::read_pkg_length(&self.bytes[..self.end], &mut self.pos)?;
        let end = start.checked_add(length).ok_or(Error::Bounds)?;
        if end < self.pos || end > self.end {
            return Err(Error::Bounds);
        }
        Ok(end)
    }
}

enum Flow {
    Next,
    Return(Value),
    Break,
    Continue,
}

enum Target {
    Null,
    Local(usize),
    Arg(usize),
    Named(AmlNode),
}

impl Context {
    fn new() -> Result<Self, Error> {
        if crate::NAMESPACE.lock().integer_width != Some(64) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            fuel: FUEL,
            depth: 0,
            start: narf_time::wall::monotonic_ns(),
        })
    }

    fn step(&mut self) -> Result<(), Error> {
        if self.fuel == 0
            || narf_time::wall::monotonic_ns().saturating_sub(self.start) >= DEADLINE_NS
        {
            return Err(Error::Budget);
        }
        self.fuel -= 1;
        Ok(())
    }

    fn node(&mut self, node: AmlNode, args: &[Value]) -> Result<Completion, Error> {
        self.step()?;
        if self.depth == DEPTH {
            return Err(Error::Budget);
        }
        self.depth += 1;
        let result = self.node_inner(node, args);
        self.depth -= 1;
        // A final hardware operation can consume time after its entry-step
        // check. It cannot turn an expired method into a success receipt.
        if result.is_ok()
            && narf_time::wall::monotonic_ns().saturating_sub(self.start) >= DEADLINE_NS
        {
            return Err(Error::Budget);
        }
        result
    }

    fn node_inner(&mut self, node: AmlNode, args: &[Value]) -> Result<Completion, Error> {
        let scope = node.path.rsplit_once('.').map_or("\\", |(scope, _)| scope);
        match node.kind {
            NodeKind::Method => {
                // Serialized/SyncLevel methods need their own ACPI lock
                // owner. Refuse them until that contract is implemented.
                if node.method_flags & !7 != 0 || args.len() != usize::from(node.method_flags & 7) {
                    return Err(Error::Arguments);
                }
                let bytes = Self::bytes(node.method_body.0, node.method_body.1)?;
                let mut cursor = Cursor::new(&bytes);
                let mut frame = Frame::new(scope, args);
                match self.walk(&mut cursor, &mut frame)? {
                    Flow::Return(value) => Ok(Completion::Value(value)),
                    Flow::Next => Ok(Completion::Void),
                    Flow::Break | Flow::Continue => Err(Error::Unsupported),
                }
            }
            NodeKind::Name if args.is_empty() => self
                .stored(node.value.ok_or(Error::Missing)?, scope)
                .map(Completion::Value),
            NodeKind::Field if args.is_empty() => crate::oregion::read_field_checked(&node.path)
                .map(|value| Completion::Value(Value::Integer(value)))
                .map_err(Error::Field),
            _ => Err(Error::Unsupported),
        }
    }

    fn bytes(offset: usize, length: usize) -> Result<Vec<u8>, Error> {
        if length > MAX_BYTES {
            return Err(Error::Budget);
        }
        let mut bytes = alloc::vec![0; length];
        if crate::copy_aml_bytes(offset, &mut bytes) != length {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }

    fn stored(&mut self, stored: NameValue, scope: &str) -> Result<Value, Error> {
        self.step()?;
        if self.depth == DEPTH {
            return Err(Error::Budget);
        }
        self.depth += 1;
        let result = self.stored_inner(stored, scope);
        self.depth -= 1;
        result
    }

    fn stored_inner(&mut self, stored: NameValue, scope: &str) -> Result<Value, Error> {
        match stored {
            NameValue::Integer(value) => Ok(Value::Integer(value)),
            NameValue::String(value) if value.len() <= MAX_BYTES => Ok(Value::String(value)),
            NameValue::Buffer(value) if value.len() <= MAX_BYTES => Ok(Value::Buffer(value)),
            NameValue::Package(values) if values.len() <= MAX_ELEMENTS => values
                .into_iter()
                .map(|value| self.stored(value, scope))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Package),
            NameValue::Unparsed { offset, length } => {
                let bytes = Self::bytes(offset, length)?;
                let mut cursor = Cursor::new(&bytes);
                let value = self.arg(&mut cursor, &mut Frame::new(scope, &[]))?;
                if cursor.pos != cursor.end {
                    return Err(Error::Bounds);
                }
                Ok(value)
            }
            _ => Err(Error::Budget),
        }
    }

    fn name(cursor: &mut Cursor<'_>, scope: &str) -> Result<AmlNode, Error> {
        let first = *cursor.bytes.get(cursor.pos).ok_or(Error::Bounds)?;
        let absolute =
            super::read_name_string(&cursor.bytes[..cursor.end], &mut cursor.pos, scope)?;
        if !matches!(first, b'\\' | b'^' | 0x2e | 0x2f) {
            // Scope search applies only to an unprefixed single NameSeg.
            // Never use the compatibility evaluator's suffix fallback.
            let leaf = absolute
                .rsplit_once('.')
                .map_or_else(|| absolute.trim_start_matches('\\'), |(_, leaf)| leaf);
            let mut scope = scope;
            loop {
                let candidate = if scope == "\\" {
                    alloc::format!("\\{leaf}")
                } else {
                    alloc::format!("{scope}.{leaf}")
                };
                if let Some(node) = crate::find_node(&candidate) {
                    return Ok(node);
                }
                if scope == "\\" {
                    break;
                }
                scope = scope.rsplit_once('.').map_or("\\", |(parent, _)| parent);
            }
            Err(Error::Missing)
        } else {
            crate::find_node(&absolute).ok_or(Error::Missing)
        }
    }

    fn target(cursor: &mut Cursor<'_>, frame: &Frame) -> Result<Target, Error> {
        let byte = cursor.byte()?;
        match byte {
            0 => Ok(Target::Null),
            0x60..=0x67 => Ok(Target::Local(usize::from(byte - 0x60))),
            0x68..=0x6e if usize::from(byte - 0x68) < frame.args.len() => {
                Ok(Target::Arg(usize::from(byte - 0x68)))
            }
            byte if super::is_name_lead(byte) => {
                cursor.pos -= 1;
                Self::name(cursor, &frame.scope).map(Target::Named)
            }
            _ => Err(Error::Arguments),
        }
    }

    fn write(target: Target, value: Value, frame: &mut Frame) -> Result<(), Error> {
        match target {
            Target::Null => Ok(()),
            Target::Local(index) => {
                frame.locals[index] = Some(value);
                Ok(())
            }
            Target::Arg(index) => {
                frame.args[index] = value;
                Ok(())
            }
            Target::Named(node) if node.kind == NodeKind::Name => {
                if !matches!(
                    (&node.value, &value),
                    (Some(NameValue::Integer(_)), Value::Integer(_))
                ) {
                    return Err(Error::Unsupported);
                }
                crate::update_name_value(&node.path, super::value_to_name_value(value));
                Ok(())
            }
            Target::Named(node) if node.kind == NodeKind::Field => {
                crate::oregion::write_field_checked(&node.path, integer(value)?)
                    .map_err(Error::Field)
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn walk(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Flow, Error> {
        self.step()?;
        if self.depth == DEPTH {
            return Err(Error::Budget);
        }
        self.depth += 1;
        let result = self.walk_inner(cursor, frame);
        self.depth -= 1;
        result
    }

    fn walk_inner(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Flow, Error> {
        while cursor.pos < cursor.end {
            self.step()?;
            match cursor.byte()? {
                0xa3 => {}
                0xa4 => return self.arg(cursor, frame).map(Flow::Return),
                0xa5 => return Ok(Flow::Break),
                0x9f => return Ok(Flow::Continue),
                0xa0 => {
                    let end = cursor.package()?;
                    let outer = cursor.end;
                    cursor.end = end;
                    let predicate = integer(self.arg(cursor, frame)?)? != 0;
                    if predicate {
                        let flow = self.walk(cursor, frame)?;
                        if !matches!(flow, Flow::Next) {
                            return Ok(flow);
                        }
                    }
                    cursor.pos = end;
                    cursor.end = outer;
                    if cursor
                        .bytes
                        .get(cursor.pos)
                        .is_some_and(|byte| *byte == 0xa1)
                        && cursor.pos < outer
                    {
                        cursor.pos += 1;
                        let else_end = cursor.package()?;
                        if !predicate {
                            cursor.end = else_end;
                            let flow = self.walk(cursor, frame)?;
                            if !matches!(flow, Flow::Next) {
                                return Ok(flow);
                            }
                        }
                        cursor.pos = else_end;
                        cursor.end = outer;
                    }
                }
                0xa2 => {
                    let end = cursor.package()?;
                    let start = cursor.pos;
                    let outer = cursor.end;
                    cursor.end = end;
                    loop {
                        cursor.pos = start;
                        cursor.end = end;
                        if integer(self.arg(cursor, frame)?)? == 0 {
                            break;
                        }
                        match self.walk(cursor, frame)? {
                            Flow::Return(value) => return Ok(Flow::Return(value)),
                            Flow::Break => break,
                            Flow::Next | Flow::Continue => {}
                        }
                    }
                    cursor.pos = end;
                    cursor.end = outer;
                }
                op => {
                    cursor.pos -= 1;
                    if super::is_name_lead(op) {
                        self.named(cursor, frame)?;
                    } else {
                        self.arg(cursor, frame)?;
                    }
                }
            }
        }
        Ok(Flow::Next)
    }

    fn named(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Completion, Error> {
        let node = Self::name(cursor, &frame.scope)?;
        let count = if node.kind == NodeKind::Method {
            usize::from(node.method_flags & 7)
        } else {
            0
        };
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            args.push(self.arg(cursor, frame)?);
        }
        self.node(node, &args)
    }

    fn arg(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Value, Error> {
        self.step()?;
        if self.depth == DEPTH {
            return Err(Error::Budget);
        }
        self.depth += 1;
        let result = self.arg_inner(cursor, frame);
        self.depth -= 1;
        result
    }

    fn arg_inner(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Value, Error> {
        let op = cursor.byte()?;
        match op {
            0 => Ok(Value::Integer(0)),
            1 => Ok(Value::Integer(1)),
            0xff => Ok(Value::Integer(u64::MAX)),
            0x0a | 0x0b | 0x0c | 0x0e => {
                let count = match op {
                    0x0a => 1,
                    0x0b => 2,
                    0x0c => 4,
                    _ => 8,
                };
                let mut value = 0;
                for byte in 0..count {
                    value |= u64::from(cursor.byte()?) << (byte * 8);
                }
                Ok(Value::Integer(value))
            }
            0x0d => {
                let start = cursor.pos;
                while cursor.byte()? != 0 {
                    if cursor.pos - start > MAX_BYTES {
                        return Err(Error::Budget);
                    }
                }
                core::str::from_utf8(&cursor.bytes[start..cursor.pos - 1])
                    .map(|s| Value::String(String::from(s)))
                    .map_err(|_| Error::Unsupported)
            }
            0x60..=0x67 => frame.locals[usize::from(op - 0x60)]
                .clone()
                .ok_or(Error::Uninitialized),
            0x68..=0x6e => frame
                .args
                .get(usize::from(op - 0x68))
                .cloned()
                .ok_or(Error::Arguments),
            0x11 | 0x12 => {
                let end = cursor.package()?;
                let outer = cursor.end;
                cursor.end = end;
                let value = if op == 0x11 {
                    let size = usize::try_from(integer(self.arg(cursor, frame)?)?)
                        .map_err(|_| Error::Budget)?;
                    if size > MAX_BYTES || end - cursor.pos > size {
                        return Err(Error::Bounds);
                    }
                    let mut bytes = alloc::vec![0; size];
                    bytes[..end - cursor.pos].copy_from_slice(&cursor.bytes[cursor.pos..end]);
                    cursor.pos = end;
                    Value::Buffer(bytes)
                } else {
                    let count = usize::from(cursor.byte()?);
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        values.push(self.arg(cursor, frame)?);
                    }
                    if cursor.pos != end {
                        return Err(Error::Bounds);
                    }
                    Value::Package(values)
                };
                cursor.end = outer;
                Ok(value)
            }
            0x70 => {
                let value = self.arg(cursor, frame)?;
                let target = Self::target(cursor, frame)?;
                Self::write(target, value.clone(), frame)?;
                Ok(value)
            }
            0x72 | 0x74 | 0x77 | 0x79..=0x7f => {
                let a = integer(self.arg(cursor, frame)?)?;
                let b = integer(self.arg(cursor, frame)?)?;
                let value = match op {
                    0x72 => a.wrapping_add(b),
                    0x74 => a.wrapping_sub(b),
                    0x77 => a.wrapping_mul(b),
                    0x79 => a
                        .checked_shl(u32::try_from(b).unwrap_or(u32::MAX))
                        .unwrap_or(0),
                    0x7a => a
                        .checked_shr(u32::try_from(b).unwrap_or(u32::MAX))
                        .unwrap_or(0),
                    0x7b => a & b,
                    0x7c => !(a & b),
                    0x7d => a | b,
                    0x7e => !(a | b),
                    _ => a ^ b,
                };
                let value = Value::Integer(value);
                Self::write(Self::target(cursor, frame)?, value.clone(), frame)?;
                Ok(value)
            }
            0x80 => {
                let value = Value::Integer(!integer(self.arg(cursor, frame)?)?);
                Self::write(Self::target(cursor, frame)?, value.clone(), frame)?;
                Ok(value)
            }
            0x90..=0x95 => {
                let a = self.arg(cursor, frame)?;
                if op == 0x92 {
                    return Ok(aml_bool(integer(a)? == 0));
                }
                let b = self.arg(cursor, frame)?;
                let result = if op == 0x93 {
                    match (a, b) {
                        (Value::Integer(a), Value::Integer(b)) => a == b,
                        (Value::String(a), Value::String(b)) => a == b,
                        (Value::Buffer(a), Value::Buffer(b)) => a == b,
                        _ => return Err(Error::Unsupported),
                    }
                } else {
                    let (a, b) = (integer(a)?, integer(b)?);
                    match op {
                        0x90 => a != 0 && b != 0,
                        0x91 => a != 0 || b != 0,
                        0x94 => a > b,
                        _ => a < b,
                    }
                };
                Ok(aml_bool(result))
            }
            byte if super::is_name_lead(byte) => {
                cursor.pos -= 1;
                self.named(cursor, frame)?.required_value()
            }
            _ => Err(Error::Unsupported),
        }
    }
}

fn integer(value: Value) -> Result<u64, Error> {
    match value {
        Value::Integer(value) => Ok(value),
        _ => Err(Error::Unsupported),
    }
}

fn aml_bool(value: bool) -> Value {
    Value::Integer(if value { u64::MAX } else { 0 })
}

#[cfg(feature = "kernel-test")]
#[path = "strict_tests.rs"]
mod tests;
