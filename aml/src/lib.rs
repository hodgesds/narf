//! Minimum-viable AML namespace builder.
//!
//! AML (ACPI Machine Language) is the bytecode that DSDT + SSDT
//! tables carry. A real interpreter — ACPICA, uACPI — runs into
//! the tens of thousands of lines because it has to evaluate
//! arbitrary methods, walk OpRegions in SystemMemory / SystemIO /
//! PCI_Config, mediate Mutex / Event / Notify, and dispatch GPEs.
//!
//! Today's scope is intentionally narrow: parse the tables enough
//! to enumerate the *namespace* — the tree of declared objects
//! (Scope, Device, Processor, Method, Name, Mutex, PowerResource,
//! ThermalZone). Method bodies are skipped via PkgLength rather
//! than evaluated. Constant `Name(...)` values are resolved when
//! the body is a single-byte / DWord / QWord / String literal so
//! callers can read `_HID`, `_UID`, `_ADR`, `_BBN` and similar
//! flat-constant identifiers.
//!
//! What this enables today:
//!   - "How many devices does the platform declare?" — scheduler /
//!     observability shape questions.
//!   - "What's the _HID of `\\_SB.PCI0`?"
//!   - Foundation for the next layer, which adds method execution
//!     + OpRegion accessors + Resource templates.
//!
//! What it deliberately does NOT do:
//!   - Run methods. Method bodies are recorded as (offset, length)
//!     so a future pass can interpret them; today they're opaque.
//!   - Touch hardware. No `OpRegion(SystemIO, ...)` reads, no PCI
//!     config writes from AML.
//!   - Resolve forward references / cross-table fixups beyond the
//!     simple namespace lookup.
//!
//! Encoding: ACPI 6.5 §20 (AML grammar). PkgLength: §20.2.4.
//! NameString: §20.2.2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_acpi::{AcpiError, SdtHeader};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

pub mod eval;
pub mod oregion;
pub mod resource;

/// Run-time AML value, used by the method evaluator + Field
/// accessors. `Name(...)` flat-constant decoding stays in
/// `NameValue` for backwards compat; `Value` is the live form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Integer(u64),
    String(String),
    Buffer(Vec<u8>),
    Package(Vec<Value>),
}

impl Value {
    /// Coerce to integer per ACPI implicit conversion rules: integers
    /// stay as-is; strings/buffers fall back to 0 when they can't
    /// trivially parse. Future evaluator passes can refine.
    pub fn as_integer(&self) -> u64 {
        match self {
            Value::Integer(v) => *v,
            Value::Buffer(b)  => {
                let mut v = 0u64;
                for (i, byte) in b.iter().take(8).enumerate() {
                    v |= (*byte as u64) << (i * 8);
                }
                v
            }
            _ => 0,
        }
    }
}

/// Errors from AML parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmlError {
    /// AML byte stream truncated mid-decode.
    Truncated,
    /// PkgLength encoding was malformed.
    BadPkgLength,
    /// Tried to consume past a Pkg boundary.
    OutOfPkg,
    /// Underlying ACPI table walk failed.
    Acpi(AcpiError),
    /// AML stream contained a name segment that's not exactly 4
    /// 7-bit-ASCII chars (root char `\` and parent `^` are handled
    /// separately).
    BadNameSegment,
    /// DSDT was not present in the XSDT.
    NoDsdt,
}

impl From<AcpiError> for AmlError {
    fn from(e: AcpiError) -> Self { AmlError::Acpi(e) }
}

/// Kind of an AML namespace node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Scope,
    Device,
    Processor,
    PowerResource,
    ThermalZone,
    Method,
    /// `Name(...)` — flat-constant Name values store the literal in
    /// `value`.
    Name,
    Mutex,
    Event,
    Field,
    /// `OpRegion(...)` declared. Body unparsed today.
    OpRegion,
}

/// A simple constant value attached to a `Name(...)` node when the
/// body is a single literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameValue {
    /// `0` (ZeroOp), `1` (OneOp), `0xFF...` (OnesOp), or a typed
    /// integer literal.
    Integer(u64),
    /// A null-terminated AsciiString literal.
    String(String),
    /// Any non-trivial body we don't decode: `Buffer(...)`,
    /// `Package(...)`, computed expressions, etc. The (offset,
    /// length) lets a future evaluator pick it up.
    Unparsed { offset: usize, length: usize },
}

/// A flattened namespace node. The full path is the only identity
/// — children/parent links are derivable by string scan.
#[derive(Clone, Debug)]
pub struct AmlNode {
    pub path:  String,
    pub kind:  NodeKind,
    /// `Some` only when `kind == Name` and the body is a flat
    /// constant we managed to decode.
    pub value: Option<NameValue>,
    /// For `Method`: the offset within the source AML stream to
    /// the method body's first byte, plus the body length.
    /// `(0, 0)` for non-Method nodes.
    pub method_body: (usize, usize),
}

/// Backing storage. We collect every parsed node into one Vec
/// behind an `IrqSafeSpinLock` — namespace builds are one-shot at
/// boot and reads are typically cold.
#[derive(Debug, Default)]
struct Namespace {
    nodes: Vec<AmlNode>,
    /// Concatenated AML byte streams of every table walked, so
    /// Method body offsets resolve cheaply. Each node's
    /// `method_body.0` is an offset into this Vec when the node
    /// was registered from `walk_aml_table`.
    aml:   Vec<u8>,
}

pub(crate) static NAMESPACE: IrqSafeSpinLock<Namespace> =
    IrqSafeSpinLock::new(Namespace { nodes: Vec::new(), aml: Vec::new() });

/// Snapshot of a slice of the stored AML byte stream. Returns the
/// number of bytes copied. Out of range → 0.
pub fn copy_aml_bytes(offset: usize, out: &mut [u8]) -> usize {
    let g = NAMESPACE.lock();
    if offset >= g.aml.len() { return 0; }
    let n = (g.aml.len() - offset).min(out.len());
    out[..n].copy_from_slice(&g.aml[offset..offset + n]);
    n
}

/// Length of the stored AML byte stream.
pub fn aml_total_len() -> usize {
    NAMESPACE.lock().aml.len()
}

/// Snapshot of the current namespace. Returns the count.
pub fn copy_nodes(out: &mut Vec<AmlNode>) -> usize {
    let g = NAMESPACE.lock();
    out.clear();
    out.extend(g.nodes.iter().cloned());
    g.nodes.len()
}

/// Total number of nodes in the namespace.
pub fn node_count() -> usize {
    NAMESPACE.lock().nodes.len()
}

/// Find the first node with the given canonical path
/// (e.g. `"\\_SB.PCI0"`). Path comparison is exact.
pub fn find_node(path: &str) -> Option<AmlNode> {
    let g = NAMESPACE.lock();
    g.nodes.iter().find(|n| n.path == path).cloned()
}

/// Iterate every Device node, calling `f` with its path.
pub fn for_each_device<F: FnMut(&AmlNode)>(mut f: F) {
    let g = NAMESPACE.lock();
    for n in g.nodes.iter().filter(|n| n.kind == NodeKind::Device) {
        f(n);
    }
}

/// Walk the DSDT + every SSDT and build the namespace. Idempotent —
/// repeated calls clear the table and rebuild.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the FADT chain
/// it leads to must also be identity-mapped (the BSP's 1 GiB low
/// identity map covers all sane QEMU layouts).
pub unsafe fn parse_namespace(rsdp_phys: PhysAddr) -> Result<u32, AmlError> {
    {
        let mut g = NAMESPACE.lock();
        g.nodes.clear();
    }

    // SAFETY: caller assertion.
    let dsdt = unsafe { narf_acpi::parse_fadt_for_dsdt(rsdp_phys) }?;
    // SAFETY: identity-mapped per caller assertion.
    let n = unsafe { walk_aml_table(dsdt, "\\")? };

    let mut total = n;
    // SAFETY: caller assertion.
    unsafe {
        let mut e: Result<(), AmlError> = Ok(());
        let _ = narf_acpi::walk_ssdts(rsdp_phys, |phys, _hdr| {
            if e.is_err() { return; }
            // SAFETY: identity-mapped (covered by enclosing block).
            match walk_aml_table(phys, "\\") {
                Ok(c)  => total += c,
                Err(x) => e = Err(x),
            }
        })?;
        e?;
    }
    Ok(total)
}

/// Internal: parse one AML table (DSDT or SSDT) starting at the
/// given physical address, registering nodes under `root_path`.
/// Appends the table's AML bytes to the namespace-wide AML store
/// so `method_body` offsets are stable references into that store.
unsafe fn walk_aml_table(phys: u64, root_path: &str) -> Result<u32, AmlError> {
    // SAFETY: caller assertion.
    let total = unsafe {
        (phys as *const SdtHeader).read_unaligned().length as usize
    };
    if total <= 36 { return Ok(0); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(phys as *const u8, total) };
    let aml_slice = &body[36..];

    // Append into the global AML store, remember the base offset so
    // node body-offsets are absolute into that store.
    let base = {
        let mut g = NAMESPACE.lock();
        let b = g.aml.len();
        g.aml.extend_from_slice(aml_slice);
        b
    };

    let mut p = Parser::new(aml_slice);
    let mut count = 0u32;
    parse_term_list(&mut p, root_path, &mut count, aml_slice.len(), base)?;
    Ok(count)
}

// ── AML decoder ─────────────────────────────────────────────────────

const ZERO_OP: u8       = 0x00;
const ONE_OP: u8        = 0x01;
const NAME_OP: u8       = 0x08;
const BYTE_PREFIX: u8   = 0x0A;
const WORD_PREFIX: u8   = 0x0B;
const DWORD_PREFIX: u8  = 0x0C;
const STRING_PREFIX: u8 = 0x0D;
const QWORD_PREFIX: u8  = 0x0E;
const SCOPE_OP: u8      = 0x10;
const BUFFER_OP: u8     = 0x11;
const PACKAGE_OP: u8    = 0x12;
const VAR_PACKAGE_OP: u8= 0x13;
const METHOD_OP: u8     = 0x14;
const EXT_OP_PREFIX: u8 = 0x5B;
const ROOT_CHAR: u8     = b'\\';
const PARENT_PREFIX: u8 = b'^';
const DUAL_NAME_PREFIX: u8 = 0x2E;
const MULTI_NAME_PREFIX: u8 = 0x2F;
const ONES_OP: u8       = 0xFF;

// Extended opcodes (after 0x5B prefix).
const EXT_MUTEX_OP: u8       = 0x01;
const EXT_EVENT_OP: u8       = 0x02;
const EXT_OP_REGION_OP: u8   = 0x80;
const EXT_FIELD_OP: u8       = 0x81;
const EXT_DEVICE_OP: u8      = 0x82;
const EXT_PROCESSOR_OP: u8   = 0x83;
const EXT_POWER_RES_OP: u8   = 0x84;
const EXT_THERMAL_ZONE_OP: u8= 0x85;
const EXT_INDEX_FIELD_OP: u8 = 0x86;
const EXT_BANK_FIELD_OP: u8  = 0x87;

pub(crate) struct Parser<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    pub(crate) fn peek(&self) -> Option<u8> { self.buf.get(self.pos).copied() }

    pub(crate) fn read_u8(&mut self) -> Result<u8, AmlError> {
        let b = self.buf.get(self.pos).copied().ok_or(AmlError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Result<(), AmlError> {
        if self.pos + n > self.buf.len() { return Err(AmlError::Truncated); }
        self.pos += n;
        Ok(())
    }

    fn slice_n(&mut self, n: usize) -> Result<&'a [u8], AmlError> {
        if self.pos + n > self.buf.len() { return Err(AmlError::Truncated); }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// PkgLength: 1-4 bytes encoding the *total length* of a Pkg
/// (including the PkgLength bytes themselves). Top 2 bits of byte 0
/// are the `byte_count` (number of *additional* bytes, 0..=3).
/// When count==0, byte 0's low 6 bits are the length. Otherwise,
/// byte 0's low 4 bits are the low nibble + each extra byte
/// contributes 8 bits.
pub(crate) fn read_pkg_length(p: &mut Parser<'_>) -> Result<usize, AmlError> {
    let first = p.read_u8()?;
    let extra = (first >> 6) & 0x3;
    let mut len: usize = if extra == 0 {
        (first & 0x3F) as usize
    } else {
        (first & 0x0F) as usize
    };
    for i in 0..extra {
        let next = p.read_u8()?;
        len |= (next as usize) << (4 + 8 * i as usize);
    }
    Ok(len)
}

/// NameString: optional root/parent prefix, then either a single
/// 4-byte NameSeg, DualNamePrefix + 2 segs, MultiNamePrefix +
/// count + count*4 bytes, or NullName (0x00 — handled by caller's
/// peek). Returns the canonical path string assembled relative to
/// `parent`. NameSegs are stripped of trailing underscores (ACPI
/// leading-zero / underscore convention).
pub(crate) fn read_name_string(p: &mut Parser<'_>, parent: &str) -> Result<String, AmlError> {
    let mut s = String::new();
    let first = p.peek().ok_or(AmlError::Truncated)?;

    if first == ROOT_CHAR {
        p.skip(1)?;
        s.push('\\');
    } else {
        // Parent prefixes (`^`) — count then resolve against parent.
        let mut up = 0usize;
        while p.peek() == Some(PARENT_PREFIX) {
            p.skip(1)?;
            up += 1;
        }
        // Build absolute prefix from parent, popping `up` segments.
        let mut base = if parent.is_empty() { String::from("\\") } else { String::from(parent) };
        for _ in 0..up {
            // Drop one segment after the last '.'. If we hit root,
            // leave it as '\\'.
            if let Some(dot) = base.rfind('.') {
                base.truncate(dot);
            } else if base.len() > 1 {
                base.truncate(1); // back to "\\"
            }
        }
        s.push_str(&base);
    }

    // Now decode the name-path portion.
    let pfx = p.peek().ok_or(AmlError::Truncated)?;
    let segs: usize;
    let consumed_pfx: usize;
    if pfx == DUAL_NAME_PREFIX {
        segs = 2;
        consumed_pfx = 1;
    } else if pfx == MULTI_NAME_PREFIX {
        consumed_pfx = 2;
        // Multi: 0x2F, count_u8.
        if p.buf.len() < p.pos + 2 { return Err(AmlError::Truncated); }
        segs = p.buf[p.pos + 1] as usize;
    } else if pfx == 0 {
        // NullName: empty path.
        p.skip(1)?;
        return Ok(s);
    } else {
        segs = 1;
        consumed_pfx = 0;
    }
    p.skip(consumed_pfx)?;

    // Each segment: 4 bytes, [A-Z_][A-Z0-9_]{3}.
    if !s.is_empty() && !s.ends_with('\\') { /* parent already there */ }
    for i in 0..segs {
        let bytes = p.slice_n(4)?;
        // Validate first char.
        let c0 = bytes[0];
        if !(c0.is_ascii_uppercase() || c0 == b'_') {
            return Err(AmlError::BadNameSegment);
        }
        if i == 0 && !s.ends_with('\\') && !s.is_empty() {
            s.push('.');
        } else if i > 0 {
            s.push('.');
        }
        // Strip trailing underscore padding.
        let mut end = 4;
        while end > 0 && bytes[end - 1] == b'_' { end -= 1; }
        if end == 0 { end = 1; } // keep at least one char
        for c in &bytes[..end] {
            s.push(*c as char);
        }
    }
    Ok(s)
}

/// Resolve a NameString relative to `parent`, producing a fully-
/// qualified absolute path. NullName → `parent`.
pub(crate) fn full_path(name: String, parent: &str) -> String {
    if name.is_empty() {
        if parent.is_empty() { String::from("\\") } else { String::from(parent) }
    } else if name.starts_with('\\') {
        name
    } else if parent.is_empty() || parent == "\\" {
        let mut s = String::from("\\");
        s.push_str(&name);
        s
    } else {
        let mut s = String::from(parent);
        s.push('.');
        s.push_str(&name);
        s
    }
}

/// Try to decode a flat-constant value at the cursor. Returns the
/// value + advances the parser past it. Anything we don't decode
/// returns `Unparsed` and skips to `after_offset`.
pub(crate) fn try_read_simple_value(p: &mut Parser<'_>, after_offset: usize)
    -> Result<NameValue, AmlError>
{
    let start_pos = p.pos;
    let op = p.peek().ok_or(AmlError::Truncated)?;
    let val = match op {
        ZERO_OP => { p.skip(1)?; NameValue::Integer(0) }
        ONE_OP  => { p.skip(1)?; NameValue::Integer(1) }
        ONES_OP => { p.skip(1)?; NameValue::Integer(u64::MAX) }
        BYTE_PREFIX => {
            p.skip(1)?;
            let v = p.read_u8()?;
            NameValue::Integer(v as u64)
        }
        WORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(2)?;
            NameValue::Integer(u16::from_le_bytes([bytes[0], bytes[1]]) as u64)
        }
        DWORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(4)?;
            NameValue::Integer(u32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]) as u64)
        }
        QWORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(8)?;
            NameValue::Integer(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }
        STRING_PREFIX => {
            p.skip(1)?;
            // Null-terminated AsciiString.
            let mut s = String::new();
            loop {
                let c = p.read_u8()?;
                if c == 0 { break; }
                s.push(c as char);
            }
            NameValue::String(s)
        }
        _ => {
            // Skip past whatever this is, leave the body offset
            // for a future evaluator.
            let length = after_offset.saturating_sub(start_pos);
            p.pos = after_offset;
            return Ok(NameValue::Unparsed { offset: start_pos, length });
        }
    };
    // Snap to after_offset in case the body has trailing bytes
    // (e.g. when nested inside a larger pkg).
    if p.pos < after_offset {
        p.pos = after_offset;
    }
    Ok(val)
}

/// TermList: a sequence of TermObj's bounded by `end_offset` (an
/// absolute position into the parser's buffer). Each TermObj is
/// either a NamedObj (Scope/Device/Method/...) or a SimpleObj
/// (we skip over those — they're not namespace-creating).
fn parse_term_list(
    p:        &mut Parser<'_>,
    parent:   &str,
    count:    &mut u32,
    end_offset: usize,
    base:       usize,
) -> Result<(), AmlError> {
    while p.pos < end_offset {
        let op = match p.peek() {
            Some(b) => b,
            None    => return Ok(()),
        };
        match op {
            SCOPE_OP => {
                p.skip(1)?;
                let pkg_start = p.pos;
                let pkg_len   = read_pkg_length(p)?;
                let pkg_end   = pkg_start + pkg_len;
                let name      = read_name_string(p, parent)?;
                let path      = full_path(name, parent);
                push_node(AmlNode {
                    path: path.clone(),
                    kind: NodeKind::Scope,
                    value: None,
                    method_body: (0, 0),
                });
                *count += 1;
                parse_term_list(p, &path, count, pkg_end, base)?;
                if p.pos != pkg_end { p.pos = pkg_end; }
            }
            NAME_OP => {
                p.skip(1)?;
                let name = read_name_string(p, parent)?;
                let path = full_path(name, parent);
                // Body is a DataRefObject. Try to read a flat
                // constant; on anything else we record an Unparsed
                // value and skip to the next opcode-boundary
                // heuristic — there's no PkgLength on Name so we
                // peek the next byte after the value attempt.
                // For Unparsed we conservatively skip 1 byte to
                // avoid stalling; the parent's TermList loop will
                // re-anchor on the next valid op.
                let pos_before = p.pos;
                let body_after = (p.pos + 1).min(p.buf.len());
                let v = match try_read_simple_value(p, body_after) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        // Restore position; record Unparsed at this offset.
                        p.pos = pos_before;
                        Some(NameValue::Unparsed { offset: pos_before, length: 0 })
                    }
                };
                push_node(AmlNode {
                    path,
                    kind: NodeKind::Name,
                    value: v,
                    method_body: (0, 0),
                });
                *count += 1;
            }
            METHOD_OP => {
                p.skip(1)?;
                let pkg_start = p.pos;
                let pkg_len   = read_pkg_length(p)?;
                let pkg_end   = pkg_start + pkg_len;
                let name      = read_name_string(p, parent)?;
                let path      = full_path(name, parent);
                // 1 byte MethodFlags follows the name.
                let _flags    = p.read_u8()?;
                let body_off  = base + p.pos;
                let body_len  = pkg_end.saturating_sub(p.pos);
                push_node(AmlNode {
                    path,
                    kind: NodeKind::Method,
                    value: None,
                    method_body: (body_off, body_len),
                });
                *count += 1;
                p.pos = pkg_end;
            }
            EXT_OP_PREFIX => {
                let next = p.buf.get(p.pos + 1).copied().ok_or(AmlError::Truncated)?;
                p.skip(2)?;
                match next {
                    EXT_DEVICE_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        let name      = read_name_string(p, parent)?;
                        let path      = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::Device,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end { p.pos = pkg_end; }
                    }
                    EXT_PROCESSOR_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        let name      = read_name_string(p, parent)?;
                        let path      = full_path(name, parent);
                        // ProcID(1) + PblkAddr(4) + PblkLen(1) = 6 bytes.
                        p.skip(6)?;
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::Processor,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end { p.pos = pkg_end; }
                    }
                    EXT_POWER_RES_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        let name      = read_name_string(p, parent)?;
                        let path      = full_path(name, parent);
                        // SystemLevel(1) + ResourceOrder(2) = 3 bytes.
                        p.skip(3)?;
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::PowerResource,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end { p.pos = pkg_end; }
                    }
                    EXT_THERMAL_ZONE_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        let name      = read_name_string(p, parent)?;
                        let path      = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::ThermalZone,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end { p.pos = pkg_end; }
                    }
                    EXT_MUTEX_OP => {
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        // SyncFlags (1 byte).
                        p.skip(1)?;
                        push_node(AmlNode {
                            path,
                            kind: NodeKind::Mutex,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                    }
                    EXT_EVENT_OP => {
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path,
                            kind: NodeKind::Event,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                    }
                    EXT_OP_REGION_OP => {
                        // Parse NameString then register the namespace node.
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::OpRegion,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        // Try to decode RegionSpace + TermArg×2 and register
                        // the region. Returns true when both TermArgs were flat
                        // literals (parser is past the declaration, loop can
                        // continue). Returns false for complex TermArgs — bail
                        // so the outer pkg_end clamp re-anchors (same as the
                        // original behaviour for non-literal regions).
                        match oregion::parse_op_region_after_name(p, path) {
                            Ok(true)  => {} // parsed cleanly; continue loop
                            Ok(false) | Err(_) => return Ok(()),
                        }
                    }
                    EXT_FIELD_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        push_node(AmlNode {
                            path: full_path(String::new(), parent),
                            kind: NodeKind::Field,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        // Parse individual field entries and register them.
                        let _ = oregion::parse_field_body(p, parent, pkg_end);
                        p.pos = pkg_end;
                    }
                    EXT_INDEX_FIELD_OP | EXT_BANK_FIELD_OP => {
                        let pkg_start = p.pos;
                        let pkg_len   = read_pkg_length(p)?;
                        let pkg_end   = pkg_start + pkg_len;
                        push_node(AmlNode {
                            path: full_path(String::new(), parent),
                            kind: NodeKind::Field,
                            value: None,
                            method_body: (0, 0),
                        });
                        *count += 1;
                        p.pos = pkg_end;
                    }
                    _ => {
                        // Unknown extended opcode. Best-effort:
                        // bail out of this term list — anything we
                        // miss the caller's outer pkg-clamp catches.
                        return Ok(());
                    }
                }
            }
            BUFFER_OP | PACKAGE_OP | VAR_PACKAGE_OP => {
                // These are TermArg-class objects that can appear at
                // the top level only as part of a `Name(...)` body
                // (which we already consumed above) or as method
                // call args. At namespace-build time we treat them
                // as opaque — bail out so the outer caller can
                // re-anchor.
                return Ok(());
            }
            _ => {
                // Anything else: best-effort skip of one byte.
                // Unknown opcodes may carry PkgLength; without
                // decoding them we'd misalign. Bail to the outer
                // pkg-clamp.
                return Ok(());
            }
        }
    }
    Ok(())
}

fn push_node(n: AmlNode) {
    let mut g = NAMESPACE.lock();
    g.nodes.push(n);
}

/// Update the `value` field of the first `Name` node matching `path`.
/// Used by the method evaluator when `Store(v, named)` is executed.
pub(crate) fn update_name_value(path: &str, value: NameValue) {
    let mut g = NAMESPACE.lock();
    if let Some(node) = g.nodes.iter_mut().find(|n| n.path == path) {
        node.value = Some(value);
    }
}

/// Reset the namespace. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = NAMESPACE.lock();
    g.nodes.clear();
    g.aml.clear();
}

/// Test entry: parse a synthetic AML body (no SDT header) under the
/// given root path. Public so unit tests can validate decoder
/// pieces without cooking a full ACPI table chain.
#[doc(hidden)]
pub fn __parse_body_for_test(body: &[u8], root: &str) -> Result<u32, AmlError> {
    // Push body into AML store so method offsets resolve.
    let base = {
        let mut g = NAMESPACE.lock();
        let b = g.aml.len();
        g.aml.extend_from_slice(body);
        b
    };
    let mut p = Parser::new(body);
    let mut count = 0u32;
    parse_term_list(&mut p, root, &mut count, body.len(), base)?;
    Ok(count)
}
