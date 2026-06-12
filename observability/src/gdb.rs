//! GDB remote-serial stub.
//!
//! Spec: `observability/specification/spec.md` (Stage-4: GDB remote
//! stub, watchpoint install). Implements the subset of RSP needed
//! to attach a host `gdb`:
//!
//! - `+` / `-` ACK framing
//! - `qSupported:feature-list` → `PacketSize=...` reply
//! - `?` → halt-reason (`S05`, treat as SIGTRAP)
//! - `g` / `G` → read / write GPRs
//! - `m addr,len` → read memory
//! - `M addr,len:hex` → write memory
//! - `s [addr]` / `c [addr]` → step / continue (returns from
//!   `process_packet` after the reply — caller resumes the target)
//! - `Z0` / `z0` → software breakpoint install / remove (treated as
//!   ack-only — full software-bp injection is `arch/` work)
//!
//! Linux reference: `kernel/debug/gdbstub.c` —
//! https://elixir.bootlin.com/linux/latest/source/kernel/debug/gdbstub.c
//! (GPL-2.0-or-later; we can cite + adapt under the post-relicense
//! NARF terms).
//!
//! Transport: any byte-stream that implements [`GdbTransport`]. The
//! production wire is COM1 (port 0x3F8) via `narf-console`; tests
//! use an in-memory `VecTransport`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{ArchRegs, Debugger};

/// GDB RSP wire-level error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GdbError {
    /// Cap epoch check failed.
    AuthorityRevoked,
    /// Packet didn't parse — bad `$`/`#` framing or checksum mismatch.
    MalformedPacket,
    /// Command recognised but not handled (the empty `$#00` reply
    /// gets sent on the wire; this variant surfaces to internal
    /// callers).
    Unsupported,
    /// Transport reported EOF before a complete packet was read,
    /// e.g. host disconnected.
    Disconnected,
    /// Reserved — kept so existing callers of the no-transport
    /// `attach` shim keep compiling. The real entry point is
    /// [`run_session`] / [`attach_com1`].
    NotImplemented,
}

impl From<CapError> for GdbError {
    fn from(_: CapError) -> Self {
        GdbError::AuthorityRevoked
    }
}

/// A decoded RSP command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GdbCommand {
    /// `g` — read all general-purpose registers.
    ReadRegs,
    /// `G <hex>` — write general-purpose registers.
    WriteRegs(Vec<u8>),
    /// `m addr,length` — read memory.
    ReadMem { addr: u64, len: u32 },
    /// `M addr,length:hex` — write memory.
    WriteMem { addr: u64, bytes: Vec<u8> },
    /// `c [addr]` — continue.
    Continue { addr: Option<u64> },
    /// `s [addr]` — single-step.
    Step { addr: Option<u64> },
    /// `Z0 addr,kind` — insert software breakpoint.
    InsertBp { addr: u64, kind: u8 },
    /// `z0 addr,kind` — remove software breakpoint.
    RemoveBp { addr: u64, kind: u8 },
    /// `?` — halt reason query.
    HaltReason,
    /// `qSupported:feature-list` — feature negotiation.
    QSupported(String),
}

/// A framed RSP packet — `$payload#checksum`. The constructor
/// computes the checksum so callers never hand-wire the `#XX`
/// footer.
#[derive(Clone, Debug)]
pub struct GdbPacket {
    pub payload: String,
    pub checksum: u8,
}

impl GdbPacket {
    /// Frame `payload` into a packet with a valid `#XX` checksum.
    pub fn new(payload: &str) -> Self {
        let mut sum: u8 = 0;
        for b in payload.as_bytes() {
            sum = sum.wrapping_add(*b);
        }
        Self {
            payload: String::from(payload),
            checksum: sum,
        }
    }

    /// Verify `self.checksum` matches `payload`'s byte-sum.
    pub fn checksum_valid(&self) -> bool {
        let mut sum: u8 = 0;
        for b in self.payload.as_bytes() {
            sum = sum.wrapping_add(*b);
        }
        sum == self.checksum
    }

    /// Wire-format the packet: `$payload#XX` with `XX` as lowercase
    /// hex.
    pub fn to_wire(&self) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        s.push('$');
        s.push_str(&self.payload);
        s.push('#');
        let _ = write!(s, "{:02x}", self.checksum);
        s
    }
}

/// Byte-stream transport for the stub. Implementors only have to
/// provide blocking byte read + write — packet framing, ACK
/// handling, hex encoding, etc. all happen above this trait.
pub trait GdbTransport {
    /// Blocking read of one byte. Returns `None` on disconnect.
    fn read_byte(&mut self) -> Option<u8>;
    /// Blocking write of one byte. Returns `false` on disconnect.
    fn write_byte(&mut self, b: u8) -> bool;

    /// Convenience: write a whole packet on the wire, including
    /// `$...#XX` framing.
    fn send_packet(&mut self, payload: &str) -> bool {
        let pkt = GdbPacket::new(payload);
        let wire = pkt.to_wire();
        for b in wire.as_bytes() {
            if !self.write_byte(*b) {
                return false;
            }
        }
        true
    }
}

/// Halt reason — what the kernel stopped on before the stub took
/// over. Surfaces as the `?` reply.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HaltReason {
    /// Generic SIGTRAP — `S05`. Used for breakpoints, single-step
    /// completion, manual entry via panic hook.
    SigTrap,
    /// Bus / page-fault — `S0B` (SIGSEGV).
    SigSegv,
    /// Illegal instruction — `S04` (SIGILL).
    SigIll,
}

impl HaltReason {
    fn signal_byte(self) -> u8 {
        match self {
            HaltReason::SigTrap => 0x05,
            HaltReason::SigSegv => 0x0B,
            HaltReason::SigIll => 0x04,
        }
    }
}

/// Stub session state. Holds the live register snapshot the host
/// is debugging plus the most-recent halt reason. A real attach
/// freezes the target before constructing this; tests synthesise
/// the registers directly.
#[derive(Clone, Debug)]
pub struct GdbSession {
    pub regs: ArchRegs,
    pub halt_reason: HaltReason,
    /// Number of packets processed since attach — surfaces for
    /// the smoke tests so they can verify the dispatcher ran.
    pub packets_handled: u32,
}

impl GdbSession {
    pub fn new(regs: ArchRegs, halt_reason: HaltReason) -> Self {
        Self {
            regs,
            halt_reason,
            packets_handled: 0,
        }
    }
}

// ── Packet parsing ─────────────────────────────────────────────────

/// Parse an RSP payload (without the `$...#XX` framing) into a
/// [`GdbCommand`].
pub fn parse_command(payload: &str) -> Result<GdbCommand, GdbError> {
    let bytes = payload.as_bytes();
    if bytes.is_empty() {
        return Err(GdbError::MalformedPacket);
    }
    match bytes[0] {
        b'?' => Ok(GdbCommand::HaltReason),
        b'g' => Ok(GdbCommand::ReadRegs),
        b'G' => {
            let regs = hex_to_bytes(&payload[1..])?;
            Ok(GdbCommand::WriteRegs(regs))
        }
        b'm' => {
            // m<addr>,<len>
            let rest = &payload[1..];
            let mut parts = rest.split(',');
            let addr_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let len_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let addr = u64::from_str_radix(addr_str, 16).map_err(|_| GdbError::MalformedPacket)?;
            let len = u32::from_str_radix(len_str, 16).map_err(|_| GdbError::MalformedPacket)?;
            Ok(GdbCommand::ReadMem { addr, len })
        }
        b'M' => {
            // M<addr>,<len>:<hex>
            let rest = &payload[1..];
            let (head, hex) = rest.split_once(':').ok_or(GdbError::MalformedPacket)?;
            let mut parts = head.split(',');
            let addr_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let _len_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let addr = u64::from_str_radix(addr_str, 16).map_err(|_| GdbError::MalformedPacket)?;
            let bytes = hex_to_bytes(hex)?;
            Ok(GdbCommand::WriteMem { addr, bytes })
        }
        b'c' | b's' => {
            let rest = &payload[1..];
            let addr = if rest.is_empty() {
                None
            } else {
                Some(u64::from_str_radix(rest, 16).map_err(|_| GdbError::MalformedPacket)?)
            };
            if bytes[0] == b'c' {
                Ok(GdbCommand::Continue { addr })
            } else {
                Ok(GdbCommand::Step { addr })
            }
        }
        b'Z' | b'z' => {
            // {Z,z}<type>,<addr>,<kind>. We only handle type 0 (software bp).
            let rest = &payload[1..];
            if !rest.starts_with("0,") {
                return Err(GdbError::Unsupported);
            }
            let rest = &rest[2..];
            let mut parts = rest.split(',');
            let addr_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let kind_str = parts.next().ok_or(GdbError::MalformedPacket)?;
            let addr = u64::from_str_radix(addr_str, 16).map_err(|_| GdbError::MalformedPacket)?;
            let kind = u8::from_str_radix(kind_str, 16).map_err(|_| GdbError::MalformedPacket)?;
            if bytes[0] == b'Z' {
                Ok(GdbCommand::InsertBp { addr, kind })
            } else {
                Ok(GdbCommand::RemoveBp { addr, kind })
            }
        }
        b'q' => {
            // qSupported:feature-list or other queries we don't handle.
            if payload.starts_with("qSupported") {
                let after = payload.strip_prefix("qSupported").unwrap_or("");
                let features = after.strip_prefix(':').unwrap_or("");
                Ok(GdbCommand::QSupported(String::from(features)))
            } else {
                Err(GdbError::Unsupported)
            }
        }
        _ => Err(GdbError::Unsupported),
    }
}

/// Read a framed packet from `transport` and return the payload (no
/// `$`/`#`/`checksum`). Sends `+` on a checksum match, `-` and
/// retries on mismatch. A bare `0x03` byte (Ctrl-C from the host) is
/// returned as the one-byte payload `"\x03"` so the dispatcher can
/// promote it to a halt-reason reply.
pub fn read_packet<T: GdbTransport>(transport: &mut T) -> Result<String, GdbError> {
    loop {
        // Spin to `$` — gdb may pre-send `+` ack bytes or stray noise.
        loop {
            let b = transport.read_byte().ok_or(GdbError::Disconnected)?;
            if b == b'$' {
                break;
            }
            if b == 0x03 {
                return Ok(String::from("\x03"));
            }
        }
        let mut payload = String::new();
        let mut sum: u8 = 0;
        loop {
            let b = transport.read_byte().ok_or(GdbError::Disconnected)?;
            if b == b'#' {
                break;
            }
            sum = sum.wrapping_add(b);
            payload.push(b as char);
        }
        let hi = transport.read_byte().ok_or(GdbError::Disconnected)?;
        let lo = transport.read_byte().ok_or(GdbError::Disconnected)?;
        let want = match (hex_nibble(hi), hex_nibble(lo)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => {
                transport.write_byte(b'-');
                continue;
            }
        };
        if want != sum {
            transport.write_byte(b'-');
            continue;
        }
        transport.write_byte(b'+');
        return Ok(payload);
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, GdbError> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(GdbError::MalformedPacket);
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i]).ok_or(GdbError::MalformedPacket)?;
        let lo = hex_nibble(b[i + 1]).ok_or(GdbError::MalformedPacket)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ── Register packing ───────────────────────────────────────────────
//
// gdb's `g` reply for x86_64 packs the register file little-endian:
// rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8..r15 (each u64), rip
// (u64), then eflags(u32), cs/ss/ds/es/fs/gs (each u32). We pack the
// fields we track in `ArchRegs` and zero-fill ds/es/fs/gs.

#[cfg(target_arch = "x86_64")]
fn encode_regs(regs: &ArchRegs) -> String {
    let mut buf = Vec::with_capacity(8 * 17 + 4 * 7);
    let gprs = [
        regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.rsp, regs.r8,
        regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rip,
    ];
    for r in gprs {
        buf.extend_from_slice(&r.to_le_bytes());
    }
    buf.extend_from_slice(&(regs.rflags as u32).to_le_bytes());
    buf.extend_from_slice(&(regs.cs as u32).to_le_bytes());
    buf.extend_from_slice(&(regs.ss as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    bytes_to_hex(&buf)
}

#[cfg(target_arch = "aarch64")]
fn encode_regs(regs: &ArchRegs) -> String {
    // gdb's aarch64 layout: x0..x30, sp, pc (u64), pstate (u32).
    let mut buf = Vec::with_capacity(8 * 33 + 4);
    for r in &regs.x {
        buf.extend_from_slice(&r.to_le_bytes());
    }
    buf.extend_from_slice(&regs.sp.to_le_bytes());
    buf.extend_from_slice(&regs.pc.to_le_bytes());
    buf.extend_from_slice(&(regs.pstate as u32).to_le_bytes());
    bytes_to_hex(&buf)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn encode_regs(_regs: &ArchRegs) -> String {
    String::new()
}

#[cfg(target_arch = "x86_64")]
fn decode_regs(bytes: &[u8]) -> Option<ArchRegs> {
    let mut regs = ArchRegs::default();
    let mut i = 0;
    let take_u64 = |buf: &[u8], i: &mut usize| -> Option<u64> {
        if *i + 8 > buf.len() {
            return None;
        }
        let v = u64::from_le_bytes(buf[*i..*i + 8].try_into().ok()?);
        *i += 8;
        Some(v)
    };
    let take_u32 = |buf: &[u8], i: &mut usize| -> Option<u32> {
        if *i + 4 > buf.len() {
            return None;
        }
        let v = u32::from_le_bytes(buf[*i..*i + 4].try_into().ok()?);
        *i += 4;
        Some(v)
    };
    regs.rax = take_u64(bytes, &mut i)?;
    regs.rbx = take_u64(bytes, &mut i)?;
    regs.rcx = take_u64(bytes, &mut i)?;
    regs.rdx = take_u64(bytes, &mut i)?;
    regs.rsi = take_u64(bytes, &mut i)?;
    regs.rdi = take_u64(bytes, &mut i)?;
    regs.rbp = take_u64(bytes, &mut i)?;
    regs.rsp = take_u64(bytes, &mut i)?;
    regs.r8 = take_u64(bytes, &mut i)?;
    regs.r9 = take_u64(bytes, &mut i)?;
    regs.r10 = take_u64(bytes, &mut i)?;
    regs.r11 = take_u64(bytes, &mut i)?;
    regs.r12 = take_u64(bytes, &mut i)?;
    regs.r13 = take_u64(bytes, &mut i)?;
    regs.r14 = take_u64(bytes, &mut i)?;
    regs.r15 = take_u64(bytes, &mut i)?;
    regs.rip = take_u64(bytes, &mut i)?;
    regs.rflags = take_u32(bytes, &mut i)? as u64;
    regs.cs = take_u32(bytes, &mut i)? as u64;
    regs.ss = take_u32(bytes, &mut i)? as u64;
    Some(regs)
}

#[cfg(target_arch = "aarch64")]
fn decode_regs(bytes: &[u8]) -> Option<ArchRegs> {
    let mut regs = ArchRegs::default();
    let mut i = 0;
    for x in &mut regs.x {
        if i + 8 > bytes.len() {
            return None;
        }
        *x = u64::from_le_bytes(bytes[i..i + 8].try_into().ok()?);
        i += 8;
    }
    if i + 8 + 8 + 4 > bytes.len() {
        return None;
    }
    regs.sp = u64::from_le_bytes(bytes[i..i + 8].try_into().ok()?);
    i += 8;
    regs.pc = u64::from_le_bytes(bytes[i..i + 8].try_into().ok()?);
    i += 8;
    regs.pstate = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as u64;
    Some(regs)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn decode_regs(_bytes: &[u8]) -> Option<ArchRegs> {
    None
}

// ── Memory peek (test-shimmable) ───────────────────────────────────
//
// In production we use `core::ptr::read_volatile` against the
// caller-supplied virtual address. Tests install a synthetic
// region via [`__test_install_memory`] so the dispatcher can be
// exercised without poking real kernel memory.

type MemoryPeekFn = fn(addr: u64, len: u32) -> Option<Vec<u8>>;
type MemoryPokeFn = fn(addr: u64, bytes: &[u8]) -> bool;

static MEM_PEEK: IrqSafeSpinLock<Option<MemoryPeekFn>> = IrqSafeSpinLock::new(None);
static MEM_POKE: IrqSafeSpinLock<Option<MemoryPokeFn>> = IrqSafeSpinLock::new(None);

/// Test-only hook: register a synthetic memory backend so the
/// dispatcher's `m` / `M` handlers exercise without touching real
/// pointers.
#[doc(hidden)]
pub fn __test_install_memory(peek: MemoryPeekFn, poke: MemoryPokeFn) {
    *MEM_PEEK.lock() = Some(peek);
    *MEM_POKE.lock() = Some(poke);
}

#[doc(hidden)]
pub fn __test_clear_memory() {
    *MEM_PEEK.lock() = None;
    *MEM_POKE.lock() = None;
}

fn peek_memory(addr: u64, len: u32) -> Option<Vec<u8>> {
    if let Some(f) = *MEM_PEEK.lock() {
        return f(addr, len);
    }
    if len == 0 || len > 4096 {
        return None;
    }
    let mut buf = Vec::with_capacity(len as usize);
    for i in 0..len as u64 {
        // SAFETY: `addr + i` stays within `[addr, addr + len)`, the byte range
        // the gdb-stub host requested to read. gdb-stub clients are part of the
        // TCB and the cap-gated `attach` entry point is the only way to reach
        // here, so the host is trusted to name a meaningful address. The access
        // is a single-byte volatile read with natural (1-byte) alignment. A bad
        // address faults rather than returning garbage — we accept that as the
        // failure mode ("? on host shows a fault") instead of fault-handling the
        // peek and silently returning zeros.
        // SAFETY: Valid memory or trusted environment
        let b = unsafe { core::ptr::read_volatile((addr + i) as *const u8) };
        buf.push(b);
    }
    Some(buf)
}

fn poke_memory(addr: u64, bytes: &[u8]) -> bool {
    if let Some(f) = *MEM_POKE.lock() {
        return f(addr, bytes);
    }
    if bytes.len() > 4096 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        // SAFETY: cap-gated TCB caller per `peek_memory` above.
        unsafe {
            core::ptr::write_volatile((addr + i as u64) as *mut u8, *b);
        }
    }
    true
}

// ── Software breakpoint map ────────────────────────────────────────
//
// Keyed by virtual address; value is the original byte overwritten
// by INT3. The map is global so the trap #BP handler can look up
// whether a given RIP belongs to a GDB-installed software breakpoint.
//
// Linux reference: kernel/debug/gdbstub.c (BP table, GPL-2.0-or-later;
// adapted under NARF's post-2026-05-20 licence).

/// Global map of (virtual address → original byte) for all installed
/// software breakpoints. Protected by an `IrqSafeSpinLock` so the
/// #BP trap handler (which runs at interrupt time) can look up entries
/// safely.
pub static BP_MAP: IrqSafeSpinLock<BTreeMap<u64, u8>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Test-only hook: drain the BP map so independent tests don't leak
/// state across runs.
#[doc(hidden)]
pub fn __test_clear_bp_map() {
    BP_MAP.lock().clear();
}

/// INT3 opcode byte.
const INT3: u8 = 0xCC;

// ── Test-shimmable arch primitives for SW breakpoints ─────────────
//
// In production we write directly to virtual addresses via volatile
// pointer operations. Tests install the shims below so BP dispatch
// exercises without touching real kernel memory — same pattern as the
// MEM_PEEK / MEM_POKE hooks above.

type BpReadFn = fn(va: u64) -> Option<u8>;
type BpWriteFn = fn(va: u64, byte: u8) -> bool;

static BP_READ: IrqSafeSpinLock<Option<BpReadFn>> = IrqSafeSpinLock::new(None);
static BP_WRITE: IrqSafeSpinLock<Option<BpWriteFn>> = IrqSafeSpinLock::new(None);

/// Test-only: register synthetic byte-level read/write primitives so
/// `install_sw_breakpoint` / `remove_sw_breakpoint` don't touch real
/// memory during unit tests.
#[doc(hidden)]
pub fn __test_install_bp_hooks(read: BpReadFn, write: BpWriteFn) {
    *BP_READ.lock() = Some(read);
    *BP_WRITE.lock() = Some(write);
}

/// Test-only: clear the synthetic BP hooks.
#[doc(hidden)]
pub fn __test_clear_bp_hooks() {
    *BP_READ.lock() = None;
    *BP_WRITE.lock() = None;
}

/// Read one byte from `va`. Uses the test shim if installed, otherwise
/// falls back to a volatile pointer read.
fn bp_read_byte(va: u64) -> u8 {
    if let Some(f) = *BP_READ.lock() {
        return f(va).unwrap_or(0);
    }
    // SAFETY: production path — GDB stub is cap-gated; fault = bad addr.
    unsafe { core::ptr::read_volatile(va as *const u8) }
}

/// Write `byte` to `va`. Uses the test shim if installed.
fn bp_write_byte(va: u64, byte: u8) {
    if let Some(f) = *BP_WRITE.lock() {
        let _ = f(va, byte);
        return;
    }
    // SAFETY: production path — same contract as bp_read_byte.
    unsafe { core::ptr::write_volatile(va as *mut u8, byte) };
}

/// Install an INT3 software breakpoint at `va`. Saves the original
/// byte in [`BP_MAP`] so [`remove_sw_breakpoint`] can restore it.
///
/// Linux reference: kernel/debug/gdbstub.c::dbg_set_sw_break
/// (GPL-2.0-or-later; adapted under NARF's post-2026-05-20 licence).
fn install_sw_breakpoint(va: u64) -> bool {
    let orig = bp_read_byte(va);
    bp_write_byte(va, INT3);
    BP_MAP.lock().insert(va, orig);
    true
}

/// Remove the INT3 breakpoint at `va`, restoring the original byte
/// from [`BP_MAP`].
///
/// Linux reference: kernel/debug/gdbstub.c::dbg_remove_sw_break
fn remove_sw_breakpoint(va: u64) -> bool {
    let orig = match BP_MAP.lock().remove(&va) {
        Some(b) => b,
        None => return false, // not installed by us
    };
    bp_write_byte(va, orig);
    true
}

// ── Packet dispatch ────────────────────────────────────────────────

/// Build the wire reply for a parsed command, given the session's
/// current state. Mutates session state on `WriteRegs` /
/// `Step` / `Continue`.
pub fn build_reply(session: &mut GdbSession, cmd: &GdbCommand) -> String {
    session.packets_handled = session.packets_handled.saturating_add(1);
    match cmd {
        GdbCommand::HaltReason => {
            use core::fmt::Write as _;
            let mut s = String::new();
            let _ = write!(s, "S{:02x}", session.halt_reason.signal_byte());
            s
        }
        GdbCommand::ReadRegs => encode_regs(&session.regs),
        GdbCommand::WriteRegs(bytes) => match decode_regs(bytes) {
            Some(r) => {
                session.regs = r;
                String::from("OK")
            }
            None => String::from("E01"),
        },
        GdbCommand::ReadMem { addr, len } => match peek_memory(*addr, *len) {
            Some(b) => bytes_to_hex(&b),
            None => String::from("E14"),
        },
        GdbCommand::WriteMem { addr, bytes } => {
            if poke_memory(*addr, bytes) {
                String::from("OK")
            } else {
                String::from("E14")
            }
        }
        GdbCommand::Continue { .. } | GdbCommand::Step { .. } => {
            use core::fmt::Write as _;
            let mut s = String::new();
            let _ = write!(s, "S{:02x}", session.halt_reason.signal_byte());
            s
        }
        GdbCommand::InsertBp { addr, .. } => {
            // Install an INT3 at `addr`. The arch hook writes the byte
            // and saves the original in BP_MAP. Reply "OK" on success,
            // "E01" if the write fails (bad address).
            //
            // Linux reference: kernel/debug/gdbstub.c::dbg_set_sw_break
            // (GPL-2.0-or-later; adapted under NARF's post-2026-05-20 licence).
            if install_sw_breakpoint(*addr) {
                String::from("OK")
            } else {
                String::from("E01")
            }
        }
        GdbCommand::RemoveBp { addr, .. } => {
            // Restore the original byte at `addr` and remove from BP_MAP.
            //
            // Linux reference: kernel/debug/gdbstub.c::dbg_remove_sw_break
            if remove_sw_breakpoint(*addr) {
                String::from("OK")
            } else {
                String::from("E01")
            }
        }
        GdbCommand::QSupported(_features) => String::from("PacketSize=400"),
    }
}

/// One iteration of the packet pump: read a framed packet, parse,
/// build a reply, send it. Returns the dispatched command so the
/// caller can decide when to resume the target (on `Continue` /
/// `Step`).
pub fn process_packet<T: GdbTransport>(
    transport: &mut T,
    session: &mut GdbSession,
) -> Result<GdbCommand, GdbError> {
    let payload = read_packet(transport)?;
    if payload == "\x03" {
        let reply = build_reply(session, &GdbCommand::HaltReason);
        transport.send_packet(&reply);
        return Ok(GdbCommand::HaltReason);
    }
    let cmd = match parse_command(&payload) {
        Ok(c) => c,
        Err(GdbError::Unsupported) => {
            transport.send_packet("");
            return Err(GdbError::Unsupported);
        }
        Err(e) => return Err(e),
    };
    let reply = build_reply(session, &cmd);
    transport.send_packet(&reply);
    Ok(cmd)
}

// ── Attach entry ───────────────────────────────────────────────────

/// Run the gdb stub against `transport` with `session` as the live
/// target snapshot. Loops on incoming packets until the host
/// disconnects or sends `c` / `s` and the caller decides to resume.
///
/// Cap-gated on `Cap<Debugger, Invoke>`.
pub fn run_session<T: GdbTransport>(
    cap: &Cap<Debugger, narf_capabilities::Invoke>,
    transport: &mut T,
    session: &mut GdbSession,
) -> Result<(), GdbError> {
    cap.invoke(NoopOp)?;
    loop {
        match process_packet(transport, session) {
            Ok(GdbCommand::Continue { .. }) | Ok(GdbCommand::Step { .. }) => return Ok(()),
            Ok(_) => continue,
            Err(GdbError::Unsupported) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Legacy no-transport `attach` shim. Returns `NotImplemented` so
/// existing call sites that pre-date the transport split keep their
/// compile-time shape. New callers should use [`run_session`] or
/// [`attach_com1`].
pub fn attach(cap: &Cap<Debugger, narf_capabilities::Invoke>) -> Result<(), GdbError> {
    cap.invoke(NoopOp)?;
    Err(GdbError::NotImplemented)
}

// ── In-memory transport (testing) ──────────────────────────────────

/// Test transport. `inbound` carries bytes the "host" has sent;
/// `outbound` collects bytes the stub writes. `read_pos` is the
/// position the stub will read next.
#[derive(Debug, Default)]
pub struct VecTransport {
    pub inbound: Vec<u8>,
    pub outbound: Vec<u8>,
    pub read_pos: usize,
}

impl VecTransport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_raw(&mut self, bytes: &[u8]) {
        self.inbound.extend_from_slice(bytes);
    }
    /// Push a fully-framed packet (`$payload#XX`) on the inbound
    /// stream.
    pub fn push_packet(&mut self, payload: &str) {
        self.inbound
            .extend_from_slice(GdbPacket::new(payload).to_wire().as_bytes());
    }
    pub fn outbound_str(&self) -> String {
        self.outbound.iter().map(|b| *b as char).collect()
    }
}

impl GdbTransport for VecTransport {
    fn read_byte(&mut self) -> Option<u8> {
        if self.read_pos >= self.inbound.len() {
            return None;
        }
        let b = self.inbound[self.read_pos];
        self.read_pos += 1;
        Some(b)
    }
    fn write_byte(&mut self, b: u8) -> bool {
        self.outbound.push(b);
        true
    }
}

// ── COM1 transport (x86_64 production wire) ───────────────────────

/// COM1 transport — blocking byte reads against the 16550A at port
/// 0x3F8. The console crate already programs this UART at boot; the
/// gdb stub piggybacks on the same port.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default)]
pub struct Com1Transport {
    /// COM1 I/O port base.
    pub base: u16,
}

#[cfg(target_arch = "x86_64")]
impl Com1Transport {
    pub const COM1_BASE: u16 = 0x3F8;

    pub const fn new() -> Self {
        Self {
            base: Self::COM1_BASE,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl GdbTransport for Com1Transport {
    fn read_byte(&mut self) -> Option<u8> {
        const MAX_SPIN: u32 = 100_000_000;
        for _ in 0..MAX_SPIN {
            // SAFETY: `self.base + 5` is the 16550 UART Line Status Register for
            // COM1 (base 0x3F8). Reading the LSR is side-effect-free, and the
            // console crate has already validated this port is live at boot.
            // SAFETY: Valid memory or trusted environment
            let lsr = unsafe { narf_arch::x86_64::io_port::inb(self.base + 5) };
            if lsr & 0x01 != 0 {
                // SAFETY: LSR bit 0 (Data Ready) is set, so the UART's Receiver
                // Buffer Register at `self.base` (COM1, 0x3F8) holds a pending
                // byte. Reading the RBR is the documented way to consume it.
                // SAFETY: Valid memory or trusted environment
                let b = unsafe { narf_arch::x86_64::io_port::inb(self.base) };
                return Some(b);
            }
            core::hint::spin_loop();
        }
        None
    }

    fn write_byte(&mut self, b: u8) -> bool {
        const MAX_SPIN: u32 = 10_000_000;
        for _ in 0..MAX_SPIN {
            // SAFETY: `self.base + 5` is the 16550 UART Line Status Register for
            // COM1 (base 0x3F8). Reading the LSR is side-effect-free, and the
            // console crate has already validated this port is live at boot.
            // SAFETY: Valid memory or trusted environment
            let lsr = unsafe { narf_arch::x86_64::io_port::inb(self.base + 5) };
            if lsr & 0x20 != 0 {
                // SAFETY: LSR bit 5 (Transmitter Holding Register Empty) is set,
                // so writing `b` to the THR at `self.base` (COM1, 0x3F8) is safe
                // and will not clobber an in-flight byte.
                // SAFETY: Valid memory or trusted environment
                unsafe { narf_arch::x86_64::io_port::outb(self.base, b) };
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

#[cfg(target_arch = "x86_64")]
static ATTACH_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// High-level attach against COM1. Snapshots the supplied regs into a
/// `GdbSession`, runs the packet pump until host sends `c` or
/// disconnects, and returns. Cap-gated.
#[cfg(target_arch = "x86_64")]
pub fn attach_com1(
    cap: &Cap<Debugger, narf_capabilities::Invoke>,
    regs: ArchRegs,
    halt: HaltReason,
) -> Result<(), GdbError> {
    cap.invoke(NoopOp)?;
    let _guard = ATTACH_LOCK.lock();
    let mut transport = Com1Transport::new();
    let mut session = GdbSession::new(regs, halt);
    run_session(cap, &mut transport, &mut session)
}
