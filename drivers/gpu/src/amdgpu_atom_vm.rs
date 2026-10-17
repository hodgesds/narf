//! ATOMBIOS bytecode VM.
//!
//! Companion to `amdgpu_atombios.rs`: that module locates a command
//! table by index; this module *executes* the bytecode at that
//! table. Together they cover the AMD `atom.c` surface the driver
//! needs: display/encoder/PLL tables, and `ASIC_Init` (the post that
//! `amdgpu_device_asic_init` runs after a reset clears
//! `ATOM_S7_ASIC_INIT_COMPLETE`).
//!
//! ## Reference: Linux `drivers/gpu/drm/amd/amdgpu/atom.{h,c}`
//!
//! NARF is GPL-2.0-or-later, so the canonical Linux interpreter is
//! a directly citable source. Every constant + dispatch layout
//! below is cross-referenced against:
//!
//! - `atom.h` — opcode count (127), EOT (91), argument classes
//!   (REG/PS/WS/FB/ID/IMM/PLL/MC), source alignment, WS pseudo-register
//!   IDs, the `ATOM_IIO_*` indirect-I/O opcodes and `ATOM_IO_*` modes.
//! - `atom.c` — `atom_arg_mask` / `atom_arg_shift` / `atom_dst_to_src` /
//!   `atom_def_dst`, `atom_iio_execute`, `atom_get_src_int` /
//!   `atom_skip_src_int`, `atom_get_dst` / `atom_put_dst`, the per-opcode
//!   handlers, `opcode_table[ATOM_OP_CNT]`,
//!   `amdgpu_atom_execute_table_locked`, `atom_index_iio`.
//!
//! ## Execution model
//!
//! Linux recurses for CALLTABLE and sleeps inside DELAY. Here a
//! [`Machine`] keeps an explicit frame stack and executes one opcode per
//! [`Machine::step`]; DELAY surfaces as [`Step::Delay`] so an async caller
//! can sleep cooperatively between opcodes, and a cancelled caller simply
//! stops stepping. [`execute_table`] / [`execute_bytes`] are the synchronous
//! drivers (DELAY goes to [`Hooks::delay_us`]).
//!
//! Register, PLL and MC accesses and table resolution go through
//! [`Hooks`]. [`Closures`] is the boxed-closure implementation the display
//! tables bind; a `Send` owner implements `Hooks` directly.
//!
//! ## Fidelity notes
//!
//! - Sub-dword destinations keep the untouched bits of the destination's
//!   raw value (`atom_get_dst(..., &saved)`), and SHL/SHR shift that raw
//!   value, exactly as `atom.c`.
//! - Conditions Linux only `pr_info`s and continues past (PS/WS/FB index
//!   out of range, PCI/SYSIO register classes, an undefined or malformed
//!   IIO program) behave as Linux does and are counted in
//!   [`AtomState::anomalies`] with the first one kept, instead of failing
//!   the table.
//! - Conditions that mean the stream itself is misdecoded fail the table
//!   (Linux would execute garbage or stop with success): a bad opcode,
//!   operands or jump targets past the table, a bad SWITCH case, a
//!   CALLTABLE chain deeper than [`ATOM_EXECUTE_MAX_DEPTH`].
//! - The stuck-loop guard is `atom_op_jump`'s: the same jump target taken
//!   for more than `ATOM_CMD_TIMEOUT_SEC` (20 s) aborts, measured by
//!   [`Hooks::now_ms`]. Hooks without a clock fall back to 65 536 repeats
//!   of one target and 1 000 000 opcodes per execution.
//!
//! `repeat`, `savereg`, `restorereg` are decoded but treated as no-ops
//! (Linux `pr_info`s "unimplemented!"). `beep`, `postcard`, `debug` are
//! likewise no-ops (Linux just `printk`s).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};

// ── Constants mirror `atom.h` ────────────────────────────────────

/// Total opcode count, per `atom.h:65` `ATOM_OP_CNT`.
pub const ATOM_OP_CNT: u8 = 127;
/// End-of-table sentinel, per `atom.h:66` `ATOM_OP_EOT`.
pub const ATOM_OP_EOT: u8 = 91;

// Source-argument classes — `atom.h:71-78`.
const ARG_REG: u8 = 0;
const ARG_PS: u8 = 1;
const ARG_WS: u8 = 2;
const ARG_FB: u8 = 3;
const ARG_ID: u8 = 4;
const ARG_IMM: u8 = 5;
const ARG_PLL: u8 = 6;
const ARG_MC: u8 = 7;

// Source alignments — `atom.h:80-87`.
const SRC_DWORD: u8 = 0;
const SRC_WORD0: u8 = 1;
const SRC_WORD8: u8 = 2;
const SRC_WORD16: u8 = 3;
const SRC_BYTE0: u8 = 4;
const SRC_BYTE8: u8 = 5;
const SRC_BYTE16: u8 = 6;
const SRC_BYTE24: u8 = 7;

// WS pseudo-registers — `atom.h:89-97`.
const WS_QUOTIENT: u8 = 0x40;
const WS_REMAINDER: u8 = 0x41;
const WS_DATAPTR: u8 = 0x42;
const WS_SHIFT: u8 = 0x43;
const WS_OR_MASK: u8 = 0x44;
const WS_AND_MASK: u8 = 0x45;
const WS_FB_WINDOW: u8 = 0x46;
const WS_ATTRIBUTES: u8 = 0x47;
const WS_REGPTR: u8 = 0x48;

// Indirect-I/O program opcodes — `atom.h:99-108`.
pub const ATOM_IIO_NOP: u8 = 0;
pub const ATOM_IIO_START: u8 = 1;
pub const ATOM_IIO_READ: u8 = 2;
pub const ATOM_IIO_WRITE: u8 = 3;
pub const ATOM_IIO_CLEAR: u8 = 4;
pub const ATOM_IIO_SET: u8 = 5;
pub const ATOM_IIO_MOVE_INDEX: u8 = 6;
pub const ATOM_IIO_MOVE_ATTR: u8 = 7;
pub const ATOM_IIO_MOVE_DATA: u8 = 8;
pub const ATOM_IIO_END: u8 = 9;
/// `atom_iio_len[]` (`atom.c`), indexed by IIO opcode.
const IIO_LEN: [usize; 10] = [1, 2, 3, 3, 3, 3, 4, 4, 4, 3];
/// `ATOM_DATA_IIO_PTR` (`atom.h:52`): the master data table's
/// `indirectioaccess` entry (index 23).
const DATA_IIO_PTR: usize = 0x32;
/// Bound on one IIO program's opcodes. Linux's loop is unbounded; VBIOS
/// programs are a handful of operations.
const IIO_MAX_OPS: usize = 4096;

// Jump conditions — `atom.c:42-48` `ATOM_COND_*`.
const COND_ABOVE: u8 = 0;
const COND_ABOVEOREQUAL: u8 = 1;
const COND_ALWAYS: u8 = 2;
const COND_BELOW: u8 = 3;
const COND_BELOWOREQUAL: u8 = 4;
const COND_EQUAL: u8 = 5;
const COND_NOTEQUAL: u8 = 6;

// Delay units — `atom.c:54-55`.
const UNIT_MICROSEC: u8 = 0;
const UNIT_MILLISEC: u8 = 1;

// I/O modes — `atom.h:110-113`.
const IO_MM: u32 = 0;
const IO_PCI: u32 = 1;
const IO_SYSIO: u32 = 2;
const IO_IIO: u32 = 0x80;

// Port classes for SETPORT — `atom.c:50-52`.
const PORT_ATI: u8 = 0;
const PORT_PCI: u8 = 1;
const PORT_SYSIO: u8 = 2;

// SWITCH delimiter magic — `atom.h:68-69`.
const CASE_MAGIC: u8 = 0x63;
const CASE_END: u16 = 0x5A5A;

/// `ATOM_CMD_TIMEOUT_SEC` (`atom.c`), in milliseconds.
pub const ATOM_CMD_TIMEOUT_MS: u64 = 20_000;
/// Clockless fallbacks for the stuck-loop guard.
const STUCK_REPEATS: u32 = 65_535;
const STEP_CAP: u64 = 1_000_000;

/// Per `atom.c:77`. Mask applied after extracting an aligned
/// sub-word from the raw 32-bit register/memory value.
const ARG_MASK: [u32; 8] = [
    0xFFFF_FFFF,
    0x0000_FFFF,
    0x00FF_FF00,
    0xFFFF_0000,
    0x0000_00FF,
    0x0000_FF00,
    0x00FF_0000,
    0xFF00_0000,
];

/// Per `atom.c:80`. Right-shift applied after masking.
const ARG_SHIFT: [u32; 8] = [0, 0, 8, 16, 0, 8, 16, 24];

/// Per `atom.c:82-92`. Translates a destination alignment field +
/// two-bit dst-shift selector into the matching source alignment
/// id.
const DST_TO_SRC: [[u8; 4]; 8] = [
    [0, 0, 0, 0],
    [1, 2, 3, 0],
    [1, 2, 3, 0],
    [1, 2, 3, 0],
    [4, 5, 6, 7],
    [4, 5, 6, 7],
    [4, 5, 6, 7],
    [4, 5, 6, 7],
];

/// Per `atom.c:93`. Default destination alignment for opcodes
/// (`clear`, `shift_left`, `shift_right`) that don't carry an
/// explicit dst-align bit pair.
const DEF_DST: [u8; 8] = [0, 0, 1, 2, 0, 1, 2, 3];

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomError {
    /// Ran past the end of the bytecode buffer without an EOT.
    BytecodeTruncated,
    /// Retained for API compatibility; opcode 0 / `>= ATOM_OP_CNT` ends the
    /// table with [`Anomaly::BadOpcode`], as in Linux.
    BadOpcode(u8),
    /// Retained for API compatibility; out-of-range PS reads/writes are
    /// [`Anomaly::PsIndex`], as in Linux.
    PsIndexOutOfRange,
    /// Retained for API compatibility; see [`Anomaly::WsIndex`].
    WsIndexOutOfRange,
    /// Retained for API compatibility; see [`Anomaly::FbIndex`].
    FbIndexOutOfRange,
    /// JUMP target outside the table; surfaced as [`Anomaly::JumpTarget`]
    /// (the table ends) and never returned from `step`.
    BadJumpTarget,
    /// Retained for API compatibility; see [`Anomaly::BadCase`].
    BadSwitchCase,
    /// Retained for API compatibility; unbound closures read 0xCDCDCDCD.
    RegisterAccessNotBound,
    /// Argument class out of range (only 3 bits — should be
    /// impossible, but guards against a malformed table).
    BadArgClass,
    /// `atom_op_jump`'s stuck-loop abort (see the module notes).
    Stuck,
    /// CALLTABLE nested deeper than [`ATOM_EXECUTE_MAX_DEPTH`].
    CallTableTooDeep,
    /// The top-level table, or a CALLTABLE target whose directory entry is
    /// non-zero, could not be resolved.
    UnknownTable(u8),
}

/// A condition Linux's interpreter logs and continues past.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Anomaly {
    PsIndex(u8),
    WsIndex(u8),
    /// Byte offset `fb_base + 4 * idx` outside the FB scratch.
    FbIndex(u32),
    /// A REG operand while SETPORT selected PCI or SYSIO.
    PortIo(u32),
    /// SETPORT ATI selected an IIO port with no program (read or write
    /// program index given).
    UndefinedIio(u8),
    /// An IIO program used an unknown opcode or ran off the image.
    BadIio(u8),
    /// Opcode 0 or `>= ATOM_OP_CNT`: amdgpu_atom_execute_table_locked's
    /// `else break;` ends the table there and returns 0.
    BadOpcode(u8),
    /// atom_op_switch "Bad case": the switch returns and execution resumes
    /// at the offending byte.
    BadCase,
    /// JUMP/SWITCH target outside this table's bytecode (the op site is
    /// `Machine::last`). Linux would run whatever ROM bytes lie there; NARF
    /// ends the table instead.
    JumpTarget,
}

// ── Hooks ────────────────────────────────────────────────────────

/// One resolved command table: the bytecode body with its
/// `ATOM_COMMON_TABLE_HEADER` and prelude already stripped, plus the
/// parameter-space size the table's own header declares.
///
/// `ps_dwords` is `(CU8(base + ATOM_CT_PS_PTR) & ATOM_CT_PS_MASK) / 4` —
/// `atom.c`'s `ectx.ps_shift`. It is needed because CALLTABLE hands the
/// callee the parameter window *above* the caller's own: `ctx->ps +
/// ctx->ps_shift`. Resolving the body alone leaves no way to compute it,
/// which is why this is a pair.
#[derive(Copy, Clone, Debug)]
pub struct ResolvedTable<'a> {
    pub body: &'a [u8],
    pub ps_dwords: usize,
    /// Absolute image offset of the table's header (`ctx->start`), which
    /// `SET_DATA_BLOCK 255` selects. Zero when the VM runs without an image.
    pub start: usize,
    /// `CU8(base + ATOM_CT_WS_PTR)`: Linux gives every table execution,
    /// including each CALLTABLE callee, its own zeroed WS of this many
    /// dwords. `None` keeps the caller's scratch (synthetic tables).
    pub ws_dwords: Option<usize>,
}

/// The `card_info` callbacks plus table resolution and time.
pub trait Hooks<'a> {
    /// `cail_reg_read`: a dword register index (`RREG32`).
    fn reg_read(&mut self, index: u32) -> u32;
    /// `cail_reg_write` (`WREG32`).
    fn reg_write(&mut self, index: u32, value: u32);
    /// `cail_pll_read`; zero on SOC15, as Linux.
    fn pll_read(&mut self, _index: u32) -> u32 {
        0
    }
    fn pll_write(&mut self, _index: u32, _value: u32) {}
    /// `cail_mc_read`; zero on SOC15, as Linux.
    fn mc_read(&mut self, _index: u32) -> u32 {
        0
    }
    fn mc_write(&mut self, _index: u32, _value: u32) {}
    /// The command table `id`, or `None` if it cannot be resolved.
    fn resolve(&mut self, id: u8) -> Option<ResolvedTable<'a>>;
    /// True when `id`'s master command-table entry is zero: `atom_op_calltable`
    /// then does nothing.
    fn table_absent(&mut self, _id: u8) -> bool {
        false
    }
    /// DELAY for the synchronous drivers ([`execute_table`]).
    fn delay_us(&mut self, _us: u64) {}
    /// Monotonic milliseconds for the stuck-loop guard; `None` selects the
    /// clockless repeat/step bounds.
    fn now_ms(&mut self) -> Option<u64> {
        None
    }
}

/// MMIO / PLL / MC / I/O accessor closures. The VM is driven from a single
/// thread under the caller's mutex (see `atom.c::amdgpu_atom_execute_table`
/// which `mutex_lock`s `ctx->mutex`), so the closures are deliberately not
/// `Send`.
pub type RegRead = Box<dyn FnMut(u32) -> u32>;
pub type RegWrite = Box<dyn FnMut(u32, u32)>;

/// CALLTABLE / top-level resolver: given a sub-table id, return that
/// table's body and declared parameter size. `None` means "no such table",
/// which the VM converts to `AtomError::UnknownTable`.
pub type TableResolver<'a> = Box<dyn FnMut(u8) -> Option<ResolvedTable<'a>> + 'a>;

/// Boxed-closure [`Hooks`]. Every accessor defaults to the "uninitialised"
/// stub (reads 0xCDCDCDCD, the Linux uninit pattern; writes dropped).
pub struct Closures<'a> {
    pub reg_read: RegRead,
    pub reg_write: RegWrite,
    pub pll_read: RegRead,
    pub pll_write: RegWrite,
    pub mc_read: RegRead,
    pub mc_write: RegWrite,
    /// SYSIO / legacy port accessors. Linux implements no port I/O, and
    /// neither does the VM; kept for binding compatibility.
    pub port_read: RegRead,
    pub port_write: RegWrite,
    /// Sub-table resolver (for the entry table and CALLTABLE).
    pub table_resolver: TableResolver<'a>,
    /// `udelay`/`msleep` for DELAY_MICROSEC/DELAY_MILLISEC, in microseconds.
    pub delay_us: Box<dyn FnMut(u64) + 'a>,
}
impl fmt::Debug for Closures<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Closures")
    }
}
impl Default for Closures<'_> {
    fn default() -> Self {
        Self {
            reg_read: unbound_read(),
            reg_write: unbound_write(),
            pll_read: unbound_read(),
            pll_write: unbound_write(),
            mc_read: unbound_read(),
            mc_write: unbound_write(),
            port_read: unbound_read(),
            port_write: unbound_write(),
            table_resolver: Box::new(|_id| None),
            delay_us: Box::new(|_| {}),
        }
    }
}
impl<'a> Hooks<'a> for Closures<'a> {
    fn reg_read(&mut self, index: u32) -> u32 {
        (self.reg_read)(index)
    }
    fn reg_write(&mut self, index: u32, value: u32) {
        (self.reg_write)(index, value)
    }
    fn pll_read(&mut self, index: u32) -> u32 {
        (self.pll_read)(index)
    }
    fn pll_write(&mut self, index: u32, value: u32) {
        (self.pll_write)(index, value)
    }
    fn mc_read(&mut self, index: u32) -> u32 {
        (self.mc_read)(index)
    }
    fn mc_write(&mut self, index: u32, value: u32) {
        (self.mc_write)(index, value)
    }
    fn resolve(&mut self, id: u8) -> Option<ResolvedTable<'a>> {
        (self.table_resolver)(id)
    }
    fn delay_us(&mut self, us: u64) {
        (self.delay_us)(us)
    }
}

fn unbound_read() -> RegRead {
    Box::new(|_addr| 0xCDCD_CDCD)
}
fn unbound_write() -> RegWrite {
    Box::new(|_addr, _val| {})
}

/// `ATOM_EXECUTE_MAX_DEPTH`: CALLTABLE recursion bound. VBIOS bytecode is
/// data read off the card, so a table whose CALLTABLE chain loops must be
/// refused rather than followed.
pub const ATOM_EXECUTE_MAX_DEPTH: u32 = 32;

// ── VM state ─────────────────────────────────────────────────────

/// `atom_context` — `atom.h:132-156`. The per-execution frames (PS
/// window, WS, jump guard) live in [`Machine`], as Linux's
/// `atom_exec_context`. Hook fields of the default [`Closures`] are
/// reachable directly (`state.reg_read = ...`) through `Deref`.
pub struct AtomState<'a, H = Closures<'a>> {
    /// Working scratch of the executing table (`ectx.ws`).
    pub scratch: Vec<u32>,
    /// `data_block` — current data-table base offset within the
    /// BIOS image (`atom.h:139` `uint16_t data_block`).
    pub data_block: u16,
    /// `fb_base` — frame-buffer / scratch-window base in bytes.
    pub fb_base: u32,
    /// `divmul[0..1]` — MUL/DIV result.
    pub divmul: [u32; 2],
    /// `io_attr` — attribute word an IIO program's MOVE_ATTR reads.
    pub io_attr: u16,
    /// `reg_block` — register-block base added to every REG-class access.
    pub reg_block: u16,
    /// `shift` — WS_SHIFT and the OR/AND mask pseudo-registers.
    pub shift: u8,
    /// Compare flags from CMP / TEST.
    pub cs_equal: bool,
    pub cs_above: bool,
    /// I/O mode for REG-class accesses: MM / PCI / SYSIO / IIO|port.
    pub io_mode: u32,
    /// `ctx->scratch`, the FB-class region (`amdgpu_atom*_allocate_fb_scratch`).
    pub fb_scratch: Vec<u32>,
    /// The whole VBIOS image and its master data table offset. When bound,
    /// `SET_DATA_BLOCK` and ID-class operands follow `atom.c` exactly:
    /// `data_block` is an absolute image offset taken from the master data
    /// table, and ID reads load from the image. Unbound (empty) keeps the
    /// table-relative behaviour the synthetic tests use.
    pub bios: &'a [u8],
    pub data_table: usize,
    /// `ctx->iio`: per IIO port (reads `port`, writes `0x80 | port`), the
    /// image offset of its program, 0 when undefined. `None` until indexed
    /// ([`AtomState::index_iio`]); a [`Machine`] indexes a bound image on
    /// first use, as `amdgpu_atom_parse` does.
    pub iio: Option<Vec<u16>>,
    /// Conditions Linux logs and continues past, and the first one seen.
    pub anomalies: u32,
    pub first_anomaly: Option<Anomaly>,
    pub hooks: H,
}

impl<'a, H> Deref for AtomState<'a, H> {
    type Target = H;
    fn deref(&self) -> &H {
        &self.hooks
    }
}
impl<'a, H> DerefMut for AtomState<'a, H> {
    fn deref_mut(&mut self) -> &mut H {
        &mut self.hooks
    }
}

impl<'a, H> fmt::Debug for AtomState<'a, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomState")
            .field("ws_len", &self.scratch.len())
            .field("data_block", &self.data_block)
            .field("fb_base", &self.fb_base)
            .field("divmul", &self.divmul)
            .field("io_attr", &self.io_attr)
            .field("reg_block", &self.reg_block)
            .field("shift", &self.shift)
            .field("cs_equal", &self.cs_equal)
            .field("cs_above", &self.cs_above)
            .field("io_mode", &self.io_mode)
            .field("fb_scratch_len", &self.fb_scratch.len())
            .field("anomalies", &self.anomalies)
            .finish()
    }
}

impl<'a> AtomState<'a> {
    /// New VM with `ws_words` working-scratch slots, `fb_words`
    /// FB-scratch words, and all accessors bound to the
    /// "uninitialised" stubs. Tests then replace whichever ones
    /// they care about.
    pub fn new(ws_words: usize, fb_words: usize) -> Self {
        Self::with_hooks(ws_words, fb_words, Closures::default())
    }
}

impl<'a, H> AtomState<'a, H> {
    pub fn with_hooks(ws_words: usize, fb_words: usize, hooks: H) -> Self {
        Self {
            scratch: vec![0u32; ws_words.max(1)],
            data_block: 0,
            fb_base: 0,
            divmul: [0, 0],
            io_attr: 0,
            reg_block: 0,
            shift: 0,
            cs_equal: false,
            cs_above: false,
            io_mode: IO_MM,
            fb_scratch: vec![0u32; fb_words.max(1)],
            bios: &[],
            data_table: 0,
            iio: None,
            anomalies: 0,
            first_anomaly: None,
            hooks,
        }
    }
    /// `atom_index_iio(ctx, CU16(ctx->data_table + ATOM_DATA_IIO_PTR) + 4)`:
    /// record each `IIO_START port` program's body offset. Bounded by the
    /// image; an unknown opcode ends the scan (Linux would index past
    /// `atom_iio_len`).
    pub fn index_iio(&mut self) {
        let mut iio = vec![0u16; 256];
        let bios = self.bios;
        let u8_at = |at: usize| bios.get(at).copied();
        let table = bios
            .get(self.data_table + DATA_IIO_PTR..self.data_table + DATA_IIO_PTR + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
        if let Some(table) = table {
            let mut base = table + 4;
            'programs: while u8_at(base) == Some(ATOM_IIO_START) {
                let Some(port) = u8_at(base + 1) else { break };
                let Ok(body) = u16::try_from(base + 2) else {
                    break;
                };
                iio[usize::from(port)] = body;
                base += 2;
                loop {
                    match u8_at(base) {
                        Some(ATOM_IIO_END) => break,
                        Some(op) if usize::from(op) < IIO_LEN.len() => {
                            base += IIO_LEN[usize::from(op)]
                        }
                        _ => break 'programs,
                    }
                }
                base += 3;
            }
        }
        self.iio = Some(iio);
    }
    fn anomaly(&mut self, anomaly: Anomaly) {
        self.anomalies = self.anomalies.saturating_add(1);
        if self.first_anomaly.is_none() {
            self.first_anomaly = Some(anomaly);
        }
    }
}

// ── Per-frame execution context ──────────────────────────────────

/// `atom_op_jump`'s per-execution loop guard (`last_jump`,
/// `last_jump_jiffies`).
#[derive(Copy, Clone, Debug, Default)]
struct JumpGuard {
    target: Option<usize>,
    since_ms: u64,
    repeats: u32,
}

/// The view of the executing `atom_exec_context` handed to one opcode.
struct Frame<'b, 'c> {
    code: &'b [u8],
    /// Parameter space (`ectx.ps`, sized `ectx.ps_size`).
    ps: &'c mut [u32],
    /// This table's declared parameter size in dwords — `ectx.ps_shift`.
    ps_shift: usize,
    /// CALLTABLE nesting depth, bounded by [`ATOM_EXECUTE_MAX_DEPTH`].
    depth: u32,
    /// Absolute image offset of this table's header (`ctx->start`).
    start: usize,
    jump: &'c mut JumpGuard,
}

impl<'b, 'c> Frame<'b, 'c> {
    fn u8_at(&self, off: usize) -> Result<u8, AtomError> {
        self.code
            .get(off)
            .copied()
            .ok_or(AtomError::BytecodeTruncated)
    }
    fn u16_at(&self, off: usize) -> Result<u16, AtomError> {
        if off + 1 >= self.code.len() {
            return Err(AtomError::BytecodeTruncated);
        }
        Ok(u16::from_le_bytes([self.code[off], self.code[off + 1]]))
    }
    fn u32_at(&self, off: usize) -> Result<u32, AtomError> {
        if off + 3 >= self.code.len() {
            return Err(AtomError::BytecodeTruncated);
        }
        Ok(u32::from_le_bytes([
            self.code[off],
            self.code[off + 1],
            self.code[off + 2],
            self.code[off + 3],
        ]))
    }
}

/// `0xFFFFFFFF >> (32 - width)` with x86 shift-count masking, as the C
/// expression evaluates on the hardware Linux runs it on.
fn iio_mask(width: u8) -> u32 {
    u32::MAX.wrapping_shr(32u32.wrapping_sub(u32::from(width)))
}

/// `atom_iio_execute`: run the IIO program at image offset `base` with the
/// REG operand's `index` and, for writes, the `data` to store. Every READ
/// and WRITE goes through the same `reg_read`/`reg_write` callbacks as an
/// MM-mode access; the programs themselves sequence the index/data pairs.
fn iio_execute<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    program: u8,
    mut base: usize,
    index: u32,
    data: u32,
) -> u32 {
    let mut temp = 0xCDCD_CDCDu32;
    let bios = state.bios;
    let u8_at = |at: usize| bios.get(at).copied();
    let u16_at = |at: usize| {
        bios.get(at..at + 2)
            .map(|b| u32::from(u16::from_le_bytes([b[0], b[1]])))
    };
    for _ in 0..IIO_MAX_OPS {
        let Some(op) = u8_at(base) else { break };
        let (b1, b2, b3) = (
            u8_at(base + 1).unwrap_or(0),
            u8_at(base + 2).unwrap_or(0),
            u8_at(base + 3).unwrap_or(0),
        );
        let field = |temp: u32, source: u32| {
            let mask = iio_mask(b1);
            (temp & !mask.wrapping_shl(u32::from(b3)))
                | (source.wrapping_shr(u32::from(b2)) & mask).wrapping_shl(u32::from(b3))
        };
        match op {
            ATOM_IIO_NOP => base += 1,
            ATOM_IIO_READ => {
                let Some(register) = u16_at(base + 1) else {
                    break;
                };
                temp = state.hooks.reg_read(register);
                base += 3;
            }
            ATOM_IIO_WRITE => {
                let Some(register) = u16_at(base + 1) else {
                    break;
                };
                state.hooks.reg_write(register, temp);
                base += 3;
            }
            ATOM_IIO_CLEAR => {
                temp &= !iio_mask(b1).wrapping_shl(u32::from(b2));
                base += 3;
            }
            ATOM_IIO_SET => {
                temp |= iio_mask(b1).wrapping_shl(u32::from(b2));
                base += 3;
            }
            ATOM_IIO_MOVE_INDEX => {
                temp = field(temp, index);
                base += 4;
            }
            ATOM_IIO_MOVE_DATA => {
                temp = field(temp, data);
                base += 4;
            }
            ATOM_IIO_MOVE_ATTR => {
                temp = field(temp, u32::from(state.io_attr));
                base += 4;
            }
            ATOM_IIO_END => return temp,
            // "Unknown IIO opcode": Linux returns 0.
            _ => {
                state.anomaly(Anomaly::BadIio(program));
                return 0;
            }
        }
    }
    state.anomaly(Anomaly::BadIio(program));
    0
}

/// The IIO program for `slot`, indexing a bound image on first use.
fn iio_program<'a, H>(state: &mut AtomState<'a, H>, slot: u8) -> Option<usize> {
    if state.iio.is_none() {
        state.index_iio();
    }
    let program = state.iio.as_ref()?.get(usize::from(slot)).copied()?;
    (program != 0).then_some(usize::from(program))
}

// ── Source / dest decoding (atom.c) ──────────────────────────────

/// `atom_get_src_int`: the aligned value of `(attr, ptr)` and the raw
/// 32-bit value it was taken from (`*saved`), advancing `ptr`.
fn get_src_saved<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &Frame,
    attr: u8,
    ptr: &mut usize,
) -> Result<(u32, u32), AtomError> {
    let arg = attr & 7;
    let align = (attr >> 3) & 7;
    let val: u32 = match arg {
        ARG_REG => {
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let idx = u32::from(idx16).wrapping_add(u32::from(state.reg_block));
            match state.io_mode {
                IO_MM => state.hooks.reg_read(idx),
                // "PCI/SYSIO registers are not implemented": return 0.
                IO_PCI | IO_SYSIO => {
                    state.anomaly(Anomaly::PortIo(idx));
                    return Ok((0, 0));
                }
                mode if mode & IO_IIO != 0 => {
                    let slot = (mode & 0x7F) as u8;
                    match iio_program(state, slot) {
                        Some(base) => iio_execute(state, slot, base, idx, 0),
                        None => {
                            state.anomaly(Anomaly::UndefinedIio(slot));
                            return Ok((0, 0));
                        }
                    }
                }
                _ => return Err(AtomError::BadArgClass),
            }
        }
        ARG_PS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            match frame.ps.get(usize::from(idx)) {
                Some(&v) => v,
                None => {
                    state.anomaly(Anomaly::PsIndex(idx));
                    0xCDCD_CDCD
                }
            }
        }
        ARG_WS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            match idx {
                WS_QUOTIENT => state.divmul[0],
                WS_REMAINDER => state.divmul[1],
                WS_DATAPTR => u32::from(state.data_block),
                WS_SHIFT => u32::from(state.shift),
                WS_OR_MASK => 1u32.wrapping_shl(u32::from(state.shift)),
                WS_AND_MASK => !1u32.wrapping_shl(u32::from(state.shift)),
                WS_FB_WINDOW => state.fb_base,
                WS_ATTRIBUTES => u32::from(state.io_attr),
                WS_REGPTR => u32::from(state.reg_block),
                _ => match state.scratch.get(usize::from(idx)) {
                    Some(&v) => v,
                    None => {
                        state.anomaly(Anomaly::WsIndex(idx));
                        0xCDCD_CDCD
                    }
                },
            }
        }
        ARG_ID => {
            // `U32(idx + gctx->data_block)`.
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let abs = usize::from(idx16) + usize::from(state.data_block);
            let bytes = if !state.bios.is_empty() {
                state.bios.get(abs..abs + 4)
            } else {
                // Without a bound image, constrain to the table buffer
                // (synthetic tables only).
                frame.code.get(abs..abs + 4)
            }
            .ok_or(AtomError::BytecodeTruncated)?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
        ARG_FB => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            let byte = state.fb_base.wrapping_add(u32::from(idx) * 4);
            match state.fb_scratch.get(byte as usize / 4) {
                Some(&v) => v,
                None => {
                    state.anomaly(Anomaly::FbIndex(byte));
                    0
                }
            }
        }
        ARG_IMM => {
            // IMM short-circuits — no align mask/shift fixup, no saved.
            let v = get_src_direct(frame, align, ptr)?;
            return Ok((v, v));
        }
        ARG_PLL => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            state.hooks.pll_read(u32::from(idx))
        }
        ARG_MC => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            state.hooks.mc_read(u32::from(idx))
        }
        _ => return Err(AtomError::BadArgClass),
    };
    let a = align as usize;
    Ok(((val & ARG_MASK[a]) >> ARG_SHIFT[a], val))
}

/// `atom_get_src`.
fn get_src<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &Frame,
    attr: u8,
    ptr: &mut usize,
) -> Result<u32, AtomError> {
    get_src_saved(state, frame, attr, ptr).map(|(v, _)| v)
}

/// Mirror of `atom_skip_src_int` — advance ptr past the source operand
/// without reading it. Used by MOVE's "skip dst" path.
fn skip_src(frame: &Frame, attr: u8, ptr: &mut usize) -> Result<(), AtomError> {
    let arg = attr & 7;
    let align = (attr >> 3) & 7;
    match arg {
        ARG_REG | ARG_ID => *ptr += 2,
        ARG_PS | ARG_WS | ARG_FB | ARG_PLL | ARG_MC => *ptr += 1,
        ARG_IMM => match align {
            SRC_DWORD => *ptr += 4,
            SRC_WORD0 | SRC_WORD8 | SRC_WORD16 => *ptr += 2,
            _ => *ptr += 1,
        },
        _ => return Err(AtomError::BadArgClass),
    }
    if *ptr > frame.code.len() {
        return Err(AtomError::BytecodeTruncated);
    }
    Ok(())
}

fn dst_attr(arg: u8, attr: u8) -> u8 {
    arg | (DST_TO_SRC[((attr >> 3) & 7) as usize][((attr >> 6) & 3) as usize] << 3)
}

/// `atom_get_dst(ctx, arg, attr, ptr, &saved, ...)`: the aligned
/// destination value and its raw 32-bit value.
fn get_dst<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &Frame,
    arg: u8,
    attr: u8,
    ptr: &mut usize,
) -> Result<(u32, u32), AtomError> {
    get_src_saved(state, frame, dst_attr(arg, attr), ptr)
}

fn skip_dst(frame: &Frame, arg: u8, attr: u8, ptr: &mut usize) -> Result<(), AtomError> {
    skip_src(frame, dst_attr(arg, attr), ptr)
}

/// Read just the raw aligned sub-word from the bytecode stream
/// (no REG/PS/WS dispatch). `atom_get_src_direct`.
fn get_src_direct(frame: &Frame, align: u8, ptr: &mut usize) -> Result<u32, AtomError> {
    let v = match align {
        SRC_DWORD => {
            let v = frame.u32_at(*ptr)?;
            *ptr += 4;
            v
        }
        SRC_WORD0 | SRC_WORD8 | SRC_WORD16 => {
            let v = u32::from(frame.u16_at(*ptr)?);
            *ptr += 2;
            v
        }
        SRC_BYTE0 | SRC_BYTE8 | SRC_BYTE16 | SRC_BYTE24 => {
            let v = u32::from(frame.u8_at(*ptr)?);
            *ptr += 1;
            v
        }
        _ => return Err(AtomError::BadArgClass),
    };
    Ok(v)
}

/// Mirror of `atom_put_dst` — store `val` back into the destination
/// encoded at (`arg`, `attr`, `ptr`). `saved` is the destination's raw
/// 32-bit value, so a sub-word store preserves the surrounding bits.
fn put_dst<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    attr: u8,
    ptr: &mut usize,
    val: u32,
    saved: u32,
) -> Result<(), AtomError> {
    let align = DST_TO_SRC[((attr >> 3) & 7) as usize][((attr >> 6) & 3) as usize] as usize;
    let val = (val.wrapping_shl(ARG_SHIFT[align]) & ARG_MASK[align]) | (saved & !ARG_MASK[align]);

    match arg {
        ARG_REG => {
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let idx = u32::from(idx16).wrapping_add(u32::from(state.reg_block));
            match state.io_mode {
                // atom.c special-cases idx 0 (MM_INDEX takes a byte address).
                IO_MM if idx == 0 => state.hooks.reg_write(idx, val << 2),
                IO_MM => state.hooks.reg_write(idx, val),
                IO_PCI | IO_SYSIO => state.anomaly(Anomaly::PortIo(idx)),
                mode if mode & IO_IIO != 0 => {
                    // atom_put_dst indexes the write program with `& 0xFF`:
                    // `INDIRECT_WRITE | port`.
                    let slot = (mode & 0xFF) as u8;
                    match iio_program(state, slot) {
                        Some(base) => {
                            iio_execute(state, slot, base, idx, val);
                        }
                        None => state.anomaly(Anomaly::UndefinedIio(slot)),
                    }
                }
                _ => return Err(AtomError::BadArgClass),
            }
        }
        ARG_PS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            match frame.ps.get_mut(usize::from(idx)) {
                Some(slot) => *slot = val,
                None => state.anomaly(Anomaly::PsIndex(idx)),
            }
        }
        ARG_WS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            match idx {
                WS_QUOTIENT => state.divmul[0] = val,
                WS_REMAINDER => state.divmul[1] = val,
                WS_DATAPTR => state.data_block = val as u16,
                WS_SHIFT => state.shift = val as u8,
                WS_OR_MASK | WS_AND_MASK => {}
                WS_FB_WINDOW => state.fb_base = val,
                WS_ATTRIBUTES => state.io_attr = val as u16,
                WS_REGPTR => state.reg_block = val as u16,
                _ => match state.scratch.get_mut(usize::from(idx)) {
                    Some(slot) => *slot = val,
                    None => state.anomaly(Anomaly::WsIndex(idx)),
                },
            }
        }
        ARG_FB => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            let byte = state.fb_base.wrapping_add(u32::from(idx) * 4);
            match state.fb_scratch.get_mut(byte as usize / 4) {
                Some(slot) => *slot = val,
                None => state.anomaly(Anomaly::FbIndex(byte)),
            }
        }
        ARG_PLL => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            state.hooks.pll_write(u32::from(idx), val);
        }
        ARG_MC => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            state.hooks.mc_write(u32::from(idx), val);
        }
        _ => return Err(AtomError::BadArgClass),
    }
    Ok(())
}

// ── Per-opcode handlers (atom.c) ─────────────────────────────────

/// What one opcode asks the machine to do next.
enum Flow<'a> {
    Next,
    Eot,
    Delay(u64),
    Call(ResolvedTable<'a>),
}

/// `atom_op_add/and/or/xor/sub`: read dst (with saved), read src,
/// combine, write dst.
fn binop<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
    op: impl Fn(u32, u32) -> u32,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let mut dptr = *ptr;
    let (dst, saved) = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    put_dst(state, frame, arg, attr, &mut dptr, op(dst, src), saved)
}

fn op_move<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let mut dptr = *ptr;
    // Full DWORD writes skip the dst pre-read.
    let saved = if ((attr >> 3) & 7) != SRC_DWORD {
        get_dst(state, frame, arg, attr, ptr)?.1
    } else {
        skip_dst(frame, arg, attr, ptr)?;
        0xCDCD_CDCD
    };
    let src = get_src(state, frame, attr, ptr)?;
    put_dst(state, frame, arg, attr, &mut dptr, src, saved)
}

/// The rewritten attribute byte `clear`/`shift_left`/`shift_right` use.
fn def_dst_attr(attr: u8) -> u8 {
    let attr = attr & 0x38;
    attr | (DEF_DST[(attr >> 3) as usize] << 6)
}

fn op_clear<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = def_dst_attr(frame.u8_at(*ptr)?);
    *ptr += 1;
    let mut dptr = *ptr;
    let (_, saved) = get_dst(state, frame, arg, attr, ptr)?;
    put_dst(state, frame, arg, attr, &mut dptr, 0, saved)
}

/// The two operands of compare/test/mul/div (`atom_get_dst(..., NULL)`
/// then `atom_get_src`).
fn operands<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(u32, u32), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let (dst, _) = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    Ok((dst, src))
}

fn op_jump<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    cond: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let target = usize::from(frame.u16_at(*ptr)?);
    *ptr += 2;
    let take = match cond {
        COND_ABOVE => state.cs_above,
        COND_ABOVEOREQUAL => state.cs_above || state.cs_equal,
        COND_ALWAYS => true,
        COND_BELOW => !(state.cs_above || state.cs_equal),
        COND_BELOWOREQUAL => !state.cs_above,
        COND_EQUAL => state.cs_equal,
        COND_NOTEQUAL => !state.cs_equal,
        _ => return Err(AtomError::BadArgClass),
    };
    if !take {
        return Ok(());
    }
    // `*ptr = ctx->start + target`: targets count from the table header,
    // and `code` starts after its 6-byte prelude (`ATOM_CT_CODE_PTR`).
    let local = target.checked_sub(6).ok_or(AtomError::BadJumpTarget)?;
    if local >= frame.code.len() {
        return Err(AtomError::BadJumpTarget);
    }
    let now = state.hooks.now_ms();
    let guard = &mut *frame.jump;
    if guard.target == Some(local) {
        guard.repeats = guard.repeats.saturating_add(1);
        let stuck = match now {
            Some(now) => now.saturating_sub(guard.since_ms) > ATOM_CMD_TIMEOUT_MS,
            None => guard.repeats > STUCK_REPEATS,
        };
        if stuck {
            return Err(AtomError::Stuck);
        }
    } else {
        *guard = JumpGuard {
            target: Some(local),
            since_ms: now.unwrap_or(0),
            repeats: 1,
        };
    }
    *ptr = local;
    Ok(())
}

fn op_delay(frame: &Frame, unit: u8, ptr: &mut usize) -> Result<u64, AtomError> {
    // `atom_op_delay`: udelay(count) or msleep(count).
    let count = u64::from(frame.u8_at(*ptr)?);
    *ptr += 1;
    Ok(if unit == UNIT_MICROSEC {
        count
    } else {
        count * 1000
    })
}

fn op_calltable<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    ptr: &mut usize,
) -> Result<Flow<'a>, AtomError> {
    let idx = frame.u8_at(*ptr)?;
    *ptr += 1;
    // `if (U16(ctx->ctx->cmd_table + 4 + 2 * idx))`: an absent table is a
    // no-op.
    if state.hooks.table_absent(idx) {
        return Ok(Flow::Next);
    }
    if frame.depth + 1 >= ATOM_EXECUTE_MAX_DEPTH {
        return Err(AtomError::CallTableTooDeep);
    }
    state
        .hooks
        .resolve(idx)
        .map(Flow::Call)
        .ok_or(AtomError::UnknownTable(idx))
}

fn op_setport<'a, H>(
    state: &mut AtomState<'a, H>,
    frame: &Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    match arg {
        PORT_ATI => {
            let port = frame.u16_at(*ptr)?;
            *ptr += 2;
            state.io_mode = if port == 0 {
                IO_MM
            } else {
                IO_IIO | u32::from(port)
            };
        }
        PORT_PCI => {
            *ptr += 1;
            state.io_mode = IO_PCI;
        }
        PORT_SYSIO => {
            *ptr += 1;
            state.io_mode = IO_SYSIO;
        }
        _ => return Err(AtomError::BadArgClass),
    }
    Ok(())
}

fn op_setdatablock<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &Frame,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let idx = frame.u8_at(*ptr)?;
    *ptr += 1;
    if state.bios.is_empty() {
        // Synthetic tables: blocks are table-relative.
        state.data_block = 0;
        return Ok(());
    }
    // atom_op_setdatablock: 0 clears, 255 selects this table's start,
    // otherwise U16(data_table + 4 + 2 * idx).
    state.data_block = match idx {
        0 => 0,
        255 => u16::try_from(frame.start).map_err(|_| AtomError::BytecodeTruncated)?,
        _ => {
            let at = state.data_table + 4 + 2 * usize::from(idx);
            let bytes = state
                .bios
                .get(at..at + 2)
                .ok_or(AtomError::BytecodeTruncated)?;
            u16::from_le_bytes([bytes[0], bytes[1]])
        }
    };
    Ok(())
}

/// `atom_op_shift_left` / `atom_op_shift_right`: the aligned destination
/// shifted by an immediate byte.
fn op_shift<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
    left: bool,
) -> Result<(), AtomError> {
    let attr = def_dst_attr(frame.u8_at(*ptr)?);
    *ptr += 1;
    let mut dptr = *ptr;
    let (dst, saved) = get_dst(state, frame, arg, attr, ptr)?;
    let shift = get_src_direct(frame, SRC_BYTE0, ptr)?;
    let dst = if left {
        dst.wrapping_shl(shift)
    } else {
        dst.wrapping_shr(shift)
    };
    put_dst(state, frame, arg, attr, &mut dptr, dst, saved)
}

/// `atom_op_shl` / `atom_op_shr`: "op needs to full dst value" — the raw
/// destination is shifted by a source operand, then realigned.
fn op_shl_shr<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
    left: bool,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let align = DST_TO_SRC[((attr >> 3) & 7) as usize][((attr >> 6) & 3) as usize] as usize;
    let mut dptr = *ptr;
    let (_, saved) = get_dst(state, frame, arg, attr, ptr)?;
    // `shift` is a uint8_t in atom.c.
    let shift = u32::from(get_src(state, frame, attr, ptr)? as u8);
    let dst = if left {
        saved.wrapping_shl(shift)
    } else {
        saved.wrapping_shr(shift)
    };
    let dst = (dst & ARG_MASK[align]) >> ARG_SHIFT[align];
    put_dst(state, frame, arg, attr, &mut dptr, dst, saved)
}

fn op_mask<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let mut dptr = *ptr;
    let (dst, saved) = get_dst(state, frame, arg, attr, ptr)?;
    let mask = get_src_direct(frame, (attr >> 3) & 7, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    put_dst(
        state,
        frame,
        arg,
        attr,
        &mut dptr,
        (dst & mask) | src,
        saved,
    )
}

fn op_switch<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let src = get_src(state, frame, attr, ptr)?;
    loop {
        let head = frame.u16_at(*ptr)?;
        if head == CASE_END {
            *ptr += 2;
            return Ok(());
        }
        if frame.u8_at(*ptr)? != CASE_MAGIC {
            // pr_info("Bad case"); return -- the next opcode is this byte.
            state.anomaly(Anomaly::BadCase);
            return Ok(());
        }
        *ptr += 1;
        let case_val = get_src(state, frame, (attr & 0x38) | ARG_IMM, ptr)?;
        let target = usize::from(frame.u16_at(*ptr)?);
        if case_val == src {
            if target < 6 || target - 6 >= frame.code.len() {
                return Err(AtomError::BadJumpTarget);
            }
            *ptr = target - 6;
            return Ok(());
        }
        *ptr += 2;
    }
}

fn op_processds(frame: &Frame, ptr: &mut usize) -> Result<(), AtomError> {
    let val = usize::from(frame.u16_at(*ptr)?);
    *ptr += val + 2;
    if *ptr > frame.code.len() {
        return Err(AtomError::BytecodeTruncated);
    }
    Ok(())
}

// ── Opcode → (handler, arg) dispatch table (atom.c:1087-1219) ────

#[derive(Copy, Clone)]
enum Op {
    Move(u8),
    And(u8),
    Or(u8),
    ShiftLeft(u8),
    ShiftRight(u8),
    Mul(u8),
    Div(u8),
    Add(u8),
    Sub(u8),
    SetPort(u8),
    SetRegBlock,
    SetFbBase,
    Compare(u8),
    Switch,
    Jump(u8),
    Test(u8),
    Delay(u8),
    CallTable,
    Repeat,
    Clear(u8),
    Nop,
    Eot,
    Mask(u8),
    PostCard,
    Beep,
    SaveReg,
    RestoreReg,
    SetDataBlock,
    Xor(u8),
    Shl(u8),
    Shr(u8),
    Debug,
    ProcessDs,
    Mul32(u8),
    Div32(u8),
}

/// Per `atom.c:1087-1219` `opcode_table[ATOM_OP_CNT]`. Index 0 is
/// unused (NULL handler in Linux → `BadOpcode`).
fn decode_op(op: u8) -> Result<Op, AtomError> {
    use Op::*;
    let o = match op {
        1 => Move(ARG_REG),
        2 => Move(ARG_PS),
        3 => Move(ARG_WS),
        4 => Move(ARG_FB),
        5 => Move(ARG_PLL),
        6 => Move(ARG_MC),
        7 => And(ARG_REG),
        8 => And(ARG_PS),
        9 => And(ARG_WS),
        10 => And(ARG_FB),
        11 => And(ARG_PLL),
        12 => And(ARG_MC),
        13 => Or(ARG_REG),
        14 => Or(ARG_PS),
        15 => Or(ARG_WS),
        16 => Or(ARG_FB),
        17 => Or(ARG_PLL),
        18 => Or(ARG_MC),
        19 => ShiftLeft(ARG_REG),
        20 => ShiftLeft(ARG_PS),
        21 => ShiftLeft(ARG_WS),
        22 => ShiftLeft(ARG_FB),
        23 => ShiftLeft(ARG_PLL),
        24 => ShiftLeft(ARG_MC),
        25 => ShiftRight(ARG_REG),
        26 => ShiftRight(ARG_PS),
        27 => ShiftRight(ARG_WS),
        28 => ShiftRight(ARG_FB),
        29 => ShiftRight(ARG_PLL),
        30 => ShiftRight(ARG_MC),
        31 => Mul(ARG_REG),
        32 => Mul(ARG_PS),
        33 => Mul(ARG_WS),
        34 => Mul(ARG_FB),
        35 => Mul(ARG_PLL),
        36 => Mul(ARG_MC),
        37 => Div(ARG_REG),
        38 => Div(ARG_PS),
        39 => Div(ARG_WS),
        40 => Div(ARG_FB),
        41 => Div(ARG_PLL),
        42 => Div(ARG_MC),
        43 => Add(ARG_REG),
        44 => Add(ARG_PS),
        45 => Add(ARG_WS),
        46 => Add(ARG_FB),
        47 => Add(ARG_PLL),
        48 => Add(ARG_MC),
        49 => Sub(ARG_REG),
        50 => Sub(ARG_PS),
        51 => Sub(ARG_WS),
        52 => Sub(ARG_FB),
        53 => Sub(ARG_PLL),
        54 => Sub(ARG_MC),
        55 => SetPort(PORT_ATI),
        56 => SetPort(PORT_PCI),
        57 => SetPort(PORT_SYSIO),
        58 => SetRegBlock,
        59 => SetFbBase,
        60 => Compare(ARG_REG),
        61 => Compare(ARG_PS),
        62 => Compare(ARG_WS),
        63 => Compare(ARG_FB),
        64 => Compare(ARG_PLL),
        65 => Compare(ARG_MC),
        66 => Switch,
        67 => Jump(COND_ALWAYS),
        68 => Jump(COND_EQUAL),
        69 => Jump(COND_BELOW),
        70 => Jump(COND_ABOVE),
        71 => Jump(COND_BELOWOREQUAL),
        72 => Jump(COND_ABOVEOREQUAL),
        73 => Jump(COND_NOTEQUAL),
        74 => Test(ARG_REG),
        75 => Test(ARG_PS),
        76 => Test(ARG_WS),
        77 => Test(ARG_FB),
        78 => Test(ARG_PLL),
        79 => Test(ARG_MC),
        80 => Delay(UNIT_MILLISEC),
        81 => Delay(UNIT_MICROSEC),
        82 => CallTable,
        83 => Repeat,
        84 => Clear(ARG_REG),
        85 => Clear(ARG_PS),
        86 => Clear(ARG_WS),
        87 => Clear(ARG_FB),
        88 => Clear(ARG_PLL),
        89 => Clear(ARG_MC),
        90 => Nop,
        91 => Eot,
        92 => Mask(ARG_REG),
        93 => Mask(ARG_PS),
        94 => Mask(ARG_WS),
        95 => Mask(ARG_FB),
        96 => Mask(ARG_PLL),
        97 => Mask(ARG_MC),
        98 => PostCard,
        99 => Beep,
        100 => SaveReg,
        101 => RestoreReg,
        102 => SetDataBlock,
        103 => Xor(ARG_REG),
        104 => Xor(ARG_PS),
        105 => Xor(ARG_WS),
        106 => Xor(ARG_FB),
        107 => Xor(ARG_PLL),
        108 => Xor(ARG_MC),
        109 => Shl(ARG_REG),
        110 => Shl(ARG_PS),
        111 => Shl(ARG_WS),
        112 => Shl(ARG_FB),
        113 => Shl(ARG_PLL),
        114 => Shl(ARG_MC),
        115 => Shr(ARG_REG),
        116 => Shr(ARG_PS),
        117 => Shr(ARG_WS),
        118 => Shr(ARG_FB),
        119 => Shr(ARG_PLL),
        120 => Shr(ARG_MC),
        121 => Debug,
        122 => ProcessDs,
        123 => Mul32(ARG_PS),
        124 => Mul32(ARG_WS),
        125 => Div32(ARG_PS),
        126 => Div32(ARG_WS),
        _ => return Err(AtomError::BadOpcode(op)),
    };
    Ok(o)
}

fn run_op<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    frame: &mut Frame,
    op: Op,
    ptr: &mut usize,
) -> Result<Flow<'a>, AtomError> {
    use Op::*;
    match op {
        Move(a) => op_move(state, frame, a, ptr)?,
        And(a) => binop(state, frame, a, ptr, |d, s| d & s)?,
        Or(a) => binop(state, frame, a, ptr, |d, s| d | s)?,
        Xor(a) => binop(state, frame, a, ptr, |d, s| d ^ s)?,
        Add(a) => binop(state, frame, a, ptr, |d, s| d.wrapping_add(s))?,
        Sub(a) => binop(state, frame, a, ptr, |d, s| d.wrapping_sub(s))?,
        ShiftLeft(a) => op_shift(state, frame, a, ptr, true)?,
        ShiftRight(a) => op_shift(state, frame, a, ptr, false)?,
        Shl(a) => op_shl_shr(state, frame, a, ptr, true)?,
        Shr(a) => op_shl_shr(state, frame, a, ptr, false)?,
        Mul(a) => {
            let (dst, src) = operands(state, frame, a, ptr)?;
            state.divmul[0] = dst.wrapping_mul(src);
        }
        Mul32(a) => {
            // atom_op_mul32: the 64-bit product in divmul[1]:divmul[0].
            let (dst, src) = operands(state, frame, a, ptr)?;
            let product = u64::from(dst) * u64::from(src);
            state.divmul = [product as u32, (product >> 32) as u32];
        }
        Div(a) => {
            let (dst, src) = operands(state, frame, a, ptr)?;
            state.divmul = match src {
                0 => [0, 0],
                _ => [dst / src, dst % src],
            };
        }
        Div32(a) => {
            // atom_op_div32: divmul[1]:dst divided by src, the 64-bit
            // quotient in divmul[1]:divmul[0].
            let (dst, src) = operands(state, frame, a, ptr)?;
            state.divmul = match src {
                0 => [0, 0],
                _ => {
                    let quotient =
                        (u64::from(state.divmul[1]) << 32 | u64::from(dst)) / u64::from(src);
                    [quotient as u32, (quotient >> 32) as u32]
                }
            };
        }
        Compare(a) => {
            let (dst, src) = operands(state, frame, a, ptr)?;
            state.cs_equal = dst == src;
            state.cs_above = dst > src;
        }
        Test(a) => {
            let (dst, src) = operands(state, frame, a, ptr)?;
            state.cs_equal = (dst & src) == 0;
        }
        Jump(c) => op_jump(state, frame, c, ptr)?,
        Switch => op_switch(state, frame, ptr)?,
        SetPort(p) => op_setport(state, frame, p, ptr)?,
        SetRegBlock => {
            state.reg_block = frame.u16_at(*ptr)?;
            *ptr += 2;
        }
        SetFbBase => {
            let attr = frame.u8_at(*ptr)?;
            *ptr += 1;
            state.fb_base = get_src(state, frame, attr, ptr)?;
        }
        SetDataBlock => op_setdatablock(state, frame, ptr)?,
        Delay(u) => return op_delay(frame, u, ptr).map(Flow::Delay),
        CallTable => return op_calltable(state, frame, ptr),
        Clear(a) => op_clear(state, frame, a, ptr)?,
        Mask(a) => op_mask(state, frame, a, ptr)?,
        ProcessDs => op_processds(frame, ptr)?,
        // Linux: pr_info-and-return no-ops.
        Repeat | SaveReg | RestoreReg => {}
        // Linux: printk no-ops with no operands.
        Nop | Beep => {}
        // Linux: each takes a single u8 operand it just prints.
        PostCard | Debug => {
            frame.u8_at(*ptr)?;
            *ptr += 1;
        }
        Eot => return Ok(Flow::Eot),
    }
    Ok(Flow::Next)
}

// ── Machine (amdgpu_atom_execute_table_locked) ───────────────────

/// What [`Machine::step`] did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// One opcode ran; more remain.
    Continue,
    /// A DELAY opcode ran: wait this many microseconds, then step again
    /// (`udelay` below 1000, `msleep` otherwise in Linux).
    Delay(u64),
    /// The entry table reached its EOT.
    Done,
}

/// Where the last opcode came from, for traces and failure reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OpSite {
    pub opcode: u8,
    /// Image offset of the executing table's header (`ctx->start`).
    pub table_start: usize,
    /// Offset of the opcode within the table body (after the prelude).
    pub offset: usize,
    /// CALLTABLE depth (0 for the entry table).
    pub depth: u32,
}

#[derive(Debug)]
struct Record<'c> {
    code: &'c [u8],
    ptr: usize,
    /// Offset of this execution's PS window in the entry table's PS.
    ps_base: usize,
    ps_shift: usize,
    start: usize,
    /// The caller's WS while this table runs on its own.
    saved_ws: Option<Vec<u32>>,
    jump: JumpGuard,
}

/// One `amdgpu_atom_execute_table` in progress: an explicit CALLTABLE
/// stack, stepped one opcode at a time. Dropping it mid-way leaves `state`
/// holding the innermost table's WS; discard the state with it.
pub struct Machine<'c, 'p> {
    stack: Vec<Record<'c>>,
    ps: &'p mut [u32],
    steps: u64,
    clockless: bool,
    last: Option<OpSite>,
}

impl fmt::Debug for Machine<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Machine")
            .field("depth", &self.stack.len())
            .field("steps", &self.steps)
            .field("last", &self.last)
            .finish()
    }
}

impl<'c, 'p> Machine<'c, 'p> {
    /// `amdgpu_atom_execute_table`: reset the per-execution context
    /// (data block, register block, FB window, I/O mode, divmul), resolve
    /// `table_id` and give it its own zeroed WS. `params` is the caller's
    /// PS (`params_size` dwords).
    pub fn start<'a: 'c, H: Hooks<'a>>(
        state: &mut AtomState<'a, H>,
        table_id: u8,
        params: &'p mut [u32],
    ) -> Result<Self, AtomError> {
        let table = state
            .hooks
            .resolve(table_id)
            .ok_or(AtomError::UnknownTable(table_id))?;
        state.data_block = 0;
        state.reg_block = 0;
        state.fb_base = 0;
        state.io_mode = IO_MM;
        state.divmul = [0, 0];
        if state.iio.is_none() && !state.bios.is_empty() {
            state.index_iio();
        }
        let saved_ws = table
            .ws_dwords
            .map(|ws| core::mem::replace(&mut state.scratch, vec![0u32; ws]));
        Ok(Self {
            stack: vec![Record {
                code: table.body,
                ptr: 0,
                ps_base: 0,
                ps_shift: table.ps_dwords,
                start: table.start,
                saved_ws,
                jump: JumpGuard::default(),
            }],
            ps: params,
            steps: 0,
            clockless: state.hooks.now_ms().is_none(),
            last: None,
        })
    }
    /// Run raw bytecode as an entry table, without the per-execution reset
    /// or a WS of its own (synthetic tables).
    pub fn from_bytes(code: &'c [u8], params: &'p mut [u32], ps_shift: usize) -> Self {
        Self {
            stack: vec![Record {
                code,
                ptr: 0,
                ps_base: 0,
                ps_shift,
                start: 0,
                saved_ws: None,
                jump: JumpGuard::default(),
            }],
            ps: params,
            steps: 0,
            clockless: true,
            last: None,
        }
    }
    /// Current CALLTABLE depth (1 for the entry table, 0 when done).
    pub fn depth(&self) -> usize {
        self.stack.len()
    }
    pub fn steps(&self) -> u64 {
        self.steps
    }
    pub fn last(&self) -> Option<OpSite> {
        self.last
    }
    /// Execute one opcode. An error unwinds every frame (restoring the
    /// caller's WS) and is terminal.
    pub fn step<'a: 'c, H: Hooks<'a>>(
        &mut self,
        state: &mut AtomState<'a, H>,
    ) -> Result<Step, AtomError> {
        let result = self.step_inner(state);
        if result.is_err() {
            while let Some(record) = self.stack.pop() {
                if let Some(ws) = record.saved_ws {
                    state.scratch = ws;
                }
            }
        }
        result
    }
    /// Return from the current table (EOT, or one Linux stops early),
    /// restoring the caller's WS.
    fn end_frame<'a: 'c, H: Hooks<'a>>(&mut self, state: &mut AtomState<'a, H>) -> Step {
        if let Some(ws) = self.stack.pop().and_then(|r| r.saved_ws) {
            state.scratch = ws;
        }
        if self.stack.is_empty() {
            Step::Done
        } else {
            Step::Continue
        }
    }
    fn step_inner<'a: 'c, H: Hooks<'a>>(
        &mut self,
        state: &mut AtomState<'a, H>,
    ) -> Result<Step, AtomError> {
        let depth = self.stack.len();
        let Some(record) = self.stack.last_mut() else {
            return Ok(Step::Done);
        };
        let base = record.ps_base.min(self.ps.len());
        let mut ptr = record.ptr;
        let opcode = *record.code.get(ptr).ok_or(AtomError::BytecodeTruncated)?;
        self.last = Some(OpSite {
            opcode,
            table_start: record.start,
            offset: ptr,
            depth: depth as u32 - 1,
        });
        ptr += 1;
        let op = if opcode == 0 || opcode >= ATOM_OP_CNT {
            None
        } else {
            Some(decode_op(opcode)?)
        };
        let Some(op) = op else {
            // atom.c: `if (op < ATOM_OP_CNT && op > 0) ... else break;` --
            // the table (only this CALLTABLE frame) ends with success.
            state.anomaly(Anomaly::BadOpcode(opcode));
            record.ptr = ptr;
            self.steps += 1;
            return Ok(self.end_frame(state));
        };
        let mut frame = Frame {
            code: record.code,
            ps: &mut self.ps[base..],
            ps_shift: record.ps_shift,
            depth: depth as u32 - 1,
            start: record.start,
            jump: &mut record.jump,
        };
        let flow = match run_op(state, &mut frame, op, &mut ptr) {
            Err(AtomError::BadJumpTarget) => {
                state.anomaly(Anomaly::JumpTarget);
                record.ptr = ptr;
                self.steps += 1;
                return Ok(self.end_frame(state));
            }
            flow => flow?,
        };
        let shift = frame.ps_shift.min(frame.ps.len());
        record.ptr = ptr;
        self.steps += 1;
        if self.clockless && self.steps > STEP_CAP {
            return Err(AtomError::Stuck);
        }
        Ok(match flow {
            Flow::Next => Step::Continue,
            Flow::Delay(us) => Step::Delay(us),
            Flow::Eot => self.end_frame(state),
            Flow::Call(table) => {
                // `ctx->ps + ctx->ps_shift`, `ctx->ps_size - ctx->ps_shift`.
                let saved_ws = table
                    .ws_dwords
                    .map(|ws| core::mem::replace(&mut state.scratch, vec![0u32; ws]));
                self.stack.push(Record {
                    code: table.body,
                    ptr: 0,
                    ps_base: base + shift,
                    ps_shift: table.ps_dwords,
                    start: table.start,
                    saved_ws,
                    jump: JumpGuard::default(),
                });
                Step::Continue
            }
        })
    }
}

fn drive<'a: 'c, 'c, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    mut machine: Machine<'c, '_>,
) -> Result<(), AtomError> {
    loop {
        match machine.step(state)? {
            Step::Continue => {}
            Step::Delay(us) => state.hooks.delay_us(us),
            Step::Done => return Ok(()),
        }
    }
}

/// Execute the bytecode in `code` until EOT or an error. `params`
/// is the caller's PS. `ps_shift` is the table-header PS-shift
/// (Linux: `CU8(base + ATOM_CT_PS_PTR) & 0x7F`, divided by 4).
pub fn execute_bytes<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    code: &[u8],
    params: &mut [u32],
    ps_shift: usize,
) -> Result<(), AtomError> {
    drive(state, Machine::from_bytes(code, params, ps_shift))
}

/// Execute a command table by id, synchronously (`amdgpu_atom_execute_table`).
/// DELAY opcodes call [`Hooks::delay_us`]; use [`Machine`] to sleep
/// cooperatively instead.
pub fn execute_table<'a, H: Hooks<'a>>(
    state: &mut AtomState<'a, H>,
    table_id: u8,
    params: &mut [u32],
) -> Result<(), AtomError> {
    let machine = Machine::start(state, table_id, params)?;
    drive(state, machine)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_atom_vm_tests.rs"]
mod tests;
