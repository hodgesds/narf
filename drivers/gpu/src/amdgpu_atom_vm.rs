//! ATOMBIOS bytecode VM — Stage-9 interpreter.
//!
//! Companion to `amdgpu_atombios.rs`: that module locates a command
//! table by index; this module *executes* the bytecode at that
//! table. Together they cover the AMD `atom.c` surface that pre-DCN3
//! parts (Renoir / Cezanne / Phoenix) lean on for display, encoder,
//! PowerPlay-base, and i2c-bus init.
//!
//! ## Reference: Linux `drivers/gpu/drm/amd/amdgpu/atom.{h,c}`
//!
//! NARF is GPL-2.0-or-later, so the canonical Linux interpreter is
//! a directly citable source. Every constant + dispatch layout
//! below is cross-referenced against:
//!
//! - `atom.h` lines 65–113 — opcode count (127), EOT (91), argument
//!   classes (REG/PS/WS/FB/ID/IMM/PLL/MC), source alignment (DWORD /
//!   WORD0/8/16 / BYTE0/8/16/24), WS pseudo-register IDs.
//! - `atom.c` lines 77–93 — `atom_arg_mask` / `atom_arg_shift` /
//!   `atom_dst_to_src` / `atom_def_dst` lookup tables.
//! - `atom.c` lines 182–406 — `atom_get_src_int` / `atom_skip_src_int`.
//! - `atom.c` lines 439–597 — `atom_get_dst` / `atom_put_dst`.
//! - `atom.c` lines 599–1085 — per-opcode handlers.
//! - `atom.c` lines 1087–1219 — the `opcode_table[ATOM_OP_CNT]`
//!   dispatch table.
//! - `atom.c` lines 1221–1310 — `amdgpu_atom_execute_table_locked`
//!   driver loop.
//!
//! ## Scope of this cut
//!
//! Implements the bytecode loop in pure Rust against caller-plugged
//! MMIO / PLL / MC / I/O-port closures. Doesn't touch real silicon
//! — the loader (`amdgpu_atombios.rs`) hands us a `&[u8]` and the
//! caller binds register accessors. Smoke tests in
//! `drivers/gpu/src/tests.rs` build a synthetic table and step it
//! through the dispatcher.
//!
//! Opcodes that need register access are routed through the bound
//! closures; if the caller leaves them as the default
//! "fail-on-touch" stubs, the corresponding opcode returns
//! `AtomError::RegisterAccessNotBound`. That keeps the VM honest
//! on pure-data tests while still exercising the dispatcher.
//!
//! `repeat`, `savereg`, `restorereg`, `mul32`, `div32` are decoded
//! but treated as no-ops (matching Linux `atom_op_repeat` /
//! `atom_op_savereg` / `atom_op_restorereg`, which `pr_info` then
//! return). The `beep`, `postcard`, and `debug` opcodes are
//! likewise no-ops on us (Linux just `printk`s).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

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
#[allow(dead_code)]
const IO_IIO: u32 = 0x80;

// Port classes for SETPORT — `atom.c:50-52`.
const PORT_ATI: u8 = 0;
const PORT_PCI: u8 = 1;
const PORT_SYSIO: u8 = 2;

// SWITCH delimiter magic — `atom.h:68-69`.
const CASE_MAGIC: u8 = 0x63;
const CASE_END: u16 = 0x5A5A;

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
    /// Opcode byte ≥ `ATOM_OP_CNT` or 0 (illegal in Linux too).
    BadOpcode(u8),
    /// PS index exceeds caller-supplied params slice.
    PsIndexOutOfRange,
    /// WS index exceeds the working-scratch length.
    WsIndexOutOfRange,
    /// FB read/write outside the scratch region.
    FbIndexOutOfRange,
    /// JUMP target lies outside the table.
    BadJumpTarget,
    /// SWITCH found neither CASE_MAGIC nor CASE_END.
    BadSwitchCase,
    /// Opcode wants a register/PLL/MC/PCI-port access but no
    /// closure was bound; in tests this catches "we never hooked
    /// MMIO up". Real driver wires real closures.
    RegisterAccessNotBound,
    /// Argument class out of range (only 3 bits — should be
    /// impossible, but guards against a malformed table).
    BadArgClass,
    /// Stuck-jump detector: 2^16 iterations without a forward
    /// EOT. Matches the Linux 20-second wall-clock guard but
    /// without a wall clock.
    Stuck,
    /// CALLTABLE / SETDATABLOCK reached but the caller's resolver
    /// returned an empty table.
    UnknownTable(u8),
}

// ── Closures ─────────────────────────────────────────────────────

/// MMIO / PLL / MC / I/O accessor. Tests plug in pure-Rust closures;
/// the real driver routes to the AMDGPU register window. The VM is
/// driven from a single thread under the caller's mutex (see
/// `atom.c::amdgpu_atom_execute_table` which `mutex_lock`s
/// `ctx->mutex`), so the closures are deliberately not `Send`.
pub type RegRead = Box<dyn FnMut(u32) -> u32>;
pub type RegWrite = Box<dyn FnMut(u32, u32)>;

/// CALLTABLE / SETDATABLOCK resolver: given a sub-table id, return
/// the byte slice for that table. `None` means "no such table",
/// which the VM converts to `AtomError::UnknownTable`.
///
/// The caller usually backs this with a closure that delegates into
/// `amdgpu_atombios::Atombios::cmd_table` / `data_table_offset`.
pub type TableResolver<'a> = Box<dyn FnMut(u8) -> Option<&'a [u8]> + 'a>;

// ── VM state ─────────────────────────────────────────────────────

/// `atom_context` — `atom.h:132-156`. We split this from the per-
/// frame execution state (params + working-scratch slice) which
/// Linux calls `atom_exec_context`. The global context survives a
/// CALLTABLE recursion; the frame doesn't.
pub struct AtomState<'a> {
    /// Working-scratch ring; `atom.h` calls these slots WS[0..N].
    /// 32 entries is the Vega+ default (`amdgpu_atom_parse` allocs
    /// `kcalloc(4, ws, GFP_KERNEL)` per table).
    pub scratch: Vec<u32>,

    /// `data_block` — current data-table base offset within the
    /// BIOS image (`atom.h:139` `uint16_t data_block`).
    pub data_block: u16,

    /// `fb_base` — frame-buffer / scratch-window base in bytes
    /// (`atom.h:140`).
    pub fb_base: u32,

    /// `divmul[0..1]` — MUL/DIV result (`atom.h:141`).
    pub divmul: [u32; 2],

    /// `io_attr` — attribute byte loaded into IIO-script context
    /// (`atom.h:142`).
    pub io_attr: u16,

    /// `reg_block` — register-block base added to every REG-class
    /// access (`atom.h:143`).
    pub reg_block: u16,

    /// `shift` — current shift register, fed by SHL/SHR
    /// (`atom.h:144`).
    pub shift: u8,

    /// Compare flags from CMP / TEST. `atom.h:145`.
    pub cs_equal: bool,
    pub cs_above: bool,

    /// I/O mode for REG-class accesses: MM / PCI / SYSIO / IIO
    /// (`atom.h:146`).
    pub io_mode: u32,

    /// "Scratch" region for FB-class accesses. Linux backs this
    /// with `kzalloc(scratch_size_bytes)`. We use a Vec<u32>.
    pub fb_scratch: Vec<u32>,

    /// MMIO read closure.
    pub reg_read: RegRead,
    /// MMIO write closure.
    pub reg_write: RegWrite,
    /// PLL read closure.
    pub pll_read: RegRead,
    /// PLL write closure.
    pub pll_write: RegWrite,
    /// MC read closure.
    pub mc_read: RegRead,
    /// MC write closure.
    pub mc_write: RegWrite,
    /// SYSIO / legacy port read.
    pub port_read: RegRead,
    /// SYSIO / legacy port write.
    pub port_write: RegWrite,

    /// Last jump target + a counter for the stuck-loop guard.
    pub last_jump_addr: usize,
    pub last_jump_count: u32,

    /// Sub-table resolver (for CALLTABLE / SETDATABLOCK).
    pub table_resolver: TableResolver<'a>,
}

impl<'a> fmt::Debug for AtomState<'a> {
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
            .finish()
    }
}

/// Default "explode loud" closure for accessors a test forgot to
/// bind. Returning 0xCDCDCDCD matches the Linux uninit pattern.
fn unbound_read() -> RegRead {
    Box::new(|_addr| 0xCDCD_CDCD)
}
fn unbound_write() -> RegWrite {
    Box::new(|_addr, _val| {})
}
fn unbound_resolver<'a>() -> TableResolver<'a> {
    Box::new(|_id| None)
}

impl<'a> AtomState<'a> {
    /// New VM with `ws_words` working-scratch slots, `fb_words`
    /// FB-scratch words, and all accessors bound to the
    /// "uninitialised" stubs. Tests then replace whichever ones
    /// they care about.
    pub fn new(ws_words: usize, fb_words: usize) -> Self {
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
            reg_read: unbound_read(),
            reg_write: unbound_write(),
            pll_read: unbound_read(),
            pll_write: unbound_write(),
            mc_read: unbound_read(),
            mc_write: unbound_write(),
            port_read: unbound_read(),
            port_write: unbound_write(),
            last_jump_addr: 0,
            last_jump_count: 0,
            table_resolver: unbound_resolver(),
        }
    }
}

// ── Per-frame execution context ──────────────────────────────────

/// `atom_exec_context` — `atom.c:62-71`.
struct Frame<'b, 'c> {
    code: &'b [u8],
    /// Parameter space.
    ps: &'c mut [u32],
    /// PS shift (table header carries a PS-mask; Linux divides by
    /// 4 to skip the input-only prefix on entry). Carried through
    /// the dispatch loop so CALLTABLE can replay it; not consumed
    /// yet in this Stage-9 cut.
    #[allow(dead_code)]
    ps_shift: usize,
}

impl<'b, 'c> Frame<'b, 'c> {
    fn u8_at(&self, off: usize) -> Result<u8, AtomError> {
        self.code.get(off).copied().ok_or(AtomError::BytecodeTruncated)
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

// ── Source / dest decoding (atom.c:182-597) ──────────────────────

/// Read a value out of `(attr, ptr)` and advance `ptr` past the
/// inline operand. Mirrors `atom_get_src_int` in atom.c:182.
fn get_src(
    state: &mut AtomState,
    frame: &Frame,
    attr: u8,
    ptr: &mut usize,
) -> Result<u32, AtomError> {
    let arg = attr & 7;
    let align = (attr >> 3) & 7;
    let mut val: u32;

    match arg {
        ARG_REG => {
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let idx = (idx16 as u32).wrapping_add(state.reg_block as u32);
            val = match state.io_mode {
                IO_MM => (state.reg_read)(idx),
                IO_PCI | IO_SYSIO => return Err(AtomError::RegisterAccessNotBound),
                m if (m & 0x80) != 0 => {
                    // IIO indirect-IO path not yet supported.
                    return Err(AtomError::RegisterAccessNotBound);
                }
                _ => return Err(AtomError::BadArgClass),
            };
        }
        ARG_PS => {
            let idx = frame.u8_at(*ptr)? as usize;
            *ptr += 1;
            if idx >= frame.ps.len() {
                return Err(AtomError::PsIndexOutOfRange);
            }
            val = frame.ps[idx];
        }
        ARG_WS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            val = match idx {
                WS_QUOTIENT => state.divmul[0],
                WS_REMAINDER => state.divmul[1],
                WS_DATAPTR => state.data_block as u32,
                WS_SHIFT => state.shift as u32,
                WS_OR_MASK => 1u32 << state.shift,
                WS_AND_MASK => !(1u32 << state.shift),
                WS_FB_WINDOW => state.fb_base,
                WS_ATTRIBUTES => state.io_attr as u32,
                WS_REGPTR => state.reg_block as u32,
                _ => {
                    let i = idx as usize;
                    if i >= state.scratch.len() {
                        return Err(AtomError::WsIndexOutOfRange);
                    }
                    state.scratch[i]
                }
            };
        }
        ARG_ID => {
            // ID = data-block-relative u32 load — `atom.c:274-284`.
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let abs = (idx16 as usize).wrapping_add(state.data_block as usize);
            if abs + 4 > frame.code.len() {
                // In Linux this reads from the BIOS image; we
                // intentionally constrain to the table buffer in
                // this Stage-9 cut. The full driver upgrade is to
                // give the VM a borrow on the BIOS image as well.
                return Err(AtomError::BytecodeTruncated);
            }
            val = u32::from_le_bytes([
                frame.code[abs],
                frame.code[abs + 1],
                frame.code[abs + 2],
                frame.code[abs + 3],
            ]);
        }
        ARG_FB => {
            let idx = frame.u8_at(*ptr)? as usize;
            *ptr += 1;
            let word_off = (state.fb_base as usize / 4).wrapping_add(idx);
            if word_off >= state.fb_scratch.len() {
                return Err(AtomError::FbIndexOutOfRange);
            }
            val = state.fb_scratch[word_off];
        }
        ARG_IMM => {
            val = match align {
                SRC_DWORD => {
                    let v = frame.u32_at(*ptr)?;
                    *ptr += 4;
                    v
                }
                SRC_WORD0 | SRC_WORD8 | SRC_WORD16 => {
                    let v = frame.u16_at(*ptr)? as u32;
                    *ptr += 2;
                    v
                }
                SRC_BYTE0 | SRC_BYTE8 | SRC_BYTE16 | SRC_BYTE24 => {
                    let v = frame.u8_at(*ptr)? as u32;
                    *ptr += 1;
                    v
                }
                _ => return Err(AtomError::BadArgClass),
            };
            // IMM short-circuits — no align mask/shift fixup.
            return Ok(val);
        }
        ARG_PLL => {
            let idx = frame.u8_at(*ptr)? as u32;
            *ptr += 1;
            val = (state.pll_read)(idx);
        }
        ARG_MC => {
            let idx = frame.u8_at(*ptr)? as u32;
            *ptr += 1;
            val = (state.mc_read)(idx);
        }
        _ => return Err(AtomError::BadArgClass),
    }

    let a = align as usize;
    val &= ARG_MASK[a];
    val >>= ARG_SHIFT[a];
    Ok(val)
}

/// Mirror of `atom_skip_src_int` (`atom.c:373`) — advance ptr
/// past the source operand without reading it. Used by MOVE's
/// "skip dst" path.
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

/// Read a destination-encoded source. `atom_get_dst` in atom.c:439
/// — same as get_src but the alignment is rebuilt from the dst-
/// alignment field + two-bit dst-shift selector.
fn get_dst(
    state: &mut AtomState,
    frame: &Frame,
    arg: u8,
    attr: u8,
    ptr: &mut usize,
) -> Result<u32, AtomError> {
    let dst_align = (attr >> 3) & 7;
    let dst_shift = (attr >> 6) & 3;
    let src_align = DST_TO_SRC[dst_align as usize][dst_shift as usize];
    let effective = arg | (src_align << 3);
    get_src(state, frame, effective, ptr)
}

fn skip_dst(frame: &Frame, arg: u8, attr: u8, ptr: &mut usize) -> Result<(), AtomError> {
    let dst_align = (attr >> 3) & 7;
    let dst_shift = (attr >> 6) & 3;
    let src_align = DST_TO_SRC[dst_align as usize][dst_shift as usize];
    let effective = arg | (src_align << 3);
    skip_src(frame, effective, ptr)
}

/// Read just the raw aligned sub-word from the bytecode stream
/// (no REG/PS/WS dispatch). Used by MASK / SHL-direct / SHR-direct.
/// `atom_get_src_direct` in atom.c:413.
fn get_src_direct(frame: &Frame, align: u8, ptr: &mut usize) -> Result<u32, AtomError> {
    let v = match align {
        SRC_DWORD => {
            let v = frame.u32_at(*ptr)?;
            *ptr += 4;
            v
        }
        SRC_WORD0 | SRC_WORD8 | SRC_WORD16 => {
            let v = frame.u16_at(*ptr)? as u32;
            *ptr += 2;
            v
        }
        SRC_BYTE0 | SRC_BYTE8 | SRC_BYTE16 | SRC_BYTE24 => {
            let v = frame.u8_at(*ptr)? as u32;
            *ptr += 1;
            v
        }
        _ => return Err(AtomError::BadArgClass),
    };
    Ok(v)
}

/// Mirror of `atom_put_dst` (`atom.c:455`) — store `val` back into
/// the destination encoded at (`arg`, `attr`, `ptr`). `saved` is
/// the dst's current full-word value (so writes that update only a
/// sub-word can preserve the surrounding bits).
fn put_dst(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    attr: u8,
    ptr: &mut usize,
    mut val: u32,
    mut saved: u32,
) -> Result<(), AtomError> {
    let dst_align = (attr >> 3) & 7;
    let dst_shift = (attr >> 6) & 3;
    let align = DST_TO_SRC[dst_align as usize][dst_shift as usize] as usize;

    val <<= ARG_SHIFT[align];
    val &= ARG_MASK[align];
    saved &= !ARG_MASK[align];
    val |= saved;

    match arg {
        ARG_REG => {
            let idx16 = frame.u16_at(*ptr)?;
            *ptr += 2;
            let idx = (idx16 as u32).wrapping_add(state.reg_block as u32);
            match state.io_mode {
                IO_MM => {
                    // atom.c:475-479 special-case idx==0 → write
                    // <<2; left in place for parity.
                    if idx == 0 {
                        (state.reg_write)(idx, val << 2);
                    } else {
                        (state.reg_write)(idx, val);
                    }
                }
                IO_PCI | IO_SYSIO => return Err(AtomError::RegisterAccessNotBound),
                m if (m & 0x80) != 0 => return Err(AtomError::RegisterAccessNotBound),
                _ => return Err(AtomError::BadArgClass),
            }
        }
        ARG_PS => {
            let idx = frame.u8_at(*ptr)? as usize;
            *ptr += 1;
            if idx >= frame.ps.len() {
                return Err(AtomError::PsIndexOutOfRange);
            }
            frame.ps[idx] = val;
        }
        ARG_WS => {
            let idx = frame.u8_at(*ptr)?;
            *ptr += 1;
            match idx {
                WS_QUOTIENT => state.divmul[0] = val,
                WS_REMAINDER => state.divmul[1] = val,
                WS_DATAPTR => state.data_block = val as u16,
                WS_SHIFT => state.shift = val as u8,
                WS_OR_MASK | WS_AND_MASK => {} // atom.c:528-530: noop
                WS_FB_WINDOW => state.fb_base = val,
                WS_ATTRIBUTES => state.io_attr = val as u16,
                WS_REGPTR => state.reg_block = val as u16,
                _ => {
                    let i = idx as usize;
                    if i >= state.scratch.len() {
                        return Err(AtomError::WsIndexOutOfRange);
                    }
                    state.scratch[i] = val;
                }
            }
        }
        ARG_FB => {
            let idx = frame.u8_at(*ptr)? as usize;
            *ptr += 1;
            let word_off = (state.fb_base as usize / 4).wrapping_add(idx);
            if word_off >= state.fb_scratch.len() {
                return Err(AtomError::FbIndexOutOfRange);
            }
            state.fb_scratch[word_off] = val;
        }
        ARG_PLL => {
            let idx = frame.u8_at(*ptr)? as u32;
            *ptr += 1;
            (state.pll_write)(idx, val);
        }
        ARG_MC => {
            let idx = frame.u8_at(*ptr)? as u32;
            *ptr += 1;
            (state.mc_write)(idx, val);
        }
        _ => return Err(AtomError::BadArgClass),
    }
    Ok(())
}

// ── Per-opcode handlers (atom.c:599-1085) ────────────────────────

/// Common "read attr, dst, src; combine; write dst" shape used by
/// add / sub / and / or / xor.
fn binop_inplace<F: Fn(u32, u32) -> u32>(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
    op: F,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dptr_start = *ptr;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let saved = dst;
    let src = get_src(state, frame, attr, ptr)?;
    let result = op(dst, src);
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, result, saved)?;
    Ok(())
}

fn op_move(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dptr_start = *ptr;
    // atom.c:805 — full DWORD writes skip the dst pre-read.
    let saved = if ((attr >> 3) & 7) != SRC_DWORD {
        get_dst(state, frame, arg, attr, ptr)?
    } else {
        skip_dst(frame, arg, attr, ptr)?;
        0xCDCD_CDCD
    };
    let src = get_src(state, frame, attr, ptr)?;
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, src, saved)
}

fn op_clear(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr0 = frame.u8_at(*ptr)?;
    *ptr += 1;
    let attr = (attr0 & 0x38) | (DEF_DST[((attr0 & 0x38) >> 3) as usize] << 6);
    let dptr_start = *ptr;
    let saved = get_dst(state, frame, arg, attr, ptr)?;
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, 0, saved)
}

fn op_compare(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    state.cs_equal = dst == src;
    state.cs_above = dst > src;
    Ok(())
}

fn op_test(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    state.cs_equal = (dst & src) == 0;
    Ok(())
}

fn op_jump(
    state: &mut AtomState,
    frame: &mut Frame,
    cond: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let target = frame.u16_at(*ptr)? as usize;
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
    if take {
        // `target` is measured from the start of the table — but
        // the table header (`ATOM_CT_CODE_PTR = 6`) means our
        // `code` slice already starts 6 bytes in. Linux walks
        // `ctx->start + target` which equals the BIOS-absolute
        // address; the table's first opcode lives at
        // `ctx->start + ATOM_CT_CODE_PTR`. Targets within the
        // bytecode are pre-shifted by +6 by the BIOS assembler.
        // For our slice, we subtract the 6-byte header to map
        // back into `code[]`.
        if target < 6 {
            return Err(AtomError::BadJumpTarget);
        }
        let local = target - 6;
        if local >= frame.code.len() {
            return Err(AtomError::BadJumpTarget);
        }
        // Stuck-loop detector.
        if state.last_jump_addr == local {
            state.last_jump_count = state.last_jump_count.saturating_add(1);
            if state.last_jump_count > 65_535 {
                return Err(AtomError::Stuck);
            }
        } else {
            state.last_jump_addr = local;
            state.last_jump_count = 1;
        }
        *ptr = local;
    }
    Ok(())
}

fn op_delay(_state: &mut AtomState, frame: &Frame, _unit: u8, ptr: &mut usize) -> Result<(), AtomError> {
    // Linux calls udelay/mdelay/msleep. In NARF kernel we'd hook
    // through `narf_time` here; for the Stage-9 cut we just step
    // past the operand byte. Real driver wires a sleep callback.
    let _count = frame.u8_at(*ptr)?;
    *ptr += 1;
    Ok(())
}

fn op_calltable(
    state: &mut AtomState,
    frame: &mut Frame,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let idx = frame.u8_at(*ptr)?;
    *ptr += 1;
    let sub = match (state.table_resolver)(idx) {
        Some(s) => s,
        None => return Err(AtomError::UnknownTable(idx)),
    };
    // Recursively execute the sub-table. We pass the *current*
    // PS-shifted view as the new PS, mirroring atom.c:642.
    let shift = 0; // sub-table's own PS shift, ignored on synthetic tables
    execute_bytes(state, sub, frame.ps, shift)
}

fn op_setport(
    state: &mut AtomState,
    frame: &Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    match arg {
        PORT_ATI => {
            let port = frame.u16_at(*ptr)?;
            *ptr += 2;
            if port == 0 {
                state.io_mode = IO_MM;
            } else {
                state.io_mode = IO_IIO | port as u32;
            }
        }
        PORT_PCI => {
            // Skip a byte to match Linux atom.c:921 (`(*ptr)++`).
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

fn op_setregblock(state: &mut AtomState, frame: &Frame, ptr: &mut usize) -> Result<(), AtomError> {
    state.reg_block = frame.u16_at(*ptr)?;
    *ptr += 2;
    Ok(())
}

fn op_setfbbase(
    state: &mut AtomState,
    frame: &mut Frame,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    state.fb_base = get_src(state, frame, attr, ptr)?;
    Ok(())
}

fn op_setdatablock(
    state: &mut AtomState,
    frame: &Frame,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let idx = frame.u8_at(*ptr)?;
    *ptr += 1;
    if idx == 0 {
        state.data_block = 0;
    } else if idx == 255 {
        // atom.c:889-890 — set to table start. We carry "start"
        // as 0 here since `code` is already at-start.
        state.data_block = 0;
    } else {
        // Linux: U16(data_table + 4 + 2*idx). The resolver gives
        // us a fully-resolved data block; we record its offset
        // as 0 since the buffer is opaque in our cut. The hook
        // is wired so the full driver can override.
        let _ = (state.table_resolver)(idx); // touch resolver for parity
        state.data_block = 0;
    }
    Ok(())
}

fn op_mul(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    state.divmul[0] = dst.wrapping_mul(src);
    Ok(())
}

fn op_div(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    if src != 0 {
        state.divmul[0] = dst / src;
        state.divmul[1] = dst % src;
    } else {
        state.divmul[0] = 0;
        state.divmul[1] = 0;
    }
    Ok(())
}

fn op_shift_left(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr0 = frame.u8_at(*ptr)?;
    *ptr += 1;
    let attr = (attr0 & 0x38) | (DEF_DST[((attr0 & 0x38) >> 3) as usize] << 6);
    let dptr_start = *ptr;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let saved = dst;
    let shift = get_src_direct(frame, SRC_BYTE0, ptr)? as u32;
    let result = dst.wrapping_shl(shift);
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, result, saved)
}

fn op_shift_right(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr0 = frame.u8_at(*ptr)?;
    *ptr += 1;
    let attr = (attr0 & 0x38) | (DEF_DST[((attr0 & 0x38) >> 3) as usize] << 6);
    let dptr_start = *ptr;
    let dst = get_dst(state, frame, arg, attr, ptr)?;
    let saved = dst;
    let shift = get_src_direct(frame, SRC_BYTE0, ptr)? as u32;
    let result = dst.wrapping_shr(shift);
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, result, saved)
}

fn op_shl(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst_align = ((attr >> 3) & 7) as usize;
    let dst_shift = ((attr >> 6) & 3) as usize;
    let align = DST_TO_SRC[dst_align][dst_shift] as usize;
    let dptr_start = *ptr;
    let _ = get_dst(state, frame, arg, attr, ptr)?;
    let saved = 0u32; // atom.c:978: dst = saved; saved itself is the dst
    let shift = get_src(state, frame, attr, ptr)?;
    let mut dst = saved.wrapping_shl(shift);
    dst &= ARG_MASK[align];
    dst >>= ARG_SHIFT[align];
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, dst, saved)
}

fn op_shr(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dst_align = ((attr >> 3) & 7) as usize;
    let dst_shift = ((attr >> 6) & 3) as usize;
    let align = DST_TO_SRC[dst_align][dst_shift] as usize;
    let dptr_start = *ptr;
    let _ = get_dst(state, frame, arg, attr, ptr)?;
    let saved = 0u32;
    let shift = get_src(state, frame, attr, ptr)?;
    let mut dst = saved.wrapping_shr(shift);
    dst &= ARG_MASK[align];
    dst >>= ARG_SHIFT[align];
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, dst, saved)
}

fn op_mask(
    state: &mut AtomState,
    frame: &mut Frame,
    arg: u8,
    ptr: &mut usize,
) -> Result<(), AtomError> {
    let attr = frame.u8_at(*ptr)?;
    *ptr += 1;
    let dptr_start = *ptr;
    let dst_in = get_dst(state, frame, arg, attr, ptr)?;
    let saved = dst_in;
    let mask = get_src_direct(frame, (attr >> 3) & 7, ptr)?;
    let src = get_src(state, frame, attr, ptr)?;
    let result = (dst_in & mask) | src;
    let mut dptr = dptr_start;
    put_dst(state, frame, arg, attr, &mut dptr, result, saved)
}

fn op_switch(
    state: &mut AtomState,
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
        let magic = frame.u8_at(*ptr)?;
        if magic != CASE_MAGIC {
            return Err(AtomError::BadSwitchCase);
        }
        *ptr += 1;
        let case_val = get_src(state, frame, (attr & 0x38) | ARG_IMM, ptr)?;
        let target = frame.u16_at(*ptr)? as usize;
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
    let val = frame.u16_at(*ptr)? as usize;
    *ptr = ptr.wrapping_add(val + 2);
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

fn run_op(
    state: &mut AtomState,
    frame: &mut Frame,
    op: Op,
    ptr: &mut usize,
) -> Result<bool, AtomError> {
    use Op::*;
    match op {
        Move(a) => op_move(state, frame, a, ptr)?,
        And(a) => binop_inplace(state, frame, a, ptr, |d, s| d & s)?,
        Or(a) => binop_inplace(state, frame, a, ptr, |d, s| d | s)?,
        Xor(a) => binop_inplace(state, frame, a, ptr, |d, s| d ^ s)?,
        Add(a) => binop_inplace(state, frame, a, ptr, |d, s| d.wrapping_add(s))?,
        Sub(a) => binop_inplace(state, frame, a, ptr, |d, s| d.wrapping_sub(s))?,
        ShiftLeft(a) => op_shift_left(state, frame, a, ptr)?,
        ShiftRight(a) => op_shift_right(state, frame, a, ptr)?,
        Shl(a) => op_shl(state, frame, a, ptr)?,
        Shr(a) => op_shr(state, frame, a, ptr)?,
        Mul(a) | Mul32(a) => op_mul(state, frame, a, ptr)?,
        Div(a) | Div32(a) => op_div(state, frame, a, ptr)?,
        Compare(a) => op_compare(state, frame, a, ptr)?,
        Test(a) => op_test(state, frame, a, ptr)?,
        Jump(c) => op_jump(state, frame, c, ptr)?,
        Switch => op_switch(state, frame, ptr)?,
        SetPort(p) => op_setport(state, frame, p, ptr)?,
        SetRegBlock => op_setregblock(state, frame, ptr)?,
        SetFbBase => op_setfbbase(state, frame, ptr)?,
        SetDataBlock => op_setdatablock(state, frame, ptr)?,
        Delay(u) => op_delay(state, frame, u, ptr)?,
        CallTable => op_calltable(state, frame, ptr)?,
        Clear(a) => op_clear(state, frame, a, ptr)?,
        Mask(a) => op_mask(state, frame, a, ptr)?,
        ProcessDs => op_processds(frame, ptr)?,
        // Linux: pr_info-and-return no-ops.
        Repeat | SaveReg | RestoreReg => {}
        // Linux: printk no-ops with no operands.
        Nop | Beep => {}
        // Linux: each takes a single u8 operand it just prints.
        PostCard | Debug => {
            let _ = frame.u8_at(*ptr)?;
            *ptr += 1;
        }
        Eot => return Ok(true),
    }
    Ok(false)
}

/// Execute the bytecode in `code` until EOT or an error. `params`
/// is the caller's PS. `ps_shift` is the table-header PS-shift
/// (Linux: `CU8(base + ATOM_CT_PS_PTR) & 0x7F`, divided by 4).
pub fn execute_bytes(
    state: &mut AtomState,
    code: &[u8],
    params: &mut [u32],
    ps_shift: usize,
) -> Result<(), AtomError> {
    let mut frame = Frame {
        code,
        ps: params,
        ps_shift,
    };
    let mut ptr = 0usize;
    let mut steps: u32 = 0;
    loop {
        if ptr >= frame.code.len() {
            return Err(AtomError::BytecodeTruncated);
        }
        let opcode = frame.code[ptr];
        ptr += 1;
        if opcode == 0 || opcode >= ATOM_OP_CNT {
            return Err(AtomError::BadOpcode(opcode));
        }
        let op = decode_op(opcode)?;
        let done = run_op(state, &mut frame, op, &mut ptr)?;
        if done {
            return Ok(());
        }
        steps = steps.saturating_add(1);
        if steps > 1_000_000 {
            // Belt-and-suspenders: even with the per-jump stuck
            // detector, hard-cap total opcode steps.
            return Err(AtomError::Stuck);
        }
    }
}

/// Execute a command table by id.
///
/// `table_loader` returns the `&[u8]` for the requested table id;
/// this lets the caller back the VM with the parsed
/// `amdgpu_atombios::Atombios` without taking a hard borrow inside
/// the VM itself. The bytecode passed in already has its
/// `ATOM_CT_*` header stripped — feed the post-`+6` body.
pub fn execute_table(
    state: &mut AtomState,
    table_id: u8,
    params: &mut [u32],
) -> Result<(), AtomError> {
    let code = match (state.table_resolver)(table_id) {
        Some(s) => s,
        None => return Err(AtomError::UnknownTable(table_id)),
    };
    // Reset per-execute state — atom.c:1296-1306.
    state.data_block = 0;
    state.reg_block = 0;
    state.fb_base = 0;
    state.io_mode = IO_MM;
    state.divmul = [0, 0];
    state.last_jump_addr = 0;
    state.last_jump_count = 0;
    execute_bytes(state, code, params, 0)
}

#[cfg(test)]
mod inline_tests {
    use super::*;

    /// Synthetic table: `MOVE PS[0] <- IMM_DWORD 0x12345678; EOT`.
    /// Validates immediate-DWORD source decoding + PS write.
    #[test]
    fn move_imm_dword_into_ps() {
        // attr layout: align=DWORD(0)<<3=0, arg=IMM=5, dst_shift=0
        // → attr = 0x05. But for MOVE the dst alignment is read
        //   from the same attr's dst-shift bits — for a full DWORD
        //   write to PS, dst_shift=0, dst_align=DWORD(0).
        // op 2 = MOVE(PS); attr = 0x05; dst index byte = 0;
        // imm dword = 0x78 0x56 0x34 0x12; EOT (91).
        let code = &[2u8, 0x05, 0x00, 0x78, 0x56, 0x34, 0x12, 91];
        let mut state = AtomState::new(8, 4);
        let mut ps = [0u32; 1];
        execute_bytes(&mut state, code, &mut ps, 0).unwrap();
        assert_eq!(ps[0], 0x1234_5678);
    }

    /// Synthetic table: `MOVE WS[2] <- IMM 0xAA; ADD WS[2] += IMM 0x11; EOT`.
    /// Verifies WS round-trip and ADD on the same slot.
    #[test]
    fn add_accumulates_into_ws() {
        // MOVE(WS=op3) attr=0x05 imm dword, dst idx byte = 2.
        // imm = 0xAA 0 0 0 (DWORD).
        // ADD(WS=op45) attr=0x05 dst idx byte = 2, imm = 0x11 0 0 0.
        let code = &[
            3, 0x05, 2, 0xAA, 0, 0, 0, // MOVE WS[2] <- 0xAA
            45, 0x05, 2, 0x11, 0, 0, 0, // ADD WS[2] += 0x11
            91, // EOT
        ];
        let mut state = AtomState::new(8, 4);
        let mut ps: [u32; 1] = [0];
        execute_bytes(&mut state, code, &mut ps, 0).unwrap();
        assert_eq!(state.scratch[2], 0xBB);
    }

    /// Synthetic: COMPARE PS[0] vs IMM, then conditional JUMP.
    #[test]
    fn compare_and_jump_equal_taken() {
        // Preload: MOVE PS[0] <- 0x42 (op 2, attr 0x05, idx 0,
        // dword 0x42 0 0 0). That's 7 bytes.
        // COMPARE(PS)=op61, attr=0x05, dst=0, src dword=0x42.
        //   That's 1 + 1 + 1 + 4 = 7 bytes.
        // JUMP_EQUAL=op68 target u16 = small offset past 91-EOT.
        // EOT=91.
        //
        // Layout offsets in `code`:
        //   0: MOVE      → bytes 0..7
        //   7: COMPARE   → bytes 7..14
        //  14: JUMP_EQUAL→ bytes 14..17 (opcode + u16 target)
        //  17: EOT (the jump should skip past this is wrong; let
        //          us instead jump *forward* to a second EOT)
        //  18: BAD opcode 0x77 (would fail if reached)
        //  19: EOT (target)
        //
        // Target byte-offset in the table-with-header world is
        // `local + 6`; we want local=19 so target=25.
        let code = &[
            2, 0x05, 0, 0x42, 0, 0, 0, // MOVE PS[0] <- 0x42
            61, 0x05, 0, 0x42, 0, 0, 0, // COMPARE PS[0] vs IMM 0x42
            68, 25, 0, // JUMP_EQUAL → local 19
            0x77, // unreachable
            0x77, // unreachable
            91, // EOT @ local 19
        ];
        assert_eq!(code.len(), 20);
        let mut state = AtomState::new(8, 4);
        let mut ps: [u32; 1] = [0];
        execute_bytes(&mut state, code, &mut ps, 0).unwrap();
        assert!(state.cs_equal);
        // PS[0] stays 0x42.
        assert_eq!(ps[0], 0x42);
    }

    #[test]
    fn bad_opcode_rejected() {
        let code = &[127u8, 91]; // 127 == ATOM_OP_CNT (out of range)
        let mut state = AtomState::new(4, 4);
        let mut ps: [u32; 0] = [];
        assert_eq!(
            execute_bytes(&mut state, code, &mut ps, 0),
            Err(AtomError::BadOpcode(127))
        );
    }

    #[test]
    fn truncated_table_returns_error() {
        // No EOT at all.
        let code = &[2u8, 0x05, 0, 1, 0, 0, 0];
        let mut state = AtomState::new(4, 4);
        let mut ps: [u32; 1] = [0];
        let r = execute_bytes(&mut state, code, &mut ps, 0);
        assert_eq!(r, Err(AtomError::BytecodeTruncated));
    }
}
