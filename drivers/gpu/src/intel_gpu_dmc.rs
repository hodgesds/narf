//! Intel Gen12 DMC — Display Microcontroller firmware:
//! container parsing, validation, program load, and the
//! DC-state handoff the loaded program enables.
//!
//! ## What DMC is (and is not)
//!
//! Since Gen9 the display engine has its own
//! microcontroller. At runtime it saves and restores
//! display state across the deep display power states
//! (DC5/DC6) the host cannot reach on its own: with no DMC
//! firmware loaded, the driver must keep the display power
//! wells up and forgo those states entirely — on a laptop,
//! panel-off idle is one of the biggest power draws there
//! is. This module owns the firmware side of that bargain:
//!
//! - **Parse + validate** the `.bin` container (CSS header,
//!   package header, per-program DMC headers) exactly as
//!   the format defines it, refusing anything malformed
//!   *before* a single register is written — a corrupt
//!   blob leaves the machine in its previous, working
//!   state, with runtime PM simply staying off.
//! - **Load** each program into the DMC's program RAM over
//!   MMIO: event handlers quiesced first, payload dwords
//!   streamed to the program base, then the firmware's
//!   own MMIO initialisation table applied.
//! - **Hand off the DC states**: only with a main program
//!   loaded may the driver program `DC_STATE_EN` to allow
//!   DC5/DC6 — mirroring i915, where the allowed-DC mask is
//!   empty when DMC has no payload.
//!
//! Pipe DMC programs (per-pipe save/restore helpers) ride
//! in the same container and are loaded by the same path.
//! Event-handler *reconfiguration* at runtime (PSR/DCB
//! event routing) is display-pipeline policy and out of
//! scope here; the load-time handler discipline is not.
//!
//! ## Format + register facts — sources
//!
//! Derived from i915, the authoritative restatement of the
//! DMC firmware format and the display register map (the
//! same sourcing the rest of this crate uses). Files
//! consulted at torvalds/linux master, 2026-10-27:
//!
//! - `drivers/gpu/drm/i915/display/intel_dmc.c`: the
//!   container structs and the parser. CSS header: 32
//!   dwords, `module_type` 0x09 for DMC, `header_ver`
//!   "always 0x10000", `header_len` in dwords. Package
//!   header: `header_ver` 1 (≤ 20 FW-info entries) or 2
//!   (≤ 32); the on-disk table always occupies the *max*
//!   entry count, and `header_len` (dwords) covers header
//!   plus full table; `num_entries` beyond the max is
//!   clamped (i915 warns and clamps). FW-info entry:
//!   dmc_id (v2 only — v1 entries are all main),
//!   stepping/substepping with `'*'` wildcards, offset
//!   in dwords from the end of the package region; first
//!   stepping match per id wins ("more specific versions
//!   come first" in the file).
//!   DMC program header: signature "always 0x40403E3E";
//!   header versions 1 and 3. **v1 quirk**: its
//!   `header_len` is in *bytes* (128), v3's is in dwords
//!   (64 → 256 bytes); v1 has no start address — the
//!   payload loads at 0x80000; v1 carries ≤ 8 MMIO pairs,
//!   v3 ≤ 20. `fw_size` is in dwords, must be nonzero and
//!   fit both the remaining blob and the per-platform max
//!   (Gen12: `ICL_DMC_MAX_FW_SIZE` = 0x6000 bytes).
//!   MMIO-address and (v3) load-address sanity ranges are
//!   enforced per DMC id. The load conversation
//!   (`dmc_load_program`): disable all event handlers,
//!   stream the payload to `start_mmioaddr + 4i`, then
//!   write the MMIO table (with per-event disable fixups —
//!   see below); afterwards the driver sets the
//!   DC_STATE_DEBUG mask bits and takes a posting read.
//!   On TGL, i915 additionally rewrites a main-DMC
//!   VBLANK_A event-handler entry to VBLANK_DELAYED_A at
//!   parse time (the shipped firmware's HRR handler uses
//!   the wrong event; fixed firmware was never released),
//!   and at load time writes pipe-DMC event entries — and
//!   on TGL the main DMC's CLK_MSEC and VBLANK_DELAYED_A
//!   handlers — in disabled form.
//! - `drivers/gpu/drm/i915/display/intel_dmc_regs.h`: the
//!   event-handler register geometry (handler count 8 on
//!   Gen12; EVT_HTP at reg-base + 0x004, EVT_CTL at
//!   reg-base + 0x034, stride 4; main reg-base 0x8F000,
//!   pipe reg-bases 0x92000 + 0x400·(id−1) on Gen12), the
//!   EVT_CTL fields (ENABLE bit 31, TYPE bits [17:16] with
//!   EDGE_0_1 = 3, EVENT_ID bits [15:8]; event FALSE = 1),
//!   the program-base and MMIO sanity ranges, and the TGL
//!   DC5/DC6 entry counters (0x101084 / 0x101088).
//! - `drivers/gpu/drm/i915/display/intel_display_regs.h`:
//!   `DC_STATE_EN` = 0x45504, target field bits [1:0]
//!   (0 = disable, 1 = up to DC5, 2 = up to DC6, 3 = up to
//!   DC3CO); `DC_STATE_DEBUG` = 0x45520 with MASK_CORES
//!   bit 0 and MASK_MEMORY_UP bit 1.
//!
//! ## Where this parser is stricter than i915, and why
//!
//! - i915 does not compare the DMC header signature; the
//!   format documents it as a constant, so this parser
//!   refuses a mismatch. A blob that is not DMC firmware
//!   must never be streamed into program RAM.
//! - i915 likewise skips the CSS `module_type` /
//!   `header_ver` checks in its current parser; both are
//!   documented constants of the format and are enforced
//!   here.
//! - A malformed *pipe* program is tolerated exactly as
//!   i915 tolerates it (the slot stays empty; only the
//!   main program is mandatory), but a malformed *main*
//!   program returns the specific parse error instead of
//!   i915's generic "main program not found", so the
//!   failure is diagnosable from the log.
//! - PIPEC/PIPED programs are *skipped*, not loaded: the
//!   Gen12 register tables ground MMIO sanity ranges only
//!   for the main DMC and pipes A/B, and loading a program
//!   whose register table was range-checked against a
//!   guessed window would be fabrication. The skip is
//!   recorded in [`DmcFirmware::skipped_mask`]. (Gen12
//!   silicon in scope here — TGL — drives its pipe-DMC
//!   state save/restore for pipes C/D through the main
//!   program; ADL-P's 0x5F000 pipe window is display-13
//!   scope.)
//!
//! ## Composition
//!
//! Like the other Gen12 modules, this one owns no
//! register window: parse is pure (bytes in, validated
//! structure out — no MMIO at all), and load/verify/DC
//! operations take the caller's `&M: MmioWindow`. The
//! firmware blob itself arrives as a byte slice from
//! whatever firmware source the platform wires up; this
//! module neither knows nor cares where the bytes live.
//! Parse borrows the payload out of the blob (zero-copy),
//! so the blob must outlive the parsed firmware — the
//! natural shape for a blob loaded once at attach and kept
//! resident for reload-after-resume, which is exactly how
//! i915 keeps it.

use crate::intel_gpu_aux::MmioWindow;

// ── Container format constants (intel_dmc.c) ────────────────

/// CSS header size in bytes (32 dwords).
pub const CSS_HEADER_BYTES: usize = 128;
/// CSS `module_type` for DMC firmware.
pub const CSS_MODULE_TYPE_DMC: u32 = 0x09;
/// CSS `header_ver` — "always value would be 0x10000".
pub const CSS_HEADER_VER: u32 = 0x1_0000;
/// Byte offset of the CSS `version` field (dword 22).
pub const CSS_VERSION_OFFSET: usize = 88;
/// Package header size in bytes.
pub const PACKAGE_HEADER_BYTES: usize = 16;
/// FW-info entries the package table holds at version 1.
pub const PACKAGE_V1_MAX_ENTRIES: usize = 20;
/// FW-info entries the package table holds at version 2.
pub const PACKAGE_V2_MAX_ENTRIES: usize = 32;
/// One FW-info entry, in bytes.
pub const FW_INFO_BYTES: usize = 12;
/// DMC program header signature — "always 0x40403E3E".
pub const DMC_SIGNATURE: u32 = 0x4040_3E3E;
/// DMC header base (common v1/v3 prefix), in bytes.
pub const DMC_HEADER_BASE_BYTES: usize = 20;
/// DMC header v1 size in bytes.
pub const DMC_HEADER_V1_BYTES: usize = 128;
/// DMC header v3 size in bytes.
pub const DMC_HEADER_V3_BYTES: usize = 256;
/// Max MMIO init pairs in a v1 header.
pub const DMC_V1_MAX_MMIO_COUNT: usize = 8;
/// Max MMIO init pairs in a v3 header.
pub const DMC_V3_MAX_MMIO_COUNT: usize = 20;
/// Per-platform max payload, Gen12 (DISPLAY_VER12 →
/// ICL_DMC_MAX_FW_SIZE), in bytes. Callers pass their
/// platform's value to the parser; this is the Gen12 one.
pub const DMC_MAX_FW_SIZE_GEN12: usize = 0x6000;
/// Load address for v1 programs (no start field in v1).
pub const DMC_V1_LOAD_ADDR: u32 = 0x80000;
/// MMIO sanity range for v1 headers (any id).
pub const DMC_MMIO_RANGE_V1: (u32, u32) = (0x80000, 0x8FFFF);

// ── DMC ids ─────────────────────────────────────────────────

/// Number of DMC slots in the container (main + 4 pipes).
pub const DMC_SLOTS: usize = 5;

/// A DMC program slot: the main DMC or a per-pipe DMC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmcId {
    Main = 0,
    PipeA = 1,
    PipeB = 2,
    PipeC = 3,
    PipeD = 4,
}

impl DmcId {
    /// All slots, in container/load order.
    pub const ALL: [DmcId; DMC_SLOTS] = [
        DmcId::Main,
        DmcId::PipeA,
        DmcId::PipeB,
        DmcId::PipeC,
        DmcId::PipeD,
    ];

    /// The slot for container id `n`, if valid (0..=4).
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(DmcId::Main),
            1 => Some(DmcId::PipeA),
            2 => Some(DmcId::PipeB),
            3 => Some(DmcId::PipeC),
            4 => Some(DmcId::PipeD),
            _ => None,
        }
    }

    /// The container id / slot index.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Program-RAM window this id's payload must land in
    /// (v3 load-address sanity range, intel_dmc_regs.h).
    pub fn program_range(self) -> (u32, u32) {
        match self {
            DmcId::Main => (0x80000, 0x86FFF),
            DmcId::PipeA => (0x90000, 0x96FFF),
            DmcId::PipeB => (0x98000, 0x9EFFF),
            DmcId::PipeC => (0x52000, 0x53FFF),
            DmcId::PipeD => (0x59000, 0x5AFFF),
        }
    }

    /// MMIO sanity range for this id's v3 init table.
    /// Gen12 grounds main + pipes A/B only; pipes C/D
    /// return `None` (see the module header).
    pub fn mmio_range_v3(self) -> Option<(u32, u32)> {
        match self {
            DmcId::Main => Some((0x8F000, 0x8FFFF)),
            DmcId::PipeA => Some((0x92000, 0x93FFF)),
            DmcId::PipeB => Some((0x96000, 0x97FFF)),
            DmcId::PipeC | DmcId::PipeD => None,
        }
    }

    /// Base of this id's event-handler register block on
    /// Gen12 (intel_dmc_regs.h `_DMC_REG_MMIO_BASE`):
    /// main 0x8F000, pipes 0x92000 + 0x400·(id−1).
    pub fn evt_reg_base(self) -> Option<u32> {
        match self {
            DmcId::Main => Some(0x8F000),
            DmcId::PipeA => Some(0x92000),
            DmcId::PipeB => Some(0x92400),
            DmcId::PipeC | DmcId::PipeD => None,
        }
    }

    /// EVT_HTP register for `handler` (reg-base + 0x004,
    /// stride 4).
    pub fn evt_htp(self, handler: usize) -> Option<u32> {
        self.evt_reg_base()
            .map(|base| base + 0x004 + 4 * handler as u32)
    }

    /// EVT_CTL register for `handler` (reg-base + 0x034,
    /// stride 4).
    pub fn evt_ctl(self, handler: usize) -> Option<u32> {
        self.evt_reg_base()
            .map(|base| base + 0x034 + 4 * handler as u32)
    }
}

/// Event handlers per DMC on Gen12
/// (`DMC_EVENT_HANDLER_COUNT_GEN12`).
pub const EVT_HANDLER_COUNT_GEN12: usize = 8;
/// EVT_CTL ENABLE bit.
pub const EVT_CTL_ENABLE: u32 = 1 << 31;
/// EVT_CTL TYPE field mask, bits [17:16].
pub const EVT_CTL_TYPE_MASK: u32 = 0x3 << 16;
/// EVT_CTL TYPE value: edge 0→1.
pub const EVT_CTL_TYPE_EDGE_0_1: u32 = 3;
/// EVT_CTL EVENT_ID field mask, bits [15:8].
pub const EVT_CTL_EVENT_ID_MASK: u32 = 0xFF << 8;
/// The "false" event id — a handler bound to it never
/// fires.
pub const DMC_EVENT_FALSE: u32 = 0x1;
/// Main-DMC event ids used by the TGL fixups
/// (intel_dmc_regs.h `maindmc_event_id`).
pub const MAINDMC_EVENT_VBLANK_A: u32 = 0x32;
/// Main-DMC delayed-vblank event id.
pub const MAINDMC_EVENT_VBLANK_DELAYED_A: u32 = 0x2E;
/// Main-DMC millisecond-clock event id.
pub const MAINDMC_EVENT_CLK_MSEC: u32 = 0xBF;

/// The EVT_CTL value that disables a handler: type
/// EDGE_0_1, event FALSE, enable bit clear
/// (`disable_event_handler` in intel_dmc.c).
pub const EVT_CTL_DISABLED: u32 = (EVT_CTL_TYPE_EDGE_0_1 << 16) | (DMC_EVENT_FALSE << 8);

/// The disabled form of a firmware-supplied EVT_CTL value
/// (`dmc_evt_ctl_disable`): the enable bit is sticky —
/// "cannot be cleared once set" — so it is preserved from
/// the original and everything else becomes the disabled
/// encoding. Used for entries the load path must not arm.
pub fn evt_ctl_disable(data: u32) -> u32 {
    (data & EVT_CTL_ENABLE) | EVT_CTL_DISABLED
}

/// The event id programmed in an EVT_CTL value.
pub fn evt_ctl_event_id(data: u32) -> u32 {
    (data & EVT_CTL_EVENT_ID_MASK) >> 8
}

// ── DC-state registers (intel_display_regs.h) ───────────────

/// DC_STATE_EN.
pub const DC_STATE_EN: u64 = 0x45504;
/// DC_STATE_EN target field mask, bits [1:0].
pub const DC_STATE_EN_UPTO_MASK: u32 = 0x3;
/// DC_STATE_DEBUG.
pub const DC_STATE_DEBUG: u64 = 0x45520;
/// DC_STATE_DEBUG mask-cores bit.
pub const DC_STATE_DEBUG_MASK_CORES: u32 = 1 << 0;
/// DC_STATE_DEBUG mask-memory-up bit.
pub const DC_STATE_DEBUG_MASK_MEMORY_UP: u32 = 1 << 1;
/// TGL DMC debug counter: DC5 entries.
pub const TGL_DMC_DEBUG_DC5_COUNT: u64 = 0x101084;
/// TGL DMC debug counter: DC6 entries.
pub const TGL_DMC_DEBUG_DC6_COUNT: u64 = 0x101088;

// ── Parsed firmware ─────────────────────────────────────────

/// One validated DMC program: its payload (borrowed from
/// the container blob) and its MMIO initialisation table,
/// with the parse-time TGL fixup already applied.
#[derive(Clone, Copy, Debug)]
pub struct DmcProgram<'a> {
    /// DMC header version (1 or 3).
    pub header_ver: u8,
    /// Firmware version from the DMC header.
    pub fw_version: u32,
    /// Project field from the DMC header.
    pub project: u32,
    /// Program-RAM base the payload loads at.
    pub start_mmioaddr: u32,
    /// The payload bytes (`fw_size` dwords × 4).
    pub payload: &'a [u8],
    /// Valid entries in the MMIO table (≤ 20).
    pub mmio_count: usize,
    /// MMIO init addresses.
    pub mmioaddr: [u32; DMC_V3_MAX_MMIO_COUNT],
    /// MMIO init data (post-fixup — see the module header).
    pub mmiodata: [u32; DMC_V3_MAX_MMIO_COUNT],
}

/// A validated DMC firmware container.
#[derive(Clone, Debug)]
pub struct DmcFirmware<'a> {
    /// Firmware version from the CSS header
    /// (major in the high half, minor in the low half).
    pub version: u32,
    /// Per-slot programs; `None` where the container has
    /// no (valid) program for the slot.
    pub programs: [Option<DmcProgram<'a>>; DMC_SLOTS],
    /// Bit per slot (by [`DmcId::index`]) whose program
    /// was present in the container but deliberately not
    /// loaded — on Gen12, pipes C/D (see the module
    /// header).
    pub skipped_mask: u32,
}

impl<'a> DmcFirmware<'a> {
    /// The program for `id`, if the container carried a
    /// valid one.
    pub fn program(&self, id: DmcId) -> Option<&DmcProgram<'a>> {
        self.programs[id.index()].as_ref()
    }

    /// Whether the main DMC program is present. Without it
    /// there is no DC-state handoff and no load at all —
    /// the same gate i915 puts on `intel_dmc_has_payload`.
    pub fn has_main(&self) -> bool {
        self.programs[DmcId::Main.index()].is_some()
    }
}

/// Why a container was refused. Parse is pure: a refusal
/// always means *no register was written*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmcError {
    /// The blob ends before a structure the format
    /// requires (CSS header, full package table, a program
    /// header, or a program's payload).
    Truncated,
    /// CSS `module_type` is not the DMC value 0x09.
    BadCssModuleType(u32),
    /// CSS `header_ver` is not 0x10000.
    BadCssHeaderVer(u32),
    /// CSS `header_len` (dwords, as read) does not cover
    /// exactly the 128-byte CSS header.
    BadCssHeaderLen(u32),
    /// Package `header_ver` is neither 1 nor 2.
    BadPackageVersion(u8),
    /// Package `header_len` does not cover header + the
    /// full entry table, in bytes.
    BadPackageHeaderLen(u32),
    /// A program header's signature is not 0x40403E3E.
    BadSignature(u32),
    /// A program header's version is neither 1 nor 3.
    BadHeaderVersion(u8),
    /// A program header's length field does not equal the
    /// version's header size, in bytes. (For v1 the field
    /// is in bytes already; for v3 it is dwords × 4.)
    BadDmcHeaderLen { header_ver: u8, len_bytes: u32 },
    /// MMIO init count is zero or exceeds the header
    /// version's maximum (8 for v1, 20 for v3).
    BadMmioCount(u32),
    /// An MMIO init address lies outside this id's sanity
    /// range — the firmware would have the driver write
    /// arbitrary registers; refused.
    MmioOutOfRange { addr: u32 },
    /// A v3 program's load window escapes its program-RAM
    /// range.
    LoadAddrOutOfRange { start: u32 },
    /// `fw_size` is zero: a header with no program.
    EmptyPayload,
    /// Payload size (bytes) exceeds the platform maximum.
    PayloadTooLarge(usize),
    /// The main program's package offset points beyond
    /// the blob.
    ProgramOffsetOutOfBounds,
    /// No valid main program: the container's entries did
    /// not select one for this stepping, or its header was
    /// unusable. (Pipe programs may still have parsed.)
    NoMainProgram,
}

fn rd32(blob: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]])
}

/// i915's stepping match (`fw_info_matches_stepping`):
/// entry fields against the silicon's, `'*'` (0x2A) the
/// wildcard on either side. Transcribed clause-for-clause
/// from the C — the shape is the audit trail, so the
/// boolean-simplification lint is waived here.
#[allow(clippy::nonminimal_bool)]
fn fw_info_matches_stepping(entry_step: u8, entry_sub: u8, step: u8, sub: u8) -> bool {
    (entry_sub == b'*' && step == entry_step)
        || (step == entry_step && sub == entry_sub)
        || (step == b'*' && sub == entry_sub)
        || (entry_step == b'*' && entry_sub == b'*')
}

/// Which EVT_CTL handler slot of `id` an address is, if
/// it is one.
fn evt_ctl_handler(id: DmcId, addr: u32) -> Option<usize> {
    let first = id.evt_ctl(0)?;
    if addr >= first && addr < first + 4 * EVT_HANDLER_COUNT_GEN12 as u32 && addr % 4 == 0 {
        Some(((addr - first) / 4) as usize)
    } else {
        None
    }
}

/// Which EVT_HTP handler slot of `id` an address is, if
/// it is one.
fn evt_htp_handler(id: DmcId, addr: u32) -> Option<usize> {
    let first = id.evt_htp(0)?;
    if addr >= first && addr < first + 4 * EVT_HANDLER_COUNT_GEN12 as u32 && addr % 4 == 0 {
        Some(((addr - first) / 4) as usize)
    } else {
        None
    }
}

/// The TGL parse-time fixup (`fixup_dmc_evt` in
/// intel_dmc.c): a main-DMC handler pair (EVT_CTL[i],
/// EVT_HTP[i] for the *same* handler) whose event is
/// VBLANK_A is rewritten to VBLANK_DELAYED_A — the shipped
/// firmware's HRR handler uses the wrong event and fixed
/// firmware was never released. Adjacent pairs only,
/// exactly as i915 scans them.
fn apply_tgl_vblank_fixup(
    mmioaddr: &mut [u32; DMC_V3_MAX_MMIO_COUNT],
    mmiodata: &mut [u32; DMC_V3_MAX_MMIO_COUNT],
    count: usize,
) {
    for i in 0..count.saturating_sub(1) {
        let Some(h) = evt_ctl_handler(DmcId::Main, mmioaddr[i]) else {
            continue;
        };
        if evt_htp_handler(DmcId::Main, mmioaddr[i + 1]) != Some(h) {
            continue;
        }
        if evt_ctl_event_id(mmiodata[i]) == MAINDMC_EVENT_VBLANK_A {
            mmiodata[i] =
                (mmiodata[i] & !EVT_CTL_EVENT_ID_MASK) | (MAINDMC_EVENT_VBLANK_DELAYED_A << 8);
        }
    }
}

/// Parse one program header + payload at `off` in `blob`
/// for slot `id`. Mirrors i915's `parse_dmc_fw_header`
/// check order: version dispatch → header length → MMIO
/// count → MMIO sanity → payload size → load-address
/// sanity (plus the signature check i915 omits — see the
/// module header).
fn parse_program<'a>(
    blob: &'a [u8],
    off: usize,
    id: DmcId,
    max_fw_size: usize,
) -> Result<DmcProgram<'a>, DmcError> {
    let rem = &blob[off..];
    if rem.len() < DMC_HEADER_BASE_BYTES {
        return Err(DmcError::Truncated);
    }
    let signature = rd32(rem, 0);
    if signature != DMC_SIGNATURE {
        return Err(DmcError::BadSignature(signature));
    }
    let header_len_field = rem[4] as u32;
    let header_ver = rem[5];
    let (header_bytes, start_mmioaddr, mmio_count, mmioaddr_off, mmiodata_off, mmio_max) =
        match header_ver {
            3 => {
                if rem.len() < DMC_HEADER_V3_BYTES {
                    return Err(DmcError::Truncated);
                }
                if header_len_field * 4 != DMC_HEADER_V3_BYTES as u32 {
                    return Err(DmcError::BadDmcHeaderLen {
                        header_ver,
                        len_bytes: header_len_field * 4,
                    });
                }
                (
                    DMC_HEADER_V3_BYTES,
                    rd32(rem, 20),
                    rd32(rem, 92),
                    96usize,
                    176usize,
                    DMC_V3_MAX_MMIO_COUNT,
                )
            }
            1 => {
                if rem.len() < DMC_HEADER_V1_BYTES {
                    return Err(DmcError::Truncated);
                }
                // The v1 quirk: header_len is in *bytes*.
                if header_len_field != DMC_HEADER_V1_BYTES as u32 {
                    return Err(DmcError::BadDmcHeaderLen {
                        header_ver,
                        len_bytes: header_len_field,
                    });
                }
                (
                    DMC_HEADER_V1_BYTES,
                    DMC_V1_LOAD_ADDR,
                    rd32(rem, 20),
                    24usize,
                    56usize,
                    DMC_V1_MAX_MMIO_COUNT,
                )
            }
            v => return Err(DmcError::BadHeaderVersion(v)),
        };
    if mmio_count == 0 || mmio_count as usize > mmio_max {
        return Err(DmcError::BadMmioCount(mmio_count));
    }
    let mmio_count = mmio_count as usize;
    let mut mmioaddr = [0u32; DMC_V3_MAX_MMIO_COUNT];
    let mut mmiodata = [0u32; DMC_V3_MAX_MMIO_COUNT];
    for i in 0..mmio_count {
        mmioaddr[i] = rd32(rem, mmioaddr_off + 4 * i);
        mmiodata[i] = rd32(rem, mmiodata_off + 4 * i);
    }
    let mmio_range = if header_ver == 1 {
        DMC_MMIO_RANGE_V1
    } else {
        // Gen12 ranges are grounded for main + pipes A/B;
        // C/D programs never reach here (skipped by the
        // caller), and their absence is a parse error if
        // one somehow does.
        id.mmio_range_v3()
            .ok_or(DmcError::MmioOutOfRange { addr: mmioaddr[0] })?
    };
    for &addr in mmioaddr.iter().take(mmio_count) {
        if addr < mmio_range.0 || addr > mmio_range.1 {
            return Err(DmcError::MmioOutOfRange { addr });
        }
    }
    let fw_size_dwords = rd32(rem, 12);
    if fw_size_dwords == 0 {
        return Err(DmcError::EmptyPayload);
    }
    let payload_bytes = (fw_size_dwords as usize)
        .checked_mul(4)
        .ok_or(DmcError::PayloadTooLarge(usize::MAX))?;
    if payload_bytes > max_fw_size {
        return Err(DmcError::PayloadTooLarge(payload_bytes));
    }
    if rem.len() < header_bytes + payload_bytes {
        return Err(DmcError::Truncated);
    }
    if header_ver == 3 {
        let (lo, hi) = id.program_range();
        let end = start_mmioaddr as u64 + payload_bytes as u64 - 1;
        if start_mmioaddr < lo || end > hi as u64 {
            return Err(DmcError::LoadAddrOutOfRange {
                start: start_mmioaddr,
            });
        }
    }
    if id == DmcId::Main {
        apply_tgl_vblank_fixup(&mut mmioaddr, &mut mmiodata, mmio_count);
    }
    Ok(DmcProgram {
        header_ver,
        fw_version: rd32(rem, 16),
        project: rd32(rem, 8),
        start_mmioaddr,
        payload: &rem[header_bytes..header_bytes + payload_bytes],
        mmio_count,
        mmioaddr,
        mmiodata,
    })
}

/// Parse and validate a DMC firmware container for
/// silicon at stepping `stepping`/`substepping` (ASCII,
/// e.g. `b'B'`, `b'1'`; the values the platform probe
/// reports). `max_fw_size` is the platform payload ceiling
/// in bytes ([`DMC_MAX_FW_SIZE_GEN12`] on Gen12).
///
/// Pure: no MMIO, no allocation; the returned firmware
/// borrows the payload bytes from `blob`.
pub fn parse_dmc_firmware<'a>(
    blob: &'a [u8],
    stepping: u8,
    substepping: u8,
    max_fw_size: usize,
) -> Result<DmcFirmware<'a>, DmcError> {
    // CSS header.
    if blob.len() < CSS_HEADER_BYTES {
        return Err(DmcError::Truncated);
    }
    let module_type = rd32(blob, 0);
    if module_type != CSS_MODULE_TYPE_DMC {
        return Err(DmcError::BadCssModuleType(module_type));
    }
    let css_header_ver = rd32(blob, 8);
    if css_header_ver != CSS_HEADER_VER {
        return Err(DmcError::BadCssHeaderVer(css_header_ver));
    }
    let css_header_len = rd32(blob, 4);
    if css_header_len * 4 != CSS_HEADER_BYTES as u32 {
        return Err(DmcError::BadCssHeaderLen(css_header_len));
    }
    let version = rd32(blob, CSS_VERSION_OFFSET);

    // Package header. The table always occupies the max
    // entry count for the package version.
    let pkg_off = CSS_HEADER_BYTES;
    if blob.len() < pkg_off + PACKAGE_HEADER_BYTES {
        return Err(DmcError::Truncated);
    }
    let package_ver = blob[pkg_off + 1];
    let max_entries = match package_ver {
        1 => PACKAGE_V1_MAX_ENTRIES,
        2 => PACKAGE_V2_MAX_ENTRIES,
        v => return Err(DmcError::BadPackageVersion(v)),
    };
    let package_size = PACKAGE_HEADER_BYTES + max_entries * FW_INFO_BYTES;
    if blob.len() < pkg_off + package_size {
        return Err(DmcError::Truncated);
    }
    let package_len_bytes = blob[pkg_off] as u32 * 4;
    if package_len_bytes != package_size as u32 {
        return Err(DmcError::BadPackageHeaderLen(package_len_bytes));
    }
    // i915 warns and clamps an over-large num_entries.
    let num_entries = (rd32(blob, pkg_off + 12) as usize).min(max_entries);

    // Select one entry per id: first stepping match wins.
    let mut chosen: [Option<u32>; DMC_SLOTS] = [None; DMC_SLOTS];
    for i in 0..num_entries {
        let e = pkg_off + PACKAGE_HEADER_BYTES + i * FW_INFO_BYTES;
        let entry_id = if package_ver <= 1 {
            0 // v1 entries are all the main DMC.
        } else {
            blob[e + 1]
        };
        let Some(id) = DmcId::from_u8(entry_id) else {
            continue; // i915: unsupported id, skipped.
        };
        if chosen[id.index()].is_some() {
            continue;
        }
        if fw_info_matches_stepping(blob[e + 2], blob[e + 3], stepping, substepping) {
            chosen[id.index()] = Some(rd32(blob, e + 4));
        }
    }

    // Parse each selected program. Pipe-program failures
    // are tolerated (slot stays empty), as in i915; a
    // main-program failure is returned verbatim.
    let mut programs: [Option<DmcProgram<'a>>; DMC_SLOTS] = [None, None, None, None, None];
    let mut skipped_mask = 0u32;
    for id in DmcId::ALL {
        let Some(offset_dwords) = chosen[id.index()] else {
            continue;
        };
        if matches!(id, DmcId::PipeC | DmcId::PipeD) {
            skipped_mask |= 1 << id.index();
            continue;
        }
        let prog_off = pkg_off + package_size + offset_dwords as usize * 4;
        if prog_off > blob.len() {
            if id == DmcId::Main {
                return Err(DmcError::ProgramOffsetOutOfBounds);
            }
            continue;
        }
        match parse_program(blob, prog_off, id, max_fw_size) {
            Ok(p) => programs[id.index()] = Some(p),
            Err(e) => {
                if id == DmcId::Main {
                    return Err(e);
                }
            }
        }
    }
    if programs[DmcId::Main.index()].is_none() {
        return Err(DmcError::NoMainProgram);
    }
    Ok(DmcFirmware {
        version,
        programs,
        skipped_mask,
    })
}

// ── Load conversation ───────────────────────────────────────

/// Quiesce every event handler of `id`: each EVT_CTL gets
/// the disabled encoding and each EVT_HTP is zeroed —
/// `disable_all_event_handlers` in intel_dmc.c. Runs
/// before a program load (stale handlers must not fire
/// against half-written program RAM) and as the whole of
/// program disable.
pub fn disable_event_handlers<M: MmioWindow>(regs: &M, id: DmcId) {
    for h in 0..EVT_HANDLER_COUNT_GEN12 {
        if let (Some(ctl), Some(htp)) = (id.evt_ctl(h), id.evt_htp(h)) {
            regs.write32(ctl as u64, EVT_CTL_DISABLED);
            regs.write32(htp as u64, 0);
        }
    }
}

/// The data the load path actually writes for one MMIO
/// table entry (`dmc_mmiodata`): pipe-DMC event entries
/// are always written disabled ("keep all pipe DMC events
/// disabled by default"), and on the main DMC the TGL
/// CLK_MSEC and VBLANK_DELAYED_A handlers are written
/// disabled as well. Everything else goes out verbatim.
pub fn load_mmiodata(id: DmcId, addr: u32, data: u32) -> u32 {
    if evt_ctl_handler(id, addr).is_some() {
        if id != DmcId::Main {
            return evt_ctl_disable(data);
        }
        let event = evt_ctl_event_id(data);
        if event == MAINDMC_EVENT_CLK_MSEC || event == MAINDMC_EVENT_VBLANK_DELAYED_A {
            return evt_ctl_disable(data);
        }
    }
    data
}

/// Load every program in `fw` into its DMC, in id order,
/// then set the DC_STATE_DEBUG masks and take the posting
/// read — `intel_dmc_load_program`'s conversation. With no
/// main payload this is a no-op (there is nothing to hand
/// the DC states to), mirroring i915's early return.
pub fn load_program<M: MmioWindow>(regs: &M, fw: &DmcFirmware<'_>) {
    if !fw.has_main() {
        return;
    }
    for id in DmcId::ALL {
        let Some(prog) = fw.program(id) else {
            continue;
        };
        disable_event_handlers(regs, id);
        for (i, dword) in prog.payload.chunks_exact(4).enumerate() {
            regs.write32(
                prog.start_mmioaddr as u64 + 4 * i as u64,
                u32::from_le_bytes([dword[0], dword[1], dword[2], dword[3]]),
            );
        }
        for i in 0..prog.mmio_count {
            regs.write32(
                prog.mmioaddr[i] as u64,
                load_mmiodata(id, prog.mmioaddr[i], prog.mmiodata[i]),
            );
        }
    }
    let debug = regs.read32(DC_STATE_DEBUG);
    regs.write32(
        DC_STATE_DEBUG,
        debug | DC_STATE_DEBUG_MASK_CORES | DC_STATE_DEBUG_MASK_MEMORY_UP,
    );
    // Posting read: flush the mask write before returning.
    let _ = regs.read32(DC_STATE_DEBUG);
}

/// Disable the firmware: quiesce the event handlers of
/// every loaded program, making the DMC inactive —
/// `intel_dmc_disable_program`'s conversation. Program
/// RAM is left as-is; a later [`load_program`] reloads it.
pub fn disable_program<M: MmioWindow>(regs: &M, fw: &DmcFirmware<'_>) {
    if !fw.has_main() {
        return;
    }
    for id in DmcId::ALL {
        if fw.program(id).is_some() {
            disable_event_handlers(regs, id);
        }
    }
}

/// Why a post-load verification read disagreed with the
/// firmware — the error-returning form of i915's
/// `assert_dmc_loaded` warnings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmcVerifyError {
    /// Program RAM's first dword is not the payload's.
    ProgramStart {
        id: DmcId,
        expected: u32,
        found: u32,
    },
    /// MMIO table entry `index` does not hold the value
    /// the load path wrote (post-transform).
    Mmio {
        id: DmcId,
        index: usize,
        expected: u32,
        found: u32,
    },
}

/// Verify a loaded program set reads back as written:
/// program RAM start dword and every MMIO table entry,
/// per program. Cheap insurance against a dropped BAR
/// write or a DMC that reset itself mid-load.
pub fn verify_loaded<M: MmioWindow>(regs: &M, fw: &DmcFirmware<'_>) -> Result<(), DmcVerifyError> {
    for id in DmcId::ALL {
        let Some(prog) = fw.program(id) else {
            continue;
        };
        let expected0 = u32::from_le_bytes([
            prog.payload[0],
            prog.payload[1],
            prog.payload[2],
            prog.payload[3],
        ]);
        let found0 = regs.read32(prog.start_mmioaddr as u64);
        if found0 != expected0 {
            return Err(DmcVerifyError::ProgramStart {
                id,
                expected: expected0,
                found: found0,
            });
        }
        for i in 0..prog.mmio_count {
            let expected = load_mmiodata(id, prog.mmioaddr[i], prog.mmiodata[i]);
            let found = regs.read32(prog.mmioaddr[i] as u64);
            if found != expected {
                return Err(DmcVerifyError::Mmio {
                    id,
                    index: i,
                    expected,
                    found,
                });
            }
        }
    }
    Ok(())
}

// ── DC-state handoff ────────────────────────────────────────

/// A display power-state target for `DC_STATE_EN`'s
/// up-to field. Deeper states need the DMC (see
/// [`set_dc_target`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcTarget {
    /// DC states off (field 0).
    Off,
    /// Allow up to DC5 (field 1).
    Dc5,
    /// Allow up to DC6 (field 2).
    Dc6,
}

impl DcTarget {
    /// The DC_STATE_EN field value for this target.
    pub fn field_value(self) -> u32 {
        match self {
            DcTarget::Off => 0,
            DcTarget::Dc5 => 1,
            DcTarget::Dc6 => 2,
        }
    }
}

/// Why a DC target was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcError {
    /// DC5/DC6 were requested with no main DMC program
    /// loaded — the DMC is what performs those states, so
    /// the request can never be honoured.
    NoMainProgram,
}

/// Program the DC-state target: a read-modify-write of
/// `DC_STATE_EN`'s up-to field, preserving every other
/// bit. DC5/DC6 are refused unless `fw` carries a main
/// program — i915's allowed-DC mask is empty without DMC
/// payload, for the same reason.
pub fn set_dc_target<M: MmioWindow>(
    regs: &M,
    fw: &DmcFirmware<'_>,
    target: DcTarget,
) -> Result<(), DcError> {
    if target != DcTarget::Off && !fw.has_main() {
        return Err(DcError::NoMainProgram);
    }
    let cur = regs.read32(DC_STATE_EN);
    regs.write32(
        DC_STATE_EN,
        (cur & !DC_STATE_EN_UPTO_MASK) | target.field_value(),
    );
    Ok(())
}

/// DC5 entries so far (TGL debug counter — a residency
/// witness for the DC states, like RC6's counter is for
/// the GT).
pub fn dc5_entry_count<M: MmioWindow>(regs: &M) -> u32 {
    regs.read32(TGL_DMC_DEBUG_DC5_COUNT)
}

/// DC6 entries so far (TGL debug counter).
pub fn dc6_entry_count<M: MmioWindow>(regs: &M) -> u32 {
    regs.read32(TGL_DMC_DEBUG_DC6_COUNT)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the DMC format + load conversation.
    //! The blob builder constructs containers *from the
    //! format description in the module header* (CSS /
    //! package / program headers laid out field by field),
    //! and the fake window is a plain register file — the
    //! hardware side of the load conversation is just
    //! "writes land, reads return what landed". Expected
    //! write sequences are hand-derived from intel_dmc.c.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Fake hardware ───────────────────────────────────

    #[derive(Clone)]
    struct FakeDmc {
        regs: Rc<RefCell<BTreeMap<u64, u32>>>,
        writes: Rc<RefCell<Vec<(u64, u32)>>>,
        reads: Rc<RefCell<Vec<u64>>>,
    }

    impl FakeDmc {
        fn new() -> Self {
            Self {
                regs: Rc::new(RefCell::new(BTreeMap::new())),
                writes: Rc::new(RefCell::new(Vec::new())),
                reads: Rc::new(RefCell::new(Vec::new())),
            }
        }
        fn writes(&self) -> Vec<(u64, u32)> {
            self.writes.borrow().clone()
        }
        fn reads(&self) -> Vec<u64> {
            self.reads.borrow().clone()
        }
        fn set_reg(&self, off: u64, val: u32) {
            self.regs.borrow_mut().insert(off, val);
        }
    }

    impl MmioWindow for FakeDmc {
        fn read32(&self, off: u64) -> u32 {
            self.reads.borrow_mut().push(off);
            *self.regs.borrow().get(&off).unwrap_or(&0)
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
        }
    }

    // ── Blob builder (from the format description) ──────

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    struct ProgSpec {
        entry_dmc_id: u8,
        stepping: u8,
        substepping: u8,
        header_ver: u8,
        start: u32,
        payload: Vec<u32>,
        mmio: Vec<(u32, u32)>,
    }

    /// Build a container: CSS header, package header of
    /// `package_ver`, then each program in order, offsets
    /// assigned sequentially. Header fields are written
    /// per the format — including v1's byte-counted
    /// header_len.
    fn build_blob(package_ver: u8, progs: &[ProgSpec]) -> Vec<u8> {
        let max_entries = if package_ver == 1 {
            PACKAGE_V1_MAX_ENTRIES
        } else {
            PACKAGE_V2_MAX_ENTRIES
        };
        let package_size = PACKAGE_HEADER_BYTES + max_entries * FW_INFO_BYTES;
        let mut blob = alloc::vec![0u8; CSS_HEADER_BYTES + package_size];
        // CSS header.
        put32(&mut blob, 0, CSS_MODULE_TYPE_DMC);
        put32(&mut blob, 4, (CSS_HEADER_BYTES / 4) as u32);
        put32(&mut blob, 8, CSS_HEADER_VER);
        put32(&mut blob, CSS_VERSION_OFFSET, 0x0002_000C);
        // Package header.
        let pkg = CSS_HEADER_BYTES;
        blob[pkg] = (package_size / 4) as u8;
        blob[pkg + 1] = package_ver;
        put32(&mut blob, pkg + 12, progs.len() as u32);
        // Programs.
        let mut offset_dwords = 0usize;
        for (i, p) in progs.iter().enumerate() {
            let e = pkg + PACKAGE_HEADER_BYTES + i * FW_INFO_BYTES;
            blob[e + 1] = p.entry_dmc_id;
            blob[e + 2] = p.stepping;
            blob[e + 3] = p.substepping;
            put32(&mut blob, e + 4, offset_dwords as u32);
            let header_bytes = if p.header_ver == 1 {
                DMC_HEADER_V1_BYTES
            } else {
                DMC_HEADER_V3_BYTES
            };
            let prog_bytes = header_bytes + p.payload.len() * 4;
            let prog_off = blob.len();
            blob.resize(prog_off + prog_bytes, 0);
            put32(&mut blob, prog_off, DMC_SIGNATURE);
            if p.header_ver == 1 {
                blob[prog_off + 4] = DMC_HEADER_V1_BYTES as u8;
            } else {
                blob[prog_off + 4] = (DMC_HEADER_V3_BYTES / 4) as u8;
            }
            blob[prog_off + 5] = p.header_ver;
            put32(&mut blob, prog_off + 8, 0x12);
            put32(&mut blob, prog_off + 12, p.payload.len() as u32);
            put32(&mut blob, prog_off + 16, 0x0002_000C);
            let (count_off, addr_off, data_off) = if p.header_ver == 1 {
                (20usize, 24usize, 56usize)
            } else {
                put32(&mut blob, prog_off + 20, p.start);
                (92usize, 96usize, 176usize)
            };
            put32(&mut blob, prog_off + count_off, p.mmio.len() as u32);
            for (j, (a, d)) in p.mmio.iter().enumerate() {
                put32(&mut blob, prog_off + addr_off + 4 * j, *a);
                put32(&mut blob, prog_off + data_off + 4 * j, *d);
            }
            for (j, v) in p.payload.iter().enumerate() {
                put32(&mut blob, prog_off + header_bytes + 4 * j, *v);
            }
            offset_dwords += prog_bytes / 4;
        }
        blob
    }

    /// The reference TGL container: main (v3) + pipe A (v3).
    /// Main's table carries a VBLANK_A handler pair (the
    /// fixup target), a CLK_MSEC handler pair (the
    /// load-time disable target) and one plain register.
    fn tgl_blob() -> Vec<u8> {
        build_blob(
            2,
            &[
                ProgSpec {
                    entry_dmc_id: 0,
                    stepping: b'*',
                    substepping: b'*',
                    header_ver: 3,
                    start: 0x80000,
                    payload: alloc::vec![0xAAAA_0001, 0xAAAA_0002, 0xAAAA_0003, 0xAAAA_0004],
                    mmio: alloc::vec![
                        (0x8F034, 0x8003_3200), // EVT_CTL(main,0): ENABLE|EDGE_0_1|VBLANK_A
                        (0x8F004, 0x0000_0010), // EVT_HTP(main,0)
                        (0x8F038, 0x8003_BF00), // EVT_CTL(main,1): ENABLE|EDGE_0_1|CLK_MSEC
                        (0x8F008, 0x0000_0020), // EVT_HTP(main,1)
                        (0x8F074, 0x0000_2FC0), // DMC_SSP_BASE
                    ],
                },
                ProgSpec {
                    entry_dmc_id: 1,
                    stepping: b'*',
                    substepping: b'*',
                    header_ver: 3,
                    start: 0x90000,
                    payload: alloc::vec![0xBBBB_0001, 0xBBBB_0002],
                    mmio: alloc::vec![
                        (0x92034, 0x8003_1000), // EVT_CTL(pipeA,0)
                        (0x92004, 0x0000_0030), // EVT_HTP(pipeA,0)
                        (0x92100, 0xDEAD_BEEF), // plain, in pipe A range
                    ],
                },
            ],
        )
    }

    /// The handler-quiesce sweep for one DMC, hand-derived
    /// from the register geometry: handlers 0..8, CTL then
    /// HTP per handler.
    fn handler_sweep(ctl_base: u32, htp_base: u32) -> Vec<(u64, u32)> {
        let mut out = Vec::new();
        for h in 0..8u32 {
            out.push(((ctl_base + 4 * h) as u64, EVT_CTL_DISABLED));
            out.push(((htp_base + 4 * h) as u64, 0));
        }
        out
    }

    // ── Fixtures ────────────────────────────────────────

    fn smoke_register_map_pinned() -> TestResult {
        // Hand-pinned from intel_dmc_regs.h /
        // intel_display_regs.h — see the module header.
        if DC_STATE_EN != 0x45504 || DC_STATE_DEBUG != 0x45520 {
            return TestResult::Fail("DC_STATE register offsets diverge");
        }
        if TGL_DMC_DEBUG_DC5_COUNT != 0x101084 || TGL_DMC_DEBUG_DC6_COUNT != 0x101088 {
            return TestResult::Fail("TGL DC debug counter offsets diverge");
        }
        if DmcId::Main.evt_ctl(0) != Some(0x8F034)
            || DmcId::Main.evt_htp(0) != Some(0x8F004)
            || DmcId::PipeA.evt_ctl(0) != Some(0x92034)
            || DmcId::PipeB.evt_ctl(0) != Some(0x92434)
            || DmcId::PipeB.evt_htp(7) != Some(0x92420)
        {
            return TestResult::Fail("event-handler register geometry diverges");
        }
        if EVT_CTL_DISABLED != 0x0003_0100 {
            return TestResult::Fail("disabled EVT_CTL encoding must be 0x0003_0100");
        }
        if evt_ctl_disable(0x8003_3200) != 0x8003_0100
            || evt_ctl_disable(0x0003_3200) != 0x0003_0100
        {
            return TestResult::Fail("evt_ctl_disable must keep only the sticky enable bit");
        }
        if DMC_SIGNATURE != 0x4040_3E3E || DMC_MAX_FW_SIZE_GEN12 != 0x6000 {
            return TestResult::Fail("format constants diverge");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_register_map_pinned);

    fn smoke_parse_valid_tgl_blob() -> TestResult {
        let blob = tgl_blob();
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the reference TGL blob must parse"),
        };
        if fw.version != 0x0002_000C {
            return TestResult::Fail("CSS version must surface on the parsed firmware");
        }
        if fw.skipped_mask != 0 {
            return TestResult::Fail("nothing in the reference blob is skipped");
        }
        let main = match fw.program(DmcId::Main) {
            Some(p) => p,
            None => return TestResult::Fail("main program must be present"),
        };
        if main.start_mmioaddr != 0x80000 || main.payload.len() != 16 || main.mmio_count != 5 {
            return TestResult::Fail("main program fields diverge from the built container");
        }
        // The parse-time TGL fixup: VBLANK_A (0x32) in the
        // handler pair becomes VBLANK_DELAYED_A (0x2E) in
        // the stored table; the CLK_MSEC entry is *not*
        // touched at parse time (its disable is a load-time
        // transform).
        if main.mmiodata[0] != 0x8003_2E00 {
            return TestResult::Fail("VBLANK_A fixup missing from the stored MMIO table");
        }
        if main.mmiodata[2] != 0x8003_BF00 {
            return TestResult::Fail("parse must not rewrite the CLK_MSEC entry");
        }
        let pipe_a = match fw.program(DmcId::PipeA) {
            Some(p) => p,
            None => return TestResult::Fail("pipe A program must be present"),
        };
        if pipe_a.start_mmioaddr != 0x90000 || pipe_a.payload.len() != 8 {
            return TestResult::Fail("pipe A program fields diverge from the built container");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_parse_valid_tgl_blob);

    fn smoke_load_conversation() -> TestResult {
        let blob = tgl_blob();
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the reference TGL blob must parse"),
        };
        let fake = FakeDmc::new();
        load_program(&fake, &fw);
        // Hand-derived from dmc_load_program, per program:
        // handler sweep → payload stream → MMIO table (with
        // load-time transforms); then the DC_STATE_DEBUG
        // mask write.
        let mut expected = handler_sweep(0x8F034, 0x8F004);
        for (i, v) in [0xAAAA_0001u32, 0xAAAA_0002, 0xAAAA_0003, 0xAAAA_0004]
            .iter()
            .enumerate()
        {
            expected.push((0x80000 + 4 * i as u64, *v));
        }
        expected.push((0x8F034, 0x8003_0100)); // VBLANK_DELAYED_A handler, disabled form
        expected.push((0x8F004, 0x0000_0010));
        expected.push((0x8F038, 0x8003_0100)); // CLK_MSEC handler, disabled form
        expected.push((0x8F008, 0x0000_0020));
        expected.push((0x8F074, 0x0000_2FC0));
        expected.extend(handler_sweep(0x92034, 0x92004));
        expected.push((0x90000, 0xBBBB_0001));
        expected.push((0x90004, 0xBBBB_0002));
        expected.push((0x92034, 0x8003_0100)); // pipe event entry, disabled form
        expected.push((0x92004, 0x0000_0030));
        expected.push((0x92100, 0xDEAD_BEEF));
        expected.push((DC_STATE_DEBUG, 0x3));
        if fake.writes() != expected {
            return TestResult::Fail("load conversation diverges from intel_dmc_load_program");
        }
        // The DC_STATE_DEBUG mask write is followed by its
        // posting read.
        let reads = fake.reads();
        if reads.last() != Some(&DC_STATE_DEBUG) {
            return TestResult::Fail("load must end with the DC_STATE_DEBUG posting read");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_load_conversation);

    fn smoke_parse_refusals() -> TestResult {
        let good = tgl_blob();
        // Byte offsets into the built container: package at
        // 128; first entry at 144 (offset field at 148);
        // main program at 128 + 400 = 528.
        let cases: &[(Vec<u8>, DmcError)] = &[
            (good[..64].to_vec(), DmcError::Truncated),
            (good[..128 + 200].to_vec(), DmcError::Truncated),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 0, 7);
                    b
                },
                DmcError::BadCssModuleType(7),
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 8, 0x2_0000);
                    b
                },
                DmcError::BadCssHeaderVer(0x2_0000),
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 4, 31);
                    b
                },
                DmcError::BadCssHeaderLen(31),
            ),
            (
                {
                    let mut b = good.clone();
                    b[129] = 3;
                    b
                },
                DmcError::BadPackageVersion(3),
            ),
            (
                {
                    let mut b = good.clone();
                    b[128] = 99;
                    b
                },
                DmcError::BadPackageHeaderLen(396),
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 148, 0x00FF_FFFF);
                    b
                },
                DmcError::ProgramOffsetOutOfBounds,
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528, 0xDEAD_BEEF);
                    b
                },
                DmcError::BadSignature(0xDEAD_BEEF),
            ),
            (
                {
                    let mut b = good.clone();
                    b[528 + 5] = 2;
                    b
                },
                DmcError::BadHeaderVersion(2),
            ),
            (
                {
                    let mut b = good.clone();
                    b[528 + 4] = 63;
                    b
                },
                DmcError::BadDmcHeaderLen {
                    header_ver: 3,
                    len_bytes: 252,
                },
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528 + 92, 0);
                    b
                },
                DmcError::BadMmioCount(0),
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528 + 92, 21);
                    b
                },
                DmcError::BadMmioCount(21),
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528 + 96, 0x7_0000);
                    b
                },
                DmcError::MmioOutOfRange { addr: 0x7_0000 },
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528 + 12, 0);
                    b
                },
                DmcError::EmptyPayload,
            ),
            (
                {
                    let mut b = good.clone();
                    put32(&mut b, 528 + 20, 0x8_7000);
                    b
                },
                DmcError::LoadAddrOutOfRange { start: 0x8_7000 },
            ),
            (good[..528 + 256 + 8].to_vec(), DmcError::Truncated),
        ];
        for (i, (blob, want)) in cases.iter().enumerate() {
            match parse_dmc_firmware(blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
                Err(e) if e == *want => {}
                Err(_) => {
                    let _ = i;
                    return TestResult::Fail("refusal case returned the wrong error");
                }
                Ok(_) => {
                    let _ = i;
                    return TestResult::Fail("a malformed blob parsed successfully");
                }
            }
        }
        // Payload ceiling is the caller's: the reference
        // main payload is 16 bytes.
        match parse_dmc_firmware(&good, b'B', b'1', 8) {
            Err(DmcError::PayloadTooLarge(16)) => {}
            _ => return TestResult::Fail("payload over the platform ceiling must refuse"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_parse_refusals);

    fn smoke_parse_v1_blob() -> TestResult {
        // Package v1 + header v1: v1 entries are main
        // regardless of the id byte (0xAB here, deliberately
        // meaningless), and the v1 header_len is in bytes.
        let blob = build_blob(
            1,
            &[ProgSpec {
                entry_dmc_id: 0xAB,
                stepping: b'*',
                substepping: b'*',
                header_ver: 1,
                start: 0,
                payload: alloc::vec![0xCCCC_0001, 0xCCCC_0002],
                mmio: alloc::vec![(0x80030, 0x1111), (0x80034, 0x2222)],
            }],
        );
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the v1 blob must parse"),
        };
        let main = fw.program(DmcId::Main).unwrap();
        if main.header_ver != 1 || main.start_mmioaddr != DMC_V1_LOAD_ADDR {
            return TestResult::Fail("v1 programs must load at 0x80000");
        }
        // A v1 header_len written in *dwords* (32) is the
        // classic misreading of the format — refused.
        let mut bad = blob.clone();
        bad[128 + (PACKAGE_HEADER_BYTES + PACKAGE_V1_MAX_ENTRIES * FW_INFO_BYTES) + 4] = 32;
        match parse_dmc_firmware(&bad, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Err(DmcError::BadDmcHeaderLen {
                header_ver: 1,
                len_bytes: 32,
            }) => {}
            _ => return TestResult::Fail("v1 header_len in dwords must refuse"),
        }
        // Load: the payload still lands at 0x80000, after
        // the handler sweep.
        let fake = FakeDmc::new();
        load_program(&fake, &fw);
        let writes = fake.writes();
        let mut expected = handler_sweep(0x8F034, 0x8F004);
        expected.push((0x80000, 0xCCCC_0001));
        expected.push((0x80004, 0xCCCC_0002));
        expected.push((0x80030, 0x1111));
        expected.push((0x80034, 0x2222));
        expected.push((DC_STATE_DEBUG, 0x3));
        if writes != expected {
            return TestResult::Fail("v1 load conversation diverges");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_parse_v1_blob);

    fn smoke_stepping_selection() -> TestResult {
        let mk = |stepping: u8, sub: u8, payload: u32| ProgSpec {
            entry_dmc_id: 0,
            stepping,
            substepping: sub,
            header_ver: 3,
            start: 0x80000,
            payload: alloc::vec![payload],
            mmio: alloc::vec![(0x8F074, 0x2FC0)],
        };
        // Specific entry first, generic second: the
        // specific one wins for matching silicon.
        let blob = build_blob(2, &[mk(b'B', b'1', 0xC1), mk(b'*', b'*', 0xC2)]);
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("stepping blob must parse"),
        };
        if fw.program(DmcId::Main).unwrap().payload != [0xC1u8, 0, 0, 0].as_slice() {
            return TestResult::Fail("the first matching entry must win");
        }
        // Generic first, specific second: the generic wins
        // — selection is file order, not specificity
        // ranking. This distinguishes the two plausible
        // implementations.
        let blob = build_blob(2, &[mk(b'*', b'*', 0xC2), mk(b'B', b'1', 0xC1)]);
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("stepping blob must parse"),
        };
        if fw.program(DmcId::Main).unwrap().payload != [0xC2u8, 0, 0, 0].as_slice() {
            return TestResult::Fail("selection must be first-match in file order");
        }
        // No entry matches this stepping at all.
        let blob = build_blob(2, &[mk(b'A', b'0', 0xC1)]);
        match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Err(DmcError::NoMainProgram) => {}
            _ => return TestResult::Fail("unmatched stepping must yield NoMainProgram"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_stepping_selection);

    fn smoke_pipec_skipped() -> TestResult {
        let progs = alloc::vec![
            ProgSpec {
                entry_dmc_id: 0,
                stepping: b'*',
                substepping: b'*',
                header_ver: 3,
                start: 0x80000,
                payload: alloc::vec![0xAAAA_0001],
                mmio: alloc::vec![(0x8F074, 0x2FC0)],
            },
            ProgSpec {
                entry_dmc_id: 3,
                stepping: b'*',
                substepping: b'*',
                header_ver: 3,
                start: 0x52000,
                payload: alloc::vec![0xDDDD_0001],
                mmio: alloc::vec![(0x52040, 1)],
            },
        ];
        let blob = build_blob(2, &progs);
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("a PIPEC-carrying blob must still parse"),
        };
        if fw.program(DmcId::PipeC).is_some() {
            return TestResult::Fail("PIPEC must not be loaded on Gen12 ranges");
        }
        if fw.skipped_mask != 1 << DmcId::PipeC.index() {
            return TestResult::Fail("the PIPEC skip must be recorded in skipped_mask");
        }
        let fake = FakeDmc::new();
        load_program(&fake, &fw);
        for (off, _) in fake.writes() {
            if off == 0x52000 {
                return TestResult::Fail("no write may target the skipped PIPEC program RAM");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_pipec_skipped);

    fn smoke_verify_loaded() -> TestResult {
        let blob = tgl_blob();
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the reference TGL blob must parse"),
        };
        let fake = FakeDmc::new();
        load_program(&fake, &fw);
        if verify_loaded(&fake, &fw) != Ok(()) {
            return TestResult::Fail("a freshly loaded program must verify");
        }
        // Tamper with one MMIO cell: verification names the
        // program, the entry and both values.
        fake.set_reg(0x8F074, 0xFFFF);
        match verify_loaded(&fake, &fw) {
            Err(DmcVerifyError::Mmio {
                id: DmcId::Main,
                index: 4,
                expected: 0x2FC0,
                found: 0xFFFF,
            }) => {}
            _ => return TestResult::Fail("a tampered MMIO cell must fail verification"),
        }
        fake.set_reg(0x8F074, 0x2FC0);
        // Tamper with program RAM's first dword.
        fake.set_reg(0x80000, 0);
        match verify_loaded(&fake, &fw) {
            Err(DmcVerifyError::ProgramStart {
                id: DmcId::Main,
                expected: 0xAAAA_0001,
                found: 0,
            }) => {}
            _ => return TestResult::Fail("tampered program RAM must fail verification"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_verify_loaded);

    fn smoke_disable_program() -> TestResult {
        let blob = tgl_blob();
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the reference TGL blob must parse"),
        };
        let fake = FakeDmc::new();
        disable_program(&fake, &fw);
        let mut expected = handler_sweep(0x8F034, 0x8F004);
        expected.extend(handler_sweep(0x92034, 0x92004));
        if fake.writes() != expected {
            return TestResult::Fail("disable must be exactly the two handler sweeps");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_disable_program);

    fn smoke_dc_target_handoff() -> TestResult {
        let blob = tgl_blob();
        let fw = match parse_dmc_firmware(&blob, b'B', b'1', DMC_MAX_FW_SIZE_GEN12) {
            Ok(fw) => fw,
            Err(_) => return TestResult::Fail("the reference TGL blob must parse"),
        };
        let fake = FakeDmc::new();
        // Bit 11 is a CSR mask bit outside the target
        // field; the RMW must preserve it.
        fake.set_reg(DC_STATE_EN, 0x800);
        if set_dc_target(&fake, &fw, DcTarget::Dc6) != Ok(()) {
            return TestResult::Fail("DC6 with a loaded main program must be accepted");
        }
        if fake.writes() != alloc::vec![(DC_STATE_EN, 0x802)] {
            return TestResult::Fail("DC6 must program field 2, preserving other bits");
        }
        if set_dc_target(&fake, &fw, DcTarget::Dc5) != Ok(())
            || fake.writes().last() != Some(&(DC_STATE_EN, 0x801))
        {
            return TestResult::Fail("DC5 must program field 1");
        }
        if set_dc_target(&fake, &fw, DcTarget::Off) != Ok(())
            || fake.writes().last() != Some(&(DC_STATE_EN, 0x800))
        {
            return TestResult::Fail("Off must program field 0");
        }
        // Without a main program, DC5/DC6 are refused with
        // no register touched; Off stays allowed.
        let empty = DmcFirmware {
            version: 0,
            programs: [None, None, None, None, None],
            skipped_mask: 0,
        };
        let fake2 = FakeDmc::new();
        fake2.set_reg(DC_STATE_EN, 0x800);
        if set_dc_target(&fake2, &empty, DcTarget::Dc6) != Err(DcError::NoMainProgram) {
            return TestResult::Fail("DC6 without DMC must refuse");
        }
        if !fake2.writes().is_empty() {
            return TestResult::Fail("a refused DC target must not touch DC_STATE_EN");
        }
        if set_dc_target(&fake2, &empty, DcTarget::Off) != Ok(()) {
            return TestResult::Fail("Off without DMC must stay allowed");
        }
        // Entry counters read straight through.
        fake.set_reg(TGL_DMC_DEBUG_DC5_COUNT, 7);
        fake.set_reg(TGL_DMC_DEBUG_DC6_COUNT, 9);
        if dc5_entry_count(&fake) != 7 || dc6_entry_count(&fake) != 9 {
            return TestResult::Fail("DC entry counters must read their debug registers");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dmc", smoke_dc_target_handoff);
}
