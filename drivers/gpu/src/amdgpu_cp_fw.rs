//! AMD GFX11 CP firmware load (PFP / ME / MEC) + enable handshake.
//!
//! After PSP signs + loads the GFX firmware blob into the trusted
//! memory region, the kernel driver pumps the per-engine firmware
//! images into the CP's instruction caches (PFP, ME, MEC) and
//! waits for the IC handshake. Sequence (per Linux
//! `gfx_v11_0.c::gfx_v11_0_cp_gfx_load_pfp_microcode_rs64`,
//! lines 3192-3360):
//!
//!   1. Allocate a 64-KiB-aligned DMA buffer in GTT; memcpy the
//!      firmware ucode + data sections in.
//!   2. Program `CP_<eng>_IC_BASE_LO/HI` with the buffer's GPU addr.
//!   3. Set `CP_<eng>_IC_BASE_CNTL.VMID = 0; CACHE_POLICY = 0;
//!      EXE_DISABLE = 0` — the program-cache base register.
//!   4. Poll `CP_<eng>_IC_OP_CNTL.INVALIDATE_CACHE_COMPLETE = 1` —
//!      programming the BASE registers forces an L1 IC invalidate.
//!   5. Set `CP_<eng>_IC_OP_CNTL.PRIME_ICACHE = 1` — kick the prime.
//!   6. Poll `CP_<eng>_IC_OP_CNTL.ICACHE_PRIMED = 1` — wait for the
//!      prime to complete.
//!
//! LINUX-GAP: priming the caches does not start the engines, and the unhalt
//! is not one register. `gfx_v11_0_cp_gfx_load_pfp_microcode_rs64` also sets
//! `CP_PFP_PRGRM_CNTR_START`/`_HI` per pipe and toggles `CP_ME_CNTL`'s
//! per-pipe `PFP_PIPEn_RESET` then `PFP_PIPEn_ACTIVE`; the data sections go
//! through a second register set (`CP_GFX_RS64_DC_BASE0_LO`/`_HI`,
//! `CP_GFX_RS64_DC_BASE_CNTL` 0x2a08, `CP_GFX_RS64_DC_OP_CNTL` 0x2a09 for
//! PFP/ME; `CP_MEC_MDBASE_LO`/`_HI` with `CP_MEC_DC_*` for the MEC), and the
//! MEC is released through `CP_MEC_RS64_CNTL.MEC_HALT`. None of that is here.
//! `CP_GFX_CNTL` (0x2a00) exists but is not the unhalt.
//!
//! ## References (post 2026-05-20 GPL relicense)
//!
//! - Linux drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::
//!   gfx_v11_0_cp_gfx_load_{pfp,me,mec}_microcode_rs64
//! - Linux drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_offset.h
//!   — register offsets.

extern crate alloc;

use alloc::vec::Vec;

// ── Register offsets (GFX11) ──────────────────────────────────────
//
// From gc/gc_11_0_0_offset.h. Each engine's IC block has 4 paired
// registers. Phoenix uses BASE_IDX=1 (segment 1) — the per-segment
// offset is applied by the driver-glue layer (`segment_base_for_ip`)
// before writing.
//
// PFP (Pre-Fetch Parser) — head of the GFX queue.
pub const CP_PFP_IC_BASE_LO: u32 = 0x5840;
pub const CP_PFP_IC_BASE_HI: u32 = 0x5841;
pub const CP_PFP_IC_BASE_CNTL: u32 = 0x5842;
pub const CP_PFP_IC_OP_CNTL: u32 = 0x5843;

// ME (Mid-Engine) — middle stage of the GFX queue.
pub const CP_ME_IC_BASE_LO: u32 = 0x5844;
pub const CP_ME_IC_BASE_HI: u32 = 0x5845;
pub const CP_ME_IC_BASE_CNTL: u32 = 0x5846;
pub const CP_ME_IC_OP_CNTL: u32 = 0x5847;

// MEC (Micro Engine for Compute) — compute queue scheduler. Its instruction
// cache is the **CPC** block, not the MEC block: `CP_CPC_IC_BASE_*` and
// `CP_CPC_IC_OP_CNTL`, which `gfx_v11_0_cp_compute_load_microcode_rs64` is
// what programs with the MEC firmware's address.
pub const CP_CPC_IC_BASE_LO: u32 = 0x584c;
pub const CP_CPC_IC_BASE_HI: u32 = 0x584d;
pub const CP_CPC_IC_BASE_CNTL: u32 = 0x584e;
/// The CPC's OP_CNTL is nowhere near its BASE registers: 0x297a against
/// 0x584c. PFP and ME keep theirs adjacent; this one does not.
pub const CP_CPC_IC_OP_CNTL: u32 = 0x297a;

// The MEC **data** cache is a separate block, and its control register is not
// adjacent to its bases either — 0x290b follows 0x5871.
pub const CP_MEC_DC_BASE_LO: u32 = 0x5870;
pub const CP_MEC_DC_BASE_HI: u32 = 0x5871;
pub const CP_MEC_DC_BASE_CNTL: u32 = 0x290b;
pub const CP_MEC_DC_OP_CNTL: u32 = 0x290c;
/// Engine halt/reset/step control, with per-pipe `MEC_PIPEn_RESET` at 16..19
/// and `MEC_PIPEn_ACTIVE` at 26..29. Not an OP_CNTL: its bit 4 is
/// `MEC_INVALIDATE_ICACHE`, and it carries `MEC_HALT` at bit 30.
pub const CP_MEC_RS64_CNTL: u32 = 0x2904;
pub const CP_MEC_RS64_INSTR_PNTR: u32 = 0x2908;

// IC_OP_CNTL bits per gc_11_0_0_sh_mask.h. They are not consecutive from
// zero: the request and its completion are adjacent, then a three-bit gap
// before the prime pair.
pub const IC_OP_CNTL_INVALIDATE_CACHE_BIT: u32 = 1 << 0;
pub const IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_SHIFT: u32 = 1;
pub const IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT: u32 = 1 << 1;
pub const IC_OP_CNTL_PRIME_ICACHE_BIT: u32 = 1 << 4;
pub const IC_OP_CNTL_ICACHE_PRIMED_BIT: u32 = 1 << 5;

// IC_BASE_CNTL bits. `CACHE_POLICY` is two bits at 24, not three at 4 —
// bits 6:4 are `ADDRESS_CLAMP` and reserved space, so clearing 0x70 would
// clear the address clamp and leave the cache policy untouched.
pub const IC_BASE_CNTL_VMID_MASK: u32 = 0x0000_000F;
pub const IC_BASE_CNTL_ADDRESS_CLAMP: u32 = 1 << 4;
pub const IC_BASE_CNTL_EXE_DISABLE: u32 = 1 << 23;
pub const IC_BASE_CNTL_CACHE_POLICY_MASK: u32 = 0x0300_0000;

// ── Engine identifier ─────────────────────────────────────────────

/// Identifies one of the three CP engines whose firmware we load.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpEngine {
    Pfp,
    Me,
    Mec,
}

impl CpEngine {
    /// Per-engine register quad (BASE_LO, BASE_HI, BASE_CNTL, OP_CNTL).
    pub fn registers(self) -> (u32, u32, u32, u32) {
        match self {
            CpEngine::Pfp => (
                CP_PFP_IC_BASE_LO,
                CP_PFP_IC_BASE_HI,
                CP_PFP_IC_BASE_CNTL,
                CP_PFP_IC_OP_CNTL,
            ),
            CpEngine::Me => (
                CP_ME_IC_BASE_LO,
                CP_ME_IC_BASE_HI,
                CP_ME_IC_BASE_CNTL,
                CP_ME_IC_OP_CNTL,
            ),
            // The MEC's instruction cache is the CPC block. The MEC_DC
            // registers are its *data* cache, and CP_MEC_RS64_CNTL is the
            // engine's halt/reset control — neither is an instruction-cache
            // OP_CNTL, and writing a prime request into the latter would land
            // on reserved bits next to MEC_HALT.
            CpEngine::Mec => (
                CP_CPC_IC_BASE_LO,
                CP_CPC_IC_BASE_HI,
                CP_CPC_IC_BASE_CNTL,
                CP_CPC_IC_OP_CNTL,
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CpEngine::Pfp => "PFP",
            CpEngine::Me => "ME",
            CpEngine::Mec => "MEC",
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpFwError {
    /// FW image phys address isn't 64 KiB aligned (CP IC base
    /// requires it).
    UnalignedFwImage,
    /// Poll for INVALIDATE_CACHE_COMPLETE timed out.
    InvalidateTimeout,
    /// Poll for ICACHE_PRIMED timed out.
    PrimeTimeout,
    /// `CP_STAT` never read back zero after the CP was un-halted. Linux logs
    /// "failed to unhalt cp gfx" here and carries on; this reports it.
    CpEnableTimeout,
}

// ── Mmio trait ────────────────────────────────────────────────────

pub trait CpFwMmio {
    fn read(&mut self, byte_off: u32) -> u32;
    fn write(&mut self, byte_off: u32, value: u32);
}

/// Iteration cap on the poll. Linux uses `usec_timeout = 50000`
/// (50 ms); against an empty-cost mock 1M is the matching upper
/// bound.
pub const CP_FW_POLL_BUDGET: u32 = 1_000_000;

/// Load one CP engine's firmware. Programs BASE_LO/HI/CNTL, waits
/// for IC invalidate, then primes the IC + waits for the primed
/// handshake.
///
/// Mirrors `gfx_v11_0.c::gfx_v11_0_cp_gfx_load_pfp_microcode_rs64`
/// (line 3192-3360).
pub fn load_cp_engine_fw<M: CpFwMmio>(
    mmio: &mut M,
    gc_base: u32,
    engine: CpEngine,
    fw_gpu_addr: u64,
) -> Result<(), CpFwError> {
    if fw_gpu_addr & 0xFFFF != 0 {
        return Err(CpFwError::UnalignedFwImage);
    }

    let (base_lo, base_hi, base_cntl, op_cntl) = engine.registers();

    // Program BASE_LO/HI — pointing CP at the firmware image's GPU
    // address.
    mmio.write((gc_base + base_lo) << 2, fw_gpu_addr as u32);
    mmio.write((gc_base + base_hi) << 2, (fw_gpu_addr >> 32) as u32);

    // Program BASE_CNTL — VMID=0, CACHE_POLICY=0, EXE_DISABLE=0.
    // Read-modify-write so we don't perturb reserved bits.
    let bc_addr = (gc_base + base_cntl) << 2;
    let mut bc = mmio.read(bc_addr);
    bc &= !IC_BASE_CNTL_VMID_MASK;
    bc &= !IC_BASE_CNTL_CACHE_POLICY_MASK;
    bc &= !IC_BASE_CNTL_EXE_DISABLE;
    mmio.write(bc_addr, bc);

    // Programming any BASE register forces an L1 IC invalidate. Poll
    // OP_CNTL.INVALIDATE_CACHE_COMPLETE.
    let op_addr = (gc_base + op_cntl) << 2;
    let mut i = 0u32;
    loop {
        let v = mmio.read(op_addr);
        if v & IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT != 0 {
            break;
        }
        i += 1;
        if i >= CP_FW_POLL_BUDGET {
            return Err(CpFwError::InvalidateTimeout);
        }
    }

    // Prime the L1 instruction cache.
    let mut op = mmio.read(op_addr);
    op |= IC_OP_CNTL_PRIME_ICACHE_BIT;
    mmio.write(op_addr, op);

    // Poll for primed.
    let mut j = 0u32;
    loop {
        let v = mmio.read(op_addr);
        if v & IC_OP_CNTL_ICACHE_PRIMED_BIT != 0 {
            break;
        }
        j += 1;
        if j >= CP_FW_POLL_BUDGET {
            return Err(CpFwError::PrimeTimeout);
        }
    }

    Ok(())
}

/// Load all three CP engines' firmware in PFP→ME→MEC order. This
/// is the canonical bring-up sequence; the engines must complete
/// in this order because PFP feeds ME which feeds MEC.
///
/// On any engine's failure the caller should treat the partial
/// state as fatal — the GFX subsystem cannot start.
pub fn load_all_cp_fw<M: CpFwMmio>(
    mmio: &mut M,
    gc_base: u32,
    pfp_phys: u64,
    me_phys: u64,
    mec_phys: u64,
) -> Result<(), CpFwError> {
    load_cp_engine_fw(mmio, gc_base, CpEngine::Pfp, pfp_phys)?;
    load_cp_engine_fw(mmio, gc_base, CpEngine::Me, me_phys)?;
    load_cp_engine_fw(mmio, gc_base, CpEngine::Mec, mec_phys)?;
    Ok(())
}

// ── CP enable handshake ───────────────────────────────────────────

/// Un-halt the GFX CP, following `gfx_v11_0_cp_gfx_enable`
/// (`gfx_v11_0.c:3189`): read `CP_ME_CNTL`, clear this generation's halt bits,
/// write it back, then poll `CP_STAT` to zero.
///
/// LINUX-GAP: this used to write 0 to `CP_GFX_CNTL`, described as unhalting
/// all engines. `CP_GFX_CNTL` holds only `ENGINE_SEL` and `CONFIG`; the halt
/// bits are in `CP_ME_CNTL`, so the write cleared an engine selector and left
/// every engine halted. It also skipped the `CP_STAT` poll entirely, so a CP
/// that never came up looked like success.
///
/// `CP_ME_CNTL` is BASE_IDX 1 on GFX11 and BASE_IDX 0 on GFX9, while `CP_STAT`
/// is BASE_IDX 0 on both, so both windows are parameters. Linux polls against
/// `usec_timeout` (50 ms) at 1 µs a turn; [`CP_FW_POLL_BUDGET`] is the
/// equivalent iteration cap here.
pub fn cp_enable<M: CpFwMmio>(
    mmio: &mut M,
    generation: crate::amdgpu_gfx::GfxGeneration,
    gc_base_idx0: u32,
    gc_base_idx1: u32,
) -> Result<(), CpFwError> {
    let (me_cntl_rel, me_cntl_idx) = generation.cp_me_cntl_rel();
    let me_cntl_base = if me_cntl_idx == 0 {
        gc_base_idx0
    } else {
        gc_base_idx1
    };
    let me_cntl = (me_cntl_base + (me_cntl_rel / 4)) << 2;
    let cp_stat = (gc_base_idx0 + (generation.cp_stat_rel() / 4)) << 2;

    // Read-modify-write: the other fields of CP_ME_CNTL are not ours to clear.
    let current = mmio.read(me_cntl);
    mmio.write(me_cntl, current & !generation.cp_me_cntl_halt_all());

    for _ in 0..CP_FW_POLL_BUDGET {
        if mmio.read(cp_stat) == 0 {
            return Ok(());
        }
    }
    Err(CpFwError::CpEnableTimeout)
}

// ── Test support ──────────────────────────────────────────────────

pub mod test_support {
    use super::*;
    use alloc::collections::VecDeque;

    /// Mock CP mmio with staged reads + recorded writes. Used by
    /// smokes to drive the IC handshake state machine without real
    /// silicon.
    #[derive(Debug, Default)]
    pub struct MockCpFwMmio {
        pub writes: Vec<(u32, u32)>,
        pub reads: VecDeque<(u32, u32)>,
        /// After N reads of `op_cntl`, ack with `complete | primed`.
        pub poll_count: u32,
        /// Returns this on `op_cntl` reads after a few polls.
        pub op_cntl_address: u32,
        /// Optional override — what the mock returns for op_cntl
        /// reads after the first 2 polls.
        pub op_cntl_ack_value: u32,
    }

    impl MockCpFwMmio {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl CpFwMmio for MockCpFwMmio {
        fn read(&mut self, byte_off: u32) -> u32 {
            if let Some(staged) = self.reads.pop_front() {
                if staged.0 == byte_off {
                    return staged.1;
                }
                self.reads.push_front(staged);
            }
            if byte_off == self.op_cntl_address && self.op_cntl_ack_value != 0 {
                self.poll_count += 1;
                if self.poll_count >= 2 {
                    return self.op_cntl_ack_value;
                }
            }
            0
        }
        fn write(&mut self, byte_off: u32, value: u32) {
            self.writes.push((byte_off, value));
        }
    }
}

// ── Smoke tests ───────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::test_support::MockCpFwMmio;
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Dword ids spelled out from `gc_11_0_0_offset.h`. PFP and ME keep their
    /// quads adjacent; nothing else in this block does, so none of the other
    /// values can be reached by continuing a run.
    fn smoke_engine_register_quads_correct() -> TestResult {
        let (lo, hi, cntl, op) = CpEngine::Pfp.registers();
        if lo != 0x5840 || hi != 0x5841 || cntl != 0x5842 || op != 0x5843 {
            return TestResult::Fail("PFP regs wrong");
        }
        let (lo, hi, cntl, op) = CpEngine::Me.registers();
        if lo != 0x5844 || hi != 0x5845 || cntl != 0x5846 || op != 0x5847 {
            return TestResult::Fail("ME regs wrong");
        }
        // The MEC's instruction cache is the CPC block, and its OP_CNTL is in
        // a different part of the map from its bases.
        let (lo, hi, cntl, op) = CpEngine::Mec.registers();
        if lo != 0x584c || hi != 0x584d || cntl != 0x584e {
            return TestResult::Fail("MEC loads through CP_CPC_IC_BASE_*, not CP_MEC_DC_*");
        }
        if op != 0x297a {
            return TestResult::Fail("regCP_CPC_IC_OP_CNTL is 0x297a, far from its bases");
        }
        // The MEC data cache is a separate block whose control register is
        // likewise not adjacent to its bases; 0x5872 is regCP_MEC_MIBOUND_LO.
        if CP_MEC_DC_BASE_LO != 0x5870 || CP_MEC_DC_BASE_HI != 0x5871 {
            return TestResult::Fail("MEC data cache bases");
        }
        if CP_MEC_DC_BASE_CNTL != 0x290b || CP_MEC_DC_OP_CNTL != 0x290c {
            return TestResult::Fail("regCP_MEC_DC_BASE_CNTL is 0x290b, not 0x5872");
        }
        if CP_MEC_RS64_CNTL != 0x2904 || CP_MEC_RS64_INSTR_PNTR != 0x2908 {
            return TestResult::Fail("MEC engine control registers");
        }
        TestResult::Pass
    }

    /// `gc_11_0_0_sh_mask.h`. Neither bitfield runs consecutively from zero,
    /// which is the shape a hand-filled table falls into.
    fn smoke_cp_fw_register_bitfields() -> TestResult {
        // INVALIDATE_CACHE 0, INVALIDATE_CACHE_COMPLETE 1, then a gap, then
        // PRIME_ICACHE 4 and ICACHE_PRIMED 5. Polling bit 0 for completion
        // would read the request back.
        if IC_OP_CNTL_INVALIDATE_CACHE_BIT != 1
            || IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT != 1 << 1
            || IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_SHIFT != 1
        {
            return TestResult::Fail("the invalidate request is bit 0 and its completion bit 1");
        }
        if IC_OP_CNTL_PRIME_ICACHE_BIT != 1 << 4 || IC_OP_CNTL_ICACHE_PRIMED_BIT != 1 << 5 {
            return TestResult::Fail("PRIME_ICACHE is bit 4 and ICACHE_PRIMED bit 5");
        }
        // VMID 3:0, ADDRESS_CLAMP 4, EXE_DISABLE 23, CACHE_POLICY 25:24.
        if IC_BASE_CNTL_VMID_MASK != 0xF || IC_BASE_CNTL_ADDRESS_CLAMP != 1 << 4 {
            return TestResult::Fail("VMID is 3:0 and ADDRESS_CLAMP bit 4");
        }
        if IC_BASE_CNTL_EXE_DISABLE != 1 << 23 {
            return TestResult::Fail("EXE_DISABLE is bit 23");
        }
        if IC_BASE_CNTL_CACHE_POLICY_MASK != 0x0300_0000 {
            return TestResult::Fail("CACHE_POLICY is two bits at 24, not three at 4");
        }
        // The two must not overlap: a 0x70 cache-policy mask would have
        // swallowed ADDRESS_CLAMP and cleared it instead.
        if IC_BASE_CNTL_CACHE_POLICY_MASK & IC_BASE_CNTL_ADDRESS_CLAMP != 0 {
            return TestResult::Fail("the cache policy mask must not cover ADDRESS_CLAMP");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cp_fw_register_bitfields);
    kernel_test_in!("drivers/gpu", smoke_engine_register_quads_correct);

    fn smoke_load_cp_fw_rejects_unaligned() -> TestResult {
        let mut m = MockCpFwMmio::new();
        // 4 KiB aligned but not 64 KiB.
        let r = load_cp_engine_fw(&mut m, 0, CpEngine::Pfp, 0x1000);
        if r != Err(CpFwError::UnalignedFwImage) {
            return TestResult::Fail("unaligned FW not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_load_cp_fw_rejects_unaligned);

    fn smoke_load_cp_fw_writes_base_then_polls() -> TestResult {
        let mut m = MockCpFwMmio::new();
        // Set up: op_cntl reads return INVALIDATE_COMPLETE | ICACHE_PRIMED
        // after a few polls.
        m.op_cntl_address = (CP_PFP_IC_OP_CNTL) << 2;
        m.op_cntl_ack_value =
            IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT | IC_OP_CNTL_ICACHE_PRIMED_BIT;
        let r = load_cp_engine_fw(&mut m, 0, CpEngine::Pfp, 0x10_0000);
        if r.is_err() {
            return TestResult::Fail("load failed");
        }
        // Three writes for BASE_LO + BASE_HI + BASE_CNTL + 1 for
        // PRIME = 4 writes. Check the first two are LO + HI.
        if m.writes.len() < 4 {
            return TestResult::Fail("not enough writes");
        }
        if m.writes[0] != (CP_PFP_IC_BASE_LO << 2, 0x10_0000) {
            return TestResult::Fail("BASE_LO wrong");
        }
        if m.writes[1] != (CP_PFP_IC_BASE_HI << 2, 0) {
            return TestResult::Fail("BASE_HI wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_load_cp_fw_writes_base_then_polls);

    fn smoke_load_cp_fw_invalidate_timeout() -> TestResult {
        let mut m = MockCpFwMmio::new();
        // op_cntl always returns 0 → invalidate-complete never fires.
        let r = load_cp_engine_fw(&mut m, 0, CpEngine::Pfp, 0x10_0000);
        if r != Err(CpFwError::InvalidateTimeout) {
            return TestResult::Fail("timeout not triggered");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_load_cp_fw_invalidate_timeout);

    fn smoke_load_all_cp_fw_engine_order() -> TestResult {
        let mut m = MockCpFwMmio::new();
        // Make every IC OP_CNTL read return the success bits — this
        // works because the mock returns 0 for all addrs except the
        // op_cntl_address; we set that to PFP's op_cntl. ME / MEC will
        // hit the timeout path since we only mocked one address. We
        // verify that at least PFP succeeded.
        m.op_cntl_address = CP_PFP_IC_OP_CNTL << 2;
        m.op_cntl_ack_value =
            IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT | IC_OP_CNTL_ICACHE_PRIMED_BIT;
        let r = load_all_cp_fw(&mut m, 0, 0x10_0000, 0x20_0000, 0x30_0000);
        // ME polling will fail since mock only acks PFP's op_cntl.
        // That's the expected behaviour in this minimal mock setup
        // — proves the engine ordering halts on the first failure.
        if r == Ok(()) {
            return TestResult::Fail("multi-engine should've failed at ME");
        }
        // PFP's BASE_LO was written first — verify ordering.
        let mut found_pfp_first = false;
        for (off, _) in &m.writes {
            if *off == CP_PFP_IC_BASE_LO << 2 {
                found_pfp_first = true;
                break;
            }
            if *off == CP_ME_IC_BASE_LO << 2 || *off == CP_CPC_IC_BASE_LO << 2 {
                return TestResult::Fail("ME/MEC written before PFP");
            }
        }
        if !found_pfp_first {
            return TestResult::Fail("PFP not written first");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_load_all_cp_fw_engine_order);

    /// Literals from `gc_11_0_0_offset.h` / `gc_9_0_offset.h` and
    /// `gc_*_sh_mask.h`, not from the constants under test.
    fn smoke_cp_enable_clears_the_me_cntl_halt_bits() -> TestResult {
        use crate::amdgpu_gfx::GfxGeneration;
        // regCP_ME_CNTL 0x0803 BASE_IDX 1 on GFX11, regCP_STAT 0x0f40 idx 0.
        // CP_ME_CNTL__ME_HALT 0x10000000, __PFP_HALT 0x04000000; GFX10 dropped
        // the constant engine so __CE_HALT 0x01000000 is not touched.
        let mut m = MockCpFwMmio::new();
        let (idx0, idx1) = (0x1000u32, 0x9000u32);
        let me_cntl = (idx1 + 0x0803) << 2;
        let cp_stat = (idx0 + 0x0F40) << 2;
        // Halted, with CE_HALT and an unrelated bit also set.
        m.reads.push_back((me_cntl, 0x1500_0002));
        m.reads.push_back((cp_stat, 0));
        cp_enable(&mut m, GfxGeneration::Gfx11, idx0, idx1).expect("enable");
        if m.writes.len() != 1 {
            return TestResult::Fail("expected exactly the CP_ME_CNTL write");
        }
        if m.writes[0].0 != me_cntl {
            return TestResult::Fail("the halt bits are in CP_ME_CNTL, not CP_GFX_CNTL");
        }
        // ME_HALT and PFP_HALT cleared; CE_HALT and bit 1 left alone.
        if m.writes[0].1 != 0x0100_0002 {
            return TestResult::Fail("GFX11 clears only ME_HALT and PFP_HALT");
        }
        // GFX9 clears CE_HALT too, and reaches CP_ME_CNTL through window 0.
        let mut m9 = MockCpFwMmio::new();
        let me_cntl9 = (idx0 + 0x01B6) << 2;
        m9.reads.push_back((me_cntl9, 0x1500_0002));
        m9.reads.push_back(((idx0 + 0x01A0) << 2, 0));
        cp_enable(&mut m9, GfxGeneration::Gfx9, idx0, idx1).expect("gfx9 enable");
        if m9.writes[0].0 != me_cntl9 || m9.writes[0].1 != 0x0000_0002 {
            return TestResult::Fail("GFX9 clears ME, PFP and CE through window 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cp_enable_clears_the_me_cntl_halt_bits);
}
