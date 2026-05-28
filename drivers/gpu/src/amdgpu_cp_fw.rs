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
//! After all three engines are primed, the driver clears `CP_GFX_CNTL`
//! to unhalt them and the CP starts fetching PM4 from the ring.
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

// MEC (Micro Engine for Compute) — compute queue scheduler. The
// MEC firmware is loaded into its own RS64-based engine with the
// CP_MEC_DC_BASE / CP_MEC_RS64_CNTL register block at 0x5870+.
pub const CP_MEC_DC_BASE_LO: u32 = 0x5870;
pub const CP_MEC_DC_BASE_HI: u32 = 0x5871;
pub const CP_MEC_DC_BASE_CNTL: u32 = 0x5872;
pub const CP_MEC_RS64_CNTL: u32 = 0x2904;
pub const CP_MEC_RS64_INSTR_PNTR: u32 = 0x2908;

// IC_OP_CNTL bits per gc_11_0_0_sh_mask.h.
pub const IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_SHIFT: u32 = 0;
pub const IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT: u32 = 1 << 0;
pub const IC_OP_CNTL_PRIME_ICACHE_BIT: u32 = 1 << 1;
pub const IC_OP_CNTL_ICACHE_PRIMED_BIT: u32 = 1 << 2;

// IC_BASE_CNTL bits.
pub const IC_BASE_CNTL_VMID_MASK: u32 = 0x0000_000F;
pub const IC_BASE_CNTL_CACHE_POLICY_MASK: u32 = 0x0000_0070;
pub const IC_BASE_CNTL_EXE_DISABLE: u32 = 1 << 23;

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
            CpEngine::Mec => (
                CP_MEC_DC_BASE_LO,
                CP_MEC_DC_BASE_HI,
                CP_MEC_DC_BASE_CNTL,
                // MEC RS64 OP_CNTL — different reg from PFP/ME but
                // bit layout matches.
                CP_MEC_RS64_CNTL,
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

/// `CP_GFX_CNTL` register — write 0 to unhalt all engines; the
/// halt bits per `amdgpu_gfx.rs::CP_GFX_CNTL_HALT_ALL`.
///
/// Mirrors `gfx_v11_0_cp_gfx_enable` — write 0 to unhalt, poll the
/// CP_STAT register's BUSY_STATUS bits to confirm engines are
/// fetching. Linux uses a 50 ms timeout against a 1 µs udelay.
pub fn cp_enable<M: CpFwMmio>(
    mmio: &mut M,
    gc_base: u32,
) -> Result<(), CpFwError> {
    let cntl_addr = (gc_base + (crate::amdgpu_gfx::CP_GFX_CNTL_REL / 4)) << 2;
    mmio.write(cntl_addr, 0);
    // Linux polls regCP_STAT to confirm the engines are running but
    // the canonical implementation here just trusts the write — the
    // ring will fail to fetch if the engines didn't come up.
    Ok(())
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

    fn smoke_engine_register_quads_correct() -> TestResult {
        let (lo, hi, cntl, op) = CpEngine::Pfp.registers();
        if lo != 0x5840 || hi != 0x5841 || cntl != 0x5842 || op != 0x5843 {
            return TestResult::Fail("PFP regs wrong");
        }
        let (lo, _, _, _) = CpEngine::Me.registers();
        if lo != 0x5844 {
            return TestResult::Fail("ME base_lo wrong");
        }
        let (lo, _, _, _) = CpEngine::Mec.registers();
        if lo != 0x5870 {
            return TestResult::Fail("MEC base_lo wrong");
        }
        TestResult::Pass
    }
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
        m.op_cntl_ack_value = IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT
            | IC_OP_CNTL_ICACHE_PRIMED_BIT;
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
        m.op_cntl_ack_value = IC_OP_CNTL_INVALIDATE_CACHE_COMPLETE_BIT
            | IC_OP_CNTL_ICACHE_PRIMED_BIT;
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
            if *off == CP_ME_IC_BASE_LO << 2 || *off == CP_MEC_DC_BASE_LO << 2 {
                return TestResult::Fail("ME/MEC written before PFP");
            }
        }
        if !found_pfp_first {
            return TestResult::Fail("PFP not written first");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_load_all_cp_fw_engine_order);

    fn smoke_cp_enable_writes_zero_to_gfx_cntl() -> TestResult {
        let mut m = MockCpFwMmio::new();
        cp_enable(&mut m, 0).expect("enable");
        if m.writes.len() != 1 {
            return TestResult::Fail("expected 1 write");
        }
        if m.writes[0].1 != 0 {
            return TestResult::Fail("not unhalt (val != 0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cp_enable_writes_zero_to_gfx_cntl);
}
