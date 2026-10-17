//! Register-model tests: every Navi22 clock-gating sequence against the
//! writes Linux's `amdgpu_device_set_cg_state` issues for navy_flounder.
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Discovery segments of the RX 6750 XT (GC 0x1260/0xA000, MMHUB 0x1A000,
/// ATHUB 0xC00, HDP 0xF20, OSSSYS 0x10A0, SMUIO 0x16800): absolute dwords.
fn abs(reg: Reg) -> u32 {
    reg.offset
        + match reg.block {
            Block::Gc0 => 0x1260,
            Block::Gc1 => 0xa000,
            Block::Mmhub => 0x1a000,
            Block::Athub => 0xc00,
            Block::Hdp => 0xf20,
            Block::Osssys => 0x10a0,
            Block::Smuio => 0x16800,
        }
}
pub(super) struct Fake {
    pub regs: Vec<(u32, u32)>,
    pub writes: Vec<(u32, u32)>,
    pub reads: Vec<u32>,
    /// Register reads outside the modelled set.
    pub unexpected: bool,
    /// RLC acknowledges safe-mode requests.
    pub rlc_acks: bool,
    /// Reads of this register return all-ones (device lost).
    pub gone: Option<u32>,
}
impl Fake {
    fn new() -> Self {
        Self {
            regs: vec![
                (0xec00, 1),           // RLC_CNTL: F32 running
                (0xeca0, 0),           // RLC_SAFE_MODE
                (0xec48, 0x0001_01fe), // RLC_CGTT_MGCG_OVERRIDE: all overrides
                (0xec49, 0),           // RLC_CGCG_CGLS_CTRL
                (0xecc5, 0),           // RLC_CGCG_CGLS_CTRL_3D
                (0xec06, 0),           // RLC_MEM_SLP_CNTL
                (0x3079, 0),           // CP_MEM_SLP_CNTL
                (0x21c2, 0x0040_0100), // CP_RB_WPTR_POLL_CNTL
                (0x306a, 0x0400_0000), // CP_INT_CNTL_RING0 (EOP armed)
                (0x306b, 0),           // CP_INT_CNTL_RING1
                (0xfb31, 0x100),       // RLC_CLK_CNTL
                (0xc200, 0),           // GRBM_GFX_INDEX
                (0xf084, 0),
                (0xf085, 0),
                (0xf086, 0),
                (0x1a070, 0xfc),       // DAGB0_CNTL_MISC2: CG disabled
                (0xc09, 0),            // ATHUB_MISC_CNTL
                (0xff4, 0),            // HDP_MEM_POWER_CTRL
                (0xff8, 0xfc00_001f),  // HDP_CLK_CNTL: overrides on
                (0x117b, 0xf800_0000), // IH_CLK_CTRL: overrides on
                (0x168e4, 0x100),      // CGTT_ROM_CLK_CTRL0
                (0x127b, 0x100),       // SDMA0_CLK_CTRL
                (0x187b, 0x100),       // SDMA1_CLK_CTRL
                (0x127a, 0x100),       // SDMA0_POWER_CNTL
                (0x187a, 0x100),       // SDMA1_POWER_CNTL
            ],
            writes: Vec::new(),
            reads: Vec::new(),
            unexpected: false,
            rlc_acks: true,
            gone: None,
        }
    }
    pub fn get(&self, dword: u32) -> u32 {
        self.regs
            .iter()
            .find(|(r, _)| *r == dword)
            .map_or(0, |(_, v)| *v)
    }
}
impl Io for Fake {
    fn read(&mut self, reg: Reg) -> u32 {
        let dword = abs(reg);
        self.reads.push(dword);
        if self.gone == Some(dword) {
            return u32::MAX;
        }
        match self.regs.iter().find(|(r, _)| *r == dword) {
            Some((_, value)) => *value,
            None => {
                self.unexpected = true;
                0
            }
        }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        let dword = abs(reg);
        self.writes.push((dword, value));
        // RLC clears CMD once safe mode is entered/left.
        let stored = if dword == 0xeca0 && self.rlc_acks {
            value & !1
        } else {
            value
        };
        match self.regs.iter_mut().find(|(r, _)| *r == dword) {
            Some(slot) => slot.1 = stored,
            None => self.unexpected = true,
        }
    }
}
fn engine() -> Engine<Fake> {
    Engine {
        io: Fake::new(),
        authority: Cap::bootstrap(),
        cg_flags: NAVY_FLOUNDER_CG,
        in_safe_mode: false,
        state: State::Idle,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
const ALL: Blocks = Blocks::SOC.union(Blocks::GFX);

/// Linux's GATE pass for navy_flounder, in IP order common, gmc, ih, gfx,
/// sdma, from the post-hw_init state in `Fake::new`.
const GATE: &[(u32, u32)] = &[
    // hdp_v5_0_update_mem_power_gating (HDP_LS): force IPH/RC clocks, clear,
    // set IPH/RC LS + CTRL_EN, release the forced clocks.
    (0xff8, 0xfc00_001f),
    (0xff4, 0),
    (0xff4, 0x0003_0003),
    (0xff8, 0xf000_001f),
    // hdp_v5_0_update_medium_grain_clock_gating.
    (0xff8, 0x0000_001f),
    // smuio_v11_0_6 ROM: no ROM_MGCG, so the clock stays forced on.
    (0x168e4, 0xc000_0100),
    // mmhub_v2_0 (2.1.0) DAGB0_CNTL_MISC2_Sienna_Cichlid, athub_v2_1 CG + LS.
    (0x1a070, 0),
    (0xc09, 0x40),
    (0xc09, 0xc0),
    // navi10_ih IH_CG.
    (0x117b, 0),
    // gfx_v10_0: RLC safe mode (CMD | MESSAGE=1).
    (0xeca0, 0x3),
    // MGCG: broadcast index, WD/VGT/IA CGTT, clear the six MGCG overrides.
    (0xc200, 0xe000_0000),
    (0xf086, 0xff00_0000),
    (0xf084, 0xff00_0000),
    (0xf085, 0xff00_0000),
    (0xec48, 0x0000_0098),
    // 3D CGCG: clear GFX3D override, FSM 0x3601, IDLE_POLL_COUNT 0x00900100.
    (0xec48, 0x0000_0018),
    (0xecc5, 0x0000_3601),
    (0x21c2, 0x0090_0100),
    // CGCG + CGLS: clear both overrides, FSM 0x363F (poll already set).
    (0xec48, 0),
    (0xec49, 0x0000_363f),
    // gfx_v10_0_enable_gui_idle_interrupt, ME0 pipes 0/1.
    (0x306a, 0x043c_0000),
    (0x306b, 0x003c_0000),
    // exit safe mode.
    (0xeca0, 0x1),
    // sdma_v5_2: no SDMA_MGCG/LS, so the "disable" branches run.
    (0x127b, 0xfc00_0100),
    (0x187b, 0xfc00_0100),
    (0x127a, 0),
    (0x187a, 0),
];
/// UNGATE, reverse IP order sdma, gfx, ih, gmc, common, after GATE.
const UNGATE: &[(u32, u32)] = &[
    (0xeca0, 0x3),
    // CGCG/CGLS off, then 3D CGCG off, then the MGCG overrides back on.
    (0xec49, 0x0000_363c),
    (0xecc5, 0x0000_3600),
    (0xec48, 0x0001_0166),
    (0x306a, 0x0400_0000),
    (0x306b, 0),
    (0xeca0, 0x1),
    (0x117b, 0xf800_0000),
    (0x1a070, 0xfc),
    (0xc09, 0x80),
    (0xc09, 0),
    (0xff8, 0x0c00_001f),
    (0xff4, 0),
    (0xff8, 0x0000_001f),
    (0xff8, 0xfc00_001f),
];

fn navi22_clock_gating_matches_linux_order_and_values() -> TestResult {
    let mut e = engine();
    if run(e.set_clockgating(true, ALL)).is_err() || e.state != State::Gated(ALL) {
        return TestResult::Fail("gate failed");
    }
    if e.io.writes != GATE || e.io.unexpected {
        return TestResult::Fail("gate writes differ from Linux");
    }
    // The safe-mode request precedes the first GC CG write and its exit
    // follows the last; RLC_CNTL was checked first.
    let first_gc = e.io.reads.iter().position(|r| *r == 0xec00);
    if first_gc.is_none_or(|i| e.io.reads[..i].contains(&0xec48)) {
        return TestResult::Fail("RLC enable not checked before GC programming");
    }
    e.io.writes.clear();
    if run(e.set_clockgating(false, ALL)).is_err() || e.state != State::Gated(Blocks::NONE) {
        return TestResult::Fail("ungate failed");
    }
    if e.io.writes != UNGATE || e.io.unexpected {
        return TestResult::Fail("ungate writes differ from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gating",
    navi22_clock_gating_matches_linux_order_and_values
);

/// Every CG enable is undone by UNGATE, a second GATE restores exactly the
/// first GATE's register state, and repeated GATE writes only Linux's
/// unconditional registers.
fn navi22_clock_gating_is_symmetric() -> TestResult {
    let mut e = engine();
    run(e.set_clockgating(true, ALL)).unwrap();
    let gated = e.io.regs.clone();
    run(e.set_clockgating(false, ALL)).unwrap();
    let f = &e.io;
    if f.get(0xec49) & 3 != 0
        || f.get(0xecc5) & 1 != 0
        || f.get(0xec48) & 0x1_0166 != 0x1_0166
        || f.get(0x1a070) & 0xfc != 0xfc
        || f.get(0xc09) & 0xc0 != 0
        || f.get(0x117b) != 0xf800_0000
        || f.get(0xff8) & 0xfc00_0000 != 0xfc00_0000
        || f.get(0xff4) != 0
        || f.get(0x306a) != 0x0400_0000
        || f.get(0x306b) != 0
    {
        return TestResult::Fail("ungate left a block gated");
    }
    run(e.set_clockgating(true, ALL)).unwrap();
    if e.io.regs != gated {
        return TestResult::Fail("regate state differs");
    }
    e.io.writes.clear();
    run(e.set_clockgating(true, ALL)).unwrap();
    // Unconditional in Linux: HDP (4 + 1), GRBM index + 3 CGTT, gui idle x2,
    // safe mode enter/exit.
    let rewritten: Vec<u32> = e.io.writes.iter().map(|(r, _)| *r).collect();
    if rewritten
        != [
            0xff8, 0xff4, 0xff4, 0xff8, 0xff8, 0xeca0, 0xc200, 0xf086, 0xf084, 0xf085, 0x306a,
            0x306b, 0xeca0,
        ]
        || e.io.regs != gated
    {
        return TestResult::Fail("idempotent gate rewrote a conditional register");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gating",
    navi22_clock_gating_is_symmetric
);

/// The policy splits GC from SoC gating; each selection touches only its
/// own blocks, and an empty selection touches nothing.
fn navi22_clock_gating_selects_blocks() -> TestResult {
    let mut e = engine();
    run(e.set_clockgating(true, Blocks::NONE)).unwrap();
    if !e.io.writes.is_empty() || !e.io.reads.is_empty() {
        return TestResult::Fail("empty selection touched hardware");
    }
    run(e.set_clockgating(true, Blocks::GFX)).unwrap();
    if e.io
        .writes
        .iter()
        .any(|(r, _)| !(0xa000..0x10000).contains(r) && !(0x1260..0x3260).contains(r))
        || e.io
            .writes
            .iter()
            .any(|(r, _)| [0x127b, 0x187b, 0x127a, 0x187a].contains(r))
    {
        return TestResult::Fail("GFX selection touched SoC blocks");
    }
    let mut e = engine();
    run(e.set_clockgating(true, Blocks::SOC)).unwrap();
    if e.io
        .writes
        .iter()
        .any(|(r, _)| (0xa000..0x10000).contains(r))
        || e.io.reads.contains(&0xec00)
    {
        return TestResult::Fail("SoC selection touched GC/RLC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gating",
    navi22_clock_gating_selects_blocks
);

fn navi22_clock_gating_refuses_unsafe_states() -> TestResult {
    // RLC halted: no safe mode, no GC write.
    let mut e = engine();
    e.io.regs.iter_mut().find(|(r, _)| *r == 0xec00).unwrap().1 = 0;
    if run(e.set_clockgating(true, Blocks::GFX)) != Err(Error::RlcHalted)
        || !e.io.writes.is_empty()
        || e.state != State::Failed
        || run(e.set_clockgating(false, Blocks::GFX)) != Err(Error::Failed)
    {
        return TestResult::Fail("halted RLC programmed or owner reusable");
    }
    // Safe mode never acknowledged: the request is withdrawn, no CG write.
    let mut e = engine();
    e.io.rlc_acks = false;
    if run(e.set_clockgating(true, Blocks::GFX)) != Err(Error::Timeout)
        || e.io.writes != [(0xeca0, 0x3), (0xeca0, 0x1)]
    {
        return TestResult::Fail("safe-mode timeout");
    }
    // Device lost mid-sequence: nothing derived from all-ones is written,
    // safe mode is exited, the owner is Failed.
    let mut e = engine();
    e.io.gone = Some(0xecc5);
    if run(e.set_clockgating(true, Blocks::GFX)) != Err(Error::DeviceGone)
        || e.io
            .writes
            .iter()
            .any(|(r, v)| *r == 0xecc5 || *v == u32::MAX)
        || e.io.writes.last() != Some(&(0xeca0, 0x1))
        || e.state != State::Failed
    {
        return TestResult::Fail("device loss");
    }
    // NBIO BIF gating needs the SMU-owned SMN path: refused before I/O.
    let mut e = engine();
    e.cg_flags |= cg::BIF_MGCG;
    if run(e.set_clockgating(true, Blocks::SOC)) != Err(Error::Unsupported)
        || !e.io.writes.is_empty()
    {
        return TestResult::Fail("BIF gating");
    }
    // Revoked authority: nothing written.
    let mut e = engine();
    e.authority.revoke();
    if run(e.set_clockgating(true, ALL)) != Err(Error::Revoked) || !e.io.writes.is_empty() {
        return TestResult::Fail("revoked authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gating",
    navi22_clock_gating_refuses_unsafe_states
);

/// Flags navy_flounder lacks keep their Linux sequences reachable: FGCG,
/// 3D CGLS and MGLS with CP/RLC LS (as on GC 10.3.1), checked by value.
fn navi22_clock_gating_optional_flags_follow_linux() -> TestResult {
    let mut e = engine();
    e.cg_flags = NAVY_FLOUNDER_CG
        | cg::GFX_FGCG
        | cg::GFX_3D_CGLS
        | cg::GFX_MGLS
        | cg::GFX_CP_LS
        | cg::GFX_RLC_LS;
    run(e.set_clockgating(true, Blocks::GFX)).unwrap();
    let f = &e.io;
    if f.get(0xec48) != 0
        || f.get(0xfb31) != 0
        || f.get(0xecc5) != 0x363f
        || f.get(0xec06) != 1
        || f.get(0x3079) != 1
    {
        return TestResult::Fail("optional GC gating values");
    }
    run(e.set_clockgating(false, Blocks::GFX)).unwrap();
    let f = &e.io;
    if f.get(0xec48) != 0x1_0166 | 0x100
        || f.get(0xfb31) != 0x100
        || f.get(0xecc5) != 0x363c
        || f.get(0xec06) != 0
        || f.get(0x3079) != 0
    {
        return TestResult::Fail("optional GC ungating values");
    }
    if NAVY_FLOUNDER_CG & (cg::GFX_FGCG | cg::GFX_MGLS | cg::GFX_3D_CGLS) != 0
        || NAVY_FLOUNDER_PG & pg::GFX_PG != 0
        || NAVY_FLOUNDER_CG != 0x0801_830d | cg::GFX_3D_CGCG | cg::VCN_MGCG | cg::JPEG_MGCG
    {
        return TestResult::Fail("nv.c flags");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gating",
    navi22_clock_gating_optional_flags_follow_linux
);
