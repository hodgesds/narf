//! Navi22 clock gating, as Linux applies it in `amdgpu_device_set_cg_state`
//! for the IP blocks of a GC 10.3.2 (navy_flounder) board: `nv_common`
//! (nbio_v2_3, hdp_v5_0, smuio_v11_0_6), `gmc_v10_0` (mmhub_v2_0 for MMHUB
//! 2.1.0, athub_v2_1), `navi10_ih`, `gfx_v10_0` and `sdma_v5_2`. VCN/JPEG
//! clock gating belongs to their own idle work in Linux and is not driven
//! here. Every sequence is a register-for-register copy of Linux's, keyed on
//! the `adev->cg_flags` nv.c sets for this ASIC ([`NAVY_FLOUNDER_CG`]);
//! where Linux's guard returns for a flag navy_flounder lacks, so does this.
//!
//! Nothing here runs on a default boot: the only caller is the explicit
//! `amdgpu.navi22_pg` opt-in, after `amdgpu_navi22_power_policy` admitted the
//! feature. GFX programming requires GFXOFF to be disallowed (GC powered) —
//! as in Linux, where CG is applied in late init before GFXOFF is allowed.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as discovery};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// amd_shared.h `AMD_CG_SUPPORT_*`.
pub mod cg {
    pub const GFX_MGCG: u64 = 1 << 0;
    pub const GFX_MGLS: u64 = 1 << 1;
    pub const GFX_CGCG: u64 = 1 << 2;
    pub const GFX_CGLS: u64 = 1 << 3;
    pub const GFX_CP_LS: u64 = 1 << 6;
    pub const GFX_RLC_LS: u64 = 1 << 7;
    pub const MC_LS: u64 = 1 << 8;
    pub const MC_MGCG: u64 = 1 << 9;
    pub const SDMA_LS: u64 = 1 << 10;
    pub const SDMA_MGCG: u64 = 1 << 11;
    pub const BIF_LS: u64 = 1 << 12;
    pub const HDP_LS: u64 = 1 << 15;
    pub const HDP_MGCG: u64 = 1 << 16;
    pub const ROM_MGCG: u64 = 1 << 17;
    pub const BIF_MGCG: u64 = 1 << 19;
    pub const GFX_3D_CGCG: u64 = 1 << 20;
    pub const GFX_3D_CGLS: u64 = 1 << 21;
    pub const VCN_MGCG: u64 = 1 << 24;
    pub const HDP_DS: u64 = 1 << 25;
    pub const HDP_SD: u64 = 1 << 26;
    pub const IH_CG: u64 = 1 << 27;
    pub const JPEG_MGCG: u64 = 1 << 30;
    pub const GFX_FGCG: u64 = 1 << 31;
}
/// amd_shared.h `AMD_PG_SUPPORT_*`.
pub mod pg {
    pub const GFX_PG: u32 = 1 << 0;
    pub const MMHUB: u32 = 1 << 13;
    pub const VCN: u32 = 1 << 14;
    pub const VCN_DPG: u32 = 1 << 15;
    pub const ATHUB: u32 = 1 << 16;
    pub const JPEG: u32 = 1 << 17;
}
/// nv.c `nv_common_early_init`, `case IP_VERSION(10, 3, 2)`. No MGLS, FGCG,
/// 3D CGLS, CP/RLC LS, SDMA, BIF or ROM gating on this ASIC.
pub const NAVY_FLOUNDER_CG: u64 = cg::GFX_MGCG
    | cg::GFX_CGCG
    | cg::GFX_CGLS
    | cg::GFX_3D_CGCG
    | cg::VCN_MGCG
    | cg::JPEG_MGCG
    | cg::MC_MGCG
    | cg::MC_LS
    | cg::HDP_MGCG
    | cg::HDP_LS
    | cg::IH_CG;
/// Same case: no `AMD_PG_SUPPORT_GFX_PG`, so `gfx_v10_cntl_pg` never runs
/// and GFX power gating is GFXOFF through PMFW (`amdgpu_navi22_gfxoff`).
/// MMHUB/ATHUB PG are PMFW features (`FEATURE_MMHUB_PG/ATHUB_PG`).
pub const NAVY_FLOUNDER_PG: u32 = pg::VCN | pg::VCN_DPG | pg::JPEG | pg::ATHUB | pg::MMHUB;

/// SOC15 register: one discovery base segment plus the header offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    Gc0,
    Gc1,
    Mmhub,
    Athub,
    Hdp,
    Osssys,
    Smuio,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reg {
    pub block: Block,
    pub offset: u32,
}
const fn reg(block: Block, offset: u32) -> Reg {
    Reg { block, offset }
}
// gc_10_3_0_offset.h (GC base index in the comment's segment).
pub(crate) const GRBM_GFX_INDEX: Reg = reg(Block::Gc1, 0x2200);
pub(crate) const CGTT_VGT_CLK_CTRL: Reg = reg(Block::Gc1, 0x5084);
pub(crate) const CGTT_IA_CLK_CTRL: Reg = reg(Block::Gc1, 0x5085);
pub(crate) const CGTT_WD_CLK_CTRL: Reg = reg(Block::Gc1, 0x5086);
pub(crate) const RLC_CNTL: Reg = reg(Block::Gc1, 0x4c00);
pub(crate) const RLC_MEM_SLP_CNTL: Reg = reg(Block::Gc1, 0x4c06);
pub(crate) const RLC_CGTT_MGCG_OVERRIDE: Reg = reg(Block::Gc1, 0x4c48);
pub(crate) const RLC_CGCG_CGLS_CTRL: Reg = reg(Block::Gc1, 0x4c49);
pub(crate) const RLC_CGCG_CGLS_CTRL_3D: Reg = reg(Block::Gc1, 0x4cc5);
/// gfx_v10_0.c `mmRLC_SAFE_MODE_Sienna_Cichlid`.
pub(crate) const RLC_SAFE_MODE: Reg = reg(Block::Gc1, 0x4ca0);
pub(crate) const RLC_CLK_CNTL: Reg = reg(Block::Gc1, 0x5b31);
pub(crate) const CP_RB_WPTR_POLL_CNTL: Reg = reg(Block::Gc0, 0x0f62);
pub(crate) const CP_INT_CNTL_RING0: Reg = reg(Block::Gc0, 0x1e0a);
pub(crate) const CP_INT_CNTL_RING1: Reg = reg(Block::Gc0, 0x1e0b);
pub(crate) const CP_MEM_SLP_CNTL: Reg = reg(Block::Gc0, 0x1e19);
/// SDMA0 registers sit on GC base 0; `sdma_v5_2_get_reg_offset` adds
/// `SDMA1_REG_OFFSET` (0x600) for instance 1.
pub(crate) const SDMA_POWER_CNTL: [Reg; 2] = [reg(Block::Gc0, 0x001a), reg(Block::Gc0, 0x061a)];
pub(crate) const SDMA_CLK_CTRL: [Reg; 2] = [reg(Block::Gc0, 0x001b), reg(Block::Gc0, 0x061b)];
/// mmhub_v2_0.c `mmDAGB0_CNTL_MISC2_Sienna_Cichlid` (MMHUB 2.1.x).
pub(crate) const DAGB0_CNTL_MISC2: Reg = reg(Block::Mmhub, 0x0070);
/// athub_2_1_0_offset.h.
pub(crate) const ATHUB_MISC_CNTL: Reg = reg(Block::Athub, 0x0009);
/// hdp_5_0_0_offset.h.
pub(crate) const HDP_MEM_POWER_CTRL: Reg = reg(Block::Hdp, 0x00d4);
pub(crate) const HDP_CLK_CNTL: Reg = reg(Block::Hdp, 0x00d8);
/// osssys_5_0_0_offset.h.
pub(crate) const IH_CLK_CTRL: Reg = reg(Block::Osssys, 0x00db);
/// smuio_11_0_6_offset.h.
pub(crate) const CGTT_ROM_CLK_CTRL0: Reg = reg(Block::Smuio, 0x00e4);
const GC0_LAST: u32 = 0x1e19;
const GC1_LAST: u32 = 0x5b31;

// gc_10_3_0_sh_mask.h fields.
const RLC_ENABLE_F32: u32 = 1 << 0;
const SAFE_MODE_CMD: u32 = 1 << 0;
const SAFE_MODE_MESSAGE_SHIFT: u32 = 1;
const OVERRIDE_RLC_CGTT_SCLK: u32 = 1 << 1;
const OVERRIDE_GFXIP_MGCG: u32 = 1 << 2;
const OVERRIDE_GFXIP_CGCG: u32 = 1 << 3;
const OVERRIDE_GFXIP_CGLS: u32 = 1 << 4;
const OVERRIDE_GRBM_CGTT_SCLK: u32 = 1 << 5;
const OVERRIDE_GFXIP_MGLS: u32 = 1 << 6;
const OVERRIDE_GFXIP_GFX3D_CG: u32 = 1 << 7;
const OVERRIDE_GFXIP_FGCG: u32 = 1 << 8;
const OVERRIDE_ENABLE_CGTS_LEGACY: u32 = 1 << 16;
/// The six bits `gfx_v10_0_update_medium_grain_clock_gating` clears/sets.
const MGCG_OVERRIDES: u32 = OVERRIDE_GRBM_CGTT_SCLK
    | OVERRIDE_RLC_CGTT_SCLK
    | OVERRIDE_GFXIP_MGCG
    | OVERRIDE_GFXIP_MGLS
    | OVERRIDE_GFXIP_FGCG
    | OVERRIDE_ENABLE_CGTS_LEGACY;
const MEM_LS_EN: u32 = 1 << 0;
const CGCG_EN: u32 = 1 << 0;
const CGLS_EN: u32 = 1 << 1;
const CGLS_REP_COMPANSAT_DELAY_SHIFT: u32 = 2;
const CGCG_GFX_IDLE_THRESHOLD_SHIFT: u32 = 8;
/// "set IDLE_POLL_COUNT(0x00900100)": POLL_FREQUENCY 0x100, IDLE_POLL_COUNT 0x90.
pub(crate) const WPTR_POLL_IDLE: u32 = 0x0100 | 0x0090 << 16;
const RLC_SRAM_CLK_GATER_OVERRIDE: u32 = 1 << 8;
/// CP_INT_CNTL_RING0: CMP_BUSY, CNTX_BUSY, CNTX_EMPTY, GFX_IDLE.
pub(crate) const GUI_IDLE_INTERRUPTS: u32 = (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21);
/// sdma0 SOFT_OVERRIDE4..0 and SOFT_OVERRIDER_REG.
const SDMA_SOFT_OVERRIDES: u32 = 0xfc00_0000;
const SDMA_MEM_POWER_OVERRIDE: u32 = 1 << 8;
/// DAGB0_CNTL_MISC2 DISABLE_{WRREQ,WRRET,RDREQ,RDRET,TLBWR,TLBRD}_CG.
const DAGB_DISABLE_CG: u32 = 0xfc;
const ATHUB_CG_ENABLE: u32 = 1 << 6;
const ATHUB_CG_MEM_LS_ENABLE: u32 = 1 << 7;
const HDP_IPH_MEM_CLK_SOFT_OVERRIDE: u32 = 1 << 26;
const HDP_RC_MEM_CLK_SOFT_OVERRIDE: u32 = 1 << 27;
/// IPH/RC mem, DBUS, DYN, XDP_REG and HDP_REG clock soft overrides.
const HDP_CLK_SOFT_OVERRIDES: u32 = 0xfc00_0000;
const HDP_IPH_CTRL_EN: u32 = 1 << 0;
const HDP_IPH_LS_EN: u32 = 1 << 1;
const HDP_IPH_DS_EN: u32 = 1 << 2;
const HDP_IPH_SD_EN: u32 = 1 << 3;
const HDP_RC_CTRL_EN: u32 = 1 << 16;
const HDP_RC_LS_EN: u32 = 1 << 17;
const HDP_RC_DS_EN: u32 = 1 << 18;
const HDP_RC_SD_EN: u32 = 1 << 19;
/// IH_CLK_CTRL DBUS_MUX, OSSSYS_SHARE, LIMIT_SMN, DYN and REG soft overrides.
const IH_SOFT_OVERRIDES: u32 = 0xf800_0000;
/// CGTT_ROM_CLK_CTRL0 SOFT_OVERRIDE0/1.
const ROM_SOFT_OVERRIDES: u32 = 0xc000_0000;
/// `adev->usec_timeout` (AMDGPU_MAX_USEC_TIMEOUT): the RLC safe-mode wait.
const SAFE_MODE_TIMEOUT_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    /// RLC never acknowledged the safe-mode request.
    Timeout,
    /// RLC F32 is halted: Linux would program GC without safe mode; NARF refuses.
    RlcHalted,
    /// A previous transition failed; the owner refuses further programming.
    Failed,
}

/// One Linux IP block's `set_clockgating_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ip {
    /// `nv_common_set_clockgating_state`: NBIO MGCG/LS, HDP, SMUIO ROM.
    Common,
    /// `gmc_v10_0_set_clockgating_state`: MMHUB then ATHUB.
    Gmc,
    /// `navi10_ih_set_clockgating_state`.
    Ih,
    /// `gfx_v10_0_set_clockgating_state` (`update_gfx_clock_gating`).
    Gfx,
    /// `sdma_v5_2_set_clockgating_state`.
    Sdma,
}
/// `adev->ip_blocks` order for this ASIC (amdgpu_discovery_set_ip_blocks):
/// common, gmc, ih, psp, smu, dm, gfx, sdma. PSP/SMU/DM have no CG work.
/// Gating walks it forward, ungating backward (`amdgpu_device_set_cg_state`).
pub const IP_ORDER: [Ip; 5] = [Ip::Common, Ip::Gmc, Ip::Ih, Ip::Gfx, Ip::Sdma];

/// A set of [`Ip`] blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Blocks(u8);
impl Blocks {
    pub const NONE: Self = Self(0);
    /// The GC part (policy feature `GfxClockGating`).
    pub const GFX: Self = Self(1 << Ip::Gfx as u8);
    /// Everything else (policy feature `ClockGating`): hubs, HDP, IH, SDMA.
    pub const SOC: Self =
        Self(1 << Ip::Common as u8 | 1 << Ip::Gmc as u8 | 1 << Ip::Ih as u8 | 1 << Ip::Sdma as u8);
    pub const fn contains(self, ip: Ip) -> bool {
        self.0 & 1 << ip as u8 != 0
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Owner built; no gating register has been written.
    Idle,
    /// The blocks currently gated (possibly none after a full ungate).
    Gated(Blocks),
    Failed,
}

pub(crate) trait Io {
    fn read(&mut self, reg: Reg) -> u32;
    fn write(&mut self, reg: Reg, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    gc0: u64,
    gc1: u64,
    mmhub: u64,
    athub: u64,
    hdp: u64,
    osssys: u64,
    smuio: u64,
}
impl Mmio {
    fn at(&self, reg: Reg) -> u64 {
        let base = match reg.block {
            Block::Gc0 => self.gc0,
            Block::Gc1 => self.gc1,
            Block::Mmhub => self.mmhub,
            Block::Athub => self.athub,
            Block::Hdp => self.hdp,
            Block::Osssys => self.osssys,
            Block::Smuio => self.smuio,
        };
        base + u64::from(reg.offset) * 4
    }
}
impl Io for Mmio {
    fn read(&mut self, reg: Reg) -> u32 {
        // SAFETY: every bank was bounded through the highest register this
        // module names on it at construction; every caller passes a constant.
        unsafe { self.regs.read32(self.at(reg)) }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        // SAFETY: same bounds; the owner's contract excludes other writers of
        // these clock-gating registers.
        unsafe { self.regs.write32(self.at(reg), value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// Register access with Linux's sequence shape: every read is checked for
/// device loss before its value can feed a write.
struct Seq<'a, I: Io> {
    io: &'a mut I,
}
impl<I: Io> Seq<'_, I> {
    fn rd(&mut self, reg: Reg) -> Result<u32, Error> {
        match self.io.read(reg) {
            u32::MAX => Err(Error::DeviceGone),
            value => Ok(value),
        }
    }
    fn wr(&mut self, reg: Reg, value: u32) {
        self.io.write(reg, value);
    }
    /// `if (def != data) WREG32(...)`.
    fn update(&mut self, reg: Reg, def: u32, data: u32) {
        if def != data {
            self.wr(reg, data);
        }
    }
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    cg_flags: u64,
    /// `adev->gfx.rlc.in_safe_mode[0]`.
    in_safe_mode: bool,
    state: State,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut Seq<'_, I>) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(&mut Seq { io })))
            .map_err(|_| Error::Revoked)
    }
    fn has(&self, flags: u64) -> bool {
        self.cg_flags & flags != 0
    }

    // ── nv_common: nbio_v2_3, hdp_v5_0, smuio_v11_0_6 ───────────────────
    fn common(&mut self, enable: bool) -> Result<(), Error> {
        // nbio_v2_3_update_medium_grain_clock_gating / _light_sleep return
        // without BIF_MGCG / BIF_LS. Their SMN (PCIE index/data) accesses are
        // the SMU owner's; a flag set that needs them is refused.
        if self.has(cg::BIF_MGCG | cg::BIF_LS) {
            return Err(Error::Unsupported);
        }
        let flags = self.cg_flags;
        self.access(|s| {
            hdp_mem_power_gating(s, flags, enable)?;
            hdp_medium_grain_clock_gating(s, flags, enable)?;
            smuio_rom_clock_gating(s, flags, enable)
        })?
    }
    // ── gmc_v10_0: mmhub_v2_0 (2.1.0), athub_v2_1 ───────────────────────
    fn gmc(&mut self, enable: bool) -> Result<(), Error> {
        let flags = self.cg_flags;
        self.access(|s| {
            // mmhub_v2_0_update_medium_grain_clock_gating, MMHUB 2.1.x: only
            // DAGB0_CNTL_MISC2_Sienna_Cichlid; light sleep returns ("There is
            // no ATCL2 in MMHUB for 2.1.x").
            if flags & cg::MC_MGCG != 0 {
                let def = s.rd(DAGB0_CNTL_MISC2)?;
                let data = if enable {
                    def & !DAGB_DISABLE_CG
                } else {
                    def | DAGB_DISABLE_CG
                };
                s.update(DAGB0_CNTL_MISC2, def, data);
            }
            // athub_v2_1_update_medium_grain_clock_gating.
            let def = s.rd(ATHUB_MISC_CNTL)?;
            let data = if enable && flags & cg::MC_MGCG != 0 {
                def | ATHUB_CG_ENABLE
            } else {
                def & !ATHUB_CG_ENABLE
            };
            s.update(ATHUB_MISC_CNTL, def, data);
            // athub_v2_1_update_medium_grain_light_sleep.
            let def = s.rd(ATHUB_MISC_CNTL)?;
            let data = if enable && flags & cg::MC_LS != 0 && flags & cg::HDP_LS != 0 {
                def | ATHUB_CG_MEM_LS_ENABLE
            } else {
                def & !ATHUB_CG_MEM_LS_ENABLE
            };
            s.update(ATHUB_MISC_CNTL, def, data);
            Ok(())
        })?
    }
    // ── navi10_ih_update_clockgating_state ──────────────────────────────
    fn ih(&mut self, enable: bool) -> Result<(), Error> {
        if !self.has(cg::IH_CG) {
            return Ok(());
        }
        self.access(|s| {
            let def = s.rd(IH_CLK_CTRL)?;
            let data = if enable {
                def & !IH_SOFT_OVERRIDES
            } else {
                def | IH_SOFT_OVERRIDES
            };
            s.update(IH_CLK_CTRL, def, data);
            Ok(())
        })?
    }
    // ── sdma_v5_2_set_clockgating_state ─────────────────────────────────
    fn sdma(&mut self, enable: bool) -> Result<(), Error> {
        let flags = self.cg_flags;
        self.access(|s| {
            // update_medium_grain_clock_gating, then _light_sleep, each over
            // both instances. Without SDMA_MGCG / SDMA_LS Linux takes the
            // "disable" branch on GATE as well.
            for clk in SDMA_CLK_CTRL {
                let def = s.rd(clk)?;
                let data = if enable && flags & cg::SDMA_MGCG != 0 {
                    def & !SDMA_SOFT_OVERRIDES
                } else {
                    def | SDMA_SOFT_OVERRIDES
                };
                s.update(clk, def, data);
            }
            for power in SDMA_POWER_CNTL {
                let def = s.rd(power)?;
                let data = if enable && flags & cg::SDMA_LS != 0 {
                    def | SDMA_MEM_POWER_OVERRIDE
                } else {
                    def & !SDMA_MEM_POWER_OVERRIDE
                };
                s.update(power, def, data);
            }
            Ok(())
        })?
    }
    // ── gfx_v10_0_update_gfx_clock_gating ───────────────────────────────
    fn gfx_cg_relevant(&self) -> bool {
        self.has(cg::GFX_CGCG | cg::GFX_MGCG | cg::GFX_3D_CGCG)
    }
    /// `amdgpu_gfx_rlc_enter_safe_mode` / `gfx_v10_0_set_safe_mode`.
    async fn enter_safe_mode(&mut self) -> Result<(), Error> {
        if self.in_safe_mode || !self.gfx_cg_relevant() {
            return Ok(());
        }
        if self.access(|s| s.rd(RLC_CNTL))?? & RLC_ENABLE_F32 == 0 {
            return Err(Error::RlcHalted);
        }
        self.access(|s| s.wr(RLC_SAFE_MODE, SAFE_MODE_CMD | 1 << SAFE_MODE_MESSAGE_SHIFT))?;
        let deadline = narf_time::Deadline::after_ms(SAFE_MODE_TIMEOUT_MS);
        loop {
            if self.access(|s| s.rd(RLC_SAFE_MODE))?? & SAFE_MODE_CMD == 0 {
                self.in_safe_mode = true;
                return Ok(());
            }
            if deadline.expired() {
                // Withdraw the request (unset_safe_mode) before failing.
                self.access(|s| s.wr(RLC_SAFE_MODE, SAFE_MODE_CMD))?;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
    }
    /// `amdgpu_gfx_rlc_exit_safe_mode` / `gfx_v10_0_unset_safe_mode`.
    fn exit_safe_mode(&mut self) -> Result<(), Error> {
        if !self.in_safe_mode {
            return Ok(());
        }
        self.access(|s| s.wr(RLC_SAFE_MODE, SAFE_MODE_CMD))?;
        self.in_safe_mode = false;
        Ok(())
    }
    async fn gfx(&mut self, enable: bool) -> Result<(), Error> {
        self.enter_safe_mode().await?;
        let flags = self.cg_flags;
        let result = self.access(|s| {
            if enable {
                // FGCG first; CGCG/CGLS after MGCG/MGLS. GC 10.3.2 takes no
                // medium-grain workaround (10.1.x only).
                fine_grain(s, flags, true)?;
                medium_grain(s, flags, true)?;
                coarse_grain_3d(s, flags, true)?;
                coarse_grain(s, flags, true)?;
            } else {
                coarse_grain(s, flags, false)?;
                coarse_grain_3d(s, flags, false)?;
                medium_grain(s, flags, false)?;
                fine_grain(s, flags, false)?;
            }
            if flags
                & (cg::GFX_MGCG | cg::GFX_CGLS | cg::GFX_CGCG | cg::GFX_3D_CGCG | cg::GFX_3D_CGLS)
                != 0
            {
                gui_idle_interrupt(s, enable)?;
            }
            Ok(())
        });
        // Linux exits safe mode unconditionally at the end.
        let exit = self.exit_safe_mode();
        result??;
        exit
    }

    async fn ip(&mut self, ip: Ip, enable: bool) -> Result<(), Error> {
        match ip {
            Ip::Common => self.common(enable),
            Ip::Gmc => self.gmc(enable),
            Ip::Ih => self.ih(enable),
            Ip::Gfx => self.gfx(enable).await,
            Ip::Sdma => self.sdma(enable),
        }
    }
    async fn set_clockgating(&mut self, gate: bool, blocks: Blocks) -> Result<(), Error> {
        let gated = match self.state {
            State::Failed => return Err(Error::Failed),
            State::Idle => Blocks::NONE,
            State::Gated(gated) => gated,
        };
        // Mark failed first: a cancelled future cannot leave a half-applied
        // transition looking clean.
        self.state = State::Failed;
        let mut order = IP_ORDER;
        if !gate {
            order.reverse();
        }
        for ip in order.into_iter().filter(|ip| blocks.contains(*ip)) {
            self.ip(ip, gate).await?;
        }
        self.state = State::Gated(if gate {
            gated.union(blocks)
        } else {
            gated.without(blocks)
        });
        Ok(())
    }
}

// ── hdp_v5_0 ────────────────────────────────────────────────────────────
/// `hdp_v5_0_update_mem_power_gating`.
fn hdp_mem_power_gating<I: Io>(s: &mut Seq<'_, I>, flags: u64, enable: bool) -> Result<(), Error> {
    if flags & (cg::HDP_LS | cg::HDP_DS | cg::HDP_SD) == 0 {
        return Ok(());
    }
    let mut clk = s.rd(HDP_CLK_CNTL)?;
    let mut power = s.rd(HDP_MEM_POWER_CTRL)?;
    // Force the IPH & RC clocks on before the mode switch.
    clk |= HDP_IPH_MEM_CLK_SOFT_OVERRIDE | HDP_RC_MEM_CLK_SOFT_OVERRIDE;
    s.wr(HDP_CLK_CNTL, clk);
    // HDP 5.0 has no dynamic mode switch: disable everything first.
    power &= !(HDP_IPH_CTRL_EN
        | HDP_IPH_LS_EN
        | HDP_IPH_DS_EN
        | HDP_IPH_SD_EN
        | HDP_RC_CTRL_EN
        | HDP_RC_LS_EN
        | HDP_RC_DS_EN
        | HDP_RC_SD_EN);
    s.wr(HDP_MEM_POWER_CTRL, power);
    if enable {
        // Only one of LS/DS/SD.
        if flags & cg::HDP_LS != 0 {
            power |= HDP_IPH_LS_EN | HDP_RC_LS_EN;
        } else if flags & cg::HDP_DS != 0 {
            power |= HDP_IPH_DS_EN | HDP_RC_DS_EN;
        } else if flags & cg::HDP_SD != 0 {
            power |= HDP_IPH_SD_EN;
            // RC must not use shut down: fall back to DS or LS.
            if flags & cg::HDP_DS != 0 {
                power |= HDP_RC_DS_EN;
            } else if flags & cg::HDP_LS != 0 {
                power |= HDP_RC_LS_EN;
            }
        }
        power |= HDP_IPH_CTRL_EN | HDP_RC_CTRL_EN;
        s.wr(HDP_MEM_POWER_CTRL, power);
    }
    // Release the IPH & RC clock overrides after the change.
    clk &= !(HDP_IPH_MEM_CLK_SOFT_OVERRIDE | HDP_RC_MEM_CLK_SOFT_OVERRIDE);
    s.wr(HDP_CLK_CNTL, clk);
    Ok(())
}
/// `hdp_v5_0_update_medium_grain_clock_gating` (unconditional write).
fn hdp_medium_grain_clock_gating<I: Io>(
    s: &mut Seq<'_, I>,
    flags: u64,
    enable: bool,
) -> Result<(), Error> {
    if flags & cg::HDP_MGCG == 0 {
        return Ok(());
    }
    let clk = s.rd(HDP_CLK_CNTL)?;
    s.wr(
        HDP_CLK_CNTL,
        if enable {
            clk & !HDP_CLK_SOFT_OVERRIDES
        } else {
            clk | HDP_CLK_SOFT_OVERRIDES
        },
    );
    Ok(())
}
/// `smuio_v11_0_6_update_rom_clock_gating` (dGPU). Without ROM_MGCG both
/// directions keep the ROM clock forced on.
fn smuio_rom_clock_gating<I: Io>(
    s: &mut Seq<'_, I>,
    flags: u64,
    enable: bool,
) -> Result<(), Error> {
    let def = s.rd(CGTT_ROM_CLK_CTRL0)?;
    let data = if enable && flags & cg::ROM_MGCG != 0 {
        def & !ROM_SOFT_OVERRIDES
    } else {
        def | ROM_SOFT_OVERRIDES
    };
    s.update(CGTT_ROM_CLK_CTRL0, def, data);
    Ok(())
}

// ── gfx_v10_0 ───────────────────────────────────────────────────────────
/// `gfx_v10_0_update_medium_grain_clock_gating`.
fn medium_grain<I: Io>(s: &mut Seq<'_, I>, flags: u64, enable: bool) -> Result<(), Error> {
    if flags & (cg::GFX_MGCG | cg::GFX_MGLS) == 0 {
        return Ok(());
    }
    if enable && flags & cg::GFX_MGCG != 0 {
        // 0 - disable some blocks' MGCG (broadcast GRBM index).
        s.wr(GRBM_GFX_INDEX, 0xe000_0000);
        s.wr(CGTT_WD_CLK_CTRL, 0xff00_0000);
        s.wr(CGTT_VGT_CLK_CTRL, 0xff00_0000);
        s.wr(CGTT_IA_CLK_CTRL, 0xff00_0000);
        // 1 - RLC_CGTT_MGCG_OVERRIDE.
        let def = s.rd(RLC_CGTT_MGCG_OVERRIDE)?;
        s.update(RLC_CGTT_MGCG_OVERRIDE, def, def & !MGCG_OVERRIDES);
        if flags & cg::GFX_MGLS != 0 {
            // 2 - RLC memory light sleep.
            if flags & cg::GFX_RLC_LS != 0 {
                let def = s.rd(RLC_MEM_SLP_CNTL)?;
                s.update(RLC_MEM_SLP_CNTL, def, def | MEM_LS_EN);
            }
            // 3 - CP memory light sleep.
            if flags & cg::GFX_CP_LS != 0 {
                let def = s.rd(CP_MEM_SLP_CNTL)?;
                s.update(CP_MEM_SLP_CNTL, def, def | MEM_LS_EN);
            }
        }
    } else {
        // 1 - MGCG_OVERRIDE.
        let def = s.rd(RLC_CGTT_MGCG_OVERRIDE)?;
        s.update(RLC_CGTT_MGCG_OVERRIDE, def, def | MGCG_OVERRIDES);
        // 2 - disable MGLS in CP.
        let data = s.rd(CP_MEM_SLP_CNTL)?;
        if data & MEM_LS_EN != 0 {
            s.wr(CP_MEM_SLP_CNTL, data & !MEM_LS_EN);
        }
        // 3 - disable MGLS in RLC.
        let data = s.rd(RLC_MEM_SLP_CNTL)?;
        if data & MEM_LS_EN != 0 {
            s.wr(RLC_MEM_SLP_CNTL, data & !MEM_LS_EN);
        }
    }
    Ok(())
}
/// RLC_CGCG_CGLS_CTRL{,_3D} enable value: threshold 0x36 with CGCG_EN, and
/// a CGLS delay of 0xF with CGLS_EN.
const fn cgcg_fsm(cgcg: bool, cgls: bool) -> u32 {
    let mut data = 0;
    if cgcg {
        data = 0x36 << CGCG_GFX_IDLE_THRESHOLD_SHIFT | CGCG_EN;
    }
    if cgls {
        data |= 0xf << CGLS_REP_COMPANSAT_DELAY_SHIFT | CGLS_EN;
    }
    data
}
/// `gfx_v10_0_update_3d_clock_gating`.
fn coarse_grain_3d<I: Io>(s: &mut Seq<'_, I>, flags: u64, enable: bool) -> Result<(), Error> {
    let (cgcg, cgls) = (flags & cg::GFX_3D_CGCG != 0, flags & cg::GFX_3D_CGLS != 0);
    if !cgcg && !cgls {
        return Ok(());
    }
    if enable {
        let def = s.rd(RLC_CGTT_MGCG_OVERRIDE)?;
        let data = if cgcg {
            def & !OVERRIDE_GFXIP_GFX3D_CG
        } else {
            def
        };
        s.update(RLC_CGTT_MGCG_OVERRIDE, def, data);
        // Enable the 3D CGCG FSM.
        let def = s.rd(RLC_CGCG_CGLS_CTRL_3D)?;
        s.update(RLC_CGCG_CGLS_CTRL_3D, def, cgcg_fsm(cgcg, cgls));
        let def = s.rd(CP_RB_WPTR_POLL_CNTL)?;
        s.update(CP_RB_WPTR_POLL_CNTL, def, WPTR_POLL_IDLE);
    } else {
        let def = s.rd(RLC_CGCG_CGLS_CTRL_3D)?;
        let mut data = def;
        if cgcg {
            data &= !CGCG_EN;
        }
        if cgls {
            data &= !CGLS_EN;
        }
        s.update(RLC_CGCG_CGLS_CTRL_3D, def, data);
    }
    Ok(())
}
/// `gfx_v10_0_update_coarse_grain_clock_gating`.
fn coarse_grain<I: Io>(s: &mut Seq<'_, I>, flags: u64, enable: bool) -> Result<(), Error> {
    let (cgcg, cgls) = (flags & cg::GFX_CGCG != 0, flags & cg::GFX_CGLS != 0);
    if !cgcg && !cgls {
        return Ok(());
    }
    if enable {
        let def = s.rd(RLC_CGTT_MGCG_OVERRIDE)?;
        let mut data = def;
        if cgcg {
            data &= !OVERRIDE_GFXIP_CGCG;
        }
        if cgls {
            data &= !OVERRIDE_GFXIP_CGLS;
        }
        s.update(RLC_CGTT_MGCG_OVERRIDE, def, data);
        let def = s.rd(RLC_CGCG_CGLS_CTRL)?;
        s.update(RLC_CGCG_CGLS_CTRL, def, cgcg_fsm(cgcg, cgls));
        let def = s.rd(CP_RB_WPTR_POLL_CNTL)?;
        s.update(CP_RB_WPTR_POLL_CNTL, def, WPTR_POLL_IDLE);
    } else {
        let def = s.rd(RLC_CGCG_CGLS_CTRL)?;
        let mut data = def;
        if cgcg {
            data &= !CGCG_EN;
        }
        if cgls {
            data &= !CGLS_EN;
        }
        s.update(RLC_CGCG_CGLS_CTRL, def, data);
    }
    Ok(())
}
/// `gfx_v10_0_update_fine_grain_clock_gating` (no-op without GFX_FGCG,
/// which navy_flounder lacks).
fn fine_grain<I: Io>(s: &mut Seq<'_, I>, flags: u64, enable: bool) -> Result<(), Error> {
    if flags & cg::GFX_FGCG == 0 {
        return Ok(());
    }
    let def = s.rd(RLC_CGTT_MGCG_OVERRIDE)?;
    let data = if enable {
        def & !OVERRIDE_GFXIP_FGCG
    } else {
        def | OVERRIDE_GFXIP_FGCG
    };
    s.update(RLC_CGTT_MGCG_OVERRIDE, def, data);
    let def = s.rd(RLC_CLK_CNTL)?;
    let data = if enable {
        def & !RLC_SRAM_CLK_GATER_OVERRIDE
    } else {
        def | RLC_SRAM_CLK_GATER_OVERRIDE
    };
    s.update(RLC_CLK_CNTL, def, data);
    Ok(())
}
/// `gfx_v10_0_enable_gui_idle_interrupt`: ME0 pipes 0 and 1
/// (`num_pipe_per_me = 2` on GC 10.3), unconditional RMW writes.
fn gui_idle_interrupt<I: Io>(s: &mut Seq<'_, I>, enable: bool) -> Result<(), Error> {
    for reg in [CP_INT_CNTL_RING0, CP_INT_CNTL_RING1] {
        let value = s.rd(reg)?;
        s.wr(
            reg,
            if enable {
                value | GUI_IDLE_INTERRUPTS
            } else {
                value & !GUI_IDLE_INTERRUPTS
            },
        );
    }
    Ok(())
}

/// Exclusive owner of the Navi22 clock-gating registers listed above.
#[derive(Debug)]
pub struct Gating {
    engine: Engine<Mmio>,
}
impl Gating {
    /// Resolve every bank; no register access.
    ///
    /// # Safety
    /// Caller exclusively owns this physical Navi22 GPU (the retained cold
    /// boot owner) with permanent mappings, and no other code writes these
    /// clock-gating registers for the owner's lifetime.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?;
        let bank = |id, version, index, last| {
            crate::amdgpu_psp_ring::bank(gpu, id, &[version], index, last).map_err(|error| {
                match error {
                    crate::amdgpu_psp_ring::Error::Invalid => Error::Invalid,
                    _ => Error::Unsupported,
                }
            })
        };
        let gc = (10, 3, 2);
        let io = Mmio {
            regs: gpu.regs,
            gc0: bank(discovery::HW_ID_GC, gc, 0, GC0_LAST)?,
            gc1: bank(discovery::HW_ID_GC, gc, 1, GC1_LAST)?,
            mmhub: bank(
                discovery::HW_ID_MMHUB,
                (2, 1, 0),
                0,
                DAGB0_CNTL_MISC2.offset,
            )?,
            athub: bank(discovery::HW_ID_ATHUB, (2, 1, 0), 0, ATHUB_MISC_CNTL.offset)?,
            hdp: bank(discovery::HW_ID_HDP, (5, 0, 3), 0, HDP_CLK_CNTL.offset)?,
            osssys: bank(discovery::HW_ID_OSSSYS, (5, 0, 3), 0, IH_CLK_CTRL.offset)?,
            smuio: bank(
                discovery::HW_ID_SMUIO,
                (11, 0, 6),
                0,
                CGTT_ROM_CLK_CTRL0.offset,
            )?,
        };
        // Both SDMA instances live on the GC bank (sdma_v5_2_get_reg_offset).
        bank(discovery::HW_ID_SDMA0, (5, 2, 2), 0, 0)?;
        Ok(Self {
            engine: Engine {
                io,
                authority,
                cg_flags: NAVY_FLOUNDER_CG,
                in_safe_mode: false,
                state: State::Idle,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// `amdgpu_device_set_cg_state(GATE|UNGATE)` over `blocks`: forward IP
    /// order to gate, reverse to ungate. A failure or cancellation leaves the
    /// owner `Failed` (registers as far as the sequence got).
    ///
    /// # Safety
    /// GC is powered: GFXOFF is disallowed (a held reference or the
    /// controller's initial count) for the whole call if `blocks` has GFX,
    /// RLC firmware runs, and the power policy admitted these blocks.
    pub async unsafe fn set_clockgating(
        &mut self,
        gate: bool,
        blocks: Blocks,
    ) -> Result<(), Error> {
        self.engine.set_clockgating(gate, blocks).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_gating_tests.rs"]
mod tests;
