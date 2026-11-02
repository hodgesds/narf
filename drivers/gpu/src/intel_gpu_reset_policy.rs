//! GuC isolated-engine-reset saves, from MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//!
//! xe_guc_ads.c::guc_mmio_regset_write saves hwe.reg_sr (xe_wa.c engine_was,
//! xe_tuning.c engine_tunings, xe_hw_engine.c hw_engine_setup_default_state,
//! xe_reg_whitelist.c whitelist_apply_to_hwe)
//! plus ring state, RCU/CCS mode and Gen12 Wa1607983814. GT-only workarounds
//! and LRC-restored registers belong to different reset/context lifetimes.

use crate::{
    intel_gpu_engine::{Engine, EngineSet},
    intel_gpu_gt::{Gen12Platform, GtPlatform},
};
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisterSave {
    pub(crate) offset: u32,
    pub(crate) flags: u32,
}

/// Immutable identity/fuse/steering facts sampled by RegisterInit under the
/// same wake ownership as the applied engine workarounds. ADS never resamples
/// a selector or a fuse after GuC reset and never guesses instance zero.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ResetPolicy {
    platform: GtPlatform,
    device: u16,
    graphics: u16,
    dss_flags: u32,
    compute: u8,
    engines: EngineSet,
    discontiguous: bool,
}

impl ResetPolicy {
    pub(crate) fn new(
        platform: GtPlatform,
        device: u16,
        graphics: u16,
        dss: u32,
        compute: u8,
        engines: EngineSet,
        discontiguous: bool,
    ) -> Option<Self> {
        let group = (dss >> 23) & 127;
        let instance = (dss >> 16) & 127;
        if GtPlatform::from_pci(0x8086, device) != Some(platform)
            || !engines.contains(Engine::Rcs0)
            || compute & !15 != 0
            || dss & !(0x40000000 | 127 << 23 | 127 << 16) != 0
            || dss & 0x40000000 == 0
            || group > 15
            || instance
                > if platform.is_gen12() || platform == GtPlatform::Alchemist {
                    7
                } else {
                    15
                }
        {
            return None;
        }
        Some(Self {
            platform,
            device,
            graphics,
            dss_flags: 2 | group << 12 | instance << 20,
            compute,
            engines,
            discontiguous,
        })
    }

    pub(crate) fn matches(self, platform: GtPlatform, engines: EngineSet) -> bool {
        self.platform == platform && self.engines == engines
    }

    pub(crate) fn device_id(self) -> u16 {
        self.device
    }

    /// Sorted and unique, as the source reg_sr xarray. Register values are
    /// captured by GuC at reset time; flags encode masked access and the
    /// cached, nonterminated DSS read target (guc_capture_abi.h:53-58).
    pub(crate) fn registers(self, engine: Engine) -> Option<Vec<RegisterSave>> {
        if !self.engines.contains(engine) {
            return None;
        }
        let base = engine.base();
        let mut registers = Vec::new();
        registers.try_reserve_exact(64).ok()?;
        let mut add = |offset, flags| registers.push(RegisterSave { offset, flags });
        // RING_MODE is not XE_REG_OPTION_MASKED in xe_engine_regs.h:160.
        for offset in [0x29c, 0x80, 0xa8] {
            add(base + offset, 0);
        }
        add(base + 0xc4, 1); // RING_CMD_CCTL_default_MOCS, every engine.
                             // whitelist_apply_to_hwe adds every installed grant to hwe.reg_sr.
                             // NARF owns all12 slots, including the explicit NOPID deny fill, so
                             // preserve that whole verified policy across an isolated reset.
        for slot in 0..12 {
            add(base + 0x4d0 + slot * 4, 0);
        }
        if self.platform == GtPlatform::Battlemage {
            // Wa16021639441 + Priority_Mem_Read, and Wa16023105232,
            // use ENGINE_BASE for each physical RCS/CCS/COPY instance.
            add(base + 0xd4, 1);
            add(base + 0x50, 1);
        }
        // RCS0 is the first render/compute engine and therefore owns all
        // shared engine-reset-domain state. Never duplicate it on each CCS.
        if engine == Engine::Rcs0 {
            add(0x14800, 1); // xe_guc_ads.c extra_regs: unconditional RCU_MODE.
            if self.compute.count_ones() > 1 {
                add(0x14804, 1); // CCS_MODE is enabled by physical fuse count.
            }
            let mcr = self.dss_flags;
            match self.platform {
                GtPlatform::Gen12(family) => {
                    add(0xb004, 0); // L3 Hashing Mask tuning.
                    add(0x20a0, 0);
                    add(0xe4f4, mcr | 1);
                    add(0xe48c, mcr | 1);
                    add(0x20ec, 1);
                    add(0xe18c, mcr | 1);
                    add(0x20e0, 1);
                    if matches!(family, Gen12Platform::TigerLake | Gen12Platform::AlderLakeP) {
                        add(0x2050, 1);
                    }
                    for index in 0..32 {
                        add(0xb020 + index * 4, 0); // Wa1607983814.
                    }
                }
                GtPlatform::Alchemist => {
                    add(0x20ec, 1);
                    add(0xe7cc, mcr);
                    add(0xe7c8, mcr);
                    add(0x83b4, 1);
                    add(0xe48c, mcr | 1);
                    add(0xe18c, mcr | 1);
                    add(0xe4f4, mcr | 1);
                    add(0xe5f0, mcr | 1);
                    if matches!(
                        self.device,
                        0x56a5
                            | 0x56a6
                            | 0x56b0
                            | 0x56b1
                            | 0x56ba
                            | 0x56bb
                            | 0x56bc
                            | 0x56bd
                            | 0x5693
                            | 0x5694
                            | 0x5695
                    ) {
                        // Wa14012342262 disables host read verification, not
                        // the source ADS save (xe_wa.c:419-427).
                        add(0xe420, mcr | 1);
                    }
                }
                GtPlatform::Integrated(_) => {
                    add(0xe49c, mcr | 1);
                    if self.graphics <= 1271 {
                        add(0xe5f0, mcr | 1);
                    }
                    add(0xe4f4, mcr | 1);
                    add(0xe18c, mcr | 1);
                }
                GtPlatform::Battlemage => {
                    add(0xe48c, mcr | 1);
                    add(0xe7cc, mcr);
                    add(0xe4f0, mcr | 1);
                    add(0xe49c, mcr | 1);
                    add(0xe7c8, mcr);
                    add(0xe194, mcr | 1);
                    add(0xe4c4, mcr | 1);
                    if self.discontiguous {
                        add(0xe5f4, mcr | 1);
                    }
                    add(0xe530, mcr); // AnyHit null-query tuning.
                }
            }
        }
        registers.sort_unstable_by_key(|entry| entry.offset);
        registers.dedup();
        Some(registers)
    }
}
