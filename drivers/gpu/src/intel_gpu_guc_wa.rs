//! GuC boot-parameter and ADS workarounds for the admitted graphics PF/RCS0.
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_guc.c,
//! xe_guc_ads.c, xe_wa_oob.rules, xe_guc_fwif.h and guc_klvs_abi.h.

use crate::intel_gpu_gt::{GraphicsIp, GtPlatform};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuCWorkarounds {
    pub ip: GraphicsIp,
    pub flags: u32,
    pub klvs: &'static [u32],
}

impl GuCWorkarounds {
    /// Only RCS0 is advertised in this owner's ADS. Modern CCS engines must
    /// add DUAL_QUEUE when admitted; a compute DSS fuse is not an engine mask.
    pub(crate) fn for_rcs(platform: GtPlatform, device: u16, ip: GraphicsIp) -> Self {
        let (flags, klvs): (_, &'static [u32]) = match platform {
            // POLLCS + PRE_PARSER. No CCS, TSC or XeHP register-state WA.
            GtPlatform::Gen12(_) => (0x44000, &[0x900b0000]),
            GtPlatform::Alchemist => {
                let isolation = matches!(
                    device,
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
                );
                // HOLD_CCS_SWITCHOUT, DUAL_QUEUE, PRE_PARSER, TSC check;
                // G11 additionally requires CONTEXT_ISOLATION.
                (
                    0x00424800 | if isolation { 0x8000 } else { 0 },
                    &[0x90020000, 0x900b0000],
                )
            }
            _ if platform.is_ptl() && ip.version == 3000 && ip.step < 4 => {
                (0, &[0x900a0000, 0x90080001, 0xc40, 0x90090000, 0x900b0000])
            }
            _ if platform.is_ptl() => (0, &[0x90080001, 0xc40, 0x90090000, 0x900b0000]),
            _ if platform.is_lnl() => (
                0,
                &[
                    0x90050000, 0x90070000, 0x90080001, 0xc40, 0x90090000, 0x900b0000,
                ],
            ),
            GtPlatform::Integrated(_) => {
                let hold = ip.version <= 1271 && ip.step < 4;
                (
                    0x00400000 | if hold { 0x20000 } else { 0 },
                    &[0x90020000, 0x900b0000],
                )
            }
            GtPlatform::Battlemage if ip.version == 2001 => {
                (0, &[0x90050000, 0x90070000, 0x90090000, 0x900b0000])
            }
            GtPlatform::Battlemage => (0, &[0x90090000, 0x900b0000]),
        };
        // All admitted firmware baselines exceed the 70.44 gate on 0x900b.
        Self { ip, flags, klvs }
    }

    /// Standalone Xe_LPM+ 13.00 media GuC (MTL/Arrow GT1). xe_rtp.c never
    /// matches GRAPHICS_VERSION rules on a standalone media GT, so GT0's
    /// HOLD_CCS_SWITCHOUT/DUAL_QUEUE/POLLCS/PRE_PARSER choices do not apply.
    /// xe_guc.c::guc_ctl_wa_flags: Wa_14018913170 (MEDIA_VERSION(1300)) sets
    /// GUC_WA_ENABLE_TSC_CHECK_ON_RC6 (bit 22); the media GT has no CCS for
    /// needs_wa_dual_queue. xe_guc_ads.c::guc_waklv_init: Wa_16021333562
    /// (MEDIA_VERSION(1300)) -> BLOCK_INTERRUPTS_WHEN_MGSR_BLOCKED (0x9002)
    /// and Wa_16026508708 (MEDIA_VERSION_RANGE(1300, 3000), firmware at least
    /// 70.44; MTL requires 70.53) -> RESET_BB_STACK_PTR_ON_VF_SWITCH (0x900b).
    /// `ip` records the media IP for this role's reload identity check.
    pub(crate) fn for_media(
        platform: GtPlatform,
        ip: crate::intel_gpu_gt::media::MediaIp,
    ) -> Option<Self> {
        if !crate::intel_gpu_gt::media::profile_eligible(platform) || ip.version != 1300 {
            return None;
        }
        Some(Self {
            ip: GraphicsIp {
                version: ip.version,
                step: ip.step,
            },
            flags: 1 << 22,
            klvs: &[0x90020000, 0x900b0000],
        })
    }
}
