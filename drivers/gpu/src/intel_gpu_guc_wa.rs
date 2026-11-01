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
}
