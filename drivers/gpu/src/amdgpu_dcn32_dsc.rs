//! DCN 3.2 Display Stream Compression — Navi31/32/33, 4 engines.
//!
//! The engine is the DCN 2.0 DSC engine (`dsc2_construct`), the same one
//! DCN 3.0 carries, and its register layout is identical on 3.2.0
//! (`dcn_3_2_0_offset.h`) except two registers: DOMAIN16_PG_CONFIG is
//! 0x0089 (not 0x00a1) and DC_IP_REQUEST_CNTL is 0x0095 (not 0x00b2).
//! Those two are parameterized on the shared [`Dsc`] via
//! `for_profile(Dcn320/Dcn321)`; everything else — the TOP/CIF/CONFIG/PPS
//! registers, the DSCRM forward, the OPTC and DIO halves — is the shared
//! engine verbatim. The one behavioural difference is the maximum image
//! width: 6016 pixels per line (`dcn3_2_ip.max_dsc_input_width`), not
//! 5184, so [`plan`] uses [`plan_for`] with 6016.
//!
//! Sequencing follows Linux's `link_set_dpms_on` as for DCN 3.0 (see the
//! shared engine's docs): power the domain, `start` the engine from the
//! OPP, set the OPTC and stream-encoder DSC halves, FEC on after the link
//! trains, DSC on in the sink, then the PPS SDP.

use crate::amdgpu_dcn30_dsc::{self as dsc, Dsc};
use crate::amdgpu_dcn30_takeover::Regs;
use crate::amdgpu_dcn_profile::Profile;
use crate::amdgpu_dml::Timing;
use crate::amdgpu_dsc::{DscConfig, DscRegisters};
use crate::amdgpu_navi22_modeset::Error;

/// `dcn3_2_ip.max_dsc_input_width`, via `dcn32_resource.c`'s
/// `res_cap_dcn32` (4 engines, `max_image_width` 6016).
pub const MAX_IMAGE_WIDTH: u32 = 6016;
/// `dcn32_resource.c` `res_cap_dcn32.num_dsc` — one engine per pipe.
pub const DSC_UNITS: u8 = 4;

/// The DCN 3.2 DSC owner: the shared DCN 2.0 engine bound to a 3.2 profile.
#[derive(Debug)]
pub struct Dsc32 {
    dsc: Dsc,
}

impl Dsc32 {
    /// Bind the DSC engines at DCN base index 2. Refuses any profile that
    /// is not DCN 3.2 — the power registers differ on every other DCN.
    pub(crate) fn bind(regs: Regs, dcn2: u64, profile: Profile) -> Result<Self, Error> {
        if !matches!(profile, Profile::Dcn320 | Profile::Dcn321) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            dsc: Dsc::new(regs, dcn2).for_profile(profile),
        })
    }

    /// `dsc2_validate_stream` / `link_set_dsc_on_stream`'s per-engine
    /// configuration for a 3.2 engine: one engine takes at most four slices
    /// and 6016 pixels.
    pub fn plan(t: &Timing, config: &DscConfig, odm: bool) -> Result<dsc::Plan, Error> {
        dsc::plan_for(t, config, odm, MAX_IMAGE_WIDTH)
    }

    /// `apply_dsc_policy_for_stream` for an 8-bpc RGB DP SST stream (shared
    /// with DCN 3.0: DSC only when the uncompressed stream exceeds the
    /// trained link, at the highest bpp that fits, and only with FEC).
    pub fn select(
        t: &Timing,
        dsc_caps: &[u8; 16],
        fec_caps: u8,
        link_kbps: u32,
    ) -> Option<DscConfig> {
        dsc::select(t, dsc_caps, fec_caps, link_kbps)
    }

    /// `dcn20_dsc_pg_control` on the 3.2 power registers (DOMAIN16 + n at
    /// 0x0089, IP requests at 0x0095).
    pub async fn power(&mut self, dsc: u8, on: bool) -> Result<bool, Error> {
        self.dsc.power(dsc, on).await
    }

    /// `dsc2_set_config` then `dsc2_enable` for engine `dsc` fed by OPP
    /// `opp`.
    pub fn start(&mut self, dsc: u8, opp: u8, r: &DscRegisters) -> Result<(), Error> {
        self.dsc.start(dsc, opp, r)
    }

    /// `dsc2_disconnect` then `dsc2_disable`.
    pub fn stop(&mut self, dsc: u8) -> Result<(), Error> {
        self.dsc.stop(dsc)
    }

    /// `optc3_set_dsc_config` on OTG `otg`. `None` disables.
    pub fn optc(&mut self, otg: u8, r: Option<&DscRegisters>) -> Result<(), Error> {
        self.dsc.optc(otg, r)
    }

    /// `enc3_dp_set_dsc_config` on frontend `fe`. `None` disables.
    pub fn encoder(&mut self, fe: u8, r: Option<&DscRegisters>) -> Result<(), Error> {
        self.dsc.encoder(fe, r)
    }

    /// `enc3_dp_set_dsc_pps_info_packet(enable)` on frontend `fe`.
    pub async fn pps(&mut self, fe: u8, packed: Option<&[u8; 128]>) -> Result<(), Error> {
        self.dsc.pps(fe, packed).await
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn uhd() -> Timing {
        Timing {
            pixel_clock_khz: 533_250,
            h_active: 3840,
            h_total: 4000,
            h_front_porch: 48,
            h_sync_width: 32,
            v_active: 2160,
            v_total: 2222,
            v_front_porch: 3,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    fn cfg() -> DscConfig {
        DscConfig {
            slices_h: 4,
            slices_v: 20,
            bpp_x16: 192,
            block_pred: true,
            linebuf_depth: 13,
            version_minor: 2,
            ycbcr422_simple: false,
            frl: None,
            bpc: 8,
        }
    }

    fn dcn32_dsc_power_uses_32_registers() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::{d2, Bench};
        let bench = Bench::new();
        // Forbid the DCN 3.0 power registers: the 3.2 owner must not touch
        // 0x00a1 / 0x00b2 at all.
        bench.model.0.lock().forbidden.push(d2(0xa1)..=d2(0xb2));
        let regs = Regs {
            window: crate::amdgpu_reg_window::Window::new(bench.gpu.regs),
            authority: narf_capabilities::Cap::bootstrap(),
        };
        let mut dsc = match Dsc32::bind(regs, u64::from(d2(0)) * 4, Profile::Dcn320) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("DCN32 DSC bind refused Dcn320"),
        };
        for index in 0..DSC_UNITS {
            for on in [true, false] {
                if narf_scheduler::block_on_spin(dsc.power(index, on)) != Ok(true) {
                    return TestResult::Fail("DCN32 DSC power operation");
                }
            }
        }
        // Four engines, not six: engine 4 is out of range on 3.2. (The
        // forbidden 3.0 registers above prove the 3.2 owner never touches
        // 0x00a1 / 0x00b2: the model asserts on any forbidden access.)
        if narf_scheduler::block_on_spin(dsc.power(4, true)) != Err(Error::Invalid)
            || dsc.stop(4) != Err(Error::Invalid)
            || dsc.optc(4, None) != Err(Error::Invalid)
            || dsc.encoder(4, None) != Err(Error::Invalid)
        {
            return TestResult::Fail("DCN32 DSC capacity");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dsc", dcn32_dsc_power_uses_32_registers);

    fn dcn32_dsc_plan_allows_6016() -> TestResult {
        // 5760 wide is past DCN 2.0's 5184 but inside 3.2's 6016.
        let wide = Timing {
            h_active: 5760,
            h_total: 6000,
            ..uhd()
        };
        if Dsc32::plan(&wide, &cfg(), false).is_err() {
            return TestResult::Fail("DCN32 DSC refused a 5760-wide picture");
        }
        let too_wide = Timing {
            h_active: 6017,
            h_total: 6257,
            ..uhd()
        };
        if Dsc32::plan(&too_wide, &cfg(), false).is_ok() {
            return TestResult::Fail("DCN32 DSC admitted a 6017-wide picture");
        }
        // Five slices per engine are past every DCN's four.
        if Dsc32::plan(
            &uhd(),
            &DscConfig {
                slices_h: 5,
                ..cfg()
            },
            false,
        )
        .is_ok()
        {
            return TestResult::Fail("DCN32 DSC admitted five slices");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dsc", dcn32_dsc_plan_allows_6016);

    fn dcn32_dsc_bind_refuses_non_32() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::{d2, Bench};
        let bench = Bench::new();
        let regs = Regs {
            window: crate::amdgpu_reg_window::Window::new(bench.gpu.regs),
            authority: narf_capabilities::Cap::bootstrap(),
        };
        if Dsc32::bind(regs, u64::from(d2(0)) * 4, Profile::Dcn303).is_ok() {
            return TestResult::Fail("DCN32 DSC bound a DCN 3.0.3 profile");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-dsc", dcn32_dsc_bind_refuses_non_32);
}
