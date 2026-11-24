//! DP-to-HDMI 2.1 protocol converters (PCON): HDMI FRL link training
//! over DPCD, as i915 drives it (`intel_dp_check_frl_training`,
//! `intel_dp_pcon_start_frl_training`, `intel_dp_pcon_set_tmds_mode`)
//! through the drm helpers (`drm_dp_get_pcon_max_frl_bw`,
//! `drm_dp_pcon_frl_prepare` / `_configure_1` / `_configure_2` /
//! `_enable`, `drm_dp_pcon_hdmi_link_active` / `_link_mode`,
//! `drm_dp_pcon_enc_is_dsc_1_2`).
//!
//! i915 has no native HDMI FRL: its FRL path is the PCON's. The source
//! keeps driving DP; the PCON trains its HDMI side in FRL when it offers
//! source-control mode and the sink is HDMI 2.1 (its HF-VSDB declares a
//! max FRL rate), and falls back to TMDS when FRL training fails.

use crate::dp_aux::{AuxChannel, AuxError};

/// `DP_DOWNSTREAMPORT_PRESENT` and its branch / detailed-caps bits.
pub const DOWNSTREAMPORT_PRESENT: u32 = 0x005;
const DWN_STRM_PORT_PRESENT: u8 = 1 << 0;
const DETAILED_CAP_INFO_AVAILABLE: u8 = 1 << 4;
/// `DP_DOWNSTREAM_PORT_0`: port 0's four detailed-cap bytes.
pub const DOWNSTREAM_PORT_0: u32 = 0x080;
const DS_PORT_TYPE_MASK: u8 = 7;
const DS_PORT_TYPE_HDMI: u8 = 3;
/// Port-cap byte 2: `DP_PCON_MAX_FRL_BW` (bits 4:2) and
/// `DP_PCON_SOURCE_CTL_MODE` (bit 5).
const PCON_MAX_FRL_BW: u8 = 7 << 2;
const PCON_SOURCE_CTL_MODE: u8 = 1 << 5;
/// `DP_PCON_DSC_ENCODER` (0x92..=0x9E); the version byte is 0x93.
pub const PCON_DSC_ENCODER: u32 = 0x092;
const PCON_DSC_ENCODER_CAP_SIZE: usize = 0xD;
/// `DP_PCON_HDMI_LINK_CONFIG_1` and its fields.
pub const PCON_HDMI_LINK_CONFIG_1: u32 = 0x305A;
const ENABLE_SOURCE_CTL_MODE: u8 = 1 << 3;
const ENABLE_CONCURRENT_LINK: u8 = 1 << 4;
const ENABLE_LINK_FRL_MODE: u8 = 1 << 5;
const ENABLE_HDMI_LINK: u8 = 1 << 7;
/// `DP_PCON_HDMI_LINK_CONFIG_2`: the FRL bandwidth mask and
/// `DP_PCON_FRL_LINK_TRAIN_EXTENDED` (bit 6; normal training is 0).
pub const PCON_HDMI_LINK_CONFIG_2: u32 = 0x305B;
const FRL_LINK_TRAIN_EXTENDED: u8 = 1 << 6;
/// `DP_PCON_HDMI_TX_LINK_STATUS`: link active (0), FRL ready (1).
pub const PCON_HDMI_TX_LINK_STATUS: u32 = 0x303B;
const HDMI_TX_LINK_ACTIVE: u8 = 1 << 0;
const FRL_READY: u8 = 1 << 1;
/// `DP_PCON_HDMI_POST_FRL_STATUS`: link mode (0 = TMDS, 1 = FRL) and the
/// trained bandwidth (bits 6:1).
pub const PCON_HDMI_POST_FRL_STATUS: u32 = 0x3036;
const HDMI_LINK_MODE_FRL: u8 = 1 << 0;
const HDMI_FRL_TRAINED_BW: u8 = 0x3F << 1;

/// `TIMEOUT_FRL_READY_MS` and `TIMEOUT_HDMI_LINK_ACTIVE_MS`, polled every
/// millisecond.
const FRL_READY_POLLS: u32 = 500;
const HDMI_LINK_ACTIVE_POLLS: u32 = 1000;

/// The PCON's FRL facts: `drm_dp_get_pcon_max_frl_bw` over downstream
/// port 0, `DP_PCON_SOURCE_CTL_MODE`, and whether its DSC encoder is 1.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PconCaps {
    /// The PCON's max FRL bandwidth in Gbps (0, 9, 18, 24, 32, 40, 48).
    pub max_frl_gbps: u8,
    /// The PCON offers source-control mode (required for FRL training).
    pub source_ctl_mode: bool,
    /// `drm_dp_pcon_enc_is_dsc_1_2`.
    pub dsc_1_2: bool,
}

/// `drm_dp_get_pcon_max_frl_bw`: a DP 1.1+ branch with detailed cap info
/// whose port 0 is HDMI reports its max FRL bandwidth in port-cap byte 2.
pub fn max_frl_bw(dpcd_rev: u8, downstream_present: u8, port_cap: &[u8; 4]) -> u8 {
    if downstream_present & DWN_STRM_PORT_PRESENT == 0
        || dpcd_rev < 0x11
        || downstream_present & DETAILED_CAP_INFO_AVAILABLE == 0
        || port_cap[0] & DS_PORT_TYPE_MASK != DS_PORT_TYPE_HDMI
    {
        return 0;
    }
    match (port_cap[2] & PCON_MAX_FRL_BW) >> 2 {
        1 => 9,
        2 => 18,
        3 => 24,
        4 => 32,
        5 => 40,
        6 => 48,
        _ => 0,
    }
}

/// Read the branch's PCON caps (`intel_dp_get_dpcd`'s downstream ports and
/// `intel_dp_get_pcon_dsc_cap`). `None` when the sink is not a branch.
pub fn read_pcon_caps<A: AuxChannel + ?Sized>(
    aux: &mut A,
    dpcd_rev: u8,
) -> Result<Option<PconCaps>, AuxError> {
    let mut present = [0u8; 1];
    aux.dpcd_read(DOWNSTREAMPORT_PRESENT, &mut present)?;
    if present[0] & DWN_STRM_PORT_PRESENT == 0 {
        return Ok(None);
    }
    let mut port = [0u8; 4];
    aux.dpcd_read(DOWNSTREAM_PORT_0, &mut port)?;
    let mut dsc = [0u8; PCON_DSC_ENCODER_CAP_SIZE];
    aux.dpcd_read(PCON_DSC_ENCODER, &mut dsc)?;
    let version = dsc[1];
    Ok(Some(PconCaps {
        max_frl_gbps: max_frl_bw(dpcd_rev, present[0], &port),
        source_ctl_mode: port[2] & PCON_SOURCE_CTL_MODE != 0,
        dsc_1_2: version & 0xF == 1 && version >> 4 == 2,
    }))
}

/// `drm_get_max_frl_rate` as lanes × per-lane Gbps: the HF-VSDB's 4-bit
/// max FRL rate code.
pub const fn frl_rate_gbps(code: u8) -> u8 {
    match code {
        1 => 9,
        2 => 18,
        3 => 24,
        4 => 32,
        5 => 40,
        6 => 48,
        7 => 64,
        8 => 80,
        9 => 96,
        _ => 0,
    }
}

/// `intel_dp_hdmi_sink_max_frl`: the sink's DSC max FRL rate bounds the
/// link only when the PCON has a DSC 1.2 encoder.
pub fn sink_max_frl_gbps(max_frl: u8, dsc_max_frl: u8, pcon: &PconCaps) -> u8 {
    if pcon.dsc_1_2 && dsc_max_frl != 0 {
        max_frl.min(dsc_max_frl)
    } else {
        max_frl
    }
}

/// `intel_dp_pcon_set_frl_mask`: the one `DP_PCON_FRL_BW_MASK_*` bit for
/// a rate.
const fn frl_mask(gbps: u8) -> u8 {
    match gbps {
        48 => 1 << 5,
        40 => 1 << 4,
        32 => 1 << 3,
        24 => 1 << 2,
        18 => 1 << 1,
        9 => 1 << 0,
        _ => 0,
    }
}

/// `intel_dp_pcon_get_frl_mask`: the highest rate a trained mask names.
const fn frl_mask_gbps(mask: u8) -> u8 {
    const GBPS: [u8; 6] = [9, 18, 24, 32, 40, 48];
    let mut i = GBPS.len();
    while i > 0 {
        i -= 1;
        if mask & (1 << i) != 0 {
            return GBPS[i];
        }
    }
    0
}

/// `drm_dp_pcon_frl_configure_1`'s `DP_PCON_ENABLE_MAX_BW_*` code.
const fn max_bw_code(gbps: u8) -> Option<u8> {
    match gbps {
        0 => Some(0),
        9 => Some(1),
        18 => Some(2),
        24 => Some(3),
        32 => Some(4),
        40 => Some(5),
        48 => Some(6),
        _ => None,
    }
}

fn read_byte<A: AuxChannel + ?Sized>(aux: &mut A, addr: u32) -> Result<u8, AuxError> {
    let mut b = [0u8; 1];
    aux.dpcd_read(addr, &mut b)?;
    Ok(b[0])
}

fn write_byte<A: AuxChannel + ?Sized>(aux: &mut A, addr: u32, v: u8) -> Result<(), AuxError> {
    aux.dpcd_write(addr, &[v])
}

/// `intel_dp_pcon_is_frl_trained`: the HDMI link is active in FRL mode at
/// no less than `max_mask`; returns the trained mask.
fn frl_trained<A: AuxChannel + ?Sized>(aux: &mut A, max_mask: u8) -> Option<u8> {
    if read_byte(aux, PCON_HDMI_TX_LINK_STATUS).ok()? & HDMI_TX_LINK_ACTIVE == 0 {
        return None;
    }
    let post = read_byte(aux, PCON_HDMI_POST_FRL_STATUS).ok()?;
    let mask = (post & HDMI_FRL_TRAINED_BW) >> 1;
    (post & HDMI_LINK_MODE_FRL != 0 && mask >= max_mask).then_some(mask)
}

/// Why FRL training stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlError {
    /// No common FRL rate (`max_frl_bw <= 0`).
    NoRate,
    /// The PCON never reported FRL ready.
    NotReady,
    /// The PCON is in autonomous mode (`drm_dp_pcon_frl_enable`).
    Autonomous,
    /// The HDMI link never came up in FRL at the requested rate.
    NotTrained,
    /// A DPCD transfer failed.
    Aux(AuxError),
}

impl From<AuxError> for FrlError {
    fn from(e: AuxError) -> Self {
        FrlError::Aux(e)
    }
}

/// `intel_dp_pcon_start_frl_training`: train at the lower of the PCON's
/// and the sink's max FRL rate, sequential link, normal training. Returns
/// the trained rate in Gbps. `delay_us` waits between polls.
pub fn start_frl_training<A: AuxChannel + ?Sized>(
    aux: &mut A,
    pcon_max_gbps: u8,
    sink_max_gbps: u8,
    mut delay_us: impl FnMut(u32),
) -> Result<u8, FrlError> {
    let max = pcon_max_gbps.min(sink_max_gbps);
    if max == 0 {
        return Err(FrlError::NoRate);
    }
    let max_mask = frl_mask(max);
    if let Some(mask) = frl_trained(aux, max_mask) {
        return Ok(frl_mask_gbps(mask));
    }
    // drm_dp_pcon_frl_prepare(aux, false).
    write_byte(
        aux,
        PCON_HDMI_LINK_CONFIG_1,
        ENABLE_SOURCE_CTL_MODE | ENABLE_LINK_FRL_MODE,
    )?;
    let mut ready = false;
    for _ in 0..FRL_READY_POLLS {
        if read_byte(aux, PCON_HDMI_TX_LINK_STATUS).is_ok_and(|s| s & FRL_READY != 0) {
            ready = true;
            break;
        }
        delay_us(1000);
    }
    if !ready {
        return Err(FrlError::NotReady);
    }
    // drm_dp_pcon_frl_configure_1(aux, max, DP_PCON_ENABLE_SEQUENTIAL_LINK).
    let code = max_bw_code(max).ok_or(FrlError::NoRate)?;
    let config = read_byte(aux, PCON_HDMI_LINK_CONFIG_1)? & !ENABLE_CONCURRENT_LINK;
    write_byte(aux, PCON_HDMI_LINK_CONFIG_1, config | code)?;
    // drm_dp_pcon_frl_configure_2(aux, mask, DP_PCON_FRL_LINK_TRAIN_NORMAL).
    write_byte(
        aux,
        PCON_HDMI_LINK_CONFIG_2,
        max_mask & !FRL_LINK_TRAIN_EXTENDED,
    )?;
    // drm_dp_pcon_frl_enable.
    let config = read_byte(aux, PCON_HDMI_LINK_CONFIG_1)?;
    if config & ENABLE_SOURCE_CTL_MODE == 0 {
        return Err(FrlError::Autonomous);
    }
    write_byte(aux, PCON_HDMI_LINK_CONFIG_1, config | ENABLE_HDMI_LINK)?;
    for _ in 0..HDMI_LINK_ACTIVE_POLLS {
        if let Some(mask) = frl_trained(aux, max_mask) {
            return Ok(frl_mask_gbps(mask));
        }
        delay_us(1000);
    }
    Err(FrlError::NotTrained)
}

/// `intel_dp_pcon_set_tmds_mode`: source-control mode, then the HDMI link
/// enabled in TMDS.
pub fn set_tmds_mode<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<(), AuxError> {
    write_byte(aux, PCON_HDMI_LINK_CONFIG_1, ENABLE_SOURCE_CTL_MODE)?;
    write_byte(
        aux,
        PCON_HDMI_LINK_CONFIG_1,
        ENABLE_SOURCE_CTL_MODE | ENABLE_HDMI_LINK,
    )
}

/// The HDMI side a PCON ended up driving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PconLink {
    /// No FRL attempt: not a source-control PCON, or not an HDMI 2.1 sink.
    Untouched,
    /// FRL trained at this many Gbps.
    Frl(u8),
    /// FRL failed and the PCON runs TMDS.
    Tmds,
    /// FRL failed and the PCON could not be set to TMDS either.
    Failed,
}

/// `intel_dp_check_frl_training`: train FRL on a source-control PCON
/// driving an HDMI 2.1 sink (`intel_dp_is_hdmi_2_1_sink`: an HDMI sink
/// with a nonzero max FRL rate); on failure fall back to TMDS and check
/// the PCON's link mode.
pub fn check_frl_training<A: AuxChannel + ?Sized>(
    aux: &mut A,
    pcon: &PconCaps,
    hdmi_sink: bool,
    sink_max_gbps: u8,
    delay_us: impl FnMut(u32),
) -> PconLink {
    if !pcon.source_ctl_mode || !hdmi_sink || sink_max_gbps == 0 {
        return PconLink::Untouched;
    }
    match start_frl_training(aux, pcon.max_frl_gbps, sink_max_gbps, delay_us) {
        Ok(gbps) => PconLink::Frl(gbps),
        Err(_) => {
            let tmds = set_tmds_mode(aux).is_ok()
                && read_byte(aux, PCON_HDMI_POST_FRL_STATUS)
                    .is_ok_and(|s| s & HDMI_LINK_MODE_FRL == 0);
            if tmds {
                PconLink::Tmds
            } else {
                PconLink::Failed
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! A PCON model written from the VESA DP-HDMI 2.1 PCON register map
    //! (DPCD 0x3036/0x303B/0x305A/0x305B), independent of the code above.
    extern crate alloc;

    use super::*;
    use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Pcon {
        regs: BTreeMap<u32, u8>,
        writes: Vec<(u32, u8)>,
        /// FRL-ready reads to answer before reporting ready.
        ready_after: u32,
        /// Link-status reads after HDMI_LINK enable before the link is up;
        /// `u32::MAX` never trains.
        train_after: u32,
        /// The trained-bandwidth mask the PCON reports once up.
        trained_mask: u8,
        status_reads: u32,
    }

    impl Pcon {
        fn new(train_after: u32, trained_mask: u8) -> Self {
            Self {
                regs: BTreeMap::new(),
                writes: Vec::new(),
                ready_after: 3,
                train_after,
                trained_mask,
                status_reads: 0,
            }
        }
        fn reg(&self, addr: u32) -> u8 {
            self.regs.get(&addr).copied().unwrap_or(0)
        }
        fn read(&mut self, addr: u32) -> u8 {
            let config = self.reg(PCON_HDMI_LINK_CONFIG_1);
            if addr == PCON_HDMI_TX_LINK_STATUS {
                self.status_reads += 1;
                let mut v = 0;
                // FRL ready: bit 1 once FRL mode is selected.
                if config & 0x20 != 0 && self.status_reads > self.ready_after {
                    v |= 0x02;
                }
                // Link active: bit 0 once the HDMI link is enabled and the
                // PCON trained (FRL) or immediately (TMDS).
                if config & 0x80 != 0 {
                    let frl = config & 0x20 != 0;
                    if !frl || self.status_reads > self.train_after {
                        v |= 0x01;
                    }
                }
                return v;
            }
            if addr == PCON_HDMI_POST_FRL_STATUS {
                let config = self.reg(PCON_HDMI_LINK_CONFIG_1);
                let up = config & 0xA0 == 0xA0 && self.status_reads > self.train_after;
                return if up { 1 | (self.trained_mask << 1) } else { 0 };
            }
            self.reg(addr)
        }
    }

    impl AuxChannel for Pcon {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeRead => {
                    let n = req.data.len();
                    reply[0] = (AuxStatus::Ack as u8) << 4;
                    for i in 0..n {
                        reply[1 + i] = self.read(req.address + i as u32);
                    }
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply[1..1 + n],
                    })
                }
                AuxCommand::NativeWrite => {
                    for (i, &b) in req.data.iter().enumerate() {
                        let addr = req.address + i as u32;
                        self.writes.push((addr, b));
                        self.regs.insert(addr, b);
                    }
                    reply[0] = (AuxStatus::Ack as u8) << 4;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply[1..1],
                    })
                }
                _ => Err(AuxError::Nacked),
            }
        }
    }

    const SRC_CTL_48G: PconCaps = PconCaps {
        max_frl_gbps: 48,
        source_ctl_mode: true,
        dsc_1_2: false,
    };

    /// `drm_dp_get_pcon_max_frl_bw`, `DP_PCON_SOURCE_CTL_MODE` and
    /// `drm_dp_pcon_enc_is_dsc_1_2` from the branch's DPCD.
    fn smoke_pcon_caps() -> TestResult {
        let hdmi_48 = [3, 0, (6 << 2) | (1 << 5), 0];
        if max_frl_bw(0x14, 0x11, &hdmi_48) != 48
            || max_frl_bw(0x14, 0x10, &hdmi_48) != 0
            || max_frl_bw(0x14, 0x01, &hdmi_48) != 0
            || max_frl_bw(0x10, 0x11, &hdmi_48) != 0
            || max_frl_bw(0x14, 0x11, &[0, 0, 6 << 2, 0]) != 0
        {
            return TestResult::Fail("the PCON max FRL needs a detailed HDMI port on DP 1.1+");
        }
        let mut pcon = Pcon::new(0, 0);
        pcon.regs.insert(DOWNSTREAMPORT_PRESENT, 0x11);
        for (i, b) in hdmi_48.iter().enumerate() {
            pcon.regs.insert(DOWNSTREAM_PORT_0 + i as u32, *b);
        }
        pcon.regs.insert(PCON_DSC_ENCODER + 1, 0x21);
        let want = PconCaps {
            max_frl_gbps: 48,
            source_ctl_mode: true,
            dsc_1_2: true,
        };
        if read_pcon_caps(&mut pcon, 0x14) != Ok(Some(want)) {
            return TestResult::Fail("PCON caps must decode port 0 and the DSC version");
        }
        let mut sst = Pcon::new(0, 0);
        if read_pcon_caps(&mut sst, 0x14) != Ok(None) {
            return TestResult::Fail("a non-branch sink has no PCON caps");
        }
        if sink_max_frl_gbps(48, 24, &want) != 24 || sink_max_frl_gbps(48, 24, &SRC_CTL_48G) != 48 {
            return TestResult::Fail("the DSC FRL cap applies only with a DSC 1.2 encoder");
        }
        if frl_rate_gbps(6) != 48 || frl_rate_gbps(1) != 9 || frl_rate_gbps(0) != 0 {
            return TestResult::Fail("drm_get_max_frl_rate is lanes x rate");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dp_pcon", smoke_pcon_caps);

    /// `intel_dp_pcon_start_frl_training`: prepare, wait for FRL ready,
    /// configure the lower of the two rates (sequential link, normal
    /// training), enable, wait for the FRL link at that rate.
    fn smoke_pcon_frl_training() -> TestResult {
        let mut pcon = Pcon::new(10, 1 << 4);
        let mut polls = 0;
        let got = check_frl_training(&mut pcon, &SRC_CTL_48G, true, 40, |_| polls += 1);
        if got != PconLink::Frl(40) {
            return TestResult::Fail("FRL must train at the sink's 40 Gbps");
        }
        // CONFIG_1: SRC_CTL|FRL_MODE, then + MAX_BW_40 (5), CONFIG_2: the
        // 40G mask bit, then CONFIG_1 + HDMI_LINK.
        let want = alloc::vec![
            (PCON_HDMI_LINK_CONFIG_1, 0x28),
            (PCON_HDMI_LINK_CONFIG_1, 0x2D),
            (PCON_HDMI_LINK_CONFIG_2, 0x10),
            (PCON_HDMI_LINK_CONFIG_1, 0xAD),
        ];
        if pcon.writes != want || polls == 0 {
            return TestResult::Fail("the FRL sequence must follow the drm helpers");
        }
        // A PCON already up in FRL at the rate is left alone.
        let mut up = Pcon::new(0, 1 << 4);
        up.regs.insert(PCON_HDMI_LINK_CONFIG_1, 0xAD);
        if check_frl_training(&mut up, &SRC_CTL_48G, true, 40, |_| {}) != PconLink::Frl(40)
            || !up.writes.is_empty()
        {
            return TestResult::Fail("a trained PCON must not be retrained");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dp_pcon", smoke_pcon_frl_training);

    /// `intel_dp_check_frl_training`: no attempt without source-control
    /// mode or an HDMI 2.1 sink; a PCON that never trains falls back to
    /// TMDS after the 1 s link-active window.
    fn smoke_pcon_frl_fallback() -> TestResult {
        for (caps, hdmi, sink) in [
            (
                PconCaps {
                    source_ctl_mode: false,
                    ..SRC_CTL_48G
                },
                true,
                48,
            ),
            (SRC_CTL_48G, false, 48),
            (SRC_CTL_48G, true, 0),
        ] {
            let mut pcon = Pcon::new(0, 1 << 5);
            if check_frl_training(&mut pcon, &caps, hdmi, sink, |_| {}) != PconLink::Untouched
                || !pcon.writes.is_empty()
            {
                return TestResult::Fail("FRL needs source-control mode and an HDMI 2.1 sink");
            }
        }
        let mut pcon = Pcon::new(u32::MAX, 0);
        let mut polls = 0u32;
        let got = check_frl_training(&mut pcon, &SRC_CTL_48G, true, 48, |_| polls += 1);
        if got != PconLink::Tmds {
            return TestResult::Fail("an untrainable PCON must fall back to TMDS");
        }
        let tail: Vec<_> = pcon.writes.iter().rev().take(2).rev().copied().collect();
        if tail
            != alloc::vec![
                (PCON_HDMI_LINK_CONFIG_1, 0x08),
                (PCON_HDMI_LINK_CONFIG_1, 0x88)
            ]
            || polls < HDMI_LINK_ACTIVE_POLLS
        {
            return TestResult::Fail("the TMDS fallback must follow the 1 s FRL window");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dp_pcon", smoke_pcon_frl_fallback);
}
