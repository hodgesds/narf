//! Panel Replay fixtures on scripted sinks. Every expected byte and
//! register value is written out from drm_dp.h, intel_psr_regs.h,
//! intel_display_regs.h and the cited intel_psr.c / intel_alpm.c
//! arithmetic, not from this module's constants.

extern crate alloc;

use super::*;
use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
use crate::drm::fb_cmd::{Damage, Rect};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl Regs {
    fn get(&self, off: u64) -> u32 {
        *self.map.borrow().get(&off).unwrap_or(&0)
    }
    fn set(&self, off: u64, v: u32) {
        self.map.borrow_mut().insert(off, v);
    }
    fn log(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
}
impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        self.get(off)
    }
    fn write32(&self, off: u64, v: u32) {
        self.writes.borrow_mut().push((off, v));
        self.set(off, v);
    }
}

#[derive(Default)]
struct Sink {
    dpcd: BTreeMap<u32, u8>,
    nack: Vec<u32>,
    writes: Vec<(u32, u8)>,
}
impl AuxChannel for Sink {
    fn transact<'a>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        if self.nack.contains(&req.address) {
            return Ok(AuxResponse {
                status: AuxStatus::Nack,
                data: &reply[..0],
            });
        }
        match req.cmd {
            AuxCommand::NativeWrite => {
                for (i, b) in req.data.iter().enumerate() {
                    self.dpcd.insert(req.address + i as u32, *b);
                    self.writes.push((req.address + i as u32, *b));
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
            AuxCommand::NativeRead => {
                let n = req.data.len();
                for i in 0..n {
                    reply[1 + i] = *self.dpcd.get(&(req.address + i as u32)).unwrap_or(&0);
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[1..1 + n],
                })
            }
            _ => Err(AuxError::UnknownStatus),
        }
    }
}

/// An eDP 1.5 panel: DPCD 0x0b0 = SUPPORT | SU_SUPPORT | EARLY_TRANSPORT
/// (0x07), 0x0b1 = SU_GRANULARITY_REQUIRED with DSC decode "supported"
/// (0x20), X granularity 8 (0x0b2/0x0b3 = 08 00), Y granularity 4;
/// `DP_RECEIVER_ALPM_CAP` = ALPM_CAP | AUX_LESS_CAP (0x05); eDP rev 1.4b.
fn edp_sink() -> Sink {
    let mut sink = Sink::default();
    for (a, v) in [
        (0x0b0, 0x07),
        (0x0b1, 0x20),
        (0x0b2, 0x08),
        (0x0b3, 0x00),
        (0x0b4, 0x04),
        (0x02e, 0x05),
        (0x700, 0x05),
    ] {
        sink.dpcd.insert(a, v);
    }
    sink
}

/// A DP 2.0 monitor: SUPPORT | SU_SUPPORT (0x03), no required
/// granularity (Linux's 4x4 default).
fn dp_sink() -> Sink {
    let mut sink = Sink::default();
    sink.dpcd.insert(0x0b0, 0x03);
    sink
}

/// 1920x1080@60: 148_500 kHz, htotal 2200, vtotal 1125.
fn timing_1080() -> crate::intel_gpu_dsb::Timing {
    crate::intel_gpu_dsb::Timing {
        clock: 148_500,
        width: 1920,
        height: 1080,
        htotal: 2200,
        vtotal: 1125,
        flags: 0,
    }
}

/// `hsw_write_infoframe(DP_SDP_VSC)` of the replay VSC SDP on the
/// transcoder at `base` (`HSW_TVIDEO_DIP_CTL` = base + 0x200, VSC data at
/// base + 0x320): the dwords of HB0..HB3 = 00 07 06 10, DB0..DB3 = 01 00 00
/// 01 and zeros, between the enable off and VSC_HSW (bit 20) |
/// VSC_DIP_HW_DATA_SW_HEA (2 << 25).
fn vsc_writes(base: u64) -> Vec<(u64, u32)> {
    let mut writes = alloc::vec![(base + 0x200, 0), (base + 0x320, 0x1006_0700), (base + 0x324, 0x0100_0001)];
    for i in 2..9 {
        writes.push((base + 0x320 + 4 * i, 0));
    }
    writes.push((base + 0x200, 0x0410_0000));
    writes
}

fn edp_stream() -> Stream {
    Stream {
        display_ver: 20,
        pipe: 0,
        port: 0,
        port_clock: 810_000,
        lanes: 4,
        timing: timing_1080(),
        dsc: false,
        uhbr: false,
        hdcp: false,
        as_sdp_v2: false,
        edp_rev: 0x05,
        fw_sync_quirk: false,
        sel_fetch: true,
    }
}

fn smoke_panel_replay_caps_and_compute_follow_linux() -> TestResult {
    let mut sink = edp_sink();
    let caps = match Caps::read(&mut sink, true, false) {
        Ok(caps) => caps,
        Err(_) => return TestResult::Fail("the eDP 1.5 sink must report Panel Replay"),
    };
    if !caps.su
        || caps.su_w_granularity != 8
        || caps.su_y_granularity != 4
        || caps.dsc != DscSupport::SelectiveUpdate
    {
        return TestResult::Fail("caps must decode SU granularity 8x4 and DSC in SU");
    }
    let config = match compute(&caps, &edp_stream(), None) {
        Ok(config) => config,
        Err(_) => return TestResult::Fail("eDP Panel Replay must qualify on display 20"),
    };
    // HBR3 at 1080p60 (`intel_alpm.c`): io/fast wake ceil(42 * 148500 /
    // 2200000) = 3 -> the 7-line floor; ALPM entry check 2 + ceil(5 us)
    // = 3; AUX-less wake 72 us (12000 + 470 + 130 + 50000 + 29 * 311 ns)
    // -> ceil(72 * 148500 / 2200000) = 5 lines; silence 130 ns at 810 MHz
    // = 105 symbols; LFPS half cycle 470 * 810 / 1000 / 20 = 19.
    let want = Alpm {
        io_wake_lines: 7,
        fast_wake_lines: 7,
        check_entry_lines: 3,
        aux_less_wake_lines: 5,
        silence_period_sym_clocks: 105,
        lfps_half_cycle_num_of_syms: 19,
    };
    if config.alpm != Some(want) || !config.su || config.sdp_prior_scanline || !config.edp {
        return TestResult::Fail("the eDP ALPM state and SU must be Linux's");
    }
    // Typed refusals: eDP below display 20, eDP off pipes A/B, HDCP,
    // 128b/132b, no AUX-less ALPM, MST, and the AS SDP need.
    let refused = |stream: Stream, caps: &Caps| compute(caps, &stream, None).err();
    if refused(
        Stream {
            display_ver: 14,
            ..edp_stream()
        },
        &caps,
    ) != Some(Refusal::SourceUnsupported)
        || refused(
            Stream {
                pipe: 2,
                ..edp_stream()
            },
            &caps,
        ) != Some(Refusal::Pipe)
        || refused(
            Stream {
                hdcp: true,
                ..edp_stream()
            },
            &caps,
        ) != Some(Refusal::Hdcp)
        || refused(
            Stream {
                uhbr: true,
                ..edp_stream()
            },
            &caps,
        ) != Some(Refusal::Uhbr)
    {
        return TestResult::Fail("eDP Panel Replay must refuse what Linux refuses");
    }
    // An AS SDP sink: intel_dp_compute_as_sdp at the fixed 1125-line
    // vtotal (FIXED_VTOTAL, coasting at vmax: 0x0b1 keeps async video
    // timing), and PR_ALPM_CTL = POSITION_T1 | AS_SDP_TRANSMISSION_IN_ACTIVE_
    // DISABLE (0x11; no link-off capability in 0x0b1 bit 7).
    match compute(
        &caps,
        &Stream {
            as_sdp_v2: true,
            ..edp_stream()
        },
        None,
    ) {
        Ok(c) if c.pr_alpm_ctl == Some(0x11)
            && c.as_sdp
                == Some(AsSdp {
                    mode: 1,
                    vtotal: 1125,
                    target_rr: 0,
                    target_rr_divider: false,
                    coasting_vtotal: 1125,
                }) => {}
        _ => return TestResult::Fail("an AS SDP sink must get Linux's AS SDP and PR_ALPM_CTL"),
    }
    let mut no_aux_less = edp_sink();
    no_aux_less.dpcd.insert(0x02e, 0x01);
    if Caps::read(&mut no_aux_less, true, false) != Err(Refusal::NoAuxLessAlpm)
        || Caps::read(&mut edp_sink(), true, true) != Err(Refusal::Mst)
    {
        return TestResult::Fail("eDP needs AUX-less ALPM and no MST");
    }
    // DP on display 14: 4x4 granularity by default and Wa_14015648006's
    // input required.
    let dp = match Caps::read(&mut dp_sink(), false, false) {
        Ok(caps) if caps.su_w_granularity == 4 && caps.su_y_granularity == 4 => caps,
        _ => return TestResult::Fail("a DP sink without required granularity takes 4x4"),
    };
    let dp_stream = Stream {
        display_ver: 14,
        pipe: 1,
        port: 3,
        port_clock: 270_000,
        edp_rev: 0,
        ..edp_stream()
    };
    if compute(&dp, &dp_stream, None) != Err(Refusal::WmLevelUnknown)
        || compute(&dp, &dp_stream, Some(false)).map(|c| (c.alpm, c.su)) != Ok((None, true))
    {
        return TestResult::Fail("DP Panel Replay on display 14 needs no ALPM, only the WA input");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_panel_replay_caps_and_compute_follow_linux
);

/// Enable, activate, exit, selective update and disable on the owned
/// display-20 eDP, in `intel_psr_enable_locked` / `dg2_activate_panel_replay`
/// / `intel_psr_exit` / `intel_psr_disable_locked` order.
fn smoke_panel_replay_edp_enable_exit_and_selective_update() -> TestResult {
    let regs = Regs::default();
    let mut sink = edp_sink();
    regs.set(0x46430, 1 << 23);
    // Without the pre-training enable, the link does not qualify.
    let caps = Caps::read(&mut sink, true, false).expect("caps");
    let config = compute(&caps, &edp_stream(), None).expect("config");
    if PanelReplay::enable(&regs, &mut sink, config) != Err(Refusal::NotEnabledAtTraining)
        || !regs.log().is_empty()
    {
        return TestResult::Fail("a link trained without the PR enable must be refused untouched");
    }
    if enable_before_training(&mut sink, 20, true, false, false)
        || !enable_before_training(&mut sink, 20, true, false, true)
        || sink.writes != [(0x1b0, 0x01)]
    {
        return TestResult::Fail("only the opted-in pre-training step writes PANEL_REPLAY_CONFIG");
    }
    sink.writes.clear();
    let mut pr = match PanelReplay::enable(&regs, &mut sink, config) {
        Ok(pr) => pr,
        Err(_) => return TestResult::Fail("enable must succeed after the pre-training enable"),
    };
    // intel_alpm_enable_sink (ENABLE | LOCK_ERROR_IRQ_HPD | MODE_AUX_LESS),
    // PANEL_REPLAY_CONFIG = ENABLE | VSC_SDP_CRC | UNRECOVERABLE_ERROR |
    // RFB_STORAGE_ERROR | ACTIVE_FRAME_CRC_ERROR | SU_ENABLE (0x7b),
    // CONFIG2 = CRC_VERIFICATION, CONFIG3 = T1, then DP_SET_POWER D0.
    if sink.writes
        != [
            (0x116, 0x07),
            (0x1b0, 0x7b),
            (0x1b1, 0x02),
            (0x11a, 0x00),
            (0x600, 0x01),
        ]
    {
        return TestResult::Fail("the sink conversation must be Linux's");
    }
    // Source: PSR_DEBUG(A) = HPD | MEMUP | LPSP, PSR_IMR all but
    // TGL_PSR_ERROR, Wa bit cleared on display 20, PORT_ALPM_CTL(A) =
    // AUX_LESS | swing setup 15 | silence 105, PORT_ALPM_LFPS_CTL(A) =
    // cycles 10 (field 3) and 19-symbol half cycles, ALPM_CTL(A) = ENABLE |
    // AUX_LESS | entry check 3 | AUX-less wake 5.
    // First the replay VSC SDP (hsw_write_infoframe on HSW_TVIDEO_DIP_CTL(A)
    // 0x60200: VSC enable off, HB0..HB3 = 00 07 06 10 and DB0 = DB3 = 1 at
    // HSW_TVIDEO_DIP_VSC_DATA(A) 0x60320.., then VIDEO_DIP_ENABLE_VSC_HSW |
    // VSC_DIP_HW_DATA_SW_HEA).
    let mut want = vsc_writes(0x60000);
    want.extend_from_slice(&[
        (0x60860, 0x0e00_0000),
        (0x60814, 0xffff_fffb),
        (0x46430, 0),
        (0x16fa2c, 0x80f0_0069),
        (0x16fa30, 0x0313_1313),
        (0x60950, 0xc003_0005),
    ]);
    if regs.log() != want || pr.active() {
        return TestResult::Fail("the source enable must be Linux's, inactive until resumed");
    }
    regs.writes.borrow_mut().clear();
    if pr.resume(&regs) != Ok(true) {
        return TestResult::Fail("an idle replay must activate");
    }
    // dg2_activate_panel_replay: EDP_PSR2_CTL (no region ET, no SDP line)
    // = 0, PSR2_MAN_TRK_CTL continuous full frame, TRANS_DP2_CTL(A) PR on.
    if regs.log() != [(0x60900, 0), (0x60910, 1 << 13), (0x600a0, 1 << 30)] || !pr.active() {
        return TestResult::Fail("activation must write PSR2_CTL, MAN_TRK and TRANS_DP2_CTL");
    }
    // Exit before a frame change, then the SU of a damaged band.
    regs.writes.borrow_mut().clear();
    if pr.exit(&regs).is_err() || regs.log() != [(0x600a0, 0)] {
        return TestResult::Fail("exit must clear TRANS_DP2_PANEL_REPLAY_ENABLE only");
    }
    let Some(su) = pr.psr2(1920, 1080) else {
        return TestResult::Fail("selective update must run over Panel Replay");
    };
    let src = Rect::new(0, 0, 1920, 1080);
    let damage = Damage::Clips(alloc::vec![Rect::new(100, 101, 300, 203)]);
    let sf = crate::intel_gpu_psr::sel_fetch_update(
        &su,
        &crate::intel_gpu_psr::SuCommit {
            damage: &damage,
            old_src: src,
            src,
            pipe_supported: true,
            cursor: None,
        },
        (None, None),
    );
    // Y granularity 4: rows 101..203 align to 100..204; MAN_TRK (ADL-P
    // layout) = SF_PARTIAL | start 100 << 16 | end 203.
    if sf.full_update || sf.su != (100, 204) || sf.man_trk_ctl != (1 << 31) | (100 << 16) | 203 {
        return TestResult::Fail("the SU area must align to the sink's 4-line granularity");
    }
    regs.writes.borrow_mut().clear();
    pr.program_sel_fetch(&regs, 1920, &sf);
    if regs.log()
        != [
            (0x70894, 100 << 16),
            (0x7089c, 100 << 16),
            (0x70898, (103 << 16) | 1919),
            (0x60910, (1 << 31) | (100 << 16) | 203),
            (0x70890, 1 << 31),
        ]
    {
        return TestResult::Fail("the SU commit must program SEL_FETCH and MAN_TRK on Pipe A");
    }
    if pr.resume(&regs) != Ok(true) || !pr.active() {
        return TestResult::Fail("replay must re-arm after the update");
    }
    // Disable: exit, idle wait on EDP_PSR2_STATUS, the Wa bit, then
    // intel_alpm_disable clears ALPM_ENABLE and LOBF_ENABLE (AUX_LESS
    // stays as Linux leaves it).
    regs.writes.borrow_mut().clear();
    regs.set(0x46430, 1 << 23);
    if pr.disable(&regs, 1).is_err()
        || regs.log()
            != [
                (0x600a0, 0),
                (0x46430, 0),
                (0x60950, 0x4003_0005),
                (0x60200, 0x0400_0000),
            ]
        || pr.active()
        || sink.writes.len() != 5
    {
        return TestResult::Fail("disable must leave the sink configured and ALPM off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_panel_replay_edp_enable_exit_and_selective_update
);

/// External DP on display 14, transcoder B: no ALPM, no DP_SET_POWER,
/// PSR_DEBUG(B) = MASK_HPD, the Wa bit for Pipe B (bit 24) from the
/// watermark input, and SRD_STATUS(B) as the idle witness.
fn smoke_panel_replay_external_dp_on_transcoder_b() -> TestResult {
    let regs = Regs::default();
    let mut sink = dp_sink();
    let caps = Caps::read(&mut sink, false, false).expect("caps");
    let stream = Stream {
        display_ver: 14,
        pipe: 1,
        port: 3,
        port_clock: 270_000,
        edp_rev: 0,
        ..edp_stream()
    };
    let config = compute(&caps, &stream, Some(true)).expect("config");
    if !enable_before_training(&mut sink, 14, false, false, true) {
        return TestResult::Fail("the DP sink must take the pre-training enable");
    }
    // A busy SRD_STATUS(B) keeps replay inactive at resume.
    regs.set(0x61840, 1 << 29);
    sink.writes.clear();
    let mut pr = match PanelReplay::enable(&regs, &mut sink, config) {
        Ok(pr) => pr,
        Err(_) => return TestResult::Fail("DP Panel Replay must enable on transcoder B"),
    };
    let mut want = vsc_writes(0x61000);
    want.extend_from_slice(&[
        (0x61860, 1 << 25),
        (0x61814, 0xffff_fffb),
        (0x46430, 1 << 24),
    ]);
    if sink.writes != [(0x1b0, 0x7b), (0x1b1, 0x02), (0x11a, 0x00)] || regs.log() != want {
        return TestResult::Fail("DP replay takes no ALPM, no SET_POWER and the Pipe-B Wa bit");
    }
    if pr.resume(&regs) != Ok(false) || pr.active() {
        return TestResult::Fail("replay must wait for SRD_STATUS(B) idle");
    }
    regs.set(0x61840, 0);
    regs.writes.borrow_mut().clear();
    if pr.resume(&regs) != Ok(true) || regs.log() != [(0x61910, 1 << 13), (0x610a0, 1 << 30)] {
        return TestResult::Fail("DP activation writes MAN_TRK(B) and TRANS_DP2_CTL(B) only");
    }
    regs.writes.borrow_mut().clear();
    if pr.disable(&regs, 1).is_err()
        || regs.log() != [(0x610a0, 0), (0x46430, 0), (0x61200, 0x0400_0000)]
    {
        return TestResult::Fail("DP disable clears the enable, the Wa bit and the VSC SDP");
    }
    // An inherited replay enable refuses before any write.
    let inherited = Regs::default();
    inherited.set(0x610a0, 1 << 30);
    if PanelReplay::enable(&inherited, &mut sink, config) != Err(Refusal::Inherited)
        || !inherited.log().is_empty()
    {
        return TestResult::Fail("an inherited TRANS_DP2_CTL enable must be refused untouched");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_panel_replay_external_dp_on_transcoder_b
);

/// The Nova display-35 eDP gets no Panel Replay here, so DC3CO keeps its
/// trigger refusal; a replay with the AS SDP would be a trigger that still
/// needs the CMTG.
fn smoke_panel_replay_leaves_nova_dc3co_refused() -> TestResult {
    use crate::intel_gpu_dc_states::{xe3plpd_dc3co_refusal, Dc3coRefusal, Dc3coState};
    if source_supported(35, true) != Err(Refusal::SourceUnsupported)
        || source_supported(35, false) != Err(Refusal::SourceUnsupported)
        || compute(
            &Caps::read(&mut edp_sink(), true, false).expect("caps"),
            &Stream {
                display_ver: 35,
                ..edp_stream()
            },
            None,
        ) != Err(Refusal::SourceUnsupported)
    {
        return TestResult::Fail("display 35 Panel Replay must be refused typed");
    }
    if xe3plpd_dc3co_refusal(&Dc3coState::OWNED_NOVA_PANEL) != Dc3coRefusal::NoTrigger
        || xe3plpd_dc3co_refusal(&Dc3coState {
            panel_replay_as_sdp: true,
            ..Dc3coState::OWNED_NOVA_PANEL
        }) != Dc3coRefusal::CmtgUnowned
    {
        return TestResult::Fail("Nova DC3CO stays refused: no trigger, and no CMTG for one");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_panel_replay_leaves_nova_dc3co_refused
);

/// The replay stream's SDPs (Linux 7.4-rc4 `intel_dp.c`, `drm_dp_helper.c`,
/// `intel_hdmi.c`, `intel_alpm.c`): the AS SDP and VSC SDP bytes, which
/// sinks need the AS SDP, and an eDP AS SDP sink's enable, which refuses a
/// transcoder without AS SDP timing before any write.
fn smoke_panel_replay_as_sdp_follows_intel_dp() -> TestResult {
    // intel_dp_as_sdp_pack of FIXED_VTOTAL at 1125 lines, coasting 1125:
    // HB 00 22 02 09; DB0 = 01, DB1/2 = 65 04, DB7/8 = 65 04.
    let words = |b: [u8; DP_SDP_BYTES]| -> Vec<u32> {
        b.chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect()
    };
    let as_sdp = words(pack_as_sdp(&as_sdp_fixed(1125, true)));
    let no_coast = words(pack_as_sdp(&as_sdp_fixed(1125, false)));
    if as_sdp != [0x0902_2200, 0x0004_6501, 0x6500_0000, 0x0000_0004, 0, 0, 0, 0, 0]
        || no_coast != [0x0902_2200, 0x0004_6501, 0, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("the AS SDP must pack as intel_dp_as_sdp_pack does");
    }
    if words(pack_replay_vsc_sdp()) != [0x1006_0700, 0x0100_0001, 0, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("the replay VSC SDP must pack as drm_dp_vsc_sdp_pack does");
    }
    // PR_ALPM_CTL: a sink with link off after the AS SDP and no async video
    // timing in PR (0x0b1 = 0x88) -> POSITION_T1 | ALLOW_LINK_OFF (0x41).
    let mut dpcd = [0u8; DP_PANEL_REPLAY_CAP_SIZE];
    dpcd[0] = 0x07;
    dpcd[1] = 0x88;
    if pr_alpm_ctl_value(&Caps::parse(dpcd, true)) != 0x41 {
        return TestResult::Fail("PR_ALPM_CTL must follow intel_alpm_configure_pr_as_sdp");
    }
    // intel_dp_needs_as_sdp: (DPCD rev, 0x2214, 0x005, 0x0b1, eDP) -> needed.
    let cases: [(u8, u8, u8, u8, bool, bool); 7] = [
        (0x14, 0x01, 0x00, 0x00, true, true),
        (0x14, 0x00, 0x00, 0x00, true, false),
        (0x12, 0x01, 0x00, 0x00, true, false),
        (0x14, 0x05, 0x00, 0x00, false, true),
        (0x14, 0x01, 0x00, 0x00, false, false),
        (0x14, 0x01, 0x00, 0x08, false, true),
        (0x14, 0x05, 0x01, 0x00, false, false),
    ];
    for (rev, rx, ports, cap, edp, want) in cases {
        let mut sink = Sink::default();
        sink.dpcd.insert(0x2214, rx);
        sink.dpcd.insert(0x005, ports);
        let mut dpcd = [0u8; DP_PANEL_REPLAY_CAP_SIZE];
        dpcd[0] = 0x01;
        dpcd[1] = cap;
        if as_sdp_needed(&mut sink, rev, &Caps::parse(dpcd, edp)) != want {
            return TestResult::Fail("which sinks take the AS SDP must be Linux's");
        }
    }
    // The eDP enable with the AS SDP: no TRANS_VRR_VSYNC(A) refuses before
    // any write; with it, the VSC SDP, the AS SDP at
    // ADL_TVIDEO_DIP_AS_SDP_DATA(A) 0x60484.. with VIDEO_DIP_ENABLE_AS_ADL
    // (bit 23), and PR_ALPM_CTL(A) 0x60948 before ALPM_CTL.
    let mut sink = edp_sink();
    let caps = Caps::read(&mut sink, true, false).expect("caps");
    let config = compute(
        &caps,
        &Stream {
            as_sdp_v2: true,
            ..edp_stream()
        },
        None,
    )
    .expect("config");
    if !enable_before_training(&mut sink, 20, true, false, true) {
        return TestResult::Fail("the pre-training enable must be written");
    }
    sink.writes.clear();
    let regs = Regs::default();
    if PanelReplay::enable(&regs, &mut sink, config) != Err(Refusal::AsSdpTiming)
        || !regs.log().is_empty()
        || !sink.writes.is_empty()
    {
        return TestResult::Fail("no AS SDP timing must refuse untouched");
    }
    regs.set(0x60078, (5 << 16) | 10);
    let mut pr = match PanelReplay::enable(&regs, &mut sink, config) {
        Ok(pr) => pr,
        Err(_) => return TestResult::Fail("the AS SDP sink must enable with its timing"),
    };
    let mut want = vsc_writes(0x60000);
    want.push((0x60200, 0x0410_0000));
    for (i, w) in as_sdp.iter().enumerate() {
        want.push((0x60484 + 4 * i as u64, *w));
    }
    want.extend_from_slice(&[
        (0x60200, 0x0490_0000),
        (0x60860, 0x0e00_0000),
        (0x60814, 0xffff_fffb),
        (0x46430, 0),
        (0x16fa2c, 0x80f0_0069),
        (0x16fa30, 0x0313_1313),
        (0x60948, 0x11),
        (0x60950, 0xc003_0005),
    ]);
    if regs.log() != want {
        return TestResult::Fail("the AS SDP replay enable must be Linux's, SDPs first");
    }
    regs.writes.borrow_mut().clear();
    if pr.disable(&regs, 1).is_err() || regs.log().last() != Some(&(0x60200, 0x0400_0000)) {
        return TestResult::Fail("disable must clear the VSC and AS SDP enables");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_panel_replay_as_sdp_follows_intel_dp
);
