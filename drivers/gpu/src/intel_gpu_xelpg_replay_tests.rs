//! External-route Panel Replay fixtures. Every expected register, DPCD
//! byte and frontbuffer bit is written out from `intel_psr_regs.h`,
//! `intel_display_regs.h`, `intel_cursor_regs.h`, `intel_frontbuffer.h`,
//! `drm_dp.h` and the cited `intel_psr.c` control flow (Linux 7.4-rc4), not
//! from this module's constants.

extern crate alloc;

use super::*;
use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
use crate::intel_gpu_xe2lpd::DisplayIp;
use crate::intel_gpu_xelpg::XeLpgPort;
use crate::intel_gpu_xelpg_external::tests::{edid_1024, fb_for, ExtFake, Sink as RouteSink};
use crate::intel_gpu_xelpg_external::{
    ExternalDisplayProfile, MtlDisplay, MtlExternalService, ServiceOutcome,
};
use crate::intel_gpu_xelpg_hpd::{LiveMode, MtlHpdEvent, MtlHpdKind, MtlHpdPin};
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
    fn set(&self, off: u64, v: u32) {
        self.map.borrow_mut().insert(off, v);
    }
    fn take_log(&self) -> Vec<(u64, u32)> {
        core::mem::take(&mut *self.writes.borrow_mut())
    }
}
impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        *self.map.borrow().get(&off).unwrap_or(&0)
    }
    fn write32(&self, off: u64, v: u32) {
        self.writes.borrow_mut().push((off, v));
        self.set(off, v);
    }
}

#[derive(Default)]
struct Sink {
    dpcd: BTreeMap<u32, u8>,
}
impl AuxChannel for Sink {
    fn transact<'a>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        match req.cmd {
            AuxCommand::NativeWrite => {
                for (i, b) in req.data.iter().enumerate() {
                    self.dpcd.insert(req.address + i as u32, *b);
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

/// `TRANS_DP2_CTL(B)` (0x600a0 + 0x1000), `TRANS_DP2_PANEL_REPLAY_ENABLE`.
const DP2_B: u64 = 0x610a0;
const PR_ENABLE: u32 = 1 << 30;
/// `PSR2_MAN_TRK_CTL(B)` and `ADLP_PSR2_MAN_TRK_CTL_SF_CONTINUOS_FULL_FRAME`.
const MAN_TRK_B: u64 = 0x61910;
const CFF: u32 = 1 << 13;
/// `EDP_PSR_STATUS(B)` (SRD_STATUS, DP replay's idle witness) and a
/// non-idle state.
const SRD_STATUS_B: u64 = 0x61840;
const SRD_BUSY: u32 = 1 << 29;
/// `CURSURFLIVE(PIPE_B)`: `_CURASURFLIVE` 0x700ac moved by
/// `TGL_CURSOR_OFFSETS` (0x71080 - 0x70080).
const CURSURFLIVE_B: u64 = 0x710ac;
/// `INTEL_FRONTBUFFER(PIPE_B, PLANE_PRIMARY)` = BIT(0 + 8 * 1).
const PRIMARY_B: u32 = 0x100;
/// `INTEL_FRONTBUFFER(PIPE_A, PLANE_PRIMARY)`.
const PRIMARY_A: u32 = 0x1;

/// A DP 2.0 sink answering `DP_PANEL_REPLAY_SUPPORT` only (0x0b0 = 0x01),
/// enabled before training, and a full-frame replay on transcoder B.
fn dp_replay(display_ver: u16, regs: &Regs) -> Option<ExtReplay> {
    let mut sink = Sink::default();
    sink.dpcd.insert(0x0b0, 0x01);
    let caps = pr::Caps::read(&mut sink, false, false).ok()?;
    let stream = pr::Stream {
        display_ver,
        pipe: 1,
        port: 0,
        port_clock: 540_000,
        lanes: 4,
        timing: crate::intel_gpu_dsb::Timing {
            clock: 148_500,
            width: 1920,
            height: 1080,
            htotal: 2200,
            vtotal: 1125,
            flags: 0,
        },
        dsc: false,
        uhbr: false,
        hdcp: false,
        as_sdp_v2: false,
        edp_rev: 0,
        fw_sync_quirk: false,
        sel_fetch: false,
    };
    let config = pr::compute(&caps, &stream, Some(false)).ok()?;
    if !pr::enable_before_training(&mut sink, display_ver, false, false, true) {
        return None;
    }
    let replay = PanelReplay::enable(regs, &mut sink, config).ok()?;
    let mut ext = ExtReplay::new(replay, XeLpgPort::Tc1, 1);
    ext.activate(regs).ok()?;
    regs.take_log();
    Some(ext)
}

/// `intel_psr_flush` / `intel_psr_invalidate` / `intel_psr_work` /
/// `intel_psr_pause` / `intel_psr_resume` on a display-30 DP replay: the
/// pipe filter, `_psr_flush_handle`'s exit on display 20+, the re-arm, the
/// work's 50 ms idle bound, flips, busy bits and the pause counter.
fn smoke_ext_replay_frontbuffer_follows_intel_psr_flush() -> TestResult {
    if frontbuffer(1, PLANE_PRIMARY) != PRIMARY_B
        || frontbuffer(0, PLANE_PRIMARY) != PRIMARY_A
        || frontbuffer_all_mask(1) != 0xff00
        || cursurflive(1) != CURSURFLIVE_B
    {
        return TestResult::Fail("frontbuffer bits and CURSURFLIVE must be Linux's");
    }
    let regs = Regs::default();
    let Some(mut ext) = dp_replay(30, &regs) else {
        return TestResult::Fail("DP replay must enable and activate on display 30");
    };
    // Another pipe's bits are filtered out.
    if ext.flush(&regs, PRIMARY_A, Origin::Dirtyfb).is_err()
        || !regs.take_log().is_empty()
        || ext.work_queued()
        || !ext.replay().active()
    {
        return TestResult::Fail("a flush of pipe A must not touch the pipe-B replay");
    }
    // Display 20+: intel_psr_exit, then the work is queued.
    if ext.flush(&regs, PRIMARY_B, Origin::Dirtyfb).is_err()
        || regs.take_log() != [(DP2_B, 0)]
        || ext.replay().active()
        || !ext.work_queued()
    {
        return TestResult::Fail("a display-30 flush must exit replay and queue the re-arm");
    }
    // The work's idle wait: busy now, then past its 50 ms bound.
    regs.set(SRD_STATUS_B, SRD_BUSY);
    if ext.run_work(&regs, 1_000) != Ok(WorkStep::Waiting)
        || ext.run_work(&regs, 1_000 + 49_999_999) != Ok(WorkStep::Waiting)
        || ext.run_work(&regs, 1_000 + 50_000_000) != Ok(WorkStep::TimedOut)
        || ext.work_queued()
        || ext.replay().active()
        || !regs.take_log().is_empty()
    {
        return TestResult::Fail("the re-arm must give up after 50 ms without idle");
    }
    // The next flush queues it again; an idle status re-activates.
    regs.set(SRD_STATUS_B, 0);
    if ext.flush(&regs, PRIMARY_B, Origin::Dirtyfb).is_err()
        || !regs.take_log().is_empty()
        || ext.run_work(&regs, 2_000_000_000) != Ok(WorkStep::Activated)
        || regs.take_log() != [(MAN_TRK_B, CFF), (DP2_B, PR_ENABLE)]
        || !ext.replay().active()
        || ext.run_work(&regs, 2_000_000_001) != Ok(WorkStep::Idle)
    {
        return TestResult::Fail("an idle re-arm must run dg2_activate_panel_replay");
    }
    // A flip neither invalidates nor exits; an active replay queues nothing.
    if ext.invalidate(&regs, PRIMARY_B, Origin::Flip).is_err()
        || ext.flush(&regs, PRIMARY_B, Origin::Flip).is_err()
        || !regs.take_log().is_empty()
        || ext.work_queued()
        || ext.busy() != 0
    {
        return TestResult::Fail("a flip must leave an active replay alone");
    }
    // Invalidate marks busy and exits; another pipe's flush keeps it busy;
    // the pipe's own flush clears it and queues the re-arm.
    if ext.invalidate(&regs, PRIMARY_B, Origin::Cpu).is_err()
        || regs.take_log() != [(DP2_B, 0)]
        || ext.busy() != PRIMARY_B
        || ext.flush(&regs, PRIMARY_A, Origin::Cpu).is_err()
        || ext.busy() != PRIMARY_B
        || ext.work_queued()
        || ext.flush(&regs, PRIMARY_B, Origin::Cpu).is_err()
        || ext.busy() != 0
        || !ext.work_queued()
        || ext.run_work(&regs, 3_000_000_000) != Ok(WorkStep::Activated)
    {
        return TestResult::Fail("busy frontbuffer bits must gate the re-arm");
    }
    regs.take_log();
    // Pause: the first exits and cancels the work; a paused flush neither
    // exits nor queues; only the last resume activates.
    let first = ext.pause(&regs);
    let second = ext.pause(&regs);
    if first != Ok(true) || second != Ok(false) || regs.take_log() != [(DP2_B, 0)] {
        return TestResult::Fail("only the first pause exits replay");
    }
    if ext.flush(&regs, PRIMARY_B, Origin::Dirtyfb).is_err()
        || !regs.take_log().is_empty()
        || ext.work_queued()
        || ext.resume(&regs).is_err()
        || !regs.take_log().is_empty()
        || ext.pause_count() != 1
        || ext.resume(&regs).is_err()
        || regs.take_log() != [(MAN_TRK_B, CFF), (DP2_B, PR_ENABLE)]
        || ext.resume(&regs).is_err()
        || !regs.take_log().is_empty()
    {
        return TestResult::Fail("intel_psr_resume must activate on the last resume only");
    }
    // A pause cancels queued work.
    if ext.flush(&regs, PRIMARY_B, Origin::Dirtyfb).is_err()
        || !ext.work_queued()
        || ext.pause(&regs) != Ok(true)
        || ext.work_queued()
        || ext.run_work(&regs, 4_000_000_000) != Ok(WorkStep::Idle)
    {
        return TestResult::Fail("intel_psr_pause must cancel the re-arm work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_frontbuffer_follows_intel_psr_flush
);

/// Below display 20, `_psr_flush_handle` without selective fetch is
/// `intel_psr_force_update` (a `CURSURFLIVE` write) and replay stays active;
/// after an invalidate's exit the flush still force-updates and re-arms.
fn smoke_ext_replay_display14_flush_force_updates() -> TestResult {
    let regs = Regs::default();
    let Some(mut ext) = dp_replay(14, &regs) else {
        return TestResult::Fail("DP replay must enable on display 14 with the WA input");
    };
    if ext.flush(&regs, PRIMARY_B, Origin::Dirtyfb).is_err()
        || regs.take_log() != [(CURSURFLIVE_B, 0)]
        || !ext.replay().active()
        || ext.work_queued()
    {
        return TestResult::Fail("a display-14 flush must force an update, not exit");
    }
    if ext.invalidate(&regs, PRIMARY_B, Origin::Cs).is_err()
        || regs.take_log() != [(DP2_B, 0)]
        || ext.flush(&regs, PRIMARY_B, Origin::Cs).is_err()
        || regs.take_log() != [(CURSURFLIVE_B, 0)]
        || !ext.work_queued()
    {
        return TestResult::Fail("invalidate exits; the flush force-updates and re-arms");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_display14_flush_force_updates
);

/// `_intel_psr_min_set_context_latency` (Linux 7.4-rc4), branch by branch.
fn smoke_ext_replay_min_set_context_latency_follows_linux() -> TestResult {
    use crate::intel_gpu_psr::panel_replay::min_set_context_latency as scl;
    // (display, eDP, replay, selective update, VRR possible) -> lines.
    let cases: [((u16, bool, bool, bool, bool), u32); 10] = [
        // Wa_14015401596.
        ((13, false, true, false, true), 1),
        ((14, false, true, false, true), 1),
        ((14, false, true, false, false), 0),
        ((12, false, false, false, true), 0),
        // Selective update needs none; eDP below display 30 neither.
        ((20, false, true, true, true), 0),
        ((20, true, true, false, true), 0),
        // DP replay on display 20 reads SRD_STATUS.
        ((20, false, true, false, true), 1),
        // Display 30: replay none, PSR1 one, eDP PSR1 one.
        ((30, false, true, false, true), 0),
        ((30, false, false, false, true), 1),
        ((30, true, false, false, true), 1),
    ];
    for ((ver, edp, replay, su, vrr), want) in cases {
        if scl(ver, edp, replay, su, vrr) != want {
            return TestResult::Fail("the minimum set context latency must be Linux's");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_min_set_context_latency_follows_linux
);

/// The console's flush queue: only a published replay slot queues, and an
/// unpublished slot drops what it had queued.
fn smoke_ext_replay_console_flush_queue() -> TestResult {
    publish_live(0);
    let _ = take_dirty();
    frontbuffer_flush(0);
    if any_live() || take_dirty() != 0 {
        return TestResult::Fail("no replay, no queued flush");
    }
    publish_live(0b01);
    frontbuffer_flush(1);
    frontbuffer_flush(0);
    frontbuffer_flush(0);
    let queued = take_dirty();
    frontbuffer_flush(0);
    publish_live(0);
    let dropped = take_dirty();
    if queued != 0b01 || dropped != 0 || any_live() {
        return TestResult::Fail("flushes must queue per live slot and drop when unpublished");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_console_flush_queue
);

// ── Through the service ───────────────────────────────────────────

fn tc2(kind: MtlHpdKind) -> MtlHpdEvent {
    MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind,
    }
}

/// A 1024x768 DP-alt monitor on TC2 that answers `DP_PANEL_REPLAY_SUPPORT`
/// (DPCD 0x0b0 = 0x01) when `replay`.
fn route_fake(replay: bool) -> ExtFake {
    let mut sink = RouteSink::new(0x14, edid_1024());
    if replay {
        sink.extra.push((0x0b0, 0x01));
    }
    ExtFake::new(XeLpgPort::Tc2, sink)
}

/// A service lighting `io`'s TC2 sink beside the panel on `ip`.
fn service_on(io: &ExtFake, ip: DisplayIp, replay: bool) -> Option<MtlExternalService> {
    let panel = io.light_panel_ip(ip)?;
    let mut service = MtlExternalService::new();
    service.set_profile(ExternalDisplayProfile::for_ip(ip));
    service.set_display(MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &crate::intel_gpu_dc_states::NoPipeDmc,
    });
    service.set_panel_replay(replay);
    Some(service)
}

/// Panther Lake (display 30) DP on Pipe B under the option: the sink's
/// enable before training, `intel_psr_enable_locked` after the route lit,
/// the event pause/resume, a queued console flush and its re-arm, and
/// `intel_psr_disable` before the route's teardown.
fn smoke_ext_replay_display30_route_lifecycle() -> TestResult {
    let io = route_fake(true);
    let Some(mut service) = service_on(&io, DisplayIp::Xe3Lpd, true) else {
        return TestResult::Fail("the fixture must light the display-30 panel");
    };
    if !matches!(
        service.handle(
            &io,
            tc2(MtlHpdKind::Connected(LiveMode::DpAlt)),
            &mut fb_for
        ),
        ServiceOutcome::Activated { .. }
    ) {
        return TestResult::Fail("the TC2 route must light on Pipe B");
    }
    let (Some(replay), None) = service.panel_replay(0) else {
        return TestResult::Fail("the lit SST route must run Panel Replay");
    };
    let config = replay.replay().config();
    if config.display_ver != 30 || config.pipe != 1 || config.su || config.edp {
        return TestResult::Fail("replay must be full-frame DP on transcoder B");
    }
    // PANEL_REPLAY_CONFIG = ENABLE before training; then
    // _panel_replay_enable_sink: ENABLE | VSC_SDP_CRC | UNRECOVERABLE_ERROR
    // | RFB_STORAGE_ERROR | ACTIVE_FRAME_CRC_ERROR (0x3b), CONFIG2 =
    // CRC_VERIFICATION (0x02), CONFIG3 = DP_PR_AS_SDP_SETUP_TIME_T1 (0).
    if io.sink.borrow().pr_log != [(0x1b0, 0x01), (0x1b0, 0x3b), (0x1b1, 0x02), (0x11a, 0x00)] {
        return TestResult::Fail("the sink conversation must be Linux's, enable first");
    }
    // Source: PSR_DEBUG(B) masks nothing for DP on display 20+, PSR_IMR(B)
    // unmasks TGL_PSR_ERROR, and activation sets CFF and the replay enable.
    if io.writes_to(0x61860) != [0]
        || io.writes_to(0x61814) != [0xffff_fffb]
        || io.writes_to(MAN_TRK_B) != [CFF]
        || io.writes_to(DP2_B) != [PR_ENABLE]
    {
        return TestResult::Fail("the source enable must be Linux's");
    }
    // A healthy short pulse is still bracketed: exit, then re-activation.
    io.writes.borrow_mut().clear();
    if !matches!(
        service.handle(&io, tc2(MtlHpdKind::ShortPulse), &mut fb_for),
        ServiceOutcome::Unchanged
    ) || io.writes_to(DP2_B) != [0, PR_ENABLE]
        || service.panel_replay(0).0.map(|r| r.pause_count()) != Some(0)
    {
        return TestResult::Fail("an event must pause replay and resume it after");
    }
    // A queued console flush exits; a busy status keeps the re-arm waiting.
    io.writes.borrow_mut().clear();
    io.phy.write32(SRD_STATUS_B, SRD_BUSY);
    service.replay_pass(&io, 0b01, 0);
    if io.writes_to(DP2_B) != [0]
        || service.panel_replay(0).0.map(|r| r.work_queued()) != Some(true)
    {
        return TestResult::Fail("a console flush must exit replay and queue the re-arm");
    }
    // A pass without a flush for slot 0 only steps the work: idle activates.
    io.phy.write32(SRD_STATUS_B, 0);
    service.replay_pass(&io, 0b10, 1_000_000);
    if io.writes_to(DP2_B) != [0, PR_ENABLE]
        || service
            .panel_replay(0)
            .0
            .map(|r| (r.replay().active(), r.work_queued()))
            != Some((true, false))
    {
        return TestResult::Fail("the re-arm must activate once the status is idle");
    }
    // Teardown: intel_psr_disable (exit, idle, the Wa bit) before the stop.
    io.writes.borrow_mut().clear();
    if !service.teardown(&io) || service.panel_replay(0) != (None, None) {
        return TestResult::Fail("teardown must disable replay and drop it");
    }
    let exit = io.first_write(|o, v| o == DP2_B && v == 0);
    let plane_off = io.first_write(|o, v| o == 0x7_1180 && v & (1 << 31) == 0);
    if !matches!((exit, plane_off), (Some(e), Some(p)) if e < p) {
        return TestResult::Fail("replay must be disabled before the plane goes off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_display30_route_lifecycle
);

/// Refusals: the option off writes nothing; a sink without replay gets no
/// pre-training write; display 14 lacks the route pipe's Wa_14015648006
/// input; display 20 DP needs a set context latency the lit route does not
/// have. Each route still lights without replay.
fn smoke_ext_replay_refusals_leave_the_route_lit() -> TestResult {
    use crate::intel_gpu_psr::panel_replay::Refusal;
    let cases = [
        (DisplayIp::Xe3Lpd, false, true, Refusal::Disabled, false),
        (
            DisplayIp::Xe3Lpd,
            true,
            false,
            Refusal::NoSinkSupport,
            false,
        ),
        (DisplayIp::Xelpdp, true, true, Refusal::WmLevelUnknown, true),
        (
            DisplayIp::Xe2Lpd,
            true,
            true,
            Refusal::SetContextLatency,
            true,
        ),
    ];
    for (ip, option, sink_replay, refusal, pretrain) in cases {
        let io = route_fake(sink_replay);
        let Some(mut service) = service_on(&io, ip, option) else {
            return TestResult::Fail("the fixture must light the panel");
        };
        if !matches!(
            service.handle(
                &io,
                tc2(MtlHpdKind::Connected(LiveMode::DpAlt)),
                &mut fb_for
            ),
            ServiceOutcome::Activated { .. }
        ) {
            return TestResult::Fail("the route must light without replay");
        }
        if service.panel_replay(0) != (None, Some(refusal)) {
            return TestResult::Fail("the refusal must be typed");
        }
        let want: &[(u32, u8)] = if pretrain { &[(0x1b0, 0x01)] } else { &[] };
        if io.sink.borrow().pr_log != want
            || io.writes_to(DP2_B).iter().any(|v| v & PR_ENABLE != 0)
            || !io.writes_to(0x61860).is_empty()
        {
            return TestResult::Fail("a refused replay programs no source register");
        }
        if !service.teardown(&io) {
            return TestResult::Fail("the route must still tear down");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_refusals_leave_the_route_lit
);

/// An AS SDP v2 monitor (`DP_DPRX_FEATURE_ENUMERATION_LIST_CONT_1` = 0x05:
/// supported, FAVT parsing; no downstream port) on the display-30 route:
/// `intel_dp_compute_as_sdp` at the EDID's 806-line vtotal (coasting at
/// vmax: 0x0b1 keeps async video timing) reaches
/// `ADL_TVIDEO_DIP_AS_SDP_DATA(B)` with `VIDEO_DIP_ENABLE_AS_ADL`, beside the
/// replay VSC SDP; teardown clears both enables.
fn smoke_ext_replay_display30_sends_the_as_sdp() -> TestResult {
    let io = route_fake(true);
    io.sink.borrow_mut().extra.push((0x2214, 0x05));
    let Some(mut service) = service_on(&io, DisplayIp::Xe3Lpd, true) else {
        return TestResult::Fail("the fixture must light the display-30 panel");
    };
    let outcome = service.handle(
        &io,
        tc2(MtlHpdKind::Connected(LiveMode::DpAlt)),
        &mut fb_for,
    );
    let ServiceOutcome::Activated { mode, .. } = outcome else {
        return TestResult::Fail("the TC2 route must light");
    };
    if mode.v_total != 806 {
        return TestResult::Fail("the EDID must give the 806-line DMT vtotal");
    }
    // HB 00 22 02 09; DB0 = 01 (FIXED_VTOTAL), DB1/2 = 26 03, DB7/8 = 26 03.
    let want = [
        0x0902_2200,
        0x0003_2601,
        0x2600_0000,
        0x0000_0003,
        0,
        0,
        0,
        0,
        0,
    ];
    for (i, w) in want.iter().enumerate() {
        if io.writes_to(0x61484 + 4 * i as u64) != [*w] {
            return TestResult::Fail("the AS SDP must be Linux's packing at transcoder B");
        }
    }
    // VSC SDP header dword at HSW_TVIDEO_DIP_VSC_DATA(B) 0x61320; enables
    // VSC_HSW | VSC_DIP_HW_DATA_SW_HEA | AS_ADL at HSW_TVIDEO_DIP_CTL(B).
    if io.writes_to(0x61320) != [0x1006_0700]
        || io.read32(0x61200) & 0x0790_0000 != 0x0490_0000
        || service
            .panel_replay(0)
            .0
            .and_then(|r| r.replay().config().as_sdp)
            .is_none()
        || !io.writes_to(0x61948).is_empty()
    {
        return TestResult::Fail("the replay SDPs must be enabled; DP takes no PR_ALPM_CTL");
    }
    if !service.teardown(&io) || io.read32(0x61200) & ((1 << 23) | (1 << 20)) != 0 {
        return TestResult::Fail("teardown must clear the VSC and AS SDP enables");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ext_replay_display30_sends_the_as_sdp
);
