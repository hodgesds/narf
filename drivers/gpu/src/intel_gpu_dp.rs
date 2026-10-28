//! Intel external DisplayPort — full single-stream path (#1092).
//!
//! Everything an external DP sink needs that the eDP-shaped
//! Stage-2 modeset did not have: DPCD capability discovery,
//! negotiated link training, full-EDID read (base + extension
//! blocks), HPD connect/disconnect handling, and DP audio
//! publication. The register sequence itself still runs through
//! [`Modeset`](crate::intel_gpu_modeset::Modeset) — this module
//! is the session layer around it.
//!
//! ## The two seams this lane builds (named for their consumers)
//!
//! 1. **Shared link-training core** —
//!    `dp_link_training::{read_caps, negotiate, train_negotiated}`
//!    (vendor-neutral, over `dp_aux::AuxChannel`).
//!    **Thunderbolt lane 3 (#1095) consumes this seam** over a
//!    tunnelled AUX channel; it must not re-implement caps or
//!    negotiation. This module is the seam's first consumer.
//! 2. **Shared display-audio sink** —
//!    `narf_drivers_sound::display_audio::{build_eld,
//!    publish_display_audio, clear_display_audio}`.
//!    **HDMI-full (#1019) consumes this seam** as its second
//!    publisher; it must not build a second sink. The DP side of
//!    the codec programming (AUD_CONFIG / AUD_PIN_ELD_CP_VLD)
//!    lives in [`crate::intel_gpu_audio`].
//!
//! ## HPD
//!
//! Combo-DDI hotplug on Gen11/12 uses the GEN8 DE Port
//! interrupt block (PRM Vol. 11; i915 `GEN8_DE_PORT_IRQ_REGS`):
//! ISR 0x44440 / IMR 0x44444 / IIR 0x44448 / IER 0x4444C, with
//! the per-DDI hotplug bit at `1 << (3 + ddi_index)` for the
//! combo DDIs A/B/C. The live ISR bit is the connection level;
//! a latched IIR bit while the level stays high is the DP
//! short pulse (IRQ_HPD) — the sink is asking the source to
//! re-check link status, so the session revalidates and
//! retrains if clock recovery was lost. (The GEN11_DE_HPD block
//! at 0x44470 is the Type-C/TBT path and is not used here.)
//!
//! ## Shape
//!
//! The session is split so production glue can interleave its
//! scanout allocation: [`probe_sink`] runs the AUX conversation
//! (caps + full EDID + negotiation) and reports the mode;
//! [`activate`] runs the modeset at the negotiated plan and
//! publishes audio. [`connect`] composes the two for callers
//! (and fixtures) that already hold a framebuffer.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_drivers_sound::display_audio::{
    build_eld, clear_display_audio, publish_display_audio, DisplayConnector, DisplaySinkId,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::dp_aux::{AuxChannel as _, AuxError};
use crate::dp_edid::{read_full_edid, EdidReadError};
use crate::dp_link_training::{
    negotiate, read_caps, DpcdCaps, LinkError, LinkRate, NegotiatedLink, SourceCaps, TrainedLink,
};
use crate::intel_gpu_audio;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_modeset::{Framebuffer, LinkPlan, Mode, Modeset, ModesetError};
use crate::intel_gpu_pipes::Pipe;

/// GEN8 DE Port interrupt status register (live levels).
pub const GEN8_DE_PORT_ISR: u64 = 0x4_4440;
/// GEN8 DE Port interrupt mask register.
pub const GEN8_DE_PORT_IMR: u64 = 0x4_4444;
/// GEN8 DE Port interrupt identity register (latched edges,
/// write-1-to-clear).
pub const GEN8_DE_PORT_IIR: u64 = 0x4_4448;
/// GEN8 DE Port interrupt enable register.
pub const GEN8_DE_PORT_IER: u64 = 0x4_444C;

/// Hotplug bit for a combo DDI in the GEN8 DE Port block:
/// `1 << (3 + index)` for DDI A/B/C. Type-C DDIs (D–H) report
/// through the GEN11 DE HPD block instead and return `None`.
pub fn hotplug_bit(ddi: Ddi) -> Option<u32> {
    match ddi {
        Ddi::A => Some(1 << 3),
        Ddi::B => Some(1 << 4),
        Ddi::C => Some(1 << 5),
        _ => None,
    }
}

/// A hotplug transition on a combo DDI, as classified by
/// [`HpdMonitor::poll`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpdEvent {
    /// Level rose: a sink is now connected.
    Connected(Ddi),
    /// Level fell: the sink went away.
    Disconnected(Ddi),
    /// Short pulse (IRQ_HPD) on a live connection: re-check
    /// link status; retrain if the link lost lock.
    RetrainRequired(Ddi),
}

/// Combo DDIs the monitor watches, in poll order.
const COMBO_DDIS: [Ddi; 3] = [Ddi::A, Ddi::B, Ddi::C];

/// HPD level/edge tracker for the combo DDIs. Poll-driven: the
/// production caller (`intel_gpu::poll_dp_hpd_events`) runs it
/// from the probe path today; the interrupt-enable programming
/// ([`HpdMonitor::enable_interrupts`]) is in place for the IRQ
/// consumer that follows.
#[derive(Debug, Default)]
pub struct HpdMonitor {
    level: [bool; 3],
}

impl HpdMonitor {
    pub const fn new() -> Self {
        Self { level: [false; 3] }
    }

    /// Unmask + enable the combo hotplug interrupts (IER set,
    /// IMR cleared for the three combo bits). Polling works
    /// with or without this; it exists so an IRQ handler sees
    /// the same edges the poller does.
    pub fn enable_interrupts<M: MmioWindow + ?Sized>(&self, mmio: &M) {
        let mask: u32 = COMBO_DDIS.iter().filter_map(|d| hotplug_bit(*d)).sum();
        let ier = mmio.read32(GEN8_DE_PORT_IER);
        mmio.write32(GEN8_DE_PORT_IER, ier | mask);
        let imr = mmio.read32(GEN8_DE_PORT_IMR);
        mmio.write32(GEN8_DE_PORT_IMR, imr & !mask);
        compiler_fence(Ordering::SeqCst);
    }

    /// Poll once. Returns at most one event per call — callers
    /// loop until `None` to drain. Consumed IIR edges are
    /// cleared (write-1-to-clear) so a short pulse is reported
    /// exactly once.
    pub fn poll<M: MmioWindow + ?Sized>(&mut self, mmio: &M) -> Option<HpdEvent> {
        let isr = mmio.read32(GEN8_DE_PORT_ISR);
        let iir = mmio.read32(GEN8_DE_PORT_IIR);
        let combo_mask: u32 = COMBO_DDIS.iter().filter_map(|d| hotplug_bit(*d)).sum();
        if iir & combo_mask != 0 {
            mmio.write32(GEN8_DE_PORT_IIR, iir & combo_mask);
        }
        for (i, ddi) in COMBO_DDIS.iter().enumerate() {
            let bit = hotplug_bit(*ddi).unwrap_or(0);
            let now = isr & bit != 0;
            if now && !self.level[i] {
                self.level[i] = true;
                return Some(HpdEvent::Connected(*ddi));
            }
            if !now && self.level[i] {
                self.level[i] = false;
                return Some(HpdEvent::Disconnected(*ddi));
            }
            if now && self.level[i] && iir & bit != 0 {
                return Some(HpdEvent::RetrainRequired(*ddi));
            }
        }
        None
    }
}

/// The process-wide HPD monitor the production poll path uses.
static HPD_MONITOR: IrqSafeSpinLock<HpdMonitor> = IrqSafeSpinLock::new(HpdMonitor::new());

/// Poll the shared HPD monitor once (production entry point;
/// see `intel_gpu::poll_dp_hpd_events`).
pub fn poll_hpd_event<M: MmioWindow + ?Sized>(mmio: &M) -> Option<HpdEvent> {
    HPD_MONITOR.lock().poll(mmio)
}

/// Program the shared monitor's interrupt enables (production
/// entry point; the session is poll-driven today, this is for
/// the IRQ consumer that follows).
pub fn enable_hpd_interrupts<M: MmioWindow + ?Sized>(mmio: &M) {
    HPD_MONITOR.lock().enable_interrupts(mmio)
}

/// The Intel Gen12 source envelope negotiation runs against:
/// HBR3 over 4 lanes (the combo PHY's documented ceiling).
pub const INTEL_SOURCE_CAPS: SourceCaps = SourceCaps {
    max_rate: LinkRate::Hbr3,
    max_lanes: 4,
};

/// Errors the DP session can return. Each variant names the
/// layer that failed so callers log precisely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DpError {
    /// Capability read / training failed in the shared core.
    Link(LinkError),
    /// EDID read or parse failed.
    Edid(EdidReadError),
    /// The modeset orchestrator failed.
    Modeset(ModesetError),
}

impl From<LinkError> for DpError {
    fn from(e: LinkError) -> Self {
        DpError::Link(e)
    }
}

impl From<EdidReadError> for DpError {
    fn from(e: EdidReadError) -> Self {
        DpError::Edid(e)
    }
}

impl From<ModesetError> for DpError {
    fn from(e: ModesetError) -> Self {
        DpError::Modeset(e)
    }
}

impl From<AuxError> for DpError {
    fn from(e: AuxError) -> Self {
        DpError::Link(LinkError::AuxFailure(e))
    }
}

/// Largest EDID this session buffers: base + 3 extensions.
/// The CTA block the audio path needs is extension 1; three
/// extension slots cover every real panel the driver targets.
pub const EDID_CAPACITY: usize = 512;

/// The result of the AUX-side sink probe: everything
/// [`activate`] needs, plus the raw EDID for the caller's own
/// inspection.
#[derive(Clone, Debug)]
pub struct DpSinkProbe {
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// Decoded DPCD receiver capabilities.
    pub caps: DpcdCaps,
    /// The sink's preferred mode (first detailed timing).
    pub mode: Mode,
    /// The negotiated link configuration for that mode.
    pub negotiated: NegotiatedLink,
    /// The complete EDID bytes (`edid_len` valid).
    pub edid: [u8; EDID_CAPACITY],
    /// Valid byte count in `edid`.
    pub edid_len: usize,
}

/// A live external DP connection: the trained link plus the
/// bookkeeping disconnect/retrain need.
#[derive(Clone, Debug)]
pub struct DpConnection {
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// The pipe scanning this connection out, claimed from
    /// `intel_gpu_multipipe` by the glue. Connections made
    /// through the original single-pipe entry points sit on
    /// Pipe A, as they always did (#1017).
    pub pipe: Pipe,
    /// The mode being scanned out.
    pub mode: Mode,
    /// The link as actually trained (post-fallback).
    pub trained: TrainedLink,
    /// The sink capabilities read at connect time.
    pub caps: DpcdCaps,
    /// Whether an ELD was published for this connection.
    pub audio_published: bool,
}

/// The display-audio sink id for a DDI: DDI index + 1 (0 is
/// reserved). The HDMI lane (#1019) uses the same id for the
/// same physical connector.
pub fn sink_id_for(ddi: Ddi) -> DisplaySinkId {
    DisplaySinkId((ddi as u32) + 1)
}

/// Convert the EDID's preferred detailed timing into the
/// modeset's `Mode` shape (same field mapping the modeset's own
/// EDID path uses). Shared with the MST session layer (#1017),
/// whose per-sink EDIDs arrive over sideband messages instead
/// of the native I²C-over-AUX channel — the conversion must not
/// fork.
pub(crate) fn mode_from_edid(edid_raw: &[u8]) -> Result<Mode, DpError> {
    let edid = narf_graphics::edid::Edid::parse(&edid_raw[..128])
        .map_err(|e| DpError::Edid(EdidReadError::Parse(e)))?;
    let d = edid
        .preferred_timing()
        .map_err(|e| DpError::Edid(EdidReadError::Parse(e)))?;
    Ok(Mode {
        pixel_clock_khz: d.pixel_clock_khz,
        h_active: d.h_active,
        h_total: d.h_active + d.h_blanking,
        h_sync_start: d.h_active + d.h_sync_offset,
        h_sync_end: d.h_active + d.h_sync_offset + d.h_sync_width,
        v_active: d.v_active,
        v_total: d.v_active + d.v_blanking,
        v_sync_start: d.v_active + d.v_sync_offset,
        v_sync_end: d.v_active + d.v_sync_offset + d.v_sync_width,
        h_sync_positive: d.h_sync_positive,
        v_sync_positive: d.v_sync_positive,
    })
}

/// Phase 1 of a connect: run the AUX conversation — read the
/// sink's DPCD capabilities, read the complete EDID, and
/// negotiate the link for the sink's preferred mode. No display
/// registers are touched beyond the AUX block.
pub fn probe_sink<M: MmioWindow + ?Sized>(mmio: &M, ddi: Ddi) -> Result<DpSinkProbe, DpError> {
    let mut aux = IntelAux::new(mmio, ddi);
    let caps = read_caps(&mut aux)?;
    let mut edid = [0u8; EDID_CAPACITY];
    let edid_len = read_full_edid(&mut aux, &mut edid)?;
    let mode = mode_from_edid(&edid[..edid_len])?;
    // 24 bpp uncompressed SST — the stream shape the modeset
    // programs today.
    let demand = crate::dp_link_training::stream_demand_kbps(mode.pixel_clock_khz, 24);
    let negotiated = negotiate(&INTEL_SOURCE_CAPS, &caps, demand);
    Ok(DpSinkProbe {
        ddi,
        caps,
        mode,
        negotiated,
        edid,
        edid_len,
    })
}

/// Phase 2 of a connect: modeset at the negotiated plan, then
/// publish display audio if the sink's EDID carries audio.
/// Audio publication order matters: the ELD lands in the
/// shared sink *first*, then the codec path enables and
/// ELD_VALID rises — a codec acting on ELD_VALID always finds
/// the bytes already published.
pub fn activate<M: MmioWindow + ?Sized>(
    mmio: &M,
    probe: &DpSinkProbe,
    fb: &Framebuffer,
) -> Result<DpConnection, DpError> {
    activate_on_pipe(mmio, probe, fb, Pipe::A, None)
}

/// [`activate`] on a caller-claimed pipe (#1017): the modeset
/// binds `pipe` (and its same-index transcoder, which the audio
/// path also keys on), and `dbuf_share` carries the pipe's
/// DBUF share when the multi-pipe coordinator computed one.
/// Pipe ownership itself is the caller's business
/// (`intel_gpu_multipipe`); this layer only records the pipe
/// on the connection so disconnect/retrain return to it.
pub fn activate_on_pipe<M: MmioWindow + ?Sized>(
    mmio: &M,
    probe: &DpSinkProbe,
    fb: &Framebuffer,
    pipe: Pipe,
    dbuf_share: Option<(u16, u16)>,
) -> Result<DpConnection, DpError> {
    let plan = LinkPlan {
        rate: probe.negotiated.rate,
        lanes: probe.negotiated.lanes,
    };
    let mut modeset = Modeset::for_pipe(mmio, probe.ddi, pipe);
    if let Some((start, end)) = dbuf_share {
        modeset.set_dbuf_share(start, end);
    }
    let (mode, trained) = modeset.modeset_with_plan(fb, &probe.mode, plan)?;

    let mut audio_published = false;
    if let Some(publication) = build_eld(
        &probe.edid[..probe.edid_len],
        DisplayConnector::DisplayPort,
        (probe.ddi as u64) + 1,
    ) {
        publish_display_audio(sink_id_for(probe.ddi), publication);
        intel_gpu_audio::audio_codec_enable(mmio, pipe.transcoder());
        intel_gpu_audio::set_eld_valid(mmio, pipe.transcoder(), true);
        audio_published = true;
    }

    Ok(DpConnection {
        ddi: probe.ddi,
        pipe,
        mode,
        trained,
        caps: probe.caps,
        audio_published,
    })
}

/// Full connect: [`probe_sink`] + [`activate`] composed, for
/// callers that already hold a framebuffer.
pub fn connect<M: MmioWindow + ?Sized>(
    mmio: &M,
    ddi: Ddi,
    fb: &Framebuffer,
) -> Result<DpConnection, DpError> {
    connect_on_pipe(mmio, ddi, fb, Pipe::A)
}

/// [`connect`] on a caller-claimed pipe (#1017).
pub fn connect_on_pipe<M: MmioWindow + ?Sized>(
    mmio: &M,
    ddi: Ddi,
    fb: &Framebuffer,
    pipe: Pipe,
) -> Result<DpConnection, DpError> {
    let probe = probe_sink(mmio, ddi)?;
    activate_on_pipe(mmio, &probe, fb, pipe, None)
}

/// Disconnect: silence audio (codec disable + sink clear)
/// before the pipeline comes down, so no consumer can act on
/// an ELD whose display is already gone.
pub fn disconnect<M: MmioWindow + ?Sized>(mmio: &M, conn: &DpConnection) {
    if conn.audio_published {
        intel_gpu_audio::audio_codec_disable(mmio, conn.pipe.transcoder());
        clear_display_audio(sink_id_for(conn.ddi));
    }
    let mut modeset = Modeset::for_pipe(mmio, conn.ddi, conn.pipe);
    modeset.teardown();
}

/// Respond to a short pulse (IRQ_HPD): re-read link status. If
/// every trained lane still reports CR_DONE the link never
/// lost lock — the pulse was informational and the connection
/// stands. Otherwise the link is gone: run a fresh connect
/// (caps, negotiation and modeset all re-derive; the modeset's
/// own disable-first step makes re-entry safe).
pub fn retrain<M: MmioWindow + ?Sized>(
    mmio: &M,
    conn: &DpConnection,
    fb: &Framebuffer,
) -> Result<DpConnection, DpError> {
    let mut aux = IntelAux::new(mmio, conn.ddi);
    let mut status01 = [0u8; 1];
    let mut status23 = [0u8; 1];
    aux.dpcd_read(0x202, &mut status01)?;
    aux.dpcd_read(0x203, &mut status23)?;
    let status = [status01[0], status23[0]];
    let lanes = conn.trained.lanes as usize;
    let cr_alive = (0..lanes).all(|lane| {
        let byte = status[lane / 2];
        let nibble = if lane & 1 == 0 {
            byte & 0x0F
        } else {
            (byte >> 4) & 0x0F
        };
        nibble & 0x01 != 0
    });
    if cr_alive {
        return Ok(conn.clone());
    }
    // The reconnect lands on the connection's own pipe: the
    // session's claim and scanout window are keyed to it.
    connect_on_pipe(mmio, conn.ddi, fb, conn.pipe)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Sink-side fixtures for the DP-full lane (#1092).
    //!
    //! `SinkMmio` is a register-level model of the Gen12 display
    //! block the session touches: writes are stored (and logged),
    //! status bits follow the documented hardware behaviour
    //! (power-well STATE mirrors REQUEST, PIPECONF STATE mirrors
    //! ENABLE, DDI_BUF IDLE mirrors !ENABLE, PLL status reads
    //! locked), and the DDI AUX block runs real transactions
    //! against `DpSink` — a DPCD state machine + EDID store that
    //! decodes the AUX wire frames itself.
    //!
    //! Every protocol constant the sink speaks (DPCD addresses,
    //! status nibbles, adjust-request layout, the AUX frame
    //! shape) is written here from the DP 1.4a spec text, not
    //! copied from the production side — the production code and
    //! the sink are independent parties to the same
    //! conversation, and the byte-for-byte wire pins below fail
    //! if either side drifts from the spec shape.

    extern crate alloc;

    use super::*;
    use crate::intel_gpu_aux::{
        AUX_CTL_DONE, AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY,
        DDI_AUX_CTL_OFFSET, DDI_AUX_DATA_OFFSET,
    };
    use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
    use crate::intel_gpu_modeset::PixelFormat;
    use crate::intel_gpu_pipes::{Pipe as PipeIdx, Transcoder as Trans, PIPECONF_OFFSET};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── The sink ────────────────────────────────────────────────

    /// Rate codes on the wire (LINK_BW_SET values, DP §2.7).
    /// (RBR's 0x06 appears in the wire log assertions via the
    /// negotiation matrix's decode path, not as a sink cap.)
    const BW_HBR: u8 = 0x0A;
    const BW_HBR2: u8 = 0x14;
    const BW_HBR3: u8 = 0x1E;

    #[derive(Debug)]
    struct DpSink {
        /// DPCD receiver-capability field (0x000..0x00F),
        /// served verbatim.
        caps: [u8; 16],
        /// Complete EDID bytes the I²C side serves.
        edid: Vec<u8>,
        /// EDID read pointer (set by the I²C offset write).
        i2c_ptr: usize,
        link_bw_set: u8,
        pattern: u8,
        /// Clock recovery has locked at the current rate. Sticky
        /// across the TPS1 → TPS2/3 pattern switch and across
        /// training-pattern-off (a real sink holds the lane
        /// status bits through equalization and into normal
        /// operation); cleared by a new LINK_BW_SET or power-down.
        cr_locked: bool,
        /// Status reads since the training pattern last changed.
        polls: u32,
        /// Polls a healthy rate needs before CR_DONE appears.
        cr_rounds: u32,
        powered: bool,
        /// Rate codes at which CR never locks (the HBR3-failure
        /// sink sets this to {BW_HBR3}).
        fail_bw: [u8; 2],
        /// Tamper switch: NACK every transaction.
        nack_all: bool,
        /// Every request frame, verbatim, in order.
        wire_log: Vec<Vec<u8>>,
        /// I²C transaction shape: (command nibble, data length)
        /// for every I²C-over-AUX request, in order; length 0 is
        /// an address-only request.
        i2c_log: Vec<(u8, usize)>,
    }

    impl DpSink {
        fn new(caps: [u8; 16], edid: Vec<u8>) -> Self {
            Self {
                caps,
                edid,
                i2c_ptr: 0,
                link_bw_set: 0,
                pattern: 0,
                cr_locked: false,
                polls: 0,
                cr_rounds: 1,
                powered: false,
                fail_bw: [0, 0],
                nack_all: false,
                wire_log: Vec::new(),
                i2c_log: Vec::new(),
            }
        }

        fn rate_fails(&self) -> bool {
            self.fail_bw.contains(&self.link_bw_set)
        }

        /// Whether channel equalization has completed at the
        /// current pattern: CR locked, TPS2/3 showing, and at
        /// least one status poll since the pattern was set.
        fn eq_done(&self) -> bool {
            self.pattern >= 2 && self.polls >= 1 && self.cr_locked
        }

        /// One lane-status byte for a lane pair (both pairs
        /// report the same state in this model: the source
        /// drives all active lanes identically).
        fn lane_status_byte(&self, _first_lane: usize) -> u8 {
            let mut nibble = 0u8;
            if self.cr_locked {
                nibble |= 0x1; // CR_DONE
            }
            if self.eq_done() {
                nibble |= 0x2 | 0x4; // CHANNEL_EQ_DONE | SYMBOL_LOCKED
            }
            // Both lanes of the pair report the same state in
            // this model (the source drives them identically).
            nibble | (nibble << 4)
        }

        fn read_dpcd(&mut self, addr: u32, len: usize) -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..len {
                let a = addr + i as u32;
                let b = match a {
                    0x000..=0x00F => self.caps[a as usize],
                    0x202 => {
                        self.polls += 1;
                        // CR locks once a healthy rate has been
                        // polled past its settle rounds under TPS1.
                        if self.powered
                            && !self.rate_fails()
                            && self.pattern == 1
                            && self.polls > self.cr_rounds
                        {
                            self.cr_locked = true;
                        }
                        self.lane_status_byte(0)
                    }
                    0x203 => self.lane_status_byte(2),
                    0x204 => {
                        if self.eq_done() {
                            0x01 // INTERLANE_ALIGN_DONE
                        } else {
                            0x00
                        }
                    }
                    // ADJUST_REQUEST: a failing rate demands MAX
                    // swing on every lane (drives the source's
                    // same-MAX-twice rule); a healthy sink asks
                    // for level 0.
                    0x206 | 0x207 => {
                        if self.rate_fails() {
                            0x33
                        } else {
                            0x00
                        }
                    }
                    _ => 0,
                };
                out.push(b);
            }
            out
        }

        fn write_dpcd(&mut self, addr: u32, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            match addr {
                0x100 => {
                    self.link_bw_set = data[0];
                    self.cr_locked = false;
                    self.polls = 0;
                }
                0x102 => {
                    self.pattern = data[0] & 0x7;
                    // Pattern-off at the end of training does NOT
                    // clear the lock: the lane-status bits report
                    // the live link, and a trained sink keeps
                    // CR/EQ/symbol-lock asserted in normal
                    // operation (that's what the retrain path
                    // revalidates against).
                    self.polls = 0;
                }
                0x600 => {
                    self.powered = data[0] & 0x1 != 0;
                    if !self.powered {
                        self.cr_locked = false;
                    }
                }
                _ => {}
            }
        }

        /// Run one AUX transaction: decode the wire frame,
        /// apply it, return the reply bytes (status byte +
        /// payload). The frame decode is written from DP 1.4a
        /// §2.7.4: byte 0 = command nibble + address[19:16],
        /// bytes 1–2 = address[15:0], byte 3 = LEN − 1.
        fn transact(&mut self, wire: &[u8]) -> Vec<u8> {
            self.wire_log.push(wire.to_vec());
            if self.nack_all {
                return alloc::vec![0x10]; // AUX_NACK
            }
            let cmd = wire[0] >> 4;
            let addr = (((wire[0] & 0x0F) as u32) << 16) | ((wire[1] as u32) << 8) | wire[2] as u32;
            // I²C requests carry the 7-bit slave address; only
            // the EDID EEPROM at 0x50 answers (I2C_NACK else).
            if cmd & 0x8 == 0 && addr != 0x50 {
                return alloc::vec![0x40];
            }
            // An I²C address-only request is the bare 3-byte
            // header (no LEN byte); with MOT clear it is the STOP.
            if wire.len() == 3 {
                if cmd & 0x8 != 0 {
                    return alloc::vec![0x10];
                }
                self.i2c_log.push((cmd, 0));
                return alloc::vec![0x00];
            }
            let len = wire[3] as usize + 1;
            match cmd {
                // NATIVE_WRITE
                0x8 => {
                    self.write_dpcd(addr, &wire[4..4 + len]);
                    alloc::vec![0x00]
                }
                // NATIVE_READ
                0x9 => {
                    let mut reply = alloc::vec![0x00];
                    reply.extend_from_slice(&self.read_dpcd(addr, len));
                    reply
                }
                // I2C_WRITE (MOT clear) / I2C_WRITE_MOT: set the
                // EDID offset pointer.
                0x0 | 0x4 => {
                    self.i2c_log.push((cmd, len));
                    self.i2c_ptr = wire[4] as usize;
                    alloc::vec![0x00]
                }
                // I2C_READ (MOT clear) / I2C_READ_MOT.
                0x1 | 0x5 => {
                    self.i2c_log.push((cmd, len));
                    let mut reply = alloc::vec![0x00];
                    for i in 0..len {
                        let b = self.edid.get(self.i2c_ptr + i).copied().unwrap_or(0);
                        reply.push(b);
                    }
                    self.i2c_ptr += len;
                    reply
                }
                _ => alloc::vec![0x10],
            }
        }
    }

    // ── The MMIO register model ─────────────────────────────────

    const PWR_WELL_CTL2: u64 = 0x4_5404;
    /// DPLL0/1/2_ENABLE: combo DDIs A/B/C each lock their own PLL.
    const DPLL_ENABLES: [u64; 3] = [0x4_6010, 0x4_6014, 0x4_6018];
    const PLL_POWER_STATE: u32 = 1 << 26;
    const PLL_LOCK: u32 = 1 << 30;

    #[derive(Debug)]
    pub struct SinkMmio {
        regs: RefCell<BTreeMap<u64, u32>>,
        pub writes: RefCell<Vec<(u64, u32)>>,
        sink: RefCell<DpSink>,
        ddi: Ddi,
        /// Staged AUX reply bytes (status + payload).
        aux_reply: RefCell<Vec<u8>>,
        /// Staged AUX request bytes as written via AUX_DATA.
        aux_data: RefCell<[u8; 20]>,
        /// AUX_CTL value reads return once a transaction lands.
        aux_ctl_state: RefCell<u32>,
        /// GEN8_DE_PORT live levels / latched edges (test-driven).
        pub hpd_level: RefCell<u32>,
        pub hpd_iir: RefCell<u32>,
    }

    impl SinkMmio {
        fn new(ddi: Ddi, sink: DpSink) -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                writes: RefCell::new(Vec::new()),
                sink: RefCell::new(sink),
                ddi,
                aux_reply: RefCell::new(Vec::new()),
                aux_data: RefCell::new([0u8; 20]),
                aux_ctl_state: RefCell::new(0),
                hpd_level: RefCell::new(0),
                hpd_iir: RefCell::new(0),
            }
        }

        fn stored(&self, off: u64) -> u32 {
            self.regs.borrow().get(&off).copied().unwrap_or(0)
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn aux_ctl_off(&self) -> u64 {
            self.ddi.base() + DDI_AUX_CTL_OFFSET
        }

        fn is_aux_data(&self, off: u64) -> Option<usize> {
            let base = self.ddi.base() + DDI_AUX_DATA_OFFSET;
            if off >= base && off < base + 20 && (off - base) % 4 == 0 {
                Some(((off - base) / 4) as usize)
            } else {
                None
            }
        }
    }

    impl MmioWindow for SinkMmio {
        fn read32(&self, off: u64) -> u32 {
            if off == self.aux_ctl_off() {
                return *self.aux_ctl_state.borrow();
            }
            if let Some(idx) = self.is_aux_data(off) {
                // Serve the staged reply, big-endian packed like
                // the real block.
                let reply = self.aux_reply.borrow();
                let mut v: u32 = 0;
                for b in 0..4 {
                    let byte = reply.get(idx * 4 + b).copied().unwrap_or(0);
                    v |= (byte as u32) << (24 - 8 * b);
                }
                return v;
            }
            if off == GEN8_DE_PORT_ISR {
                return *self.hpd_level.borrow();
            }
            if off == GEN8_DE_PORT_IIR {
                return *self.hpd_iir.borrow();
            }
            let v = self.stored(off);
            if off == PWR_WELL_CTL2 {
                // STATE(idx) mirrors REQUEST(idx): REQ bits sit
                // at 0x2 << 2i, STATE at 0x1 << 2i.
                return v | ((v & 0xAAAA_AAAA) >> 1);
            }
            if DPLL_ENABLES.contains(&off) {
                return v | PLL_POWER_STATE | PLL_LOCK;
            }
            // DBUF slices grant power when requested.
            {
                use crate::intel_gpu_wm::{
                    DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST, DBUF_POWER_STATE,
                };
                if (off == DBUF_CTL_S1 || off == DBUF_CTL_S2) && v & DBUF_POWER_REQUEST != 0 {
                    return v | DBUF_POWER_STATE;
                }
            }
            // PIPECONF (pipe + transcoder A): STATE follows ENABLE.
            let pipeconf_offs = [
                PipeIdx::A.base() + PIPECONF_OFFSET,
                Trans::A.conf_base() + PIPECONF_OFFSET,
            ];
            if pipeconf_offs.contains(&off) {
                use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
                let state = if v & PIPECONF_ENABLE != 0 {
                    PIPECONF_STATE
                } else {
                    0
                };
                return (v & !PIPECONF_STATE) | state;
            }
            if off == self.ddi.base() + DDI_BUF_CTL_OFFSET {
                use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                let idle = if v & DDI_BUF_CTL_ENABLE != 0 {
                    0
                } else {
                    DDI_BUF_CTL_IDLE_STATUS
                };
                return (v & !DDI_BUF_CTL_IDLE_STATUS) | idle;
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
            if let Some(idx) = self.is_aux_data(off) {
                let mut data = self.aux_data.borrow_mut();
                for b in 0..4 {
                    data[idx * 4 + b] = (val >> (24 - 8 * b)) as u8;
                }
            }
            if off == self.aux_ctl_off() {
                if val & AUX_CTL_SEND_BUSY != 0 {
                    let msgsize = ((val & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
                    let wire = self.aux_data.borrow()[..msgsize].to_vec();
                    let reply = self.sink.borrow_mut().transact(&wire);
                    let total = reply.len() as u32;
                    *self.aux_reply.borrow_mut() = reply;
                    *self.aux_ctl_state.borrow_mut() =
                        AUX_CTL_DONE | (total << AUX_CTL_MSGSIZE_SHIFT);
                } else {
                    // The RW1C clear write before each transaction.
                    *self.aux_ctl_state.borrow_mut() = 0;
                }
            }
            if off == GEN8_DE_PORT_IIR {
                let mut iir = self.hpd_iir.borrow_mut();
                *iir &= !val;
            }
        }
    }

    // ── EDID fixtures ───────────────────────────────────────────

    /// Encode one detailed-timing descriptor per E-EDID §3.10
    /// (the layout the production parser decodes). The
    /// parameter-per-field shape is deliberate: it mirrors the
    /// descriptor's field list so a transcription slip is visible.
    #[allow(clippy::too_many_arguments)]
    fn detailed_timing(
        out: &mut [u8],
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        h_sync_off: u16,
        h_sync_w: u16,
        v_active: u16,
        v_blank: u16,
        v_sync_off: u16,
        v_sync_w: u16,
    ) {
        let pclk_10k = (pclk_khz / 10) as u16;
        out[0] = pclk_10k as u8;
        out[1] = (pclk_10k >> 8) as u8;
        out[2] = h_active as u8;
        out[3] = h_blank as u8;
        out[4] = (((h_active >> 8) as u8 & 0xF) << 4) | ((h_blank >> 8) as u8 & 0xF);
        out[5] = v_active as u8;
        out[6] = v_blank as u8;
        out[7] = (((v_active >> 8) as u8 & 0xF) << 4) | ((v_blank >> 8) as u8 & 0xF);
        out[8] = h_sync_off as u8;
        out[9] = h_sync_w as u8;
        out[10] = ((v_sync_off as u8 & 0xF) << 4) | (v_sync_w as u8 & 0xF);
        out[11] = (((h_sync_off >> 8) as u8 & 0x3) << 6)
            | (((h_sync_w >> 8) as u8 & 0x3) << 4)
            | (((v_sync_off >> 4) as u8 & 0x3) << 2)
            | ((v_sync_w >> 4) as u8 & 0x3);
        out[12] = 52; // ~520 mm wide
        out[13] = 29; // ~290 mm tall
        out[17] = 0x1E; // digital separate sync, +H +V
    }

    /// Build a complete EDID (base + CTA extension with the
    /// same audio blocks the sound-sink fixture carries),
    /// checksummed per block.
    fn fixture_edid(pclk_khz: u32, h_active: u16, v_active: u16, name: &[u8]) -> Vec<u8> {
        let mut e = alloc::vec![0u8; 256];
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let mfr: u16 = (14 << 10) | (1 << 5) | 18; // "NAR"
        e[8] = (mfr >> 8) as u8;
        e[9] = mfr as u8;
        e[10] = 0x34;
        e[11] = 0x12;
        e[18] = 1;
        e[19] = 4;
        e[126] = 1;
        // Preferred timing in the first descriptor slot (0x36).
        // Blanking/sync numbers are plausible for the class;
        // the parser round-trip in the smoke pins them.
        detailed_timing(
            &mut e[0x36..0x36 + 18],
            pclk_khz,
            h_active,
            280,
            88,
            44,
            v_active,
            45,
            4,
            5,
        );
        // Monitor-name descriptor in the second slot.
        let desc = 0x48;
        e[desc + 3] = 0xFC;
        let n = name.len().min(12);
        e[desc + 5..desc + 5 + n].copy_from_slice(&name[..n]);
        e[desc + 5 + n] = 0x0A;
        for b in &mut e[desc + 5 + n + 1..desc + 18] {
            *b = 0x20;
        }
        // CTA-861 extension: LPCM + AC-3 SADs, speaker block.
        let cta = 128usize;
        e[cta] = 0x02;
        e[cta + 1] = 3;
        e[cta + 3] = 0x40; // basic audio
        let mut p = cta + 4;
        e[p] = (1 << 5) | 6;
        p += 1;
        e[p] = (1 << 3) | 1; // LPCM 2ch
        e[p + 1] = 0x7F;
        e[p + 2] = 0x07;
        p += 3;
        e[p] = (2 << 3) | 5; // AC-3 6ch
        e[p + 1] = 0x07;
        e[p + 2] = 0x00;
        p += 3;
        p += 1;
        e[p] = (4 << 5) | 3; // speaker allocation
        e[p + 1] = 0x01;
        p += 1 + 3;
        e[cta + 2] = (p - cta) as u8;
        // Per-block checksums.
        for block in 0..2 {
            let start = block * 128;
            let sum: u32 = e[start..start + 127].iter().map(|&b| b as u32).sum();
            e[start + 127] = ((256 - (sum % 256)) % 256) as u8;
        }
        e
    }

    /// DPCD caps field for a sink: rev 1.4, given max rate code
    /// and lane count, TPS3 + enhanced framing advertised.
    fn fixture_caps(max_bw: u8, max_lanes: u8) -> [u8; 16] {
        let mut caps = [0u8; 16];
        caps[0] = 0x14; // DPCD_REV 1.4
        caps[1] = max_bw; // MAX_LINK_RATE
        caps[2] = (max_lanes & 0x1F) | 0x40 | 0x80; // lanes | TPS3 | ENHANCED_FRAME
        caps[0xE] = 0; // TRAINING_AUX_RD_INTERVAL = 100 µs
        caps
    }

    fn test_fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x40_0000,
            stride_bytes: 8192,
            format: PixelFormat::Xrgb8888,
        }
    }

    // ── Smokes ──────────────────────────────────────────────────

    fn smoke_dp_full_conversation_hbr2_sink() -> TestResult {
        // 3840x2160@60 (594 MHz, 14.26 Gbps demand): RBR x4
        // (5.18) and HBR x4 (8.64) cannot carry it, HBR2 x4
        // (17.28) can — negotiation must land exactly there.
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(594_000, 3840, 2160, b"TEST DP MON");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid));
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(e) => {
                let _ = e;
                return TestResult::Fail("connect over the sink model must succeed");
            }
        };
        if conn.mode.h_active != 3840 || conn.mode.v_active != 2160 {
            return TestResult::Fail("mode must come from the sink EDID");
        }
        if conn.trained.rate != LinkRate::Hbr2 || conn.trained.lanes != 4 {
            return TestResult::Fail("4K60 over an HBR2 sink must train HBR2 x4");
        }
        // Byte-for-byte wire pin: the first frame on the wire is
        // the caps burst read — NATIVE_READ (0x9) at DPCD 0x0000
        // with LEN = 16 − 1 (DP 1.4a §2.7.4 frame shape).
        let sink = mmio.sink.borrow();
        if sink.wire_log.is_empty() || sink.wire_log[0] != alloc::vec![0x90, 0x00, 0x00, 0x0F] {
            return TestResult::Fail("first wire frame must be the 16-byte caps read");
        }
        // Training wrote LINK_BW_SET = 0x14 (HBR2) — and only
        // that rate (no fallback was needed).
        let bw_writes: Vec<u8> = sink
            .wire_log
            .iter()
            .filter(|w| w.len() >= 5 && w[0] >> 4 == 0x8 && w[1] == 0x01 && w[2] == 0x00)
            .map(|w| w[4])
            .collect();
        if bw_writes != alloc::vec![BW_HBR2] {
            return TestResult::Fail("LINK_BW_SET must be written exactly once, at HBR2");
        }
        drop(sink);
        // Audio: ELD published for DDI B's sink id, and the codec
        // path shows OUTPUT_ENABLE + ELD_VALID raised.
        let published =
            narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B));
        match published {
            Some(p) => {
                if p.lpcm_max_channels != 2 || p.sad_count != 2 {
                    return TestResult::Fail("published ELD must carry the fixture SADs");
                }
            }
            None => return TestResult::Fail("connect must publish the ELD"),
        }
        if !conn.audio_published {
            return TestResult::Fail("connection must record audio publication");
        }
        let pin_eld = mmio.writes_to(intel_gpu_audio::HSW_AUD_PIN_ELD_CP_VLD);
        let want =
            intel_gpu_audio::aud_output_enable(Trans::A) | intel_gpu_audio::aud_eld_valid(Trans::A);
        if !pin_eld.iter().any(|w| w & want == want) {
            return TestResult::Fail("PIN_ELD must end with OUTPUT_ENABLE + ELD_VALID set");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp",
        smoke_dp_full_conversation_hbr2_sink
    );

    fn smoke_dp_hbr3_sink_trains_hbr3() -> TestResult {
        // A 1-lane HBR3 sink (a legal MAX_LANE_COUNT = 1
        // advertisement — long-cable / hub sinks do this):
        // 2560x1440@60 demand is 5.80 Gbps; per-lane payloads
        // are RBR 1.30 / HBR 2.16 / HBR2 4.32 / HBR3 6.48, so
        // only HBR3 carries it. (At 4 lanes no EDID-encodable
        // mode can force HBR3: detailed timings cap the pixel
        // clock at 655.35 MHz = 15.7 Gbps < HBR2 x4 payload.)
        let caps = fixture_caps(BW_HBR3, 1);
        let edid = fixture_edid(241_500, 2560, 1440, b"QHD DP");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid));
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("HBR3 connect must succeed"),
        };
        if conn.trained.rate != LinkRate::Hbr3 || conn.trained.lanes != 1 {
            return TestResult::Fail("the QHD mode on a 1-lane sink must train HBR3 x1");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_hbr3_sink_trains_hbr3);

    fn smoke_dp_hbr3_failure_falls_back() -> TestResult {
        // The sink advertises HBR3 but never locks CR at HBR3 —
        // training must fall back to HBR2 and the modeset must
        // reprogram the DPLL to the HBR2 row (CFGCR1 with the
        // P/3 divider field) after the HBR3 attempt. Same
        // 1-lane QHD shape as the HBR3 success smoke: that is
        // the configuration whose negotiation starts at HBR3.
        let caps = fixture_caps(BW_HBR3, 1);
        let edid = fixture_edid(241_500, 2560, 1440, b"QHD DP");
        let mut sink = DpSink::new(caps, edid);
        sink.fail_bw = [BW_HBR3, 0];
        let mmio = SinkMmio::new(Ddi::B, sink);
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("fallback connect must succeed at HBR2"),
        };
        if conn.trained.rate != LinkRate::Hbr2 {
            return TestResult::Fail("HBR3 failure must fall back to HBR2");
        }
        // The wire shows LINK_BW_SET attempts at HBR3 then HBR2.
        let sink = mmio.sink.borrow();
        let bw_writes: Vec<u8> = sink
            .wire_log
            .iter()
            .filter(|w| w.len() >= 5 && w[0] >> 4 == 0x8 && w[1] == 0x01 && w[2] == 0x00)
            .map(|w| w[4])
            .collect();
        if bw_writes.first() != Some(&BW_HBR3) || !bw_writes.contains(&BW_HBR2) {
            return TestResult::Fail("wire must show HBR3 attempted before HBR2");
        }
        drop(sink);
        // The DPLL was reprogrammed after training settled: a
        // CFGCR1 write carrying the HBR2 row (K/1, P/3) must
        // appear after a CFGCR1 write carrying the HBR3 row
        // (K/1, P/2).
        use crate::intel_gpu_pll::{COMBO_HBR2, COMBO_HBR3, DPLL_CFGCR0_DPLL1};
        let cfgcr1_off = crate::intel_gpu_pll::dpll_cfgcr1(DPLL_CFGCR0_DPLL1);
        let cfgcr1_writes = mmio.writes_to(cfgcr1_off);
        let pos_hbr3 = cfgcr1_writes.iter().position(|w| *w == COMBO_HBR3.cfgcr1);
        let pos_hbr2 = cfgcr1_writes.iter().position(|w| *w == COMBO_HBR2.cfgcr1);
        match (pos_hbr3, pos_hbr2) {
            (Some(a), Some(b)) if b > a => {}
            _ => {
                return TestResult::Fail(
                    "DPLL must be programmed HBR3 first, then reprogrammed to HBR2",
                )
            }
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_hbr3_failure_falls_back);

    fn smoke_dp_edid_over_aux_i2c_shape() -> TestResult {
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(148_500, 1920, 1080, b"SHAPE MON");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid.clone()));
        let probe = match probe_sink(&mmio, Ddi::B) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("probe_sink must succeed"),
        };
        if probe.edid_len != 256 {
            return TestResult::Fail("full EDID must be base + 1 extension = 256 bytes");
        }
        if probe.edid[..256] != edid[..] {
            return TestResult::Fail("EDID bytes must arrive verbatim");
        }
        // I²C shape per block, as Linux `drm_dp_i2c_xfer` drives
        // it: the offset write and 8 read bursts of 16 bytes all
        // carry MOT (0x4 / 0x5 — no STOP, one I²C transaction),
        // then an address-only I2C_READ with MOT clear is the
        // STOP. Two blocks = 2 x (1 + 8 + 1) requests.
        let sink = mmio.sink.borrow();
        if sink.i2c_log.len() != 20 {
            return TestResult::Fail("EDID read must be 2 x (write + 8 bursts + stop)");
        }
        for (i, (cmd, len)) in sink.i2c_log.iter().enumerate() {
            let ok = match i % 10 {
                0 => *cmd == 0x4 && *len == 1,
                9 => *cmd == 0x1 && *len == 0,
                _ => *cmd == 0x5 && *len == 16,
            };
            if !ok {
                return TestResult::Fail(
                    "block read must be WRITE_MOT, 8 x READ_MOT, then an address-only STOP",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_edid_over_aux_i2c_shape);

    fn smoke_dp_disconnect_tears_down() -> TestResult {
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(148_500, 1920, 1080, b"TEST DP MON");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid));
        // HPD: level rises → Connected.
        let mut monitor = HpdMonitor::new();
        *mmio.hpd_level.borrow_mut() = hotplug_bit(Ddi::B).unwrap_or(0);
        match monitor.poll(&mmio) {
            Some(HpdEvent::Connected(Ddi::B)) => {}
            _ => return TestResult::Fail("level rise must report Connected(DDI B)"),
        }
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("connect must succeed"),
        };
        if narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)).is_none() {
            return TestResult::Fail("ELD must be published while connected");
        }
        // HPD: level falls → Disconnected → teardown.
        *mmio.hpd_level.borrow_mut() = 0;
        match monitor.poll(&mmio) {
            Some(HpdEvent::Disconnected(Ddi::B)) => {}
            _ => return TestResult::Fail("level fall must report Disconnected(DDI B)"),
        }
        disconnect(&mmio, &conn);
        if narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)).is_some() {
            return TestResult::Fail("disconnect must clear the ELD");
        }
        // DDI buffer was disabled by the teardown (an ENABLE-
        // clearing write to DDI_BUF_CTL after the enabling one).
        let buf_writes = mmio.writes_to(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        use crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE;
        let last = buf_writes[buf_writes.len() - 1];
        if last & DDI_BUF_CTL_ENABLE != 0 {
            return TestResult::Fail("teardown must clear DDI_BUF_CTL ENABLE last");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_disconnect_tears_down);

    fn smoke_dp_hpd_short_pulse_retrain() -> TestResult {
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(148_500, 1920, 1080, b"TEST DP MON");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid));
        let mut monitor = HpdMonitor::new();
        let bit = hotplug_bit(Ddi::B).unwrap_or(0);
        *mmio.hpd_level.borrow_mut() = bit;
        let _ = monitor.poll(&mmio); // Connected
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("connect must succeed"),
        };
        // Short pulse: level stays high, IIR latches the bit.
        *mmio.hpd_iir.borrow_mut() = bit;
        match monitor.poll(&mmio) {
            Some(HpdEvent::RetrainRequired(Ddi::B)) => {}
            _ => return TestResult::Fail("latched IIR on a live level must be RetrainRequired"),
        }
        // The pulse is consumed exactly once.
        if monitor.poll(&mmio).is_some() {
            return TestResult::Fail("a consumed short pulse must not repeat");
        }
        // Link still locked → retrain is a no-op success.
        match retrain(&mmio, &conn, &test_fb()) {
            Ok(c) if c.trained == conn.trained => {}
            _ => return TestResult::Fail("retrain with a live link must keep the connection"),
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_hpd_short_pulse_retrain);

    fn smoke_dp_caps_negotiation_matrix() -> TestResult {
        use crate::dp_link_training::{negotiate, stream_demand_kbps, SourceCaps};
        let source = SourceCaps {
            max_rate: LinkRate::Hbr3,
            max_lanes: 4,
        };
        // (sink max bw, sink lanes, pclk khz, want rate, want lanes, want over_budget)
        // Payload reference (Gbps): x4 — RBR 5.18, HBR 8.64,
        // HBR2 17.28, HBR3 25.92; x2 halves those. Demand is
        // pclk x 24 bpp.
        let cases: [(u8, u8, u32, LinkRate, u8, bool); 6] = [
            (BW_HBR2, 4, 148_500, LinkRate::Rbr, 4, false), // 3.56 Gbps fits RBR x4
            (BW_HBR3, 4, 65_000, LinkRate::Rbr, 4, false),  // small mode, big sink → floor rate
            (BW_HBR3, 2, 148_500, LinkRate::Hbr, 2, false), // lane-capped: HBR x2 = 4.32
            (BW_HBR, 4, 148_500, LinkRate::Rbr, 4, false),  // rate-capped sink still fits at RBR
            (BW_HBR3, 4, 950_000, LinkRate::Hbr3, 4, false), // 22.8 Gbps needs HBR3 x4
            (BW_HBR3, 4, 1_400_000, LinkRate::Hbr3, 4, true), // beyond HBR3 x4 payload
        ];
        for (bw, lanes, pclk, want_rate, want_lanes, want_over) in cases {
            let caps = DpcdCaps::decode(&fixture_caps(bw, lanes));
            let n = negotiate(&source, &caps, stream_demand_kbps(pclk, 24));
            if n.rate != want_rate || n.lanes != want_lanes || n.over_budget != want_over {
                return TestResult::Fail("negotiation matrix case mismatch");
            }
        }
        // Garbage MAX_LINK_RATE byte decodes to the RBR floor,
        // and TRAINING_AUX_RD_INTERVAL maps per the spec table.
        let mut raw = fixture_caps(0xFF, 4);
        raw[0xE] = 3;
        let caps = DpcdCaps::decode(&raw);
        if caps.max_rate != LinkRate::Rbr {
            return TestResult::Fail("unknown MAX_LINK_RATE must floor at RBR");
        }
        if caps.aux_rd_interval_us() != 12_000 {
            return TestResult::Fail("AUX_RD_INTERVAL 3 must mean 12 ms");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_caps_negotiation_matrix);

    fn smoke_dp_mn_follows_trained_link() -> TestResult {
        // After an HBR2 x4 connect at 1080p, the M/N registers
        // must carry the values the PRM formula gives for the
        // *trained* link. The expected values are computed here
        // from the formula text (data M/N = strm*bpp / ls*lanes,
        // link M/N = strm / ls, N = 2^23, M rounded up) — an
        // independent party from `intel_gpu_pipes::dp_mn`.
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(148_500, 1920, 1080, b"TEST DP MON");
        let mmio = SinkMmio::new(Ddi::B, DpSink::new(caps, edid));
        let conn = match connect(&mmio, Ddi::B, &test_fb()) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("connect must succeed"),
        };
        // 1080p over 4 lanes negotiates RBR (its 5.18 Gbps
        // payload covers the 3.56 Gbps demand) — the M/N must
        // follow the *trained* link, not the sink's maximum.
        // Symbol clocks written from the DP rate table here.
        let ls: u64 = match conn.trained.rate {
            LinkRate::Rbr => 162_000,
            LinkRate::Hbr => 270_000,
            LinkRate::Hbr2 => 540_000,
            LinkRate::Hbr3 => 810_000,
        };
        if conn.trained.rate != LinkRate::Rbr || conn.trained.lanes != 4 {
            return TestResult::Fail("1080p x4 must negotiate RBR x4 for this pin");
        }
        let strm: u64 = 148_500;
        let n: u64 = 0x80_0000;
        let link_m = (strm * n).div_ceil(ls);
        // Data M/N uses bytes per pixel (3 for 24 bpp), per the
        // PRM formula the pipes module implements.
        let data_m = (strm * 3 * n).div_ceil(ls * 4);
        use crate::intel_gpu_pipes::{
            PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
        };
        let base = Trans::A.base();
        let dm = mmio.writes_to(base + PIPE_DATA_M1_OFFSET);
        let dn = mmio.writes_to(base + PIPE_DATA_N1_OFFSET);
        let lm = mmio.writes_to(base + PIPE_LINK_M1_OFFSET);
        let ln = mmio.writes_to(base + PIPE_LINK_N1_OFFSET);
        if dm.last() != Some(&(data_m as u32))
            || dn.last() != Some(&(n as u32))
            || lm.last() != Some(&(link_m as u32))
            || ln.last() != Some(&(n as u32))
        {
            return TestResult::Fail(
                "M/N registers must match the PRM formula for the trained link",
            );
        }
        let _ = conn;
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_dp", smoke_dp_mn_follows_trained_link);

    fn smoke_dp_nacking_sink_fails_clean() -> TestResult {
        // Tamper case: a sink that NACKs everything must fail
        // the connect at the caps read, before any modeset
        // register is written (the DDI buffer never enables).
        let caps = fixture_caps(BW_HBR2, 4);
        let edid = fixture_edid(148_500, 1920, 1080, b"TEST DP MON");
        let mut sink = DpSink::new(caps, edid);
        sink.nack_all = true;
        let mmio = SinkMmio::new(Ddi::B, sink);
        match connect(&mmio, Ddi::B, &test_fb()) {
            Err(DpError::Link(_)) => {}
            _ => return TestResult::Fail("NACKing sink must fail with a link error"),
        }
        use crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE;
        let buf_writes = mmio.writes_to(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        if buf_writes.iter().any(|w| w & DDI_BUF_CTL_ENABLE != 0) {
            return TestResult::Fail("no modeset may happen against a dead sink");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_dp",
        smoke_dp_nacking_sink_fails_clean
    );
}
