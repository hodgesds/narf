use super::*;
use crate::{
    hda_codec::Codec,
    native_irq::{Kind, Route, State},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, AtomicBool, AtomicU32, Ordering},
};
use narf_bus::{bar, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};
use narf_time::Deadline;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdaError {
    BarMapFailed,
    ResetTimeout,
    CorbResetTimeout,
    NoCodecs,
    NoOutputStream,
    DmaAllocFailed,
    CommandTimeout,
    FirmwareMissing,
    FirmwarePatchMalformed,
    Busy,
    DeviceFailed,
}
#[derive(Debug, Default)]
struct Commands {
    wp: u16,
    rp: u16,
}

pub struct IntelHda {
    pub(super) bar0: bar::MmioRegion,
    corb: ManuallyDrop<DmaBuffer>,
    rirb: ManuallyDrop<DmaBuffer>,
    commands: IrqSafeSpinLock<Commands>,
    busy: AtomicBool,
    pub(super) irq: Arc<State>,
    route: Option<Route>,
    pub irq_vector: Option<u8>,
    counts: (u8, u8, u8),
    codecs: Vec<CodecInfo>,
    pub(super) graphs: Vec<Codec>,
    pub(super) outputs: Vec<super::routing::Path>,
    /// Currently selected capture path. Behind a lock because the
    /// 100 ms jack loop re-selects it from `&self` while streams
    /// read it at configure time; `inputs` itself is immutable
    /// after discovery.
    pub(super) input: IrqSafeSpinLock<Option<super::routing::Path>>,
    /// Every discovered analog input path, in preference order (Mic >
    /// Line > AUX). `input` is the currently selected one; jack state
    /// re-selects among these without re-enumerating the codec.
    pub(super) inputs: Vec<super::routing::Path>,
    pub(super) streams: [IrqSafeSpinLock<super::stream::Stream>; 2],
    pub(super) irq_control: IrqSafeSpinLock<()>,
    pub(super) volume: IrqSafeSpinLock<super::routing::Volume>,
    /// Per-route playback trims (headphone, speaker). The effective
    /// converter gain is master × route / 87 with either mute
    /// silencing the path, so untouched routes behave exactly like
    /// the old single-master path.
    pub(super) route_volumes: IrqSafeSpinLock<super::routing::RouteVolumes>,
    /// Capture gain state, re-applied after every capture path
    /// configuration so a jack-driven source switch cannot reset it.
    pub(super) capture_gain: IrqSafeSpinLock<super::routing::CaptureGain>,
    /// Formats the routed converters can actually configure, indexed by
    /// `capture as usize`. Queried once at probe from the codec's
    /// `AC_PAR_PCM` word — the same word `configure_paths` enforces — so
    /// `capabilities()` stays a pure read on a path alsa-lib walks repeatedly.
    pub(super) supported_formats: [Vec<narf_drivers_sound::format::SampleFormat>; 2],
    pub ready: bool,
    /// AMD GPU HD-Audio does not snoop (Linux AZX_DCAPS_SNOOP_OFF): CORB,
    /// RIRB, BDL and sample buffers need explicit cache maintenance.
    pub(crate) noncoherent: bool,
    /// HDMI/DP port pins on GPU codecs and their last sensed sink.
    pub(super) hdmi: IrqSafeSpinLock<Vec<super::hdmi::Port>>,
    /// The HDMI playback PCM's IEC958 status, DIGEN and channel map.
    pub(super) hdmi_playback: IrqSafeSpinLock<super::hdmi::Playback>,
    /// Sound card index once registered (`u32::MAX` before), for control
    /// change notifications.
    pub(super) card: AtomicU32,
    /// Power-management park flag (#779): set by quiesce once the
    /// codecs are D3 and the command + stream engines are off,
    /// cleared by reinit. The PCM bring-up paths reinit when they
    /// see it set; the service loops skip work while it is set.
    suspended: AtomicBool,
}
impl core::fmt::Debug for IntelHda {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelHda")
            .field("codecs", &self.codecs)
            .field("counts", &self.counts)
            .field("ready", &self.ready)
            .finish()
    }
}

pub(super) fn wait(mut predicate: impl FnMut() -> bool, ms: u64) -> bool {
    narf_scheduler::responsive_spin_until(&mut predicate, Deadline::after_ms(ms))
}
pub(super) fn delay_us(us: u64) {
    let deadline = Deadline::after_us(us);
    narf_scheduler::responsive_spin_until(|| deadline.expired(), Deadline::after_us(us + 1000));
}

/// SET_AMP_GAIN_MUTE payload muting both output channels (HDA
/// §7.3.3.9: bit 15 output amp, bits 13/12 left/right, bit 7
/// mute; Linux `AMP_OUT_MUTE` in the Realtek init hooks).
const AMP_OUT_MUTE: u32 = 0xB080;

/// GET_PIN_SENSE presence bit (HDA §7.3.3.28; Linux
/// `AC_PIN_SENSE_PRESENCE`).
const PIN_SENSE_PRESENCE: u32 = 1 << 31;

impl IntelHda {
    /// # Safety
    /// Caller exclusively owns this PCI function and its DMA engines.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, HdaError> {
        // SAFETY: Bus probing has exclusively claimed this function and its BAR.
        let bar = unsafe { bar::map_bar(device, 0) }.map_err(|_| HdaError::BarMapFailed)?;
        if bar.len < 0x100 {
            return Err(HdaError::BarMapFailed);
        }
        // AMD SB cache snooping, matching azx_init_pci; never touch Intel TCSEL.
        if device.id.vendor == 0x1022 {
            cap.check_live().map_err(|_| HdaError::DeviceFailed)?;
            if let narf_bus::BusKind::Pcie { cfg_phys, .. } = device.kind {
                // SAFETY: claimed function's vendor-specific byte, not a status dword.
                unsafe {
                    let p =
                        narf_bus::ecam::ptr_for(cfg_phys, 0x42).ok_or(HdaError::BarMapFailed)?;
                    p.write_volatile((p.read_volatile() & !7) | 2);
                }
            }
        }
        // Linux's AZX_DCAPS_PRESET_ATI_HDMI_NS: every ATI GPU HD-Audio
        // function runs with snooping off; position comes from LPIB.
        let noncoherent = super::ati_hdmi_noncoherent(device.id.vendor, device.id.device);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let mut dev = unsafe { Self::initialize(bar, noncoherent) }?;
        dev.route = Route::new(device, cap, dev.irq.clone());
        dev.irq_vector = dev.route.as_ref().map(|r| r.vector);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(
                REG_INTCTL,
                if dev.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        Ok(dev)
    }

    /// # Safety
    /// The window is exclusively owned and has space for all advertised streams.
    pub(super) unsafe fn initialize(
        bar: bar::MmioRegion,
        noncoherent: bool,
    ) -> Result<Self, HdaError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(REG_INTCTL, 0);
            bar.write8(REG_CORBCTL, 0);
            bar.write8(REG_RIRBCTL, 0);
            bar.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read32(REG_GCTL) } & 1 == 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(100);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(REG_GCTL, GCTL_CRST);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read32(REG_GCTL) } & 1 != 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(1000);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let gcap = unsafe { bar.read16(REG_GCAP) };
        let counts = (
            ((gcap >> 8) & 15) as u8,
            ((gcap >> 12) & 15) as u8,
            ((gcap >> 4) & 15) as u8,
        );
        if counts.0 + counts.1 + counts.2 > 30 || sd_base(counts.0 + counts.1 + counts.2) > bar.len
        {
            return Err(HdaError::BarMapFailed);
        }
        let corb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let rirb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        if gcap & 1 == 0 && (corb.dma_addr().raw() >> 32 != 0 || rirb.dma_addr().raw() >> 32 != 0) {
            return Err(HdaError::DmaAllocFailed);
        }
        let mut dev = Self {
            bar0: bar,
            corb: ManuallyDrop::new(corb),
            rirb: ManuallyDrop::new(rirb),
            commands: IrqSafeSpinLock::new(Commands::default()),
            busy: AtomicBool::new(false),
            irq: State::new(bar, Kind::Hda),
            route: None,
            irq_vector: None,
            counts,
            codecs: Vec::new(),
            graphs: Vec::new(),
            outputs: Vec::new(),
            input: IrqSafeSpinLock::new(None),
            inputs: Vec::new(),
            supported_formats: [Vec::new(), Vec::new()],
            streams: [
                IrqSafeSpinLock::new(super::stream::Stream::new(counts.0, false)),
                IrqSafeSpinLock::new(super::stream::Stream::new(0, true)),
            ],
            irq_control: IrqSafeSpinLock::new(()),
            volume: IrqSafeSpinLock::new(super::routing::Volume {
                left: 87,
                right: 87,
                enabled: true,
            }),
            route_volumes: IrqSafeSpinLock::new(super::routing::RouteVolumes {
                headphone: super::routing::Volume {
                    left: 87,
                    right: 87,
                    enabled: true,
                },
                speaker: super::routing::Volume {
                    left: 87,
                    right: 87,
                    enabled: true,
                },
            }),
            capture_gain: IrqSafeSpinLock::new(super::routing::CaptureGain {
                volume: 87,
                boost: 0,
            }),
            ready: false,
            noncoherent,
            hdmi: IrqSafeSpinLock::new(Vec::new()),
            hdmi_playback: IrqSafeSpinLock::new(super::hdmi::Playback::from_converter(0)),
            card: AtomicU32::new(u32::MAX),
            suspended: AtomicBool::new(false),
        };
        if noncoherent {
            // The CPU zeroed both rings; write that back before the
            // controller owns them so no dirty line lands over a response.
            dev.corb.sync(0, 4096);
            dev.rirb.sync(0, 4096);
        }
        // From here Drop resets/quarantines all published DMA on every failure.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if unsafe { bar.read8(REG_CORBSIZE) } & 0x40 == 0
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { bar.read8(REG_RIRBSIZE) } & 0x40 == 0
        {
            return Err(HdaError::DeviceFailed);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write8(REG_CORBSIZE, CORBSIZE_256);
            bar.write8(REG_RIRBSIZE, RIRBSIZE_256);
            bar.write32(REG_CORBLBASE, dev.corb.dma_addr().raw() as u32);
            bar.write32(REG_CORBUBASE, (dev.corb.dma_addr().raw() >> 32) as u32);
            bar.write32(REG_RIRBLBASE, dev.rirb.dma_addr().raw() as u32);
            bar.write32(REG_RIRBUBASE, (dev.rirb.dma_addr().raw() >> 32) as u32);
            bar.write16(REG_CORBWP, 0);
            bar.write16(REG_CORBRP, 1 << 15);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read16(REG_CORBRP) } & (1 << 15) != 0, 100) {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_CORBRP, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read16(REG_CORBRP) } & (1 << 15) == 0, 100) {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_RIRBWP, 1 << 15);
            bar.write16(REG_RINTCNT, 1);
            bar.write8(REG_RIRBSTS, bar.read8(REG_RIRBSTS) & 5);
            bar.write8(REG_CORBSTS, bar.read8(REG_CORBSTS) & 1);
            bar.write8(REG_RIRBCTL, RIRBCTL_RUN | RIRBCTL_RINTCTL | RIRBCTL_OIC);
            bar.write8(REG_CORBCTL, CORBCTL_RUN | CORBCTL_CMEIE);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let mask = unsafe { bar.read16(REG_STATESTS) } & 0x7fff;
        for cad in 0..15 {
            if mask & (1 << cad) == 0 {
                continue;
            }
            // SAFETY: The live controller owns the command rings; its command lease serializes access.
            let vendor = unsafe { dev.send_verb(make_verb(cad, 0, VERB_GET_PARAMETER)) }?;
            if vendor == 0 || vendor == u32::MAX {
                continue;
            }
            // #776 / #1496: read the codec subsystem ID (HDA
            // §7.3.3.2, verb 0xF01 on the root node — the same word
            // Linux matches its Realtek quirk tables on) and apply
            // the verified per-chip init coef sequence and any
            // verified pin quirk for that subsystem ID before the
            // widget graph is built, so the graph is enumerated on
            // the fixed-up codec. A failed or zero read fails open:
            // unknown subsystem, generic behavior — the codec still
            // enumerates. Only the re-derived `VERIFIED_QUIRK_TABLE`
            // is consulted: none of the rescued `hda::quirks`
            // entries verified as a codec subsystem ID (see
            // `quirks.rs`).
            // SAFETY: Read-only subsystem-ID parameter read on the root node of
            // codec `cad` (present per the STATESTS mask above); this controller
            // exclusively owns the command transport and the lease serializes it.
            let subsystem_id = unsafe {
                dev.send_verb(make_verb(
                    cad,
                    0,
                    VERB_GET_PARAMETER | crate::hda_codec::param::SUBSYSTEM_ID,
                ))
            }
            .ok()
            .filter(|&v| v != 0);
            // #1496: verified codec fixups. The parse-time coef
            // updates (#776 remainders, Linux `patch_alc269`
            // dispatch) run first, once, before the widget graph
            // is built; the init coef table and a quirk's chained
            // coef sequence run before the widget graph is built
            // (Linux PRE_PROBE), so the graph is enumerated on the
            // fixed-up codec; the pin / connection-list /
            // preferred-DAC overrides patch the decoded graph
            // afterwards (Linux's driver-side caches —
            // `snd_hda_codec_set_pincfg` /
            // `snd_hda_override_conn_list` — issue no verbs). The
            // ALC282/283 HP-pin tails run after enumeration
            // (below): the HP pin is only known once the graph is
            // built. A quirk matches only when BOTH the codec
            // subsystem ID and the chip agree; anything else fails
            // open to generic behavior.
            let chip = super::quirks::RealtekChip::from_vendor_id(vendor);
            if let Some(chip) = chip {
                if !super::quirks::parse_table_for(chip).is_empty() {
                    dev.apply_parse_coef(cad, chip)?;
                }
                if chip.has_verified_coef_init() {
                    dev.apply_coef_init(cad, chip)?;
                }
            }
            let quirk = subsystem_id
                .and_then(super::quirks::find_verified_quirk)
                .filter(|q| Some(q.chip) == chip);
            if let Some(quirk) = quirk {
                dev.apply_quirk_seq(cad, quirk)?;
            }
            let mut error = None;
            let mut graph = crate::hda_codec::enumerate(cad, |command| {
                if error.is_some() {
                    return 0;
                }
                // SAFETY: The live controller owns the command rings; its command lease serializes access.
                match unsafe { dev.send_verb(command) } {
                    Ok(v) => v,
                    Err(e) => {
                        error = Some(e);
                        0
                    }
                }
            });
            if let Some(e) = error {
                return Err(e);
            }
            if let Some(quirk) = quirk {
                Self::apply_quirk_to_graph(&mut graph, quirk);
            }
            // #776 remainders: the ALC282/283 HP-pin tails run
            // after enumeration — the HP pin (`Codec::hp_pin`,
            // Linux `alc_get_hp_pin`) is only known once the
            // graph is built, and the quirk overrides above may
            // have re-typed a pin. No HP pin, no tail: Linux
            // returns early when `alc_get_hp_pin` is 0.
            if let Some(chip) = chip {
                if let Some(hp_pin) = graph.hp_pin() {
                    dev.apply_hp_tail(cad, chip, hp_pin)?;
                }
            }
            dev.codecs.push(CodecInfo {
                addr: cad,
                vendor_id: vendor,
                revision_id: graph.revision,
                afg_node_id: (graph.afg_nid != 0).then_some(graph.afg_nid),
                subsystem_id,
            });
            if graph.afg_nid != 0 {
                dev.graphs.push(graph);
            }
        }
        if dev.codecs.is_empty() {
            return Err(HdaError::NoCodecs);
        }
        dev.discover_paths();
        dev.hdmi = IrqSafeSpinLock::new(dev.hdmi_ports());
        dev.hdmi_playback = IrqSafeSpinLock::new(dev.initial_hdmi_playback()?);
        dev.supported_formats = [
            dev.query_supported_formats(false),
            dev.query_supported_formats(true),
        ];
        dev.ready = !dev.outputs.is_empty() || dev.input.lock().is_some();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_STATESTS, mask);
            bar.write32(REG_GCTL, GCTL_CRST | GCTL_UNSOL);
            bar.write32(
                REG_INTCTL,
                if dev.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        Ok(dev)
    }

    /// #776 / #1496: issue a chip's init coef table as
    /// SET_COEF_INDEX + SET_PROC_COEF verb pairs (plain writes) or
    /// read-modify-write updates (masked rows) to the addressed
    /// coef node — usually nid 0x20, Linux `alc_write_coef_idx` /
    /// `alc_update_coef_idx`, but `CoefOp` carries the nid because
    /// a few rows address another widget (ALC283's 0x53 row,
    /// ALC256's 0x53 pulse). Caller gates on
    /// `RealtekChip::has_verified_coef_init`: only verified
    /// unconditional tables are applied, in Linux's order. A verb
    /// failure propagates — this runs during probe/reinit where a
    /// dead command transport already fails the bring-up. A failed
    /// coef read inside a masked update instead skips that write,
    /// exactly as Linux's `__alc_update_coefex_idx` does when the
    /// read returns -1.
    fn apply_coef_init(&self, cad: u8, chip: super::quirks::RealtekChip) -> Result<(), HdaError> {
        self.apply_coef_ops(cad, super::quirks::init_table_for(chip))
    }

    /// #776 remainders: issue a chip's parse-time coef table
    /// (Linux `patch_alc269` dispatch, `super::quirks::parse_table_for`)
    /// — the ALC294-arm 0x6b and ALC700-arm 0x4a masked updates. Probe-only: Linux's patch dispatch
    /// runs once, so reinit deliberately does NOT call this.
    /// Caller gates on the table being non-empty.
    fn apply_parse_coef(&self, cad: u8, chip: super::quirks::RealtekChip) -> Result<(), HdaError> {
        self.apply_coef_ops(cad, super::quirks::parse_table_for(chip))
    }

    /// Issue coef ops in order, exactly as Linux's
    /// `alc_process_coef_fw` walks its table.
    fn apply_coef_ops(&self, cad: u8, ops: &[super::quirks::CoefOp]) -> Result<(), HdaError> {
        for op in ops {
            if op.is_write() {
                self.write_coef_idx(cad, op.nid, op.idx, op.value)?;
            } else {
                self.update_coef_idx(cad, op.nid, op.idx, op.mask, op.value)?;
            }
        }
        Ok(())
    }

    /// Plain coef write: SET_COEF_INDEX then SET_PROC_COEF
    /// (Linux `alc_write_coef_idx`).
    fn write_coef_idx(&self, cad: u8, nid: u8, idx: u16, value: u16) -> Result<(), HdaError> {
        self.verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_PROC_COEF | u32::from(value),
        )?;
        Ok(())
    }

    /// Read one coef value: SET_COEF_INDEX then GET_PROC_COEF
    /// (Linux `alc_read_coef_idx`).
    fn read_coef_idx(&self, cad: u8, nid: u8, idx: u16) -> Result<u32, HdaError> {
        self.verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.verb(cad, nid, crate::hda_codec::verb::GET_PROC_COEF)
    }

    /// Masked coef update (Linux `alc_update_coef_idx` /
    /// `alc_update_coefex_idx`): `new = (old & ~mask) | value`.
    /// A failed read skips the write and returns Ok — Linux writes
    /// nothing when the read returns -1.
    fn update_coef_idx(
        &self,
        cad: u8,
        nid: u8,
        idx: u16,
        mask: u16,
        value: u16,
    ) -> Result<(), HdaError> {
        let Ok(current) = self.read_coef_idx(cad, nid, idx) else {
            return Ok(());
        };
        let next = (current & !u32::from(mask)) | u32::from(value);
        self.verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_PROC_COEF | (next & 0xFFFF),
        )?;
        Ok(())
    }

    /// Issue a verified quirk's chained coef verb sequence
    /// verbatim, in order (Linux `HDA_FIXUP_VERBS`). Runs before
    /// enumeration at probe, and again at reinit — a controller
    /// reset drops the coef state the sequence programs.
    fn apply_quirk_seq(&self, cad: u8, quirk: &super::quirks::Quirk) -> Result<(), HdaError> {
        for step in quirk.coef_seq {
            self.verb(cad, step.nid, step.verb)?;
        }
        Ok(())
    }

    /// Linux `snd_hda_jack_detect`: GET_PIN_SENSE (HDA §7.3.3.28)
    /// presence bit. A failed sense read counts as unplugged —
    /// the HP tail still issues its verbs, only the sleeps are
    /// skipped — so a sense failure never fails probe or reinit.
    fn jack_present(&self, cad: u8, pin: u8) -> bool {
        self.verb(cad, pin, crate::hda_codec::verb::GET_PIN_SENSE)
            .is_ok_and(|sense| sense & PIN_SENSE_PRESENCE != 0)
    }

    /// #776 remainders: the HP-pin tail of `alc282_init` /
    /// `alc283_init` (Linux `sound/hda/codecs/realtek/alc269.c`,
    /// after the `alc*_restore_default_value` table). Runs after
    /// enumeration — the HP pin is only known once the graph is
    /// built — and again at reinit, because Linux re-runs the
    /// init hook on resume. A chip with no tail is a no-op; the
    /// caller skips the call entirely when the graph has no HP
    /// pin, exactly as Linux returns early when `alc_get_hp_pin`
    /// is 0.
    fn apply_hp_tail(
        &self,
        cad: u8,
        chip: super::quirks::RealtekChip,
        hp_pin: u8,
    ) -> Result<(), HdaError> {
        match chip {
            super::quirks::RealtekChip::Alc282 => self.apply_alc282_hp_tail(cad, hp_pin),
            super::quirks::RealtekChip::Alc283 => self.apply_alc283_hp_tail(cad, hp_pin),
            _ => Ok(()),
        }
    }

    /// Linux `alc282_init` after `alc282_restore_default_value`:
    /// sense the HP pin, read coef 0x78, drive the capless HP amp
    /// to high-power mode (0x9004), mute the HP amp, set PIN_OUT,
    /// then restore coef 0x78 — the sleeps only when a plug is
    /// sensed. The 0x78 write itself is NOT sense-gated (only the
    /// sleeps are); the restore is skipped when the read failed
    /// (Linux: `if (coef78 != -1)`).
    fn apply_alc282_hp_tail(&self, cad: u8, hp_pin: u8) -> Result<(), HdaError> {
        let sense = self.jack_present(cad, hp_pin);
        let coef78 = self.read_coef_idx(cad, super::quirks::COEF_NODE, 0x78).ok();
        // Index 0x78 Direct Drive HP AMP LPM Control 1 —
        // headphone capless set to high power mode.
        self.write_coef_idx(cad, super::quirks::COEF_NODE, 0x78, 0x9004)?;
        if sense {
            delay_us(2_000);
        }
        self.verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_AMP_GAIN_MUTE | AMP_OUT_MUTE,
        )?;
        if sense {
            delay_us(85_000);
        }
        self.verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL
                | u32::from(super::quirks::PIN_WIDGET_OUT),
        )?;
        if sense {
            delay_us(100_000);
        }
        // Headphone capless set to normal mode — the value read
        // before the high-power write.
        if let Some(value) = coef78 {
            self.write_coef_idx(cad, super::quirks::COEF_NODE, 0x78, (value & 0xFFFF) as u16)?;
        }
        Ok(())
    }

    /// Linux `alc283_init` after `alc283_restore_default_value`:
    /// 30 ms settle, sense the HP pin, drive the capless HP amp
    /// to high-power mode (0x43 = 0x9004), mute the HP amp, set
    /// PIN_OUT, then the 0x46 3k pull-low update and back to
    /// normal mode (0x43 = 0x9614). The 30 ms settle is
    /// unconditional (Linux: the power pin needs time to wake
    /// after resume); only the 85 ms sleeps are sense-gated.
    fn apply_alc283_hp_tail(&self, cad: u8, hp_pin: u8) -> Result<(), HdaError> {
        delay_us(30_000);
        let sense = self.jack_present(cad, hp_pin);
        // Index 0x43 Direct Drive HP AMP LPM Control 1 —
        // headphone capless set to high power mode.
        self.write_coef_idx(cad, super::quirks::COEF_NODE, 0x43, 0x9004)?;
        self.verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_AMP_GAIN_MUTE | AMP_OUT_MUTE,
        )?;
        if sense {
            delay_us(85_000);
        }
        self.verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL
                | u32::from(super::quirks::PIN_WIDGET_OUT),
        )?;
        if sense {
            delay_us(85_000);
        }
        // Index 0x46 Combo jack auto switch control 2 — 3k pull
        // low control for the headset jack. The same masked
        // update ALC256's tail carries, gated on the HP pin
        // existing.
        self.update_coef_idx(cad, super::quirks::COEF_NODE, 0x46, 0x3000, 0x0000)?;
        // Headphone capless set to normal mode.
        self.write_coef_idx(cad, super::quirks::COEF_NODE, 0x43, 0x9614)?;
        Ok(())
    }

    /// Patch a decoded codec graph with a verified quirk's
    /// driver-side overrides (Linux's pin cache, connection cache
    /// and preferred-DAC list — `snd_hda_codec_set_pincfg`,
    /// `snd_hda_override_conn_list`, `spec->gen.preferred_dacs`).
    /// Graph-side only: no verbs. Overrides naming a nid the
    /// graph does not have are skipped — the graph is the authority
    /// on what the codec actually contains.
    fn apply_quirk_to_graph(graph: &mut crate::hda_codec::Codec, quirk: &super::quirks::Quirk) {
        for pin in quirk.pins {
            graph.override_pin_config(pin.nid, pin.cfg);
        }
        for conn in quirk.conns {
            graph.override_conn_list(conn.nid, conn.conns);
        }
        graph.preferred_dacs = quirk
            .preferred_dacs
            .iter()
            .map(|p| (p.pin, p.dac))
            .collect();
    }

    fn acquire_command(&self) -> Result<CommandLease<'_>, HdaError> {
        if self.irq.failed.load(Ordering::Acquire) {
            return Err(HdaError::DeviceFailed);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HdaError::Busy)?;
        Ok(CommandLease {
            dev: self,
            pending: false,
        })
    }
    fn post(&self, verb: u32) -> Result<(), HdaError> {
        let mut state = self.commands.lock();
        let next = (state.wp + 1) & 255;
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let rp = unsafe { self.bar0.read16(REG_CORBRP) } & 255;
        if next == rp {
            return Err(HdaError::Busy);
        }
        // SAFETY: Command lock owns the next in-range CORB slot; the BAR remains mapped.
        unsafe {
            self.corb
                .cpu_mut_ptr::<u32>()
                .add(next as usize)
                .write_volatile(verb);
        }
        fence(Ordering::Release);
        if self.noncoherent {
            self.corb.sync(next as usize * 4, 4);
        }
        state.wp = next;
        // SAFETY: Command lock owns the next in-range CORB slot; the BAR remains mapped.
        unsafe {
            self.bar0.write16(REG_CORBWP, next);
        }
        Ok(())
    }
    fn response(&self, cad: u8) -> Result<Option<u32>, HdaError> {
        if self.irq.failed.load(Ordering::Acquire) {
            return Err(HdaError::DeviceFailed);
        }
        let mut state = self.commands.lock();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let wp = unsafe { self.bar0.read16(REG_RIRBWP) };
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let status = unsafe { self.bar0.read8(REG_RIRBSTS) };
        if wp == u16::MAX
            || status & RIRBSTS_RIRBOIS != 0
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { self.bar0.read8(REG_CORBSTS) } & 1 != 0
        {
            return Err(HdaError::DeviceFailed);
        }
        // The polled boot path has no IRQ handler yet. Acknowledge response
        // status here too: controllers may pause CORB at the RINTCNT threshold.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe { self.bar0.write8(REG_RIRBSTS, status & 1) };
        while state.rp != (wp & 255) {
            state.rp = (state.rp + 1) & 255;
            if self.noncoherent {
                self.rirb.sync(state.rp as usize * 8, 8);
            }
            fence(Ordering::Acquire);
            // SAFETY: Masked RIRB index is within the owned 256-entry coherent completion ring.
            let (value, extra) = unsafe {
                let p = self.rirb.cpu_ptr::<u32>().add(state.rp as usize * 2);
                (p.read_volatile(), p.add(1).read_volatile())
            };
            // Unsolicited jack events advance RIRB independently of CORB.
            // Jack state is refreshed by the service task; never use this as a reply.
            if extra & 0x10 == 0 && extra as u8 & 15 == cad {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    /// # Safety
    /// This object exclusively owns the controller command transport.
    pub unsafe fn send_verb(&self, verb: u32) -> Result<u32, HdaError> {
        let mut lease = self.acquire_command()?;
        self.post(verb)?;
        lease.pending = true;
        let mut reply = Ok(None);
        let done = wait(
            || {
                reply = self.response((verb >> 28) as u8);
                !matches!(reply, Ok(None))
            },
            100,
        );
        if !done {
            narf_console::write_str(&alloc::format!(
                "hda: verb {:#x} timeout: CORB wp/rp={:#x}/{:#x} RIRB wp={:#x} ctl={:#x}/{:#x}\n",
                verb,
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_CORBWP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_CORBRP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_RIRBWP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read8(REG_CORBCTL) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read8(REG_RIRBCTL) },
            ));
            return Err(HdaError::CommandTimeout);
        }
        let value = reply?.ok_or(HdaError::CommandTimeout)?;
        lease.pending = false;
        Ok(value)
    }
    /// Bounded IRQ/timer wait. Cancellation poisons the transport until reset,
    /// preventing a late response from being assigned to a subsequent command.
    /// # Safety
    /// Same exclusive device ownership as send_verb.
    pub async unsafe fn send_verb_async(&self, verb: u32) -> Result<u32, HdaError> {
        let mut lease = self.acquire_command()?;
        self.post(verb)?;
        lease.pending = true;
        let deadline = Deadline::after_ms(100);
        loop {
            // Arm before checking the ring to close the completion/wake race.
            let waiter = self
                .irq_vector
                .map(|v| narf_interrupts::wait_for_irq_until(v, Deadline::after_ms(1)));
            if let Some(value) = self.response((verb >> 28) as u8)? {
                lease.pending = false;
                return Ok(value);
            }
            if deadline.expired() {
                return Err(HdaError::CommandTimeout);
            }
            if let Some(waiter) = waiter {
                let _ = waiter.await;
            } else {
                narf_time::SleepUntil::new(Deadline::after_ms(1).as_instant()).await;
            }
        }
    }
    pub fn stream_counts(&self) -> (u8, u8, u8) {
        self.counts
    }
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs
    }
    pub fn output_stream_idx(&self) -> u8 {
        self.counts.0
    }
    pub fn period_bytes(&self) -> u32 {
        4096
    }
    pub fn period_samples(&self) -> usize {
        2048
    }
    /// # Safety
    /// The controller mapping remains exclusively owned.
    pub unsafe fn drain_irq(&self) {
        self.irq.service();
    }
    /// # Safety
    /// Caller owns this controller and trusts the firmware verb patch.
    pub unsafe fn load_codec_patch(
        &self,
        blob_name: &str,
        fw_authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
    ) -> Result<u32, HdaError> {
        let cap =
            narf_firmware::open(blob_name, fw_authority).map_err(|_| HdaError::FirmwareMissing)?;
        let view = narf_firmware::view_of(&cap).map_err(|_| HdaError::FirmwareMissing)?;
        let bytes = view.bytes;
        if bytes.len() % 4 != 0 {
            return Err(HdaError::FirmwarePatchMalformed);
        }
        let mut sent = 0u32;
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let verb = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            // SAFETY: caller-asserted exclusive ownership.
            let _ = unsafe { self.send_verb(verb)? };
            sent += 1;
            i += 4;
        }
        // Record the firmware coupling on the bound driver.
        narf_drivers::set_bound_firmware(
            "hda0",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from(blob_name),
                sha256: view.sha256,
                signer: view.signer,
                version: None,
            },
        );
        Ok(sent)
    }

    fn service(&self) {
        if self.suspended.load(Ordering::Acquire) {
            return;
        }
        self.irq.service();
        for state in &self.streams {
            state.lock().update(self);
        }
    }
}

// ── Power management (#779) ──────────────────────────────────────────
// Two layers, one quiesce/reinit core:
//
// - System PM: `HdaSystemPm` implements `narf_power::device_pm::
//   DevicePmOps` and is registered at probe; the S3/s2idle fan-out
//   calls it with interrupts gated. Suspend refuses (Busy) while
//   any stream is running or prepared — suspend never discards
//   stream state — and resume re-inits engines + codecs.
// - Runtime PM: `HdaRuntimePm` implements `narf_power::runtime_pm::
//   RuntimePmOps` over the same core, fixture-proven through the
//   `PciRuntimePm` wrapper. Production probe registration of the
//   PCI node is a follow-up: moving the function to D3hot needs a
//   PCM start path that can await resume (the ALSA start hook is
//   sync), and wiring it without one would let a start touch a
//   D3hot BAR. The live idle path is the PCM stop hook below
//   (codecs D3 + engines off, PCI stays D0).
//
// The verb path is synchronous in both layers: `send_verb` polls
// RIRB via MMIO and never waits on an IRQ, so it is safe with
// interrupts gated and cheap (microseconds on the success path)
// inside the async runtime callbacks.
impl IntelHda {
    /// True when no stream can move samples: every descriptor
    /// either has no ring or a ring that is neither running nor
    /// prepared. A prepared-but-idle ring still blocks quiesce:
    /// its BDL is published and its SD state would go stale across
    /// a command-ring restart, so the owner must stop it first.
    fn streams_idle(&self) -> bool {
        self.streams.iter().all(|s| {
            !s.lock()
                .ring
                .as_ref()
                .is_some_and(|r| r.running || r.prepared)
        })
    }

    /// Send a power-state verb to every codec that discovered an
    /// audio function group (HDA §7.3.3.10; payload D0 = 0, D3 = 3).
    /// Codecs without an AFG node are skipped: there is no node to
    /// address, and guessing one would power-manage the wrong
    /// widget. On failure the codecs already switched are rolled
    /// back to D0, so a half-switched controller never escapes.
    fn set_codec_power(&self, d3: bool) -> Result<(), HdaError> {
        let mut switched = Vec::new();
        for codec in &self.codecs {
            let Some(nid) = codec.afg_node_id else {
                continue;
            };
            // SAFETY: Controller owns this live BAR and its command
            // rings; the verb targets the codec's own AFG node.
            let verb = make_verb(
                codec.addr,
                nid,
                crate::hda_codec::verb::SET_POWER_STATE | if d3 { 3 } else { 0 },
            );
            // SAFETY: Controller owns this live BAR and its command rings.
            if let Err(e) = unsafe { self.send_verb(verb) } {
                for (addr, nid) in switched {
                    // Best-effort rollback; the original error wins.
                    // SAFETY: Controller owns this live BAR and its command rings.
                    let _ = unsafe {
                        self.send_verb(make_verb(
                            addr,
                            nid,
                            crate::hda_codec::verb::SET_POWER_STATE,
                        ))
                    };
                }
                return Err(e);
            }
            switched.push((codec.addr, nid));
        }
        Ok(())
    }

    /// Power-management quiesce: codecs to D3, command + stream
    /// engines off, DMA rings retained (host memory survives the
    /// park). Idempotent: already-suspended is Ok. Refuses with
    /// Busy when any stream is running or prepared.
    fn quiesce(&self) -> Result<(), HdaError> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.streams_idle() {
            return Err(HdaError::Busy);
        }
        self.set_codec_power(true)?;
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window. Mirrors Drop
        // minus ring handling: the rings stay owned for resume.
        unsafe {
            self.bar0.write32(REG_INTCTL, 0);
            self.bar0.write8(REG_CORBCTL, 0);
            self.bar0.write8(REG_RIRBCTL, 0);
            self.bar0.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 == 0, 100) {
            // The engines are already off and the codecs D3: this
            // is a parked controller even though the reset did not
            // acknowledge, so mark it suspended — the next
            // ensure_active (or system resume) runs the full
            // reinit rather than trusting a half-parked controller.
            self.suspended.store(true, Ordering::Release);
            return Err(HdaError::ResetTimeout);
        }
        self.suspended.store(true, Ordering::Release);
        Ok(())
    }

    /// Reverse of quiesce: reset the controller, reprogram the
    /// command rings from the retained CORB/RIRB buffers (mirrors
    /// `initialize`'s engine sequence), restore IRQs, codecs back
    /// to D0. Stream descriptors are NOT restored: suspend refused
    /// running or prepared streams, so every stream needs a fresh
    /// prepare after resume. Clears the sticky command-transport
    /// failure: the rings were reset, so a pre-suspend verb timeout
    /// must not poison post-resume verbs (`acquire_command`
    /// refuses while `irq.failed` is set). Idempotent.
    fn reinit(&self) -> Result<(), HdaError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 == 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(100);
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_GCTL, GCTL_CRST);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 != 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(1000);
        // SAFETY: Controller owns this live BAR and its retained
        // CORB/RIRB buffers; same writes as `initialize`.
        unsafe {
            self.bar0.write8(REG_CORBSIZE, CORBSIZE_256);
            self.bar0.write8(REG_RIRBSIZE, RIRBSIZE_256);
            self.bar0
                .write32(REG_CORBLBASE, self.corb.dma_addr().raw() as u32);
            self.bar0
                .write32(REG_CORBUBASE, (self.corb.dma_addr().raw() >> 32) as u32);
            self.bar0
                .write32(REG_RIRBLBASE, self.rirb.dma_addr().raw() as u32);
            self.bar0
                .write32(REG_RIRBUBASE, (self.rirb.dma_addr().raw() >> 32) as u32);
            self.bar0.write16(REG_CORBWP, 0);
            self.bar0.write16(REG_CORBRP, 1 << 15);
        }
        let corb_reset = wait(
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { self.bar0.read16(REG_CORBRP) } & (1 << 15) != 0,
            100,
        );
        if !corb_reset {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window.
        unsafe {
            self.bar0.write16(REG_CORBRP, 0);
        }
        let corb_cleared = wait(
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { self.bar0.read16(REG_CORBRP) } & (1 << 15) == 0,
            100,
        );
        if !corb_cleared {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window.
        unsafe {
            self.bar0.write16(REG_RIRBWP, 1 << 15);
            self.bar0.write16(REG_RINTCNT, 1);
            self.bar0
                .write8(REG_RIRBSTS, self.bar0.read8(REG_RIRBSTS) & 5);
            self.bar0
                .write8(REG_CORBSTS, self.bar0.read8(REG_CORBSTS) & 1);
            self.bar0
                .write8(REG_RIRBCTL, RIRBCTL_RUN | RIRBCTL_RINTCTL | RIRBCTL_OIC);
            self.bar0.write8(REG_CORBCTL, CORBCTL_RUN | CORBCTL_CMEIE);
            self.bar0.write32(
                REG_INTCTL,
                if self.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        // The ring pointers above restarted at 0 (CORBWP=0, RIRBWP
        // reset): the driver's shadow cursors must restart with
        // them, exactly as `initialize` starts them at 0. Without
        // this, the first post-reset response() reads RIRBWP's reset
        // value (low byte 0) with a stale rp and walks pre-reset
        // RIRB slots, accepting the first stale reply whose cad
        // nibble matches as the new verb's response — the D0 verb
        // then "succeeds" without ever reaching the codec, and every
        // following verb validates against a stale value.
        {
            let mut state = self.commands.lock();
            state.wp = 0;
            state.rp = 0;
        }
        // The rings are reset; a pre-suspend verb timeout no longer
        // describes the transport.
        self.irq.failed.store(false, Ordering::Release);
        self.set_codec_power(false)?;
        // #776 / #1496: the controller reset dropped the codecs'
        // coef state (Linux re-runs the init hook on resume for the
        // same reason), so re-apply the probe-time init before the
        // controller is marked active — otherwise suspend/resume
        // silently loses the fixup. The chip is re-derived from the
        // stored vendor id; the same gate as probe applies. A
        // quirk's chained coef sequence is re-applied for the same
        // reason; its graph-side overrides (pins, connections,
        // preferred DACs) survive in the retained graph and need no
        // re-application. The HP-pin tail is re-applied too (it is
        // part of the init hook); the parse-time coef updates are
        // NOT (Linux's patch dispatch runs once, at probe).
        for codec in &self.codecs {
            if let Some(chip) = super::quirks::RealtekChip::from_vendor_id(codec.vendor_id) {
                if chip.has_verified_coef_init() {
                    self.apply_coef_init(codec.addr, chip)?;
                }
                if let Some(quirk) = codec
                    .subsystem_id
                    .and_then(super::quirks::find_verified_quirk)
                    .filter(|q| q.chip == chip)
                {
                    self.apply_quirk_seq(codec.addr, quirk)?;
                }
                if let Some(graph) = self.graphs.iter().find(|g| g.addr == codec.addr) {
                    if let Some(hp_pin) = graph.hp_pin() {
                        self.apply_hp_tail(codec.addr, chip, hp_pin)?;
                    }
                }
            }
        }
        self.suspended.store(false, Ordering::Release);
        Ok(())
    }

    /// PCM bring-up entry: reinit a parked controller before any
    /// path that sends verbs or programs streams.
    pub(super) fn ensure_active(&self) -> Result<(), HdaError> {
        self.reinit()
    }

    /// Best-effort idle transition for the PCM stop path: quiesce
    /// when every stream is stopped, ignore failures (the next stop
    /// retries; the controller simply stays powered).
    pub(super) fn maybe_idle_quiesce(&self) {
        if self.suspended.load(Ordering::Acquire) || !self.streams_idle() {
            return;
        }
        let _ = self.quiesce();
    }
}

/// System-PM ops over every probed HDA controller (#779). The
/// device_pm registry holds one entry per name, so a single unit
/// struct fans out over CONTROLLERS instead of one entry per
/// controller; the lock is dropped before touching any device.
/// Suspend refuses (Busy) while any controller has a running or
/// prepared stream; resume re-inits every suspended controller.
struct HdaSystemPm;
impl narf_power::device_pm::DevicePmOps for HdaSystemPm {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        let devs: Vec<Arc<IntelHda>> = CONTROLLERS
            .lock()
            .iter()
            .map(|(_, dev, _)| dev.clone())
            .collect();
        for dev in devs {
            dev.quiesce().map_err(|e| match e {
                HdaError::Busy => E::Busy,
                _ => E::DriverError,
            })?;
        }
        Ok(())
    }

    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        let devs: Vec<Arc<IntelHda>> = CONTROLLERS
            .lock()
            .iter()
            .map(|(_, dev, _)| dev.clone())
            .collect();
        for dev in devs {
            dev.reinit().map_err(|_| E::DriverError)?;
        }
        Ok(())
    }
}

/// Runtime-PM ops for one HDA controller (#779). The core is
/// synchronous (see above), so the async callbacks simply run it;
/// the PCI D3hot move belongs to the `PciRuntimePm` wrapper.
/// Constructed by kernel tests today; production probe
/// registration is the follow-up that needs an async-aware PCM
/// start path, so the non-test build does not construct it yet.
#[allow(dead_code)]
pub(super) struct HdaRuntimePm {
    pub(super) dev: Arc<IntelHda>,
}
impl narf_power::runtime_pm::RuntimePmOps for HdaRuntimePm {
    fn runtime_suspend(&self) -> narf_power::runtime_pm::RpmFuture<'_> {
        let dev = self.dev.clone();
        Box::pin(async move {
            dev.quiesce().map_err(|e| match e {
                HdaError::Busy => narf_power::runtime_pm::RpmError::Busy,
                _ => narf_power::runtime_pm::RpmError::Failed,
            })
        })
    }

    fn runtime_resume(&self) -> narf_power::runtime_pm::RpmFuture<'_> {
        let dev = self.dev.clone();
        Box::pin(async move {
            dev.reinit()
                .map_err(|_| narf_power::runtime_pm::RpmError::Failed)
        })
    }
}
struct CommandLease<'a> {
    dev: &'a IntelHda,
    pending: bool,
}
impl Drop for CommandLease<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.dev.irq.failed.store(true, Ordering::Release);
        }
        self.dev.busy.store(false, Ordering::Release);
    }
}
impl Drop for IntelHda {
    fn drop(&mut self) {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_INTCTL, 0);
            self.bar0.write8(REG_CORBCTL, 0);
            self.bar0.write8(REG_RIRBCTL, 0);
        }
        self.route.take();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let stopped = wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 == 0, 100);
        for stream in &self.streams {
            if let Some(ring) = stream.lock().ring.take() {
                if !stopped {
                    core::mem::forget(ring);
                }
            }
        }
        if stopped {
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            unsafe {
                ManuallyDrop::drop(&mut self.corb);
                ManuallyDrop::drop(&mut self.rirb);
            }
        }
    }
}

static CONTROLLERS: IrqSafeSpinLock<Vec<(narf_bus::BusAddr, Arc<IntelHda>, u32)>> =
    IrqSafeSpinLock::new(Vec::new());
pub fn controller() -> Option<Arc<IntelHda>> {
    let all = CONTROLLERS.lock();
    all.iter()
        .find(|(_, c, _)| !c.outputs.is_empty())
        .or_else(|| all.first())
        .map(|(_, c, _)| c.clone())
}
pub fn capture_card() -> Option<u32> {
    CONTROLLERS
        .lock()
        .iter()
        .find(|(_, c, _)| c.input.lock().is_some())
        .map(|(_, _, card)| *card)
}
pub fn is_probed() -> bool {
    controller().is_some_and(|c| !c.outputs.is_empty())
}
pub fn stream_counts() -> Option<(u8, u8, u8)> {
    controller().map(|c| c.stream_counts())
}
pub fn codec_count() -> Option<u8> {
    controller().map(|c| c.codecs.len() as u8)
}
pub fn with_controller<R>(f: impl FnOnce(&IntelHda) -> R) -> Option<R> {
    controller().map(|c| f(&c))
}
#[doc(hidden)]
pub fn __reset_for_test() {
    let old = core::mem::take(&mut *CONTROLLERS.lock());
    for (_, _, card) in &old {
        narf_drivers_sound::unregister_hardware_card(*card);
    }
    drop(old);
}
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.class != 0x040300 {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLERS
        .lock()
        .iter()
        .any(|(addr, _, _)| *addr == device.addr)
    {
        return Ok(());
    }
    crate::native_pci::power_on(&device, &cap)?;
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let dev = Arc::new(
        // SAFETY: Bus probing has exclusively claimed this function and its BAR.
        unsafe { IntelHda::bring_up(&device, &cap) }.map_err(|error| {
            narf_bus::ProbeError::Other(match error {
                HdaError::BarMapFailed => "HDA BAR invalid",
                HdaError::ResetTimeout => "HDA controller reset timed out",
                HdaError::CorbResetTimeout => "HDA CORB reset timed out",
                HdaError::NoCodecs => "HDA no codecs responded",
                HdaError::DmaAllocFailed => "HDA DMA allocation failed",
                HdaError::CommandTimeout => "HDA codec command timed out",
                HdaError::DeviceFailed => "HDA command engine failed",
                _ => "HDA initialization failed",
            })
        })?,
    );
    if !dev.ready {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let info = narf_drivers_sound::CardInfo {
        index: 0,
        driver: "hda",
        id: "HDA",
        name: "HD Audio",
        playback_count: u32::from(!dev.outputs.is_empty()),
        capture_count: u32::from(dev.input.lock().is_some()),
    };
    let card = narf_drivers_sound::register_hardware_card_at(
        info,
        Arc::new(super::stream::Card(dev.clone())),
        Some(device.addr),
    );
    dev.card.store(card, Ordering::Release);
    CONTROLLERS.lock().push((device.addr, dev.clone(), card));
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(2).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            dev.service();
        }
    });
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            if !dev.suspended.load(Ordering::Acquire) {
                let _ = dev.refresh_jacks();
            }
        }
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "hda".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    // System power management (#779): one registry entry fans out
    // over every probed controller. Registration is idempotent on
    // the name, so re-probe is safe.
    narf_power::device_pm::register_device_pm_ops("hda", Arc::new(HdaSystemPm));
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "runtime_tests.rs"]
mod tests;
