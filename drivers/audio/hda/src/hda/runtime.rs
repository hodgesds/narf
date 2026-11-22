use super::*;
use crate::{
    hda_codec::Codec,
    native_irq::{Kind, Route, State},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, Ordering},
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
    /// The controller is parked (#779); a command that may not wake it
    /// (the jack service) is refused instead of posted into rings held
    /// in reset.
    Suspended,
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
    /// Brought up and ready for its card, codecs or not (Linux registers a
    /// card for a link with no codec too).
    pub ready: bool,
    /// AMD GPU HD-Audio does not snoop (Linux AZX_DCAPS_SNOOP_OFF): CORB,
    /// RIRB, BDL and sample buffers need explicit cache maintenance.
    pub(crate) noncoherent: bool,
    /// HDMI/DP port pins on GPU codecs and their last sensed sink.
    pub(super) hdmi: IrqSafeSpinLock<Vec<super::hdmi::Port>>,
    /// The HDMI playback PCM's IEC958 status, DIGEN and channel map.
    pub(super) hdmi_playback: IrqSafeSpinLock<Vec<super::hdmi::Playback>>,
    /// Sound card index once registered (`u32::MAX` before), for control
    /// change notifications.
    pub(super) card: AtomicU32,
    /// Power-management park flag (#779): set by quiesce once the
    /// codecs are D3 and the command + stream engines are off,
    /// cleared by reinit. The PCM bring-up paths reinit when they
    /// see it set; the service loops skip work while it is set.
    suspended: AtomicBool,
    /// The stream service task, parked while no stream runs; a stream
    /// start (and teardown) wakes it.
    service_waker: IrqSafeSpinLock<Option<core::task::Waker>>,
    /// Jack state to re-read (Linux `hda_jack_tbl.jack_dirty`): set at
    /// probe and resume (`snd_hda_jack_set_dirty_all`), by an unsolicited
    /// response (`snd_hda_jack_unsol_event`) and by the jackpoll of a
    /// controller without an interrupt.
    jack_dirty: AtomicBool,
    /// The jack service while it waits for a jack event.
    jack_waker: IrqSafeSpinLock<Option<core::task::Waker>>,
    /// Unsolicited-response tags given to jack pins (bit per tag): a
    /// response with any other tag is no jack's (`snd_hda_jack_tbl_get_from_tag`).
    jack_tags: core::sync::atomic::AtomicU64,
    /// Held by a park or a wake (`lock_pm`).
    pm: AtomicBool,
    /// Power references (Linux `snd_hda_power_up` / `_down`): one per open
    /// PCM. The controller parks only with none held.
    power_refs: AtomicU32,
    /// `pm_runtime_mark_last_busy`: the last command or reference drop.
    last_busy_ns: AtomicU64,
    /// The autosuspend delay (Linux `power_save`, in ms).
    pub(super) autosuspend_ms: AtomicU64,
    /// The autosuspend service while nothing can be parked.
    pm_waker: IrqSafeSpinLock<Option<core::task::Waker>>,
    /// Linux `card->longname` ("<short name> at 0x<BAR> irq <n>"), set when
    /// the card is registered.
    pub(super) long_name: IrqSafeSpinLock<alloc::string::String>,
    /// Linux `azx_has_pm_runtime` (`AZX_DCAPS_PM_RUNTIME`): the autosuspend
    /// may power the controller down after its codecs. Without it only the
    /// codecs suspend.
    pub(super) runtime_pm: AtomicBool,
    /// The codecs are in D3 while the controller stays up (the autosuspend
    /// of a controller without `runtime_pm`); a command resumes them first.
    codecs_suspended: AtomicBool,
    /// Linux `codec->cvt_setups` with a stream assigned: the converters a
    /// configure gave a stream tag and format, cleared at codec suspend.
    cvt_setups: IrqSafeSpinLock<Vec<(u8, u8)>>,
    /// What the open playback PCM drives (`pcm_layout`), `None` while no
    /// playback PCM is open.
    pub(super) active_pcm: IrqSafeSpinLock<Option<super::hdmi::PcmSlot>>,
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

/// A codec command's response timeout (Linux `azx_rirb_get_response`
/// waits up to 1 s before falling back to polling; NARF bounds it at 100 ms).
const COMMAND_TIMEOUT_MS: u64 = 100;
/// How long a synchronous command waits for another command to finish
/// (the timeout of the one in flight, its retry and slack).
const LEASE_WAIT_MS: u64 = 3 * COMMAND_TIMEOUT_MS;
/// How long a park or wake waits for another one: a wake runs the codec
/// init again, up to the ALC28x headphone tails' 200 ms of settle time.
const PM_WAIT_MS: u64 = 1000;
/// The autosuspend delay: Linux `snd_hda_intel.power_save`, whose default is
/// `CONFIG_SND_HDA_POWER_SAVE_DEFAULT` (10 s in the host's Linux config), set
/// on each codec with `pm_runtime_set_autosuspend_delay`.
const AUTOSUSPEND_MS: u64 = 10_000;
/// How often the autosuspend service looks for a codec wake (STATESTS
/// under WAKEEN) while the controller is parked. Linux takes the wake as a
/// PCI PME; a NARF park keeps the function in D0 with the link in reset,
/// where no interrupt can arrive, so the resume-well status is polled.
const WAKE_POLL_MS: u64 = 100;
/// `STATESTS_INT_MASK` (include/sound/hda_register.h): the codec wake bits
/// for `HDA_MAX_CODECS` (8) codecs.
const STATESTS_INT_MASK: u16 = 0xff;
/// `AZX_DEFAULT_CODECS`: the codec slots `azx_probe_codecs` probes on every
/// controller NARF binds (only NVIDIA and Teradici differ in Linux).
const AZX_DEFAULT_CODECS: u8 = 4;
const AZX_DEFAULT_CODEC_MASK: u16 = (1 << AZX_DEFAULT_CODECS) - 1;

pub(super) fn wait(mut predicate: impl FnMut() -> bool, ms: u64) -> bool {
    narf_scheduler::responsive_spin_until(&mut predicate, Deadline::after_ms(ms))
}
pub(super) fn delay_us(us: u64) {
    let deadline = Deadline::after_us(us);
    narf_scheduler::responsive_spin_until(|| deadline.expired(), Deadline::after_us(us + 1000));
}

/// `snd_hdac_bus_reset_link(bus, true)` (sound/hda/core/controller.c):
/// clear STATESTS if the link is up, so the mask read afterwards holds only
/// this reset's codec wake events; enter link reset and hold it; leave it
/// and give the codecs time to request an address; then the codec mask.
/// The hold and the settle time are Linux's (500-1000 us and 1000-1200 us);
/// the spec minimums are 100 us and 521 us (25 frames), and NARF held the
/// link in reset for only 100 us before.
fn reset_link(bar: bar::MmioRegion) -> Result<u16, HdaError> {
    // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
    unsafe {
        if bar.read8(REG_GCTL) & GCTL_CRST as u8 != 0 {
            bar.write16(REG_STATESTS, STATESTS_INT_MASK);
        }
        // snd_hdac_bus_enter_link_reset: clear CRST only.
        bar.write32(REG_GCTL, bar.read32(REG_GCTL) & !GCTL_CRST);
    }
    if !wait(
        // SAFETY: as above.
        || unsafe { bar.read8(REG_GCTL) } & GCTL_CRST as u8 == 0,
        100,
    ) {
        return Err(HdaError::ResetTimeout);
    }
    // Codec PLL settle (HDA spec 5.5.1): usleep_range(500, 1000).
    delay_us(1000);
    // snd_hdac_bus_exit_link_reset: set CRST, wait for GCTL to read non-zero.
    // SAFETY: as above.
    unsafe {
        bar.write8(REG_GCTL, bar.read8(REG_GCTL) | GCTL_CRST as u8);
    }
    // SAFETY: as above.
    if !wait(|| unsafe { bar.read8(REG_GCTL) } != 0, 100) {
        return Err(HdaError::ResetTimeout);
    }
    // "Brent Chartrand said to wait >= 540us for codecs to initialize":
    // usleep_range(1000, 1200).
    delay_us(1200);
    // SAFETY: as above.
    if unsafe { bar.read8(REG_GCTL) } == 0 {
        // "controller not ready!"
        return Err(HdaError::ResetTimeout);
    }
    // SAFETY: as above.
    Ok(unsafe { bar.read16(REG_STATESTS) } & STATESTS_INT_MASK)
}

/// Linux `hda_vendor_ids` (sound/hda/core/device.c).
fn codec_vendor_name(vendor: u16) -> Option<&'static str> {
    Some(match vendor {
        0x0014 => "Loongson",
        0x1002 => "ATI",
        0x1013 => "Cirrus Logic",
        0x1057 => "Motorola",
        0x1095 => "Silicon Image",
        0x10de => "Nvidia",
        0x10ec => "Realtek",
        0x1102 => "Creative",
        0x1106 => "VIA",
        0x111d => "IDT",
        0x11c1 => "LSI",
        0x11d4 => "Analog Devices",
        0x13f6 => "C-Media",
        0x14f1 => "Conexant",
        0x17e8 => "Chrontel",
        0x1854 => "LG",
        0x19e5 => "Huawei",
        0x1aec => "Wolfson Microelectronics",
        0x1af4 => "QEMU",
        0x1fa8 => "Senarytech",
        0x434d => "C-Media",
        0x8086 => "Intel",
        0x8384 => "SigmaTel",
        _ => return None,
    })
}

/// "<vendor> <chip>" as Linux names a codec: the vendor from
/// `hda_vendor_ids` ("Generic %04x" otherwise), the chip from the codec
/// driver that binds it (atihdmi's "R6xx HDMI", the Realtek tables), or the
/// core's "ID %x" for a codec no driver names.
fn codec_name(vendor_id: u32) -> alloc::string::String {
    let vendor = (vendor_id >> 16) as u16;
    let chip = if vendor_id == 0x1002_aa01 {
        alloc::string::String::from("R6xx HDMI")
    } else if let Some(chip) = super::quirks::RealtekChip::from_vendor_id(vendor_id) {
        alloc::string::String::from(chip.name())
    } else {
        alloc::format!("ID {:x}", vendor_id & 0xffff)
    };
    match codec_vendor_name(vendor) {
        Some(name) => alloc::format!("{} {}", name, chip),
        None => alloc::format!("Generic {:04x} {}", vendor, chip),
    }
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
        dev.runtime_pm.store(
            super::runtime_pm(device.id.vendor, device.id.device),
            Ordering::Release,
        );
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
        }
        let codec_mask = reset_link(bar)?;
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
            hdmi_playback: IrqSafeSpinLock::new(Vec::new()),
            card: AtomicU32::new(u32::MAX),
            suspended: AtomicBool::new(false),
            service_waker: IrqSafeSpinLock::new(None),
            jack_dirty: AtomicBool::new(true),
            jack_waker: IrqSafeSpinLock::new(None),
            jack_tags: core::sync::atomic::AtomicU64::new(0),
            pm: AtomicBool::new(false),
            power_refs: AtomicU32::new(0),
            last_busy_ns: AtomicU64::new(narf_time::monotonic_ns()),
            autosuspend_ms: AtomicU64::new(AUTOSUSPEND_MS),
            pm_waker: IrqSafeSpinLock::new(None),
            long_name: IrqSafeSpinLock::new(alloc::string::String::new()),
            runtime_pm: AtomicBool::new(true),
            codecs_suspended: AtomicBool::new(false),
            cvt_setups: IrqSafeSpinLock::new(Vec::new()),
            active_pcm: IrqSafeSpinLock::new(None),
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
        dev.init_cmd_io()?;
        // Linux takes the codec mask once, right after the link reset
        // (`snd_hdac_bus_reset_link`); a codec whose wake event lands while
        // the rings were set up is taken too; a slot that does not answer is
        // dropped below either way.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let mask = codec_mask | (unsafe { bar.read16(REG_STATESTS) } & STATESTS_INT_MASK);
        let probed = dev.probe_codec_slots(mask)?;
        if probed != mask & AZX_DEFAULT_CODEC_MASK {
            narf_console::write_str(&alloc::format!(
                "hda: codec mask {:#x} (GCAP {:#06x}), slots answering {:#x}\n",
                mask,
                gcap,
                probed
            ));
        }
        for cad in 0..AZX_DEFAULT_CODECS {
            if probed & (1 << cad) == 0 {
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
            // Linux azx_probe_continue: "no codecs found!", then "keep
            // running the rest for the runtime PM" and register a card
            // without PCMs. The register values tell a link without codecs
            // from codecs that do not answer.
            narf_console::write_str(&alloc::format!(
                "hda: no codecs found! STATESTS mask {:#x}, answering {:#x}, GCAP {:#06x}, \
                 GCTL {:#x}\n",
                mask,
                probed,
                gcap,
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { bar.read32(REG_GCTL) },
            ));
        }
        dev.discover_paths();
        dev.hdmi = IrqSafeSpinLock::new(dev.hdmi_ports());
        dev.hdmi_playback = IrqSafeSpinLock::new(dev.initial_hdmi_playback()?);
        dev.supported_formats = [
            dev.query_supported_formats(false),
            dev.query_supported_formats(true),
        ];
        // Linux registers the card whatever the codecs give it; one with no
        // path simply has no PCMs.
        dev.ready = true;
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
        let _ = dev.enable_jack_events();
        Ok(dev)
    }

    /// `snd_hdac_bus_init_cmd_io` (sound/hda/core/controller.c): program
    /// both command rings from the retained CORB/RIRB buffers, restart both
    /// ring pointers, enable the ring DMA engines and accept unsolicited
    /// responses (GCTL.UNSOL). Shared by probe and resume, so a resumed
    /// controller is set up exactly as a probed one.
    ///
    /// The driver's shadow cursors restart with the hardware pointers.
    /// Without that, the first response after the restart reads RIRBWP's
    /// reset value (low byte 0) against a stale `rp` and walks pre-reset
    /// RIRB slots, taking the first stale reply whose codec address matches
    /// as the new command's response.
    fn init_cmd_io(&self) -> Result<(), HdaError> {
        let bar = self.bar0;
        // `snd_hdac_bus_stop_cmd_io`: the ring bases and pointers may only
        // change with both DMA engines stopped. After a link reset they
        // already are; a ring restart on a running controller stops them
        // here, and nothing in flight survives.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write8(REG_RIRBCTL, 0);
            bar.write8(REG_CORBCTL, 0);
        }
        // `hdac_wait_for_cmd_dmas`: bounded, and like Linux not an error.
        // SAFETY: as above.
        wait(|| unsafe { bar.read8(REG_RIRBCTL) } & RIRBCTL_RUN == 0, 100);
        // SAFETY: as above.
        wait(|| unsafe { bar.read8(REG_CORBCTL) } & CORBCTL_RUN == 0, 100);
        // SAFETY: Controller owns this live BAR and its retained CORB/RIRB
        // buffers; fixed register offsets are inside the validated window.
        unsafe {
            bar.write8(REG_CORBSIZE, CORBSIZE_256);
            bar.write8(REG_RIRBSIZE, RIRBSIZE_256);
            bar.write32(REG_CORBLBASE, self.corb.dma_addr().raw() as u32);
            bar.write32(REG_CORBUBASE, (self.corb.dma_addr().raw() >> 32) as u32);
            bar.write32(REG_RIRBLBASE, self.rirb.dma_addr().raw() as u32);
            bar.write32(REG_RIRBUBASE, (self.rirb.dma_addr().raw() >> 32) as u32);
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
            bar.write32(REG_GCTL, bar.read32(REG_GCTL) | GCTL_UNSOL);
        }
        let mut state = self.commands.lock();
        state.wp = 0;
        state.rp = 0;
        Ok(())
    }

    /// The first pass of Linux `azx_probe_codecs`: one vendor-id read per
    /// slot in `mask` (`probe_codec`, without the timeout fallback, as Linux
    /// does while `chip->probing`). A slot that does not answer is dropped
    /// ("Some BIOSen give you wrong codec addresses that don't exist") and,
    /// because "accessing to a non-existing codec often screws up the
    /// controller chip", the controller is reset before the next slot
    /// (`azx_stop_chip` + `azx_init_chip`). Returns the answering slots.
    /// Probe only: no other user of the rings exists yet.
    fn probe_codec_slots(&self, mask: u16) -> Result<u16, HdaError> {
        let mut answering = mask & AZX_DEFAULT_CODEC_MASK;
        for cad in 0..AZX_DEFAULT_CODECS {
            if answering & (1 << cad) == 0 {
                continue;
            }
            let vendor = self.exec_verb(make_verb(cad, 0, VERB_GET_PARAMETER), false);
            if matches!(vendor, Ok(id) if id != u32::MAX) {
                continue;
            }
            narf_console::write_str(&alloc::format!(
                "hda: codec #{} probe error ({:?}); disabling it\n",
                cad,
                vendor
            ));
            answering &= !(1 << cad);
            if answering == 0 {
                break;
            }
            self.reset_chip()?;
        }
        Ok(answering)
    }

    /// `azx_stop_chip` + `azx_init_chip(chip, true)` during probe: command
    /// I/O stopped, link reset, command I/O restarted, which also drops a
    /// failed probe's poisoned transport.
    fn reset_chip(&self) -> Result<(), HdaError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0.write8(REG_RIRBCTL, 0);
            self.bar0.write8(REG_CORBCTL, 0);
        }
        reset_link(self.bar0)?;
        self.init_cmd_io()?;
        self.irq.failed.store(false, Ordering::Release);
        Ok(())
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
        self.pm_verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.pm_verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_PROC_COEF | u32::from(value),
        )?;
        Ok(())
    }

    /// Read one coef value: SET_COEF_INDEX then GET_PROC_COEF
    /// (Linux `alc_read_coef_idx`).
    fn read_coef_idx(&self, cad: u8, nid: u8, idx: u16) -> Result<u32, HdaError> {
        self.pm_verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.pm_verb(cad, nid, crate::hda_codec::verb::GET_PROC_COEF)
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
        self.pm_verb(
            cad,
            nid,
            crate::hda_codec::verb::SET_COEF_INDEX | u32::from(idx),
        )?;
        self.pm_verb(
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
            self.pm_verb(cad, step.nid, step.verb)?;
        }
        Ok(())
    }

    /// Linux `snd_hda_jack_detect`: GET_PIN_SENSE (HDA §7.3.3.28)
    /// presence bit. A failed sense read counts as unplugged —
    /// the HP tail still issues its verbs, only the sleeps are
    /// skipped — so a sense failure never fails probe or reinit.
    fn jack_present(&self, cad: u8, pin: u8) -> bool {
        self.pm_verb(cad, pin, crate::hda_codec::verb::GET_PIN_SENSE)
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
        self.pm_verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_AMP_GAIN_MUTE | AMP_OUT_MUTE,
        )?;
        if sense {
            delay_us(85_000);
        }
        self.pm_verb(
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
        self.pm_verb(
            cad,
            hp_pin,
            crate::hda_codec::verb::SET_AMP_GAIN_MUTE | AMP_OUT_MUTE,
        )?;
        if sense {
            delay_us(85_000);
        }
        self.pm_verb(
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

    /// Try for the command lease. The lease alone: a caller that issues a
    /// command checks the transport (`irq.failed`) under it, and the wake
    /// takes it to restart a failed transport.
    fn acquire_command(&self) -> Result<CommandLease<'_>, HdaError> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HdaError::Busy)?;
        Ok(CommandLease {
            dev: self,
            pending: false,
        })
    }
    /// The command lease for a synchronous command (`bus->cmd_mutex`):
    /// spin, bounded, while another command is in flight, as
    /// `codec_exec_verb` sleeps on the mutex, so a control read that meets
    /// a jack re-read waits for it instead of failing with `Busy`.
    fn acquire_command_blocking(&self) -> Result<CommandLease<'_>, HdaError> {
        let mut result = self.acquire_command();
        if matches!(result, Err(HdaError::Busy)) {
            wait(
                || {
                    result = self.acquire_command();
                    !matches!(result, Err(HdaError::Busy))
                },
                LEASE_WAIT_MS,
            );
        }
        result
    }
    /// The PM lock (Linux serialises runtime suspend and resume in the PM
    /// core): one park or wake at a time, so two threads that both find
    /// the controller parked do not reset it under each other.
    fn lock_pm(&self) -> Result<PmLock<'_>, HdaError> {
        let take = || {
            self.pm
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        };
        if take() || wait(take, PM_WAIT_MS) {
            Ok(PmLock(self))
        } else {
            Err(HdaError::Busy)
        }
    }
    /// The command lease for an async command (`bus->cmd_mutex`): sleep,
    /// not spin, while another command is in flight, bounded by the command
    /// timeout, so a jack re-read that meets an ALSA command is not lost.
    async fn acquire_command_async(&self) -> Result<CommandLease<'_>, HdaError> {
        let deadline = Deadline::after_ms(COMMAND_TIMEOUT_MS);
        loop {
            match self.acquire_command() {
                Err(HdaError::Busy) if !deadline.expired() => {
                    narf_time::SleepUntil::new(Deadline::after_ms(1).as_instant()).await;
                }
                result => return result,
            }
        }
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
    /// `snd_hdac_bus_update_rirb` for one command: the reply for `cad`, if
    /// posted. An unsolicited response met on the way is a jack event
    /// (`snd_hdac_bus_queue_event`).
    fn response(&self, cad: u8) -> Result<Option<u32>, HdaError> {
        let mut unsolicited = false;
        let reply = self.scan_rirb(cad, &mut unsolicited);
        if unsolicited {
            self.note_jack_event();
        }
        reply
    }
    fn scan_rirb(&self, cad: u8, unsolicited: &mut bool) -> Result<Option<u32>, HdaError> {
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
            // Unsolicited jack events advance RIRB independently of CORB:
            // never a reply; the jack service re-reads the jack.
            if extra & RIRB_EX_UNSOL != 0 {
                *unsolicited |= self.is_jack_tag(value);
                continue;
            }
            if extra as u8 & 15 == cad {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    /// A command (Linux `codec_exec_verb`): power the controller up
    /// (`snd_hda_power_up_pm`), then take the command lease (`cmd_mutex`)
    /// and run it. A PCM stop may park the controller between the two; the
    /// command then sees `suspended` under the lease and wakes it again.
    /// # Safety
    /// This object exclusively owns the controller command transport.
    pub unsafe fn send_verb(&self, verb: u32) -> Result<u32, HdaError> {
        let mut result = Err(HdaError::Suspended);
        for _ in 0..2 {
            self.ensure_active()?;
            result = self.exec_verb(verb, true);
            // A parked controller is woken and the command tried again; so
            // is a lost response, on restarted rings, as
            // `azx_rirb_get_response` retries after each fallback.
            if !matches!(
                result,
                Err(HdaError::Suspended | HdaError::CommandTimeout | HdaError::DeviceFailed)
            ) {
                break;
            }
        }
        result
    }
    /// A command issued by a PM transition or by probe (Linux `codec_in_pm`):
    /// no power-up and no `suspended` gate, the caller owns the transition.
    fn pm_verb(&self, cad: u8, nid: u8, verb: u32) -> Result<u32, HdaError> {
        self.exec_verb(make_verb(cad, nid, verb), false)
    }
    /// One command under the command lease. `gated` refuses a parked
    /// controller (`Suspended`) instead of posting into rings held in reset;
    /// only the PM transitions themselves issue ungated commands.
    fn exec_verb(&self, verb: u32, gated: bool) -> Result<u32, HdaError> {
        let mut lease = self.acquire_command_blocking()?;
        let parked =
            self.suspended.load(Ordering::Acquire) || self.codecs_suspended.load(Ordering::Acquire);
        if gated && parked {
            return Err(HdaError::Suspended);
        }
        self.ready_transport()?;
        self.post(verb)?;
        lease.pending = true;
        let mut reply = Ok(None);
        let done = wait(
            || {
                reply = self.response((verb >> 28) as u8);
                !matches!(reply, Ok(None))
            },
            COMMAND_TIMEOUT_MS,
        );
        if !done {
            self.report_timeout(verb);
            return Err(HdaError::CommandTimeout);
        }
        let value = reply?.ok_or(HdaError::CommandTimeout)?;
        lease.pending = false;
        Ok(value)
    }
    /// Make the command rings usable for the next command; the caller holds
    /// the command lease.
    ///
    /// A command that timed out or was cancelled leaves `irq.failed` set: a
    /// late reply may still land and be taken as the next command's. Linux
    /// `azx_rirb_get_response` falls back instead of giving up (polling
    /// mode, MSI off, then a bus reset or single_cmd mode, which stops the
    /// rings with `snd_hdac_bus_stop_cmd_io`). Here both rings restart
    /// (`init_cmd_io`), which drops whatever was in flight; the link, the
    /// codecs and the stream DMA are left alone. Before, nothing but the
    /// resume of a parked controller cleared the flag, so one lost
    /// response failed every later command on a running controller.
    ///
    /// A controller whose command engine stopped without a park lost its
    /// state (a function reset or power loss, which reads like the parked
    /// rings: pointers and controls 0): with the link in reset it is
    /// marked parked, so the next wake re-initialises it and the codecs.
    fn ready_transport(&self) -> Result<(), HdaError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let control = unsafe { self.bar0.read8(REG_CORBCTL) };
        if control == u8::MAX {
            // The function no longer decodes its BAR.
            return Err(HdaError::DeviceFailed);
        }
        if control & CORBCTL_RUN == 0 {
            // SAFETY: as above.
            if unsafe { self.bar0.read32(REG_GCTL) } & GCTL_CRST == 0 {
                narf_console::write_str("hda: controller lost its state; re-initialising\n");
                self.suspended.store(true, Ordering::Release);
                return Err(HdaError::Suspended);
            }
            self.irq.failed.store(true, Ordering::Release);
        }
        if self.irq.failed.load(Ordering::Acquire) {
            self.init_cmd_io()?;
            self.irq.failed.store(false, Ordering::Release);
            narf_console::write_str("hda: command rings restarted after a lost response\n");
        }
        Ok(())
    }
    /// `azx_get_response` timed out: the command and ring state.
    fn report_timeout(&self, verb: u32) {
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
    }
    /// Bounded IRQ/timer wait (`azx_rirb_get_response` sleeps on
    /// `bus->rirb_wq`). Every poll re-reads the ring, so a caller that
    /// re-polls at once (`block_on_spin`) sees the reply as soon as the codec
    /// posts it, while a task sleeps until the controller's interrupt or the
    /// 1 ms period. Cancellation poisons the transport until the next command
    /// restarts the rings (`ready_transport`), so a late response is never
    /// assigned to a subsequent command.
    /// # Safety
    /// Same exclusive device ownership as send_verb.
    pub async unsafe fn send_verb_async(&self, verb: u32) -> Result<u32, HdaError> {
        use core::{future::Future, task::Poll};
        enum Step {
            Reply(u32),
            Expired,
            Rearm,
        }
        let mut lease = self.acquire_command_async().await?;
        // The jack service never wakes a parked controller: its rings are
        // held in reset, and the resume marks every jack dirty anyway.
        if self.suspended.load(Ordering::Acquire) {
            return Err(HdaError::Suspended);
        }
        self.ready_transport()?;
        self.post(verb)?;
        lease.pending = true;
        let deadline = Deadline::after_ms(COMMAND_TIMEOUT_MS);
        let cad = (verb >> 28) as u8;
        loop {
            // Arm before checking the ring to close the completion/wake race.
            let waiter = self
                .irq_vector
                .map(|v| narf_interrupts::wait_for_irq_until(v, Deadline::after_ms(1)));
            let timer = waiter
                .is_none()
                .then(|| narf_time::SleepUntil::new(Deadline::after_ms(1).as_instant()));
            let mut waiter = core::pin::pin!(waiter);
            let mut timer = core::pin::pin!(timer);
            let step = core::future::poll_fn(|cx| {
                match self.response(cad) {
                    Err(error) => return Poll::Ready(Err(error)),
                    Ok(Some(value)) => return Poll::Ready(Ok(Step::Reply(value))),
                    Ok(None) => {}
                }
                if deadline.expired() {
                    return Poll::Ready(Ok(Step::Expired));
                }
                let ended = if let Some(waiter) = waiter.as_mut().as_pin_mut() {
                    waiter.poll(cx).is_ready()
                } else if let Some(timer) = timer.as_mut().as_pin_mut() {
                    timer.poll(cx).is_ready()
                } else {
                    true
                };
                if ended {
                    Poll::Ready(Ok(Step::Rearm))
                } else {
                    Poll::Pending
                }
            })
            .await?;
            match step {
                Step::Reply(value) => {
                    lease.pending = false;
                    return Ok(value);
                }
                Step::Expired => {
                    self.report_timeout(verb);
                    return Err(HdaError::CommandTimeout);
                }
                Step::Rearm => {}
            }
        }
    }
    /// A jack's state changed or must be re-read: mark it and wake the jack
    /// service.
    pub(super) fn note_jack_event(&self) {
        self.jack_dirty.store(true, Ordering::Release);
        let waker = self.jack_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }
    /// `snd_hdac_bus_update_rirb` with no command in flight: consume what
    /// the codecs posted since the last command. An unsolicited response is
    /// a jack event; a solicited one is a late reply to a command that
    /// already timed out (Linux logs it as spurious and drops it).
    pub(super) fn drain_unsolicited(&self) {
        let Ok(lease) = self.acquire_command() else {
            return;
        };
        // A parked controller reads RIRBWP 0: walking to it would consume
        // every stale slot. The resume restarts the rings and the cursors.
        if self.suspended.load(Ordering::Acquire) || self.irq.failed.load(Ordering::Acquire) {
            return;
        }
        let mut unsolicited = false;
        {
            let mut state = self.commands.lock();
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            let wp = unsafe { self.bar0.read16(REG_RIRBWP) };
            if wp != u16::MAX {
                // SAFETY: as above; acknowledge as `response` does so a
                // controller counting against RINTCNT keeps writing.
                unsafe {
                    let status = self.bar0.read8(REG_RIRBSTS);
                    self.bar0.write8(REG_RIRBSTS, status & 1);
                }
                while state.rp != (wp & 255) {
                    state.rp = (state.rp + 1) & 255;
                    if self.noncoherent {
                        self.rirb.sync(state.rp as usize * 8, 8);
                    }
                    fence(Ordering::Acquire);
                    // SAFETY: Masked RIRB index is within the owned 256-entry coherent completion ring.
                    let (res, extra) = unsafe {
                        let p = self.rirb.cpu_ptr::<u32>().add(state.rp as usize * 2);
                        (p.read_volatile(), p.add(1).read_volatile())
                    };
                    unsolicited |= extra & RIRB_EX_UNSOL != 0 && self.is_jack_tag(res);
                }
            }
        }
        drop(lease);
        if unsolicited {
            self.note_jack_event();
        }
    }
    /// Whether an unsolicited response carries a jack's tag
    /// (`AC_UNSOL_RES_TAG`, bits 31:26).
    fn is_jack_tag(&self, res: u32) -> bool {
        let tag = (res >> 26) & 0x3f;
        tag != 0 && self.jack_tags.load(Ordering::Acquire) & (1 << tag) != 0
    }
    /// `snd_hda_jack_detect_enable` for every jack-detectable pin
    /// (`is_jack_detectable`: presence detect, no NO_PRESENCE override,
    /// unsolicited capable), tagged in discovery order from 1 as Linux
    /// allocates jack tags.
    pub(super) fn enable_jack_events(&self) -> Result<(), HdaError> {
        let mut pins: Vec<(u8, u8)> = Vec::new();
        for path in self.outputs.iter().chain(self.inputs.iter()) {
            let graph = &self.graphs[path.codec];
            let Some(pin) = graph.widget(path.nodes.pin_nid) else {
                continue;
            };
            let detectable = pin.pin_caps.unwrap_or(0) & PINCAP_PRES_DETECT != 0
                && pin
                    .pin_config
                    .is_none_or(|config| config.misc & DEFCFG_MISC_NO_PRESENCE == 0)
                && pin.caps.unsol_capable();
            if detectable && !pins.contains(&(graph.addr, pin.nid)) {
                pins.push((graph.addr, pin.nid));
            }
        }
        // Tags are 6 bits and 0 is none.
        for (index, (cad, nid)) in pins.into_iter().enumerate().take(63) {
            let tag = index as u32 + 1;
            self.jack_tags.fetch_or(1 << tag, Ordering::AcqRel);
            self.pm_verb(cad, nid, VERB_SET_UNSOLICITED_ENABLE | tag)?;
        }
        Ok(())
    }
    pub fn stream_counts(&self) -> (u8, u8, u8) {
        self.counts
    }
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs
    }
    /// Linux `card->mixername`: "<vendor> <chip>" of the first codec with
    /// an audio function group (`snd_hda_codec_configure`).
    pub(super) fn mixer_name(&self) -> Option<alloc::string::String> {
        self.codecs
            .iter()
            .find(|codec| codec.afg_node_id.is_some())
            .map(|codec| codec_name(codec.vendor_id))
    }
    /// Linux `card->components`: "HDA:<vendor>,<subsystem>,<revision>" for
    /// each codec with a function group, space separated and without
    /// repeats (`snd_hda_codec_device_new` -> `snd_component_add`).
    pub(super) fn components(&self) -> Option<alloc::string::String> {
        let mut words: Vec<alloc::string::String> = Vec::new();
        for codec in self.codecs.iter().filter(|c| c.afg_node_id.is_some()) {
            let word = alloc::format!(
                "HDA:{:08x},{:08x},{:08x}",
                codec.vendor_id,
                codec.subsystem_id.unwrap_or(0),
                codec.revision_id
            );
            if !words.contains(&word) {
                words.push(word);
            }
        }
        (!words.is_empty()).then(|| words.join(" "))
    }
    /// `/proc/asound/cardN/codec#A` for every codec: Linux
    /// `print_codec_core_info`'s header, from the values probe read.
    pub(super) fn codec_proc(&self) -> Vec<(u8, alloc::string::String)> {
        self.codecs
            .iter()
            .map(|codec| {
                let mut text = alloc::format!(
                    "Codec: {}\nAddress: {}\n",
                    codec_name(codec.vendor_id),
                    codec.addr
                );
                if codec.afg_node_id.is_some() {
                    let function = self
                        .graphs
                        .iter()
                        .find(|graph| graph.addr == codec.addr)
                        .map_or(0, |graph| graph.afg_function);
                    text.push_str(&alloc::format!(
                        "AFG Function Id: 0x{:x} (unsol {})\n",
                        function & 0xff,
                        (function >> 8) & 1
                    ));
                }
                text.push_str(&alloc::format!(
                    "Vendor Id: 0x{:08x}\nSubsystem Id: 0x{:08x}\nRevision Id: 0x{:x}\n\
                     No Modem Function Group found\n",
                    codec.vendor_id,
                    codec.subsystem_id.unwrap_or(0),
                    codec.revision_id
                ));
                (codec.addr, text)
            })
            .collect()
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

    /// Whether the service task has work: a stream's DMA engine runs (its
    /// position needs tracking), or the controller has no interrupt route,
    /// so nothing else acknowledges its RIRB / stream status (a controller
    /// that counts responses against RINTCNT stops writing them until it is
    /// acknowledged).
    pub(super) fn needs_service(&self) -> bool {
        self.irq_vector.is_none() || self.streams.iter().any(|s| s.lock().is_running())
    }

    /// Wake the parked stream service task (a stream started, or the
    /// controller is going away).
    pub(super) fn kick_service(&self) {
        let waker = self.service_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Parks the stream service task until it has work (`needs_service`) or the
/// controller is gone (`Ready(None)`). Holds no strong reference while parked, so the
/// controller can still be dropped, which wakes it.
struct StreamsIdle<'a>(&'a alloc::sync::Weak<IntelHda>);

impl core::future::Future for StreamsIdle<'_> {
    type Output = Option<()>;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<()>> {
        let Some(dev) = self.0.upgrade() else {
            return core::task::Poll::Ready(None);
        };
        // Register, then re-check, so a start racing this poll wakes us.
        *dev.service_waker.lock() = Some(cx.waker().clone());
        if dev.needs_service() {
            dev.service_waker.lock().take();
            return core::task::Poll::Ready(Some(()));
        }
        core::task::Poll::Pending
    }
}

/// Linux `jackpoll_interval` for a controller that takes no interrupt
/// (`AZX_DRIVER_LOONGSON`, `bus->not_use_interrupts`: 1500 ms). Any other
/// controller is driven by unsolicited responses alone (`jackpoll_ms`
/// defaults to 0).
const JACKPOLL_MS: u64 = 1500;

/// The controller's jack presence service (Linux `hda_jack`): an unsolicited
/// response marks the jacks dirty (`snd_hda_jack_unsol_event`) and their
/// state is re-read (`snd_hda_jack_report_sync`) with commands that sleep on
/// the response (`send_verb_async`), so a codec that stopped answering never
/// holds the CPU. Every jack is re-read once at start, as
/// `snd_hda_jack_report_sync` runs at codec build.
pub(super) async fn jack_service(weak: alloc::sync::Weak<IntelHda>) {
    loop {
        let (irq, poll) = {
            let Some(dev) = weak.upgrade() else {
                return;
            };
            // Armed before the drain: a response posted after it raises the
            // interrupt that ends the wait.
            let irq = dev.irq_vector.map(narf_interrupts::wait_for_irq);
            dev.drain_unsolicited();
            let poll = dev
                .irq_vector
                .is_none()
                .then(|| narf_time::SleepUntil::new(Deadline::after_ms(JACKPOLL_MS).as_instant()));
            (irq, poll)
        };
        if (JackWait {
            weak: &weak,
            irq,
            poll,
        })
        .await
        .is_none()
        {
            return;
        }
        let Some(dev) = weak.upgrade() else {
            return;
        };
        if !dev.suspended.load(Ordering::Acquire) && dev.jack_dirty.swap(false, Ordering::AcqRel) {
            // A jack event on suspended codecs resumes them first, as
            // `hda_jackpoll_work` wraps the re-read in snd_hda_power_up_pm.
            if dev.codecs_suspended.load(Ordering::Acquire) {
                let _ = dev.ensure_active();
            }
            let _ = dev.refresh_jacks_async().await;
        }
    }
}

/// Parks the jack service until a jack is dirty, the controller interrupts
/// (its RIRB may hold an unsolicited response) or, without an interrupt,
/// the jackpoll period ends. `None` once the controller is gone. Holds no
/// strong reference while parked.
struct JackWait<'a> {
    weak: &'a alloc::sync::Weak<IntelHda>,
    irq: Option<narf_interrupts::WaitForIrq>,
    poll: Option<narf_time::SleepUntil>,
}

impl core::future::Future for JackWait<'_> {
    type Output = Option<()>;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<()>> {
        use core::task::Poll;
        let this = self.get_mut();
        let Some(dev) = this.weak.upgrade() else {
            return Poll::Ready(None);
        };
        let ready = |dev: &IntelHda| {
            dev.jack_dirty.load(Ordering::Acquire) && !dev.suspended.load(Ordering::Acquire)
        };
        if ready(&dev) {
            return Poll::Ready(Some(()));
        }
        // Register, then re-check, so an event racing this poll wakes us.
        *dev.jack_waker.lock() = Some(cx.waker().clone());
        if ready(&dev) {
            dev.jack_waker.lock().take();
            return Poll::Ready(Some(()));
        }
        if let Some(irq) = this.irq.as_mut() {
            if core::pin::Pin::new(irq).poll(cx).is_ready() {
                return Poll::Ready(Some(()));
            }
        }
        if let Some(timer) = this.poll.as_mut() {
            if core::pin::Pin::new(timer).poll(cx).is_ready() {
                // Polling re-reads every jack (`snd_hda_jack_set_dirty_all`),
                // and like `hda_jackpoll_work`'s power up/down it marks the
                // controller busy, so a polled controller stays up.
                dev.jack_dirty.store(true, Ordering::Release);
                dev.mark_last_busy();
                return Poll::Ready(Some(()));
            }
        }
        Poll::Pending
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
//   D3hot BAR. The live idle path is the autosuspend service below
//   (`autosuspend`): an open PCM holds a power reference, and the
//   controller parks (codecs D3, then engines off and link reset; PCI
//   stays D0) `power_save` after the last one went, as Linux runtime PM
//   suspends the codecs and then the controller.
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
    /// The power state a failed suspend reports.
    fn pm_state(&self) -> alloc::string::String {
        let streams: Vec<(bool, bool, bool)> = self
            .streams
            .iter()
            .map(|s| {
                let state = s.lock();
                let ring = state.ring.as_ref();
                (
                    state.claimed,
                    ring.is_some_and(|r| r.prepared),
                    ring.is_some_and(|r| r.running),
                )
            })
            .collect();
        alloc::format!(
            "suspended {}, codecs suspended {}, power refs {}, pm lock {}, lease {}, \
             streams (claimed, prepared, running) {:?}",
            self.suspended.load(Ordering::Acquire),
            self.codecs_suspended.load(Ordering::Acquire),
            self.power_refs.load(Ordering::Acquire),
            self.pm.load(Ordering::Acquire),
            self.busy.load(Ordering::Acquire),
            streams
        )
    }

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
        if d3 {
            self.cleanup_all_streams();
        }
        let mut switched = Vec::new();
        for codec in &self.codecs {
            let Some(nid) = codec.afg_node_id else {
                continue;
            };
            // The verb targets the codec's own AFG node.
            let verb = make_verb(
                codec.addr,
                nid,
                crate::hda_codec::verb::SET_POWER_STATE | if d3 { 3 } else { 0 },
            );
            // Part of a PM transition: no power-up, no `suspended` gate.
            if let Err(e) = self.exec_verb(verb, false) {
                for (addr, nid) in switched {
                    // Best-effort rollback; the original error wins.
                    let _ = self.exec_verb(
                        make_verb(addr, nid, crate::hda_codec::verb::SET_POWER_STATE),
                        false,
                    );
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
    /// Busy when any stream is running or prepared. The runtime-PM callback
    /// (`HdaRuntimePm`, constructed by kernel tests only so far, like the
    /// struct itself); system suspend uses `system_suspend`.
    #[allow(dead_code)]
    fn quiesce(&self) -> Result<(), HdaError> {
        self.quiesce_with(|| true, false)
    }

    /// [`Self::quiesce`] that also refuses while `idle` is false, checked
    /// again under the command lease right before the park (the autosuspend
    /// passes "no power reference held").
    fn quiesce_with(&self, idle: impl Fn() -> bool, arm_wake: bool) -> Result<(), HdaError> {
        let _pm = self.lock_pm()?;
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.streams_idle() || !idle() {
            return Err(HdaError::Busy);
        }
        self.park(&idle, arm_wake)
    }

    /// Linux system suspend: the PCM core suspends every prepared or running
    /// stream first (`snd_pcm_suspend_all`: DMA stops; HDA has no
    /// SNDRV_PCM_INFO_RESUME, so the stream is prepared again after resume),
    /// the codecs are force-suspended (`hda_codec_pm_suspend`) and
    /// `azx_suspend` shuts the chip down, whatever runtime PM holds. Only a
    /// stream whose DMA does not stop fails it.
    fn system_suspend(&self) -> Result<(), HdaError> {
        let _pm = self.lock_pm()?;
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        for stream in &self.streams {
            stream
                .lock()
                .stop(self)
                .map_err(|_| HdaError::DeviceFailed)?;
        }
        self.park(&|| true, false)
    }

    /// The park itself, under the PM lock: codecs to D3 (unless their own
    /// suspend already put them there: `pm_runtime_force_suspend` skips a
    /// runtime-suspended codec), then the controller reset. `idle` is
    /// checked again under the command lease.
    fn park(&self, idle: &dyn Fn() -> bool, arm_wake: bool) -> Result<(), HdaError> {
        let codecs_to_d3 = !self.codecs_suspended.load(Ordering::Acquire);
        if codecs_to_d3 {
            self.set_codec_power(true)?;
        }
        // Park under the command lease: a command either finished before
        // this point or, once it holds the lease, sees `suspended` and never
        // posts into the rings the reset below stops.
        let lease = match self.acquire_command_blocking() {
            Ok(lease) => lease,
            Err(error) => {
                if codecs_to_d3 {
                    let _ = self.set_codec_power(false);
                }
                return Err(error);
            }
        };
        if !self.streams_idle() || !idle() {
            drop(lease);
            if codecs_to_d3 {
                let _ = self.set_codec_power(false);
            }
            return Err(HdaError::Busy);
        }
        // Set before the reset: the engines stop below whether or not the
        // reset acknowledges, and a half-parked controller must take the
        // full reinit on the next wake rather than be trusted.
        self.suspended.store(true, Ordering::Release);
        if arm_wake {
            // `azx_runtime_suspend`: WAKEEN for every codec slot, so a codec
            // state change while parked sets STATESTS (resume well).
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            unsafe {
                self.bar0
                    .write16(REG_WAKEEN, self.bar0.read16(REG_WAKEEN) | STATESTS_INT_MASK);
                self.bar0
                    .write16(REG_STATESTS, self.bar0.read16(REG_STATESTS));
            }
        }
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
        let reset = wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 == 0, 100);
        drop(lease);
        if reset {
            Ok(())
        } else {
            Err(HdaError::ResetTimeout)
        }
    }

    /// Reverse of quiesce: reset the controller, reprogram the
    /// command rings from the retained CORB/RIRB buffers (mirrors
    /// `initialize`'s engine sequence), restore IRQs, codecs back
    /// to D0. Stream descriptors are NOT restored: suspend refused
    /// running or prepared streams, so every stream needs a fresh
    /// prepare after resume. Clears the sticky command-transport
    /// failure: the rings were reset, so a pre-suspend verb timeout
    /// must not poison post-resume verbs (`exec_verb` refuses
    /// while `irq.failed` is set). Idempotent; serialised with
    /// `quiesce` by the PM lock.
    fn reinit(&self) -> Result<(), HdaError> {
        // One wake at a time: a second caller that also found the
        // controller parked waits here, then finds it awake.
        let _pm = self.lock_pm()?;
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        // `suspended` stays set until the codecs are back, so a jack
        // command in between is refused rather than sent to a codec the
        // restart has not re-initialised yet.
        self.restart_controller()?;
        self.resume_codecs()?;
        self.suspended.store(false, Ordering::Release);
        // A wake with no reference held (a control read) parks again after
        // the delay.
        self.mark_last_busy();
        self.kick_pm();
        Ok(())
    }

    /// Linux `hda_call_codec_resume` for every codec: D0, the codec init
    /// (the Realtek coef tables, a quirk's coef sequence, the HP-pin tail),
    /// unsolicited responses re-armed and every jack marked dirty. Runs
    /// with the PM lock held, after a controller restart or on its own for
    /// a controller that only suspended its codecs.
    fn resume_codecs(&self) -> Result<(), HdaError> {
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
        let _ = self.enable_jack_events();
        self.codecs_suspended.store(false, Ordering::Release);
        self.note_jack_event();
        Ok(())
    }

    /// The codec half of a park on its own (Linux `hda_codec_runtime_suspend`
    /// for a controller `azx_runtime_idle` keeps up): the codecs go to D3,
    /// the link and the command rings stay up. `idle` is checked again under
    /// the command lease, as for a full park.
    fn suspend_codecs_if(&self, idle: impl Fn() -> bool) -> Result<(), HdaError> {
        let _pm = self.lock_pm()?;
        if self.suspended.load(Ordering::Acquire) || self.codecs_suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.streams_idle() || !idle() {
            return Err(HdaError::Busy);
        }
        self.set_codec_power(true)?;
        let lease = self.acquire_command_blocking();
        if lease.is_err() || !self.streams_idle() || !idle() {
            drop(lease);
            let _ = self.set_codec_power(false);
            return Err(HdaError::Busy);
        }
        // Under the lease: a gated command from here on resumes the codecs.
        self.codecs_suspended.store(true, Ordering::Release);
        drop(lease);
        Ok(())
    }

    /// The wake of a controller that only suspended its codecs.
    fn resume_codecs_only(&self) -> Result<(), HdaError> {
        let _pm = self.lock_pm()?;
        if !self.codecs_suspended.load(Ordering::Acquire) || self.suspended.load(Ordering::Acquire)
        {
            return Ok(());
        }
        self.resume_codecs()?;
        self.mark_last_busy();
        self.kick_pm();
        Ok(())
    }

    /// The hardware half of a wake: link reset, command I/O and interrupt
    /// enables, under the command lease so no command is in flight across
    /// the reset. Clears the command-transport failure: the rings were
    /// restarted, so an earlier timeout no longer describes them.
    fn restart_controller(&self) -> Result<(), HdaError> {
        let _lease = self.acquire_command_blocking()?;
        // The codecs are already known; the wake does not re-probe them.
        reset_link(self.bar0)?;
        // `azx_int_clear` clears STATESTS after the link reset, and
        // `azx_runtime_resume` disarms the codec wake.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0
                .write16(REG_STATESTS, self.bar0.read16(REG_STATESTS));
            self.bar0.write16(
                REG_WAKEEN,
                self.bar0.read16(REG_WAKEEN) & !STATESTS_INT_MASK,
            );
        }
        // The shadow cursors restart with the ring pointers inside.
        self.init_cmd_io()?;
        // SAFETY: Controller owns this live BAR; fixed register
        // offsets are inside the validated window.
        unsafe {
            self.bar0.write32(
                REG_INTCTL,
                if self.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        self.irq.failed.store(false, Ordering::Release);
        Ok(())
    }

    /// Linux `snd_hda_power_up_pm`: wake a parked controller, and restart a
    /// failed command transport, before any path that sends verbs or
    /// programs streams.
    pub(super) fn ensure_active(&self) -> Result<(), HdaError> {
        if self.suspended.load(Ordering::Acquire) {
            self.reinit()?;
        }
        if self.codecs_suspended.load(Ordering::Acquire) {
            self.resume_codecs_only()?;
        }
        // A failed transport (a lost response, a latched controller error)
        // is restarted here too: the stream paths refuse one, and nothing
        // else may come by to restart it before the next open or prepare.
        if self.irq.failed.load(Ordering::Acquire) {
            let lease = self.acquire_command_blocking()?;
            let ready = self.ready_transport();
            drop(lease);
            if ready == Err(HdaError::Suspended) {
                return self.reinit();
            }
            ready?;
        }
        Ok(())
    }

    /// `pm_runtime_mark_last_busy`: every command marks it when its lease
    /// goes (Linux `codec_exec_verb` ends in `snd_hda_power_down_pm`, whose
    /// `pm_runtime_put_autosuspend` marks it), and so does a reference drop.
    fn mark_last_busy(&self) {
        self.last_busy_ns
            .store(narf_time::monotonic_ns(), Ordering::Release);
    }

    /// Record a converter a configure gave a stream (Linux `hda_cvt_setup`).
    pub(super) fn note_cvt_setup(&self, cad: u8, nid: u8) {
        let mut setups = self.cvt_setups.lock();
        if !setups.contains(&(cad, nid)) {
            setups.push((cad, nid));
        }
    }

    /// Linux `hda_cleanup_all_streams` at codec suspend: every converter
    /// still assigned a stream gets SET_CHANNEL_STREAMID 0 and
    /// SET_STREAM_FORMAT 0 (`really_cleanup_stream`). Best effort, as in
    /// Linux: a failed write does not stop the suspend.
    fn cleanup_all_streams(&self) {
        let setups = core::mem::take(&mut *self.cvt_setups.lock());
        for (cad, nid) in setups {
            let _ = self.pm_verb(cad, nid, VERB_SET_CONVERTER_STREAM);
            let _ = self.pm_verb(cad, nid, VERB_SET_CONVERTER_FORMAT);
        }
    }

    /// Whether a codec signalled a state change the park armed a wake for
    /// (STATESTS under WAKEEN, both in the resume well the link reset does
    /// not clear).
    fn codec_wake_pending(&self) -> bool {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let (status, wake) =
            unsafe { (self.bar0.read16(REG_STATESTS), self.bar0.read16(REG_WAKEEN)) };
        status != u16::MAX && status & wake & STATESTS_INT_MASK != 0
    }

    /// Linux `snd_hda_power_up` (`pm_runtime_get_sync`): take a power
    /// reference, then wake the controller. A PCM open holds one until close
    /// (`azx_pcm_open` / `azx_pcm_close`).
    pub(super) fn power_up(&self) -> Result<(), HdaError> {
        self.power_refs.fetch_add(1, Ordering::AcqRel);
        if let Err(error) = self.ensure_active() {
            self.power_down();
            return Err(error);
        }
        Ok(())
    }

    /// Linux `snd_hda_power_down` (`pm_runtime_put_autosuspend`): drop a
    /// power reference and mark the controller busy; the autosuspend service
    /// parks it `autosuspend_ms` later if nothing took a reference since.
    pub(super) fn power_down(&self) {
        self.mark_last_busy();
        let refs = &self.power_refs;
        let _ = refs.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        self.kick_pm();
    }

    /// Wake the autosuspend service: a reference went, or a wake left the
    /// controller up with none held.
    fn kick_pm(&self) {
        let waker = self.pm_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// One autosuspend decision (Linux `rpm_suspend` under the autosuspend
    /// timer): held while a reference or a running stream is; otherwise
    /// park once the controller has been idle `autosuspend_ms`. The park
    /// suspends the codecs first and then the controller, as Linux runs
    /// `hda_codec_runtime_suspend` before `azx_runtime_suspend`. A park that
    /// cannot run now is retried a whole delay later.
    pub(super) fn autosuspend(&self) -> Autosuspend {
        if self.suspended.load(Ordering::Acquire) {
            // `azx_runtime_resume` on a codec wake: a state change while
            // parked (a hotplug) wakes the controller and its codecs, which
            // re-read their jacks; the delay then runs again.
            if self.codec_wake_pending() && self.ensure_active().is_ok() {
                return Autosuspend::Wait(self.autosuspend_ms.load(Ordering::Acquire));
            }
            return Autosuspend::Parked;
        }
        if self.codecs_suspended.load(Ordering::Acquire) {
            return Autosuspend::CodecsSuspended;
        }
        if self.power_refs.load(Ordering::Acquire) != 0 || !self.streams_idle() {
            return Autosuspend::Held;
        }
        let delay = self.autosuspend_ms.load(Ordering::Acquire);
        let idle_ms = narf_time::monotonic_ns()
            .saturating_sub(self.last_busy_ns.load(Ordering::Acquire))
            / 1_000_000;
        if idle_ms < delay {
            return Autosuspend::Wait(delay - idle_ms);
        }
        let unheld = || self.power_refs.load(Ordering::Acquire) == 0;
        // `azx_runtime_idle`: without AZX_DCAPS_PM_RUNTIME the controller
        // stays up and only the codecs suspend.
        let parked = if self.runtime_pm.load(Ordering::Acquire) {
            // `azx_runtime_suspend` arms the codec wake first.
            self.quiesce_with(unheld, true)
                .map(|()| Autosuspend::Parked)
        } else {
            self.suspend_codecs_if(unheld)
                .map(|()| Autosuspend::CodecsSuspended)
        };
        match parked {
            Ok(step) => step,
            Err(_) => {
                self.mark_last_busy();
                Autosuspend::Wait(delay)
            }
        }
    }
}

/// What the autosuspend service does next.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Autosuspend {
    /// A power reference or a running stream holds the controller up.
    Held,
    /// Idle, but not for the whole delay yet: look again in this many ms.
    Wait(u64),
    /// Parked (codecs D3, link in reset), watched for a codec wake.
    Parked,
    /// Only the codecs are suspended; the controller stays up.
    CodecsSuspended,
}

/// The controller's autosuspend timer (Linux runtime PM's autosuspend for
/// the codecs, then the controller). Sleeps out the delay while the
/// controller is idle and parks with no strong reference held while it is
/// held up or parked; a reference drop or a wake wakes it.
pub(super) async fn autosuspend_service(weak: alloc::sync::Weak<IntelHda>) {
    loop {
        let step = {
            let Some(dev) = weak.upgrade() else {
                return;
            };
            dev.autosuspend()
        };
        match step {
            Autosuspend::Wait(ms) => {
                narf_time::SleepUntil::new(Deadline::after_ms(ms.max(1)).as_instant()).await;
            }
            // A parked controller is watched for a codec wake.
            Autosuspend::Parked => {
                narf_time::SleepUntil::new(Deadline::after_ms(WAKE_POLL_MS).as_instant()).await;
            }
            Autosuspend::Held | Autosuspend::CodecsSuspended => {
                if PmIdle(&weak).await.is_none() {
                    return;
                }
            }
        }
    }
}

/// Parks the autosuspend service until the controller could be parked (up,
/// no reference, no running stream), or `None` once it is gone.
struct PmIdle<'a>(&'a alloc::sync::Weak<IntelHda>);

impl core::future::Future for PmIdle<'_> {
    type Output = Option<()>;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<()>> {
        let Some(dev) = self.0.upgrade() else {
            return core::task::Poll::Ready(None);
        };
        let idle = |dev: &IntelHda| {
            !dev.suspended.load(Ordering::Acquire)
                && !dev.codecs_suspended.load(Ordering::Acquire)
                && dev.power_refs.load(Ordering::Acquire) == 0
                && dev.streams_idle()
        };
        if idle(&dev) {
            return core::task::Poll::Ready(Some(()));
        }
        // Register, then re-check, so a reference drop racing this poll
        // wakes us.
        *dev.pm_waker.lock() = Some(cx.waker().clone());
        if idle(&dev) {
            dev.pm_waker.lock().take();
            return core::task::Poll::Ready(Some(()));
        }
        core::task::Poll::Pending
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
            if let Err(error) = dev.system_suspend() {
                // What a refused system suspend needs on the console.
                narf_console::write_str(&alloc::format!(
                    "hda: system suspend of {:#x} failed: {:?}; {}\n",
                    dev.bar0.phys.raw(),
                    error,
                    dev.pm_state()
                ));
                return Err(match error {
                    HdaError::Busy => E::Busy,
                    _ => E::DriverError,
                });
            }
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
/// Held by a park or a wake ([`IntelHda::lock_pm`]).
struct PmLock<'a>(&'a IntelHda);
impl Drop for PmLock<'_> {
    fn drop(&mut self) {
        self.0.pm.store(false, Ordering::Release);
    }
}
impl Drop for CommandLease<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.dev.irq.failed.store(true, Ordering::Release);
        }
        self.dev.mark_last_busy();
        self.dev.busy.store(false, Ordering::Release);
    }
}
impl Drop for IntelHda {
    fn drop(&mut self) {
        // The parked service tasks see the controller gone and exit.
        self.kick_service();
        self.kick_pm();
        let waker = self.jack_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
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
    // SAFETY: Bus probing has exclusively claimed this function and its BAR.
    let brought_up = unsafe { IntelHda::bring_up(&device, &cap) };
    match brought_up {
        Ok(dev) => register_controller(&device, dev),
        Err(error) if retries_probe(&device, error) => {
            narf_console::write_str(&alloc::format!(
                "hda: {:04x}:{:04x} codec probe failed ({:?}); retrying every second\n",
                device.id.vendor,
                device.id.device,
                error
            ));
            // Linux returns 0 from the probe and keeps the device ("keep
            // things up") while the delayed probe work retries.
            narf_scheduler::spawn(retry_probe(device, cap));
            Ok(())
        }
        Err(error) => Err(probe_error(error)),
    }
}

fn probe_error(error: HdaError) -> narf_bus::ProbeError {
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
}

/// Linux `AZX_DCAPS_RETRY_PROBE` (the AMD SB preset): a codec that fails to
/// configure on an AMD platform controller is retried rather than final.
/// A link with no codec is not retried; it comes up with an empty card.
fn retries_probe(device: &BusDevice, error: HdaError) -> bool {
    super::amd_sb_preset(device.id.vendor, device.id.device)
        && matches!(error, HdaError::CommandTimeout)
}

/// Linux `azx_probe_continue`: `++hda->probe_retry < 60`, one second apart.
const PROBE_ATTEMPTS: u32 = 60;

/// The delayed probe work of an AMD platform controller whose codecs did
/// not come up at boot: bring the controller up again every second until a
/// codec answers, as Linux re-runs `azx_codec_configure` from `probe_work`.
async fn retry_probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) {
    let (vendor, id) = (device.id.vendor, device.id.device);
    for attempt in 1..PROBE_ATTEMPTS {
        narf_time::SleepUntil::new(Deadline::after_ms(1000).as_instant()).await;
        // SAFETY: probe handed this task the claimed function and its BAR;
        // nothing else drives the controller until it registers.
        match unsafe { IntelHda::bring_up(&device, &cap) } {
            Ok(dev) => {
                let result = register_controller(&device, dev);
                narf_console::write_str(&alloc::format!(
                    "hda: {:04x}:{:04x} codec probe retry {}: {:?}\n",
                    vendor,
                    id,
                    attempt,
                    result
                ));
                return;
            }
            Err(error) if retries_probe(&device, error) => {}
            Err(error) => {
                narf_console::write_str(&alloc::format!(
                    "hda: {:04x}:{:04x} codec probe retry {} failed: {:?}\n",
                    vendor,
                    id,
                    attempt,
                    error
                ));
                return;
            }
        }
    }
    narf_console::write_str(&alloc::format!(
        "hda: {:04x}:{:04x} cannot probe codecs, giving up\n",
        vendor,
        id
    ));
}

/// Publish a brought-up controller: sound card, service tasks, bound-driver
/// record and system PM.
fn register_controller(device: &BusDevice, dev: IntelHda) -> Result<(), narf_bus::ProbeError> {
    let dev = Arc::new(dev);
    if !dev.ready {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // Linux azx_create: card->driver "HDA-Intel", the driver type's short
    // name, and "<short name> at 0x<BAR> irq <n>" as the long name; the id
    // is the short name's last word, made unique by the sound registry.
    let short_name = super::card_short_name(device.id.vendor, device.id.device);
    *dev.long_name.lock() = alloc::format!(
        "{} at 0x{:x} irq {}",
        short_name,
        dev.bar0.phys.raw(),
        dev.irq_vector.map_or(-1, i32::from)
    );
    let info = narf_drivers_sound::CardInfo {
        index: 0,
        driver: "HDA-Intel",
        id: super::card_id(short_name),
        name: short_name,
        // One playback PCM per HDMI pin besides the analog one (Linux
        // patch_hdmi; see `pcm_layout`).
        playback_count: if dev.outputs.is_empty() {
            0
        } else {
            dev.pcm_layout().len() as u32
        },
        capture_count: u32::from(dev.input.lock().is_some()),
    };
    let card = narf_drivers_sound::register_hardware_card_at(
        info,
        Arc::new(super::stream::Card(dev.clone())),
        Some(device.addr),
    );
    dev.card.store(card, Ordering::Release);
    CONTROLLERS.lock().push((device.addr, dev.clone(), card));
    // Stream service: position tracking and xrun detection, every 2 ms
    // while a stream runs. With no stream running there is nothing to track
    // and the interrupt handler acknowledges controller status itself, so
    // the task parks until a start wakes it: an idle controller arms no
    // timer, as Linux's interrupt-driven `azx_interrupt` arms none. A
    // controller without an interrupt route keeps the 2 ms service, which
    // is all that acknowledges its status.
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            if StreamsIdle(&weak).await.is_none() {
                break;
            }
            narf_time::usleep_range(2_000, 2_500).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            dev.service();
        }
    });
    narf_scheduler::spawn(jack_service(Arc::downgrade(&dev)));
    // Runtime PM: park the controller `power_save` after the last PCM closed.
    narf_scheduler::spawn(autosuspend_service(Arc::downgrade(&dev)));
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
