//! Intel HDMI/DP display codecs through the display-audio component. Linux
//! references: sound/hda/codecs/hdmi/intelhdmi.c (the codec ids and models,
//! intel_haswell_enable_all_pins, intel_haswell_fixup_enable_dp12,
//! haswell_set_power_state, intel_pin2port / intel_port2pin,
//! intel_pin_eld_notify, haswell_verify_D0, intel_verify_pin_cvt_connect,
//! intel_not_share_assigned_cvt, i915_pin_cvt_fixup, i915_hsw_setup_stream),
//! sound/hda/codecs/hdmi/hdmi.c (sync_eld_via_acomp, update_eld,
//! snd_hda_hdmi_generic_pcm_prepare, snd_hda_hdmi_setup_audio_infoframe,
//! hdmi_pin_setup_infoframe, snd_hda_hdmi_setup_stream, hdmi_pin_hbr_setup),
//! sound/hda/core/hdmi_chmap.c (the standard slot mapping) and
//! sound/hda/core/{i915.c,component.c} (snd_hdac_i915_init,
//! snd_hdac_acomp_get_eld, snd_hdac_sync_audio_rate,
//! snd_hdac_display_power).
//!
//! Linux binds an Intel HDMI codec only when i915 bound the audio component
//! (`alloc_intel_hdmi`: "No i915 binding for Intel HDMI/DP codec" otherwise).
//! The same rule holds here: the component is the Intel display's, bound
//! only under `narf.intel.hdmi14_ext=1`, and without it an Intel HDMI codec
//! gets no vendor verb, no path and no port, exactly as before.
//!
//! Deviations, each a simplification: converters are assigned to pins once,
//! at discovery (the first free converter in each pin's connection list),
//! and each pin keeps its own PCM, where Linux picks a converter at PCM open
//! and maps PCMs to pins dynamically; only device entry 0 of each pin is
//! used (no DP MST audio, which Linux also leaves as a todo); the silent
//! stream and keep-alive are not modelled; the vendor verbs are re-issued
//! before the AFG's D0 at stream configuration, not at every power
//! transition; display power is dropped at codec suspend.
use super::*;
use crate::hda_codec::{self, AudioPath, Codec, IntelHdmiModel, WidgetType};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use narf_drivers_sound::display_audio::{self as acomp, DisplayAudioCodec, DisplayAudioComponent};
use narf_lib::sync::IrqSafeSpinLock;

/// `INTEL_GET_VENDOR_VERB` / `INTEL_SET_VENDOR_VERB` and their bits.
pub(super) const INTEL_GET_VENDOR_VERB: u32 = 0xf81;
pub(super) const INTEL_SET_VENDOR_VERB: u32 = 0x781;
/// `INTEL_EN_DP12`: enable DP 1.2 features.
pub(super) const INTEL_EN_DP12: u32 = 0x02;
/// `INTEL_EN_ALL_PIN_CVTS`: enable the second and third pins and converters.
pub(super) const INTEL_EN_ALL_PIN_CVTS: u32 = 0x01;

const GET_CONNECT_SEL: u32 = 0xf01;
const SET_CONNECT_SEL: u32 = 0x701;
const GET_POWER_STATE: u32 = 0xf05;
const SET_POWER_STATE: u32 = 0x705;
const AC_PWRST_ERROR: u32 = 1 << 8;
const GET_CVT_CHAN_COUNT: u32 = 0xf2d;
const SET_CVT_CHAN_COUNT: u32 = 0x72d;
const SET_HDMI_DIP_INDEX: u32 = 0x730;
const SET_HDMI_DIP_DATA: u32 = 0x731;
const SET_HDMI_DIP_XMIT: u32 = 0x732;
const GET_HDMI_DIP_DATA: u32 = 0xf31;
const GET_HDMI_DIP_XMIT: u32 = 0xf32;
const SET_HDMI_CHAN_SLOT: u32 = 0x734;
const AC_DIPXMIT_DISABLE: u32 = 0x00;
const AC_DIPXMIT_BEST: u32 = 0xc0;
const GET_DIGI_CONVERT_1: u32 = 0xf0d;
const SET_DIGI_CONVERT_3: u32 = 0x73e;
const AC_DIG3_ICT: u32 = 0xf;
const GET_PIN_WIDGET_CONTROL: u32 = 0xf07;
const AC_PINCTL_EPT: u32 = 0x3;
const AC_PINCTL_EPT_HBR: u32 = 3;
const AC_PINCAP_HBR: u32 = 1 << 27;
/// `AMP_OUT_UNMUTE` (Set Amp Gain/Mute, output, both channels, gain 0).
const AMP_OUT_UNMUTE: u32 = 0xb000;
/// `ELD_MAX_SIZE`.
const ELD_MAX_SIZE: usize = 256;

/// The vendor-verb node of a model (`spec->vendor_nid`, set by
/// `intel_hsw_common_init`); Valleyview and the PCH codecs have none.
pub(super) const fn vendor_nid(model: IntelHdmiModel) -> Option<u8> {
    match model {
        IntelHdmiModel::Hsw => Some(0x08),
        IntelHdmiModel::Glk => Some(0x0b),
        IntelHdmiModel::Icl | IntelHdmiModel::Tgl | IntelHdmiModel::Adlp => Some(0x02),
        IntelHdmiModel::Byt | IntelHdmiModel::Cpt => None,
    }
}

/// The pin-to-port table (`spec->port_map`): the value is the pin NID, the
/// index the display port (`enum port`). `probe_i915_icl_hdmi` and
/// `probe_i915_tgl_hdmi` (which Alder Lake-P to Nova Lake share); the
/// older models have none and use [`intel_base_nid`].
pub(super) const fn port_map(model: IntelHdmiModel) -> &'static [u8] {
    match model {
        IntelHdmiModel::Icl => &[0x0, 0x4, 0x6, 0x8, 0xa, 0xb],
        IntelHdmiModel::Tgl | IntelHdmiModel::Adlp => {
            &[0x4, 0x6, 0x8, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
        }
        _ => &[],
    }
}

/// `intel_base_nid`: pin 4 is port B on Ironlake and Valleyview (codec ids
/// 0x80860054, 0x80862804, 0x80862882), pin 5 elsewhere.
pub(super) const fn intel_base_nid(codec_id: u32) -> u8 {
    match codec_id {
        0x8086_0054 | 0x8086_2804 | 0x8086_2882 => 4,
        _ => 5,
    }
}

/// `intel_pin2port`: the display port behind `pin`, or `None` (-1).
pub(super) fn intel_pin2port(model: IntelHdmiModel, codec_id: u32, pin: u32) -> Option<i32> {
    let map = port_map(model);
    if map.is_empty() {
        let base = u32::from(intel_base_nid(codec_id));
        return (base..base + 3)
            .contains(&pin)
            .then(|| (pin - base + 1) as i32);
    }
    map.iter()
        .position(|&nid| u32::from(nid) == pin)
        .map(|port| port as i32)
}

/// `intel_port2pin`: the pin of display port `port`, or `None` (0).
pub(super) fn intel_port2pin(model: IntelHdmiModel, codec_id: u32, port: i32) -> Option<u8> {
    let map = port_map(model);
    if map.is_empty() {
        // "we assume only from port-B to port-D"
        return (1..=3)
            .contains(&port)
            .then(|| port as u8 + intel_base_nid(codec_id) - 1);
    }
    usize::try_from(port)
        .ok()
        .and_then(|p| map.get(p).copied())
        .filter(|&pin| pin != 0)
}

/// The bound display half (`bus->audio_component`), if the Intel display
/// registered one.
fn component() -> Option<&'static (dyn DisplayAudioComponent + Sync)> {
    acomp::display_audio_component()
}

/// `alloc_intel_hdmi`'s precondition: an Intel HDMI codec binds only with
/// the display's audio component. The model of root-node id `codec_id`
/// when it does.
pub(super) fn bound_model(codec_id: u32) -> Option<IntelHdmiModel> {
    hda_codec::intel_hdmi_model_for((codec_id >> 16) as u16, codec_id as u16)
        .filter(|_| component().is_some())
}

/// [`bound_model`] of a decoded codec.
pub(super) fn bound_graph_model(graph: &Codec) -> Option<IntelHdmiModel> {
    hda_codec::intel_hdmi_model(graph).filter(|_| component().is_some())
}

/// The codec's root-node id as Linux matches it (`vendor_id`).
fn codec_id(graph: &Codec) -> u32 {
    (u32::from(graph.vendor_id) << 16) | u32::from(graph.device_id)
}

/// `intel_haswell_enable_all_pins` (with `update_tree`: the caller
/// enumerates the widgets afterwards) and `intel_haswell_fixup_enable_dp12`
/// over `verb` (an encoded command, its response). A failed read leaves the
/// vendor parameter alone, as Linux's `-1` check does.
pub(super) fn vendor_verbs(
    cad: u8,
    model: IntelHdmiModel,
    mut verb: impl FnMut(u32) -> Result<u32, HdaError>,
) -> Result<(), HdaError> {
    let Some(nid) = vendor_nid(model) else {
        return Ok(());
    };
    let get = |verb: &mut dyn FnMut(u32) -> Result<u32, HdaError>| {
        verb(make_verb(cad, nid, INTEL_GET_VENDOR_VERB << 8))
            .ok()
            .filter(|&v| v != u32::MAX)
    };
    if let Some(param) = get(&mut verb) {
        if param & INTEL_EN_ALL_PIN_CVTS == 0 {
            verb(make_verb(
                cad,
                nid,
                (INTEL_SET_VENDOR_VERB << 8) | ((param | INTEL_EN_ALL_PIN_CVTS) & 0xff),
            ))?;
        }
    }
    if let Some(param) = get(&mut verb) {
        if param & INTEL_EN_DP12 == 0 {
            verb(make_verb(
                cad,
                nid,
                (INTEL_SET_VENDOR_VERB << 8) | ((param | INTEL_EN_DP12) & 0xff),
            ))?;
        }
    }
    Ok(())
}

/// The HDMI/DP output paths of an Intel display codec
/// (`snd_hda_hdmi_parse_codec`): every digital output pin with a physical
/// connection (`hdmi_add_pin` skips `AC_JACK_PORT_NONE`), in NID order, each
/// given the first converter of its connection list no earlier pin took (the
/// first one when all are taken).
pub(super) fn intel_output_paths(c: &Codec) -> Vec<AudioPath> {
    let mut taken: Vec<u8> = Vec::new();
    let mut paths = Vec::new();
    for pin in c.widgets.iter().filter(|w| {
        w.ty() == WidgetType::PinComplex
            && w.caps.digital()
            && w.pin_caps.unwrap_or(0) & 0x10 != 0
            && w.pin_config.is_some_and(|p| p.port_connectivity != 0x1)
    }) {
        let converters: Vec<u8> = pin
            .connections
            .iter()
            .copied()
            .filter(|nid| {
                c.widget(*nid)
                    .is_some_and(|w| w.ty() == WidgetType::AudioOutput)
            })
            .collect();
        let Some(&first) = converters.first() else {
            continue;
        };
        let converter = converters
            .iter()
            .copied()
            .find(|nid| !taken.contains(nid))
            .unwrap_or(first);
        taken.push(converter);
        paths.push(AudioPath {
            pin_nid: pin.nid,
            chain: Vec::new(),
            converter_nid: converter,
        });
    }
    paths
}

/// `intel_cvt_id_to_mux_idx`: a converter's index among the codec's
/// converters, which is its connection index on every Intel pin.
fn mux_idx(c: &Codec, cvt: u8) -> Option<u32> {
    c.widgets
        .iter()
        .filter(|w| w.ty() == WidgetType::AudioOutput && w.caps.digital())
        .position(|w| w.nid == cvt)
        .map(|i| i as u32)
}

/// The HDMI audio InfoFrame `hdmi_pin_setup_infoframe` writes (the 9-byte
/// `union audio_infoframe`): the HDMI layout with its checksum, or the DP
/// one, for `ca` and `active` channels.
pub(super) fn audio_infoframe(conn_type: u8, ca: u8, active: u8) -> [u8; 9] {
    let mut ai = [0u8; 9];
    let cc = active.saturating_sub(1);
    if conn_type == 1 {
        ai[..8].copy_from_slice(&[0x84, 0x1b, 0x11 << 2, cc, 0, 0, ca, 0]);
    } else {
        ai = [0x84, 0x01, 0x0a, 0, cc, 0, 0, ca, 0];
        let sum = ai.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        ai[3] = 0u8.wrapping_sub(sum);
    }
    ai
}

/// The codec half Linux's `register_i915_notifier` registers: the
/// controllers whose Intel HDMI codec bound the component.
#[derive(Debug)]
struct Binding {
    dev: Weak<IntelHda>,
    model: IntelHdmiModel,
    codec_id: u32,
}

static BOUND: IrqSafeSpinLock<Vec<Binding>> = IrqSafeSpinLock::new(Vec::new());

/// `intel_audio_ops`.
#[derive(Debug)]
struct IntelAudioOps;

impl DisplayAudioCodec for IntelAudioOps {
    fn pin2port(&self, pin_nid: u32) -> Option<i32> {
        let (model, id) = {
            let bound = BOUND.lock();
            let first = bound.iter().find(|b| b.dev.strong_count() > 0)?;
            (first.model, first.codec_id)
        };
        intel_pin2port(model, id, pin_nid)
    }

    /// `intel_pin_eld_notify`: the pin of `port`, then
    /// `snd_hda_hdmi_check_presence_and_report` — here the controller's jack
    /// re-read.
    fn pin_eld_notify(&self, port: i32, _pipe: i32) {
        let targets: Vec<(Arc<IntelHda>, IntelHdmiModel, u32)> = BOUND
            .lock()
            .iter()
            .filter_map(|b| b.dev.upgrade().map(|dev| (dev, b.model, b.codec_id)))
            .collect();
        for (dev, model, id) in targets {
            if let Some(pin) = intel_port2pin(model, id, port) {
                if dev.intel_port_of_pin(pin).is_some() {
                    dev.note_jack_event();
                }
            }
        }
    }
}

static OPS: IntelAudioOps = IntelAudioOps;

/// `register_i915_notifier` for a controller whose Intel HDMI codec bound
/// the component: its ports follow `pin_eld_notify` from here on.
pub(super) fn register_notifier(dev: &Arc<IntelHda>) {
    let Some(graph) = dev.graphs.iter().find(|g| bound_graph_model(g).is_some()) else {
        return;
    };
    let Some(model) = hda_codec::intel_hdmi_model(graph) else {
        return;
    };
    let mut bound = BOUND.lock();
    bound.retain(|b| b.dev.strong_count() > 0 && !core::ptr::eq(b.dev.as_ptr(), Arc::as_ptr(dev)));
    bound.push(Binding {
        dev: Arc::downgrade(dev),
        model,
        codec_id: codec_id(graph),
    });
    drop(bound);
    acomp::register_display_audio_codec(&OPS);
}

/// `snd_hdac_display_power`'s bus state (one Intel display per system).
static DISPLAY_POWER: IrqSafeSpinLock<acomp::DisplayPower> =
    IrqSafeSpinLock::new(acomp::DisplayPower {
        status: 0,
        active: None,
    });

/// `snd_hdac_display_power(bus, cad, enable)`, with no lock held across the
/// component's calls.
fn display_power(cad: u8, enable: bool) {
    let mut state = *DISPLAY_POWER.lock();
    state.set(
        component().map(|c| c as &dyn DisplayAudioComponent),
        u32::from(cad),
        enable,
    );
    *DISPLAY_POWER.lock() = state;
}

impl IntelHda {
    /// The Intel HDMI port (index into `self.hdmi`) whose path ends at `pin`.
    pub(super) fn intel_port_of_pin(&self, pin: u8) -> Option<usize> {
        let ports = self.hdmi.lock();
        ports.iter().position(|p| {
            let path = &self.outputs[p.output];
            path.nodes.pin_nid == pin
                && hda_codec::intel_hdmi_model(&self.graphs[path.codec]).is_some()
        })
    }

    /// `sync_eld_via_acomp` + `update_eld` for one Intel pin (device entry
    /// 0): `snd_hdac_acomp_get_eld` through this codec's `pin2port`; the
    /// monitor is present when the display reports audio enabled, and the
    /// ELD is valid when it has a size, parses and carries a SAD.
    pub(super) fn intel_sense(&self, graph: &Codec, pin: u8) -> (bool, Option<super::hdmi::Sink>) {
        let mut buf = [0u8; ELD_MAX_SIZE];
        let codec = IntelPin {
            model: hda_codec::intel_hdmi_model(graph),
            codec_id: codec_id(graph),
        };
        match acomp::acomp_get_eld(
            component().map(|c| c as &dyn DisplayAudioComponent),
            Some(&codec as &dyn DisplayAudioCodec),
            u32::from(pin),
            0,
            &mut buf,
        ) {
            Ok((present, size)) if size > 0 => (
                present,
                super::hdmi::parse_eld(&buf[..size.min(ELD_MAX_SIZE)]),
            ),
            Ok((present, _)) => (present, None),
            Err(_) => (false, None),
        }
    }

    /// `snd_hdac_sync_audio_rate` for `pin` (device entry 0) at `rate` Hz.
    fn intel_sync_audio_rate(&self, graph: &Codec, pin: u8, rate: u32) {
        let codec = IntelPin {
            model: hda_codec::intel_hdmi_model(graph),
            codec_id: codec_id(graph),
        };
        let _ = acomp::acomp_sync_audio_rate(
            component().map(|c| c as &dyn DisplayAudioComponent),
            Some(&codec as &dyn DisplayAudioCodec),
            u32::from(pin),
            0,
            rate,
        );
    }

    /// `haswell_verify_D0`: the converter, then the pin, to D0 when their
    /// power state reads otherwise (an `AC_PWRST_ERROR` read counts as D0,
    /// `snd_hdac_check_power_state`), the pin with Linux's 40 ms settle.
    fn haswell_verify_d0(&self, cad: u8, cvt: u8, pin: u8) -> Result<(), HdaError> {
        let in_d0 = |state: u32| state & AC_PWRST_ERROR != 0 || (state >> 4) & 0xf == 0;
        if !in_d0(self.verb(cad, cvt, GET_POWER_STATE << 8)?) {
            self.verb(cad, cvt, SET_POWER_STATE << 8)?;
        }
        if !in_d0(self.verb(cad, pin, GET_POWER_STATE << 8)?) {
            self.verb(cad, pin, SET_POWER_STATE << 8)?;
            super::runtime::delay_us(40_000);
            self.verb(cad, pin, GET_POWER_STATE << 8)?;
        }
        Ok(())
    }

    /// `intel_verify_pin_cvt_connect` and `intel_not_share_assigned_cvt`
    /// (`i915_pin_cvt_fixup` with a pin): the pin selects its converter, and
    /// every other connected Intel pin that selects the same converter is
    /// moved to the first converter no open stream holds.
    fn intel_pin_cvt_fixup(&self, graph: &Codec, nodes: &AudioPath) -> Result<(), HdaError> {
        let (cad, pin, cvt) = (graph.addr, nodes.pin_nid, nodes.converter_nid);
        self.haswell_verify_d0(cad, cvt, pin)?;
        let Some(mux) = mux_idx(graph, cvt) else {
            return Ok(());
        };
        if self.verb(cad, pin, GET_CONNECT_SEL << 8)? & 0xff != mux {
            self.verb(cad, pin, (SET_CONNECT_SEL << 8) | mux)?;
        }
        let others: Vec<u8> = self
            .hdmi
            .lock()
            .iter()
            .filter(|p| p.present && p.sink.is_some())
            .map(|p| &self.outputs[p.output])
            .filter(|path| self.graphs[path.codec].addr == cad && path.nodes.pin_nid != pin)
            .map(|path| path.nodes.pin_nid)
            .collect();
        for other in others {
            if self.verb(cad, other, GET_CONNECT_SEL << 8)? & 0xff != mux {
                continue;
            }
            // "choose an unassigned converter": the one stream holds `cvt`.
            if let Some(free) = (0..32u32).find(|&i| i != mux && i < self.intel_cvt_count(graph)) {
                self.verb(cad, other, (SET_CONNECT_SEL << 8) | free)?;
            }
        }
        Ok(())
    }

    fn intel_cvt_count(&self, graph: &Codec) -> u32 {
        graph
            .widgets
            .iter()
            .filter(|w| w.ty() == WidgetType::AudioOutput && w.caps.digital())
            .count() as u32
    }

    /// `snd_hda_hdmi_setup_audio_infoframe` on an Intel pin: the output amp
    /// unmuted, the channel allocation, the converter's channel count, the
    /// standard (or user) slot map and, unless the pin already sends it, the
    /// audio InfoFrame (stop, fill from index 0, start best-effort). Returns
    /// the CA.
    pub(super) fn intel_hdmi_infoframe(
        &self,
        graph: &Codec,
        nodes: &AudioPath,
        channels: u8,
        sink: Option<&super::hdmi::Sink>,
        pcm: &super::hdmi::Playback,
    ) -> Result<u8, HdaError> {
        let (cad, pin, cvt) = (graph.addr, nodes.pin_nid, nodes.converter_nid);
        if graph.widget(pin).is_some_and(|w| w.caps.out_amp_present()) {
            self.verb(cad, pin, VERB_SET_AMP_GAIN_MUTE | AMP_OUT_UNMUTE)?;
        }
        let spk_alloc = sink.map_or(0, |s| s.spk_alloc);
        let ca = super::hdmi::stream_allocation(spk_alloc, channels, pcm);
        let active = super::hdmi::active_channels(ca);
        if self.verb(cad, cvt, GET_CVT_CHAN_COUNT << 8)? & 0xf != u32::from(active - 1) {
            self.verb(cad, cvt, (SET_CVT_CHAN_COUNT << 8) | u32::from(active - 1))?;
        }
        for entry in super::hdmi::slot_entries(ca, channels, pcm) {
            self.verb(cad, pin, (SET_HDMI_CHAN_SLOT << 8) | u32::from(entry))?;
        }
        let conn_type = sink.and_then(|s| s.eld.get(5)).map_or(0, |b| (b >> 2) & 3);
        let ai = audio_infoframe(conn_type, ca, active);
        // hdmi_infoframe_uptodate.
        self.verb(cad, pin, SET_HDMI_DIP_INDEX << 8)?;
        let mut uptodate = self.verb(cad, pin, GET_HDMI_DIP_XMIT << 8)? == AC_DIPXMIT_BEST;
        if uptodate {
            for byte in ai {
                if self.verb(cad, pin, GET_HDMI_DIP_DATA << 8)? as u8 != byte {
                    uptodate = false;
                    break;
                }
            }
        }
        if !uptodate {
            self.verb(cad, pin, SET_HDMI_DIP_INDEX << 8)?;
            self.verb(cad, pin, (SET_HDMI_DIP_XMIT << 8) | AC_DIPXMIT_DISABLE)?;
            self.verb(cad, pin, SET_HDMI_DIP_INDEX << 8)?;
            for byte in ai {
                self.verb(cad, pin, (SET_HDMI_DIP_DATA << 8) | u32::from(byte))?;
            }
            self.verb(cad, pin, SET_HDMI_DIP_INDEX << 8)?;
            self.verb(cad, pin, (SET_HDMI_DIP_XMIT << 8) | AC_DIPXMIT_BEST)?;
        }
        Ok(ca)
    }

    /// `snd_hda_hdmi_generic_pcm_prepare` and `i915_hsw_setup_stream` for one
    /// Intel pin, up to the stream format and tag the caller writes: the
    /// display power (`snd_hdac_display_power`, which pulses the codec
    /// wake), `i915_pin_cvt_fixup`, `snd_hdac_sync_audio_rate` at `rate`, the
    /// audio InfoFrame setup, `haswell_verify_D0`, `hdmi_pin_hbr_setup` (the
    /// pin's EPT bits for an 8-channel non-PCM stream), the IEC coding type
    /// (`AC_DIG3_ICT`, `intel_hsw_fixup`) and the converter's DIG1/DIG2.
    pub(super) fn intel_hdmi_prepare(
        &self,
        graph: &Codec,
        nodes: &AudioPath,
        output: usize,
        channels: u8,
        rate: u32,
    ) -> Result<(), HdaError> {
        if !(2..=8).contains(&channels) {
            return Err(HdaError::NoOutputStream);
        }
        let (cad, pin, cvt) = (graph.addr, nodes.pin_nid, nodes.converter_nid);
        display_power(cad, true);
        let index = self
            .hdmi_pcm_of_output(output)
            .ok_or(HdaError::NoOutputStream)?;
        let pcm = self.hdmi_state(index);
        self.intel_pin_cvt_fixup(graph, nodes)?;
        self.intel_sync_audio_rate(graph, pin, rate);
        let sink = self.hdmi_sink(output);
        let ca = self.intel_hdmi_infoframe(graph, nodes, channels, sink.as_ref(), &pcm)?;
        self.update_hdmi_state(index, |state| {
            if pcm.non_pcm || !state.chmap_set {
                state.chmap = super::hdmi::default_chmap(ca);
            }
        });
        self.haswell_verify_d0(cad, cvt, pin)?;
        // is_hbr_format: non-PCM with eight channels.
        let hbr = pcm.non_pcm && channels == 8;
        let caps = graph.widget(pin).and_then(|w| w.pin_caps).unwrap_or(0);
        if caps & AC_PINCAP_HBR != 0 {
            let ctl = self.verb(cad, pin, GET_PIN_WIDGET_CONTROL << 8)?;
            let next = (ctl & !AC_PINCTL_EPT) | if hbr { AC_PINCTL_EPT_HBR } else { 0 };
            if next != ctl {
                self.verb(cad, pin, VERB_SET_PIN_WIDGET_CONTROL | (next & 0xff))?;
            }
        } else if hbr {
            return Err(HdaError::NoOutputStream);
        }
        let dig = self.verb(cad, cvt, GET_DIGI_CONVERT_1 << 8)?;
        let ict = ((dig >> 16) & 0xff & !AC_DIG3_ICT) | u32::from(hbr);
        self.verb(cad, cvt, (SET_DIGI_CONVERT_3 << 8) | ict)?;
        self.verb(cad, cvt, (0x70d << 8) | u32::from(pcm.ctls & 0xff))?;
        self.verb(cad, cvt, (0x70e << 8) | u32::from(pcm.ctls >> 8))?;
        Ok(())
    }

    /// `haswell_set_power_state`'s vendor verbs before the AFG enters D0.
    pub(super) fn intel_before_d0(&self, graph: &Codec) -> Result<(), HdaError> {
        let Some(model) = hda_codec::intel_hdmi_model(graph) else {
            return Ok(());
        };
        vendor_verbs(graph.addr, model, |command| {
            self.verb(
                (command >> 28) as u8,
                (command >> 20) as u8,
                command & 0xf_ffff,
            )
        })
    }

    /// The display power of the Intel HDMI codecs, dropped at codec suspend
    /// (`hda_codec_runtime_suspend`'s `snd_hdac_display_power(.., false)`).
    pub(super) fn intel_display_power_off(&self) {
        for graph in &self.graphs {
            if hda_codec::intel_hdmi_model(graph).is_some() {
                display_power(graph.addr, false);
            }
        }
    }
}

/// The `pin2port` of one Intel codec, for the HDA-core helpers.
#[derive(Debug)]
struct IntelPin {
    model: Option<IntelHdmiModel>,
    codec_id: u32,
}

impl DisplayAudioCodec for IntelPin {
    fn pin2port(&self, pin_nid: u32) -> Option<i32> {
        intel_pin2port(self.model?, self.codec_id, pin_nid)
    }
    fn pin_eld_notify(&self, _port: i32, _pipe: i32) {}
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn reset_display_power_for_test() {
    *DISPLAY_POWER.lock() = acomp::DisplayPower::default();
}
