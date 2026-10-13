//! BIOS pin defaults and connection-list routing. Linux references:
//! sound/hda/codecs/generic.c (paths, amp inheritance, EAPD, automute).
use super::*;
use crate::hda_codec::{self, AudioPath, WidgetType};
use alloc::vec::Vec;
use narf_drivers_sound::format::{pack_sdfmt, HwParams, SampleFormat};

#[derive(Debug, Clone)]
pub(super) struct Path {
    pub codec: usize,
    pub nodes: AudioPath,
}
impl IntelHda {
    pub(super) fn discover_paths(&mut self) {
        for (index, graph) in self.graphs.iter().enumerate() {
            // GPU HDMI/DP audio: every connected digital port, no analog.
            if hda_codec::is_ati_hdmi(graph) {
                if self.stream_counts().1 != 0 {
                    for nodes in hda_codec::find_digital_output_paths(graph) {
                        self.outputs.push(Path {
                            codec: index,
                            nodes,
                        });
                    }
                }
                continue;
            }
            if self.stream_counts().1 != 0 {
                for pin in &graph.widgets {
                    if pin.ty() != WidgetType::PinComplex
                        || pin.caps.digital()
                        || pin.pin_caps.unwrap_or(0) & 0x10 == 0
                    {
                        continue;
                    }
                    let mut candidate = graph.clone();
                    for widget in &mut candidate.widgets {
                        if widget.nid != pin.nid && widget.ty() == WidgetType::PinComplex {
                            widget.pin_config = None;
                        }
                    }
                    if let Some(path) = hda_codec::find_output_path(&candidate) {
                        self.outputs.push(Path {
                            codec: index,
                            nodes: path,
                        });
                    }
                }
            }
            if self.input.is_none() && self.stream_counts().0 != 0 {
                self.input = hda_codec::find_input_path(graph).map(|nodes| Path {
                    codec: index,
                    nodes,
                });
            }
        }
    }
    /// The `AC_PAR_PCM` (parameter 0x0a) size bit for `format`.
    ///
    /// Linux reads the same word in `snd_hda_query_supported_pcm`
    /// (sound/pci/hda/hda_codec.c) to build a PCM's format constraint. Shared
    /// by the capability query and by `configure_paths`'s enforcement so the
    /// set a card ADVERTISES and the set it ACCEPTS are the same set.
    fn pcm_size_bit(format: SampleFormat) -> Option<u32> {
        match format {
            SampleFormat::S16LE => Some(1 << 17),
            SampleFormat::S32LE => Some(1 << 20),
            _ => None,
        }
    }

    /// Formats every routed converter in `capture`'s direction can configure.
    ///
    /// Empty when the direction has no usable path, or when the codec query
    /// itself fails; the caller falls back to the driver's own default format
    /// rather than offering nothing.
    ///
    /// This must be answered from the codec, not from a fixed list. Advertising
    /// S32_LE on a codec whose `AC_PAR_PCM` word lacks bit 20 made `HW_REFINE`
    /// offer a point `HW_PARAMS` then rejected, and alsa-lib cannot recover
    /// from that: PipeWire negotiates the widest format on offer and its ALSA
    /// node dies with `set_hw_params: Invalid argument`, leaving the graph with
    /// a sink that never takes a quantum. QEMU's hda-duplex codec is exactly
    /// such a codec.
    pub(super) fn query_supported_formats(&self, capture: bool) -> Vec<SampleFormat> {
        let paths: Vec<&Path> = if capture {
            self.input.iter().collect()
        } else {
            self.outputs.iter().collect()
        };
        if paths.is_empty() {
            return Vec::new();
        }
        let mut supported = alloc::vec![SampleFormat::S16LE, SampleFormat::S32LE];
        for path in paths {
            let Some(graph) = self.graphs.get(path.codec) else {
                return Vec::new();
            };
            let Some(converter) = graph.widget(path.nodes.converter_nid) else {
                return Vec::new();
            };
            let caps_nid = if converter.caps.format_override() {
                converter.nid
            } else {
                graph.afg_nid
            };
            // atihdmi_probe: ATI converters under-advertise; Linux grants
            // every rate, S16/S32 and eight channels regardless.
            if hda_codec::is_ati_hdmi(graph) {
                continue;
            }
            let (Ok(pcm), Ok(formats)) = (
                self.verb(graph.addr, caps_nid, VERB_GET_PARAMETER | 0x0a),
                self.verb(graph.addr, caps_nid, VERB_GET_PARAMETER | 0x0b),
            ) else {
                return Vec::new();
            };
            // Bit 6 is the 48 kHz rate, bit 0 of the stream-formats word is
            // PCM — the same two gates `configure_paths` applies before it
            // looks at the size bits.
            if pcm & (1 << 6) == 0 || formats & 1 == 0 {
                return Vec::new();
            }
            supported
                .retain(|format| Self::pcm_size_bit(*format).is_some_and(|bit| pcm & bit != 0));
        }
        supported
    }

    fn verb(&self, cad: u8, nid: u8, verb: u32) -> Result<u32, HdaError> {
        // SAFETY: this object's lifetime owns the controller and command ring.
        unsafe { self.send_verb(make_verb(cad, nid, verb)) }
    }
    pub(super) fn configure_paths(&self, capture: bool, params: HwParams) -> Result<(), HdaError> {
        let paths: Vec<&Path> = if capture {
            self.input.iter().collect()
        } else {
            self.outputs.iter().collect()
        };
        if paths.is_empty() {
            return Err(HdaError::NoOutputStream);
        }
        for path in paths {
            let graph = &self.graphs[path.codec];
            let cad = graph.addr;
            let converter = graph
                .widget(path.nodes.converter_nid)
                .ok_or(HdaError::NoCodecs)?;
            let ati = hda_codec::is_ati_hdmi(graph);
            if !ati && converter.caps.channels() < params.channels.count() {
                return Err(HdaError::NoOutputStream);
            }
            let caps_nid = if converter.caps.format_override() {
                converter.nid
            } else {
                graph.afg_nid
            };
            let Some(bits) = Self::pcm_size_bit(params.format) else {
                return Err(HdaError::NoOutputStream);
            };
            if !ati {
                let pcm = self.verb(cad, caps_nid, VERB_GET_PARAMETER | 0x0a)?;
                let formats = self.verb(cad, caps_nid, VERB_GET_PARAMETER | 0x0b)?;
                if pcm & (1 << 6) == 0 || pcm & bits == 0 || formats & 1 == 0 {
                    return Err(HdaError::NoOutputStream);
                }
            }
            self.verb(cad, graph.afg_nid, 0x705 << 8)?;
            super::runtime::delay_us(1000);
            let mut nodes = Vec::new();
            if capture {
                nodes.push(path.nodes.converter_nid);
                nodes.extend_from_slice(&path.nodes.chain);
                nodes.push(path.nodes.pin_nid);
            } else {
                nodes.push(path.nodes.pin_nid);
                nodes.extend_from_slice(&path.nodes.chain);
                nodes.push(path.nodes.converter_nid);
            }
            for (position, &nid) in nodes.iter().enumerate() {
                let widget = graph.widget(nid).ok_or(HdaError::NoCodecs)?;
                if widget.caps.power_ctrl() {
                    self.verb(cad, nid, 0x705 << 8)?;
                }
                let selected = nodes
                    .get(position + 1)
                    .and_then(|next| widget.connections.iter().position(|n| n == next));
                if let Some(selected) = selected {
                    if widget.ty() != WidgetType::AudioMixer {
                        self.verb(cad, nid, (0x701 << 8) | selected as u32)?;
                    }
                    if let Some(amp) = widget.in_amp {
                        if selected > 15 {
                            return Err(HdaError::NoOutputStream);
                        }
                        // Mute unused mixer inputs to avoid unintended analog loops.
                        for input in 0..widget.connections.len().min(16) {
                            let gain = amp.offset.min(amp.num_steps) as u32;
                            let mute = if input == selected { 0 } else { 0x80 };
                            self.verb(
                                cad,
                                nid,
                                VERB_SET_AMP_GAIN_MUTE
                                    | 0x7000
                                    | ((input as u32) << 8)
                                    | gain
                                    | mute,
                            )?;
                        }
                    }
                }
                if let Some(amp) = widget.out_amp {
                    self.verb(
                        cad,
                        nid,
                        VERB_SET_AMP_GAIN_MUTE | 0xb000 | amp.offset.min(amp.num_steps) as u32,
                    )?;
                }
            }
            let pin = graph.widget(path.nodes.pin_nid).ok_or(HdaError::NoCodecs)?;
            let caps = pin.pin_caps.unwrap_or(0);
            if caps & (1 << 16) != 0 {
                let old = self.verb(cad, pin.nid, 0xf0c << 8)?;
                self.verb(cad, pin.nid, (0x70c << 8) | (old & 7) | 2)?;
            }
            let ctl = if capture {
                // Prefer 80% VREF, then 50%, only when advertised.
                0x20 | if caps & (1 << 12) != 0 {
                    4
                } else if caps & (1 << 9) != 0 {
                    1
                } else {
                    0
                }
            } else if pin.pin_config.is_some_and(|p| p.default_device == 2) {
                0xc0
            } else {
                0x40
            };
            self.verb(cad, pin.nid, VERB_SET_PIN_WIDGET_CONTROL | ctl)?;
            if ati {
                self.ati_hdmi_prepare(graph, &path.nodes, params.channels.count())?;
            }
            self.verb(
                cad,
                converter.nid,
                VERB_SET_CONVERTER_FORMAT
                    | pack_sdfmt(params.format, params.rate, params.channels) as u32,
            )?;
            self.verb(
                cad,
                converter.nid,
                VERB_SET_CONVERTER_STREAM | if capture { 0x20 } else { 0x10 },
            )?;
        }
        if !capture {
            self.apply_volume(&self.volume.lock())?;
            self.refresh_jacks()?;
        }
        Ok(())
    }
    /// Linux atihdmi_init plus snd_hda_hdmi_generic_pcm_prepare and
    /// atihdmi_setup_stream for one HDMI/DP port carrying LPCM: zero downmix,
    /// per-channel remap mode (rev3+), converter channel count, the CEA slot
    /// map and channel allocation (CA 0, FL/FR for stereo), ramp rate
    /// (rev3+), HBR off, then the converter's digital enable (Linux leaves
    /// DIGEN to the IEC958 switch userspace turns on; narf has no such
    /// control, so the PCM path enables it).
    fn ati_hdmi_prepare(
        &self,
        graph: &hda_codec::Codec,
        nodes: &AudioPath,
        channels: u8,
    ) -> Result<(), HdaError> {
        const SET_CHANNEL_ALLOCATION: u32 = 0x771;
        const SET_DOWNMIX_INFO: u32 = 0x772;
        const SET_MULTICHANNEL_01: u32 = 0x777;
        const GET_HBR_CONTROL: u32 = 0xf7c;
        const SET_HBR_CONTROL: u32 = 0x77c;
        const SET_MULTICHANNEL_MODE: u32 = 0x789;
        const SET_RAMP_RATE: u32 = 0x770;
        if channels != 2 {
            return Err(HdaError::NoOutputStream);
        }
        let (cad, pin, cvt) = (graph.addr, nodes.pin_nid, nodes.converter_nid);
        let rev3 = hda_codec::ati_hdmi_rev3(graph);
        self.verb(cad, pin, SET_DOWNMIX_INFO << 8)?;
        if rev3 {
            self.verb(cad, pin, (SET_MULTICHANNEL_MODE << 8) | 1)?;
        }
        if self.verb(cad, cvt, 0xf2d << 8)? & 0xf != u32::from(channels - 1) {
            self.verb(cad, cvt, (0x72d << 8) | u32::from(channels - 1))?;
        }
        // CA 0 (FL FR): stream channels 0 and 1 in slots 0 and 1, the rest
        // off. Pre-rev3 codecs map slot pairs, so only even slots are written.
        for slot in 0..8u32 {
            let channel = (slot < 2).then_some(slot);
            let (slot, channel) = if rev3 {
                (slot, channel)
            } else if slot % 2 == 1 {
                continue;
            } else {
                (slot, channel.map(|c| c - c % 2))
            };
            let verb = SET_MULTICHANNEL_01 + slot / 2 + (slot % 2) * 0xe;
            let setup = channel.map_or(0, |c| (c << 4) | 1);
            self.verb(cad, pin, (verb << 8) | setup)?;
        }
        self.verb(cad, pin, SET_CHANNEL_ALLOCATION << 8)?;
        if rev3 {
            self.verb(cad, cvt, (SET_RAMP_RATE << 8) | 180)?;
        }
        let hbr = self.verb(cad, pin, GET_HBR_CONTROL << 8)?;
        if hbr & 1 != 0 && hbr & 0x10 != 0 {
            self.verb(cad, pin, (SET_HBR_CONTROL << 8) | (hbr & 0xef))?;
        }
        let dig = self.verb(cad, cvt, 0xf0d << 8)?;
        self.verb(cad, cvt, (0x70d << 8) | (dig & 0xff) | 1)?;
        Ok(())
    }
    pub(super) fn refresh_jacks(&self) -> Result<(), HdaError> {
        if !self.streams[0]
            .lock()
            .ring
            .as_ref()
            .is_some_and(|r| r.prepared)
        {
            return Ok(());
        }
        let enabled = self.volume.lock().enabled;
        let mut headphones = false;
        for path in &self.outputs {
            let graph = &self.graphs[path.codec];
            let pin = graph.widget(path.nodes.pin_nid).ok_or(HdaError::NoCodecs)?;
            if pin.pin_config.is_some_and(|p| p.default_device == 2)
                && pin.pin_caps.unwrap_or(0) & 4 != 0
            {
                headphones |= self.verb(graph.addr, pin.nid, 0xf09 << 8)? & (1 << 31) != 0;
            }
        }
        for path in &self.outputs {
            let graph = &self.graphs[path.codec];
            let pin = graph.widget(path.nodes.pin_nid).ok_or(HdaError::NoCodecs)?;
            let role = pin.pin_config.map_or(0, |p| p.default_device);
            let ctl = if !enabled || (role == 1 && headphones) {
                0
            } else if role == 2 {
                0xc0
            } else {
                0x40
            };
            self.verb(graph.addr, pin.nid, VERB_SET_PIN_WIDGET_CONTROL | ctl)?;
        }
        Ok(())
    }
    /// Configure the discovered analog output route at the baseline PCM format.
    /// # Safety
    /// Caller owns this controller and has stopped its output stream.
    pub unsafe fn setup_default_output_path(&self) -> Result<(u8, u8), HdaError> {
        self.configure_paths(false, super::stream::default_params())?;
        self.outputs
            .first()
            .map(|p| (p.nodes.converter_nid, p.nodes.pin_nid))
            .ok_or(HdaError::NoOutputStream)
    }
    /// # Safety
    /// Caller owns this controller and has stopped its output stream.
    pub unsafe fn bring_up_all_codecs(&self) -> Result<(), HdaError> {
        // SAFETY: The live controller owns the command rings; its command lease serializes access.
        unsafe { self.setup_default_output_path() }.map(|_| ())
    }
}

#[derive(Debug, Copy, Clone)]
pub(super) struct Volume {
    pub left: u8,
    pub right: u8,
    pub enabled: bool,
}
impl IntelHda {
    pub(super) fn mixer_controls(&self) -> Vec<narf_drivers_sound::mixer::ControlId> {
        use narf_drivers_sound::mixer::{ControlId, ControlKind};
        if self.outputs.is_empty() {
            return Vec::new();
        }
        let mut controls = Vec::new();
        if self.outputs.iter().all(|path| {
            self.graphs[path.codec]
                .widget(path.nodes.converter_nid)
                .and_then(|w| w.out_amp)
                .is_some()
        }) {
            controls.push(ControlId {
                index: 0,
                kind: ControlKind::MasterVolume,
            });
        }
        controls.push(ControlId {
            index: 1,
            kind: ControlKind::MasterMute,
        });
        if self.outputs.iter().any(|path| {
            self.graphs[path.codec]
                .widget(path.nodes.pin_nid)
                .is_some_and(|pin| {
                    pin.pin_config.is_some_and(|p| p.default_device == 2)
                        && pin.pin_caps.unwrap_or(0) & 4 != 0
                })
        }) {
            controls.push(ControlId {
                index: 2,
                kind: ControlKind::JackSense,
            });
        }
        controls
    }
    fn apply_volume(&self, volume: &Volume) -> Result<(), HdaError> {
        for path in &self.outputs {
            let graph = &self.graphs[path.codec];
            let converter = graph
                .widget(path.nodes.converter_nid)
                .ok_or(HdaError::NoCodecs)?;
            if let Some(amp) = converter.out_amp {
                for (channel, value) in [(0x2000, volume.left), (0x1000, volume.right)] {
                    let gain = amp.offset.min(amp.num_steps) as u32 * value as u32 / 87;
                    self.verb(
                        graph.addr,
                        converter.nid,
                        VERB_SET_AMP_GAIN_MUTE
                            | 0x8000
                            | channel
                            | gain
                            | if volume.enabled { 0 } else { 0x80 },
                    )?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn get_mixer(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
    ) -> Result<narf_drivers_sound::mixer::ControlValue, narf_drivers_sound::SoundError> {
        use narf_drivers_sound::{
            mixer::{ControlKind, ControlValue},
            SoundError,
        };
        if !self.mixer_controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        match id.kind {
            ControlKind::MasterVolume => {
                let v = self.volume.lock();
                Ok(ControlValue::integer(v.left as i32, v.right as i32))
            }
            ControlKind::MasterMute => Ok(ControlValue::boolean(self.volume.lock().enabled)),
            ControlKind::JackSense => {
                let mut present = false;
                for path in &self.outputs {
                    let graph = &self.graphs[path.codec];
                    let pin = graph
                        .widget(path.nodes.pin_nid)
                        .ok_or(SoundError::BadState)?;
                    if pin.pin_config.is_some_and(|p| p.default_device == 2)
                        && pin.pin_caps.unwrap_or(0) & 4 != 0
                    {
                        present |= self
                            .verb(graph.addr, pin.nid, 0xf09 << 8)
                            .map_err(|_| SoundError::BadState)?
                            & (1 << 31)
                            != 0;
                    }
                }
                Ok(ControlValue::boolean(present))
            }
            _ => Err(SoundError::NoSuchControl),
        }
    }
    pub(super) fn set_mixer(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
        value: narf_drivers_sound::mixer::ControlValue,
    ) -> Result<(), narf_drivers_sound::SoundError> {
        use narf_drivers_sound::{
            mixer::{ControlKind, ControlValue},
            SoundError,
        };
        if !self.mixer_controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        let mut current = self.volume.lock();
        let mut next = *current;
        match (id.kind, value) {
            (ControlKind::MasterVolume, ControlValue::Integer { left, right })
                if (0..=87).contains(&left) && (0..=87).contains(&right) =>
            {
                next.left = left as u8;
                next.right = right as u8;
            }
            (ControlKind::MasterMute, ControlValue::Boolean(enabled)) => next.enabled = enabled,
            _ => return Err(SoundError::OutOfRange),
        }
        self.apply_volume(&next).map_err(|_| SoundError::BadState)?;
        *current = next;
        drop(current);
        self.refresh_jacks().map_err(|_| SoundError::BadState)?;
        Ok(())
    }
}
