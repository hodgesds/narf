//! Codec widget graph — walks the AFG subnodes after enumeration.
//!
//! HDA §7.3.4 lays out the parameter table that each widget answers
//! to. The Audio Function Group (AFG) widget at NID 0x01 reports
//! a `Subordinate Node Count` parameter naming `(start, count)` of
//! its children. Each child reports its own widget type (in the
//! `Audio Widget Capabilities` parameter, bits 20..23):
//!
//! ```text
//!   0x0  Audio Output (DAC)
//!   0x1  Audio Input  (ADC)
//!   0x2  Audio Mixer  (sum + per-input gain)
//!   0x3  Audio Selector (mux)
//!   0x4  Pin Complex (jack / speaker / mic)
//!   0x5  Power Widget
//!   0x6  Volume Knob
//!   0x7  Beep Generator
//!   0xF  Vendor Defined
//! ```
//!
//! Linux references:
//! - `sound/hda/codecs/generic.c::snd_hda_gen_parse_auto_config`
//!   parses pin configs and builds output/input chains.
//! - `sound/hda/core/device.c::snd_hdac_get_sub_nodes` walks
//!   subnode lists.

use alloc::vec::Vec;

use crate::codec::generic::{PinDevice, Widget, WidgetKind};

/// One identified output path through the codec graph.
#[derive(Clone, Debug)]
pub struct OutputPath {
    /// Driving DAC node (widget kind = AudioOutput).
    pub dac_nid: u8,
    /// Optional intermediate mixer or selector NIDs along the path.
    pub via: Vec<u8>,
    /// Terminal pin complex (speaker, headphone, etc).
    pub pin_nid: u8,
    /// What the pin is connected to (speaker, headphone, ...).
    pub pin_device: PinDevice,
}

/// One identified capture path.
#[derive(Clone, Debug)]
pub struct InputPath {
    /// Source pin complex (mic jack, internal mic, ...).
    pub pin_nid: u8,
    pub pin_device: PinDevice,
    /// Intermediate selector / mixer NIDs.
    pub via: Vec<u8>,
    /// Capturing ADC.
    pub adc_nid: u8,
}

/// Full graph walk result.
#[derive(Clone, Debug, Default)]
pub struct CodecGraph {
    pub outputs: Vec<OutputPath>,
    pub inputs: Vec<InputPath>,
}

impl CodecGraph {
    /// Build a graph from an enumerated widget list. Recursive walk:
    /// start at each Audio Output node, follow each Pin Complex's
    /// connection list back, identify intervening Mixer / Selector
    /// nodes.
    pub fn build(widgets: &[Widget]) -> Self {
        let mut graph = CodecGraph::default();

        // First: identify all pin complexes and bucket by direction.
        for w in widgets {
            if matches!(w.kind, WidgetKind::PinComplex) {
                let dev = w.pin_device;
                let is_output = matches!(
                    dev,
                    PinDevice::LineOut | PinDevice::Speaker | PinDevice::HpOut | PinDevice::Spdif
                );
                let is_input = matches!(
                    dev,
                    PinDevice::MicIn | PinDevice::LineIn | PinDevice::SpdifIn
                );
                if is_output {
                    // For each output pin, trace its connection list
                    // backwards to find a DAC.
                    if let Some(dac) = trace_back_to_dac(widgets, w.nid) {
                        let via = trace_via(widgets, w.nid, dac);
                        graph.outputs.push(OutputPath {
                            dac_nid: dac,
                            via,
                            pin_nid: w.nid,
                            pin_device: dev,
                        });
                    }
                } else if is_input {
                    if let Some(adc) = trace_forward_to_adc(widgets, w.nid) {
                        let via = trace_via(widgets, w.nid, adc);
                        graph.inputs.push(InputPath {
                            pin_nid: w.nid,
                            pin_device: dev,
                            via,
                            adc_nid: adc,
                        });
                    }
                }
            }
        }
        graph
    }
}

/// Walk backwards from a pin complex through Mixer/Selector
/// connections until reaching an Audio Output (DAC). Returns the
/// DAC NID or None when no DAC is reachable.
fn trace_back_to_dac(widgets: &[Widget], start: u8) -> Option<u8> {
    let mut current = start;
    // Bounded BFS — limit to widget-graph depth (max realistic is 4).
    for _ in 0..8 {
        let widget = widgets.iter().find(|w| w.nid == current)?;
        if matches!(widget.kind, WidgetKind::AudioOutput) {
            return Some(widget.nid);
        }
        // Follow the first entry of the connection list — for the
        // simple bring-up path that's the canonical path.
        let next = *widget.connections.first()?;
        if next == 0 || next == current {
            return None;
        }
        current = next;
    }
    None
}

/// Walk forward from a pin to find a connected ADC.
fn trace_forward_to_adc(widgets: &[Widget], start: u8) -> Option<u8> {
    // ADCs *consume* pin complexes via their connection list, so
    // we search for an ADC whose conn list contains `start`.
    for w in widgets {
        if matches!(w.kind, WidgetKind::AudioInput) && w.connections.contains(&start) {
            return Some(w.nid);
        }
    }
    // Otherwise: trace through mixers/selectors that include `start`
    // and recurse to ADCs that consume those.
    for w in widgets {
        if matches!(w.kind, WidgetKind::Mixer | WidgetKind::Selector)
            && w.connections.contains(&start)
        {
            if let Some(adc) = trace_forward_to_adc(widgets, w.nid) {
                return Some(adc);
            }
        }
    }
    None
}

/// Collect intermediate (non-pin, non-end) NIDs traversed between
/// `from` and `to`. Best-effort.
fn trace_via(widgets: &[Widget], from: u8, to: u8) -> Vec<u8> {
    let mut via = Vec::new();
    let mut current = from;
    for _ in 0..8 {
        if current == to {
            break;
        }
        let Some(widget) = widgets.iter().find(|w| w.nid == current) else {
            break;
        };
        if !matches!(widget.kind, WidgetKind::PinComplex) && current != from && current != to {
            via.push(current);
        }
        let Some(&next) = widget.connections.first() else {
            break;
        };
        if next == 0 || next == current {
            break;
        }
        current = next;
    }
    via
}
