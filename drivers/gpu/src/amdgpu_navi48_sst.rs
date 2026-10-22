//! Physical connector inventory independent of successful scanout.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SstOutput {
    pub port: usize,
    pub edid: Vec<u8>,
    /// Independent candidates beside the current streams, not reservations.
    pub modes: Vec<Timing>,
    /// amdgpu_dm's freesync_capable for this sink (DP SST only here).
    pub vrr_capable: bool,
}

pub(super) fn dark_modes(
    soc: &dml::Soc,
    paths: &[inventory::Path],
    port: &display::Port,
    max_bpc: u8,
    lit: &[Selection],
) -> Vec<Timing> {
    let mut out = Vec::new();
    let Ok(sink) = &port.sink else { return out };
    if lit.len() >= MAX_DISPLAYS {
        return out;
    }
    for timing in edid_timings(&sink.edid) {
        if out.len() == MAX_MODES {
            break;
        }
        let formats: &[_] = if port.path.connector == inventory::Connector::HdmiTypeA {
            &[
                crate::amdgpu_hdr::ColorFormat::Auto,
                crate::amdgpu_hdr::ColorFormat::Ycbcr444,
                crate::amdgpu_hdr::ColorFormat::Ycbcr422,
            ]
        } else {
            &[crate::amdgpu_hdr::ColorFormat::Auto]
        };
        let accepted = formats.iter().any(|&requested| {
            let Ok(candidates) = select_all_for_format(
                paths,
                core::slice::from_ref(port),
                max_bpc,
                &|_| Some(timing),
                &|_| requested,
            ) else {
                return false;
            };
            let Some(candidate) = candidates.into_iter().next() else {
                return false;
            };
            if candidate.timing != timing
                || candidate.frl.is_some() && lit.iter().any(|s| s.frl.is_some())
            {
                return false;
            }
            let mut joint = lit.to_vec();
            joint.push(candidate);
            let fixed: Vec<_> = (0..joint.len()).map(|k| k < lit.len()).collect();
            admit_selection_candidates(soc, &joint, &fixed).is_some()
        });
        if accepted {
            out.push(timing);
        }
    }
    out
}

impl ColdBoot {
    /// Last physical-connector EDID/admission snapshot, including unlit sinks.
    /// Recomputed by modeset_displays; no stream or allocation is created here.
    pub fn display_sst_outputs(&self) -> &[SstOutput] {
        &self.sst_outputs
    }

    pub(super) fn update_sst_outputs(
        &mut self,
        soc: Option<&dml::Soc>,
        paths: &[inventory::Path],
        ports: &[display::Port],
        lit: &[Modeset],
    ) {
        let selections: Vec<_> = lit.iter().map(|m| m.selection).collect();
        self.sst_outputs = paths
            .iter()
            .enumerate()
            .filter_map(|(index, path)| {
                if !matches!(
                    path.connector,
                    inventory::Connector::DisplayPort | inventory::Connector::HdmiTypeA
                ) {
                    return None;
                }
                let port = ports.iter().find(|p| p.path == *path)?;
                let sink = port.sink.as_ref().ok()?;
                let base = sink.edid.get(..128)?;
                narf_edid::Block::parse(base).ok()?;
                let modes = if let Some(m) = lit.iter().find(|m| m.selection.port == index) {
                    m.modes.iter().flatten().copied().collect()
                } else {
                    soc.map_or_else(Vec::new, |soc| {
                        dark_modes(soc, paths, port, max_bpc(), &selections)
                    })
                };
                let vrr_capable = match path.connector {
                    inventory::Connector::DisplayPort => sink
                        .dpcd
                        .as_ref()
                        .and_then(|d| crate::amdgpu_freesync::dp_sst_caps(&sink.edid, d)),
                    inventory::Connector::HdmiTypeA => sink.hdmi_vrr_range(),
                    _ => None,
                }
                .is_some();
                Some(SstOutput {
                    port: index,
                    edid: sink.edid.clone(),
                    modes,
                    vrr_capable,
                })
            })
            .collect();
    }
}
