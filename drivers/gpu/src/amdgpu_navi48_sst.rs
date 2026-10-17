//! Physical connector inventory independent of successful scanout.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SstOutput {
    pub port: usize,
    pub edid: Vec<u8>,
    /// Independent candidates beside the current streams, not reservations.
    pub modes: Vec<Timing>,
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
        let Ok(mut candidate) = select(paths, core::slice::from_ref(port), max_bpc, Some(timing))
        else {
            continue;
        };
        // select may fall back to preferred; admission must describe this mode.
        if candidate.timing != timing
            || (candidate.frl.is_some() && lit.iter().any(|s| s.frl.is_some()))
            || refine_dsc(soc, core::slice::from_mut(&mut candidate)).is_err()
        {
            continue;
        }
        let mut modes: Vec<_> = lit.iter().map(selection_mode).collect();
        modes.push(selection_mode(&candidate));
        if dml::admit_all(soc, &modes).is_ok() {
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
                Some(SstOutput {
                    port: index,
                    edid: sink.edid.clone(),
                    modes,
                })
            })
            .collect();
    }
}
