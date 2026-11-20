// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual native20/40 program selection, separate from peer metadata.
use super::*;
#[cfg(any(test, feature = "kernel-test"))]
use crate::rtl8xxxu::ht_runtime::WideProgram;
use crate::rtl8xxxu::{
    device_init::Factory,
    ht_runtime::{Geometry, WideMode, WidePlan, WideQualification},
    management_runtime::Candidate,
};
impl<C: ControlIo, B: PacketIo> Receiver<C, B> {
    pub(in crate::rtl8xxxu) fn has_wide_profiles(&self) -> bool {
        !self.wide_profiles.is_empty()
    }
    pub(in crate::rtl8xxxu) fn wide_mode(&self) -> Option<(Geometry, WideMode)> {
        self.wide.as_ref().map(|p| (p.geometry(), p.mode()))
    }
    pub(in crate::rtl8xxxu) fn wide_plan_for_channel(&self, channel: u8) -> Option<WidePlan> {
        self.wide_profiles
            .iter()
            .find(|q| q.geometry().primary() == channel)
            .map(|q| WidePlan::new(q.clone(), WideMode::Twenty))
    }
    pub(in crate::rtl8xxxu) fn resolve_wide_profiles(
        base: &Arc<super::super::wmm_runtime::Proof>,
        executable: super::super::firmware_transport::Executable,
        factory: Factory,
    ) -> Result<Vec<Arc<WideQualification>>, Error> {
        let mut profiles = Vec::new();
        for primary in 1u8..=13 {
            let selected = base.for_channel(primary);
            base.invoke(|| ())?;
            let Ok(selected) = selected else {
                continue;
            };
            for secondary in [primary.checked_sub(4), primary.checked_add(4)]
                .into_iter()
                .flatten()
            {
                let Ok(geometry) = Geometry::new(primary, secondary) else {
                    continue;
                };
                if let Some(q) =
                    WideQualification::registered(selected.clone(), executable, factory, geometry)?
                {
                    profiles.push(q);
                }
            }
        }
        Ok(profiles)
    }
    /// Selects only an already signed current geometry. Missing geometry
    /// falls back to a20MHz offer; metadata never creates a new qualification.
    pub(in crate::rtl8xxxu) fn ht_local_for(
        &self,
        candidate: &Candidate,
    ) -> Option<narf_wireless::association::phy::LocalPhy> {
        let local = self.ht_local()?;
        let mut secondary = None;
        let mut at = candidate.information_elements();
        while at.len() >= 2 {
            let len = usize::from(at[1]) + 2;
            let element = at.get(..len)?;
            if element[0] == 61 && element.len() == 24 {
                secondary = match element[3] & 3 {
                    1 => candidate.channel().checked_add(4),
                    3 => candidate.channel().checked_sub(4),
                    _ => None,
                };
            }
            at = &at[len..];
        }
        if let Some(second) = secondary {
            if let Ok(geometry) = Geometry::new(candidate.channel(), second) {
                if self
                    .wide_profiles
                    .iter()
                    .any(|q| q.geometry() == geometry && q.gains().is_ok())
                {
                    return Some(super::super::ht_runtime::local_wide());
                }
            }
        }
        // A current v2 program qualifies20MHz fallback too; preserve v1's
        // original20MHz-only local profile when it is the active owner.
        Some(if self.wide.is_some() {
            super::super::ht_runtime::local()
        } else {
            local
        })
    }
    pub(in crate::rtl8xxxu) async fn select_station_geometry(
        &mut self,
        geometry: Option<Geometry>,
    ) -> Result<(), Error> {
        let plan = if let Some(geometry) = geometry {
            let q = self
                .wide_profiles
                .iter()
                .find(|q| q.geometry() == geometry)
                .ok_or(Error::State)?
                .clone();
            Some(WidePlan::new(q, WideMode::Forty))
        } else if let Some(program) = &self.wide {
            let q = self
                .wide_profiles
                .iter()
                .find(|q| q.geometry() == program.geometry())
                .cloned()
                .ok_or(Error::State)?;
            Some(WidePlan::new(q, WideMode::Twenty))
        } else {
            None
        };
        let Some(plan) = plan else {
            return Ok(());
        };
        if self.wide_mode() == Some((plan.geometry(), plan.mode())) {
            return Ok(());
        }
        self.cold_wide_plan(plan).await?;
        Ok(())
    }
    pub(in crate::rtl8xxxu) fn confirm_station_geometry(
        &self,
        geometry: Option<Geometry>,
    ) -> Result<(), Error> {
        match (geometry, self.wide_mode()) {
            (Some(expected), Some((actual, WideMode::Forty))) if expected == actual => Ok(()),
            (None, Some((_, WideMode::Forty))) | (Some(_), _) => Err(Error::State),
            (None, _) => Ok(()),
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtl8xxxu) async fn install_wide_model(
        &mut self,
        qualification: Arc<WideQualification>,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        if qualification.geometry().primary() == self.channel() {
            let program = WideProgram::install(
                &self.firmware,
                WidePlan::new(qualification.clone(), WideMode::Twenty),
            )
            .await?;
            self.ht = None;
            self.ht_gains = None;
            self.wide = Some(program);
        }
        self.wide_profiles.push(qualification);
        Ok(())
    }
}
