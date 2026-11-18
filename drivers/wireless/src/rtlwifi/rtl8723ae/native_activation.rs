// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted under interface: original native façade activation for AE only.
use super::*;
impl Native {
    pub(in crate::rtlwifi) fn commit_ae_station<T>(
        &self,
        commit: impl FnOnce() -> Result<T, super::super::prepare::Error>,
    ) -> Result<T, super::super::prepare::Error> {
        let _publication = self.admission.publication.lock();
        if self.removed.load(Ordering::Acquire)
            || !self.published.load(Ordering::Acquire)
            || self.admission.closed.load(Ordering::Acquire)
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            return Err(super::super::prepare::Error::State);
        }
        commit()
    }
    /// Lock order matches native MLME: lifecycle -> original Prepared.
    /// The caller owns the registered AE admission mutex and has made the
    /// attempt terminal before this wait. No ring/firmware reconstruction.
    pub(in crate::rtlwifi) async fn prepare_ae_station(
        &self,
    ) -> Result<(), super::super::prepare::Error> {
        use super::super::prepare;
        let _control = self.lifecycle.control.lock().await;
        if self.removed.load(Ordering::Acquire)
            || !self.published.load(Ordering::Acquire)
            || self.admission.closed.load(Ordering::Acquire)
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            return Err(prepare::Error::State);
        }
        let mut storage = self.prepared.lock().await;
        let owner = storage.as_mut().ok_or(prepare::Error::State)?;
        if owner.chip() != prepare::Chip::Rtl8723ae || owner.phase() != Phase::Prepared {
            return Err(prepare::Error::State);
        }
        let (program, grant) = owner.rtl8723ae_program()?;
        program
            .wait(grant, owner.configure_rtl8723ae_station())
            .await?;
        let domain = program.prepared().current_domain()?;
        owner
            .stage_rtl8723ae_station_program(program.clone(), &domain)
            .map_err(|_| prepare::Error::State)?;
        program.with_current(|| {
            if self.removed.load(Ordering::Acquire)
                || self.admission.closed.load(Ordering::Acquire)
                || owner.rtl8723ae_program()?.1 != grant
            {
                return Err(prepare::Error::State);
            }
            // The façade has existed on the SAME name/wiphy since probe.
            // Commit the actual original prepared channel without reset,
            // replacement, rfkill removal/re-add or a fresh source owner.
            self.lifecycle
                .channel
                .store(grant.channel(), Ordering::Release);
            Ok(())
        })
    }
}
