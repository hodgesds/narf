//! Native management RX belongs to a started independent WDEV and the
//! actual CNM lease. Subscription metadata alone opens no receive owner.
use super::*;
use super::{
    p2p_management_capture::{Captured, Spec},
    p2p_management_filters::{Install, Shared},
};
use narf_wireless::ap_control::RadioControlAuthority;
#[derive(Debug, Default)]
pub(super) struct Management {
    pub filters: Option<Shared>,
    pub capture: Option<Spec>,
    pub tx: Option<super::p2p_management_tx::Emission>,
}
impl<B: Backend> Session<B> {
    pub(super) fn bind_p2p_management(
        &mut self,
        authority: &RadioControlAuthority,
        filters: Shared,
    ) -> Result<(), Error> {
        self.check_p2p_request(authority)?;
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        if owner
            .management
            .filters
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, &filters))
        {
            return Ok(());
        }
        owner.management.filters = Some(filters);
        self.close_p2p_management_capture();
        Ok(())
    }
    pub(super) fn close_p2p_management_capture(&mut self) {
        self.backend.close_p2p_capture();
        if let Some(owner) = self.p2p_owner.as_mut() {
            owner.management.capture = None;
        }
    }
    fn planned_p2p_capture(&self, filters: u64) -> Result<Option<Spec>, Error> {
        let Some(owner) = self
            .p2p_owner
            .as_ref()
            .filter(|owner| owner.activated && owner.ready)
        else {
            return Ok(None);
        };
        let Some(lease) = owner.cnm.lease() else {
            return Ok(None);
        };
        if !self.p2p_roc_current(lease.cookie, lease.frequency_mhz)? {
            return Ok(None);
        }
        Spec::prepare(
            owner.info,
            owner.vif,
            owner.identity.mac(),
            filters,
            lease,
            self.backend.now_ns(),
        )
        .map(Some)
    }
    pub(super) fn register_p2p_management(
        &mut self,
        authority: &RadioControlAuthority,
        filters: Shared,
        install: Install,
    ) -> Result<(), i32> {
        authority.require_mode(10).map_err(|_| 1)?;
        if !authority.has_reservation() {
            return Err(1);
        }
        self.backend.check().map_err(|_| 1)?;
        if self.p2p_owner.is_some() {
            self.check_p2p_request(authority).map_err(|_| 1)?;
        }
        let planned = self
            .planned_p2p_capture(install.generation())
            .map_err(|_| 1)?;
        self.close_p2p_management_capture();
        if let Some(spec) = planned {
            self.backend
                .configure_p2p_capture(Some(spec))
                .map_err(|_| 5)?;
        }
        let committed = filters.commit(install);
        if let Err(error) = committed {
            self.close_p2p_management_capture();
            return Err(error);
        }
        if let Some(owner) = self.p2p_owner.as_mut() {
            owner.management.filters = Some(filters);
            owner.management.capture = planned;
        }
        if authority.current().is_err() {
            self.close_p2p_management_capture();
            return Err(1);
        }
        Ok(())
    }
    /// Preserve an unchanged actual capture; any filter/lease change earns a
    /// new epoch only AFTER the native finite descriptor-prefix cut.
    pub(super) fn refresh_p2p_management_capture(&mut self) -> Result<(), Error> {
        let Some(filters) = self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.management.filters.clone())
        else {
            return Ok(());
        };
        let snapshot = filters.snapshot();
        if !snapshot.has_current_source() {
            self.close_p2p_management_capture();
            return Ok(());
        }
        if let Some(old) = self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.management.capture)
        {
            let same_lease = self.p2p_owner.as_ref().and_then(|owner|owner.cnm.lease()).is_some_and(|lease| {
                lease.cookie==old.cookie && lease.frequency_mhz==old.frequency_mhz
                    && matches!(lease.phase, crate::mt7921::p2p_cnm::Phase::Granted { expires_ns, .. } if expires_ns==old.expires_ns)
            });
            if old.filters == snapshot.generation
                && same_lease
                && self.p2p_roc_current(old.cookie, old.frequency_mhz)?
            {
                return Ok(());
            }
        }
        let Some(planned) = self.planned_p2p_capture(snapshot.generation)? else {
            self.close_p2p_management_capture();
            return Ok(());
        };
        if self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.management.capture)
            .is_some_and(|old| {
                old.filters == planned.filters
                    && old.cookie == planned.cookie
                    && old.frequency_mhz == planned.frequency_mhz
                    && old.expires_ns == planned.expires_ns
                    && old.local == planned.local
                    && old.vif == planned.vif
            })
        {
            return Ok(());
        }
        self.close_p2p_management_capture();
        self.backend.configure_p2p_capture(Some(planned))?;
        if !self.p2p_roc_current(planned.cookie, planned.frequency_mhz)? {
            self.close_p2p_management_capture();
            return Err(Error::Authority);
        }
        self.p2p_owner
            .as_mut()
            .ok_or(Error::Busy)?
            .management
            .capture = Some(planned);
        Ok(())
    }
    fn p2p_management_copy_current(&self, packet: &Captured) -> Result<bool, Error> {
        self.backend.check()?;
        let Some(owner) = self
            .p2p_owner
            .as_ref()
            .filter(|owner| owner.ready && owner.activated)
        else {
            return Ok(false);
        };
        Ok(owner.management.capture == Some(packet.spec)
            && owner.identity.current().is_ok()
            && owner
                .management
                .filters
                .as_ref()
                .is_some_and(|filters| filters.snapshot().generation == packet.spec.filters)
            && self.p2p_roc_current(packet.spec.cookie, packet.spec.frequency_mhz)?)
    }
    pub(super) fn service_p2p_management_receive(&mut self) -> Result<(), Error> {
        self.refresh_p2p_management_capture()?;
        if self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.management.capture)
            .is_none()
        {
            return Ok(());
        }
        for _ in 0..8 {
            let Some(packet) = self.backend.receive_p2p_management()? else {
                break;
            };
            if !self.p2p_management_copy_current(&packet)? {
                continue;
            }
            let Some(decoded) = super::p2p_management_wire::received(
                &packet.packet,
                packet.spec.nss,
                packet.spec.local,
                packet.spec.frequency_mhz,
            ) else {
                continue;
            };
            let filters = self
                .p2p_owner
                .as_ref()
                .and_then(|owner| owner.management.filters.clone())
                .ok_or(Error::Busy)?;
            let snapshot = filters.snapshot();
            if snapshot.generation != packet.spec.filters {
                continue;
            }
            let Some(source) = snapshot.receiver(decoded.frame_type, &decoded.frame[24..]) else {
                continue;
            };
            if !self.p2p_management_copy_current(&packet)? {
                continue;
            }
            // No driver/registry spinlock is held across a source callback.
            // Reentrant closure/revocation can only suppress this event.
            let _ = source.management_received(
                packet.spec.frequency_mhz,
                decoded.signal_dbm,
                decoded.frame,
            );
        }
        Ok(())
    }
}
