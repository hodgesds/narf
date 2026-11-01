//! Fixed, callback-free AP emission authority captured outside native State.
use super::*;
use core::task::Waker;
use narf_net::native_emission::Lifetime;

/// Retains original capabilities and only weak concrete provider identities.
/// Native drivers separately prove their actual role generation, PCI/RF,
/// command/copy epochs, installed keys, peers and controlled ports. Cleanup
/// after this guard dies uses still-current device authority, not this grant.
#[derive(Clone, Debug)]
pub struct ApEmissionAuthority {
    admin: narf_net::AdminEmissionAuthority,
    source: Lifetime,
    registration: Lifetime,
    receiver: usize,
    mode: u32,
    generation: NonZeroU64,
}
impl ApControlAuthority {
    /// All arbitrary source/interface callbacks execute during capture,
    /// outside the native State lock. Unknown socket providers and control-
    /// only ancestry refuse; no cached current bool is converted to authority.
    pub fn native_emission_for<I: WirelessNetIface + ?Sized>(
        &self,
        receiver: &I,
    ) -> Result<ApEmissionAuthority, WirelessError> {
        self.check_for(receiver)?;
        self.require_up()?;
        if !matches!(self.kind, ControlKind::Ap) {
            return Err(WirelessError::NotSupported);
        }
        let Target::Netdev { ifindex, epoch } = self.target else {
            return Err(WirelessError::NotSupported);
        };
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        let registration =
            crate::registry::native_registration(receiver).ok_or(WirelessError::Denied)?;
        let source = self
            .reply
            .native_source()
            .ok_or(WirelessError::NotSupported)?;
        let admin = self
            .admin
            .native_emission(
                iface.name(),
                self.namespace,
                ifindex.get(),
                epoch.get(),
                iface.mac(),
            )
            .map_err(|_| WirelessError::Denied)?;
        let guard = ApEmissionAuthority {
            admin,
            source,
            registration,
            receiver: core::ptr::from_ref(receiver).cast::<()>() as usize,
            mode: self.mode,
            generation: self.generation,
        };
        self.check_for(receiver)?;
        self.require_up()?;
        if !guard.current() {
            return Err(WirelessError::Denied);
        }
        Ok(guard)
    }
}
impl ApEventAuthority {
    pub fn native_emission_for<I: WirelessNetIface + ?Sized>(
        &self,
        receiver: &I,
    ) -> Result<ApEmissionAuthority, WirelessError> {
        self.guard.native_emission_for(receiver)
    }
}
impl ApEmissionAuthority {
    /// Callback-free current authority; no virtual method, source socket,
    /// Registry or IFACES lock. The native driver must also check the current
    /// concrete role-generation owner it bound during capture.
    pub fn current(&self) -> bool {
        self.source.current() && self.registration.current() && self.admin.current()
    }
    pub fn matches_role<I: WirelessNetIface + ?Sized>(
        &self,
        receiver: &I,
        mode: u32,
        generation: NonZeroU64,
    ) -> bool {
        self.receiver == core::ptr::from_ref(receiver).cast::<()>() as usize
            && self.mode == mode
            && self.generation == generation
            && self.current()
    }
    /// Register the retained physical cleanup owner's waker outside native
    /// State. A provider retirement wakes it, even with no RF interrupt. The
    /// owner must additionally poll on a bounded timer for cap epoch revocation.
    pub fn watch(&self, waker: &Waker) -> bool {
        self.source.watch(waker.clone())
            && self.registration.watch(waker.clone())
            && self.admin.watch(waker)
            && self.current()
    }
}
