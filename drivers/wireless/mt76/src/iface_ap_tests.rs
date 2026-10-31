//! Scoped concrete-interface fixture. It refuses to displace an actual
//! active radio; it uses the same native callback/publication implementation.
use super::*;
use narf_capabilities::{Cap, Invoke};
pub(crate) struct Binding {
    pub iface: Arc<Mt76Iface>,
    pub admin: narf_net::AdminHandle,
    pub daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
}
impl Drop for Binding {
    fn drop(&mut self) {
        let mut active = ACTIVE.lock();
        if active.as_ref().is_some_and(|a| Arc::ptr_eq(a, &self.iface)) {
            *active = None;
        }
        drop(active);
        self.iface.close_ap_host();
        self.iface.withdraw_p2p_metadata();
        narf_wireless::registry::unregister(self.iface.name());
        narf_net::registry().unregister(self.iface.name());
        narf_net::iface::unregister(self.iface.name());
    }
}
pub(crate) fn bind(info: RadioInfo) -> Result<Binding, &'static str> {
    bind_profile(info, None)
}
pub(crate) fn bind_profile(
    info: RadioInfo,
    profile: Option<crate::mt7921::firmware_transport::P2pProfile>,
) -> Result<Binding, &'static str> {
    if ACTIVE.lock().is_some() {
        return Err("active physical radio cannot be displaced");
    }
    let name = narf_net::iface::register(
        "mt76-ap-concrete-proof%d",
        info.capabilities.mac,
        send_frame,
    );
    struct Unpublished(Option<String>);
    impl Drop for Unpublished {
        fn drop(&mut self) {
            if let Some(name) = self.0.as_ref() {
                narf_wireless::registry::unregister(name);
                narf_net::registry().unregister(name);
                narf_net::iface::unregister(name);
            }
        }
    }
    let mut unpublished = Unpublished(Some(name.clone()));
    let mut iface = Mt76Iface::new(name.clone(), info).map_err(|_| "concrete iface identity")?;
    iface.p2p_profile = profile;
    let iface = Arc::new(iface);
    let authority = narf_net::bootstrap_authority();
    let cap = narf_net::registry()
        .register(&authority, RegisteredIface(iface.clone()))
        .map_err(|_| "concrete registry grant")?;
    *iface.registration_cap.lock() = Some(cap);
    let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
    let admin =
        narf_net::stack::control_registered(&narf_net::stack::StackAttach { iface: cap, daemon })
            .map_err(|_| "concrete delegated administration")?
            .admin;
    let binding = Binding {
        iface,
        admin,
        daemon,
    };
    unpublished.0 = None;
    {
        let mut active = ACTIVE.lock();
        if active.is_some() {
            return Err("physical probe won concrete fixture admission");
        }
        *active = Some(binding.iface.clone());
    }
    narf_wireless::registry::register(binding.iface.clone());
    // Exercise the production mode transition, rather than editing atomic
    // state or manufacturing an AP mode/generation in the fixture.
    binding
        .iface
        .set_iftype(3)
        .map_err(|_| "concrete AP mode transition")?;
    Ok(binding)
}
