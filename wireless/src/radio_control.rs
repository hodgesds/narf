//! Typed source-bound control for native CNM/P2P work (next batch).
//! The private shared identity code creates no additional grant.
use super::*;
use alloc::{vec, vec::Vec};

#[derive(Clone, Debug)]
pub struct RadioControlAuthority {
    guard: ApControlAuthority,
}
impl RadioControlAuthority {
    /// Native station/client/GO/device controls use the actual delegated
    /// grant, registered interface/mode generation and exact source socket.
    /// AP-only binding remains a separate constructor with its own modes.
    pub fn bind(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        ifindex: u32,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        Ok(Self {
            guard: ApControlAuthority::bind_radio(admin, iface, namespace, ifindex, reply)?,
        })
    }
    /// Bind an actual control-only P2P-device registration. There is no
    /// netdev/ifindex argument and no synthetic administrative UP state.
    pub fn bind_wdev(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        wdev: u64,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        Ok(Self {
            guard: ApControlAuthority::bind_control_wdev(admin, iface, namespace, wdev, reply)?,
        })
    }
    pub fn current(&self) -> Result<(), WirelessError> {
        self.guard.current()
    }
    /// Explicitly retain this newly created child's actual current grant on
    /// the exact creating socket. The typed net operation also proves the
    /// registered parent-cap relation inside its parent/daemon/child invokes.
    /// A source sink, name or observed WDEV cannot manufacture authority.
    pub fn retain_control_child(
        &self,
        child: &Arc<dyn WirelessNetIface>,
        cap: &narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Write>,
    ) -> Result<(), WirelessError> {
        self.current()?;
        let parent = self.guard.iface.upgrade().ok_or(WirelessError::Denied)?;
        if !crate::registry::control_parent_matches(&parent, child)
            || child.control_namespace() != Some(self.guard.namespace)
        {
            return Err(WirelessError::Denied);
        }
        let admin = self
            .guard
            .admin
            .control_registered_child(cap)
            .map_err(|_| WirelessError::Denied)?;
        self.current()?;
        if !crate::registry::control_parent_matches(&parent, child) {
            return Err(WirelessError::Denied);
        }
        if let Some(admin) = admin {
            admin
                .authorize_interface(child.name(), self.guard.namespace)
                .map_err(|_| WirelessError::Denied)?;
            self.guard
                .reply
                .retain_control_admin(admin)
                .map_err(|_| WirelessError::Denied)?;
        }
        self.current()
    }
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.guard.check_for(iface)
    }
    /// Require the actual admitted role without exporting its underlying
    /// grant. A current station/AP request cannot start a P2P-device BSS.
    pub fn require_mode(&self, mode: u32) -> Result<(), WirelessError> {
        self.current()?;
        if self.guard.mode != mode {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    pub fn reserve(self) -> Result<Self, WirelessError> {
        Ok(Self {
            guard: self.guard.reserve()?,
        })
    }
    pub fn has_reservation(&self) -> bool {
        self.guard.has_reservation()
    }
    /// A P2P-device wdev has no administrative-UP netdev contract. Its
    /// actual START_P2P_DEVICE receipt is checked by the native owner; this
    /// identity observation cannot substitute for it or authorize RF use.
    pub fn require_link(&self) -> Result<(), WirelessError> {
        self.current()?;
        if self.guard.mode != 10 {
            self.guard.require_up()?;
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<RadioInterfaceIdentity, WirelessError> {
        self.require_link()?;
        let identity = RadioInterfaceIdentity {
            identity: self.guard.capture_identity(self.guard.mode != 10)?,
        };
        identity.current()?;
        Ok(identity)
    }
    /// Bind a new current request to the same completed native interface.
    /// Neither a same-MAC namesake nor another valid radio grant suffices.
    pub fn check_identity(&self, identity: &RadioInterfaceIdentity) -> Result<(), WirelessError> {
        self.require_link()?;
        identity.current()?;
        let retained = &identity.identity;
        if !Weak::ptr_eq(&self.guard.iface, &retained.iface)
            || self.guard.namespace != retained.namespace
            || self.guard.target != retained.target
            || self.guard.mode != retained.mode
            || self.guard.generation != retained.generation
        {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    pub fn event_authority(&self) -> Result<RadioEventAuthority, WirelessError> {
        self.current()?;
        let mut source = self.clone();
        source.guard.reservation = None;
        source.guard.reserved = false;
        Ok(RadioEventAuthority { source })
    }
}
impl narf_net::netlink_generic::DeferredAuthority for RadioControlAuthority {
    fn current(&self) -> bool {
        RadioControlAuthority::current(self).is_ok()
    }
}
/// Completed native device identity, with no command/packet/RF authority.
/// The driver additionally proves an actual started P2P wdev when mode10.
#[derive(Clone, Debug)]
pub struct RadioInterfaceIdentity {
    identity: ApInterfaceIdentity,
}
impl RadioInterfaceIdentity {
    pub fn mac(&self) -> [u8; 6] {
        self.identity.mac()
    }
    pub fn current(&self) -> Result<(), WirelessError> {
        self.identity.check_with_up(None, self.identity.mode != 10)
    }
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.identity.check_with_up(
            Some(core::ptr::from_ref(iface).cast::<()>()),
            self.identity.mode != 10,
        )
    }
}
/// Only typed ROC/native-management events may use the retained exact
/// source. The native driver supplies actual started/channel/copy facts.
#[derive(Clone, Debug)]
pub struct RadioEventAuthority {
    source: RadioControlAuthority,
}
impl RadioEventAuthority {
    pub fn registration_current(&self) -> Result<(), WirelessError> {
        self.source.current()
    }
    pub fn current(&self) -> Result<(), WirelessError> {
        self.source.require_link()
    }
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.source.check_for(iface)?;
        self.current()
    }
    /// Call only after the matching native CNM grant, not queued acquire or
    /// command-DMA progress. `duration_ms` is its actual bounded interval.
    pub fn roc_ready(
        &self,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        self.roc(55, cookie, frequency_mhz, duration_ms)
    }
    /// Native timer/abort/retirement ownership must be resolved by the
    /// driver; a local source lookup does not make an uncertain ROC expire.
    pub fn roc_expired(
        &self,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        self.roc(56, cookie, frequency_mhz, duration_ms)
    }
    fn roc(
        &self,
        command: u8,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        if cookie == 0 || frequency_mhz == 0 || duration_ms == 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut attrs = self.base()?;
        attr(&mut attrs, 38, &frequency_mhz.to_ne_bytes());
        attr(&mut attrs, 87, &duration_ms.to_ne_bytes());
        attr(&mut attrs, 88, &cookie.to_ne_bytes());
        self.deliver(command, attrs)
    }
    /// The driver must recheck its native copy/channel owner and installed
    /// filter immediately before this typed delivery. It grants no packet.
    pub fn management_received(
        &self,
        frequency_mhz: u32,
        signal_dbm: Option<i8>,
        frame: &[u8],
    ) -> Result<(), WirelessError> {
        if !(24..=4096).contains(&frame.len()) || frame[0] & 15 != 0 || frequency_mhz == 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut attrs = self.base()?;
        attr(&mut attrs, 38, &frequency_mhz.to_ne_bytes());
        if let Some(signal) = signal_dbm {
            attr(&mut attrs, 151, &i32::from(signal).to_ne_bytes());
        }
        attr(&mut attrs, 51, frame);
        self.deliver(59, attrs)
    }
    /// The native scheduled request is running only after the driver's
    /// matching firmware start receipt. Admission/queued work is insufficient.
    pub fn scheduled_scan_started(&self) -> Result<(), WirelessError> {
        self.scheduled_scan(75)
    }
    /// Report only admitted native BSS results from the retained scan UID,
    /// after current source/channel/filter checks and outside owner locks.
    pub fn scheduled_scan_results(&self) -> Result<(), WirelessError> {
        self.scheduled_scan(77)
    }
    /// Publish the actual admitted native scan snapshot before RESULTS, so
    /// GET_SCAN observes the same BSS records. This adds no RF authority;
    /// the driver retains its copy-time/filter/native-UID proof throughout.
    pub fn scheduled_scan_results_with_bss(
        &self,
        results: Vec<(crate::BssInfo, Vec<u8>)>,
    ) -> Result<(), WirelessError> {
        self.current()?;
        let iface = self
            .source
            .guard
            .iface
            .upgrade()
            .ok_or(WirelessError::Denied)?;
        crate::nl80211::scheduled_results(
            self,
            iface.name(),
            self.source.guard.namespace,
            self.source.guard.netdev_ifindex()?,
            results,
        )?;
        self.current()?;
        self.scheduled_scan(77)
    }
    /// Actual native stop/terminal completion precedes this notification.
    /// An ACK, abandoned waiter or expired host timer cannot prove it.
    pub fn scheduled_scan_stopped(&self) -> Result<(), WirelessError> {
        self.scheduled_scan(78)
    }
    fn scheduled_scan(&self, command: u8) -> Result<(), WirelessError> {
        let attrs = self.base()?;
        self.current()?;
        narf_net::netlink_generic::publish_event(
            crate::nl80211::NL80211_FAMILY_ID,
            18,
            self.source.guard.namespace,
            narf_net::netlink_generic::GenlReply { command, attrs },
        );
        Ok(())
    }
    fn base(&self) -> Result<Vec<u8>, WirelessError> {
        self.current()?;
        let iface = self
            .source
            .guard
            .iface
            .upgrade()
            .ok_or(WirelessError::Denied)?;
        let wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(WirelessError::Denied)?;
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &wiphy.to_ne_bytes());
        if let Ok(ifindex) = self.source.guard.netdev_ifindex() {
            attr(&mut attrs, 3, &ifindex.to_ne_bytes());
        }
        let wdev = self.source.guard.target.wdev(wiphy);
        attr(&mut attrs, 153, &wdev.to_ne_bytes());
        Ok(attrs)
    }
    fn deliver(&self, command: u8, attrs: Vec<u8>) -> Result<(), WirelessError> {
        self.current()?;
        let mut message = vec![0; 16];
        message[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
        message.extend_from_slice(&[command, 1, 0, 0]);
        message.extend_from_slice(&attrs);
        let len = message.len() as u32;
        message[..4].copy_from_slice(&len.to_ne_bytes());
        self.current()?;
        self.source
            .guard
            .reply
            .deliver(message)
            .map_err(|_| WirelessError::Denied)
    }
}
fn attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    out.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize((out.len() + 3) & !3, 0);
}
