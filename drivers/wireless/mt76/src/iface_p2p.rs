//! Actual control-only P2P-device registration and retained physical owner.
//! The metadata object has no Ethernet entry, IFINDEX, UP bit or frame rings.
use super::*;
use alloc::sync::Weak;
use core::num::NonZeroU64;
use narf_capabilities::{Cap, Grant, Write};
use narf_wireless::ap_control::{RadioControlAuthority, RadioInterfaceIdentity};

#[derive(Debug)]
pub(crate) struct P2pDeviceIface {
    name: String,
    namespace: u64,
    mac: [u8; 6],
    parent: Weak<Mt76Iface>,
    physical: u64,
    parent_epoch: u64,
    allocation: crate::mt7921::vif_slots::Allocation,
    cnm: bool,
    registration: IrqSafeSpinLock<Option<Registration>>,
    identity: IrqSafeSpinLock<Option<RadioInterfaceIdentity>>,
    owned: AtomicBool,
    management: crate::mt7921::firmware_transport::p2p_management_filters::Shared,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
#[derive(Debug)]
struct Registration {
    net: Cap<narf_net::NetIface, Write>,
    wdev: narf_wireless::registry::ControlWdev,
}
struct PendingSlot<'a> {
    parent: &'a Mt76Iface,
    allocation: crate::mt7921::vif_slots::Allocation,
    committed: bool,
}
impl Drop for PendingSlot<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.parent
                .vif_slots
                .lock()
                .release_retired(self.allocation);
        }
    }
}
impl Mt76Iface {
    /// Metadata publication only. The caller supplies the current source
    /// authority and actual registration grant; START is a separate operation.
    pub(crate) fn create_p2p_device(
        self: &Arc<Self>,
        authority: &RadioControlAuthority,
        registration_grant: &Cap<narf_net::NetIface, Grant>,
        namespace: u64,
        name: &str,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<P2pDeviceIface>, WirelessError> {
        authority.check_for(self.as_ref())?;
        if !authority.has_reservation() {
            return Err(WirelessError::Denied);
        }
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) {
            return Err(WirelessError::InvalidArgs);
        }
        let mac = mac.unwrap_or_else(|| {
            crate::mt7921::vif_slots::mac_candidates(self.mac())
                .into_iter()
                .find(|candidate| *candidate != self.mac())
                .unwrap_or_else(|| self.mac())
        });
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let _control = self.control.try_lock().ok_or(WirelessError::Busy)?;
        if self.p2p_device.lock().is_some() || self.sleeping.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let metadata = narf_net::iface::lookup(self.name()).ok_or(WirelessError::Denied)?;
        if !ACTIVE
            .lock()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, self))
            || metadata.net_ns_id != namespace
            || metadata.ownership_epoch == 0
        {
            return Err(WirelessError::Denied);
        }
        let allocation = self.vif_slots.lock().reserve().map_err(map_error)?;
        let mut pending = PendingSlot {
            parent: self,
            allocation,
            committed: false,
        };
        let actual = Arc::new(P2pDeviceIface {
            name: name.into(),
            namespace,
            mac,
            parent: Arc::downgrade(self),
            physical: self.wiphy_id(),
            parent_epoch: metadata.ownership_epoch,
            allocation,
            cnm: self.p2p_profile.is_some_and(|profile| profile.cnm()),
            registration: IrqSafeSpinLock::new(None),
            identity: IrqSafeSpinLock::new(None),
            owned: AtomicBool::new(false),
            management: Arc::new(Default::default()),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        });
        let parent_cap = self
            .registration_cap
            .lock()
            .as_ref()
            .copied()
            .ok_or(WirelessError::Denied)?;
        let net = narf_net::registry()
            .register_control_child(registration_grant, &parent_cap, Registered(actual.clone()))
            .map_err(|error| match error {
                narf_net::ControlRegisterError::AuthorityRevoked => WirelessError::Denied,
                narf_net::ControlRegisterError::DuplicateName => WirelessError::Busy,
                narf_net::ControlRegisterError::NotControl => WirelessError::InvalidArgs,
            })?;
        let parent: Arc<dyn WirelessNetIface> = self.clone();
        let iface: Arc<dyn WirelessNetIface> = actual.clone();
        let wdev = match narf_wireless::registry::register_control(&parent, iface.clone()) {
            Ok(wdev) => wdev,
            Err(_) => {
                narf_net::registry().unregister_for_handle(&net);
                return Err(WirelessError::Busy);
            }
        };
        *actual.registration.lock() = Some(Registration { net, wdev });
        *self.p2p_device.lock() = Some(actual.clone());
        let publication = (|| {
            authority.check_for(self.as_ref())?;
            actual.current()?;
            authority.retain_control_child(&iface, &net)
        })();
        if let Err(error) = publication {
            *self.p2p_device.lock() = None;
            actual.withdraw();
            return Err(error);
        }
        pending.committed = true;
        Ok(actual)
    }
    /// Concrete owner API for explicit control-device creation. The native
    /// BSS remains stopped until a separate current START request completes.
    /// Normal role discovery stays unchanged until native coexistence lands.
    pub fn new_p2p_device(
        &self,
        authority: &RadioControlAuthority,
        name: &str,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        authority.check_for(self)?;
        let parent = ACTIVE
            .lock()
            .as_ref()
            .filter(|active| core::ptr::eq(active.as_ref(), self))
            .cloned()
            .ok_or(WirelessError::Denied)?;
        let namespace = narf_net::iface::lookup(self.name())
            .ok_or(WirelessError::Denied)?
            .net_ns_id;
        let grant = narf_net::trusted_net_authority().ok_or(WirelessError::Denied)?;
        parent
            .create_p2p_device(authority, &grant, namespace, name, mac)
            .map(|child| child as Arc<dyn WirelessNetIface>)
    }
    pub(super) fn withdraw_p2p_metadata(&self) {
        let child = { self.p2p_device.lock().take() };
        if let Some(child) = child {
            child.withdraw();
        }
    }
    pub(super) fn commit_p2p_stopped(&self) {
        let child = { self.p2p_device.lock().clone() };
        if let Some(child) = child {
            child.commit_stopped();
        }
    }
    pub(super) async fn poll_p2p(&self) -> Result<bool, WirelessError> {
        let child = self.p2p_device.lock().clone();
        let Some(child) = child else {
            return Ok(false);
        };
        if !child.owned.load(Ordering::Acquire) {
            if child.current().is_err() {
                child.withdraw();
                let mut slot = self.p2p_device.lock();
                if slot
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &child))
                {
                    *slot = None;
                }
            }
            return Ok(false);
        }
        let Some(_control) = self.control.try_lock() else {
            return Ok(true);
        };
        crate::mt7921::firmware_transport::boot_p2p::maintenance(Arc::downgrade(&child))
            .await
            .map_err(map_error)?;
        // The control-only child has its own BSS. Its completed maintenance
        // must not monopolize the parent's station/AP packet service.
        Ok(false)
    }
}
impl P2pDeviceIface {
    pub(crate) fn management_subscriptions(
        &self,
    ) -> crate::mt7921::firmware_transport::p2p_management_filters::Shared {
        self.management.clone()
    }
    pub(crate) fn cleanup_current(&self) -> Result<(), WirelessError> {
        let parent = self.parent.upgrade().ok_or(WirelessError::Denied)?;
        if !ACTIVE
            .lock()
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &parent))
            || !parent
                .p2p_device
                .lock()
                .as_ref()
                .is_some_and(|child| core::ptr::eq(child.as_ref(), self))
        {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    pub(crate) fn physical_mac(&self) -> Result<[u8; 6], WirelessError> {
        self.cleanup_current()?;
        self.parent
            .upgrade()
            .map(|parent| parent.mac())
            .ok_or(WirelessError::Denied)
    }
    pub(crate) fn current(&self) -> Result<Arc<Mt76Iface>, WirelessError> {
        let parent = self.parent.upgrade().ok_or(WirelessError::Denied)?;
        // Copy local observations before entering any other registry or
        // interface callback. Retirement takes these same locks separately;
        // keeping one across current_for() would invert its lock order.
        let slot_current = { parent.vif_slots.lock().current(self.allocation) };
        let registered = { self.registration.lock().as_ref().map(|r| (r.net, r.wdev)) };
        let physical_current = {
            ACTIVE
                .lock()
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &parent))
        };
        let child_current = {
            parent
                .p2p_device
                .lock()
                .as_ref()
                .is_some_and(|child| core::ptr::eq(child.as_ref(), self))
        };
        if parent.sleeping.load(Ordering::Acquire)
            || !slot_current
            || narf_net::iface::lookup(parent.name()).is_none_or(|metadata| {
                metadata.ownership_epoch != self.parent_epoch
                    || metadata.net_ns_id != self.namespace
            })
            || !physical_current
            || !child_current
            || !registered
                .is_some_and(|(cap, wdev)| cap.invoke(Observed).is_ok() && wdev.current_for(self))
        {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }
    pub(crate) fn native_vif(&self) -> Result<crate::mt7921::vif_slots::Vif, WirelessError> {
        self.current()?;
        Ok(self.allocation.vif())
    }
    pub(crate) fn request_current(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.current()?;
        authority.check_for(self)?;
        authority.require_mode(10)
    }
    fn weak(&self) -> Result<Weak<Self>, WirelessError> {
        let parent = self.current()?;
        let child = parent.p2p_device.lock();
        child
            .as_ref()
            .filter(|child| core::ptr::eq(child.as_ref(), self))
            .map(Arc::downgrade)
            .ok_or(WirelessError::Denied)
    }
    pub(crate) fn work_started(&self) {
        self.owned.store(true, Ordering::Release);
    }
    pub(crate) fn commit_started(
        &self,
        authority: &RadioControlAuthority,
        identity: RadioInterfaceIdentity,
    ) -> Result<(), WirelessError> {
        self.request_current(authority)?;
        identity.check_for(self)?;
        *self.identity.lock() = Some(identity);
        self.owned.store(true, Ordering::Release);
        Ok(())
    }
    pub(crate) fn commit_stopped(&self) {
        self.identity.lock().take();
        self.owned.store(false, Ordering::Release);
    }
    pub(crate) fn retire_metadata(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<narf_wireless::ap_control::RadioControlRetirement, WirelessError> {
        if self.owned.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let cap = self
            .registration
            .lock()
            .as_ref()
            .map(|r| r.net)
            .ok_or(WirelessError::Denied)?;
        authority.retire_control(&cap)
    }
    pub(crate) fn release_retired_metadata(&self) {
        if self.owned.load(Ordering::Acquire) {
            return;
        }
        self.withdraw();
        if let Some(parent) = self.parent.upgrade() {
            let removed = {
                let mut child = parent.p2p_device.lock();
                if child
                    .as_ref()
                    .is_some_and(|child| core::ptr::eq(child.as_ref(), self))
                {
                    child.take()
                } else {
                    None
                }
            };
            drop(removed);
        }
    }
    /// Software-only exact-registration cleanup; native ownership must have
    /// been retired first. A failed native reset never reaches this function.
    fn withdraw(&self) {
        let registration = { self.registration.lock().take() };
        if let Some(registration) = registration {
            narf_wireless::registry::unregister_control(registration.wdev, self);
            narf_net::registry().unregister_for_handle(&registration.net);
            if let Some(parent) = self.parent.upgrade() {
                parent.vif_slots.lock().release_retired(self.allocation);
            }
        }
    }
    fn started(&self) -> bool {
        let identity = { self.identity.lock().clone() };
        self.current().is_ok() && identity.is_some_and(|identity| identity.check_for(self).is_ok())
    }
    pub(crate) fn started_current(&self) -> bool {
        self.started()
    }
    async fn request(
        &self,
        authority: &RadioControlAuthority,
        operation: crate::mt7921::firmware_transport::boot_p2p::Request,
    ) -> Result<(), WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        crate::mt7921::firmware_transport::boot_p2p::request(
            self.weak()?,
            Arc::new(authority.clone()),
            operation,
        )
        .await
        .map_err(map_error)
    }
}
impl Interface for P2pDeviceIface {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(self.namespace)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[derive(Debug)]
struct Registered(Arc<P2pDeviceIface>);
impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.0.control_namespace()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
#[async_trait]
impl WirelessNetIface for P2pDeviceIface {
    fn async_p2p_management_tx_control(&self) -> bool {
        self.cnm
    }
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        self.cnm
    }
    async fn mgmt_tx_radio_async(
        &self,
        authority: &RadioControlAuthority,
        _cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        if !self.cnm || !self.started_current() {
            return Err(WirelessError::NotSupported);
        }
        crate::mt7921::firmware_transport::boot_p2p::management_tx::transmit(
            self.weak()?,
            Arc::new(authority.clone()),
            request,
        )
        .await
        .map_err(|error| match error {
            crate::mt7921::firmware_transport::Error::UnsupportedFirmware => {
                WirelessError::NotSupported
            }
            other => map_error(other),
        })
    }
    fn async_p2p_management_rx_control(&self) -> bool {
        true
    }
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let parent = self.current().map_err(|_| 1)?;
        let _control = parent.control.lock().await;
        self.request_current(authority).map_err(|_| 1)?;
        crate::mt7921::firmware_transport::boot_p2p::management::register(
            self.weak().map_err(|_| 1)?,
            Arc::new(authority.clone()),
            frame_type,
            prefix.to_vec(),
        )
        .await
    }
    fn async_control_interfaces(&self) -> bool {
        true
    }
    fn release_control_metadata(&self) {
        self.release_retired_metadata();
    }
    async fn delete_control_interface_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<narf_wireless::ap_control::RadioControlRetirement, WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        crate::mt7921::firmware_transport::boot_p2p::delete(
            self.weak()?,
            Arc::new(authority.clone()),
        )
        .await
        .map_err(map_error)
    }
    fn wiphy_id(&self) -> u64 {
        self.physical
    }
    fn current_iftype(&self) -> u32 {
        10
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        let mut info = self
            .parent
            .upgrade()
            .map(|parent| parent.get_wireless_info())
            .unwrap_or(WirelessIfaceInfo {
                base_name: self.name.clone(),
                base_mac: self.mac,
                bands: Vec::new(),
                modes: WirelessModes::empty(),
                hw_caps: HwCaps {
                    ht_supported: false,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            });
        info.base_name = self.name.clone();
        info.base_mac = self.mac;
        info.modes = WirelessModes::empty();
        info
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        self.current().ok().and_then(|_| NonZeroU64::new(1))
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.current()?.ap_serial.try_reserve().map(Some)
    }
    fn async_p2p_device_control(&self) -> bool {
        true
    }
    fn async_roc_control(&self) -> bool {
        self.cnm
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        if self.cnm {
            5000
        } else {
            0
        }
    }
    async fn start_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.request(
            authority,
            crate::mt7921::firmware_transport::boot_p2p::Request::Start,
        )
        .await
    }
    async fn stop_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.request(
            authority,
            crate::mt7921::firmware_transport::boot_p2p::Request::Stop,
        )
        .await
    }
    async fn remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        self.request_current(authority)?;
        if !self.started() {
            return Err(WirelessError::Busy);
        }
        self.request(
            authority,
            crate::mt7921::firmware_transport::boot_p2p::Request::Roc {
                cookie,
                frequency_mhz,
                duration_ms,
            },
        )
        .await
    }
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        self.request(
            authority,
            crate::mt7921::firmware_transport::boot_p2p::Request::Cancel(cookie),
        )
        .await
    }
    async fn scan(&self, _: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
struct Observed;
impl narf_capabilities::CapOp<narf_net::NetIface, Write> for Observed {
    type Output = ();
    fn execute(
        self,
        _: &Cap<narf_net::NetIface, Write>,
    ) -> Result<(), narf_capabilities::CapError> {
        Ok(())
    }
}
fn map_error(error: crate::mt7921::firmware_transport::Error) -> WirelessError {
    use crate::mt7921::firmware_transport::Error;
    match error {
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Authority | Error::DeviceGone => WirelessError::Denied,
        Error::Bounds | Error::InvalidIdentity => WirelessError::InvalidArgs,
        _ => WirelessError::HardwareError,
    }
}
