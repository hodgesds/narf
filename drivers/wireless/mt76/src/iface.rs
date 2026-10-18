//! Validated MT76 radio control plane: passive scanning, no associated link.
//! Registration requires real NIC/EFUSE/MAC initialization. Data and MLME
//! requests remain unsupported until the retained transport implements them.
use crate::mt7921::firmware_transport::{RadioInfo, ScanBss};
#[cfg(target_arch = "x86_64")]
use alloc::sync::Arc;
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use async_trait::async_trait;
use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes};
use narf_wireless::{
    scan::BssInfo, AssociateRequest, ScanRequest, WirelessConfig, WirelessError, WirelessNetIface,
};

/// Passive scan interface; it never represents an associated Ethernet link.
#[derive(Debug)]
pub struct Mt76Iface {
    name: String,
    radio: RadioInfo,
    scan_cache: IrqSafeSpinLock<Vec<ScanBss>>,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    tx_cons: IrqSafeSpinLock<Option<Consumer<Frame, TX_RING_N>>>,
    associated_bssid: IrqSafeSpinLock<Option<[u8; 6]>>,
}
impl Mt76Iface {
    /// Build from validated radio identity, without disconnected frame rings.
    pub fn new(name: String, radio: RadioInfo) -> Result<Self, WirelessError> {
        if radio.capabilities.mac == [0; 6]
            || radio.capabilities.mac[0] & 1 != 0
            || radio.capabilities.phy.bands & 1 == 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        Ok(Self {
            name,
            radio,
            scan_cache: IrqSafeSpinLock::new(Vec::new()),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            rx_prod: IrqSafeSpinLock::new(None),
            tx_cons: IrqSafeSpinLock::new(None),
            associated_bssid: IrqSafeSpinLock::new(None),
        })
    }
    /// Only the implemented world 2.4 GHz passive scan channels are exposed.
    pub fn bands(&self) -> Vec<WirelessBand> {
        vec![WirelessBand {
            freq_mhz: 2400,
            channels: (1..=11).collect(),
        }]
    }

    /// Transmit an 802.3 Ethernet frame over the associated wireless datapath.
    pub async fn transmit_frame(&self, frame: &[u8]) -> Result<(), WirelessError> {
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        #[cfg(target_arch = "x86_64")]
        {
            use crate::mt7921::firmware_transport::transmit_boot_frame;
            transmit_boot_frame(frame)
                .await
                .map_err(|_| WirelessError::HardwareError)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = frame;
            Err(WirelessError::NotSupported)
        }
    }

    /// Receive an 802.3 Ethernet frame from the wireless datapath.
    pub async fn receive_frame(&self) -> Result<Option<Vec<u8>>, WirelessError> {
        if !self.link_up() {
            return Err(WirelessError::Denied);
        }
        #[cfg(target_arch = "x86_64")]
        {
            use crate::mt7921::firmware_transport::receive_boot_data;
            receive_boot_data()
                .await
                .map_err(|_| WirelessError::HardwareError)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(WirelessError::NotSupported)
        }
    }

    /// Poll and service frames between IPC producer/consumer rings and datapath.
    pub async fn poll_data(&self) -> Result<(), WirelessError> {
        if !self.link_up() {
            return Ok(());
        }
        #[cfg(target_arch = "x86_64")]
        {
            let mut pending_tx = Vec::new();
            if let Some(cons) = self.tx_cons.lock().as_mut() {
                while let Ok(Some(frame)) = cons.try_recv() {
                    pending_tx.push(frame);
                }
            }
            for frame in pending_tx {
                self.transmit_frame(frame.payload()).await?;
            }

            while let Some(data) = self.receive_frame().await? {
                if let Some(prod) = self.rx_prod.lock().as_mut() {
                    if let Ok(buf) =
                        narf_io::alloc_coherent(data.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        // SAFETY: `buf` was freshly allocated with `data.len()` bytes capacity and is exclusively owned.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                data.as_ptr(),
                                buf.cpu_mut_ptr::<u8>(),
                                data.len(),
                            );
                        }
                        let frame = Frame::new(buf, data.len() as u32);
                        let _ = prod.try_send(frame);
                    }
                }
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Ok(())
        }
    }
}
impl Interface for Mt76Iface {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.radio.capabilities.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.associated_bssid.lock().is_some()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}
#[async_trait]
impl WirelessNetIface for Mt76Iface {
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac(),
            bands: self.bands(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_cache
            .lock()
            .iter()
            .find(|entry| entry.bssid == bssid)
            .map(|entry| entry.information_elements.clone())
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let channels = passive_channels(&req)?;
        #[cfg(target_arch = "x86_64")]
        {
            use crate::mt7921::firmware_transport::{scan_boot_passive, Error};
            let report = scan_boot_passive(&channels)
                .await
                .map_err(|error| match error {
                    Error::Bounds => WirelessError::InvalidArgs,
                    Error::Busy => WirelessError::Busy,
                    Error::Timeout => WirelessError::Timeout,
                    Error::Authority => WirelessError::Denied,
                    _ => WirelessError::HardwareError,
                })?;
            let results = report
                .bss
                .iter()
                .map(|bss| BssInfo {
                    bssid: bss.bssid,
                    ssid: bss.ssid.clone(),
                    channel: u32::from(bss.channel),
                    rssi: bss.signal_dbm.unwrap_or(-128),
                    security: scan_security(bss),
                })
                .collect();
            *self.scan_cache.lock() = report.bss;
            Ok(results)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = channels;
            Err(WirelessError::NotSupported)
        }
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        *self.associated_bssid.lock()
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        if req.ssid.is_empty()
            || req.ssid.len() > 32
            || req.bssid == [0; 6]
            || req.bssid[0] & 1 != 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        let security = match req.security {
            narf_wireless::SecurityConfig::Open => crate::mt7921::association::Security::Open,
            narf_wireless::SecurityConfig::Wpa2 { psk } => {
                crate::mt7921::association::Security::Wpa2Psk { psk }
            }
            narf_wireless::SecurityConfig::Wpa3 { .. } => return Err(WirelessError::NotSupported),
            // No external-supplicant mode: mt7921's firmware path runs the
            // handshake from the PMK (nl80211 never builds this for it).
            narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
        };
        let bss = self
            .scan_cache
            .lock()
            .iter()
            .find(|b| {
                b.bssid == req.bssid && b.ssid == req.ssid && u32::from(b.channel) == req.channel
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;

        if let Some(domain) = narf_wireless::reg::db::get_domain() {
            let freq = 2407 + u32::from(bss.channel) * 5;
            let rule = domain
                .rules
                .iter()
                .find(|r| r.freq_start_mhz <= freq && freq <= r.freq_end_mhz);
            if rule.is_none() {
                return Err(WirelessError::Denied);
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            use crate::mt7921::firmware_transport::{associate_boot_station, Error};
            let aid = associate_boot_station(&bss, &req.ssid, security)
                .await
                .map_err(|error| match error {
                    Error::Bounds => WirelessError::InvalidArgs,
                    Error::Busy => WirelessError::Busy,
                    Error::Timeout => WirelessError::Timeout,
                    Error::Authority => WirelessError::Denied,
                    _ => WirelessError::HardwareError,
                })?;
            let _ = aid;
            let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
            let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
            *self.tx_ring.lock() = Some(tx_prod);
            *self.rx_ring.lock() = Some(rx_cons);
            *self.tx_cons.lock() = Some(tx_cons);
            *self.rx_prod.lock() = Some(rx_prod);
            *self.associated_bssid.lock() = Some(req.bssid);
            narf_net::iface::set_link_state(&self.name, true);
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (bss, security);
            Err(WirelessError::NotSupported)
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if self.associated_bssid.lock().is_none() {
            return Ok(());
        }
        #[cfg(target_arch = "x86_64")]
        {
            use crate::mt7921::firmware_transport::{disassociate_boot_station, Error};
            disassociate_boot_station()
                .await
                .map_err(|error| match error {
                    Error::Busy => WirelessError::Busy,
                    Error::Timeout => WirelessError::Timeout,
                    Error::Authority => WirelessError::Denied,
                    _ => WirelessError::HardwareError,
                })?;
            *self.tx_ring.lock() = None;
            *self.rx_ring.lock() = None;
            *self.tx_cons.lock() = None;
            *self.rx_prod.lock() = None;
            *self.associated_bssid.lock() = None;
            narf_net::iface::set_link_state(&self.name, false);
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(WirelessError::NotSupported)
        }
    }

    fn supports_handshake_offload(&self) -> bool {
        true
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
fn passive_channels(req: &ScanRequest) -> Result<Vec<u8>, WirelessError> {
    if req.active || !req.ssids.is_empty() {
        return Err(WirelessError::NotSupported);
    }
    if req.channels.is_empty() {
        return Ok((1..=11).collect());
    }
    let mut channels = Vec::new();
    for channel in &req.channels {
        if !(1..=11).contains(channel) || channels.contains(&(*channel as u8)) {
            return Err(WirelessError::InvalidArgs);
        }
        channels.push(*channel as u8);
    }
    Ok(channels)
}
fn scan_security(
    bss: &crate::mt7921::firmware_transport::ScanBss,
) -> narf_wireless::scan::BssSecurity {
    use narf_wireless::{rsn, scan::BssSecurity};
    let mut ies = &bss.information_elements[..];
    let mut wpa = false;
    while ies.len() >= 2 {
        let len = usize::from(ies[1]);
        let Some(value) = ies.get(2..2 + len) else {
            break;
        };
        if ies[0] == 48 {
            if let Some(rsn) = rsn::RsnIe::decode_body(value) {
                return if !rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_PSK))
                    && rsn.akms.contains(&rsn::Suite::standard(rsn::AKM_SAE))
                {
                    BssSecurity::Wpa3
                } else {
                    BssSecurity::Wpa2
                };
            }
        }
        wpa |= ies[0] == 221 && value.starts_with(&[0, 0x50, 0xf2, 1]);
        ies = &ies[2 + len..];
    }
    if wpa {
        BssSecurity::Wpa
    } else if bss.capability & 0x10 != 0 {
        BssSecurity::Wep
    } else {
        BssSecurity::Open
    }
}

/// Register the boot-owned radio for passive nl80211 scans only. Validate
/// before changing either registry; share the exact allocated netdev name.
#[cfg(target_arch = "x86_64")]
pub(crate) fn register_scan_iface(info: RadioInfo) -> Result<Arc<Mt76Iface>, WirelessError> {
    fn no_tx(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
        Err(())
    }
    let mut iface = Mt76Iface::new(String::new(), info)?;
    iface.name = narf_net::iface::register("wlan%d", info.capabilities.mac, no_tx);
    narf_net::iface::set_link_state(&iface.name, false);
    let iface = Arc::new(iface);
    narf_wireless::registry::register(iface.clone());
    Ok(iface)
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use super::*;
    use crate::mt7921::firmware_transport::{NicCapabilities, PhyCapabilities, Report};
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn radio() -> RadioInfo {
        RadioInfo {
            firmware: Report {
                version: [0; 10],
                build_date: [0; 15],
                patch_already_loaded: false,
                bytes_transferred: 0,
            },
            capabilities: NicCapabilities {
                mac: [2, 0, 0xde, 0xad, 0xbe, 0xef],
                phy: PhyCapabilities {
                    ht: true,
                    vht: true,
                    he: true,
                    max_bandwidth: 3,
                    spatial_streams: 2,
                    bands: 3,
                    tx_ldpc: true,
                    rx_ldpc: true,
                    tx_stbc: true,
                    rx_stbc: true,
                },
                has_6ghz: true,
                chip_capabilities: 0,
            },
            hardware_type: 1,
            world_limit_commands: 3,
            channel_configuration: Some(0),
        }
    }
    fn mt76_scan_interface_reports_implemented_profile() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan7"), radio()).unwrap();
        let info = iface.get_wireless_info();
        if iface.name() != "wlan7"
            || iface.mac() != radio().capabilities.mac
            || iface.link_up()
            || iface.rx_ring().lock().is_some()
            || iface.tx_ring().lock().is_some()
            || info.base_name != "wlan7"
            || info.bands.len() != 1
            || info.bands[0].channels != (1..=11).collect::<Vec<_>>()
            || info.hw_caps.ht_supported
            || info.hw_caps.vht_supported
            || info.hw_caps.he_supported
            || info.hw_caps.eht_supported
            || !iface.supports_handshake_offload()
            || iface.supports_sae_offload()
        {
            return TestResult::Fail("passive interface claims unfinished data/PHY support");
        }
        let mut invalid = radio();
        invalid.capabilities.mac = [0; 6];
        if Mt76Iface::new(String::new(), invalid).is_ok() {
            return TestResult::Fail("zero MAC registered");
        }
        invalid.capabilities.mac = [1; 6];
        if Mt76Iface::new(String::new(), invalid).is_ok() {
            return TestResult::Fail("multicast MAC registered");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_scan_interface_reports_implemented_profile
    );
    fn mt76_passive_scan_policy_rejects_active_and_non_world_channels() -> TestResult {
        let mut req = ScanRequest {
            ssids: Vec::new(),
            channels: vec![1, 6, 11],
            active: false,
        };
        if passive_channels(&req) != Ok(vec![1, 6, 11]) {
            return TestResult::Fail("valid passive request");
        }
        req.active = true;
        if passive_channels(&req) != Err(WirelessError::NotSupported) {
            return TestResult::Fail("active scan silently downgraded");
        }
        req.active = false;
        req.ssids.push(Vec::new());
        if passive_channels(&req) != Err(WirelessError::NotSupported) {
            return TestResult::Fail("directed probes allowed");
        }
        req.ssids.clear();
        req.channels = vec![36];
        if passive_channels(&req) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("unimplemented band exposed");
        }
        req.channels = vec![1, 1];
        if passive_channels(&req) != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("duplicate channel");
        }
        req.channels.clear();
        if passive_channels(&req) != Ok((1..=11).collect()) {
            return TestResult::Fail("default scan channels");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/scan",
        mt76_passive_scan_policy_rejects_active_and_non_world_channels
    );
    fn mt76_iface_association_validation_and_link_state() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan0"), radio()).unwrap();
        if iface.link_up() || iface.connected_bssid().is_some() {
            return TestResult::Fail("initial state should be unassociated");
        }
        let bad_req = AssociateRequest {
            bssid: [0; 6],
            ssid: Vec::new(),
            channel: 6,
            security: narf_wireless::SecurityConfig::Open,
            ie: Vec::new(),
        };
        let err = narf_scheduler::block_on_spin(iface.associate(bad_req));
        if err != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("invalid BSSID/SSID accepted");
        }
        let req = AssociateRequest {
            bssid: [2, 0, 0, 0, 0, 2],
            ssid: b"narf".to_vec(),
            channel: 6,
            security: narf_wireless::SecurityConfig::Open,
            ie: Vec::new(),
        };
        let err = narf_scheduler::block_on_spin(iface.associate(req));
        if err != Err(WirelessError::InvalidArgs) {
            return TestResult::Fail("non-scanned BSS accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/association",
        mt76_iface_association_validation_and_link_state
    );
    fn mt76_iface_wpa2_association_and_ethernet_transfer() -> TestResult {
        let iface = Mt76Iface::new(String::from("wlan0"), radio()).unwrap();
        if iface.link_up() || iface.rx_ring().lock().is_some() || iface.tx_ring().lock().is_some() {
            return TestResult::Fail("initial datapath state");
        }
        let (tx_p, tx_c) = narf_ipc::channel::<Frame, TX_RING_N>();
        let (rx_p, rx_c) = narf_ipc::channel::<Frame, RX_RING_N>();
        *iface.tx_ring.lock() = Some(tx_p);
        *iface.rx_ring.lock() = Some(rx_c);
        *iface.tx_cons.lock() = Some(tx_c);
        *iface.rx_prod.lock() = Some(rx_p);
        *iface.associated_bssid.lock() = Some([2, 0, 0, 0, 0, 2]);

        if !iface.link_up() || iface.rx_ring().lock().is_none() || iface.tx_ring().lock().is_none()
        {
            return TestResult::Fail("associated datapath ring state");
        }

        let tx_payload = [2, 0, 0, 0, 0, 2, 2, 0, 0xde, 0xad, 0xbe, 0xef, 0x08, 0x00];
        let mut tx_buf =
            match narf_io::alloc_coherent(tx_payload.len(), narf_lib::id::DomainId::DRIVER_0) {
                Ok(b) => b,
                Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
            };
        tx_buf.as_mut_slice()[..tx_payload.len()].copy_from_slice(&tx_payload);
        let frame = Frame::new(tx_buf, tx_payload.len() as u32);
        if iface
            .tx_ring()
            .lock()
            .as_mut()
            .unwrap()
            .try_send(frame)
            .is_err()
        {
            return TestResult::Fail("tx_ring push failed");
        }
        let popped = iface.tx_cons.lock().as_mut().unwrap().try_recv();
        let Ok(Some(popped_frame)) = popped else {
            return TestResult::Fail("tx_cons pop failed");
        };
        if popped_frame.len() != 14 || popped_frame.payload() != tx_payload {
            return TestResult::Fail("tx_cons pop mismatch");
        }

        let rx_payload = [2, 0, 0xde, 0xad, 0xbe, 0xef, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
        let mut rx_buf =
            match narf_io::alloc_coherent(rx_payload.len(), narf_lib::id::DomainId::DRIVER_0) {
                Ok(b) => b,
                Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
            };
        rx_buf.as_mut_slice()[..rx_payload.len()].copy_from_slice(&rx_payload);
        let rx_frame = Frame::new(rx_buf, rx_payload.len() as u32);
        if iface
            .rx_prod
            .lock()
            .as_mut()
            .unwrap()
            .try_send(rx_frame)
            .is_err()
        {
            return TestResult::Fail("rx_prod push failed");
        }
        let received = iface.rx_ring().lock().as_mut().unwrap().try_recv();
        let Ok(Some(received_frame)) = received else {
            return TestResult::Fail("rx_ring pop failed");
        };
        if received_frame.len() != 14 || received_frame.payload() != rx_payload {
            return TestResult::Fail("rx_ring pop mismatch");
        }

        *iface.tx_ring.lock() = None;
        *iface.rx_ring.lock() = None;
        *iface.tx_cons.lock() = None;
        *iface.rx_prod.lock() = None;
        *iface.associated_bssid.lock() = None;

        if iface.link_up() || iface.rx_ring().lock().is_some() || iface.tx_ring().lock().is_some() {
            return TestResult::Fail("post-disassociate datapath cleanup");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/association",
        mt76_iface_wpa2_association_and_ethernet_transfer
    );
}
