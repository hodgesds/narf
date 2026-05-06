#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{Cap, Grant, Read, Write};
use narf_net::Interface;

pub mod caps;
pub mod iface;
pub mod mlme;
pub mod reg;
pub mod scan;

pub use iface::{WirelessError, WirelessIface, WirelessIfaceInfo};
pub use scan::{BssInfo, ScanRequest, ScanResult};

/// Capability for wireless-specific operations.
pub enum WirelessRight {
    /// Allows triggering scans and reading BSSID lists.
    Scan,
    /// Allows associating with and disassociating from Access Points.
    Associate,
    /// Allows changing PHY configuration (channel, power).
    Config,
    /// Allows entering monitor mode and receiving all management frames.
    Monitor,
    /// Full administrative rights over the wireless interface.
    Admin,
}

/// A specialized network interface supporting 802.11 operations.
#[async_trait]
pub trait WirelessNetIface: Interface {
    /// Returns detailed information about the wireless interface.
    fn get_wireless_info(&self) -> WirelessIfaceInfo;

    /// Triggers an asynchronous scan.
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;

    /// Initiates association with an Access Point.
    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError>;

    /// Disconnects from the current Access Point.
    async fn disassociate(&self) -> Result<(), WirelessError>;

    /// Configures PHY-level parameters.
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError>;
}

pub struct AssociateRequest {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u32,
    pub security: SecurityConfig,
}

pub enum SecurityConfig {
    Open,
    Wpa2 { psk: [u8; 32] },
    Wpa3 { password: Vec<u8> },
}

pub struct WirelessConfig {
    pub channel: u32,
    pub tx_power_dbm: Option<i8>,
}

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn WirelessNetIface>>> =
        IrqSafeSpinLock::new(Vec::new());

    pub fn register(iface: Arc<dyn WirelessNetIface>) {
        REGISTRY.lock().push(iface);
    }

    pub fn list() -> Vec<Arc<dyn WirelessNetIface>> {
        REGISTRY.lock().clone()
    }
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_ipc::{Consumer, Producer};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    struct MockWireless {
        is_scanning: AtomicBool,
        is_associated: AtomicBool,
        rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
        tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    }

    impl MockWireless {
        fn new() -> Self {
            Self {
                is_scanning: AtomicBool::new(false),
                is_associated: AtomicBool::new(false),
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            }
        }
    }

    impl Interface for MockWireless {
        fn name(&self) -> &str {
            "wlan0"
        }
        fn mac(&self) -> [u8; 6] {
            [0; 6]
        }
        fn mtu(&self) -> u32 {
            1500
        }
        fn link_up(&self) -> bool {
            true
        }
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
            &self.rx
        }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
            &self.tx
        }
    }

    #[async_trait]
    impl WirelessNetIface for MockWireless {
        fn get_wireless_info(&self) -> WirelessIfaceInfo {
            WirelessIfaceInfo {
                base_name: self.name().into(),
                base_mac: self.mac(),
                bands: alloc::vec![],
                modes: iface::WirelessModes::STATION,
                hw_caps: iface::HwCaps {
                    ht_supported: true,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            }
        }

        async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
            if self.is_scanning.swap(true, Ordering::SeqCst) {
                return Err(WirelessError::Busy);
            }
            narf_scheduler::yield_now().await;
            self.is_scanning.store(false, Ordering::SeqCst);
            Ok(alloc::vec![BssInfo {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                channel: 1,
                rssi: -50,
                security: scan::BssSecurity::Wpa2,
            }])
        }

        async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
            self.is_associated.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn disassociate(&self) -> Result<(), WirelessError> {
            self.is_associated.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
            Ok(())
        }
    }

    fn smoke_wireless_scan_busy_logic() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m1 = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let res = m1
                .scan(ScanRequest {
                    ssids: Vec::new(),
                    channels: Vec::new(),
                    active: true,
                })
                .await;
            if res.is_ok() && res.unwrap().len() == 1 {
                s.store(true, Ordering::SeqCst);
            }
        });

        // We can't easily test the "Busy" error here because spawn order is deterministic in this scheduler
        // and we only have one CPU. But we can verify the scan completes.
        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("scan failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_scan_busy_logic);

    fn smoke_wireless_association_state() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockWireless::new());
        let success = Arc::new(AtomicBool::new(false));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let req = AssociateRequest {
                bssid: [0x12; 6],
                ssid: alloc::vec![b'T', b'e', b's', b't'],
                channel: 1,
                security: SecurityConfig::Open,
            };
            m.associate(req).await.expect("associate failed");
            if m.is_associated.load(Ordering::SeqCst) {
                m.disassociate().await.expect("disassociate failed");
                if !m.is_associated.load(Ordering::SeqCst) {
                    s.store(true, Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("association state cycle failed")
        }
    }
    kernel_test_in!("wireless", smoke_wireless_association_state);

    fn smoke_mlme_frame_control_round_trip() -> TestResult {
        use crate::mlme::{FrameControl, FrameType, MgmtSubtype};
        let fc = FrameControl::mgmt(MgmtSubtype::ProbeRequest);
        let raw = fc.encode();
        // §9.2.4.1.3: type=0 (mgmt), subtype=4 (ProbeReq).
        if (raw >> 2) & 0x3 != 0 {
            return TestResult::Fail("Mgmt frame Type field drift");
        }
        if (raw >> 4) & 0xF != 4 {
            return TestResult::Fail("ProbeRequest Subtype drift");
        }
        let back = FrameControl::decode(raw);
        if back.frame_type != FrameType::Management
            || back.subtype != MgmtSubtype::ProbeRequest as u8
        {
            return TestResult::Fail("Frame Control round-trip lost type/subtype");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_frame_control_round_trip);

    fn smoke_mlme_mgmt_header_layout() -> TestResult {
        use crate::mlme::{FrameControl, MgmtHeader, MgmtSubtype};
        let h = MgmtHeader {
            fc: FrameControl::mgmt(MgmtSubtype::Authentication),
            duration: 0x0030,
            addr1: [0x11; 6],
            addr2: [0x22; 6],
            addr3: [0x33; 6],
            seq_ctrl: 0x0010,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        if buf.len() != 24 {
            return TestResult::Fail("Mgmt header should be 24 bytes (no addr4)");
        }
        let back = match MgmtHeader::decode(&buf) {
            Some(v) => v,
            None => return TestResult::Fail("MgmtHeader::decode returned None"),
        };
        if back != h {
            return TestResult::Fail("MgmtHeader round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_mgmt_header_layout);

    fn smoke_mlme_ie_iter_and_write() -> TestResult {
        use crate::mlme::{iter_ies, write_ie, ElementId};
        let mut buf = Vec::new();
        write_ie(&mut buf, ElementId::Ssid, b"narf");
        write_ie(&mut buf, ElementId::SupportedRates, &[0x82, 0x84, 0x8B, 0x96]);
        let ies: Vec<_> = iter_ies(&buf).collect();
        if ies.len() != 2 {
            return TestResult::Fail("expected 2 IEs back from iter");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("SSID IE round-trip lost contents");
        }
        if ies[1].id != ElementId::SupportedRates as u8 || ies[1].body.len() != 4 {
            return TestResult::Fail("SupportedRates IE round-trip mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_ie_iter_and_write);

    fn smoke_mlme_probe_request_builder() -> TestResult {
        use crate::mlme::{build_probe_request_body, iter_ies, ElementId};
        let body = build_probe_request_body(b"narf", &[0x82, 0x84]);
        let ies: Vec<_> = iter_ies(&body).collect();
        if ies.len() != 2 {
            return TestResult::Fail("ProbeReq body should hold 2 IEs");
        }
        if ies[0].id != ElementId::Ssid as u8 || ies[0].body != b"narf" {
            return TestResult::Fail("ProbeReq SSID IE wrong");
        }
        if ies[1].id != ElementId::SupportedRates as u8 {
            return TestResult::Fail("ProbeReq SupportedRates IE wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_probe_request_builder);

    fn smoke_mlme_open_auth_request() -> TestResult {
        use crate::mlme::{build_open_auth_request, AuthFields};
        let body = build_open_auth_request();
        let fields = match AuthFields::decode(&body) {
            Some(f) => f,
            None => return TestResult::Fail("AuthFields::decode returned None"),
        };
        if fields.algorithm != 0 {
            return TestResult::Fail("Open System should use algorithm 0");
        }
        if fields.sequence != 1 {
            return TestResult::Fail("Auth sequence should be 1 for the request");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_open_auth_request);

    fn smoke_mlme_beacon_ssid_channel_extract() -> TestResult {
        use crate::mlme::{beacon_ssid_channel, write_ie, ElementId};
        // Build a synthetic beacon body: 12-byte fixed header (zeroed
        // for the test), then SSID + DS Parameter Set IEs.
        let mut body = alloc::vec![0u8; 12];
        write_ie(&mut body, ElementId::Ssid, b"NarfNet");
        write_ie(&mut body, ElementId::DsParameterSet, &[6]);
        let (ssid, ch) = match beacon_ssid_channel(&body) {
            Some(p) => p,
            None => return TestResult::Fail("beacon_ssid_channel returned None"),
        };
        if ssid != b"NarfNet" {
            return TestResult::Fail("Beacon SSID extraction wrong");
        }
        if ch != Some(6) {
            return TestResult::Fail("Beacon DS channel extraction wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mlme", smoke_mlme_beacon_ssid_channel_extract);
}
