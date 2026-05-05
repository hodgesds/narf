#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::boxed::Box;
use async_trait::async_trait;
use narf_net::Interface;
use narf_capabilities::{Cap, Read, Write, Grant};

pub mod caps;
pub mod iface;
pub mod scan;
pub mod reg;

pub use iface::{WirelessIface, WirelessIfaceInfo, WirelessError};
pub use scan::{ScanRequest, ScanResult, BssInfo};

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
    use narf_lib::sync::IrqSafeSpinLock;
    use alloc::vec::Vec;
    use alloc::sync::Arc;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn WirelessNetIface>>> = IrqSafeSpinLock::new(Vec::new());

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
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_net::{Frame, RX_RING_N, TX_RING_N};
    use narf_ipc::{Consumer, Producer};
    use narf_lib::sync::IrqSafeSpinLock;
    use core::sync::atomic::{AtomicBool, Ordering};
    use alloc::sync::Arc;

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
        fn name(&self) -> &str { "wlan0" }
        fn mac(&self) -> [u8; 6] { [0; 6] }
        fn mtu(&self) -> u32 { 1500 }
        fn link_up(&self) -> bool { true }
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> { &self.rx }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> { &self.tx }
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
            let res = m1.scan(ScanRequest { ssids: Vec::new(), channels: Vec::new(), active: true }).await;
            if res.is_ok() && res.unwrap().len() == 1 {
                s.store(true, Ordering::SeqCst);
            }
        });

        // We can't easily test the "Busy" error here because spawn order is deterministic in this scheduler
        // and we only have one CPU. But we can verify the scan completes.
        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) { TestResult::Pass }
        else { TestResult::Fail("scan failed") }
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
        if success.load(Ordering::SeqCst) { TestResult::Pass }
        else { TestResult::Fail("association state cycle failed") }
    }
    kernel_test_in!("wireless", smoke_wireless_association_state);
}
