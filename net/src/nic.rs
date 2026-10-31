//! Device control shared by native drivers and the Linux ethtool bridge.
//! Mutation authority is checked by the caller (AdminHandle/CAP_NET_ADMIN).
//! Drivers serialize hardware changes and keep DMA alive until quiescence.

use alloc::{string::String, vec::Vec};

pub type Result<T> = core::result::Result<T, i32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSettings {
    /// Bits: 10 half/full, 100 half/full, 1000 full, 2500 full.
    pub advertised: u32,
    pub autoneg: bool,
    pub speed_mbps: u32,
    pub full_duplex: bool,
}
impl Default for LinkSettings {
    fn default() -> Self {
        Self {
            advertised: 0x3f,
            autoneg: true,
            speed_mbps: 0,
            full_duplex: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pause {
    pub autoneg: bool,
    pub rx: bool,
    pub tx: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub rx_entries: u32,
    pub tx_entries: u32,
    pub channels: u16,
    pub coalesce_us: u32,
    pub rss: crate::rss::RssConfig,
    pub link: LinkSettings,
    pub pause: Pause,
    pub eee: bool,
    /// Linux WAKE_PHY/UCAST/MCAST/BCAST/MAGIC bits; zero disables wake.
    pub wake: u32,
}
impl Settings {
    pub fn validate(&self, maximum_queues: u16, gigabit_only: bool) -> Result<()> {
        if self.channels == 0
            || self.channels > maximum_queues
            || [self.rx_entries, self.tx_entries]
                .iter()
                .any(|n| !(64..=4096).contains(n) || n % 8 != 0)
            || self.coalesce_us > 8388
            || self.rss.key.len() != 40
            || self.rss.indirection.len() != 128
            || self
                .rss
                .indirection
                .iter()
                .any(|q| u16::from(*q) >= self.channels)
            || self.link.advertised & !0x3f != 0
            || (gigabit_only && self.link.advertised & 0x20 != 0)
            || (self.link.autoneg && self.link.advertised == 0)
            || (!self.link.autoneg && (!matches!(self.link.speed_mbps, 10 | 100) || self.eee))
            || self.wake & !0x2f != 0
        {
            return Err(22);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EeeStatus {
    pub advertised: u32,
    pub partner: u32,
    pub active: bool,
    pub tx_lpi: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statistic {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub name: &'static str,
    pub passed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimestampConfig {
    pub tx: bool,
    pub rx: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub cookie: u64,
    pub nanoseconds: u64,
    pub transmit: bool,
    /// Positive errno on cancellation or timestamp timeout.
    pub error: Option<i32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Shaper {
    pub queue: u8,
    pub idle_slope_kbps: u32,
    pub send_slope_kbps: i32,
    pub high_credit: i32,
    pub low_credit: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    pub mask: u8,
    pub interval_ns: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficSchedule {
    pub base_time_ns: u64,
    pub cycle_ns: u32,
    pub gates: Vec<Gate>,
    pub shapers: Vec<Shaper>,
    pub launch_time_queues: u8,
    pub preemptible_queues: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRule {
    pub location: u16,
    pub queue: u16,
    pub ethertype: Option<u16>,
    pub destination_mac: Option<[u8; 6]>,
    pub vlan_priority: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preemption {
    pub enabled: bool,
    pub tx_enabled: bool,
    pub verify: bool,
    pub verify_ms: u8,
    pub minimum_fragment: u16,
}
impl Default for Preemption {
    fn default() -> Self {
        Self {
            enabled: false,
            tx_enabled: false,
            verify: true,
            verify_ms: 10,
            minimum_fragment: 64,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreemptionStatus {
    pub active: bool,
    pub verified: bool,
    pub failed: bool,
    pub attempts: u8,
}
/// Hardware features. Defaults explicitly reject operations absent on a NIC.
pub trait NicControl: core::fmt::Debug + Send + Sync {
    fn settings(&self) -> Result<Settings> {
        Err(95)
    }
    fn set_settings(&self, _: Settings) -> Result<()> {
        Err(95)
    }
    fn eee_status(&self) -> Result<EeeStatus> {
        Err(95)
    }
    fn statistics(&self) -> Result<Vec<Statistic>> {
        Err(95)
    }
    fn registers(&self) -> Result<Vec<u32>> {
        Err(95)
    }
    fn nvm_info(&self) -> Result<(u32, u32)> {
        Err(95)
    }
    fn supported_link_modes(&self) -> u32 {
        0x3f
    }
    fn nvm(&self, _: u32, _: u32) -> Result<Vec<u8>> {
        Err(95)
    }
    fn diagnostics(&self, _: bool) -> Result<Vec<Diagnostic>> {
        Err(95)
    }
    fn restart_link(&self) -> Result<()> {
        Err(95)
    }
    fn clock_index(&self) -> i32 {
        -1
    }
    fn timestamp_config(&self) -> Result<TimestampConfig> {
        Err(95)
    }
    fn clock_get(&self) -> Result<u64> {
        Err(95)
    }
    fn clock_set(&self, _: u64) -> Result<()> {
        Err(95)
    }
    fn clock_adjust(&self, _: i64, _: i32) -> Result<()> {
        Err(95)
    }
    fn timestamps(&self, _: TimestampConfig) -> Result<()> {
        Err(95)
    }
    fn take_timestamp(&self) -> Result<Option<Timestamp>> {
        Err(95)
    }
    fn schedule(&self, _: TrafficSchedule) -> Result<()> {
        Err(95)
    }
    fn preemption(&self) -> Result<(Preemption, PreemptionStatus)> {
        Err(95)
    }
    fn set_preemption(&self, _: Preemption) -> Result<()> {
        Err(95)
    }
    fn traffic_schedule(&self) -> Result<TrafficSchedule> {
        Err(95)
    }
    fn flow_rules(&self) -> Result<Vec<FlowRule>> {
        Err(95)
    }
    fn set_flow_rules(&self, _: Vec<FlowRule>) -> Result<()> {
        Err(95)
    }
    /// Attach a queue to registered UMEM. Caller holds network administration
    /// authority; driver holds each lease through DMA completion or quiescence.
    /// Bind a native queue while preserving DMA ownership on failure. If a
    /// restart fails after attachment, close the socket and retain its queue
    /// claim until a successful drain/reset detaches it.
    fn bind_xsk(
        &self,
        _: u16,
        _: Option<alloc::sync::Arc<crate::bypass::xdp::XdpSocket>>,
    ) -> Result<()> {
        Err(95)
    }
    fn kick_xsk(&self, _: u16) -> Result<()> {
        Ok(())
    }
    fn runtime_suspend(&self) -> Result<()> {
        Err(95)
    }
    fn runtime_resume(&self) -> Result<()> {
        Err(95)
    }
}

pub fn with_control<T>(name: &str, f: impl FnOnce(&dyn NicControl) -> Result<T>) -> Result<T> {
    let control = crate::iface::device_control(name).ok_or(19)?;
    f(control.nic().ok_or(95)?)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    #[derive(Debug)]
    struct Model(IrqSafeSpinLock<Settings>);
    impl crate::iface::DeviceControl for Model {
        fn configure(&self, _: &crate::iface::DeviceConfig) -> Result<()> {
            Ok(())
        }
        fn nic(&self) -> Option<&dyn NicControl> {
            Some(self)
        }
    }
    impl NicControl for Model {
        fn settings(&self) -> Result<Settings> {
            Ok(self.0.lock().clone())
        }
        fn set_settings(&self, s: Settings) -> Result<()> {
            s.validate(4, false)?;
            *self.0.lock() = s;
            Ok(())
        }
        fn statistics(&self) -> Result<Vec<Statistic>> {
            Ok(alloc::vec![Statistic {
                name: String::from("rx_packets"),
                value: 123
            }])
        }
    }
    fn defaults() -> Settings {
        Settings {
            rx_entries: 256,
            tx_entries: 256,
            channels: 2,
            coalesce_us: 166,
            rss: crate::rss::RssConfig::standard(2, 128),
            link: LinkSettings::default(),
            pause: Pause::default(),
            eee: false,
            wake: 0,
        }
    }
    fn send(_: &[u8], _: crate::TxMeta) -> core::result::Result<(), ()> {
        Ok(())
    }
    struct Interface(String);
    impl Drop for Interface {
        fn drop(&mut self) {
            crate::iface::unregister(&self.0);
        }
    }
    fn setup() -> (Interface, Arc<Model>) {
        let name = crate::iface::register("nic-control%d", [2, 1, 2, 3, 4, 5], send);
        let m = Arc::new(Model(IrqSafeSpinLock::new(defaults())));
        crate::iface::set_device_control(&name, m.clone());
        (Interface(name), m)
    }
    fn put(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn get(b: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn smoke_nic_settings_validation() -> TestResult {
        let s = defaults();
        if s.validate(4, false).is_err() {
            return TestResult::Fail("valid settings rejected");
        }
        for n in [0, 63, 65, 4097] {
            let mut bad = s.clone();
            bad.rx_entries = n;
            if bad.validate(4, false).is_ok() {
                return TestResult::Fail("invalid ring accepted");
            }
        }
        let mut bad = s.clone();
        bad.rss.indirection[127] = 2;
        if bad.validate(4, false).is_ok() {
            return TestResult::Fail("RSS targets missing queue");
        }
        if s.validate(4, true).is_ok() {
            return TestResult::Fail("gigabit NIC accepted 2500 advertisement");
        }
        bad = s;
        bad.wake = 0x10;
        if bad.validate(4, false).is_ok() {
            return TestResult::Fail("unsupported ARP wake accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("net", smoke_nic_settings_validation);
    fn smoke_ethtool_control_roundtrip_and_rejection() -> TestResult {
        let (name, m) = setup();
        let mut ring = alloc::vec![0;36];
        put(&mut ring, 0, 0x10);
        if crate::ethtool::execute(&name.0, &mut ring).is_err()
            || get(&ring, 20) != 256
            || get(&ring, 32) != 256
        {
            return TestResult::Fail("GET rings failed");
        }
        put(&mut ring, 0, 0x11);
        put(&mut ring, 20, 128);
        put(&mut ring, 32, 512);
        if crate::ethtool::execute(&name.0, &mut ring).is_err() || m.0.lock().rx_entries != 128 {
            return TestResult::Fail("SET rings failed");
        }
        put(&mut ring, 20, 63);
        if crate::ethtool::execute(&name.0, &mut ring) != Err(22) || m.0.lock().rx_entries != 128 {
            return TestResult::Fail("rejected settings committed");
        }
        let mut rss = alloc::vec![0;24];
        put(&mut rss, 0, 0x46);
        if crate::ethtool::execute(&name.0, &mut rss).is_err()
            || get(&rss, 8) != 128
            || get(&rss, 12) != 40
        {
            return TestResult::Fail("RSS size query failed");
        }
        let mut stats = alloc::vec![0;16];
        put(&mut stats, 0, 0x1d);
        put(&mut stats, 4, 1);
        if crate::ethtool::execute(&name.0, &mut stats).is_err()
            || u64::from_ne_bytes(stats[8..].try_into().unwrap()) != 123
        {
            return TestResult::Fail("stats codec failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("net", smoke_ethtool_control_roundtrip_and_rejection);
    fn smoke_ethtool_variable_requests_are_bounded() -> TestResult {
        for (cmd, size, offset) in [
            (4, 12, 8),
            (11, 16, 12),
            (27, 12, 8),
            (29, 8, 4),
            (26, 16, 12),
            (48, 192, 184),
        ] {
            let mut b = alloc::vec![0;size];
            put(&mut b, 0, cmd);
            put(&mut b, offset, u32::MAX);
            if crate::ethtool::request_size(&b).is_ok() {
                return TestResult::Fail("oversized ethtool request accepted");
            }
            for n in 0..size {
                if crate::ethtool::request_size(&b[..n]).is_ok() {
                    return TestResult::Fail("short ethtool header accepted");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("net", smoke_ethtool_variable_requests_are_bounded);
    fn smoke_umem_dma_lease_revocation_and_duplicates() -> TestResult {
        let umem = crate::bypass::umem::Umem::register(4096, 2048).unwrap();
        let read = umem.frame_bytes(0).unwrap();
        if umem.lease(0).is_ok() {
            return TestResult::Fail("CPU borrow aliased DMA ownership");
        }
        drop(read);
        let lease = umem.lease(0).unwrap();
        if umem.frame_bytes(0).is_some() {
            return TestResult::Fail("DMA ownership allowed CPU borrow");
        }
        if umem.lease(0).is_ok() || umem.lease(2).is_ok() {
            return TestResult::Fail("duplicate or out-of-bounds DMA ownership");
        }
        umem.revoke_soft();
        if umem.lease(1).is_ok() || lease.address() != umem.desc().base_phys {
            return TestResult::Fail("revocation invalidated in-flight DMA or granted new DMA");
        }
        drop(lease);
        TestResult::Pass
    }
    kernel_test_in!("net", smoke_umem_dma_lease_revocation_and_duplicates);
}
