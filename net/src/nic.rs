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

/// MAC Merge statistics (Linux `ethtool_mm_stats`): the five counters
/// `igc_ethtool_get_mm_stats` reports. HOLD_COUNT is not reported by igc.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmStats {
    pub reassembly_errors: u64,
    pub smd_errors: u64,
    pub reassembly_ok: u64,
    pub rx_frag_count: u64,
    pub tx_frag_count: u64,
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

/// Linux `IGC_MAX_RXNFC_RULES` (igc.h): 16 MAC + 8 ethertype + 32 flex
/// + 8 VLAN-priority + 1 default-queue rule. The location space is 65
///   even though each hardware table behind it is smaller.
pub const MAX_RXNFC_RULES: u16 = 65;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRule {
    pub location: u16,
    pub queue: u16,
    pub ethertype: Option<u16>,
    pub destination_mac: Option<[u8; 6]>,
    /// Linux `IGC_FILTER_FLAG_SRC_MAC_ADDR`: full-mask source-MAC match
    /// (`h_u.ether_spec.h_source`, programmed via the RAL ASEL bit).
    pub source_mac: Option<[u8; 6]>,
    pub vlan_priority: Option<u8>,
    /// Linux `IGC_FILTER_FLAG_VLAN_ETYPE`: full-mask VLAN EtherType match
    /// (`h_ext.vlan_etype`, FLOW_EXT). Flex-filter only.
    pub vlan_etype: Option<u16>,
    /// Linux `IGC_FILTER_FLAG_VLAN_TCI` with the full mask: whole-TCI
    /// match (`h_ext.vlan_tci`, FLOW_EXT). Flex-filter only; the
    /// priority-only form stays in `vlan_priority`.
    pub vlan_tci: Option<u16>,
    /// Linux `IGC_FILTER_FLAG_USER_DATA`: user-defined bytes
    /// (`h_ext.data`, FLOW_EXT). Flex-filter only; matched only where
    /// the corresponding `user_mask` byte is nonzero.
    pub user_data: Option<[u8; 8]>,
    /// Mask bytes for `user_data` (`m_ext.data`); `None` matches all
    /// eight bytes.
    pub user_mask: Option<[u8; 8]>,
    /// Linux `IGC_FILTER_FLAG_DEFAULT_QUEUE`: the wildcard rule — no
    /// match field at all, plain `ETHER_FLOW`, zero masks. Everything
    /// unmatched goes to `queue` (MRQC default queue).
    pub default_queue: bool,
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
    /// Linux `ETHTOOL_GMSGLVL`: the driver's `msg_enable` bitmap.
    fn msglevel(&self) -> Result<u32> {
        Err(95)
    }
    /// Linux `ETHTOOL_SMSGLVL`.
    fn set_msglevel(&self, _: u32) -> Result<()> {
        Err(95)
    }
    /// Linux `ETHTOOL_GPFLAGS`: the driver's private-flags bitmap.
    fn priv_flags(&self) -> Result<u32> {
        Err(95)
    }
    /// Linux `ETHTOOL_SPFLAGS`.
    fn set_priv_flags(&self, _: u32) -> Result<()> {
        Err(95)
    }
    /// Private-flag names in `ETHTOOL_GSTRINGS` (sset 2) order; the count is
    /// `ETHTOOL_GDRVINFO`'s `n_priv_flags`. Empty when the driver has none.
    fn priv_flag_names(&self) -> &'static [&'static str] {
        &[]
    }
    /// Linux `ETHTOOL_GRXFH` (`ethtool_rxfh_fields.data`): the RSS hash
    /// fields for `flow_type` (uapi `TCP_V4_FLOW` etc.), as RXH bits.
    fn rxfh_fields(&self, _: u8) -> Result<u32> {
        Err(95)
    }
    /// Linux `ETHTOOL_SRXFH`.
    fn set_rxfh_fields(&self, _: u8, _: u32) -> Result<()> {
        Err(95)
    }
    /// Linux `ETHTOOL_MSG_MM_GET` with `ETHTOOL_FLAG_STATS`: the MAC Merge
    /// statistics. `Err(95)` omits the stats nest from the reply.
    fn mm_stats(&self) -> Result<MmStats> {
        Err(95)
    }
    /// `ETHTOOL_GREGS` version word. Linux igc reports
    /// `(2 << 24) | (revision << 16) | device_id`; the default 1 matches the
    /// previous codec behaviour for drivers that do not override it.
    fn registers_version(&self) -> u32 {
        1
    }
    /// Linux `igc_ethtool_set_coalesce` validation for one rx/tx usecs pair.
    /// The default accepts everything; the shared `Settings` cap still
    /// bounds the committed value.
    fn check_coalesce(&self, _: u32, _: u32) -> Result<()> {
        Ok(())
    }
    /// Linux `ETHTOOL_GPERMADDR`: the permanent hardware address
    /// (`dev->perm_addr`), unaffected by a later `set_mac`. Defaults to
    /// -EOPNOTSUPP; igc returns the probe-time RAL0 address.
    fn permanent_mac(&self) -> Result<[u8; 6]> {
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
    /// Write EEPROM/NVM bytes (ETHTOOL_SETEEPROM, 0x0c). `magic` is the
    /// driver-reported value from `nvm_info`; `offset` is a byte offset.
    /// Defaults to -EOPNOTSUPP; igc implements Linux igc_ethtool_set_eeprom.
    fn set_nvm(&self, _: u32, _: u32, _: &[u8]) -> Result<()> {
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
    /// Timestamp modes actually implemented by this device's frame path.
    fn timestamp_info(&self) -> (u32, u32, u32) {
        ((1 << 1) | (1 << 3) | (1 << 4), 1, 1)
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
    let control = crate::iface::device_control(name).ok_or_else(|| {
        if crate::iface::lookup(name).is_some() {
            95
        } else {
            19
        }
    })?;
    f(control.nic().ok_or(95)?)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    #[derive(Debug)]
    struct Model(
        IrqSafeSpinLock<Settings>,
        IrqSafeSpinLock<alloc::vec::Vec<FlowRule>>,
    );
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
        fn flow_rules(&self) -> Result<Vec<FlowRule>> {
            Ok(self.1.lock().clone())
        }
        fn set_flow_rules(&self, rules: Vec<FlowRule>) -> Result<()> {
            *self.1.lock() = rules;
            Ok(())
        }
        fn permanent_mac(&self) -> Result<[u8; 6]> {
            Ok([2, 1, 2, 3, 4, 5])
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
        let m = Arc::new(Model(
            IrqSafeSpinLock::new(defaults()),
            IrqSafeSpinLock::new(alloc::vec::Vec::new()),
        ));
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
    kernel_test_in!("net/ethtool", smoke_ethtool_control_roundtrip_and_rejection);
    fn smoke_ethtool_set_eeprom_routes_to_driver() -> TestResult {
        // SETEEPROM (0x0c) must size like GETEEPROM (0x0b) and reach the
        // driver's set_nvm op; the test Model leaves the default, so the
        // op itself refuses with -EOPNOTSUPP.
        if crate::ethtool::header_size(0x0c) != Some(16) {
            return TestResult::Fail("SETEEPROM header size wrong");
        }
        let mut b = alloc::vec![0; 20];
        put(&mut b, 0, 0x0c);
        put(&mut b, 12, 4);
        if crate::ethtool::request_size(&b) != Ok(20) {
            return TestResult::Fail("SETEEPROM request size wrong");
        }
        let (name, _) = setup();
        if crate::ethtool::execute(&name.0, &mut b) != Err(95) {
            return TestResult::Fail("SETEEPROM not routed to driver op");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_set_eeprom_routes_to_driver);
    fn smoke_ethtool_rxnfc_gap14_and_gpermaddr() -> TestResult {
        // GPERMADDR (0x20): 8-byte header, the size word, then the
        // address. A buffer smaller than the address is -ETOOSMALL.
        if crate::ethtool::header_size(0x20) != Some(8) {
            return TestResult::Fail("GPERMADDR header size wrong");
        }
        let (name, _) = setup();
        let mut perm = alloc::vec![0; 14];
        put(&mut perm, 0, 0x20);
        put(&mut perm, 4, 6);
        if crate::ethtool::execute(&name.0, &mut perm).is_err()
            || get(&perm, 4) != 6
            || perm[8..14] != [2, 1, 2, 3, 4, 5]
        {
            return TestResult::Fail("GPERMADDR failed");
        }
        let mut small = alloc::vec![0; 13];
        put(&mut small, 0, 0x20);
        put(&mut small, 4, 5);
        if crate::ethtool::execute(&name.0, &mut small) != Err(133) {
            return TestResult::Fail("GPERMADDR small buffer accepted");
        }
        // RXNFC buffers are built from the uapi layout, not from the
        // codec: flow_type @16, h_u @20 (h_dest @20, h_source @26,
        // h_proto @32), h_ext @72 (vlan_etype @80, vlan_tci @82,
        // data @84), m_u @92, m_ext @144 (vlan_etype @152,
        // vlan_tci @154, data @156), ring_cookie @168, location @176,
        // rule_cnt @184, rule_locs @188.
        let put64 = |b: &mut [u8], at: usize, v: u64| {
            b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
        };
        let get64 = |b: &[u8], at: usize| u64::from_ne_bytes(b[at..at + 8].try_into().unwrap());
        let mut rule = alloc::vec![0; 192];
        let insert = |name: &str, b: &mut [u8]| crate::ethtool::execute(name, b);
        // Source MAC, full mask.
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12);
        rule[26..32].copy_from_slice(&[6, 5, 4, 3, 2, 1]);
        rule[98..104].copy_from_slice(&[255; 6]);
        put64(&mut rule, 168, 1);
        put(&mut rule, 176, 5);
        if insert(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC source-MAC insert failed");
        }
        // VLAN EtherType, full mask, FLOW_EXT.
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12 | 0x80000000);
        rule[80..82].copy_from_slice(&[0x81, 0x00]);
        rule[152..154].copy_from_slice(&[255; 2]);
        put(&mut rule, 176, 6);
        if insert(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC VLAN-EtherType insert failed");
        }
        // User data with a partial mask.
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12 | 0x80000000);
        rule[84..92].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        rule[156..164].copy_from_slice(&[0xff, 0xff, 0, 0, 0, 0, 0, 0]);
        put64(&mut rule, 168, 2);
        put(&mut rule, 176, 7);
        if insert(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC user-data insert failed");
        }
        // Full-TCI match.
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12 | 0x80000000);
        rule[82..84].copy_from_slice(&[0x12, 0x34]);
        rule[154..156].copy_from_slice(&[255; 2]);
        put(&mut rule, 176, 8);
        if insert(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC full-TCI insert failed");
        }
        // Wildcard: plain ETHER_FLOW, no match field at all.
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12);
        put64(&mut rule, 168, 3);
        put(&mut rule, 176, 9);
        if insert(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC wildcard insert failed");
        }
        // RX_CLS_LOC_ANY takes the first free location (0).
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12);
        rule[32..34].copy_from_slice(&[0x88, 0xf7]);
        rule[104..106].copy_from_slice(&[255; 2]);
        put(&mut rule, 176, u32::MAX);
        if insert(&name.0, &mut rule).is_err() || get(&rule, 176) != 0 {
            return TestResult::Fail("RXNFC ANY location failed");
        }
        // Count and table size: 6 rules, 65 locations.
        rule.fill(0);
        put(&mut rule, 0, 0x2e);
        if crate::ethtool::execute(&name.0, &mut rule).is_err()
            || get(&rule, 184) != 6
            || get64(&rule, 8) != 65
        {
            return TestResult::Fail("RXNFC count / 65 table size wrong");
        }
        // All locations, in location order.
        let mut all = alloc::vec![0; 448];
        put(&mut all, 0, 0x30);
        put(&mut all, 184, 64);
        if crate::ethtool::execute(&name.0, &mut all).is_err()
            || get64(&all, 8) != 65
            || get(&all, 184) != 6
            || (0..6)
                .map(|i| get(&all, 188 + i * 4))
                .collect::<alloc::vec::Vec<u32>>()
                != alloc::vec![0, 5, 6, 7, 8, 9]
        {
            return TestResult::Fail("RXNFC location list wrong");
        }
        // Get the user-data rule back: same bytes, FLOW_EXT, queue 2,
        // and the table size in data, as Linux reports it.
        rule.fill(0);
        put(&mut rule, 0, 0x2f);
        put(&mut rule, 176, 7);
        if crate::ethtool::execute(&name.0, &mut rule).is_err()
            || get(&rule, 16) != 0x12 | 0x80000000
            || get64(&rule, 168) != 2
            || get64(&rule, 8) != 65
            || rule[84..92] != [1, 2, 3, 4, 5, 6, 7, 8]
            || rule[156..164] != [0xff, 0xff, 0, 0, 0, 0, 0, 0]
        {
            return TestResult::Fail("RXNFC user-data round-trip wrong");
        }
        // Get the wildcard back: plain ETHER_FLOW, queue 3, zero masks.
        rule.fill(0);
        put(&mut rule, 0, 0x2f);
        put(&mut rule, 176, 9);
        if crate::ethtool::execute(&name.0, &mut rule).is_err()
            || get(&rule, 16) != 0x12
            || get64(&rule, 168) != 3
            || rule[92..164].iter().any(|v| *v != 0)
        {
            return TestResult::Fail("RXNFC wildcard round-trip wrong");
        }
        // Rejections: a partial source-MAC mask, a bad VLAN TCI mask,
        // and an empty FLOW_EXT rule (no match at all).
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12);
        rule[26..32].copy_from_slice(&[6, 5, 4, 3, 2, 1]);
        rule[98..104].copy_from_slice(&[255, 255, 0, 0, 0, 0]);
        put(&mut rule, 176, 10);
        if insert(&name.0, &mut rule) != Err(95) {
            return TestResult::Fail("partial source-MAC mask accepted");
        }
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12 | 0x80000000);
        rule[82..84].copy_from_slice(&[0xe0, 0x00]);
        rule[154..156].copy_from_slice(&[0xf0, 0]);
        put(&mut rule, 176, 10);
        if insert(&name.0, &mut rule) != Err(95) {
            return TestResult::Fail("bad VLAN TCI mask accepted");
        }
        rule.fill(0);
        put(&mut rule, 0, 0x32);
        put(&mut rule, 16, 0x12 | 0x80000000);
        put(&mut rule, 176, 10);
        if insert(&name.0, &mut rule) != Err(22) {
            return TestResult::Fail("empty FLOW_EXT rule accepted");
        }
        // Delete one rule; the count drops.
        rule.fill(0);
        put(&mut rule, 0, 0x31);
        put(&mut rule, 176, 5);
        if crate::ethtool::execute(&name.0, &mut rule).is_err() {
            return TestResult::Fail("RXNFC delete failed");
        }
        rule.fill(0);
        put(&mut rule, 0, 0x2e);
        if crate::ethtool::execute(&name.0, &mut rule).is_err() || get(&rule, 184) != 5 {
            return TestResult::Fail("RXNFC count after delete wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_rxnfc_gap14_and_gpermaddr);
    fn smoke_ethtool_variable_requests_are_bounded() -> TestResult {
        for (cmd, size, offset) in [
            (4, 12, 8),
            (11, 16, 12),
            (27, 12, 8),
            (29, 8, 4),
            (26, 16, 12),
            (48, 192, 184),
            (0x38, 8, 4),
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
    kernel_test_in!("net/ethtool", smoke_ethtool_variable_requests_are_bounded);
    fn smoke_ethtool_igc_surface_roundtrip() -> TestResult {
        let (name, m) = setup();
        // The test Model keeps the NicControl defaults: msglevel, priv
        // flags and RXFH fields are unimplemented, so the new commands
        // surface as -EOPNOTSUPP rather than silently succeeding.
        for cmd in [0x07u32, 0x08, 0x27, 0x28] {
            let mut b = alloc::vec![0; 8];
            put(&mut b, 0, cmd);
            if crate::ethtool::execute(&name.0, &mut b) != Err(95) {
                return TestResult::Fail("unimplemented ethtool value command accepted");
            }
        }
        let mut rxfh = alloc::vec![0; 192];
        put(&mut rxfh, 0, 0x29);
        put(&mut rxfh, 4, 1);
        if crate::ethtool::execute(&name.0, &mut rxfh) != Err(95) {
            return TestResult::Fail("unimplemented GRXFH accepted");
        }
        put(&mut rxfh, 0, 0x2a);
        put(&mut rxfh, 8, 0xf0);
        if crate::ethtool::execute(&name.0, &mut rxfh) != Err(95) {
            return TestResult::Fail("unimplemented SRXFH accepted");
        }
        // Legacy RXFH indirection: GET with size 0 reports the table size;
        // SET requires exactly 128 entries and in-range queues.
        let mut indir = alloc::vec![0; 8];
        put(&mut indir, 0, 0x38);
        if crate::ethtool::execute(&name.0, &mut indir).is_err() || get(&indir, 4) != 128 {
            return TestResult::Fail("GRXFHINDIR size query failed");
        }
        let mut indir = alloc::vec![0; 16];
        put(&mut indir, 0, 0x38);
        put(&mut indir, 4, 2);
        if crate::ethtool::execute(&name.0, &mut indir).is_err()
            || get(&indir, 8) != 0
            || get(&indir, 12) != 1
        {
            return TestResult::Fail("GRXFHINDIR entries wrong");
        }
        let mut set = alloc::vec![0; 520];
        put(&mut set, 0, 0x39);
        put(&mut set, 4, 128);
        put(&mut set, 8, 99);
        if crate::ethtool::execute(&name.0, &mut set) != Err(22) {
            return TestResult::Fail("SRXFHINDIR accepted an out-of-range queue");
        }
        let mut set = alloc::vec![0; 264];
        put(&mut set, 0, 0x39);
        put(&mut set, 4, 64);
        if crate::ethtool::execute(&name.0, &mut set) != Err(22) {
            return TestResult::Fail("SRXFHINDIR accepted a short table");
        }
        // Channels: Linux NON_Q_VECTORS is 1.
        let mut ch = alloc::vec![0; 36];
        put(&mut ch, 0, 0x3c);
        if crate::ethtool::execute(&name.0, &mut ch).is_err()
            || get(&ch, 12) != 1
            || get(&ch, 28) != 1
            || get(&ch, 32) != 2
        {
            return TestResult::Fail("GCHANNELS other_count wrong");
        }
        put(&mut ch, 0, 0x3d);
        put(&mut ch, 28, 0);
        if crate::ethtool::execute(&name.0, &mut ch) != Err(22) {
            return TestResult::Fail("SCHANNELS accepted other_count 0");
        }
        put(&mut ch, 28, 1);
        put(&mut ch, 32, 2);
        if crate::ethtool::execute(&name.0, &mut ch).is_err() || m.0.lock().channels != 2 {
            return TestResult::Fail("SCHANNELS with other_count 1 rejected");
        }
        // A generic device must not inherit I225 hardware timestamp claims.
        let mut ts = alloc::vec![0; 44];
        put(&mut ts, 0, 0x41);
        if crate::ethtool::execute(&name.0, &mut ts).is_err() || get(&ts, 4) != 0x1a {
            return TestResult::Fail("GET_TS_INFO invented hardware timestamp support");
        }
        // Coalesce: non-usecs fields are ignored (Linux), not -EOPNOTSUPP.
        let mut coal = alloc::vec![0; 92];
        put(&mut coal, 0, 0x0f);
        put(&mut coal, 4, 166);
        put(&mut coal, 8, 5);
        put(&mut coal, 20, 166);
        put(&mut coal, 24, 7);
        if crate::ethtool::execute(&name.0, &mut coal).is_err() || m.0.lock().coalesce_us != 166 {
            return TestResult::Fail("SET_COALESCE rejected non-usecs fields");
        }
        // GSSET_INFO mask bit 2 reports the priv-flag count (0 here).
        let mut info = alloc::vec![0; 24];
        put(&mut info, 0, 0x37);
        put(&mut info, 8, 6);
        if crate::ethtool::execute(&name.0, &mut info).is_err()
            || get(&info, 8) != 6
            || get(&info, 16) != 1
            || get(&info, 20) != 0
        {
            return TestResult::Fail("GSSET_INFO priv-flag count wrong");
        }
        // GSTRINGS sset 2 (priv flags) with no flags reports count 0.
        let mut strings = alloc::vec![0; 12];
        put(&mut strings, 0, 0x1b);
        put(&mut strings, 4, 2);
        if crate::ethtool::execute(&name.0, &mut strings).is_err() || get(&strings, 8) != 0 {
            return TestResult::Fail("GSTRINGS priv-flag count wrong");
        }
        // Link ksettings: a too-small mask reports the required 2 words in
        // the signed nwords byte; a set with the wrong count is -EINVAL.
        let mut link = alloc::vec![0; 48];
        put(&mut link, 0, 0x4c);
        if crate::ethtool::execute(&name.0, &mut link).is_err() || link[15] as i8 != -2 {
            return TestResult::Fail("GLINKSETTINGS did not report 2 mask words");
        }
        link[15] = 2;
        link.resize(72, 0);
        if crate::ethtool::execute(&name.0, &mut link).is_err()
            || get(&link, 48) & (1 << 7) == 0
            || get(&link, 56) & 0xc0 != 0xc0
        {
            return TestResult::Fail("GLINKSETTINGS masks wrong");
        }
        put(&mut link, 0, 0x4d);
        link[15] = 1;
        if crate::ethtool::execute(&name.0, &mut link) != Err(22) {
            return TestResult::Fail("SLINKSETTINGS accepted a short mask");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_igc_surface_roundtrip);
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
    fn smoke_ethtool_features_track_packet_policy() -> TestResult {
        let name = Interface(crate::iface::register(
            "feature-test%d",
            [2, 3, 4, 5, 6, 7],
            send,
        ));
        let caps = crate::OffloadCapabilities {
            tx_checksum: true,
            rx_checksum: true,
            max_tso_bytes: 65536,
            vlan_insert: true,
        };
        crate::iface::set_offloads(&name.0, caps);
        let mut b = alloc::vec![0;40];
        put(&mut b, 0, 0x3a);
        put(&mut b, 4, 2);
        if crate::ethtool::execute(&name.0, &mut b).is_err()
            || get(&b, 8) & 8 == 0
            || get(&b, 24) & (1 << 8) == 0
        {
            return TestResult::Fail("features unavailable without a native control hook");
        }
        let mut set = alloc::vec![0;24];
        put(&mut set, 0, 0x3b);
        put(&mut set, 4, 2);
        put(&mut set, 8, 8);
        if crate::ethtool::execute_with_result(&name.0, &mut set) != Ok(2) {
            return TestResult::Fail("checksum/TSO dependency did not report WISH");
        }
        crate::iface::set_offloads(&name.0, caps); // reset must preserve policy
        let e = crate::iface::lookup(&name.0).unwrap();
        if e.offloads.tx_checksum || e.offloads.max_tso_bytes != 0 || !e.offloads.rx_checksum {
            return TestResult::Fail("feature request did not change stack packet policy");
        }
        put(&mut set, 12, 8);
        if crate::ethtool::execute_with_result(&name.0, &mut set) != Ok(0)
            || crate::iface::lookup(&name.0).unwrap().offloads != caps
        {
            return TestResult::Fail("offload reenable lost hardware capabilities");
        }
        put(&mut set, 8, 1);
        put(&mut set, 12, 1);
        if crate::ethtool::execute_with_result(&name.0, &mut set) != Ok(1) {
            return TestResult::Fail("unsupported feature was silently accepted");
        }
        let mut flags = [0; 8];
        put(&mut flags, 0, 0x26);
        if crate::ethtool::execute(&name.0, &mut flags).is_err()
            || crate::iface::lookup(&name.0).unwrap().offloads.vlan_insert
        {
            return TestResult::Fail("SFLAGS did not disable VLAN insertion policy");
        }
        let mut link = [0; 44];
        put(&mut link, 0, 1);
        if crate::ethtool::execute(&name.0, &mut link) != Err(95)
            || crate::ethtool::execute("missing-ethtool-device", &mut link) != Err(19)
        {
            return TestResult::Fail("unsupported and absent device errors conflated");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_features_track_packet_policy);

    fn smoke_ethtool_independent_string_counts() -> TestResult {
        #[derive(Debug)]
        struct Counts;
        impl NicControl for Counts {}
        impl crate::iface::DeviceControl for Counts {
            fn configure(&self, _: &crate::iface::DeviceConfig) -> Result<()> {
                Err(95)
            }
            fn nic(&self) -> Option<&dyn NicControl> {
                Some(self)
            }
        }
        let name = Interface(crate::iface::register(
            "count-test%d",
            [2, 3, 4, 5, 6, 8],
            send,
        ));
        crate::iface::set_device_control(&name.0, Arc::new(Counts));
        let mut b = [0; 24];
        put(&mut b, 0, 0x37);
        b[8] = 0x14;
        if crate::ethtool::execute(&name.0, &mut b).is_err()
            || b[8] != 0x14
            || get(&b, 16) != 0
            || get(&b, 20) != 64
        {
            return TestResult::Fail("priv/feature counts unnecessarily require statistics");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_independent_string_counts);

    fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
        out.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize((out.len() + 3) & !3, 0);
    }
    fn eth_request(name: &str) -> Vec<u8> {
        let mut h = Vec::new();
        let mut text = name.as_bytes().to_vec();
        text.push(0);
        nla(&mut h, 2, &text);
        let mut req = Vec::new();
        nla(&mut req, 0x8001, &h);
        req
    }
    fn eth_context(admin: bool, ns: u64) -> crate::netlink_generic::RequestContext<'static> {
        crate::netlink_generic::RequestContext {
            net_ns_id: ns,
            admin: None,
            init_net_admin: admin,
            net_admin: admin,
            capable: admin,
            portid: 0,
            ack_cookie: None,
        }
    }
    fn smoke_ethtool_netlink_native_roundtrip() -> TestResult {
        let (name, m) = setup();
        let req = eth_request(&name.0);
        for (cmd, reply) in [
            (2, 2),
            (4, 4),
            (6, 6),
            (11, 11),
            (15, 16),
            (17, 18),
            (19, 20),
            (21, 22),
            (25, 26),
        ] {
            let Ok(r) = crate::ethtool::handle_genl(cmd, &req, false, eth_context(false, 0)) else {
                return TestResult::Fail("native GET unavailable over netlink");
            };
            if r.len() != 1 || r[0].command != reply {
                return TestResult::Fail("wrong netlink reply command");
            }
        }
        let mut set = req.clone();
        nla(&mut set, 2, &200u32.to_ne_bytes());
        nla(&mut set, 6, &200u32.to_ne_bytes());
        if crate::ethtool::handle_genl(20, &set, false, eth_context(false, 0)).err() != Some(1)
            || m.0.lock().coalesce_us != 166
        {
            return TestResult::Fail("netlink SET bypassed admin authority");
        }
        if crate::ethtool::handle_genl(20, &set, false, eth_context(true, 0)).is_err()
            || m.0.lock().coalesce_us != 200
        {
            return TestResult::Fail("netlink coalesce SET did not reach native control");
        }
        nla(&mut set, 31, &[1]);
        if crate::ethtool::handle_genl(20, &set, false, eth_context(true, 0)).err() != Some(22)
            || m.0.lock().coalesce_us != 200
        {
            return TestResult::Fail("unknown attribute accepted or mutated native state");
        }
        if crate::ethtool::handle_genl(6, &req, false, eth_context(false, 91234)).err() != Some(19)
        {
            return TestResult::Fail("netlink GET escaped its network namespace");
        }
        if crate::ethtool::ETHTOOL_MSG_MM_GET != 42
            || crate::ethtool::ETHTOOL_MSG_MM_SET != 43
            || crate::ethtool::ETHTOOL_MSG_MM_GET_REPLY != 42
        {
            return TestResult::Fail("MAC Merge command IDs disagree with Linux UAPI");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_netlink_native_roundtrip);
    fn smoke_ethtool_netlink_features_bitsets() -> TestResult {
        let (name, _) = setup();
        crate::iface::set_offloads(
            &name.0,
            crate::OffloadCapabilities {
                tx_checksum: true,
                ..Default::default()
            },
        );
        for compact in [false, true] {
            let mut req = eth_request(&name.0);
            let mut bits = Vec::new();
            nla(&mut bits, 2, &64u32.to_ne_bytes());
            if compact {
                nla(&mut bits, 4, &0u64.to_ne_bytes());
                nla(&mut bits, 5, &8u64.to_ne_bytes());
            } else {
                let mut bit = Vec::new();
                nla(&mut bit, 2, b"tx-checksum-ip-generic\0");
                let mut entries = Vec::new();
                nla(&mut entries, 0x8001, &bit);
                nla(&mut bits, 0x8003, &entries);
            }
            nla(&mut req, 0x8003, &bits);
            let Ok(result) = crate::ethtool::handle_genl(12, &req, false, eth_context(true, 0))
            else {
                return TestResult::Fail("feature bitset SET rejected");
            };
            if result.len() != 1
                || result[0].command != 12
                || crate::iface::lookup(&name.0).unwrap().offloads.tx_checksum
            {
                return TestResult::Fail("feature netlink SET did not update active policy");
            }
            crate::iface::with_features(&name.0, |e| {
                e.feature_wanted = None;
                crate::ethtool::features::apply(e);
            })
            .unwrap();
            req.pop();
            req.pop();
            req.pop();
            req.pop();
            if crate::ethtool::handle_genl(12, &req, false, eth_context(true, 0)).err() != Some(22)
                || !crate::iface::lookup(&name.0).unwrap().offloads.tx_checksum
            {
                return TestResult::Fail("truncated feature SET changed policy");
            }
        }
        let mut global = Vec::new();
        let mut set = Vec::new();
        nla(&mut set, 1, &4u32.to_ne_bytes());
        let mut sets = Vec::new();
        nla(&mut sets, 0x8001, &set);
        nla(&mut global, 0x8002, &sets);
        if crate::ethtool::handle_genl(1, &global, false, eth_context(false, 0)).is_err() {
            return TestResult::Fail("global feature string set requires a NIC");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/ethtool", smoke_ethtool_netlink_features_bitsets);
}
