//! AHB netdev registration smokes: an AHB-attached core (IPQ6018
//! shape, no ring MSI) must register an initial netdev through
//! `register_ahb` the same way a PCI core does through `register_pci`,
//! and the stack must route to it by dispatch cookie.
//!
//! Fixture notes: the "firmware" here is a scripted pair of WMI
//! service-ready records (`ServiceReadyExt` + `Ready`), not wire
//! bytes — the registration path reads recorded fields, never parses
//! a frame. The CE/DP rings run on a zeroed `ChipIo` (reads return 0,
//! writes ignored), which is the no-hardware shape the DP tests use
//! for the no-MSI path. The scripted records carry no protocol
//! constants beyond the in-tree WMI band-cap bits (`wmi.rs`).

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::super::ce::{monotonic_ms, Ce, CeIrq, CeMsi};
use super::super::core::{Ath11kCore, CeHif, QmiFw};
use super::super::dp_ring::{Dp, DpHwParams, DpRingSizes};
use super::super::hal::Hal;
use super::super::hw::{HwRev, MSI_CONFIG_NONE};
use super::super::mac::{Mac, MacConfig};
use super::super::power::ChipIo;
use super::super::runtime::{Port, Rt, Shared};
use super::super::wlfw::WlfwError;
use super::super::wmi::{
    PdevCap, Ready, ServiceMap, ServiceReadyExt, TargetCaps, WMI_HOST_WLAN_2G_CAP,
    WMI_HOST_WLAN_5G_CAP,
};
use super::{ahb_drain, ahb_send_context, register_ahb, AHB_ACTIVE};
use crate::ath11k::ahb::AhbChip;

/// Locally-administered test MAC, distinct from every in-tree fixture
/// MAC (integration tests use `02:00:00:00:00:02`-style addresses only
/// via `caps.mac_addr` from their own scripted records).
const TEST_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];

/// Small ring sizes, copied from the DP tests' proven no-MSI rig
/// (`dp_tests::SMALL`): the smallest sizes that allocate cleanly.
const SIZES: DpRingSizes = DpRingSizes {
    wbm_release: 16,
    tcl_cmd: 8,
    tcl_status: 8,
    tcl_data: Some(8),
    tx_comp: 16,
    reo_reinject: 8,
    rx_release: 16,
    reo_exception: 16,
    reo_cmd: 8,
    reo_status: 16,
    reo_dst: 16,
    rxdma_buf: 16,
    rx_mac_buf: 16,
    rxdma_err_dst: 16,
    rxdma_mon_status: 8,
    rxdma_mon_buf: 8,
    rxdma_mon_dst: 8,
    rxdma_mon_desc: 8,
    tx_status_fifo: 8,
    n_link_desc: Some(64),
};

fn test_rng(_out: &mut [u8]) -> Result<(), i32> {
    Ok(())
}

/// Zeroed MMIO: every read returns 0, every write is ignored. The CE
/// and DP rings therefore see empty rings (head == tail).
#[derive(Clone, Copy, Default)]
struct FakeIo;

impl ChipIo for FakeIo {
    fn read32(&self, _offset: u32) -> u32 {
        0
    }
    fn write32(&self, _offset: u32, _value: u32) {}
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

/// No interrupts ever fire.
#[derive(Clone, Copy, Default)]
struct FakeIrq;

impl CeIrq for FakeIrq {
    fn take_pending(&self) -> u32 {
        0
    }
    async fn wait(&self, _ms: u32) {}
}

impl super::super::runtime::DpIrq for FakeIrq {
    fn take_dp_pending(&self) -> u32 {
        0
    }
}

/// QMI transport that never runs: `device_caps` reads recorded
/// fields, never calls QMI.
struct FakeQmi;

impl QmiFw for FakeQmi {
    async fn firmware_start(
        &mut self,
        _mode: u32,
        _shadow_reg_v2: &[u32],
    ) -> Result<(), WlfwError> {
        Ok(())
    }
    async fn firmware_stop(&mut self) {}
}

/// A ready IPQ6018-shaped core: CE allocated with no ring MSI
/// (`MSI_CONFIG_NONE`, the IPQ shape from `ahb_ce_hif`), and scripted
/// WMI service-ready records planted. The DP is allocated by the
/// caller (it needs the caller's `Hal`).
fn ready_core() -> Result<Ath11kCore<CeHif<FakeIo, FakeIrq>, FakeQmi>, TestResult> {
    let params = AhbChip::Ipq6018Hw10.params();
    let hw = params.hw_params(HwRev::Ipq6018Hw10);
    let ce = match Ce::alloc(
        &hw,
        CeMsi {
            addr: 0,
            ep_base_data: 0,
            config: &MSI_CONFIG_NONE,
        },
        monotonic_ms,
    ) {
        Ok(ce) => ce,
        Err(_) => return Err(TestResult::Fail("ce alloc")),
    };
    let hif = CeHif {
        ce,
        io: FakeIo,
        irq: FakeIrq,
        on_start: || {},
        clock: monotonic_ms,
    };
    let cfg = match super::super::core::CoreConfig::for_hw(&hw) {
        Some(cfg) => cfg,
        None => return Err(TestResult::Fail("IPQ6018 core config")),
    };
    let mut core = match Ath11kCore::new(hif, FakeQmi, cfg) {
        Ok(core) => core,
        Err(_) => return Err(TestResult::Fail("core new")),
    };
    core.svc_ext = Some(ServiceReadyExt {
        pdevs: vec![PdevCap {
            pdev_id: 0,
            supported_bands: WMI_HOST_WLAN_2G_CAP | WMI_HOST_WLAN_5G_CAP,
            ..Default::default()
        }],
        num_radios: 1,
        ..Default::default()
    });
    core.ready = Some(Ready {
        mac_addr: TEST_MAC,
        ..Default::default()
    });
    core.target_caps = TargetCaps::default();
    core.svc_map = ServiceMap::default();
    core.mac_addr = Some(TEST_MAC);
    Ok(core)
}

/// An IPQ6018-shaped DP with no MSI, on the caller's `Hal`, with
/// `radios` pdevs allocated as `ath11k_core_pdev_create` ->
/// `ath11k_dp_pdev_alloc` leaves them before `ath11k_mac_register`
/// (the HTT SRING_SETUP messages are dropped: no firmware listens).
fn ready_dp_with(hal: &mut Hal, radios: u32) -> Result<Dp, TestResult> {
    let cfg = match DpHwParams::for_rev(HwRev::Ipq6018Hw10) {
        Some(cfg) => cfg,
        None => return Err(TestResult::Fail("complete DP params")),
    };
    let mut dp = match Dp::alloc(hal, &FakeIo, &cfg, SIZES, None) {
        Ok(dp) => dp,
        Err(_) => return Err(TestResult::Fail("dp alloc")),
    };
    if dp.pdev_reo_setup(hal, &FakeIo).is_err() {
        return Err(TestResult::Fail("dp reo setup"));
    }
    for mac_id in 0..radios {
        if dp.pdev_alloc(hal, &FakeIo, mac_id).is_err() {
            return Err(TestResult::Fail("dp pdev alloc"));
        }
    }
    Ok(dp)
}

fn ready_dp(hal: &mut Hal) -> Result<Dp, TestResult> {
    ready_dp_with(hal, 1)
}

fn hal() -> Result<Hal, TestResult> {
    let cfg = match DpHwParams::for_rev(HwRev::Ipq6018Hw10) {
        Some(cfg) => cfg,
        None => return Err(TestResult::Fail("complete DP params")),
    };
    match Hal::new(&cfg.hw) {
        Ok(hal) => Ok(hal),
        Err(_) => Err(TestResult::Fail("hal")),
    }
}

fn smoke_ath11k_ahb_netdev_register() -> TestResult {
    let mut h = match hal() {
        Ok(h) => h,
        Err(e) => return e,
    };
    let dp = match ready_dp(&mut h) {
        Ok(dp) => dp,
        Err(e) => return e,
    };
    let core = match ready_core() {
        Ok(core) => core,
        Err(e) => return e,
    };
    let (_shared, mac) = super::super::runtime::start_ahb(core, dp);
    let macs = match mac {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("start_ahb device_caps"),
    };
    kt_assert_eq!(macs, vec![TEST_MAC]);

    // The wireless registry exposes the new radio under its MAC.
    let profile = narf_wireless::registry::list()
        .into_iter()
        .find(|p| p.mac() == TEST_MAC);
    kt_assert!(profile.is_some());
    let profile = profile.unwrap();
    let name = profile.name();
    kt_assert!(name.starts_with("wlan"));
    // No virtual interfaces on an AHB netdev yet: the lifecycle hooks
    // route through the PCI active list.
    kt_assert_eq!(profile.supports_virtual_interfaces(), false);

    // The net stack knows the iface: same MAC, down with no carrier
    // until IFF_UP, driver name `ath11k_ahb`.
    let snap = narf_net::iface::lookup(name);
    kt_assert!(snap.is_some());
    let snap = snap.unwrap();
    kt_assert_eq!(snap.mac, TEST_MAC);
    kt_assert_eq!(snap.carrier, false);
    let info = narf_net::iface::driver_info(name);
    kt_assert!(info.is_some());
    let (driver, version, bus) = info.unwrap();
    kt_assert_eq!(driver, "ath11k_ahb");
    kt_assert!(version.is_none());
    kt_assert!(bus.is_empty());
    TestResult::Pass
}

fn smoke_ath11k_ahb_netdev_dispatch() -> TestResult {
    let mut h = match hal() {
        Ok(h) => h,
        Err(e) => return e,
    };
    let dp = match ready_dp(&mut h) {
        Ok(dp) => dp,
        Err(e) => return e,
    };
    let core = match ready_core() {
        Ok(core) => core,
        Err(e) => return e,
    };
    let rt = Rt::new(core, dp);
    let caps = match rt.device_caps() {
        Ok(caps) => caps,
        Err(_) => return TestResult::Fail("device_caps"),
    };
    let shared = Shared::new(rt, test_rng);
    let mac = Mac::new(
        Port(shared.clone(), 0, 0),
        Port(shared.clone(), 0, 0),
        caps.clone(),
        MacConfig::wcn6855(),
        None,
    );
    let cookie = shared.radio_id << 2;

    // Before registration nothing routes to this cookie.
    kt_assert_eq!(
        ahb_send_context(cookie, b"frame", narf_net::TxMeta::plain()),
        Err(())
    );

    let name = register_ahb(shared.clone(), mac, caps.mac_addr, 0);
    kt_assert!(name.starts_with("wlan"));

    // The dispatch table now maps this cookie to this iface, and only
    // to this iface: an unknown cookie still fails.
    let entry = AHB_ACTIVE
        .lock()
        .iter()
        .find(|dev| dev.cookie() == cookie)
        .cloned();
    kt_assert!(entry.is_some());
    let entry = entry.unwrap();
    kt_assert_eq!(entry.dispatch_name(), name);
    kt_assert_eq!(
        ahb_send_context(u64::MAX, b"frame", narf_net::TxMeta::plain()),
        Err(())
    );

    // Draining a registered AHB netdev with no pending frames runs
    // clean over the fake runtime and reports nothing delivered.
    kt_assert_eq!(ahb_drain(), false);
    // The test's own handle can go: the registered dev is owned by
    // the dispatch table and the netdev itself.
    drop(shared);
    TestResult::Pass
}

/// Two-radio IPQ6018 (`max_radios = 2`, Linux `ath11k_hw_params`): the
/// firmware reports two pdevs and one READY extra MAC address per radio
/// (`ath11k_mac_allocate` with `pdevs_macaddr_valid`). `start_ahb` must
/// register one netdev per pdev, each with its own radio's MAC, on its
/// own vdev slot (distinct dispatch cookies), not one `wcn6855()` MAC
/// on `Port(shared, 0, 0)`. The firmware pdev ids (1, 2) differ from
/// the DP mac ids (0, 1): caps are resolved by pdev index, as Linux
/// walks `ab->pdevs[i]`.
fn smoke_ath11k_ahb_multi_pdev_register() -> TestResult {
    const RADIO_MACS: [[u8; 6]; 2] = [
        [0x02, 0x00, 0x5e, 0x00, 0x53, 0x10],
        [0x02, 0x00, 0x5e, 0x00, 0x53, 0x11],
    ];
    let mut h = match hal() {
        Ok(h) => h,
        Err(e) => return e,
    };
    let dp = match ready_dp_with(&mut h, 2) {
        Ok(dp) => dp,
        Err(e) => return e,
    };
    kt_assert_eq!(dp.pdev_mac_ids(), vec![0, 1]);
    let mut core = match ready_core() {
        Ok(core) => core,
        Err(e) => return e,
    };
    let pdev = |id: u32| PdevCap {
        pdev_id: id,
        supported_bands: WMI_HOST_WLAN_2G_CAP | WMI_HOST_WLAN_5G_CAP,
        ..Default::default()
    };
    // Firmware pdev ids are 1-based on a multi-pdev part
    // (`mac_phy_caps->pdev_id`); the DP mac ids are 0-based indices.
    core.svc_ext = Some(ServiceReadyExt {
        pdevs: vec![pdev(1), pdev(2)],
        num_radios: 2,
        ..Default::default()
    });
    core.ready = Some(Ready {
        mac_addr: TEST_MAC,
        num_extra_mac_addr: 2,
        extra_mac_addrs: RADIO_MACS.to_vec(),
        ..Default::default()
    });
    let (shared, r) = super::super::runtime::start_ahb(core, dp);
    let macs = match r {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("start_ahb multi-pdev caps"),
    };
    kt_assert_eq!(macs, RADIO_MACS.to_vec());
    let mut names = Vec::new();
    for (slot, mac) in RADIO_MACS.iter().enumerate() {
        let cookie = (shared.radio_id << 2) | slot as u64;
        let entry = AHB_ACTIVE
            .lock()
            .iter()
            .find(|dev| dev.cookie() == cookie)
            .cloned();
        kt_assert!(entry.is_some(), "radio netdev on its own vdev slot");
        let name = alloc::string::String::from(entry.unwrap().dispatch_name());
        let snap = narf_net::iface::lookup(&name);
        kt_assert!(snap.is_some());
        kt_assert_eq!(snap.unwrap().mac, *mac);
        let profile = narf_wireless::registry::list()
            .into_iter()
            .find(|p| p.mac() == *mac);
        kt_assert!(profile.is_some(), "radio in the wireless registry");
        names.push(name);
    }
    kt_assert!(names[0] != names[1], "one netdev per radio");
    // Nothing was registered on a third slot.
    let third = (shared.radio_id << 2) | 2;
    kt_assert!(!AHB_ACTIVE.lock().iter().any(|dev| dev.cookie() == third));
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_netdev_register);
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_multi_pdev_register
);
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_netdev_dispatch);
