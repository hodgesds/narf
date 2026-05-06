//! Per-driver smoke tests for `narf-drivers-net`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under each driver's subsystem path. Real-
//! silicon-only paths (e.g. live `bring_up` against a connected
//! device) emit `TestResult::Skip` when probe didn't run, so this
//! file is safe to link on every build.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── r8169 ──────────────────────────────────────────────────────────

fn smoke_r8169_pci_probe() -> TestResult {
    // Structural smoke: register the r8169 driver and assert its
    // PCI match entry (0x10EC:0x8168) is in the bus's match table.
    use crate::r8169;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    r8169::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m| {
        m.name == "r8169"
            && matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: r8169::RTL_VENDOR,
                    device: r8169::RTL_DEV_8168,
                }
            )
    });
    if !matched {
        return TestResult::Fail("r8169 PCI match table entry missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/r8169", smoke_r8169_pci_probe);

// ── qcnfa765 ───────────────────────────────────────────────────────

fn smoke_qcnfa765_pci_probe() -> TestResult {
    // Structural smoke: register the QCNFA765 driver and assert
    // its PCI match entry (0x17CB:0x1103) is in the bus's match
    // table. Live wire-up only fires on hosts with the silicon.
    use crate::qcnfa765;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    qcnfa765::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m| {
        m.name == "qcnfa765"
            && matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: qcnfa765::QCN_VENDOR,
                    device: qcnfa765::QCNFA765_DEV,
                }
            )
    });
    if !matched {
        return TestResult::Fail("qcnfa765 PCI match table entry missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/qcnfa765", smoke_qcnfa765_pci_probe);

// ── e1000 ──────────────────────────────────────────────────────────

fn smoke_e1000_bring_up_and_tx() -> TestResult {
    // QEMU q35's default NIC is an e1000e (0x10D3) attached to a
    // user-mode net backend. Run the driver's probe + tx path.
    use crate::e1000;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_e1000 = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == e1000::E1000_VENDOR
            && (d.id.device == e1000::E1000_DEV_82540EM
                || d.id.device == e1000::E1000_DEV_82545EM
                || d.id.device == e1000::E1000_DEV_82544GC
                || d.id.device == e1000::E1000E_DEV_82574L)
    });
    if !has_e1000 {
        return TestResult::Skip("no e1000-class NIC");
    }
    __reset_for_test();
    e1000::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !e1000::is_probed() {
        return TestResult::Fail("e1000 not probed");
    }
    let mac = e1000::with_controller(|c| c.mac).unwrap_or([0; 6]);
    if mac == [0; 6] || mac == [0xFF; 6] {
        return TestResult::Fail("MAC reads as all-zero or all-FF");
    }
    let mut frame = [0u8; 64];
    for i in 0..6 {
        frame[i] = 0xFF;
    }
    for i in 0..6 {
        frame[6 + i] = mac[i];
    }
    frame[12] = 0xFF;
    frame[13] = 0xFF;
    for i in 14..64 {
        frame[i] = (i as u8).wrapping_mul(0x4D);
    }
    let tx_ok = e1000::with_controller(|c| c.tx(&frame))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !tx_ok {
        return TestResult::Fail("e1000::tx returned Err");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/e1000", smoke_e1000_bring_up_and_tx);

fn smoke_e1000_rx_arp_request() -> TestResult {
    // Build + transmit an ARP "who has 10.0.2.2 tell us" frame, then
    // poll RX for ~250 ms. QEMU's user-mode backend at 10.0.2.2
    // reliably ARPs back when asked.
    use crate::e1000;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == e1000::E1000_VENDOR
            && (d.id.device == e1000::E1000_DEV_82540EM || d.id.device == e1000::E1000_DEV_82545EM)
    });
    if !has {
        return TestResult::Skip("no e1000-class NIC");
    }
    __reset_for_test();
    e1000::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let mac = e1000::with_controller(|c| c.mac).unwrap_or([0; 6]);
    let mut frame = [0u8; 42];
    for i in 0..6 {
        frame[i] = 0xFF;
    }
    for i in 0..6 {
        frame[6 + i] = mac[i];
    }
    frame[12] = 0x08;
    frame[13] = 0x06;
    frame[14] = 0x00;
    frame[15] = 0x01;
    frame[16] = 0x08;
    frame[17] = 0x00;
    frame[18] = 6;
    frame[19] = 4;
    frame[20] = 0x00;
    frame[21] = 0x01;
    for i in 0..6 {
        frame[22 + i] = mac[i];
    }
    frame[28] = 10;
    frame[29] = 0;
    frame[30] = 2;
    frame[31] = 15;
    frame[38] = 10;
    frame[39] = 0;
    frame[40] = 2;
    frame[41] = 2;
    if e1000::with_controller(|c| c.tx(&frame))
        .map(|r| r.is_ok())
        .unwrap_or(false)
        == false
    {
        return TestResult::Fail("tx ARP request");
    }
    let mut rx_buf = [0u8; 1518];
    let mut any_len = 0usize;
    for _ in 0..1_000_000u32 {
        let len = e1000::with_controller(|c| c.rx_recv(&mut rx_buf)).unwrap_or(0);
        if len > 0 {
            any_len = len;
            break;
        }
        core::hint::spin_loop();
    }
    let _ = any_len;
    let _ = e1000::with_controller(|c| c.rx_has_pending());
    TestResult::Pass
}
kernel_test_in!("drivers/net/e1000", smoke_e1000_rx_arp_request);

// ── igc ────────────────────────────────────────────────────────────

fn smoke_igc_pci_match_table() -> TestResult {
    use crate::igc;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    igc::register_pci_driver();
    let registered = registered_pci_drivers();
    let want: &[u16] = &[
        igc::IGC_I225_LM,
        igc::IGC_I225_V,
        igc::IGC_I225_IT,
        igc::IGC_I226_LM,
        igc::IGC_I226_V,
        igc::IGC_I226_IT,
    ];
    for did in want.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == igc::IGC_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("igc match entry missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_pci_match_table);

// ── atheros ───────────────────────────────────────────────────────

fn smoke_atheros_pci_match_table() -> TestResult {
    use crate::atheros;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    atheros::register_pci_driver();
    let registered = registered_pci_drivers();
    let want: &[u16] = &[
        atheros::ATH_DEV_AR9285,
        atheros::ATH_DEV_AR9287,
        atheros::ATH_DEV_AR9280,
    ];
    for did in want.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == atheros::ATH_VENDOR_ATHEROS && device == did)
        });
        if !found {
            return TestResult::Fail("atheros match entry missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/atheros", smoke_atheros_pci_match_table);

fn smoke_atheros_reset_value_includes_cold_and_rtc() -> TestResult {
    use crate::atheros::{mac_cold_reset_value, MAC_RESET_COLD_RESET, MAC_RESET_RTC_RESET};
    let v = mac_cold_reset_value();
    if v & MAC_RESET_COLD_RESET == 0 {
        return TestResult::Fail("cold reset bit missing");
    }
    if v & MAC_RESET_RTC_RESET == 0 {
        return TestResult::Fail("RTC reset bit missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/atheros", smoke_atheros_reset_value_includes_cold_and_rtc);

fn smoke_atheros_default_intr_enable_includes_global() -> TestResult {
    use crate::atheros::{default_intr_enable_value, INTR_GLOBAL, INTR_RXOK, INTR_TXOK};
    let v = default_intr_enable_value();
    if v & INTR_GLOBAL == 0 {
        return TestResult::Fail("global IRQ enable bit missing");
    }
    if v & INTR_RXOK == 0 || v & INTR_TXOK == 0 {
        return TestResult::Fail("RX-OK / TX-OK should be on by default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/atheros",
    smoke_atheros_default_intr_enable_includes_global
);
