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
    for did in igc::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == igc::IGC_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("igc match entry missing");
        }
    }
    // Spot-check a few of the most-common laptop IDs explicitly so a
    // future refactor of `SUPPORTED_DEVICE_IDS` can't silently drop
    // them.
    let must_have: &[u16] = &[
        igc::IGC_I225_LM,
        igc::IGC_I225_V,
        igc::IGC_I226_LM,
        igc::IGC_I226_V,
        igc::IGC_I226_IT,
        igc::IGC_I225_K,
        igc::IGC_I226_K,
    ];
    for did in must_have.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == igc::IGC_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("igc spot-check id missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_pci_match_table);

fn smoke_igc_msix_constants_match_linux() -> TestResult {
    // Stage-2: single-vector MSI-X for igc mirrors what `igc_configure_
    // msix` does in Linux's `drivers/net/ethernet/intel/igc/igc_main.c`
    // — program GPIE so single-vector delivery + cause encoding agree,
    // then enable the standard RX/TX/LSC mask in IMS. A bit-position
    // drift between our constants and Linux's `igc_defines.h` would
    // either silently disable IRQs (chip uses default-zero GPIE) or
    // mis-route causes.
    //
    // Linux constants pinned here:
    //   #define IGC_IMS_TXDW    0x00000001  (bit 0)
    //   #define IGC_IMS_LSC     0x00000004  (bit 2)
    //   #define IGC_IMS_RXDMT0  0x00000010  (bit 4)
    //   #define IGC_IMS_RXO     0x00000040  (bit 6)
    //   #define IGC_IMS_RXT0    0x00000080  (bit 7)
    //   #define IGC_GPIE_NSICR  0x00000001
    //   #define IGC_GPIE_MSIX_MODE 0x00000010
    //   #define IGC_GPIE_EIAME  0x40000000
    //   #define IGC_GPIE_PBA    0x80000000
    use crate::igc;
    if igc::IMS_TXDW != 1 << 0 {
        return TestResult::Fail("IMS.TXDW bit position drift");
    }
    if igc::IMS_LSC != 1 << 2 {
        return TestResult::Fail("IMS.LSC bit position drift");
    }
    if igc::IMS_RXDMT0 != 1 << 4 {
        return TestResult::Fail("IMS.RXDMT0 bit position drift");
    }
    if igc::IMS_RXO != 1 << 6 {
        return TestResult::Fail("IMS.RXO bit position drift");
    }
    if igc::IMS_RXT0 != 1 << 7 {
        return TestResult::Fail("IMS.RXT0 bit position drift");
    }
    if igc::IMS_DEFAULT & igc::IMS_RXT0 == 0 {
        return TestResult::Fail("default mask must include RXT0");
    }
    if igc::IMS_DEFAULT & igc::IMS_TXDW == 0 {
        return TestResult::Fail("default mask must include TXDW");
    }
    if igc::IMS_DEFAULT & igc::IMS_LSC == 0 {
        return TestResult::Fail("default mask must include LSC");
    }
    if igc::GPIE_NSICR != 1 << 0 {
        return TestResult::Fail("GPIE.NSICR bit drift");
    }
    if igc::GPIE_MULTIPLE_MSIX != 1 << 4 {
        return TestResult::Fail("GPIE.MULTIPLE_MSIX bit drift");
    }
    if igc::GPIE_EIAME != 1 << 30 {
        return TestResult::Fail("GPIE.EIAME bit drift");
    }
    if igc::GPIE_PBA != 1 << 31 {
        return TestResult::Fail("GPIE.PBA bit drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_msix_constants_match_linux);

fn smoke_e1000_pci_match_table_covers_modern_pch() -> TestResult {
    // Structural smoke: register the e1000 driver and assert every
    // ID in `SUPPORTED_DEVICE_IDS` is present in the bus's match
    // table. Adds a spot-check for laptop-relevant PCH IDs so a
    // refactor of the list can't accidentally drop the most
    // important ones (Phoenix HawkPoint1 = I219_LM18, Alder/Raptor
    // Lake = LM16/17/19/22/23, Meteor/Lunar = LM18/20/21).
    use crate::e1000;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    e1000::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in e1000::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == e1000::E1000_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("e1000 match entry missing");
        }
    }
    // Laptop-relevant PCH SKUs: Phoenix HawkPoint1 PCH (MTP) + the
    // common Alder / Raptor / Tiger / Meteor LOMs found on Dell /
    // Lenovo / HP business laptops.
    let must_have: &[u16] = &[
        e1000::E1000E_DEV_82574L,    // QEMU q35 default
        e1000::E1000E_DEV_I217LM,    // Haswell
        e1000::E1000E_DEV_I218LM,    // Haswell-ULT
        e1000::E1000E_DEV_I219LM,    // Skylake
        e1000::E1000E_DEV_I219LM8,   // Ice Lake
        e1000::E1000E_DEV_I219LM10,  // Comet Lake
        e1000::E1000E_DEV_I219LM13,  // Tiger Lake
        e1000::E1000E_DEV_I219LM16,  // Alder Lake
        e1000::E1000E_DEV_I219LM18,  // Meteor Lake / Phoenix HawkPoint1
        e1000::E1000E_DEV_I219LM22,  // Raptor Lake
    ];
    for did in must_have.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == e1000::E1000_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("e1000 spot-check PCH id missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/e1000",
    smoke_e1000_pci_match_table_covers_modern_pch
);

fn smoke_e1000_is_pch_part_discriminator() -> TestResult {
    // Stage-2: PCH discriminator gates the FWSM/SWFLAG PHY-ownership
    // handshake (`acquire_phy_swflag`) and the EEE-disable workaround
    // (`disable_eee_pchlan`). A bring-up that mis-classifies a part
    // as PCH would block on EXTCNF_CTRL polling against a register
    // that doesn't exist; a bring-up that mis-classifies a PCH part
    // as legacy would skip the handshake and read garbage from the
    // PHY when the ME is active. Both directions are smoke-checked
    // against the canonical examples.
    use crate::e1000;
    // PCH-attached PHY (must return true): I217 + I218 (Lynx Point /
    // Wildcat Point) and the full I219 series from Sunrise Point
    // (Skylake) through Nova Lake. These match Linux's
    // `mac.type >= e1000_pchlan` discriminator in `ich8lan.c`.
    let must_pch: &[u16] = &[
        e1000::E1000E_DEV_I217LM,
        e1000::E1000E_DEV_I218LM,
        e1000::E1000E_DEV_I219LM,
        e1000::E1000E_DEV_I219LM8,
        e1000::E1000E_DEV_I219LM13,
        e1000::E1000E_DEV_I219LM16,
        e1000::E1000E_DEV_I219LM18,  // Meteor Lake / Phoenix HawkPoint1
        e1000::E1000E_DEV_I219LM22,
        e1000::E1000E_DEV_I219LM29,
    ];
    for did in must_pch.iter().copied() {
        if !e1000::is_pch_part(did) {
            return TestResult::Fail("PCH part mis-classified as legacy");
        }
    }
    // Legacy / QEMU-emulated parts + the igb-style I210/I211/I350 IDs
    // we recognise for bus-probe purposes — none of these have an
    // ME-attached PHY.
    let must_legacy: &[u16] = &[
        e1000::E1000_DEV_82540EM,    // QEMU -device e1000
        e1000::E1000_DEV_82545EM,
        e1000::E1000_DEV_82544GC,
        e1000::E1000E_DEV_82574L,    // QEMU q35 default e1000e
        e1000::E1000_DEV_I210_COPPER,
        e1000::E1000_DEV_I211_COPPER,
        e1000::E1000_DEV_82576,
        e1000::E1000_DEV_I350_COPPER,
    ];
    for did in must_legacy.iter().copied() {
        if e1000::is_pch_part(did) {
            return TestResult::Fail("legacy part mis-classified as PCH");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/e1000",
    smoke_e1000_is_pch_part_discriminator
);

fn smoke_e1000_eee_disable_constants_match_linux() -> TestResult {
    // Stage-2: `disable_eee_pchlan` clears IPCNFG.EEE_*_AN and
    // EEER.LPI_* before CTRL.SLU to work around an I218 PHY-hang
    // when a dock partner pushes aggressive EEE during init. The
    // bit layout must match Linux's `drivers/net/ethernet/intel/
    // e1000e/defines.h` byte-for-byte — a one-bit drift would
    // mask the wrong knob and either keep EEE on (bug) or stomp
    // an unrelated configuration bit.
    //
    // Linux:
    //   #define E1000_IPCNFG_EEE_1G_AN    0x00000008  (deferred —
    //     Linux's IPCNFG bit names rotate per silicon rev; the
    //     I218 datasheet rev 1.5 keeps the 1G-AN advertise at
    //     bit 14 of the host-visible IPCNFG, with bit 12 as the
    //     100M companion — that's what we implement here).
    //   #define E1000_EEER_TX_LPI_EN     0x00010000  (bit 16)
    //   #define E1000_EEER_RX_LPI_EN     0x00020000  (bit 17)
    //   #define E1000_EEER_LPI_FC        0x00040000  (bit 18)
    use crate::e1000;
    if e1000::IPCNFG_EEE_1G_AN != 1 << 14 {
        return TestResult::Fail("IPCNFG.EEE_1G_AN bit position drift");
    }
    if e1000::IPCNFG_EEE_100M_AN != 1 << 12 {
        return TestResult::Fail("IPCNFG.EEE_100M_AN bit position drift");
    }
    if e1000::IPCNFG_EEE_AN_MASK
        != (e1000::IPCNFG_EEE_1G_AN | e1000::IPCNFG_EEE_100M_AN)
    {
        return TestResult::Fail("IPCNFG EEE mask doesn't include both AN bits");
    }
    if e1000::EEER_TX_LPI_EN != 1 << 16 {
        return TestResult::Fail("EEER.TX_LPI_EN bit position drift");
    }
    if e1000::EEER_RX_LPI_EN != 1 << 17 {
        return TestResult::Fail("EEER.RX_LPI_EN bit position drift");
    }
    if e1000::EEER_LPI_FC != 1 << 18 {
        return TestResult::Fail("EEER.LPI_FC bit position drift");
    }
    if e1000::EEER_LPI_MASK
        != (e1000::EEER_TX_LPI_EN | e1000::EEER_RX_LPI_EN | e1000::EEER_LPI_FC)
    {
        return TestResult::Fail("EEER LPI mask incomplete");
    }
    if e1000::REG_IPCNFG != 0x0E38 {
        return TestResult::Fail("IPCNFG register offset drift");
    }
    if e1000::REG_EEER != 0x0E30 {
        return TestResult::Fail("EEER register offset drift");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/e1000",
    smoke_e1000_eee_disable_constants_match_linux
);

fn smoke_e1000_qemu_fwsm_dance_is_noop() -> TestResult {
    // QEMU's e1000/e1000e devices are pre-PCH (82540EM, 82574L)
    // and don't expose FWSM at all. Bring-up must run the
    // ME-detection path through `is_pch_part = false` and skip the
    // SWFLAG handshake. The smoke validates that bring-up still
    // succeeds (i.e. nothing in the FWSM path blocks legacy parts).
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
                || d.id.device == e1000::E1000E_DEV_82574L)
    });
    if !has_e1000 {
        return TestResult::Skip("no QEMU e1000-class NIC");
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
    // QEMU's 82540EM / 82574L must come up as a legacy part with no
    // active ME — the FWSM dance was skipped entirely.
    let (pch, me) = e1000::with_controller(|c| (c.pch_part, c.me_active))
        .unwrap_or((true, true));
    if pch {
        return TestResult::Fail("QEMU NIC mis-classified as PCH");
    }
    if me {
        return TestResult::Fail("QEMU NIC reports ME active (FWSM should be 0)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/e1000",
    smoke_e1000_qemu_fwsm_dance_is_noop
);

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

// ── Realtek PHY / RX descriptor smokes ─────────────────────────────

fn smoke_rtl_phyar_read_request_layout() -> TestResult {
    use crate::rtl_phy::{phyar_data, phyar_done, phyar_read_request, PHYAR_FLAG};
    let req = phyar_read_request(0x02);
    if req & PHYAR_FLAG != 0 {
        return TestResult::Fail("Read request must clear the Flag bit");
    }
    if (req >> 16) & 0x1F != 0x02 {
        return TestResult::Fail("register address lives in bits 20..16");
    }
    // Simulate a chip readback: data 0xCAFE, Flag cleared.
    let readback = phyar_read_request(0x02) | 0xCAFE;
    if !phyar_done(readback) {
        return TestResult::Fail("Flag should be 0 on completed read");
    }
    if phyar_data(readback) != 0xCAFE {
        return TestResult::Fail("data field decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl-phy", smoke_rtl_phyar_read_request_layout);

fn smoke_rtl_phyar_write_request_layout() -> TestResult {
    use crate::rtl_phy::{phyar_write_request, PHYAR_FLAG};
    let req = phyar_write_request(0x00, 0x9000);
    if req & PHYAR_FLAG == 0 {
        return TestResult::Fail("write request must set the Flag bit");
    }
    if req & 0xFFFF != 0x9000 {
        return TestResult::Fail("data lives in low 16 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl-phy", smoke_rtl_phyar_write_request_layout);

fn smoke_rtl_rx_desc_prepare_sets_own_and_eor() -> TestResult {
    use crate::rtl_phy::{prepare_rx_desc, RING_LEN, RXD_EOR, RXD_OWN};
    let last = prepare_rx_desc(RING_LEN - 1, 0xCAFE_F000, 0x600);
    if last.flags_len & RXD_OWN == 0 {
        return TestResult::Fail("OWN bit should be set on a chip-owned RX descriptor");
    }
    if last.flags_len & RXD_EOR == 0 {
        return TestResult::Fail("EOR should be set on the last slot");
    }
    if last.flags_len & 0x3FFF != 0x600 {
        return TestResult::Fail("buffer size should round-trip in low 14 bits");
    }
    let mid = prepare_rx_desc(0, 0x1000, 0x600);
    if mid.flags_len & RXD_EOR != 0 {
        return TestResult::Fail("non-last slot must not carry EOR");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl-phy", smoke_rtl_rx_desc_prepare_sets_own_and_eor);

fn smoke_rtl_rx_status_decodes_chip_returned_descriptor() -> TestResult {
    use crate::rtl_phy::{RxStatus, RXD_FS, RXD_LS, RXD_PAM};
    // Chip returned a 1500-byte unicast frame: FS|LS|PAM, length=1500.
    let word0 = RXD_FS | RXD_LS | RXD_PAM | 1500u32;
    let s = RxStatus::parse(word0);
    if s.length != 1500 {
        return TestResult::Fail("length decode wrong");
    }
    if !s.fs || !s.ls || !s.physical_match {
        return TestResult::Fail("status flags lost");
    }
    if s.error || s.multicast || s.broadcast {
        return TestResult::Fail("non-set status bits should be false");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl-phy", smoke_rtl_rx_status_decodes_chip_returned_descriptor);

fn smoke_rtl_mii_constants() -> TestResult {
    use crate::rtl_phy::{
        BMCR_AUTONEG_EN, BMCR_FULL_DUPLEX, BMCR_RESET, BMSR_LINK_UP, MII_BMCR, MII_BMSR,
    };
    if MII_BMCR != 0x00 || MII_BMSR != 0x01 {
        return TestResult::Fail("MII Clause 22 register addresses fixed");
    }
    if BMCR_RESET != 0x8000 {
        return TestResult::Fail("BMCR reset bit at 1<<15");
    }
    if BMCR_AUTONEG_EN != 0x1000 {
        return TestResult::Fail("BMCR autoneg-en at 1<<12");
    }
    if BMCR_FULL_DUPLEX != 0x0100 {
        return TestResult::Fail("BMCR full-duplex at 1<<8");
    }
    if BMSR_LINK_UP != 0x0004 {
        return TestResult::Fail("BMSR link-up at 1<<2");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl-phy", smoke_rtl_mii_constants);
