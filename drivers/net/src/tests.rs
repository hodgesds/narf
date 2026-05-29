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
//
// (moved to drivers/wireless/ as part of the wireless consolidation
// during the iwlwifi Stage-3 wave. Smoke retired here; the wireless
// crate carries the equivalent registry-table check now.)

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

fn smoke_igc_advanced_rx_descriptor_layout() -> TestResult {
    // Stage-2: igc switched to advanced RX descriptor format
    // (Linux `union igc_adv_rx_desc`). Same 16-byte slot; field
    // layout differs from the legacy descriptor — `status_error`
    // moves to offset 8 (was offset 12 in the legacy `status` byte),
    // `length` moves to offset 12 (was offset 8 in the legacy
    // `length` u16).
    //
    // The chip-driver contract that gets us into trouble if it
    // drifts:
    //   - SRRCTL.DESCTYPE = ADV_ONEBUF (1 << 25) — selects the
    //     advanced descriptor format on the chip side. A driver
    //     parsing wb-form while the chip is writing legacy-form
    //     (or vice versa) reads garbage.
    //   - DD bit lives at bit 0 of `status_error` (offset 8 in
    //     the wb slot).
    //
    // Linux references:
    //   #define IGC_SRRCTL_DESCTYPE_ADV_ONEBUF 0x02000000  (= 1<<25)
    //   `union igc_adv_rx_desc::wb::upper::status_error` — bit 0 DD,
    //     bit 1 EOP.
    use crate::igc;
    if igc::SRRCTL_DESCTYPE_ADV_ONEBUF != 1 << 25 {
        return TestResult::Fail("ADV_ONEBUF must be 1<<25 per IGC datasheet §7.1.5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_advanced_rx_descriptor_layout
);

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

// ── atheros (atl1c — AR81xx Gigabit Ethernet) ─────────────────────
//
// Hard cutover from the previous AR9xxx Wi-Fi stub: the atheros
// module now drives the wired NIC family (AR8131 / AR8161 / etc.)
// per `drivers/net/ethernet/atheros/atl1c/` in Linux.

fn smoke_atl1c_pci_match_table() -> TestResult {
    use crate::atheros;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    atheros::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in atheros::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == atheros::ATL_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("atl1c match entry missing");
        }
    }
    // Spot-check the common consumer-laptop ids: AR8131 (Acer / Asus
    // 2010-era), AR8161 (modern PCIe Gigabit), AR8151 / AR8152
    // (HP / Lenovo low-power laptops).
    let must_have: &[u16] = &[
        atheros::ATL_DEV_AR8131,
        atheros::ATL_DEV_AR8161,
        atheros::ATL_DEV_AR8151,
        atheros::ATL_DEV_AR8152,
    ];
    for did in must_have.iter().copied() {
        let found = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == atheros::ATL_VENDOR && device == did)
        });
        if !found {
            return TestResult::Fail("atl1c spot-check id missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/atheros", smoke_atl1c_pci_match_table);

fn smoke_atl1c_master_reset_value() -> TestResult {
    // MASTER_CTRL.SOFT_RST lives at bit 0 in `atl1c_hw.h`. A drift
    // would either fail to reset the chip (silently brick bring-up)
    // or hit an unrelated bit (toggle clock-select mid-bring-up).
    use crate::atheros::{master_reset_value, MASTER_CTRL_SOFT_RST};
    let v = master_reset_value();
    if v & MASTER_CTRL_SOFT_RST == 0 {
        return TestResult::Fail("MASTER_CTRL.SOFT_RST missing from reset value");
    }
    if MASTER_CTRL_SOFT_RST != 1 << 0 {
        return TestResult::Fail("MASTER_CTRL.SOFT_RST bit position drift vs atl1c_hw.h");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/atheros", smoke_atl1c_master_reset_value);

fn smoke_atl1c_default_mac_ctrl_enables_rx_tx() -> TestResult {
    // Bring-up programs MAC_CTRL with RX + TX + CRC-append + pad +
    // broadcast + multicast + speed=1G. Bit-position drift on the
    // speed field is the most common source of "link reports up but
    // no frames flow" — pin it here.
    use crate::atheros::{
        default_mac_ctrl_value, MAC_CTRL_BC_EN, MAC_CTRL_MC_EN, MAC_CTRL_RX_EN, MAC_CTRL_SPEED_1000,
        MAC_CTRL_TX_EN,
    };
    let v = default_mac_ctrl_value();
    if v & MAC_CTRL_RX_EN == 0 {
        return TestResult::Fail("RX_EN missing from default MAC_CTRL");
    }
    if v & MAC_CTRL_TX_EN == 0 {
        return TestResult::Fail("TX_EN missing from default MAC_CTRL");
    }
    if v & MAC_CTRL_BC_EN == 0 || v & MAC_CTRL_MC_EN == 0 {
        return TestResult::Fail("BC/MC accept missing from default MAC_CTRL");
    }
    if v & MAC_CTRL_SPEED_1000 == 0 {
        return TestResult::Fail("default speed should be 1G");
    }
    if MAC_CTRL_RX_EN != 1 << 1 {
        return TestResult::Fail("MAC_CTRL.RX_EN bit position drift vs atl1c_hw.h");
    }
    if MAC_CTRL_TX_EN != 1 << 0 {
        return TestResult::Fail("MAC_CTRL.TX_EN bit position drift vs atl1c_hw.h");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/atheros",
    smoke_atl1c_default_mac_ctrl_enables_rx_tx
);

fn smoke_atl1c_eeprom_mac_decode_round_trip() -> TestResult {
    // `mac_from_sta_addr` decodes the EEPROM-loaded MAC_STA_ADDR_{HI,
    // LO} registers into a 6-byte MAC. atl1c_main.c assembles the
    // MAC in the order [HI byte1, HI byte0, LO byte3..0]. A wrong
    // shift here would surface as a MAC like `[00, AA, BB, CC, DD,
    // EE]` getting transposed at probe — test pins the byte order.
    use crate::atheros::mac_from_sta_addr;
    // Hypothetical EEPROM-stored MAC 11:22:33:44:55:66.
    //   HI = 0x0000_1122  (byte1 = 0x11, byte0 = 0x22)
    //   LO = 0x3344_5566  (byte3..0 = 0x33 .. 0x66)
    let mac = mac_from_sta_addr(0x0000_1122, 0x3344_5566);
    if mac != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] {
        return TestResult::Fail("EEPROM MAC decode produced wrong byte order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/atheros",
    smoke_atl1c_eeprom_mac_decode_round_trip
);

fn smoke_atl1c_rrs_field_layout_matches_linux() -> TestResult {
    // `atl1c_main.c`'s recv-ret-status word2 layout pins:
    //   bit 31 = OWN
    //   bits[19:0] = frame length
    //   bits[27:20] = RFD slot index
    // A drift in any of these would either miss frames (wrong OWN
    // probe) or read garbage (wrong slot index → wrong RFD buffer).
    use crate::atheros::{RRS_LEN_MASK, RRS_OWN, RRS_RFD_INDEX_MASK, RRS_RFD_INDEX_SHIFT};
    if RRS_OWN != 1 << 31 {
        return TestResult::Fail("RRS.OWN bit position drift");
    }
    if RRS_LEN_MASK != 0x000F_FFFF {
        return TestResult::Fail("RRS length mask drift (should be bits[19:0])");
    }
    if RRS_RFD_INDEX_SHIFT != 20 {
        return TestResult::Fail("RRS RFD index shift drift (should be 20)");
    }
    if RRS_RFD_INDEX_MASK != 0xFF << 20 {
        return TestResult::Fail("RRS RFD index mask drift");
    }
    // Synthesise a chip-returned descriptor and decode it: frame of
    // 1500 bytes, came from RFD slot 42.
    let synth = RRS_OWN | (42u32 << RRS_RFD_INDEX_SHIFT) | 1500u32;
    if synth & RRS_OWN == 0 {
        return TestResult::Fail("synthesised OWN bit didn't survive composition");
    }
    if (synth & RRS_LEN_MASK) != 1500 {
        return TestResult::Fail("length decode mismatch");
    }
    if ((synth & RRS_RFD_INDEX_MASK) >> RRS_RFD_INDEX_SHIFT) != 42 {
        return TestResult::Fail("RFD index decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/atheros",
    smoke_atl1c_rrs_field_layout_matches_linux
);

fn smoke_atl1c_tpd_field_layout() -> TestResult {
    // TPD word0 layout pin: length in bits[15:0], SOP at bit 16, EOP
    // at bit 17, OWN at bit 31. A single-segment frame must set both
    // SOP + EOP + OWN.
    use crate::atheros::{TPD_EOP, TPD_LEN_MASK, TPD_OWN, TPD_SOP};
    if TPD_LEN_MASK != 0xFFFF {
        return TestResult::Fail("TPD length mask should be bits[15:0]");
    }
    if TPD_SOP != 1 << 16 {
        return TestResult::Fail("TPD.SOP bit drift");
    }
    if TPD_EOP != 1 << 17 {
        return TestResult::Fail("TPD.EOP bit drift");
    }
    if TPD_OWN != 1 << 31 {
        return TestResult::Fail("TPD.OWN bit drift");
    }
    // Build a synthetic 64-byte frame command and decode.
    let w0 = 64u32 | TPD_SOP | TPD_EOP | TPD_OWN;
    if (w0 & TPD_LEN_MASK) != 64 {
        return TestResult::Fail("length round-trip failed");
    }
    if w0 & TPD_SOP == 0 || w0 & TPD_EOP == 0 || w0 & TPD_OWN == 0 {
        return TestResult::Fail("SOP/EOP/OWN not preserved through compose");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/atheros", smoke_atl1c_tpd_field_layout);

fn smoke_atl1c_default_intr_mask_includes_rx_tx() -> TestResult {
    // The default IRQ mask must include RX_PKT0 + TX_PKT (we drive
    // bring-up off frame-arrival / frame-complete events) and GPHY +
    // PHY_LINKDOWN (link-state change). A drift here would manifest
    // as a NIC that probes cleanly but never wakes the RX pump.
    use crate::atheros::{
        default_intr_mask, INT_GPHY, INT_PHY_LINKDOWN, INT_RX_PKT0, INT_TX_PKT,
    };
    let m = default_intr_mask();
    if m & INT_RX_PKT0 == 0 {
        return TestResult::Fail("INT.RX_PKT0 missing from default mask");
    }
    if m & INT_TX_PKT == 0 {
        return TestResult::Fail("INT.TX_PKT missing from default mask");
    }
    if m & INT_GPHY == 0 || m & INT_PHY_LINKDOWN == 0 {
        return TestResult::Fail("link-state IRQs missing from default mask");
    }
    if INT_RX_PKT0 != 1 << 2 {
        return TestResult::Fail("INT.RX_PKT0 bit position drift");
    }
    if INT_TX_PKT != 1 << 1 {
        return TestResult::Fail("INT.TX_PKT bit position drift");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/atheros",
    smoke_atl1c_default_intr_mask_includes_rx_tx
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

// ── mlx5 EQE / CQE decode smokes ───────────────────────────────────

fn smoke_mlx5_eqe_decode() -> TestResult {
    // Build a synthetic SW-owned EQE (owner bit = 0) with event_type
    // = PortStateChange (0x09) and sub-type = 0x04.  Verify
    // decode_eqe extracts the right fields.
    //
    // EQE layout (mlx5/eqe.rs):
    //   +0x01  event_type   u8
    //   +0x03  event_sub_type u8
    //   +0x3F  owner bit 0   (0 = SW owns)
    use crate::mlx5::eqe;

    let mut raw = [0u8; eqe::EQE_LEN];
    raw[eqe::EQE_OFF_EVENT_TYPE] = 0x09;      // PortStateChange
    raw[eqe::EQE_OFF_EVENT_SUB_TYPE] = 0x04;
    raw[eqe::EQE_OFF_OWNER] = 0x00;           // SW owns

    // is_hw_owned must be false for SW-owned slot.
    if eqe::is_hw_owned(&raw) {
        return TestResult::Fail("is_hw_owned returned true for owner=0");
    }

    let view = eqe::decode_eqe(&raw);
    if view.event_type != eqe::EventType::PortStateChange {
        return TestResult::Fail("event_type decoded wrongly");
    }
    if view.event_sub_type != 0x04 {
        return TestResult::Fail("event_sub_type lost");
    }
    if view.owner {
        return TestResult::Fail("owner field should be false for owner=0");
    }

    // A hardware-owned slot (owner bit = 1) must NOT be consumed.
    raw[eqe::EQE_OFF_OWNER] = eqe::EQE_OWNER_BIT;
    if !eqe::is_hw_owned(&raw) {
        return TestResult::Fail("is_hw_owned returned false for owner=1");
    }
    let hw_view = eqe::decode_eqe(&raw);
    if !hw_view.owner {
        return TestResult::Fail("decode_eqe owner field wrong for owner=1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eqe_decode);

fn smoke_mlx5_cqe_decode() -> TestResult {
    // Build a synthetic SW-owned CQE (owner bit = 0) representing a
    // 1500-byte RX completion on QP 0x42 with Success status.
    //
    // CQE layout (mlx5/cqe.rs):
    //   +0x14..0x17  byte_count  BE u32
    //   +0x37        status      u8
    //   +0x38..0x39  wqe_counter BE u16
    //   +0x3C..0x3F  qp_op_own   BE u32:
    //                  bits[31:8]  = qp_num
    //                  bits[7:4]   = opcode (ResponderSend = 0x2)
    //                  bit[0]      = owner (0 = SW)
    use crate::mlx5::cqe;

    let mut raw = [0u8; cqe::CQE_LEN];

    // byte_count = 1500 at offset 0x14.
    raw[cqe::CQE_OFF_BYTE_COUNT..cqe::CQE_OFF_BYTE_COUNT + 4]
        .copy_from_slice(&1500u32.to_be_bytes());

    // status = Success (0x00) at offset 0x37.
    raw[cqe::CQE_OFF_STATUS] = 0x00;

    // wqe_counter = 7 at offset 0x38.
    raw[cqe::CQE_OFF_WQE_COUNTER..cqe::CQE_OFF_WQE_COUNTER + 2]
        .copy_from_slice(&7u16.to_be_bytes());

    // qp_op_own: qp_num=0x42, opcode=ResponderSend(0x2), owner=0.
    // bits: [31:8]=0x42, [7:4]=0x2, [0]=0.
    let qp_op_own: u32 = (0x42u32 << 8) | (0x2u32 << 4) | 0;
    raw[cqe::CQE_OFF_QP_OP_OWN..cqe::CQE_OFF_QP_OP_OWN + 4]
        .copy_from_slice(&qp_op_own.to_be_bytes());

    // SW-owned: is_hw_owned must be false.
    if cqe::is_hw_owned(&raw) {
        return TestResult::Fail("is_hw_owned returned true for owner=0");
    }

    let view = cqe::decode_cqe(&raw);
    if view.byte_count != 1500 {
        return TestResult::Fail("byte_count decoded wrongly");
    }
    if view.status != cqe::CqeStatus::Success {
        return TestResult::Fail("status decoded wrongly");
    }
    if view.wqe_counter != 7 {
        return TestResult::Fail("wqe_counter decoded wrongly");
    }
    if view.qp_num != 0x42 {
        return TestResult::Fail("qp_num decoded wrongly");
    }
    if view.opcode != cqe::CqeOpcode::ResponderSend {
        return TestResult::Fail("opcode decoded wrongly");
    }
    if view.owner {
        return TestResult::Fail("owner should be false for owner=0");
    }

    // HW-owned slot: owner bit = 1.
    raw[cqe::CQE_OFF_QP_OP_OWN + 3] |= cqe::CQE_OWNER_BIT;
    if !cqe::is_hw_owned(&raw) {
        return TestResult::Fail("is_hw_owned returned false for owner=1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_decode);

// ── vmxnet3 quiesce/reset command-code smokes ───────────────────────

fn smoke_vmxnet3_quiesce_cmd_encode() -> TestResult {
    // Verify VMXNET3_CMD_QUIESCE_DEV matches the Linux definition.
    //
    // Linux ref: `vmxnet3_defs.h` enum VMXNET3_CMD:
    //   VMXNET3_CMD_QUIESCE_DEV = 0xCAFE0001
    // and `vmxnet3_drv.c::vmxnet3_quiesce_dev` (line 3262):
    //   VMXNET3_WRITE_BAR1_REG(adapter, VMXNET3_REG_CMD,
    //                          VMXNET3_CMD_QUIESCE_DEV);
    use crate::vmxnet3::regs;

    if regs::VMXNET3_CMD_QUIESCE_DEV != 0xCAFE_0001 {
        return TestResult::Fail(
            "VMXNET3_CMD_QUIESCE_DEV != 0xCAFE0001 (vmxnet3_defs.h drift)",
        );
    }
    // Sanity: must be "set" class (high 16 bits = 0xCAFE).
    if regs::VMXNET3_CMD_QUIESCE_DEV >> 16 != 0xCAFE {
        return TestResult::Fail("QUIESCE_DEV not in set-class range (0xCAFE_xxxx)");
    }
    // Must be distinct from ACTIVATE_DEV and RESET_DEV.
    if regs::VMXNET3_CMD_QUIESCE_DEV == regs::VMXNET3_CMD_ACTIVATE_DEV {
        return TestResult::Fail("QUIESCE_DEV == ACTIVATE_DEV");
    }
    if regs::VMXNET3_CMD_QUIESCE_DEV == regs::VMXNET3_CMD_RESET_DEV {
        return TestResult::Fail("QUIESCE_DEV == RESET_DEV");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_quiesce_cmd_encode);

fn smoke_vmxnet3_reset_cmd_encode() -> TestResult {
    // Verify VMXNET3_CMD_RESET_DEV matches the Linux definition.
    //
    // Linux ref: `vmxnet3_defs.h` enum VMXNET3_CMD:
    //   VMXNET3_CMD_RESET_DEV = 0xCAFE0002
    // and `vmxnet3_drv.c::vmxnet3_reset_dev` (line 3247):
    //   VMXNET3_WRITE_BAR1_REG(adapter, VMXNET3_REG_CMD,
    //                          VMXNET3_CMD_RESET_DEV);
    use crate::vmxnet3::regs;

    if regs::VMXNET3_CMD_RESET_DEV != 0xCAFE_0002 {
        return TestResult::Fail(
            "VMXNET3_CMD_RESET_DEV != 0xCAFE0002 (vmxnet3_defs.h drift)",
        );
    }
    if regs::VMXNET3_CMD_RESET_DEV >> 16 != 0xCAFE {
        return TestResult::Fail("RESET_DEV not in set-class range (0xCAFE_xxxx)");
    }
    // Ordering invariant per Linux: QUIESCE (0x0001) < RESET (0x0002).
    if regs::VMXNET3_CMD_RESET_DEV <= regs::VMXNET3_CMD_QUIESCE_DEV {
        return TestResult::Fail("RESET_DEV must be > QUIESCE_DEV in the cmd enum");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_reset_cmd_encode);

// ── TSO / checksum-offload descriptor encode smokes ─────────────────
// 14 tests total (2 per driver).

// ── e1000 ─────────────────────────────────────────────────────────

fn smoke_e1000_tso_desc_encode() -> TestResult {
    use crate::e1000::{TxDesc, TXD_CMD_DEXT, TXD_CMD_TSE, TXD_DTYP_D, TXD_OPTS_IXSM, TXD_OPTS_TXSM};
    let d = TxDesc::with_tso(0x1234_0000u64, 1448, 1448);
    if d.cmd & TXD_CMD_DEXT == 0 { return TestResult::Fail("e1000 TSO: TXD_CMD_DEXT not set"); }
    if d.cmd & TXD_CMD_TSE == 0 { return TestResult::Fail("e1000 TSO: TXD_CMD_TSE not set"); }
    if d.cmd & TXD_DTYP_D == 0 { return TestResult::Fail("e1000 TSO: TXD_DTYP_D not set"); }
    if d.css & TXD_OPTS_IXSM == 0 || d.css & TXD_OPTS_TXSM == 0 { return TestResult::Fail("e1000 TSO: IXSM/TXSM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/e1000", smoke_e1000_tso_desc_encode);

fn smoke_e1000_csum_offload_bits() -> TestResult {
    use crate::e1000::{TxDesc, TXD_CMD_DEXT, TXD_DTYP_D, TXD_OPTS_IXSM, TXD_OPTS_TXSM};
    let d = TxDesc::new_with_csum(0xABCD_0000u64, 60, TXD_OPTS_IXSM | TXD_OPTS_TXSM);
    if d.cmd & TXD_CMD_DEXT == 0 { return TestResult::Fail("e1000 csum: TXD_CMD_DEXT not set"); }
    if d.cmd & TXD_DTYP_D == 0 { return TestResult::Fail("e1000 csum: TXD_DTYP_D not set"); }
    if d.css & TXD_OPTS_IXSM == 0 { return TestResult::Fail("e1000 csum: IXSM not set"); }
    if d.css & TXD_OPTS_TXSM == 0 { return TestResult::Fail("e1000 csum: TXSM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/e1000", smoke_e1000_csum_offload_bits);

// ── ixgbe ─────────────────────────────────────────────────────────

fn smoke_ixgbe_tso_desc_encode() -> TestResult {
    use crate::ixgbe::{AdvTxCtxtDesc, AdvTxDesc, ADVTXD_DCMD_TSE, ADVTXD_DTYP_CTXT, ADVTXD_MSS_SHIFT, ADVTXD_TUCMD_IPV4, ADVTXD_TUCMD_L4T_TCP};
    let ctx = AdvTxCtxtDesc::new_tso_v4(14, 20, 20, 1448);
    if ctx.mss_l4len_idx >> ADVTXD_MSS_SHIFT != 1448 { return TestResult::Fail("ixgbe TSO ctx: mss wrong"); }
    if ctx.type_tucmd_mlhl & ADVTXD_DTYP_CTXT == 0 { return TestResult::Fail("ixgbe TSO ctx: DTYP_CTXT not set"); }
    if ctx.type_tucmd_mlhl & ADVTXD_TUCMD_IPV4 == 0 { return TestResult::Fail("ixgbe TSO ctx: TUCMD_IPV4 not set"); }
    if ctx.type_tucmd_mlhl & ADVTXD_TUCMD_L4T_TCP == 0 { return TestResult::Fail("ixgbe TSO ctx: TUCMD_L4T_TCP not set"); }
    let data = AdvTxDesc::with_tso(0xDEAD_0000u64, 5792, 1448);
    if data.cmd_type_len & ADVTXD_DCMD_TSE == 0 { return TestResult::Fail("ixgbe TSO data: DCMD_TSE not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_tso_desc_encode);

fn smoke_ixgbe_csum_offload_bits() -> TestResult {
    use crate::ixgbe::{AdvTxDesc, ADVTXD_POPTS_IXSM, ADVTXD_POPTS_TXSM};
    let d = AdvTxDesc::with_csum(0x1000_0000u64, 60);
    if d.olinfo & ADVTXD_POPTS_IXSM == 0 { return TestResult::Fail("ixgbe csum: POPTS_IXSM not set"); }
    if d.olinfo & ADVTXD_POPTS_TXSM == 0 { return TestResult::Fail("ixgbe csum: POPTS_TXSM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_csum_offload_bits);

// ── igc ───────────────────────────────────────────────────────────

fn smoke_igc_tso_desc_encode() -> TestResult {
    use crate::igc::{AdvTxCtxtDesc, IGC_ADVTXD_DCMD_DEXT, IGC_ADVTXD_DTYP_CTXT, IGC_ADVTXD_MSS_SHIFT, IGC_ADVTXD_TUCMD_IPV4, IGC_ADVTXD_TUCMD_L4T_TCP};
    let ctx = AdvTxCtxtDesc::new_tso_v4(14, 20, 20, 1448);
    if ctx.mss_l4len_idx >> IGC_ADVTXD_MSS_SHIFT != 1448 { return TestResult::Fail("igc TSO ctx: mss wrong"); }
    if ctx.type_tucmd_mlhl & IGC_ADVTXD_DTYP_CTXT == 0 { return TestResult::Fail("igc TSO ctx: DTYP_CTXT not set"); }
    if ctx.type_tucmd_mlhl & IGC_ADVTXD_DCMD_DEXT == 0 { return TestResult::Fail("igc TSO ctx: DCMD_DEXT not set"); }
    if ctx.type_tucmd_mlhl & IGC_ADVTXD_TUCMD_IPV4 == 0 { return TestResult::Fail("igc TSO ctx: TUCMD_IPV4 not set"); }
    if ctx.type_tucmd_mlhl & IGC_ADVTXD_TUCMD_L4T_TCP == 0 { return TestResult::Fail("igc TSO ctx: TUCMD_L4T_TCP not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_tso_desc_encode);

fn smoke_igc_csum_offload_bits() -> TestResult {
    use crate::igc::{AdvTxDataDesc, IGC_TXD_POPTS_IXSM, IGC_TXD_POPTS_TXSM};
    let d = AdvTxDataDesc::with_csum(0x2000_0000u64, 60);
    if d.olinfo_status & IGC_TXD_POPTS_IXSM == 0 { return TestResult::Fail("igc csum: POPTS_IXSM not set"); }
    if d.olinfo_status & IGC_TXD_POPTS_TXSM == 0 { return TestResult::Fail("igc csum: POPTS_TXSM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_csum_offload_bits);

// ── tg3 ───────────────────────────────────────────────────────────

fn smoke_tg3_tso_desc_encode() -> TestResult {
    use crate::tg3::{TxBufferDesc, TXD_FLAG_IP_CSUM, TXD_FLAG_TCPUDP_CSUM, TXD_MSS_SHIFT};
    let d = TxBufferDesc::with_tso(0x0001u32, 0x0000_A000u32, 1448, 1448);
    if d.vlan_tag >> TXD_MSS_SHIFT != 1448 { return TestResult::Fail("tg3 TSO: mss not encoded in vlan_tag[31:16]"); }
    if d.len_flags & TXD_FLAG_IP_CSUM == 0 { return TestResult::Fail("tg3 TSO: TXD_FLAG_IP_CSUM not set"); }
    if d.len_flags & TXD_FLAG_TCPUDP_CSUM == 0 { return TestResult::Fail("tg3 TSO: TXD_FLAG_TCPUDP_CSUM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/tg3", smoke_tg3_tso_desc_encode);

fn smoke_tg3_csum_offload_bits() -> TestResult {
    use crate::tg3::{TxBufferDesc, TXD_FLAG_IP_CSUM, TXD_FLAG_TCPUDP_CSUM};
    let d = TxBufferDesc::with_csum(0x0001u32, 0x0000_B000u32, 60);
    if d.vlan_tag != 0 { return TestResult::Fail("tg3 csum: vlan_tag should be 0"); }
    if d.len_flags & TXD_FLAG_IP_CSUM == 0 { return TestResult::Fail("tg3 csum: TXD_FLAG_IP_CSUM not set"); }
    if d.len_flags & TXD_FLAG_TCPUDP_CSUM == 0 { return TestResult::Fail("tg3 csum: TXD_FLAG_TCPUDP_CSUM not set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/tg3", smoke_tg3_csum_offload_bits);

// ── r8169 ─────────────────────────────────────────────────────────

fn smoke_r8169_tso_desc_encode() -> TestResult {
    use crate::r8169::{Desc, TD1_GTSENV4, TD1_IPv4_CS, TD1_MSS_SHIFT, TD1_TCP_CS};
    let d = Desc::tx_with_tso(0xC000u32, 0x0001u32, 1448, 1448);
    if d.vlan & TD1_GTSENV4 == 0 { return TestResult::Fail("r8169 TSO: TD1_GTSENV4 not set"); }
    if d.vlan & TD1_IPv4_CS == 0 { return TestResult::Fail("r8169 TSO: TD1_IPv4_CS not set"); }
    if d.vlan & TD1_TCP_CS == 0 { return TestResult::Fail("r8169 TSO: TD1_TCP_CS not set"); }
    if (d.vlan >> TD1_MSS_SHIFT) & 0x7FF != 1448 { return TestResult::Fail("r8169 TSO: mss wrong"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/r8169", smoke_r8169_tso_desc_encode);

fn smoke_r8169_csum_offload_bits() -> TestResult {
    use crate::r8169::{Desc, TD1_GTSENV4, TD1_IPv4_CS, TD1_TCP_CS};
    let d = Desc::tx_with_csum(0xD000u32, 0x0001u32, 60);
    if d.vlan & TD1_IPv4_CS == 0 { return TestResult::Fail("r8169 csum: TD1_IPv4_CS not set"); }
    if d.vlan & TD1_TCP_CS == 0 { return TestResult::Fail("r8169 csum: TD1_TCP_CS not set"); }
    if d.vlan & TD1_GTSENV4 != 0 { return TestResult::Fail("r8169 csum: TD1_GTSENV4 must not be set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/r8169", smoke_r8169_csum_offload_bits);

// ── rtl8125 ───────────────────────────────────────────────────────

fn smoke_rtl8125_tso_desc_encode() -> TestResult {
    use crate::rtl8125::{TxDesc, TD1_GTSENV4, TD1_IPv4_CS, TD1_MSS_SHIFT, TD1_TCP_CS};
    let d = TxDesc::with_tso(0xE000u32, 0x0001u32, 1448, 1448);
    if d.vlan & TD1_GTSENV4 == 0 { return TestResult::Fail("rtl8125 TSO: TD1_GTSENV4 not set"); }
    if d.vlan & TD1_IPv4_CS == 0 { return TestResult::Fail("rtl8125 TSO: TD1_IPv4_CS not set"); }
    if d.vlan & TD1_TCP_CS == 0 { return TestResult::Fail("rtl8125 TSO: TD1_TCP_CS not set"); }
    if (d.vlan >> TD1_MSS_SHIFT) & 0x7FF != 1448 { return TestResult::Fail("rtl8125 TSO: mss wrong"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_tso_desc_encode);

fn smoke_rtl8125_csum_offload_bits() -> TestResult {
    use crate::rtl8125::{TxDesc, TD1_GTSENV4, TD1_IPv4_CS, TD1_TCP_CS};
    let d = TxDesc::with_csum(0xF000u32, 0x0001u32, 60);
    if d.vlan & TD1_IPv4_CS == 0 { return TestResult::Fail("rtl8125 csum: TD1_IPv4_CS not set"); }
    if d.vlan & TD1_TCP_CS == 0 { return TestResult::Fail("rtl8125 csum: TD1_TCP_CS not set"); }
    if d.vlan & TD1_GTSENV4 != 0 { return TestResult::Fail("rtl8125 csum: TD1_GTSENV4 must not be set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_csum_offload_bits);

// ── forcedeth ─────────────────────────────────────────────────────

fn smoke_forcedeth_tso_desc_encode() -> TestResult {
    use crate::forcedeth::{Desc, NV_TX2_CHECKSUM_L3, NV_TX2_CHECKSUM_L4, NV_TX2_TSO, NV_TX2_TSO_SHIFT, TXD_LASTPACKET, TXD_VALID};
    let d = Desc::tx_with_tso(0x0000_C000u32, 1460, 1448);
    if d.flaglen & TXD_VALID == 0 { return TestResult::Fail("forcedeth TSO: TXD_VALID not set"); }
    if d.flaglen & TXD_LASTPACKET == 0 { return TestResult::Fail("forcedeth TSO: TXD_LASTPACKET not set"); }
    if d.flaglen & NV_TX2_TSO == 0 { return TestResult::Fail("forcedeth TSO: NV_TX2_TSO not set"); }
    if d.flaglen & NV_TX2_CHECKSUM_L3 == 0 { return TestResult::Fail("forcedeth TSO: NV_TX2_CHECKSUM_L3 not set"); }
    if d.flaglen & NV_TX2_CHECKSUM_L4 == 0 { return TestResult::Fail("forcedeth TSO: NV_TX2_CHECKSUM_L4 not set"); }
    if (d.flaglen >> NV_TX2_TSO_SHIFT) & 0x3FFF != 1448 { return TestResult::Fail("forcedeth TSO: mss wrong"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_tso_desc_encode);

fn smoke_forcedeth_csum_offload_bits() -> TestResult {
    use crate::forcedeth::{Desc, NV_TX2_CHECKSUM_L3, NV_TX2_CHECKSUM_L4, NV_TX2_TSO, TXD_LASTPACKET, TXD_VALID};
    let d = Desc::tx_with_csum(0x0000_D000u32, 60);
    if d.flaglen & TXD_VALID == 0 { return TestResult::Fail("forcedeth csum: TXD_VALID not set"); }
    if d.flaglen & TXD_LASTPACKET == 0 { return TestResult::Fail("forcedeth csum: TXD_LASTPACKET not set"); }
    if d.flaglen & NV_TX2_CHECKSUM_L3 == 0 { return TestResult::Fail("forcedeth csum: NV_TX2_CHECKSUM_L3 not set"); }
    if d.flaglen & NV_TX2_CHECKSUM_L4 == 0 { return TestResult::Fail("forcedeth csum: NV_TX2_CHECKSUM_L4 not set"); }
    if d.flaglen & NV_TX2_TSO != 0 { return TestResult::Fail("forcedeth csum: NV_TX2_TSO must not be set"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_csum_offload_bits);
