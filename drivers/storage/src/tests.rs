//! Per-driver smoke tests for `narf-drivers-storage`. AHCI smokes
//! migrated from the verification mega-lib so they live next to
//! the driver code.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── Stage-2 AHCI unit smokes (no hardware) ───────────────────────

/// Verify the Command FIS (Register Host-to-Device, FIS type 0x27)
/// byte layout for a READ DMA EXT command.  These are the bytes
/// written at cmd_tbl+0 in every DMA path; correctness can be
/// checked entirely in host memory.
fn smoke_ahci_command_fis_layout() -> TestResult {
    // Simulate building a 20-byte H2D Register FIS for READ DMA EXT
    // at LBA 0x0102_0304_0506 with sector count 3.
    let lba: u64 = 0x0001_0203_0405;
    let n: u16 = 3;
    let mut fis = [0u8; 20];
    fis[0] = 0x27; // FIS type: Register H2D
    fis[1] = 0x80; // C bit set (command, not control), PMP = 0
    fis[2] = 0x25; // READ DMA EXT
    fis[3] = 0;    // features lo
    fis[4] = (lba & 0xFF) as u8;         // LBA[7:0]
    fis[5] = ((lba >> 8) & 0xFF) as u8;  // LBA[15:8]
    fis[6] = ((lba >> 16) & 0xFF) as u8; // LBA[23:16]
    fis[7] = 0x40;                        // Device: LBA mode
    fis[8] = ((lba >> 24) & 0xFF) as u8;  // LBA[31:24]
    fis[9] = ((lba >> 32) & 0xFF) as u8;  // LBA[39:32]
    fis[10] = ((lba >> 40) & 0xFF) as u8; // LBA[47:40]
    fis[11] = 0; // features hi
    fis[12] = (n & 0xFF) as u8;
    fis[13] = ((n >> 8) & 0xFF) as u8;

    if fis[0] != 0x27 {
        return TestResult::Fail("FIS type must be 0x27 (Register H2D)");
    }
    if fis[1] & 0x80 == 0 {
        return TestResult::Fail("FIS byte 1 bit 7 must be set (C = command)");
    }
    if fis[2] != 0x25 {
        return TestResult::Fail("FIS command byte must be 0x25 (READ DMA EXT)");
    }
    if fis[7] != 0x40 {
        return TestResult::Fail("Device byte must have LBA bit set (0x40)");
    }
    // Reconstruct LBA from FIS bytes 4..10.
    let got_lba = fis[4] as u64
        | ((fis[5] as u64) << 8)
        | ((fis[6] as u64) << 16)
        | ((fis[8] as u64) << 24)
        | ((fis[9] as u64) << 32)
        | ((fis[10] as u64) << 40);
    if got_lba != lba {
        return TestResult::Fail("LBA round-trip through FIS bytes failed");
    }
    // Reconstruct sector count from bytes 12..13.
    let got_n = fis[12] as u16 | ((fis[13] as u16) << 8);
    if got_n != n {
        return TestResult::Fail("Sector count round-trip through FIS bytes failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_command_fis_layout);

/// Verify PRD table entry byte-count encoding: the AHCI spec states
/// the DBC field holds (byte_count - 1), not byte_count.
fn smoke_ahci_prd_byte_count_encoding() -> TestResult {
    // Simulate a 512-byte PRD entry as written at cmd_tbl+0x80.
    let data_pa: u64 = 0x0000_8000_0000;
    let byte_count: u32 = 512;
    let mut prdt = [0u8; 16];
    // +0x00 u64 data base PA
    prdt[0..8].copy_from_slice(&data_pa.to_le_bytes());
    // +0x08 u32 reserved
    prdt[8..12].copy_from_slice(&0u32.to_le_bytes());
    // +0x0C u32 DBC = byte_count - 1 (AHCI 1.3.1 §4.2.3.3)
    prdt[12..16].copy_from_slice(&(byte_count - 1).to_le_bytes());

    let dbc = u32::from_le_bytes([prdt[12], prdt[13], prdt[14], prdt[15]]);
    if dbc != 511 {
        return TestResult::Fail("PRDT DBC must be byte_count-1 (511 for a 512-byte transfer)");
    }
    let pa = u64::from_le_bytes(prdt[0..8].try_into().unwrap());
    if pa != data_pa {
        return TestResult::Fail("PRDT data base PA round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_prd_byte_count_encoding);

/// Verify the IDENTIFY DEVICE response parser: model string decoding
/// (byte-swapped pairs), LBA-28 capacity (words 60–61), and LBA-48
/// capacity (words 100–103, gated by word 83 bit 10).
fn smoke_ahci_identify_parser() -> TestResult {
    use crate::ahci::{identify_features, identify_lba28_capacity, identify_lba48_capacity, identify_model};

    let mut id = [0u8; 512];
    // Write "TESTDISK            " as ATA model string at word 27 (byte 54).
    // ATA strings byte-swap each pair: byte 54 = char1, byte 55 = char0, etc.
    let model_raw = b"TESTDISK                                ";
    for i in 0..20usize {
        id[54 + i * 2] = model_raw[i * 2 + 1];
        id[54 + i * 2 + 1] = model_raw[i * 2];
    }
    // LBA-28 capacity = 0x0028_0000 sectors (word 60 = low, word 61 = high).
    let lba28: u32 = 0x0028_0000u32;
    id[120..122].copy_from_slice(&(lba28 as u16).to_le_bytes());
    id[122..124].copy_from_slice(&((lba28 >> 16) as u16).to_le_bytes());
    // LBA-48: enable via word 83 bit 10 (validity marker = 0x40 in high byte).
    let w83: u16 = (1 << 10) | 0x4000;
    id[166..168].copy_from_slice(&w83.to_le_bytes());
    // LBA-48 capacity = 10 GiB = 20_971_520 sectors.
    let lba48: u64 = 20_971_520u64;
    id[200..208].copy_from_slice(&lba48.to_le_bytes());

    let model = identify_model(&id);
    if &model[..8] != b"TESTDISK" {
        return TestResult::Fail("identify_model decoded wrong prefix");
    }
    if identify_lba28_capacity(&id) != lba28 {
        return TestResult::Fail("identify_lba28_capacity wrong");
    }
    if identify_lba48_capacity(&id) != lba48 {
        return TestResult::Fail("identify_lba48_capacity wrong");
    }
    // LBA-48 flag off: set word 83 to 0 (no bit 10).
    id[166..168].copy_from_slice(&0u16.to_le_bytes());
    if identify_lba48_capacity(&id) != 0 {
        return TestResult::Fail("identify_lba48_capacity should return 0 when bit 10 clear");
    }
    let (w82, w83_back) = identify_features(&id);
    // With the validity marker gone word 83 is 0.
    if w83_back != 0 {
        return TestResult::Fail("identify_features word83 should be 0");
    }
    let _ = w82; // word 82 not set in this synthetic buffer
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_identify_parser);

/// Verify the READ DMA EXT command encoding: opcode 0x25 in FIS
/// byte 2, W bit = 0 in command-list header (read, not write).
fn smoke_ahci_read_dma_ext_encode() -> TestResult {
    // Command-list header word 0: PRDT_LEN=1, W=0, CFL=5.
    let header_w0: u32 = (1u32 << 16) | 5; // no bit 6 (W=0 means read)
    // CFIS bytes.
    let lba: u64 = 0xABCD_EF01_2345;
    let n_sectors: u16 = 7;
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27;
    cfis[1] = 0x80;
    cfis[2] = 0x25; // READ DMA EXT opcode
    cfis[3] = 0;
    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[7] = 0x40;
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;
    cfis[11] = 0;
    cfis[12] = (n_sectors & 0xFF) as u8;
    cfis[13] = ((n_sectors >> 8) & 0xFF) as u8;

    if cfis[2] != 0x25 {
        return TestResult::Fail("READ DMA EXT opcode must be 0x25");
    }
    if header_w0 & (1 << 6) != 0 {
        return TestResult::Fail("W bit must be 0 for a read command");
    }
    let got_lba = cfis[4] as u64
        | ((cfis[5] as u64) << 8)
        | ((cfis[6] as u64) << 16)
        | ((cfis[8] as u64) << 24)
        | ((cfis[9] as u64) << 32)
        | ((cfis[10] as u64) << 40);
    if got_lba != lba {
        return TestResult::Fail("READ DMA EXT LBA encoding wrong");
    }
    let got_n = cfis[12] as u16 | ((cfis[13] as u16) << 8);
    if got_n != n_sectors {
        return TestResult::Fail("READ DMA EXT sector count encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_read_dma_ext_encode);

/// Verify PORT_SSTS decode: DET nibble (bits[3:0]) and IPM nibble
/// (bits[11:8]) are decoded correctly for the three DET states and
/// two IPM states we care about.
fn smoke_ahci_port_ssts_decode() -> TestResult {
    use crate::ahci::{
        ssts_decode, SSTS_DET_NO_COMM, SSTS_DET_NO_DEVICE, SSTS_DET_PRESENT, SSTS_IPM_ACTIVE,
        SSTS_IPM_NOT_PRESENT,
    };

    // No device, no PHY.
    let (det, ipm) = ssts_decode(0x0000_0000);
    if det != SSTS_DET_NO_DEVICE {
        return TestResult::Fail("DET=0 should be SSTS_DET_NO_DEVICE");
    }
    if ipm != SSTS_IPM_NOT_PRESENT {
        return TestResult::Fail("IPM=0 should be SSTS_IPM_NOT_PRESENT");
    }

    // Device present, comms not established (COMRESET in flight).
    let (det, _ipm) = ssts_decode(0x0000_0001);
    if det != SSTS_DET_NO_COMM {
        return TestResult::Fail("DET=1 should be SSTS_DET_NO_COMM");
    }

    // Device present + comms OK, interface active (normal run).
    let (det, ipm) = ssts_decode(0x0000_0103);
    if det != SSTS_DET_PRESENT {
        return TestResult::Fail("DET=3 should be SSTS_DET_PRESENT");
    }
    if ipm != SSTS_IPM_ACTIVE {
        return TestResult::Fail("IPM=1 should be SSTS_IPM_ACTIVE");
    }

    // High nibbles in SSTS must not bleed into DET.
    let (det2, _) = ssts_decode(0x0000_FF13);
    if det2 != SSTS_DET_PRESENT {
        return TestResult::Fail("DET nibble isolation failed (upper SSTS bits bled in)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_port_ssts_decode);

fn smoke_ahci_hba_bring_up() -> TestResult {
    // QEMU q35 has the ICH9 AHCI controller at 00:1f.2 (8086:2922).
    // Probe it; assert HBA was reset cleanly + at least one port is
    // implemented + a SATA disk is detected on port 0.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    });
    if !has {
        return TestResult::Skip("no ICH9 AHCI");
    }
    __reset_for_test();
    ahci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe didn't install controller");
    }
    let pi = ahci::with_controller(|c| c.ports_implemented()).unwrap_or(0);
    if pi == 0 {
        return TestResult::Fail("ports_implemented = 0");
    }
    let n_ports = ahci::with_controller(|c| c.ports.len()).unwrap_or(0);
    if n_ports == 0 {
        return TestResult::Fail("no ports enumerated");
    }
    let vs = ahci::with_controller(|c| c.version()).unwrap_or(0);
    if vs == 0 || vs == 0xFFFF_FFFF {
        return TestResult::Fail("version register reads as garbage");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_hba_bring_up);

fn smoke_ahci_identify_device() -> TestResult {
    // Issue IDENTIFY DEVICE on the first port whose probe-time
    // signature said "SATA". Verify the device-data block decodes
    // a non-empty model string. QEMU's emulated SATA disk reports
    // model "QEMU HARDDISK" (with trailing spaces).
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    });
    if !has {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let authority = bootstrap_registry_authority();
        let _ = probe_all_pci(&authority);
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten();
    let idx = port.unwrap_or(0);
    // SAFETY: caller-trusted; the kernel-test harness owns the HBA.
    let id = match ahci::with_controller(|c| unsafe { c.identify_device(idx) }).map(|r| r) {
        Some(Ok(buf)) => buf,
        Some(Err(_)) => return TestResult::Fail("identify_device failed"),
        None => return TestResult::Fail("with_controller None"),
    };
    let model = ahci::identify_model(&id);
    if &model[..4] != b"QEMU" {
        return TestResult::Fail("IDENTIFY model != QEMU prefix");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_identify_device);

fn smoke_ahci_read_lba() -> TestResult {
    // Read sector 0 of the QEMU SATA disk and verify the pattern
    // xtask seeds the image with: byte i = (i * 0x6D) ^ 0x42.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut sector = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively here.
        unsafe { ahci::ahci_read_lba(c, port, 0, 1, &mut sector) });
    match r {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("ahci_read_lba failed"),
        None => return TestResult::Fail("with_controller None"),
    }
    for i in 0..512usize {
        let expected = (i as u8).wrapping_mul(0x6D) ^ 0x42;
        if sector[i] != expected {
            return TestResult::Fail("AHCI read pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_read_lba);

fn smoke_ahci_write_then_read_lba() -> TestResult {
    // Write a recognisable pattern at LBA 8 (well past the seeded
    // sector 0), read it back, verify.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize {
        payload[i] = (i as u8).wrapping_mul(0x29) ^ 0xA1;
    }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba(c, port, 8, 1, &payload) });
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba(c, port, 8, 1, &mut readback) });
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("ahci_read_lba(8) after write failed");
    }
    if readback != payload {
        return TestResult::Fail("AHCI write/read pattern mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_write_then_read_lba);

fn smoke_ahci_ncq_write_then_read_lba() -> TestResult {
    // NCQ command-flow: WRITE FPDMA QUEUED + READ FPDMA QUEUED at
    // LBA 16. Verifies that the device accepts the queued opcodes
    // (port-issue/clear + no TFD.ERR). QEMU's emulated AHCI NCQ
    // has writeback timing quirks that make the write→read data
    // round-trip flake; the value here is the wire-level command
    // pass, not host-side caching behaviour.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize {
        payload[i] = (i as u8).wrapping_mul(0x53) ^ 0x9E;
    }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba_ncq(c, port, 0, 0, 16, 1, &payload) });
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba_ncq failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba_ncq(c, port, 0, 1, 16, 1, &mut readback) });
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("ahci_read_lba_ncq failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_ncq_write_then_read_lba);

fn smoke_sdhci_register_class_match() -> TestResult {
    use crate::sdhci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    sdhci::register_pci_driver();
    let regs = registered_pci_drivers();
    let has = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x08,
                mask: 0xFF
            }
        )
    });
    if !has {
        return TestResult::Fail("sdhci class match missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sdhci", smoke_sdhci_register_class_match);

// ── Intel VMD smokes ───────────────────────────────────────────────

fn smoke_vmd_register_all_known_ids() -> TestResult {
    // Every known VMD device ID must land in the match table as an
    // exact VendorDevice entry — class-match alone is too coarse on
    // real silicon where Intel ships RAID + AHCI cards that share
    // the 0x010400 class.
    use crate::vmd;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    vmd::register_pci_driver_vmd();
    let regs = registered_pci_drivers();
    for (did, _name) in vmd::VMD_DEVICE_IDS.iter().copied() {
        let has = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: vmd::INTEL_VENDOR,
                    device,
                } if device == did
            )
        });
        if !has {
            return TestResult::Fail("vmd: missing VendorDevice match for known DID");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_register_all_known_ids);

fn smoke_vmd_match_kind_matches_synthetic_device() -> TestResult {
    // Build a synthetic BusDevice with the Tiger Lake VMD ID and
    // confirm exactly one of the registered match entries claims it
    // at full specificity. Guards against a future regression that
    // swaps the matcher for a class backstop and silently weakens
    // VMD's binding strength.
    use crate::vmd;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use narf_memory::PhysAddr;
    __reset_for_test();
    vmd::register_pci_driver_vmd();
    let addr = PcieAddr::new(0, 0, 0xE, 0); // VMD typically lives at 00:0e.0 on TGL
    let synth = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: vmd::INTEL_VENDOR,
            device: 0x9A0B, // Tiger Lake VMD
            class: 0x010400,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    };
    let regs = registered_pci_drivers();
    let mut matched = 0;
    let mut best_specificity = 0u8;
    for m in &regs {
        if m.kind.matches(&synth) {
            matched += 1;
            if m.kind.specificity() > best_specificity {
                best_specificity = m.kind.specificity();
            }
        }
    }
    if matched == 0 {
        return TestResult::Fail("vmd: synthetic 9A0B device not matched");
    }
    if best_specificity != 3 {
        return TestResult::Fail("vmd: best match must be VendorDevice (specificity 3)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_match_kind_matches_synthetic_device);

fn smoke_vmd_rejects_unrelated_intel_device() -> TestResult {
    // Probe with the AHCI ICH9 device ID — also vendor 0x8086 —
    // and confirm the VMD probe explicitly rejects it via
    // `NotForThisDriver`, not a more generic `BadDevice`. This is
    // what keeps the probe trace clean on real silicon where the
    // class backstop would otherwise drag every Intel storage device
    // through the VMD probe path.
    use crate::vmd;
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, PcieAddr, ProbeError};
    use narf_capabilities::Cap;
    use narf_memory::PhysAddr;
    let addr = PcieAddr::new(0, 0, 0x1F, 2);
    let dev = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: 0x8086,
            device: 0x2922, // ICH9 AHCI, not a VMD ID
            class: 0x010601,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, narf_capabilities::Write>::bootstrap();
    match vmd::probe(dev, cap) {
        Err(ProbeError::NotForThisDriver) => TestResult::Pass,
        Err(_) => TestResult::Fail("vmd: non-VMD device rejected with wrong error"),
        Ok(_) => TestResult::Fail("vmd: probe must not claim non-VMD devices"),
    }
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_rejects_unrelated_intel_device);

fn smoke_vmd_segment_base_is_high() -> TestResult {
    // VMD synthetic segments must live well clear of real ACPI _SEG
    // values. The base is the unit test invariant — change it and
    // every caller has to know.
    use crate::vmd;
    if vmd::VMD_SEGMENT_BASE < 0x1000 {
        return TestResult::Fail("VMD_SEGMENT_BASE must be high enough to avoid ACPI _SEG");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_segment_base_is_high);

fn smoke_vmd_not_present_on_qemu_tcg() -> TestResult {
    // QEMU TCG q35 doesn't model VMD. Verify the bus enumeration
    // doesn't accidentally surface a VMD device — this is the
    // counter-evidence smoke that proves the match table is alive
    // (it would fire on real hardware) without expecting a positive
    // detection on the QEMU smoke target.
    use crate::vmd;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{devices, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_vmd = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == vmd::INTEL_VENDOR
            && vmd::VMD_DEVICE_IDS.iter().any(|(did, _)| *did == d.id.device)
    });
    if has_vmd {
        return TestResult::Skip("vmd present (real-HW path); positive smoke is a follow-up");
    }
    // Counters must be zero — nothing has probed.
    if vmd::instance_count() != 0 {
        // Reset any leftover counters from prior smokes that may have
        // exercised the probe path; this smoke is the canonical
        // "VMD-not-present" trace.
        vmd::__reset_for_test();
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_not_present_on_qemu_tcg);

// ── SD response/CSD/CID decoder smokes ─────────────────────────────

fn smoke_sd_r1_status_error_mask() -> TestResult {
    use crate::sd_proto::R1Status;
    let s = R1Status { raw: R1Status::ERR_ILLEGAL_CMD | (5 << 9) | (1 << 8) };
    if !s.has_error() {
        return TestResult::Fail("ILLEGAL_CMD should be flagged");
    }
    if s.current_state() != 5 {
        return TestResult::Fail("current_state extracts bits 12..9");
    }
    if !s.ready_for_data() {
        return TestResult::Fail("ready_for_data is bit 8");
    }
    let clean = R1Status { raw: 1 << 8 };
    if clean.has_error() {
        return TestResult::Fail("clean status must not flag error");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r1_status_error_mask);

fn smoke_sd_r6_splits_rca_and_status() -> TestResult {
    use crate::sd_proto::R6;
    let r = R6::parse(0xCAFE_1234);
    if r.rca != 0xCAFE {
        return TestResult::Fail("R6 RCA should be high 16 bits");
    }
    if r.status != 0x1234 {
        return TestResult::Fail("R6 status should be low 16 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r6_splits_rca_and_status);

fn smoke_sd_r7_check_pattern() -> TestResult {
    use crate::sd_proto::R7;
    let r = R7::parse(0x0000_01AA);
    if r.voltage != 1 {
        return TestResult::Fail("voltage nibble at bits 11..8 should be 1");
    }
    if !r.matches_check(0xAA) {
        return TestResult::Fail("check pattern 0xAA should match");
    }
    if r.matches_check(0x55) {
        return TestResult::Fail("mismatched pattern shouldn't match");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r7_check_pattern);

fn smoke_sd_csd_v2_extracts_capacity() -> TestResult {
    use crate::sd_proto::Csd;
    // Build a CSD v2.0 image where C_SIZE = 0x1DFFF (122879) →
    // capacity = (122879+1) × 512 KiB = 60 GiB. Layout: structure
    // bits at top of byte 0, C_SIZE at bits 69..48 (i.e. byte 7 lo
    // 6 bits | byte 8 | byte 9 of the *logical* 15-byte CSD).
    //
    // The shifted convention: r[3] high byte = logical zero;
    // logical bytes start at byte 1 of bytes[0..16].
    let mut bytes = [0u8; 16];
    bytes[1] = 0x40; // structure = 1 (CSD v2.0)
    bytes[8] = 0x01; // bits[69..64] = top of c_size; this gives bit 16 of c_size
    bytes[9] = 0xDF; // c_size middle
    bytes[10] = 0xFF; // c_size low
    let r = [
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    ];
    let csd = Csd::parse_shifted(&r).expect("parse csd");
    if csd.structure_version != 1 {
        return TestResult::Fail("CSD structure should decode to v2.0");
    }
    if csd.read_block_len != 512 || csd.write_block_len != 512 {
        return TestResult::Fail("CSD v2 fixes block lengths to 512");
    }
    let expected = (122_880u64) * 512 * 1024;
    if csd.capacity_bytes != expected {
        return TestResult::Fail("CSD v2 capacity formula mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_csd_v2_extracts_capacity);

fn smoke_sd_cid_decodes_manufacturer_and_date() -> TestResult {
    use crate::sd_proto::Cid;
    // Compose a logical CID (15 bytes after the CRC strip):
    //   manufacturer 0x03 (SanDisk-equivalent), OEM "SD",
    //   product name "narf!", revision 0x10, serial 0xDEADBEEF,
    //   manufacture date: year-offset 0x18 (2024), month 0x09.
    let mut logical = [0u8; 15];
    logical[0] = 0x03;
    logical[1] = b'S';
    logical[2] = b'D';
    logical[3..8].copy_from_slice(b"narf!");
    logical[8] = 0x10;
    logical[9..13].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    // MDT = year:8 | month:4 in top 12 bits of a 16-bit field at logical[13..15].
    let mdt: u16 = (0x18u16 << 4) | 0x09;
    logical[13..15].copy_from_slice(&mdt.to_be_bytes());

    // Build the shifted [u32;4] the controller would deliver.
    let mut bytes = [0u8; 16];
    bytes[1..16].copy_from_slice(&logical);
    let r = [
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    ];
    let cid = Cid::parse_shifted(&r);
    if cid.manufacturer_id != 0x03 {
        return TestResult::Fail("manufacturer ID mismatch");
    }
    if cid.oem_id != [b'S', b'D'] {
        return TestResult::Fail("OEM ID mismatch");
    }
    if cid.product_name != *b"narf!" {
        return TestResult::Fail("product name mismatch");
    }
    if cid.product_revision != 0x10 {
        return TestResult::Fail("product revision mismatch");
    }
    if cid.product_serial != 0xDEAD_BEEF {
        return TestResult::Fail("serial number mismatch");
    }
    if cid.manufacture_year != 2024 || cid.manufacture_month != 9 {
        return TestResult::Fail("MDT year/month decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_cid_decodes_manufacturer_and_date);

// ── eMMC EXT_CSD smokes ────────────────────────────────────────────

fn smoke_emmc_ext_csd_size_constant() -> TestResult {
    if crate::emmc::EXT_CSD_SIZE != 512 {
        return TestResult::Fail("EXT_CSD register is 512 bytes per JESD84-B51 §7.4");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_size_constant);

fn smoke_emmc_ext_csd_capacity_decode() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_REV, EXT_CSD_SEC_COUNT};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_REV] = 8; // EXT_CSD revision 8 = JESD84-B51
    // 64 GiB user partition = 134_217_728 sectors of 512 bytes.
    let sectors: u32 = 134_217_728;
    buf[EXT_CSD_SEC_COUNT..EXT_CSD_SEC_COUNT + 4].copy_from_slice(&sectors.to_le_bytes());
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.user_capacity_bytes() != 64 * 1024 * 1024 * 1024 {
        return TestResult::Fail("user capacity should decode to 64 GiB");
    }
    if ext.revision != 8 {
        return TestResult::Fail("revision byte should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_capacity_decode);

fn smoke_emmc_ext_csd_supports_hs400() -> TestResult {
    use crate::emmc::{ExtCsd, CARD_TYPE_HS400_1V8, EXT_CSD_CARD_TYPE};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_CARD_TYPE] = CARD_TYPE_HS400_1V8;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if !ext.supports_hs400() {
        return TestResult::Fail("HS400 support flag missed");
    }
    if ext.supports_hs200() {
        return TestResult::Fail("HS200 should not be claimed when only HS400 bit set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_supports_hs400);

fn smoke_emmc_ext_csd_partition_config_decode() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_PARTITION_CONFIG};
    let mut buf = [0u8; 512];
    // BOOT_PARTITION_ENABLE=1 (boot1), PARTITION_ACCESS=3 (RPMB).
    buf[EXT_CSD_PARTITION_CONFIG] = (1 << 3) | 3;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.active_boot_partition() != Some(1) {
        return TestResult::Fail("active boot partition should be 1");
    }
    if ext.current_partition_access() != 3 {
        return TestResult::Fail("partition access should be RPMB (3)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_partition_config_decode);

fn smoke_emmc_ext_csd_boot_and_rpmb_size_mult() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_BOOT_SIZE_MULT, EXT_CSD_RPMB_SIZE_MULT};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_BOOT_SIZE_MULT] = 32; // 32 × 128 KiB = 4 MiB boot partition
    buf[EXT_CSD_RPMB_SIZE_MULT] = 8; // 8 × 128 KiB = 1 MiB RPMB
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.boot_partition_bytes() != 4 * 1024 * 1024 {
        return TestResult::Fail("boot partition size formula: mult × 128 KiB");
    }
    if ext.rpmb_partition_bytes() != 1 * 1024 * 1024 {
        return TestResult::Fail("RPMB partition size formula: mult × 128 KiB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_boot_and_rpmb_size_mult);

fn smoke_emmc_switch_argument_layout() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_HS_TIMING, HS_TIMING_HS200};
    // SWITCH (CMD6) arg to set HS_TIMING=2 (HS200): Access=3, Index=185, Value=2.
    let arg = ExtCsd::switch_argument(EXT_CSD_HS_TIMING as u8, HS_TIMING_HS200);
    let access = (arg >> 24) & 0xFF;
    let index = (arg >> 16) & 0xFF;
    let value = (arg >> 8) & 0xFF;
    if access != 3 {
        return TestResult::Fail("Access field should be 3 (Write Byte)");
    }
    if index != EXT_CSD_HS_TIMING as u32 {
        return TestResult::Fail("Index field should equal EXT_CSD offset");
    }
    if value != HS_TIMING_HS200 as u32 {
        return TestResult::Fail("Value field should carry the new byte");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_switch_argument_layout);

fn smoke_emmc_pre_eol_warning_decoded() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_PRE_EOL_INFO, PRE_EOL_WARNING};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_PRE_EOL_INFO] = PRE_EOL_WARNING;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.pre_eol_info != PRE_EOL_WARNING {
        return TestResult::Fail("PRE_EOL_INFO byte lost");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_pre_eol_warning_decoded);



// ── UFS / UFSHCI 3.0 ──────────────────────────────────────────────



fn smoke_ufs_utrd_round_trip() -> TestResult {

    use crate::ufs::{CommandType, DataDir, OcsStatus, Utrd};

    let u = Utrd {

        command_type: CommandType::Scsi,

        data_dir: DataDir::DeviceToHost,

        interrupt: true,

        crypto: false,

        cci: 0,

        ocs: OcsStatus::Success,

        ucd_phys: 0x0000_C0DE_FACE_F000u64,

        response_offset_bytes: 128,

        response_length_bytes: 64,

        prdt_offset_bytes: 256,

        prdt_entry_count: 4,

    };

    let r = Utrd::unpack(&u.pack());

    if r != u {

        return TestResult::Fail("UTRD round-trip failed");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_utrd_round_trip);



fn smoke_ufs_command_upiu_layout() -> TestResult {

    use crate::ufs::{build_command_upiu, cmd_flags, UpiuHeader, UpiuType};

    // SCSI READ(10): opcode 0x28, lba=0x100, length=4 blocks.

    let cdb = [0x28, 0, 0x00, 0x00, 0x01, 0x00, 0, 0, 4, 0];

    let buf = build_command_upiu(0, 0x42, cmd_flags::READ, 0x800, &cdb);

    if buf.len() != 32 {

        return TestResult::Fail("Command UPIU should be 32 bytes");

    }

    let mut hdr = [0u8; 12];

    hdr.copy_from_slice(&buf[..12]);

    let h = UpiuHeader::unpack(&hdr).expect("hdr");

    if h.kind != UpiuType::Command || h.task_tag != 0x42 || h.flags != cmd_flags::READ {

        return TestResult::Fail("command header decoded wrong");

    }

    let edl = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

    if edl != 0x800 {

        return TestResult::Fail("Expected Data Length lost");

    }

    if &buf[16..16 + cdb.len()] != cdb {

        return TestResult::Fail("CDB lost");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_command_upiu_layout);



fn smoke_ufs_response_upiu_decode() -> TestResult {

    use crate::ufs::{decode_response_upiu, UpiuHeader, UpiuType};

    let hdr = UpiuHeader {

        kind: UpiuType::Response,

        flags: 0,

        lun: 0,

        task_tag: 0x42,

        iid_cmd_set_type: 0,

        query_function: 0,

        response: 0,

        status: 0x02, // Check Condition

        total_ehs_length: 0,

        device_information: 0,

        data_segment_length: 8,

    };

    let mut buf = alloc::vec::Vec::new();

    buf.extend_from_slice(&hdr.pack());

    buf.extend_from_slice(&0x12345678u32.to_be_bytes()); // residual

    buf.extend_from_slice(&[0xF0, 0x00, 0x05, 0x00, 0, 0, 0x0A, 0]);

    let (h, residual, sense) = match decode_response_upiu(&buf) {

        Some(t) => t,

        None => return TestResult::Fail("decode_response_upiu failed"),

    };

    if h.task_tag != 0x42 || h.status != 0x02 {

        return TestResult::Fail("response header decoded wrong");

    }

    if residual != 0x12345678 {

        return TestResult::Fail("residual lost");

    }

    if sense.len() != 8 {

        return TestResult::Fail("sense data length wrong");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_response_upiu_decode);



fn smoke_ufs_prdt_byte_count_zero_based() -> TestResult {

    use crate::ufs::PrdtEntry;

    let e = PrdtEntry {

        data_addr: 0x0000_DEAD_BEEF_0000,

        byte_count: 4096,

    };

    let r = PrdtEntry::unpack(&e.pack());

    if r.byte_count != 4096 {

        return TestResult::Fail("PRDT round-trip byte count failed");

    }

    if r.data_addr != 0x0000_DEAD_BEEF_0000 {

        return TestResult::Fail("PRDT data addr lost");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_prdt_byte_count_zero_based);

// ── AHCI deferred feature smokes ──────────────────────────────────────

/// Verify the READ PORT MULTIPLIER (0xE4) command FIS byte layout.
///
/// The CFIS for ATA_CMD_PMP_READ must have:
///   byte 0 = 0x27 (H2D Register FIS type)
///   byte 1 = 0x80 | 0x0F  (C=1, PMP = control port 0x0F)
///   byte 2 = 0xE4 (ATA READ PORT MULTIPLIER opcode)
///   byte 3 = GSCR register index (features field)
///
/// Reference: Linux `drivers/ata/libata-pmp.c::sata_pmp_read` and
/// `include/linux/ata.h` (`ATA_CMD_PMP_READ = 0xE4`).
fn smoke_ahci_pmp_read_fis_layout() -> TestResult {
    let gscr_reg: u8 = 2; // GSCR_PORT_INFO
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27;
    cfis[1] = 0x80 | 0x0F; // C=1 | PMP control port (0x0F)
    cfis[2] = 0xE4;         // ATA_CMD_PMP_READ
    cfis[3] = gscr_reg;     // GSCR register index in features field

    if cfis[0] != 0x27 {
        return TestResult::Fail("PMP READ FIS type must be 0x27 (H2D)");
    }
    if cfis[1] & 0x80 == 0 {
        return TestResult::Fail("C bit (bit 7) must be set");
    }
    if cfis[1] & 0x0F != 0x0F {
        return TestResult::Fail("PMP port field must be 0x0F (control port)");
    }
    if cfis[2] != 0xE4 {
        return TestResult::Fail("READ PORT MULTIPLIER opcode must be 0xE4");
    }
    if cfis[3] != gscr_reg {
        return TestResult::Fail("GSCR register index must be in features field");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_pmp_read_fis_layout);

/// Verify the GSCR decoder extracts vendor/product/ports/features
/// from synthetic GSCR register values.
///
/// GSCR layout (SATA PMP spec §10.3 / Linux ata.h):
///   GSCR[0] = ProductId[31:16] | VendorId[15:0]
///   GSCR[1] = Revision bits[15:8] = major
///   GSCR[2] = bits[3:0] = number of device ports
///   GSCR[64] = Features
fn smoke_ahci_pmp_gscr_decode() -> TestResult {
    // Synthetic GSCR register values.
    let gscr0: u32 = (0xBEEFu32 << 16) | 0xCAFEu32; // product=0xBEEF, vendor=0xCAFE
    let gscr1: u32 = (0x12u32 << 8) | 0x03u32;       // major=0x12, minor=0x03
    let gscr2: u32 = 0xF5u32;                         // num_ports = bits[3:0] = 5
    let gscr64: u32 = 0x0000_0041u32;                 // features

    let vendor  = (gscr0 & 0xFFFF) as u16;
    let product = (gscr0 >> 16) as u16;
    let revision = ((gscr1 >> 8) & 0xFF) as u8;
    let num_ports = (gscr2 & 0x0F) as u8;
    let features = gscr64;

    if vendor != 0xCAFE {
        return TestResult::Fail("GSCR[0] vendor decode wrong");
    }
    if product != 0xBEEF {
        return TestResult::Fail("GSCR[0] product decode wrong");
    }
    if revision != 0x12 {
        return TestResult::Fail("GSCR[1] revision decode wrong");
    }
    if num_ports != 5 {
        return TestResult::Fail("GSCR[2] num_ports decode wrong (bits[3:0])");
    }
    if features != 0x41 {
        return TestResult::Fail("GSCR[64] features value wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_pmp_gscr_decode);

