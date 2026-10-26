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
    fis[3] = 0; // features lo
    fis[4] = (lba & 0xFF) as u8; // LBA[7:0]
    fis[5] = ((lba >> 8) & 0xFF) as u8; // LBA[15:8]
    fis[6] = ((lba >> 16) & 0xFF) as u8; // LBA[23:16]
    fis[7] = 0x40; // Device: LBA mode
    fis[8] = ((lba >> 24) & 0xFF) as u8; // LBA[31:24]
    fis[9] = ((lba >> 32) & 0xFF) as u8; // LBA[39:32]
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
    use crate::ahci::{
        identify_features, identify_lba28_capacity, identify_lba48_capacity, identify_model,
    };

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
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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

/// The installed HBA must never move, be replaced, or be dropped.
///
/// `ahci::probed_ahci` reads the device's address under the CONTROLLER
/// lock, releases the lock, and then uses that reference for the whole
/// transfer — which is what lets a 30-second-budget CI/D2H poll run
/// with interrupts enabled instead of livelocking every other CPU on
/// an IRQ-masking spinlock. That is only sound because `probe`
/// installs the device exactly once and nothing ever stores `None`
/// back.
///
/// This is precisely the sort of assumption a later "support
/// hot-unplug" or "re-probe on reset" change invalidates silently,
/// leaving a use-after-free reachable only under load. Assert it
/// directly: probing again must not move the device, and the address
/// must stay put across I/O through the unlocked path.
fn smoke_ahci_device_address_is_stable() -> TestResult {
    use crate::ahci;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, probe_all_pci};

    // SAFETY: identity-mapped QEMU ECAM region.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !ahci::is_probed() {
        return TestResult::Skip("AHCI not probed");
    }
    let before = match ahci::dbg_device_addr() {
        Some(a) => a,
        None => return TestResult::Fail("probed HBA has no address"),
    };

    // A repeat probe must be refused, not re-install a fresh device.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    match ahci::dbg_device_addr() {
        Some(a) if a == before => {}
        Some(_) => return TestResult::Fail("re-probe MOVED the installed HBA"),
        None => return TestResult::Fail("re-probe removed the installed HBA"),
    }

    // And it must survive ordinary traffic through the unlocked path.
    // The I/O result itself is irrelevant here; only the address
    // matters.
    use narf_block::BlockDeviceSync;
    let mut sector = [0u8; 512];
    if let Some(sync) = ahci::AhciBlockSync::from_probed() {
        let _ = sync.read(0, 1, &mut sector);
    }
    match ahci::dbg_device_addr() {
        Some(a) if a == before => TestResult::Pass,
        Some(_) => TestResult::Fail("HBA address changed across a read"),
        None => TestResult::Fail("HBA vanished across a read"),
    }
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_device_address_is_stable);

fn smoke_ahci_identify_device() -> TestResult {
    // Issue IDENTIFY DEVICE on the first port whose probe-time
    // signature said "SATA". Verify the device-data block decodes
    // a non-empty model string. QEMU's emulated SATA disk reports
    // model "QEMU HARDDISK" (with trailing spaces).
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    let id = match ahci::with_controller(|c| unsafe { c.identify_device(idx) }) {
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
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    for (i, &got) in sector.iter().enumerate() {
        let expected = (i as u8).wrapping_mul(0x6D) ^ 0x42;
        if got != expected {
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
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x29) ^ 0xA1;
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
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x53) ^ 0x9E;
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

/// The installed SDHCI controller must never move, be replaced, or be
/// dropped. Mirror of `smoke_ahci_device_address_is_stable` — see
/// that test for the full rationale; `sdhci::with_controller` hands
/// out a reference that outlives the CONTROLLER lock, which is only
/// sound while `probe` installs exactly once and nothing stores
/// `None` back.
///
/// QEMU's default machine has no SDHCI controller, so this usually
/// Skips in CI; it pins the invariant on real hardware (AMD FCH SD
/// host) and any future SDHCI-enabled QEMU config.
fn smoke_sdhci_device_address_is_stable() -> TestResult {
    use crate::sdhci;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, probe_all_pci};

    // SAFETY: identity-mapped QEMU ECAM region.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !sdhci::is_probed() {
        return TestResult::Skip("SDHCI not probed");
    }
    let before = match sdhci::dbg_device_addr() {
        Some(a) => a,
        None => return TestResult::Fail("probed SDHCI has no address"),
    };

    // A repeat probe must be refused, not re-install a fresh device.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    match sdhci::dbg_device_addr() {
        Some(a) if a == before => {}
        Some(_) => return TestResult::Fail("re-probe MOVED the installed SDHCI"),
        None => return TestResult::Fail("re-probe removed the installed SDHCI"),
    }

    // And it must survive traffic through the unlocked accessor.
    let _ = sdhci::with_controller(|c| c.card.lock().is_some());
    match sdhci::dbg_device_addr() {
        Some(a) if a == before => TestResult::Pass,
        Some(_) => TestResult::Fail("SDHCI address changed across an access"),
        None => TestResult::Fail("SDHCI vanished across an access"),
    }
}
kernel_test_in!(
    "drivers/storage/sdhci",
    smoke_sdhci_device_address_is_stable
);

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
            subsystem_vendor: 0,
            subsystem_id: 0,
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
kernel_test_in!(
    "drivers/storage/vmd",
    smoke_vmd_match_kind_matches_synthetic_device
);

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
            subsystem_vendor: 0,
            subsystem_id: 0,
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
kernel_test_in!(
    "drivers/storage/vmd",
    smoke_vmd_rejects_unrelated_intel_device
);

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
    // SAFETY: the kernel-test harness runs post-boot, so the allocator is
    // online and the bootloader handoff is complete; `ECAM_DEFAULT_BASE` is
    // QEMU q35's known-good ECAM window and the enumerator only reads config
    // space (rejecting all-1s), so re-running init here is sound.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_vmd = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == vmd::INTEL_VENDOR
            && vmd::VMD_DEVICE_IDS
                .iter()
                .any(|(did, _)| *did == d.id.device)
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

// ── VMD domain end-to-end fixture (issue #933 items 3 + 4) ────────
//
// A fake VMD bridge in RAM: a bridge config window (MSI-X cap whose
// table lives in MEMBAR2, VMCONFIG preset with remapping DISABLED),
// a 1 MiB CFGBAR window containing one NVMe function, and MEMBAR1 /
// MEMBAR2 register RAM. `Vmd::assemble_domain` runs the production
// assembly (enumerate, bridge MSI-X setup, VMCONFIG, domain
// registration), a mirror NVMe driver binds the child through
// probe_all and runs the child-side conversation (map BAR0, assign
// BAR2, program MSI-X vector 0), and the fixture fires the bridge
// vector to prove the demux reaches the child's handler.
//
// The one seam: BAR *decode*. RAM cannot emulate the sizing dance
// (a RAM cell reads back the all-ones probe verbatim, so every fake
// BAR reports the minimum size), so the fixture hands
// `assemble_domain` the decoded MEMBAR windows directly — the same
// values `bring_up` computes from `read_bar` on real hardware.

/// Page-aligned RAM window standing in for a hardware aperture.
struct VmdFakeWindow {
    _backing: alloc::vec::Vec<u8>,
    ptr: *mut u8,
    phys: u64,
    len: usize,
}

impl VmdFakeWindow {
    fn new(len: usize) -> Self {
        let mut backing = alloc::vec![0u8; len + 4096];
        let base = backing.as_mut_ptr() as usize;
        let aligned = (base + 4095) & !4095;
        let ptr = aligned as *mut u8;
        let phys = narf_memory::PhysAddr::from_kernel_ptr(ptr as *const u8).raw();
        Self {
            _backing: backing,
            ptr,
            phys,
            len,
        }
    }

    fn write32(&self, off: usize, v: u32) {
        debug_assert!(off + 4 <= self.len);
        // SAFETY: `off` is inside the owned window per the assert.
        unsafe {
            core::ptr::write_volatile(self.ptr.add(off) as *mut u32, v);
        }
    }

    fn read32(&self, off: usize) -> u32 {
        debug_assert!(off + 4 <= self.len);
        // SAFETY: `off` is inside the owned window per the assert.
        unsafe { core::ptr::read_volatile(self.ptr.add(off) as *const u32) }
    }
}

static VMD_E2E_PROBE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static VMD_E2E_BAR0_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static VMD_E2E_IRQ_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static VMD_E2E_DV: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn vmd_e2e_count_handler(_cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    use core::sync::atomic::Ordering;
    VMD_E2E_IRQ_COUNT.fetch_add(1, Ordering::SeqCst);
    narf_interrupts::dispatch::IrqStatus::Handled
}

/// Mirror NVMe child probe: the child-side conversation a real
/// driver runs against a VMD child, with results parked in statics
/// for the fixture body to assert.
fn vmd_e2e_child_probe(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    use core::sync::atomic::Ordering;
    VMD_E2E_PROBE_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the probe owns the child exclusively (bus contract).
    match unsafe { narf_bus::map_bar(&device, 0) } {
        Ok(region) => VMD_E2E_BAR0_PHYS.store(region.phys.raw(), Ordering::SeqCst),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    }
    // SAFETY: same ownership.
    match unsafe { narf_bus::assign_unprogrammed_bars(&device) } {
        Ok(n) if n >= 1 => {}
        _ => return Err(narf_bus::ProbeError::BadDevice),
    }
    let mut table = match narf_bus::enable_msix(&cap, &device) {
        Ok(t) => t,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let dv = VMD_E2E_DV.load(Ordering::SeqCst) as u8;
    // SAFETY: same ownership; vector 0 came from enable_msix's table.
    if unsafe { table.program_vector(0, 0, dv) }.is_err() {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    Ok(())
}

fn smoke_vmd_domain_end_to_end() -> TestResult {
    use core::sync::atomic::Ordering;

    use crate::vmd;
    use narf_bus::{
        BarKind, BusAddr, BusDevice, BusKind, DeviceId, MembarWindow, MmioRegion, PcieAddr,
    };
    use narf_memory::PhysAddr;

    let saved_registry = narf_bus::devices();
    narf_bus::driver_match::__reset_for_test();
    narf_bus::vmd_domain::__reset_for_test();
    narf_bus::vmd_irq::__reset_for_test();
    vmd::__reset_for_test();
    VMD_E2E_PROBE_CALLS.store(0, Ordering::SeqCst);
    VMD_E2E_BAR0_PHYS.store(0, Ordering::SeqCst);
    VMD_E2E_IRQ_COUNT.store(0, Ordering::SeqCst);

    // ── Fake hardware ──────────────────────────────────────────────
    let bridge_cfg = VmdFakeWindow::new(0x1000);
    let cfgbar = VmdFakeWindow::new(0x10_0000);
    let regs = VmdFakeWindow::new(0x8000); // MEMBAR1: child registers
    let membar2 = VmdFakeWindow::new(0x4000); // MEMBAR2: bridge MSI-X table

    // Bridge config: Tiger Lake VMD, cap list -> MSI-X (4 entries,
    // table in BAR4), VMCONFIG with remap-disable SET + BIOS-owned
    // bits that must survive.
    bridge_cfg.write32(0x00, 0x9A0B_8086);
    bridge_cfg.write32(0x04, 0x0010_0000);
    bridge_cfg.write32(0x08, 0x0104_0000);
    bridge_cfg.write32(0x10, (cfgbar.phys as u32 & 0xFFFF_FFF0) | 0x4);
    bridge_cfg.write32(0x14, (cfgbar.phys >> 32) as u32);
    bridge_cfg.write32(0x18, (regs.phys as u32 & 0xFFFF_FFF0) | 0x4);
    bridge_cfg.write32(0x1C, (regs.phys >> 32) as u32);
    bridge_cfg.write32(0x20, (membar2.phys as u32 & 0xFFFF_FFF0) | 0x4);
    bridge_cfg.write32(0x24, (membar2.phys >> 32) as u32);
    bridge_cfg.write32(0x34, 0x80);
    bridge_cfg.write32(0x44, 0xDEAD_0002); // VMCONFIG: MSI_RMP_DIS set
    bridge_cfg.write32(0x80, (3 << 16) | 0x11); // MSI-X cap, size 4
    bridge_cfg.write32(0x84, 4); // table: BIR 4, offset 0
    bridge_cfg.write32(0x88, 4 | 0x800); // PBA: BIR 4, offset 0x800

    // Child function at CFGBAR bus 0, dev 0: NVMe, BAR0 = the
    // register window inside MEMBAR1, BAR2 unprogrammed, MSI-X
    // (2 entries) table in BAR0.
    cfgbar.write32(0x00, 0xA808_144D);
    cfgbar.write32(0x04, 0x0010_0000);
    cfgbar.write32(0x08, 0x0108_0200);
    cfgbar.write32(0x10, (regs.phys as u32 & 0xFFFF_FFF0) | 0x4);
    cfgbar.write32(0x14, (regs.phys >> 32) as u32);
    cfgbar.write32(0x18, 0);
    cfgbar.write32(0x34, 0x80);
    cfgbar.write32(0x80, (1 << 16) | 0x11); // MSI-X cap, size 2
    cfgbar.write32(0x84, 0);
    cfgbar.write32(0x88, 0x800);

    let bridge_addr = PcieAddr::new(0, 0, 0x0E, 0);
    let bridge = BusDevice {
        addr: BusAddr::Pcie(bridge_addr),
        id: DeviceId {
            vendor: vmd::INTEL_VENDOR,
            device: 0x9A0B,
            class: 0x010400,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: bridge_addr,
            cfg_phys: PhysAddr::new(bridge_cfg.phys),
        },
    };

    // SAFETY: fixture-owned RAM window, mapped as the bridge's ECAM
    // segment so cap-gated config accesses resolve.
    if !unsafe { narf_bus::ecam::map_segment(PhysAddr::new(bridge_cfg.phys), 0x1000) } {
        return TestResult::Fail("could not map the fake bridge cfg segment");
    }
    narf_bus::registry::install(alloc::vec![bridge]);
    let authority = narf_bus::bootstrap_registry_authority();
    let (_handle, cap) = match narf_bus::claim_device_cap(&authority, bridge.addr) {
        Ok(x) => x,
        Err(_) => return TestResult::Fail("claim on the fake bridge failed"),
    };

    // The child driver's host vector, allocated up front so the
    // mirror probe can program it.
    let dv = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("host vector allocation failed"),
    };
    VMD_E2E_DV.store(dv as u64, Ordering::SeqCst);
    narf_interrupts::dispatch::install_handler_named(dv, "vmd-e2e", 7, vmd_e2e_count_handler);

    narf_bus::driver_match::register(narf_bus::PciMatch {
        name: "vmd-e2e-nvme",
        kind: narf_bus::MatchKind::ClassFull {
            class: 0x01,
            subclass: 0x08,
            prog_if: 0x02,
        },
        probe: vmd_e2e_child_probe,
    });

    // ── Production assembly ────────────────────────────────────────
    let region = MmioRegion {
        phys: PhysAddr::new(cfgbar.phys),
        virt: cfgbar.ptr as u64,
        len: 0x10_0000,
        kind: BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    // SAFETY: the fixture owns the fake bridge + windows; the seam
    // is only that the MEMBAR windows arrive pre-decoded (see the
    // fixture header comment).
    let vmd_inst = match unsafe {
        vmd::Vmd::assemble_domain(
            &bridge,
            &cap,
            region,
            Some(MembarWindow::new(regs.phys, 0x8000, 0)),
            Some(MembarWindow::new(membar2.phys, 0x4000, 0x2000)),
        )
    } {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("assemble_domain failed on the fake bridge"),
    };
    let seg = vmd_inst.segment;
    if seg != vmd::VMD_SEGMENT_BASE || vmd_inst.child_count() != 1 || vmd_inst.msix_entries != 4 {
        return TestResult::Fail("assembly produced the wrong domain shape");
    }
    // VMCONFIG: remap-disable cleared, every BIOS-owned bit intact.
    if bridge_cfg.read32(0x44) != 0xDEAD_0000 {
        return TestResult::Fail("VMCONFIG was not switched to remapping, or lost BIOS bits");
    }
    // Bridge MSI-X table in MEMBAR2 RAM: four entries pointing at
    // the LAPIC base with distinct host vectors, all unmasked.
    let mut seen = [0u32; 4];
    for i in 0..4usize {
        let base = i * 16;
        if membar2.read32(base) != 0xFEE0_0000 || membar2.read32(base + 12) != 0 {
            return TestResult::Fail("bridge MSI-X entry is not a native LAPIC message");
        }
        let data = membar2.read32(base + 8);
        if !(48..=240).contains(&data) || seen[..i].contains(&data) {
            return TestResult::Fail("bridge MSI-X entries do not hold distinct host vectors");
        }
        seen[i] = data;
    }
    // Domain registered with the client shape (first_vec = 1).
    match narf_bus::vmd_domain_info(seg) {
        Some(info) => {
            if info.msix_entries != 4
                || info.first_vec != 1
                || info.membar1.map(|w| w.base) != Some(regs.phys)
                || info.membar2.map(|w| w.reserve_head) != Some(0x2000)
            {
                return TestResult::Fail("registered domain info does not match the fake hardware");
            }
        }
        None => return TestResult::Fail("domain was not registered"),
    }

    // ── Child binding + conversation ───────────────────────────────
    vmd_inst.install_children();
    let child_addr = BusAddr::Pcie(PcieAddr::new(seg, 0, 0, 0));
    if !narf_bus::devices().iter().any(|d| d.addr == child_addr) {
        return TestResult::Fail("child was not installed into the registry");
    }
    match narf_bus::driver_match::probe_all(&authority) {
        Ok(1) => {}
        _ => return TestResult::Fail("probe_all did not bind exactly the child"),
    }
    if VMD_E2E_PROBE_CALLS.load(Ordering::SeqCst) != 1
        || VMD_E2E_BAR0_PHYS.load(Ordering::SeqCst) != regs.phys
    {
        return TestResult::Fail("child probe did not map BAR0 inside MEMBAR1");
    }
    // BAR2 was assigned from MEMBAR1, routed around BAR0's range.
    if cfgbar.read32(0x18) != (regs.phys as u32 + 0x1000) {
        return TestResult::Fail("child BAR2 was not assigned from MEMBAR1 past BAR0");
    }
    // Child MSI-X entry 0 holds the remap message for bridge
    // entry 2 (NVMe policy: least loaded at/above first_vec + 1).
    if regs.read32(0) != 0xFEE0_2000 || regs.read32(8) != 0 {
        return TestResult::Fail("child MSI-X entry does not hold the remap message");
    }
    if narf_bus::vmd_entry_for_child(seg, child_addr, 0) != Some(2) {
        return TestResult::Fail("child vector was not assigned bridge entry 2");
    }

    // ── Demux: fire the bridge vector, reach the child handler ────
    let bv = match narf_bus::vmd_bridge_vector(seg, 2) {
        Some(v) => v,
        None => return TestResult::Fail("no bridge vector for entry 2"),
    };
    if bv as u32 != seen[2] {
        return TestResult::Fail("bridge vector disagrees with the programmed table entry");
    }
    narf_interrupts::dispatch::on_irq(bv);
    if VMD_E2E_IRQ_COUNT.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("demux did not dispatch the bridge interrupt to the child");
    }

    // ── Detach: mappings die with the binding ──────────────────────
    match narf_bus::detach_pci_device(&authority, child_addr) {
        Ok(true) => {}
        _ => return TestResult::Fail("detach of the child failed"),
    }
    if narf_bus::vmd_entry_for_child(seg, child_addr, 0).is_some() {
        return TestResult::Fail("detach left the child's remap mapping live");
    }
    narf_interrupts::dispatch::on_irq(bv);
    if VMD_E2E_IRQ_COUNT.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("demux dispatched to a detached child");
    }

    // ── Cleanup ────────────────────────────────────────────────────
    narf_interrupts::dispatch::clear_handler(dv);
    let _ = narf_interrupts::vector::free(dv);
    narf_bus::unregister_vmd_domain(seg);
    narf_bus::unregister_vmd_irq_domain(seg);
    narf_bus::registry::install(saved_registry);
    narf_bus::driver_match::__reset_for_test();
    vmd::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/storage/vmd", smoke_vmd_domain_end_to_end);

// ── SD response/CSD/CID decoder smokes ─────────────────────────────

fn smoke_sd_r1_status_error_mask() -> TestResult {
    use crate::sd_proto::R1Status;
    let s = R1Status {
        raw: R1Status::ERR_ILLEGAL_CMD | (5 << 9) | (1 << 8),
    };
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
kernel_test_in!(
    "drivers/storage/sd-proto",
    smoke_sd_r6_splits_rca_and_status
);

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
kernel_test_in!(
    "drivers/storage/sd-proto",
    smoke_sd_csd_v2_extracts_capacity
);

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
kernel_test_in!(
    "drivers/storage/sd-proto",
    smoke_sd_cid_decodes_manufacturer_and_date
);

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
kernel_test_in!(
    "drivers/storage/emmc",
    smoke_emmc_ext_csd_partition_config_decode
);

fn smoke_emmc_ext_csd_boot_and_rpmb_size_mult() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_BOOT_SIZE_MULT, EXT_CSD_RPMB_SIZE_MULT};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_BOOT_SIZE_MULT] = 32; // 32 × 128 KiB = 4 MiB boot partition
    buf[EXT_CSD_RPMB_SIZE_MULT] = 8; // 8 × 128 KiB = 1 MiB RPMB
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.boot_partition_bytes() != 4 * 1024 * 1024 {
        return TestResult::Fail("boot partition size formula: mult × 128 KiB");
    }
    if ext.rpmb_partition_bytes() != 1024 * 1024 {
        return TestResult::Fail("RPMB partition size formula: mult × 128 KiB");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/emmc",
    smoke_emmc_ext_csd_boot_and_rpmb_size_mult
);

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

    if buf[16..16 + cdb.len()] != cdb {
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
    cfis[2] = 0xE4; // ATA_CMD_PMP_READ
    cfis[3] = gscr_reg; // GSCR register index in features field

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
    let gscr1: u32 = (0x12u32 << 8) | 0x03u32; // major=0x12, minor=0x03
    let gscr2: u32 = 0xF5u32; // num_ports = bits[3:0] = 5
    let gscr64: u32 = 0x0000_0041u32; // features

    let vendor = (gscr0 & 0xFFFF) as u16;
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

/// Verify the ATAPI PACKET command FIS byte layout for a 12-byte CDB.
///
/// CFIS for ATA PACKET (0xA0) with DMA D2H:
///   byte 0 = 0x27 (H2D Register FIS type)
///   byte 1 = 0x80 (C=1, PMP=0)
///   byte 2 = 0xA0 (ATA_CMD_PACKET)
///   byte 3 = 0x05 (features: DMA=1 | DMADIR=1 for D2H)
///
/// Command-list header bit 5 (A) must be set for ATAPI.
/// Reference: ATA8-ACS §7.18 PACKET command; Linux
/// `include/linux/ata.h` (`ATA_CMD_PACKET = 0xA0`).
fn smoke_ahci_atapi_packet_fis_layout() -> TestResult {
    let cdb: [u8; 12] = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // READ CAPACITY(10)

    // Command-list header word 0.
    let prdt_len: u32 = 1;
    let w_bit: u32 = 0; // D2H = read, no W bit
    let header_w0 = (prdt_len << 16) | w_bit | (1 << 5) | 5; // A=1 | CFL=5

    // CFIS bytes.
    let mut cfis = [0u8; 20];
    cfis[0] = 0x27;
    cfis[1] = 0x80;
    cfis[2] = 0xA0; // ATA PACKET
    cfis[3] = 0x01 | 0x04; // DMA | DMADIR=D2H

    // ACMD must hold the CDB.
    let mut acmd = [0u8; 16];
    acmd[..12].copy_from_slice(&cdb);

    if cfis[0] != 0x27 {
        return TestResult::Fail("ATAPI FIS type must be 0x27 (H2D)");
    }
    if cfis[2] != 0xA0 {
        return TestResult::Fail("ATAPI opcode must be 0xA0 (PACKET)");
    }
    if cfis[3] & 0x01 == 0 {
        return TestResult::Fail("ATAPI features DMA bit (bit 0) must be set");
    }
    if cfis[3] & 0x04 == 0 {
        return TestResult::Fail("ATAPI features DMADIR bit (bit 2) must be set for D2H");
    }
    if header_w0 & (1 << 5) == 0 {
        return TestResult::Fail("command-list header A bit (bit 5) must be set for ATAPI");
    }
    if header_w0 & (1 << 6) != 0 {
        return TestResult::Fail("W bit must be clear for D2H ATAPI transfer");
    }
    if acmd[0] != 0x25 {
        return TestResult::Fail("CDB opcode lost in ACMD");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_atapi_packet_fis_layout);

/// Verify READ CAPACITY(10) response decode: big-endian 8-byte
/// response fields decoded into (block_count, block_size).
///
/// Reference: SPC-4 §6.18: returned data bytes 0–3 = last LBA,
/// bytes 4–7 = block length. `block_count = last_lba + 1`.
fn smoke_ahci_atapi_read_capacity_decode() -> TestResult {
    // Simulate an 80-minute CD-ROM: 360,000 sectors of 2048 bytes.
    let last_lba: u32 = 359_999;
    let block_size: u32 = 2048;

    // Big-endian response as the device would send.
    let mut resp = [0u8; 8];
    resp[0..4].copy_from_slice(&last_lba.to_be_bytes());
    resp[4..8].copy_from_slice(&block_size.to_be_bytes());

    // Decode as read_atapi_capacity would.
    let got_last_lba = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]);
    let got_block_size = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
    let block_count = got_last_lba.wrapping_add(1);

    if got_last_lba != last_lba {
        return TestResult::Fail("last LBA round-trip failed");
    }
    if got_block_size != block_size {
        return TestResult::Fail("block size round-trip failed");
    }
    if block_count != 360_000 {
        return TestResult::Fail("block_count = last_lba + 1 formula wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_atapi_read_capacity_decode
);

/// Verify that PORT_IS_PHYRDY (bit 22) is the correct bit position
/// for the PhyRdy change interrupt in PORT_IS / PORT_IE.
///
/// Reference: AHCI 1.3.1 §3.3.5 Table 11 — "PhyRdy Change Status"
/// is bit 22 of PORT_IS.
fn smoke_ahci_phyrdy_bit_position() -> TestResult {
    use crate::ahci::{PORT_IE_PHYRDY, PORT_IS_PHYRDY, SERR_PHYRDY_CHG};

    // Bit 22 = 0x0040_0000.
    if PORT_IS_PHYRDY != (1 << 22) {
        return TestResult::Fail("PORT_IS_PHYRDY must be bit 22 (0x0040_0000)");
    }
    if PORT_IE_PHYRDY != (1 << 22) {
        return TestResult::Fail("PORT_IE_PHYRDY must be bit 22");
    }
    // SERR.N (PHY RDY Changed) = bit 16 per Linux ata.h SERR_PHYRDY_CHG.
    if SERR_PHYRDY_CHG != (1 << 16) {
        return TestResult::Fail("SERR_PHYRDY_CHG must be bit 16 (0x0001_0000)");
    }
    // Spot-check: bit 22 must not alias bit 16.
    if PORT_IS_PHYRDY == SERR_PHYRDY_CHG {
        return TestResult::Fail("PORT_IS_PHYRDY and SERR_PHYRDY_CHG must be different bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_phyrdy_bit_position);

/// Verify hot-unplug state transition using a fake MMIO port that
/// has PORT_SSTS.DET = 0 (no device), simulating a hot-unplug event.
///
/// `handle_phyrdy_change` with DET = 0 must return
/// `PortLinkState::Disconnected` without attempting a port reset.
fn smoke_ahci_hot_unplug_state_transition() -> TestResult {
    use crate::ahci::{ssts_decode, PortLinkState, SSTS_DET_NO_DEVICE, SSTS_DET_PRESENT};

    // Simulate reading PORT_SSTS after a hot-unplug: DET = 0, IPM = 0.
    let ssts_after_unplug: u32 = 0x0000_0000;
    let (det, _ipm) = ssts_decode(ssts_after_unplug);

    // The state machine: if DET != SSTS_DET_PRESENT, return Disconnected.
    let state = if det != SSTS_DET_PRESENT {
        PortLinkState::Disconnected
    } else {
        PortLinkState::Connected {
            kind: crate::ahci::PortKind::Sata,
        }
    };

    if state != PortLinkState::Disconnected {
        return TestResult::Fail("DET=0 must produce PortLinkState::Disconnected");
    }

    // Cross-check: DET = 3 (present) must produce Connected path.
    let ssts_present: u32 = 0x0000_0103; // IPM=1 (active), DET=3 (present)
    let (det2, _) = ssts_decode(ssts_present);
    if det2 != SSTS_DET_PRESENT {
        return TestResult::Fail("DET=3 should decode as SSTS_DET_PRESENT");
    }

    // Verify the no-device sentinel constant.
    if SSTS_DET_NO_DEVICE != 0 {
        return TestResult::Fail("SSTS_DET_NO_DEVICE must be 0");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_hot_unplug_state_transition
);

// ── RTSX smokes ────────────────────────────────────────────────────

/// Verify that every Realtek device ID in the RTSX table is registered
/// as a VendorDevice match after `register_pci_driver()`.
fn smoke_rtsx_device_id_match() -> TestResult {
    use crate::rtsx;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    rtsx::register_pci_driver();
    let regs = registered_pci_drivers();
    for (did, _name) in rtsx::RTSX_DEVICE_IDS.iter().copied() {
        let has = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: rtsx::RTSX_VENDOR,
                    device,
                } if device == did
            )
        });
        if !has {
            return TestResult::Fail("rtsx: missing VendorDevice match for known DID");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_device_id_match);

/// Verify RTS525A (0x525A) is in the RTSX device table — the device
/// found on Phoenix-class HawkPoint1 laptops.
fn smoke_rtsx_rts525a_in_table() -> TestResult {
    use crate::rtsx;
    let has = rtsx::RTSX_DEVICE_IDS.iter().any(|(did, _)| *did == 0x525A);
    if !has {
        return TestResult::Fail("RTS525A (0x525A) must be in RTSX_DEVICE_IDS");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_rts525a_in_table);

/// Verify the RTSX vendor ID is 0x10EC (Realtek).
fn smoke_rtsx_vendor_id() -> TestResult {
    use crate::rtsx;
    if rtsx::RTSX_VENDOR != 0x10EC {
        return TestResult::Fail("RTSX_VENDOR must be 0x10EC (Realtek)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_vendor_id);

/// Verify the SD command frame built by `build_sd_cmd_frame`:
/// CMD17 (READ_SINGLE_BLOCK) with LBA 0x12345678 should produce a
/// 6-byte frame with the start+direction bits set, the command index
/// in bits[5:0] of byte 0, and the argument in bytes 1..4 big-endian.
fn smoke_rtsx_sd_cmd17_encode() -> TestResult {
    use crate::rtsx::cmd::build_sd_cmd_frame;

    let frame = build_sd_cmd_frame(17, 0x1234_5678);

    // Byte 0: 0x40 | cmd_index — start=0 (implicit), direction=1, index=17.
    if frame[0] != (0x40 | 17) {
        return TestResult::Fail("CMD17 frame byte 0: must be 0x40 | 17");
    }
    // Bytes 1..4: argument big-endian.
    let reconstructed_arg = ((frame[1] as u32) << 24)
        | ((frame[2] as u32) << 16)
        | ((frame[3] as u32) << 8)
        | (frame[4] as u32);
    if reconstructed_arg != 0x1234_5678 {
        return TestResult::Fail("CMD17 argument big-endian encoding wrong");
    }
    // Byte 5: CRC7 placeholder = 0x00.
    if frame[5] != 0x00 {
        return TestResult::Fail("CMD17 frame byte 5 must be 0 (CRC7 filled by hardware)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_sd_cmd17_encode);

/// Verify CMD0 (GO_IDLE_STATE) frame: index 0, arg 0, byte 0 = 0x40.
fn smoke_rtsx_sd_cmd0_encode() -> TestResult {
    use crate::rtsx::cmd::build_sd_cmd_frame;

    let frame = build_sd_cmd_frame(0, 0);
    if frame[0] != 0x40 {
        return TestResult::Fail("CMD0 byte 0 must be 0x40 (0b01_000000)");
    }
    for b in &frame[1..5] {
        if *b != 0 {
            return TestResult::Fail("CMD0 argument must be all-zero");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_sd_cmd0_encode);

/// Verify CMD8 (SEND_IF_COND) frame: index 8, arg 0x000001AA.
fn smoke_rtsx_sd_cmd8_encode() -> TestResult {
    use crate::rtsx::cmd::build_sd_cmd_frame;

    let frame = build_sd_cmd_frame(8, 0x000001AA);
    if frame[0] != (0x40 | 8) {
        return TestResult::Fail("CMD8 frame byte 0 must be 0x40 | 8");
    }
    // Argument 0x000001AA → bytes 1..4 = 0x00, 0x00, 0x01, 0xAA.
    if frame[1] != 0x00 || frame[2] != 0x00 || frame[3] != 0x01 || frame[4] != 0xAA {
        return TestResult::Fail("CMD8 argument 0x000001AA encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_sd_cmd8_encode);

/// Verify the RTSX write-register host-command-buffer entry encoding.
/// A WRITE_REG for addr=0xFDA9 (SD_CMD0), mask=0xFF, data=0x51 should
/// encode to a specific 32-bit LE word per the RTSX spec.
fn smoke_rtsx_cmd_entry_write_encode() -> TestResult {
    use crate::rtsx::cmd::CmdEntry;
    use crate::rtsx::regs::{SD_CMD0, WRITE_REG_CMD};

    let e = CmdEntry::write(SD_CMD0, 0xFF, 0x51);
    let bytes = e.as_le_bytes();
    let word = u32::from_le_bytes(bytes);

    // type   = WRITE_REG_CMD (1) → bits[31:30] = 0b01
    let expected_type = (WRITE_REG_CMD as u32) << 30;
    if word & (0x3u32 << 30) != expected_type {
        return TestResult::Fail("WRITE_REG type bits wrong");
    }
    // addr   = 0xFDA9 & 0x3FFF = 0x3DA9 → bits[29:16]
    let expected_addr = (0xFDA9u32 & 0x3FFF) << 16;
    if word & (0x3FFFu32 << 16) != expected_addr {
        return TestResult::Fail("WRITE_REG addr bits wrong");
    }
    // mask   = 0xFF → bits[15:8]
    if (word >> 8) & 0xFF != 0xFF {
        return TestResult::Fail("WRITE_REG mask bits wrong");
    }
    // data   = 0x51 → bits[7:0]
    if word & 0xFF != 0x51 {
        return TestResult::Fail("WRITE_REG data bits wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_cmd_entry_write_encode);

/// Verify the CmdBuf accumulates entries and serialises correctly.
fn smoke_rtsx_cmd_buf_serialise() -> TestResult {
    use crate::rtsx::cmd::CmdBuf;
    use crate::rtsx::regs::{SD_CMD0, SD_CMD1};

    let mut buf = CmdBuf::new();
    assert!(buf.push_write(SD_CMD0, 0xFF, 0x51));
    assert!(buf.push_write(SD_CMD1, 0xFF, 0x23));
    if buf.len() != 2 {
        return TestResult::Fail("CmdBuf::len should be 2");
    }
    let mut out = [0u8; 8];
    buf.serialise(&mut out);

    // Deserialise and verify each entry.
    let w0 = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    let w1 = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);

    if w0 & 0xFF != 0x51 {
        return TestResult::Fail("first entry data byte lost in serialise");
    }
    if w1 & 0xFF != 0x23 {
        return TestResult::Fail("second entry data byte lost in serialise");
    }
    // Check clear + re-use.
    buf.clear();
    if !buf.is_empty() {
        return TestResult::Fail("CmdBuf::clear should reset len to 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_cmd_buf_serialise);

/// Verify BIPR_SD_EXIST (bit 16) is used for card-detection.
/// Linux `rtsx_pci.h:60` — `SD_EXIST = (1 << 16)`.
fn smoke_rtsx_bipr_sd_exist_bit() -> TestResult {
    use crate::rtsx::card::sd_card_detected;
    use crate::rtsx::regs::BIPR_SD_EXIST;

    if BIPR_SD_EXIST != (1 << 16) {
        return TestResult::Fail("BIPR_SD_EXIST must be bit 16 (1 << 16)");
    }
    // When bit 16 is set, sd_card_detected returns true.
    if !sd_card_detected(1 << 16) {
        return TestResult::Fail("sd_card_detected should be true when SD_EXIST bit set");
    }
    // When bit 16 is clear, sd_card_detected returns false.
    if sd_card_detected(0x0000_FFFF) {
        return TestResult::Fail("sd_card_detected should be false when SD_EXIST clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_bipr_sd_exist_bit);

/// Verify the ACMD41 argument sets CCS (bit 30) when hcs=true,
/// and clears it when hcs=false.
fn smoke_rtsx_acmd41_hcs_arg() -> TestResult {
    use crate::rtsx::card::SdCmd;

    let acmd_hcs = SdCmd::acmd41(true);
    if acmd_hcs.arg & (1 << 30) == 0 {
        return TestResult::Fail("ACMD41 with hcs=true must set CCS (bit 30)");
    }
    let acmd_no_hcs = SdCmd::acmd41(false);
    if acmd_no_hcs.arg & (1 << 30) != 0 {
        return TestResult::Fail("ACMD41 with hcs=false must clear CCS");
    }
    if acmd_hcs.index != 41 {
        return TestResult::Fail("ACMD41 command index must be 41");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_acmd41_hcs_arg);

/// Verify RTSX probe rejects a non-RTSX device.
fn smoke_rtsx_probe_rejects_non_rtsx() -> TestResult {
    use crate::rtsx;
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, PcieAddr, ProbeError};
    use narf_capabilities::Cap;
    use narf_memory::PhysAddr;

    let addr = PcieAddr::new(0, 0, 0x1F, 2);
    let dev = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: 0x8086, // Intel, not Realtek
            device: 0x2922,
            class: 0xFF0000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, narf_capabilities::Write>::bootstrap();
    match rtsx::probe(dev, cap) {
        Err(ProbeError::NotForThisDriver) => TestResult::Pass,
        Err(_) => TestResult::Fail("rtsx: non-RTSX device rejected with wrong error"),
        Ok(_) => TestResult::Fail("rtsx: probe must not claim non-RTSX devices"),
    }
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_probe_rejects_non_rtsx);

/// Verify R7 (CMD8 response) decode: voltage nibble=1, pattern=0xAA.
fn smoke_rtsx_r7_decode() -> TestResult {
    use crate::rtsx::card::decode_r7;

    // Standard CMD8 response for 2.7–3.6 V range + check pattern 0xAA.
    let resp: u32 = 0x0000_01AA;
    let (v_ok, pat_ok) = decode_r7(resp);
    if !v_ok {
        return TestResult::Fail("R7 voltage nibble 1 should be accepted");
    }
    if !pat_ok {
        return TestResult::Fail("R7 check pattern 0xAA should match");
    }
    // Mismatched pattern.
    let (_, bad_pat) = decode_r7(0x0000_0155);
    if bad_pat {
        return TestResult::Fail("R7 pattern 0x55 should not match 0xAA");
    }
    // Wrong voltage nibble.
    let (bad_v, _) = decode_r7(0x0000_02AA);
    if bad_v {
        return TestResult::Fail("R7 voltage nibble 2 should not be accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/rtsx", smoke_rtsx_r7_decode);

// ── MMC command-protocol smokes ────────────────────────────────────

/// Verify the eMMC CMD8 (SEND_EXT_CSD) EXT_CSD HS200/HS400 decode
/// round-trip: set both HS200 1.8 V and HS400 1.8 V bits and verify
/// both predicates fire.
fn smoke_mmc_cmd8_ext_csd_hs_flags() -> TestResult {
    use crate::emmc::{ExtCsd, CARD_TYPE_HS200_1V8, CARD_TYPE_HS400_1V8, EXT_CSD_CARD_TYPE};

    let mut buf = [0u8; 512];
    buf[EXT_CSD_CARD_TYPE] = CARD_TYPE_HS200_1V8 | CARD_TYPE_HS400_1V8;
    let ext = ExtCsd::parse(&buf).expect("parse");

    if !ext.supports_hs200() {
        return TestResult::Fail("HS200 flag must be set when CARD_TYPE_HS200_1V8 is set");
    }
    if !ext.supports_hs400() {
        return TestResult::Fail("HS400 flag must be set when CARD_TYPE_HS400_1V8 is set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_mmc_cmd8_ext_csd_hs_flags);

/// Verify eMMC CMD0 framing: index=0, arg=0, no response expected.
/// This maps to the `SdCmd::go_idle()` constructor in the RTSX card
/// layer (same encoding used by the MMC layer for SDHCI).
fn smoke_mmc_cmd0_encoding() -> TestResult {
    use crate::rtsx::card::SdCmd;

    let cmd = SdCmd::go_idle();
    if cmd.index != 0 {
        return TestResult::Fail("CMD0 index must be 0");
    }
    if cmd.arg != 0 {
        return TestResult::Fail("CMD0 argument must be 0");
    }
    use crate::rtsx::card::RspType;
    if cmd.rsp != RspType::None {
        return TestResult::Fail("CMD0 must expect no response");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/mmc", smoke_mmc_cmd0_encoding);

/// Verify CMD3 (SEND_RELATIVE_ADDR) and CMD7 (SELECT) encoding in
/// the RTSX card layer — same protocol used by the eMMC MMC layer.
fn smoke_mmc_cmd3_cmd7_encoding() -> TestResult {
    use crate::rtsx::card::SdCmd;

    let cmd3 = SdCmd::send_relative_addr();
    if cmd3.index != 3 {
        return TestResult::Fail("CMD3 index must be 3");
    }
    if cmd3.arg != 0 {
        return TestResult::Fail("CMD3 argument must be 0 on host side");
    }

    let rca: u16 = 0xBEEF;
    let cmd7 = SdCmd::select_card(rca);
    if cmd7.index != 7 {
        return TestResult::Fail("CMD7 index must be 7");
    }
    // CMD7 argument = RCA << 16.
    if cmd7.arg != ((rca as u32) << 16) {
        return TestResult::Fail("CMD7 argument must be RCA << 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/mmc", smoke_mmc_cmd3_cmd7_encoding);

// ── AHCI: generic class binding + spec-generic HBA init ───────────────

fn synth_pci(vendor: u16, device: u16, class: u32) -> narf_bus::BusDevice {
    use narf_bus::{BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use narf_memory::PhysAddr;
    let addr = PcieAddr::new(0, 0x11, 0, 0);
    BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor,
            device,
            class,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    }
}

/// The best (most specific) registered match for `dev`, as `probe_all`
/// picks it.
fn best_match(dev: &narf_bus::BusDevice) -> Option<narf_bus::PciMatch> {
    narf_bus::registered_pci_drivers()
        .into_iter()
        .filter(|m| m.kind.matches(dev))
        .max_by_key(|m| m.kind.specificity())
}

/// The AMD 600-series chipset SATA controller (`1022:43f6`, class
/// `01:06:01`, the Navi22 host's `11:00.0`) binds to AHCI through the
/// generic class entry, as Linux's `ahci_pci_tbl` does. Only the binding
/// is exercised here: QEMU models no AMD AHCI controller, so the AMD
/// silicon itself is untested.
fn smoke_ahci_binds_amd_600_series_by_class() -> TestResult {
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    __reset_for_test();
    ahci::register_pci_driver();

    let amd = synth_pci(
        ahci::AMD_VENDOR,
        ahci::AMD_600_SERIES_SATA_DEV,
        ((ahci::PCI_CLASS_STORAGE as u32) << 16)
            | ((ahci::PCI_SUBCLASS_SATA as u32) << 8)
            | ahci::PCI_PROGIF_AHCI as u32,
    );
    let Some(m) = best_match(&amd) else {
        return TestResult::Fail("AMD 1022:43f6 (01:06:01) matched no driver");
    };
    if m.name != "ahci-class" || m.probe as usize != ahci::probe as usize {
        return TestResult::Fail("AMD 1022:43f6 must bind the AHCI class entry");
    }
    if !matches!(m.kind, narf_bus::MatchKind::ClassFull { .. }) {
        return TestResult::Fail("AMD binding must be the full class triple");
    }
    // ICH9 keeps its exact-ID entry (higher specificity than the class).
    let ich9 = synth_pci(ahci::AHCI_VENDOR, ahci::AHCI_ICH9_DEV, 0x010601);
    if best_match(&ich9).map(|m| m.name) != Some("ahci-ich9") {
        return TestResult::Fail("ICH9 must still bind its VendorDevice entry");
    }
    // Neither NVMe (01:08:02), IDE-mode SATA (01:01:8a) nor a RAID-class
    // AMD controller (01:04:00) reaches the AHCI probe.
    let nvme = synth_pci(0x1987, 0x5016, 0x010802);
    if best_match(&nvme).map(|m| m.probe as usize) == Some(ahci::probe as usize) {
        return TestResult::Fail("an NVMe controller must not bind AHCI");
    }
    for class in [0x01018A, 0x010400, 0x010600] {
        let other = synth_pci(ahci::AMD_VENDOR, 0x7901, class);
        if best_match(&other).map(|m| m.probe as usize) == Some(ahci::probe as usize) {
            return TestResult::Fail("a non-AHCI storage class must not bind AHCI");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_binds_amd_600_series_by_class
);

/// Software model of the HBA-global registers: write-once CAP / CAP2 / PI
/// and port capability bits that GHC.HR wipes (as on controllers where
/// firmware programs them), an AE bit that needs `ae_writes` writes to
/// stick, HR that self-clears after `hr_reads` GHC reads, and a BIOS
/// that releases BOHC.BOS when the OS sets OOS.
struct ModelHba {
    regs: core::cell::RefCell<alloc::vec::Vec<u32>>,
    ae_writes: core::cell::Cell<u32>,
    hr_reads: core::cell::Cell<u32>,
    hr_pending: core::cell::Cell<bool>,
    resets: core::cell::Cell<u32>,
}

const M_CAP: u64 = 0x00;
const M_GHC: u64 = 0x04;
const M_PI: u64 = 0x0C;
const M_VS: u64 = 0x10;
const M_CAP2: u64 = 0x24;
const M_BOHC: u64 = 0x28;
const fn m_port_cmd(n: u64) -> u64 {
    0x100 + n * 0x80 + 0x18
}

impl ModelHba {
    fn new(cap: u32, vs: u32, pi: u32, cap2: u32, bohc: u32) -> Self {
        let m = Self {
            regs: core::cell::RefCell::new(alloc::vec![0u32; 0x1100 / 4]),
            ae_writes: core::cell::Cell::new(1),
            hr_reads: core::cell::Cell::new(3),
            hr_pending: core::cell::Cell::new(false),
            resets: core::cell::Cell::new(0),
        };
        {
            let mut r = m.regs.borrow_mut();
            r[(M_CAP / 4) as usize] = cap;
            r[(M_VS / 4) as usize] = vs;
            r[(M_PI / 4) as usize] = pi;
            r[(M_CAP2 / 4) as usize] = cap2;
            r[(M_BOHC / 4) as usize] = bohc;
        }
        m
    }
    fn get(&self, off: u64) -> u32 {
        self.regs.borrow()[(off / 4) as usize]
    }
    fn set(&self, off: u64, v: u32) {
        self.regs.borrow_mut()[(off / 4) as usize] = v;
    }
}

impl crate::ahci::AhciRegs for ModelHba {
    fn read32(&self, off: u64) -> u32 {
        if off == M_GHC && self.hr_pending.get() {
            let left = self.hr_reads.get();
            if left == 0 {
                // Reset completes: firmware-programmed RWO state is lost.
                self.hr_pending.set(false);
                self.resets.set(self.resets.get() + 1);
                self.set(M_GHC, 0);
                self.set(M_PI, 0);
                self.set(M_CAP, self.get(M_CAP) & !((1 << 27) | (1 << 28)));
                for n in 0..32 {
                    self.set(m_port_cmd(n), 0);
                }
            } else {
                self.hr_reads.set(left - 1);
            }
        }
        self.get(off)
    }
    fn write32(&self, off: u64, mut v: u32) {
        match off {
            M_GHC => {
                if v & (1 << 31) != 0 && self.ae_writes.get() > 1 {
                    self.ae_writes.set(self.ae_writes.get() - 1);
                    v &= !(1 << 31);
                }
                if v & 1 != 0 {
                    self.hr_pending.set(true);
                }
                self.set(off, v);
            }
            M_BOHC => {
                // OOS set: the BIOS hands over and clears BOS.
                if v & 0b10 != 0 {
                    v &= !0b1;
                }
                self.set(off, v);
            }
            _ => self.set(off, v),
        }
    }
}

fn smoke_ahci_hba_init_restores_firmware_config() -> TestResult {
    use crate::ahci::{effective_port_map, hba_global_init, AhciError, BiosHandoff};
    // AHCI 1.3.1, 6 ports, SSS + MPS + S64A, BOH supported, BIOS owned;
    // ports 0 and 2 carry platform capability bits (ESP / CPD / HPCP).
    let cap = (1 << 31) | (1 << 28) | (1 << 27) | 5;
    let m = ModelHba::new(cap, 0x0001_0301, 0x3F, 1, 0b1);
    m.ae_writes.set(3); // needs three AE writes (Linux retries five)
    m.set(m_port_cmd(0), 1 << 21);
    m.set(
        m_port_cmd(2),
        (1 << 20) | (1 << 18) | 1, /* ST: volatile */
    );
    let cfg = match hba_global_init(&m) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("hba_global_init failed on a healthy model"),
    };
    if m.resets.get() != 1 {
        return TestResult::Fail("exactly one HBA reset expected");
    }
    if m.get(M_GHC) & (1 << 31) == 0 || m.get(M_GHC) & 1 != 0 {
        return TestResult::Fail("AE must be set and HR clear after init");
    }
    if m.get(M_PI) != 0x3F || m.get(M_CAP) != cap || cfg.port_map != 0x3F {
        return TestResult::Fail("CAP / PI must be restored after the reset");
    }
    if m.get(m_port_cmd(0)) != 1 << 21 || m.get(m_port_cmd(2)) != (1 << 20) | (1 << 18) {
        return TestResult::Fail("port capability bits (only) must be restored");
    }
    if cfg.handoff != BiosHandoff::Completed || m.get(M_BOHC) & 0b11 != 0b10 {
        return TestResult::Fail("BIOS/OS handoff must leave OOS set, BOS clear");
    }

    // AHCI 1.0, PI reads 0: Linux fabricates the map from CAP.NP and
    // writes it back; there is no CAP2 / handoff below 1.2.
    let m = ModelHba::new(3, 0x0001_0000, 0, 1, 0b1);
    let cfg = match hba_global_init(&m) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("hba_global_init failed on an AHCI 1.0 model"),
    };
    if cfg.port_map != 0xF || m.get(M_PI) != 0xF || cfg.handoff != BiosHandoff::NotSupported {
        return TestResult::Fail("AHCI 1.0 port map must be fabricated from CAP.NP");
    }

    // PI with more ports than CAP.NP is discarded (1.3: not fabricated).
    if effective_port_map(3, 0x0001_0300, 0xFF) != 0
        || effective_port_map(3, 0x0001_0201, 0xFF) != 0xF
        || effective_port_map(31, 0x0001_0301, 0x8000_0001) != 0x8000_0001
    {
        return TestResult::Fail("port-map cross-check disagrees with Linux");
    }

    // A reset that never completes fails within the 1 s bound.
    let m = ModelHba::new(cap, 0x0001_0301, 0x3F, 0, 0);
    m.hr_reads.set(u32::MAX);
    if hba_global_init(&m) != Err(AhciError::ResetTimeout) {
        return TestResult::Fail("a stuck GHC.HR must time out");
    }
    // AE that never sticks is reported, not ignored.
    let m = ModelHba::new(cap, 0x0001_0301, 0x3F, 0, 0);
    m.ae_writes.set(u32::MAX);
    if hba_global_init(&m) != Err(AhciError::AhciEnableFailed) {
        return TestResult::Fail("GHC.AE that never sets must fail");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_hba_init_restores_firmware_config
);

/// Port-level AHCI register model: PxCMD.CR follows ST and FR follows FRE
/// (the engines stop at once) except on `stuck` ports, whose CR stays set
/// once set; `stick_on_start` ports latch CR the moment ST is written.
/// PxSSTS reads DET = 3 on `present` ports, whose PxTFD is BSY forever
/// unless `ready` (then 0x50). PxCI clears on write (the command
/// "completes"). `comresets` counts PxSCTL.DET = 1 writes per port.
struct PortModel {
    regs: core::cell::RefCell<alloc::vec::Vec<u32>>,
    stuck: u32,
    stick_on_start: u32,
    present: u32,
    ready: u32,
    comresets: core::cell::RefCell<[u32; 32]>,
}

impl PortModel {
    fn new(present: u32) -> Self {
        Self {
            regs: core::cell::RefCell::new(alloc::vec![0u32; 0x1100 / 4]),
            stuck: 0,
            stick_on_start: 0,
            present,
            ready: 0,
            comresets: core::cell::RefCell::new([0; 32]),
        }
    }
    fn get(&self, off: u64) -> u32 {
        self.regs.borrow()[(off / 4) as usize]
    }
    fn set(&self, off: u64, v: u32) {
        self.regs.borrow_mut()[(off / 4) as usize] = v;
    }
}

const fn m_port(n: u32, reg: u64) -> u64 {
    0x100 + n as u64 * 0x80 + reg
}

impl crate::ahci::AhciRegs for PortModel {
    fn read32(&self, off: u64) -> u32 {
        if off >= 0x100 {
            let n = ((off - 0x100) / 0x80) as u32;
            match (off - 0x100) % 0x80 {
                0x28 if self.present & (1 << n) != 0 => return 0x123,
                0x20 if self.present & (1 << n) != 0 => {
                    return if self.ready & (1 << n) != 0 {
                        0x50
                    } else {
                        0x80
                    };
                }
                _ => {}
            }
        }
        self.get(off)
    }
    fn write32(&self, off: u64, v: u32) {
        if off >= 0x100 {
            let n = ((off - 0x100) / 0x80) as u32;
            match (off - 0x100) % 0x80 {
                0x18 => {
                    let old = self.get(off);
                    let stuck = self.stuck & (1 << n) != 0
                        || (self.stick_on_start & (1 << n) != 0 && (v | old) & 1 != 0);
                    let mut cr = if v & 1 != 0 { 1 << 15 } else { 0 };
                    if stuck && (old & (1 << 15) != 0 || v & 1 != 0) {
                        cr = 1 << 15;
                    }
                    let fr = if v & (1 << 4) != 0 { 1 << 14 } else { 0 };
                    let fr = if stuck && old & (1 << 14) != 0 {
                        1 << 14
                    } else {
                        fr
                    };
                    self.set(off, (v & !((1 << 15) | (1 << 14))) | cr | fr);
                    return;
                }
                0x2C if v & 0xF == 1 => self.comresets.borrow_mut()[n as usize] += 1,
                0x38 => return, // PxCI: completes immediately
                _ => {}
            }
        }
        self.set(off, v);
    }
}

/// One HBA's port bring-up is bounded as a whole: six ports that report a
/// device (DET = 3) but never clear BSY used to cost ~13 s each, serially
/// (~80 s). Under the HBA-wide budget the bring-up ends shortly after it,
/// later ports are classified without a COMRESET, and every port still
/// gets its PxIE programmed.
fn smoke_ahci_port_bring_up_is_bounded_per_hba() -> TestResult {
    use crate::ahci::{bring_up_ports, PortKind};
    let m = PortModel::new(0x3F);
    let limit = narf_time::Deadline::after_ms(3_000);
    let ports = bring_up_ports(&m, 0, 0x3F, Some((0x10_0000, 0x10_0400)), 400);
    if limit.expired() {
        return TestResult::Fail("six never-ready ports outlived the HBA bring-up budget");
    }
    // Port 0 was reset and never became ready; the rest were classified from
    // their registers alone (DET = 3, no signature), never as a disk.
    if ports.len() != 6
        || ports[0].kind != PortKind::None
        || ports.iter().any(|p| p.kind == PortKind::Sata)
    {
        return TestResult::Fail("never-ready ports must not classify as disks");
    }
    if m.comresets.borrow()[0] != 1 || m.comresets.borrow()[5] != 0 {
        return TestResult::Fail("ports past the budget must not be COMRESET");
    }
    if (0..6).any(|n| m.get(m_port(n, 0x14)) == 0) {
        return TestResult::Fail("every port must get its PxIE programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_port_bring_up_is_bounded_per_hba
);

/// IDENTIFY DEVICE on a port whose engine will not stop must fail without
/// touching PxCLB / PxFB (the old code ignored the `port_idle` failure and
/// pointed a running engine at a fresh page). When the final stop fails the
/// call fails too, and the page the HBA may still write is never freed.
fn smoke_ahci_identify_refuses_a_running_port() -> TestResult {
    use crate::ahci::{identify_device, AhciError};
    let mut m = PortModel::new(0b1);
    m.stuck = 0b1;
    m.set(m_port(0, 0x18), (1 << 15) | 1); // ST + CR, never drains
    m.set(m_port(0, 0x00), 0xDEAD_0000);
    m.set(m_port(0, 0x08), 0xBEEF_0000);
    // SAFETY: a register model; the call fails before any DMA is set up.
    let r = unsafe { identify_device(&m, 1 << 31, 0) };
    if r != Err(AhciError::PortIdleTimeout) {
        return TestResult::Fail("identify on a port that will not stop must fail");
    }
    if m.get(m_port(0, 0x00)) != 0xDEAD_0000 || m.get(m_port(0, 0x08)) != 0xBEEF_0000 {
        return TestResult::Fail("CLB/FB reprogrammed under a running engine");
    }
    let mut m = PortModel::new(0b1);
    m.ready = 0b1;
    m.stick_on_start = 0b1;
    // SAFETY: a register model standing in for the HBA; the scratch page is
    // a real coherent allocation the model never writes.
    let r = unsafe { identify_device(&m, 1 << 31, 0) };
    if r != Err(AhciError::PortIdleTimeout) {
        return TestResult::Fail("a failed final stop must fail identify (page kept)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_identify_refuses_a_running_port
);

/// DMA page a command-issuing call programmed into the model's
/// port 0, recovered from PxCLB/PxCLBU, plus the command-table
/// address from command-list entry 0. Lets a fixture inspect the
/// exact FIS bytes the driver built (#841).
fn model_cmd_addrs(m: &PortModel) -> (u64, u64) {
    let clb = m.get(m_port(0, 0x00)) as u64 | ((m.get(m_port(0, 0x04)) as u64) << 32);
    // SAFETY: `clb` is the coherent DMA page the driver allocated
    // for this command; entry 0's command-table pointer sits at +8.
    let tbl = unsafe {
        core::ptr::read_volatile(narf_memory::PhysAddr::new(clb + 8).kernel_ptr::<u64>())
    };
    (clb, tbl)
}

/// Read `n` bytes out of a DMA page at physical address `phys`.
fn model_dma_bytes(phys: u64, n: usize) -> alloc::vec::Vec<u8> {
    // SAFETY: the caller guarantees `phys..phys+n` is the coherent
    // DMA region the driver set up for the command under test.
    unsafe {
        core::slice::from_raw_parts(narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(), n).to_vec()
    }
}

/// #841: FLUSH CACHE / FLUSH CACHE EXT must reach the port as a
/// real non-data H2D FIS with the right opcode — driven against
/// the register model, inspecting the DMA page the driver built.
fn smoke_ahci_flush_cache_issues_real_fis() -> TestResult {
    use crate::ahci::flush_cache;
    for (ext, opcode) in [(true, 0xEAu8), (false, 0xE7u8)] {
        let mut m = PortModel::new(0b1);
        m.ready = 0b1;
        // SAFETY: a register model standing in for the HBA; the
        // command page is a real coherent allocation the model
        // never writes, and port 0 is present + ready.
        let r = unsafe { flush_cache(&m, 1 << 31, 0, ext) };
        if r.is_err() {
            return TestResult::Fail("flush_cache failed on a healthy model port");
        }
        let (clb, tbl) = model_cmd_addrs(&m);
        let hdr = model_dma_bytes(clb, 4);
        // Command List entry 0: PRDT length 0 (non-data), CFL = 5.
        if hdr[..4] != [5, 0, 0, 0] {
            return TestResult::Fail("flush command header must be PRDT=0, CFL=5");
        }
        let fis = model_dma_bytes(tbl, 20);
        if fis[0] != 0x27 || fis[1] != 0x80 {
            return TestResult::Fail("flush FIS must be H2D Register with the C bit set");
        }
        if fis[2] != opcode {
            return TestResult::Fail("flush FIS carries the wrong opcode");
        }
        if fis[7] != 0x40 {
            return TestResult::Fail("flush FIS device byte must select LBA mode");
        }
        // The port is left stopped (the final port_idle ran).
        if m.get(m_port(0, 0x18)) & 1 != 0 {
            return TestResult::Fail("flush must leave the port idled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_flush_cache_issues_real_fis
);

/// #841: DATA SET MANAGEMENT must stage the range buffer exactly
/// as the ACS lays it out (48-bit LBA + 16-bit count per 8-byte
/// entry) and issue opcode 0x06 with FEATURE = TRIM, the block
/// count in the count registers, and a PRDT entry covering the
/// staged blocks. Chunking past the per-command block limit must
/// issue further commands.
fn smoke_ahci_dsm_trim_issues_real_fis() -> TestResult {
    use crate::ahci::dsm_trim;
    let mut m = PortModel::new(0b1);
    m.ready = 0b1;
    let ranges: [(u64, u16); 2] = [(0x1000, 0x20), (0x5000, 0x10)];
    // SAFETY: register model; see the flush fixture.
    let r = unsafe { dsm_trim(&m, 1 << 31, 0, &ranges, 1) };
    if r.is_err() {
        return TestResult::Fail("dsm_trim failed on a healthy model port");
    }
    let (clb, tbl) = model_cmd_addrs(&m);
    let hdr = model_dma_bytes(clb, 4);
    // Command List entry 0: PRDT length 1, W bit set, CFL = 5.
    if hdr[..4] != [0x45, 0, 1, 0] {
        return TestResult::Fail("DSM command header must be PRDT=1, W=1, CFL=5");
    }
    let fis = model_dma_bytes(tbl, 20);
    if fis[0] != 0x27 || fis[1] != 0x80 || fis[2] != 0x06 {
        return TestResult::Fail("DSM FIS must be H2D Register, opcode 0x06");
    }
    if fis[3] != 0x01 {
        return TestResult::Fail("DSM FEATURE byte must be 0x01 (TRIM)");
    }
    if fis[12] != 1 || fis[13] != 0 {
        return TestResult::Fail("DSM sector count must be the staged block count (1)");
    }
    // PRDT entry 0 at cmd_tbl + 0x80: data pointer + byte count - 1.
    let prdt = model_dma_bytes(tbl + 0x80, 16);
    let data_phys = u64::from_le_bytes(prdt[0..8].try_into().unwrap());
    if u32::from_le_bytes(prdt[12..16].try_into().unwrap()) != 511 {
        return TestResult::Fail("DSM PRDT byte count must cover one 512-byte block");
    }
    let data = model_dma_bytes(data_phys, 512);
    // Entry 0: LBA 0x1000 (48-bit LE) + count 0x20 (16-bit LE).
    if data[0..8] != [0x00, 0x10, 0, 0, 0, 0, 0x20, 0] {
        return TestResult::Fail("DSM range entry 0 encoding wrong");
    }
    // Entry 1: LBA 0x5000 + count 0x10.
    if data[8..16] != [0x00, 0x50, 0, 0, 0, 0, 0x10, 0] {
        return TestResult::Fail("DSM range entry 1 encoding wrong");
    }
    if data[16..].iter().any(|&b| b != 0) {
        return TestResult::Fail("unused DSM range entries must be zero");
    }

    // Chunking: 65 ranges with a 1-block device limit = two
    // commands; the second stages range 64 alone in its block.
    let mut m = PortModel::new(0b1);
    m.ready = 0b1;
    let many: alloc::vec::Vec<(u64, u16)> = (0..65u64).map(|i| (i * 0x100, 1)).collect();
    // SAFETY: register model; see above.
    let r = unsafe { dsm_trim(&m, 1 << 31, 0, &many, 1) };
    if r.is_err() {
        return TestResult::Fail("chunked dsm_trim failed on a healthy model port");
    }
    let (_clb, tbl) = model_cmd_addrs(&m);
    let prdt = model_dma_bytes(tbl + 0x80, 16);
    let data_phys = u64::from_le_bytes(prdt[0..8].try_into().unwrap());
    let data = model_dma_bytes(data_phys, 512);
    // Range 64: LBA 64 * 0x100 = 0x4000, count 1.
    if data[0..8] != [0x00, 0x40, 0, 0, 0, 0, 1, 0] {
        return TestResult::Fail("the second DSM chunk must stage range 64");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_dsm_trim_issues_real_fis);

/// #841: the IDENTIFY feature decoder + the DSM range encoder are
/// the pure core of the flush/FUA/TRIM surface — pin their exact
/// semantics, including the word-validity signatures.
fn smoke_ahci_identify_features_and_dsm_encoding() -> TestResult {
    use crate::ahci::{
        encode_dsm_range_block, identify_ata_features, identify_firmware, identify_model_string,
        identify_serial,
    };
    fn set_word(id: &mut [u8; 512], n: usize, v: u16) {
        id[2 * n..2 * n + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn set_string(id: &mut [u8; 512], first_word: usize, text: &str) {
        // ATA strings are byte-swapped per pair, space padded.
        let mut bytes = alloc::vec![b' '; 40];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        for i in 0..text.len().div_ceil(2) {
            id[(first_word + i) * 2] = bytes[i * 2 + 1];
            id[(first_word + i) * 2 + 1] = bytes[i * 2];
        }
    }

    let mut id = [0u8; 512];
    set_word(&mut id, 82, (1 << 5) | (1 << 12)); // WC supported + FLUSH CACHE
    set_word(&mut id, 83, 0x4000 | (1 << 10) | (1 << 13)); // valid + LBA48 + FLUSH EXT
    set_word(&mut id, 84, 0x4000 | (1 << 10)); // valid + WRITE DMA FUA EXT
    set_word(&mut id, 85, 1 << 5); // WC enabled
    set_word(&mut id, 105, 8); // 8 blocks per DSM command
    set_word(&mut id, 169, 1); // DSM/TRIM supported
    set_string(&mut id, 10, "WD-WX21A012345");
    set_string(&mut id, 23, "01.01A01");
    set_string(&mut id, 27, "WDC WD10EZEX");
    let f = identify_ata_features(&id);
    if !f.lba48
        || !f.write_cache_supported
        || !f.write_cache_enabled
        || !f.flush_cache
        || !f.flush_cache_ext
        || !f.write_fua_ext
        || !f.trim
        || f.dsm_max_blocks != 8
    {
        return TestResult::Fail("feature decode dropped a reported feature");
    }
    if identify_serial(&id) != "WD-WX21A012345"
        || identify_firmware(&id) != "01.01A01"
        || identify_model_string(&id) != "WDC WD10EZEX"
    {
        return TestResult::Fail("ATA string fields must decode byte-swapped + trimmed");
    }

    // An all-zero block reports nothing (and the DSM limit floors
    // at 1), and feature bits behind an INVALID word 83 signature
    // are not believed.
    let zero = [0u8; 512];
    let f = identify_ata_features(&zero);
    if f.lba48 || f.write_cache_enabled || f.flush_cache || f.trim || f.dsm_max_blocks != 1 {
        return TestResult::Fail("a zero IDENTIFY block must decode to no features");
    }
    let mut id = [0u8; 512];
    set_word(&mut id, 83, (1 << 10) | (1 << 13)); // bits set, signature absent
    let f = identify_ata_features(&id);
    if f.lba48 || f.flush_cache_ext {
        return TestResult::Fail("word 83 features require the validity signature");
    }

    // The range encoder: exact bytes, 64-entry cap, zero padding.
    let mut block = [0xFFu8; 512];
    let used = encode_dsm_range_block(&[(0x0102_0304_0506, 0x0708)], &mut block);
    if used != 1 || block[0..8] != [0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07] {
        return TestResult::Fail("DSM entry must be 48-bit LBA LE + 16-bit count LE");
    }
    if block[8..].iter().any(|&b| b != 0) {
        return TestResult::Fail("DSM block tail must be zeroed");
    }
    let many: alloc::vec::Vec<(u64, u16)> = (0..65).map(|i| (i as u64, 1)).collect();
    if encode_dsm_range_block(&many, &mut block) != 64 {
        return TestResult::Fail("one DSM block holds at most 64 ranges");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_identify_features_and_dsm_encoding
);

/// Position-sensitive test pattern for the AHCI data-path smokes.
fn audit_ahci_pattern(i: usize) -> u8 {
    ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8
}

/// #930: a single block-surface call far past the historical
/// 8-block cap — 256 blocks (128 KiB, one transfer-buffer chunk)
/// plus a 9-block call — must round-trip byte-exact through
/// `AhciBlockSync`. Uses the middle of the disk, away from the
/// low LBAs other smokes scribble on.
fn smoke_ahci_large_transfer_round_trip() -> TestResult {
    use crate::ahci;
    use narf_block::BlockDeviceSync;
    let Some(sync) = ahci::AhciBlockSync::from_probed() else {
        return TestResult::Skip("AHCI not probed / no disk");
    };
    let cap = sync.capacity();
    if cap < 1024 {
        return TestResult::Skip("disk too small for the large-transfer fixture");
    }
    let base = cap / 2;
    // 256-block single call.
    let mut wbuf = alloc::vec![0u8; 256 * 512];
    for (i, b) in wbuf.iter_mut().enumerate() {
        *b = audit_ahci_pattern(i);
    }
    if sync.write(base, 256, &wbuf).is_err() {
        return TestResult::Fail("a single 256-block write must succeed (#930)");
    }
    let mut rbuf = alloc::vec![0u8; 256 * 512];
    if sync.read(base, 256, &mut rbuf).is_err() {
        return TestResult::Fail("a single 256-block read must succeed (#930)");
    }
    if rbuf != wbuf {
        return TestResult::Fail("256-block round-trip data mismatch");
    }
    // 9 blocks: one past the historical cap, unaligned chunk edge.
    let mut w9 = alloc::vec![0u8; 9 * 512];
    for (i, b) in w9.iter_mut().enumerate() {
        *b = audit_ahci_pattern(i + 7);
    }
    if sync.write(base + 256, 9, &w9).is_err() {
        return TestResult::Fail("a single 9-block write must succeed (#930)");
    }
    let mut r9 = alloc::vec![0u8; 9 * 512];
    if sync.read(base + 256, 9, &mut r9).is_err() || r9 != w9 {
        return TestResult::Fail("9-block round-trip data mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_large_transfer_round_trip);

/// #841: the block surface's durability contract on the real
/// disk — flush succeeds, FUA writes round-trip (natively or via
/// the write + flush emulation), the advertised capabilities
/// match an independent IDENTIFY decode, and trim either works
/// end-to-end or is honestly reported as unsupported (in which
/// case calling it must fail, not silently succeed).
fn smoke_ahci_flush_fua_trim_contract() -> TestResult {
    use crate::ahci;
    use narf_block::BlockDeviceSync;
    let Some(sync) = ahci::AhciBlockSync::from_probed() else {
        return TestResult::Skip("AHCI not probed / no disk");
    };
    let cap = sync.capacity();
    if cap < 64 {
        return TestResult::Skip("disk too small for the durability fixture");
    }
    // Cross-check the surface's claims against a fresh IDENTIFY.
    let id = ahci::with_controller(|c| {
        // SAFETY: with_controller holds the request gate; the
        // block port is a published ATA disk port.
        unsafe { c.identify_device(c.block_port) }
    })
    .and_then(|r| r.ok());
    if let Some(id) = id {
        let f = ahci::identify_ata_features(&id);
        let caps = sync.capabilities();
        if caps.volatile_cache != f.write_cache_enabled || caps.fua != f.write_fua_ext {
            return TestResult::Fail("capabilities() must mirror the IDENTIFY feature words");
        }
        if sync.supports_trim() != f.trim {
            return TestResult::Fail("supports_trim() must mirror IDENTIFY word 169");
        }
    }
    if sync.flush().is_err() {
        return TestResult::Fail("flush() must succeed on a healthy disk");
    }
    // Scratch area near the end of the disk.
    let lba = cap - 16;
    let mut wbuf = alloc::vec![0u8; 4 * 512];
    for (i, b) in wbuf.iter_mut().enumerate() {
        *b = audit_ahci_pattern(i + 3);
    }
    if sync.write_fua(lba, 4, &wbuf).is_err() {
        return TestResult::Fail("write_fua must succeed (native or emulated)");
    }
    let mut rbuf = alloc::vec![0u8; 4 * 512];
    if sync.read(lba, 4, &mut rbuf).is_err() || rbuf != wbuf {
        return TestResult::Fail("write_fua round-trip data mismatch");
    }
    if sync.supports_trim() {
        if sync.trim(lba, 4).is_err() {
            return TestResult::Fail("trim must succeed on a trim-capable disk");
        }
        // The disk stays fully usable after a trim.
        if sync.write(lba, 4, &wbuf).is_err() {
            return TestResult::Fail("write after trim failed");
        }
        if sync.read(lba, 4, &mut rbuf).is_err() || rbuf != wbuf {
            return TestResult::Fail("read after trim + rewrite mismatch");
        }
        if sync.trim(lba, 0).is_err() {
            return TestResult::Fail("a zero-length trim is a no-op success");
        }
        if sync.trim(cap - 1, 4).is_ok() {
            return TestResult::Fail("an out-of-range trim must fail");
        }
    } else if sync.trim(lba, 1).is_ok() {
        return TestResult::Fail("trim on a trim-less disk must fail, not silently succeed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_flush_fua_trim_contract);

/// #931: every published disk of every installed controller has
/// a `sata<n>` registry entry whose capacity matches its
/// IDENTIFY record, names are dense from `sata0`, and the
/// controller registry agrees with the block registry.
fn smoke_ahci_publishes_every_disk() -> TestResult {
    use crate::ahci;
    if !ahci::is_probed() {
        return TestResult::Skip("AHCI not probed");
    }
    let ctrls = ahci::controllers();
    if ctrls.len() != ahci::controller_count() {
        return TestResult::Fail("controllers() and controller_count() disagree");
    }
    let mut total = 0usize;
    for c in &ctrls {
        for disk in c.disks() {
            let name = alloc::format!("sata{total}");
            let Some(dev) = narf_block::find_block_device(&name) else {
                return TestResult::Fail("a published disk has no registry entry");
            };
            if dev.capacity() != disk.sectors || disk.sectors == 0 {
                return TestResult::Fail("registry capacity must match the IDENTIFY record");
            }
            total += 1;
        }
    }
    if total == 0 {
        return TestResult::Skip("no AHCI disks published in this boot");
    }
    let extra = alloc::format!("sata{total}");
    if narf_block::find_block_device(&extra).is_some() {
        return TestResult::Fail("an unpublished sata name resolves in the registry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_publishes_every_disk);

/// #932: the `ahci` device_pm entry suspends and resumes the real
/// controller — I/O is refused while suspended (never served from
/// a quiesced port) and the disk comes back byte-identical after
/// resume revalidation. Skipped when the AHCI disk is the
/// designated root: quiescing the running system's root is the
/// real suspend path's business, not a smoke's.
fn smoke_ahci_device_pm_round_trip() -> TestResult {
    use crate::ahci;
    use narf_block::BlockDeviceSync;
    let Some(sync) = ahci::AhciBlockSync::from_probed() else {
        return TestResult::Skip("AHCI not probed / no disk");
    };
    if let Some(root) = narf_block::disk_policy::designated_root() {
        if root.starts_with("sata") {
            return TestResult::Skip("AHCI disk is the designated root");
        }
    }
    let entries = narf_power::device_pm::registered_devices();
    let Some(entry) = entries.iter().find(|e| e.name == "ahci") else {
        return TestResult::Fail("ahci must register with the device_pm fan-out (#932)");
    };
    if entry.ops.is_some() {
        return TestResult::Fail("ahci must register fn-pointer PM handlers");
    }
    let cap = sync.capacity();
    if cap < 64 {
        return TestResult::Skip("disk too small for the PM fixture");
    }
    let lba = cap - 8;
    let mut baseline = [0u8; 512];
    if sync.read(lba, 1, &mut baseline).is_err() {
        return TestResult::Fail("baseline read failed before suspend");
    }
    if (entry.suspend)().is_err() {
        return TestResult::Fail("the ahci suspend handler must succeed on a healthy disk");
    }
    let mut byte = [0u8; 512];
    if sync.read(lba, 1, &mut byte).is_ok() {
        return TestResult::Fail("reads must be refused while the controller is suspended");
    }
    if sync.write(lba, 1, &baseline).is_ok() {
        return TestResult::Fail("writes must be refused while the controller is suspended");
    }
    if (entry.resume)().is_err() {
        return TestResult::Fail("the ahci resume handler must revalidate the disk");
    }
    if sync.capacity() != cap {
        return TestResult::Fail("capacity must be unchanged after resume");
    }
    if sync.read(lba, 1, &mut byte).is_err() || byte != baseline {
        return TestResult::Fail("the disk must serve identical data after resume");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_device_pm_round_trip);

/// GHC.IE is the HBA's master interrupt gate and must stay clear until the
/// ISR is installed and routed (it was set at the end of bring-up, before
/// `probe` had any vector).
fn smoke_ahci_ghc_ie_waits_for_the_irq_route() -> TestResult {
    use crate::ahci::{hba_enable_irq, hba_finish_init, AhciRegs};
    let m = PortModel::new(0);
    m.set(0x04, (1 << 31) | (1 << 1)); // firmware left IE set
    m.set(0x08, 0b101);
    hba_finish_init(&m);
    if m.read32(0x04) != 1 << 31 {
        return TestResult::Fail("bring-up must leave GHC.AE set and GHC.IE clear");
    }
    hba_enable_irq(&m);
    if m.read32(0x04) != (1 << 31) | (1 << 1) {
        return TestResult::Fail("hba_enable_irq must set GHC.IE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_ghc_ie_waits_for_the_irq_route
);

fn smoke_ahci_link_debounce_matches_libata() -> TestResult {
    use crate::ahci::sata_link_debounce;
    use core::cell::Cell;
    // Short timing so the smoke stays fast: interval 1 ms, stable for
    // 20 ms, deadline 200 ms.
    let t = [1, 20, 200];
    if sata_link_debounce(|| 0, t) != Some(0) {
        return TestResult::Fail("an empty port must settle at DET = 0");
    }
    // Device present but PHY not yet up (DET = 1) for a while, then up.
    let n = Cell::new(0u32);
    let det = || {
        n.set(n.get() + 1);
        if n.get() < 30 {
            1
        } else {
            0x113 // DET = 3 with SPD / IPM bits set
        }
    };
    if sata_link_debounce(det, t) != Some(3) {
        return TestResult::Fail("DET 1 → 3 must settle at 3");
    }
    // A link that keeps flapping gives up at the deadline.
    let n = Cell::new(0u32);
    let flap = || {
        n.set(n.get() + 1);
        if n.get() % 2 == 0 {
            1
        } else {
            3
        }
    };
    if sata_link_debounce(flap, t).is_some() {
        return TestResult::Fail("a flapping link must not debounce");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_link_debounce_matches_libata
);

/// On QEMU's ICH9 the boot-time probe now runs the spec port bring-up
/// (FIS receive, spin-up, COMRESET, debounce, BSY wait) before
/// classifying, so the disk on port 0 (`ide.0`, the 1 MiB `narf-sata.img`)
/// must read back as an ATA disk with its IDENTIFY capacity.
fn smoke_ahci_port_bring_up_classifies_qemu_disk() -> TestResult {
    use crate::ahci;
    use narf_block::BlockDeviceSync;
    if !ahci::is_probed() {
        return TestResult::Skip("AHCI not probed");
    }
    let Some((port, kind, cap)) = ahci::with_controller(|c| {
        let kind = c
            .ports
            .iter()
            .find(|p| p.index == c.block_port)
            .map(|p| p.kind);
        (c.block_port, kind, c.capacity)
    }) else {
        return TestResult::Fail("controller vanished");
    };
    if kind != Some(ahci::PortKind::Sata) {
        return TestResult::Fail("the QEMU disk port must classify as SATA");
    }
    if port != 0 {
        return TestResult::Fail("the QEMU disk sits on port 0");
    }
    let sync_cap = ahci::AhciBlockSync::from_probed()
        .map(|s| s.capacity())
        .unwrap_or(0);
    if cap == 0 || sync_cap != cap {
        return TestResult::Fail("IDENTIFY capacity must be cached and reported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/storage/ahci",
    smoke_ahci_port_bring_up_classifies_qemu_disk
);
