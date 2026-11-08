use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn pci(device: u16, subsystem: (u16, u16)) -> narf_bus::DeviceId {
    narf_bus::DeviceId {
        vendor: 0x14e4,
        device,
        subsystem_vendor: subsystem.0,
        subsystem_id: subsystem.1,
        class: 0x028000,
    }
}

/// Linux `brcmf_chip_tcm_rambase` / `brcmf_pcie_fwnames` literal rows.
fn smoke_brcmf_chip_profile_linux_rambase_and_firmware_rows() -> TestResult {
    for (chip, rev, base) in [
        (BRCM_CC_43602, 1, Some(0x180000)),
        (BRCM_CC_4350, 8, Some(0x180000)),
        (BRCM_CC_4356, 2, Some(0x180000)),
        (BRCM_CC_4366, 4, Some(0x200000)),
        (BRCM_CC_4359, 8, Some(0x180000)),
        (BRCM_CC_4359, 9, Some(0x160000)),
        (0x4345, 6, Some(0x198000)),
        (BRCM_CC_4387, 7, Some(0x740000)),
        (43439, 0, None),
    ] {
        if tcm_rambase(chip, rev) != base {
            return TestResult::Fail("RAM base differs from brcmf_chip_tcm_rambase");
        }
    }
    for (chip, rev, name) in [
        (BRCM_CC_43602, 1, Some("brcmfmac43602-pcie")),
        (BRCM_CC_4350, 7, Some("brcmfmac4350c2-pcie")),
        (BRCM_CC_4350, 8, Some("brcmfmac4350-pcie")),
        (BRCM_CC_4356, 2, Some("brcmfmac4356-pcie")),
        (BRCM_CC_4366, 3, Some("brcmfmac4366b-pcie")),
        (BRCM_CC_4366, 4, Some("brcmfmac4366c-pcie")),
        (BRCM_CC_43664, 3, None),
        (BRCM_CC_4355, 13, Some("brcmfmac54591-pcie")),
        (BRCM_CC_4355, 12, Some("brcmfmac4355c1-pcie")),
        (BRCM_CC_4354, 1, None),
        (BRCM_CC_4356, 32, None),
    ] {
        if firmware(chip, rev).map(|row| row.base) != name {
            return TestResult::Fail("firmware row differs from brcmf_fw_alloc_request");
        }
    }
    if !firmware(BRCM_CC_4356, 2).unwrap().clm || firmware(BRCM_CC_4366, 4).unwrap().clm {
        return TestResult::Fail("BRCMF_FW_CLM_DEF marking differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_linux_rambase_and_firmware_rows
);

/// Covered chips, CPU kind, PCI vendor/seed admission and Linux asset names.
fn smoke_brcmf_chip_profile_admission_and_asset_names() -> TestResult {
    let cases = [
        (
            BRCM_CC_43602,
            1,
            pci(0x43ba, (0x106b, 0x0133)),
            Some(Some(Cpu::Cr4)),
        ),
        (
            BRCM_CC_4350,
            8,
            pci(0x43a3, (0x1028, 0x0023)),
            Some(Some(Cpu::Cr4)),
        ),
        (
            BRCM_CC_4356,
            2,
            pci(0x43ec, (0x17aa, 0x0777)),
            Some(Some(Cpu::Cr4)),
        ),
        (
            BRCM_CC_4366,
            4,
            pci(0x43c3, (0x1043, 0x86fb)),
            Some(Some(Cpu::Ca7)),
        ),
        // 4354 raw PCI id binds in Linux, but no PCIe firmware row exists.
        (BRCM_CC_4354, 1, pci(0x4354, (0, 0)), None),
        // OTP board selection is not part of the chip-only admission:
        // `admit()` is the PCI/profile lookup Linux performs for OTP
        // chips too (`BRCMF_PCIE_DEVICE(BRCM_PCIE_4364_DEVICE_ID,
        // WCC_SEED)`); the OTP gate lives in `BoardProfile::admits`
        // and the signed selection claim, not here.
        (BRCM_CC_4364, 4, pci(0x4464, (0x106b, 0x07bf)), Some(None)),
        // BCM43752 (seeded PCI id): no CPU table fact, Linux dispatch.
        (BRCM_CC_43752, 1, pci(0x449d, (0, 0)), Some(None)),
        // Linux keys the seed on the PCI id, so a covered chip under a
        // seeded id is admitted (with the footer); a CYW id is refused.
        (BRCM_CC_4356, 2, pci(0x449d, (0, 0)), Some(Some(Cpu::Cr4))),
        (BRCM_CC_4356, 2, pci(0x4415, (0, 0)), None),
        // Unknown PCI id or a non-network class never matches.
        (BRCM_CC_4356, 2, pci(0x43df, (0, 0)), None),
    ];
    for (chip, rev, id, cpu) in cases {
        if admit(chip, rev, &id).map(|(p, _)| p.cpu) != cpu {
            return TestResult::Fail("chip/PCI admission differs from the Linux tables");
        }
    }
    let mut class = pci(0x43ec, (0, 0));
    class.class = 0x020000;
    if admit(BRCM_CC_4356, 2, &class).is_some() {
        return TestResult::Fail("PCI class mask ignored");
    }
    if admit(BRCM_CC_4366, 4, &pci(0x43c3, (0, 0))).map(|(_, v)| v) != Some(FwVendor::Bca)
        || pci_match(&pci(0x4365, (0x14e4, 0x4365))).map(|m| m.vendor) != Some(FwVendor::Bca)
        || pci_match(&pci(0x4365, (0x14e4, 0x4366))).is_some()
    {
        return TestResult::Fail("drvdata vendor / SUB match differs");
    }
    let base = "brcmfmac4356-pcie";
    for (key, ext, ok) in [
        ("brcm/brcmfmac4356-pcie.bin", "bin", true),
        ("brcm/brcmfmac4356-pcie.lenovo,x1.txt", "txt", true),
        ("brcm/brcmfmac4356-pcie..txt", "txt", false),
        ("brcm/brcmfmac4356-pcie.a/b.txt", "txt", false),
        ("brcm/brcmfmac4356-pciex.bin", "bin", false),
        ("brcmfmac4356-pcie.bin", "bin", false),
        ("brcm/brcmfmac4356-pcie.bin", "txt", false),
    ] {
        if linux_asset_name(base, key, ext) != ok {
            return TestResult::Fail("Linux asset name rule differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_admission_and_asset_names
);

use super::super::{boot, chip};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const ROM: u32 = 0x1810_0000;
const CPU: u32 = 0x1800_2000;
const CPU_WRAP: u32 = 0x1811_4000;
const MEM: u32 = 0x1800_4000;
const MEM_WRAP: u32 = 0x1811_6000;
const D11: u32 = 0x1800_6000;
const D11_WRAP: u32 = 0x1811_8000;

/// Plain register/TCM model of a discovered AI chip. Firmware publishes the
/// shared address in the RAM tail once the ARM leaves HALT after the reset
/// vector reached TCM0.
struct Model {
    registers: BTreeMap<u32, u32>,
    tcm: BTreeMap<u32, u8>,
    writes: Vec<(u32, u32)>,
    tcm_writes: Vec<(u32, usize)>,
    rstvec: bool,
    tail: u32,
    shared: u32,
    extent: u32,
}
impl chip::Backplane for Model {
    fn read32(&mut self, at: u32) -> Result<u32, chip::Error> {
        Ok(*self.registers.get(&at).unwrap_or(&0))
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), chip::Error> {
        self.registers.insert(at, value);
        self.writes.push((at, value));
        if at == CPU_WRAP + 0x408 && value & 0x20 == 0 && self.rstvec {
            let shared = self.shared.to_le_bytes();
            for (i, b) in shared.iter().enumerate() {
                self.tcm.insert(self.tail + i as u32, *b);
            }
        }
        Ok(())
    }
}
impl boot::Bus for Model {
    fn tcm_extent(&self) -> u32 {
        self.extent
    }
    fn read_tcm(&mut self, at: u32, bytes: &mut [u8]) -> Result<(), boot::Error> {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.tcm.get(&(at + i as u32)).unwrap_or(&0);
        }
        Ok(())
    }
    fn write_tcm(&mut self, at: u32, bytes: &[u8]) -> Result<(), boot::Error> {
        for (i, b) in bytes.iter().enumerate() {
            self.tcm.insert(at + i as u32, *b);
        }
        self.tcm_writes.push((at, bytes.len()));
        if at == 0 && bytes == [0x44, 0x33, 0x22, 0x11] {
            self.rstvec = true;
        }
        Ok(())
    }
    fn dma_enabled(&mut self) -> Result<bool, boot::Error> {
        Ok(false)
    }
}
/// EROM: ChipCommon, PCIe2, the ARM (`cpu`), an optional memory core
/// (`mem`: SYS_MEM / SOCRAM) and one D11, each with one slave wrapper.
fn model(identity: u32, cpu: u16, mem: Option<u16>, base: u32) -> Model {
    let mut registers = BTreeMap::new();
    registers.insert(chip::ENUM_BASE, identity);
    registers.insert(chip::ENUM_BASE + 0xfc, ROM);
    let mut erom = alloc::vec![
        0x4bf80001,
        0x28080001,
        0x18000005,
        0x18110085,
        0x4bf83c01,
        0x0d004001,
        3,
        0x18012005,
        0x181120c5,
        0x4bf80001 | u32::from(cpu) << 8,
        0x07080001,
        CPU | 5,
        CPU_WRAP | 0x85,
    ];
    if let Some(mem) = mem {
        erom.extend_from_slice(&[
            0x4bf80001 | u32::from(mem) << 8,
            0x14080001,
            MEM | 5,
            MEM_WRAP | 0x85,
        ]);
    }
    erom.extend_from_slice(&[0x4bf81201, 0x18080001, D11 | 5, D11_WRAP | 0x85, 15]);
    for (i, w) in erom.into_iter().enumerate() {
        registers.insert(ROM + i as u32 * 4, w);
    }
    // CR4: two A-banks of (15+1)*8 KiB; SYS_MEM: SRCI_SRNB=2, same banks.
    registers.insert(CPU + 4, 2);
    registers.insert(CPU + 0x44, 15);
    registers.insert(MEM, 2 << 4);
    registers.insert(MEM + 0x40, 15);
    let size = 2 * 16 * 8192;
    let mut tcm = BTreeMap::new();
    let shared = base + 0x100;
    let mut info = [0u8; 76];
    info[0..4].copy_from_slice(&6u32.to_le_bytes());
    info[40..44].copy_from_slice(&(base + 0x500).to_le_bytes());
    info[44..48].copy_from_slice(&(base + 0x504).to_le_bytes());
    info[48..52].copy_from_slice(&(base + 0x200).to_le_bytes());
    for (i, b) in info.iter().enumerate() {
        tcm.insert(shared + i as u32, *b);
    }
    Model {
        registers,
        tcm,
        writes: Vec::new(),
        tcm_writes: Vec::new(),
        rstvec: false,
        tail: base + size - 4,
        shared,
        extent: base + size,
    }
}
fn board(chip: u16, revision: u8, device: u16) -> (boot::PciIdentity, boot::BoardProfile) {
    let pci = boot::PciIdentity {
        vendor: 0x14e4,
        device,
        subsystem_vendor: 0x17aa,
        subsystem_device: 0x0777,
    };
    (
        pci,
        boot::BoardProfile {
            chip,
            revision_mask: 1 << revision,
            pci,
            firmware: "brcm/fixture.bin",
            nvram: "brcm/fixture.txt",
        },
    )
}
const FIRMWARE: [u8; 8] = [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6];

/// BCM4350 CR4 (Linux 0x180000 base, TCM banks) and BCM4366 CA7 (0x200000
/// base, SYS_MEM banks) through the retained loader: firmware at the Linux
/// RAM base, reset vector at TCM0, no BCM43602 bank-PDA or SOCRAM step,
/// the CA7 D11 reset and SYS_MEM bring-up.
fn smoke_brcmf_chip_profile_cr4_and_ca7_boot_transcripts() -> TestResult {
    let nvram = match boot::pack_nvram(b"boardrev=0x1101\nboardtype=0x0777\n") {
        Ok(nvram) => nvram,
        Err(_) => return TestResult::Fail("fixture NVRAM did not pack"),
    };
    for (identity, chip_id, revision, device, cpu, mem, base) in [
        (
            0x1008_4350,
            BRCM_CC_4350,
            8,
            0x43a3,
            chip::CORE_ARM_CR4,
            None,
            0x180000,
        ),
        (
            0x1004_4366,
            BRCM_CC_4366,
            4,
            0x43c3,
            chip::CORE_ARM_CA7,
            Some(CORE_SYS_MEM),
            0x200000,
        ),
    ] {
        let bus = model(identity, cpu, mem, base);
        let (pci, profile) = board(chip_id, revision, device);
        let booted = match boot::Cr4::claim(bus, pci, profile)
            .and_then(|loader| loader.boot(&FIRMWARE, &nvram))
        {
            Ok(booted) => booted,
            Err(_) => return TestResult::Fail("covered chip did not boot through the loader"),
        };
        let bus = &booted.bus;
        if booted.ram.base != base || booted.ram.size != 2 * 16 * 8192 {
            return TestResult::Fail("RAM base/size differs from Linux raminfo");
        }
        if !bus.tcm_writes.contains(&(base, FIRMWARE.len())) || !bus.tcm_writes.contains(&(0, 4)) {
            return TestResult::Fail("firmware not at the RAM base or reset vector not at TCM0");
        }
        if bus.writes.iter().any(|&(at, _)| at == CPU + 0x4c) {
            return TestResult::Fail("BCM43602 bank-PDA quirk applied to another chip");
        }
        if bus.registers.get(&(CPU_WRAP + 0x408)) != Some(&1)
            || bus.registers.get(&(CPU_WRAP + 0x800)) != Some(&0)
        {
            return TestResult::Fail("ARM not released from HALT/reset");
        }
        let d11 = bus.registers.get(&(D11_WRAP + 0x408)).copied();
        let d11_reset = bus.registers.get(&(D11_WRAP + 0x800)).copied();
        match cpu {
            // brcmf_chip_cr4_set_passive: D11 disabled (in reset).
            chip::CORE_ARM_CR4 if d11 == Some(4 | 3) && d11_reset == Some(1) => {}
            // brcmf_chip_ca7_set_passive: D11 reset released, PHYCLOCKEN.
            chip::CORE_ARM_CA7
                if d11 == Some(4 | 1)
                    && d11_reset == Some(0)
                    && bus.registers.get(&(MEM_WRAP + 0x408)) == Some(&1)
                    && bus.writes.contains(&(MEM + 0x10, 1)) => {}
            _ => return TestResult::Fail("CR4/CA7 passive D11 or SYS_MEM sequence differs"),
        }
        if booted.shared_address != base + 0x100 {
            return TestResult::Fail("shared address not read from the RAM tail");
        }
    }
    // Wrong CPU for the chip, CA7 without SYS_MEM, or an uncovered chip.
    for (identity, chip_id, revision, device, cpu, mem, error) in [
        (
            0x1004_4366,
            BRCM_CC_4366,
            4,
            0x43c3,
            chip::CORE_ARM_CR4,
            Some(CORE_SYS_MEM),
            boot::Error::Unsupported,
        ),
        (
            0x1004_4366,
            BRCM_CC_4366,
            4,
            0x43c3,
            chip::CORE_ARM_CA7,
            None,
            boot::Error::Unsupported,
        ),
        (
            0x1008_4350,
            BRCM_CC_4350,
            8,
            0x43a3,
            chip::CORE_ARM_CA7,
            Some(CORE_SYS_MEM),
            boot::Error::Unsupported,
        ),
        (
            0x1001_4354,
            BRCM_CC_4354,
            1,
            0x4354,
            chip::CORE_ARM_CR4,
            None,
            boot::Error::Board,
        ),
    ] {
        let bus = model(identity, cpu, mem, 0x180000);
        let (pci, profile) = board(chip_id, revision, device);
        match boot::Cr4::claim(bus, pci, profile) {
            Err(refused) if refused.error == error && refused.bus.tcm_writes.is_empty() => {}
            _ => return TestResult::Fail("unsupported chip/CPU layout was not refused before TCM"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_cr4_and_ca7_boot_transcripts
);

/// `brcmf_pcie_download_fw_nvram` with `devinfo->fwseed`: BCM43752 (seeded
/// PCI id 0x449d, Linux RAM base 0x170000, CR4 found by Linux's dispatch)
/// gets the `brcmf_random_seed_footer` {0x100, 0xfeedc0de} directly below
/// NVRAM and 0x100 DRBG bytes below the footer; an unseeded id gets none.
fn smoke_brcmf_chip_profile_random_seed_footer_below_nvram() -> TestResult {
    let nvram = match boot::pack_nvram(b"boardrev=0x1101\nboardtype=0x0777\n") {
        Ok(nvram) => nvram,
        Err(_) => return TestResult::Fail("fixture NVRAM did not pack"),
    };
    let size = 2 * 16 * 8192u32;
    for (identity, chip_id, device, base, seeded) in [
        (0x1001_aae8, BRCM_CC_43752, 0x449d, 0x170000, true),
        (0x1002_4356, BRCM_CC_4356, 0x43ec, 0x180000, false),
    ] {
        let bus = model(identity, chip::CORE_ARM_CR4, None, base);
        let (pci, profile) = board(chip_id, (identity >> 16 & 15) as u8, device);
        let booted = match boot::Cr4::claim(bus, pci, profile)
            .and_then(|loader| loader.boot(&FIRMWARE, &nvram))
        {
            Ok(booted) => booted,
            Err(refused) if refused.error == boot::Error::Entropy => {
                return TestResult::Fail("kernel DRBG refused the random-seed bytes")
            }
            Err(_) => return TestResult::Fail("seeded/unseeded chip did not boot"),
        };
        let bus = &booted.bus;
        let nvram_address = base + size - nvram.len() as u32;
        let footer = nvram_address - 8;
        let random = footer - 0x100;
        let mut tail = [0u8; 8];
        for (i, b) in tail.iter_mut().enumerate() {
            *b = *bus.tcm.get(&(footer + i as u32)).unwrap_or(&0);
        }
        let wrote_footer = bus.tcm_writes.contains(&(footer, 8));
        let wrote_random = bus.tcm_writes.contains(&(random, 0x100));
        if seeded != (wrote_footer && wrote_random && tail == [0, 1, 0, 0, 0xde, 0xc0, 0xed, 0xfe])
            || !seeded && (wrote_footer || wrote_random)
        {
            return TestResult::Fail("random-seed footer placement differs from Linux");
        }
        if !bus.tcm_writes.contains(&(nvram_address, nvram.len()))
            || !bus.tcm_writes.contains(&(base, FIRMWARE.len()))
        {
            return TestResult::Fail("NVRAM/firmware placement changed by the seed");
        }
        // The footer and seed follow NVRAM in Linux's write order.
        let order = |at: u32| bus.tcm_writes.iter().position(|w| w.0 == at);
        if seeded && !(order(nvram_address) < order(footer) && order(footer) < order(random)) {
            return TestResult::Fail("seed written out of Linux order");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_random_seed_footer_below_nvram
);

/// One `BRCMF_OTP_SYS_VENDOR` record: header 0x8, chip params, board params.
fn sys_vendor(board: &str) -> Vec<u8> {
    let mut data = alloc::vec![8, 0, 0, 0];
    data.extend_from_slice(b"chip\0");
    data.extend_from_slice(board.as_bytes());
    data.push(0);
    let mut record = alloc::vec![0x15, data.len() as u8];
    record.extend_from_slice(&data);
    record
}

/// `brcmf_pcie_parse_otp` / `_sys_vendor` and the Apple `board_types`,
/// using the module/vendor/version/SKU of Linux's own comment example
/// ("apple,shikoku-RASP-m-6.11-X3"); no board is claimed by it.
fn smoke_brcmf_chip_profile_otp_parse_and_board_types() -> TestResult {
    let mut otp = alloc::vec![0x80, 2, 0xaa, 0xbb]; // BRCM_CIS, skipped
    otp.extend(sys_vendor("  M=RASP V=m m=6.11 x=ignored"));
    otp.extend_from_slice(&[0, 0, 0, 0]);
    let Some(params) = parse_otp(&otp) else {
        return TestResult::Fail("valid SYS_VENDOR OTP rejected");
    };
    if params.module != "RASP" || params.vendor != "m" || params.version != "6.11" {
        return TestResult::Fail("OTP module/vendor/version differ");
    }
    let types = apple_board_types("apple,shikoku", &params, "X3");
    if types[0] != "apple,shikoku-RASP-m-6.11-X3"
        || types[1] != "apple,shikoku-RASP-m-6.11"
        || types[2] != "apple,shikoku-RASP-m"
        || types[3] != "apple,shikoku-RASP"
        || types[4] != "apple,shikoku-X3"
        || types[5] != "apple,shikoku"
    {
        return TestResult::Fail("Apple board_types differ from brcmf_pcie_prepare_fw_request");
    }
    // Missing version, bad tag syntax, 16-byte value, no SYS_VENDOR, a bad
    // header, and an invalid last SYS_VENDOR after a valid one.
    let mut bad_header = sys_vendor("M=RASP V=m m=6.11");
    bad_header[2] = 9;
    let mut last_bad = sys_vendor("M=RASP V=m m=6.11");
    last_bad.extend(sys_vendor("M"));
    for bad in [
        sys_vendor("M=RASP V=m"),
        sys_vendor("M=RASP Vm m=6.11"),
        sys_vendor("M=0123456789abcdef V=m m=6.11"),
        alloc::vec![0x80, 2, 0, 0],
        bad_header,
        last_bad,
    ] {
        if parse_otp(&bad).is_some() {
            return TestResult::Fail("invalid OTP accepted");
        }
    }
    // Parameters accumulate across SYS_VENDOR records as devinfo->otp does.
    let mut split = sys_vendor("M=RASP");
    split.extend(sys_vendor("V=m m=6.11"));
    if parse_otp(&split).map(|p| p.module) != Some("RASP".into()) {
        return TestResult::Fail("OTP parameters did not accumulate");
    }
    if otp_source(BRCM_CC_4378)
        != Some(OtpSource {
            core: CORE_GCI,
            offset: 0x1120,
            words: 0x170,
        })
        || otp_source(BRCM_CC_4387).map(|s| s.offset) != Some(0x113c)
        || otp_source(BRCM_CC_4364).map(|s| (s.core, s.words))
            != Some((chip::CORE_CHIPCOMMON, 0x1a0))
        || otp_source(BRCM_CC_4356).is_some()
    {
        return TestResult::Fail("OTP core/offset table differs from brcmf_pcie_read_otp");
    }
    if asset_board(
        "brcmfmac4378b1-pcie",
        "brcm/brcmfmac4378b1-pcie.apple,shikoku-RASP.txt",
        "txt",
    ) != Some("apple,shikoku-RASP")
        || asset_board("brcmfmac4378b1-pcie", "brcm/brcmfmac4378b1-pcie.txt", "txt").is_some()
    {
        return TestResult::Fail("asset board type extraction differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_otp_parse_and_board_types
);

/// `brcmf_pcie_read_otp` on a ChipCommon chip (BCM4364): `OTPSEL` set
/// around the 0x1a0-word read at CC + 0x8c0, `sromcontrol` restored; no
/// `OTP_PRESENT` is Linux's "using default firmware" (no OTP, no read).
fn smoke_brcmf_chip_profile_chipcommon_otp_read() -> TestResult {
    let cc = chip::ENUM_BASE;
    for present in [true, false] {
        let mut bus = model(0x1004_4364, chip::CORE_ARM_CR4, None, 0x160000);
        bus.registers
            .insert(cc + CC_SROM_CONTROL, if present { 0x20 } else { 0 });
        let mut otp = sys_vendor("M=RASP V=m m=6.11");
        otp.resize(0x1a0 * 2, 0);
        for (i, word) in otp.chunks_exact(4).enumerate() {
            bus.registers.insert(
                cc + 0x8c0 + i as u32 * 4,
                u32::from_le_bytes(word.try_into().unwrap()),
            );
        }
        let Ok(found) = chip::Chip::discover(&mut bus) else {
            return TestResult::Fail("model chip did not enumerate");
        };
        let read = boot::read_otp(&mut bus, &found);
        let selected = bus.writes.contains(&(cc + CC_SROM_CONTROL, 0x30));
        match (present, read) {
            (true, Ok(Some(params)))
                if params.module == "RASP"
                    && selected
                    && bus.registers.get(&(cc + CC_SROM_CONTROL)) == Some(&0x20) => {}
            (false, Ok(None)) if !selected => {}
            _ => return TestResult::Fail("ChipCommon OTP read differs from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_chipcommon_otp_read
);
