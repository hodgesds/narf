use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Byte-addressed register file that logs every access as
/// `(write, width, offset, value)`.
#[derive(Debug)]
struct Log {
    regs: [u8; 0x100],
    ops: Vec<(bool, u8, u32, u32)>,
}
impl Default for Log {
    fn default() -> Self {
        Self {
            regs: [0; 0x100],
            ops: Vec::new(),
        }
    }
}
impl Log {
    fn get(&self, offset: u32, width: u32) -> u32 {
        (0..width).fold(0, |acc, i| {
            acc | u32::from(self.regs[(offset + i) as usize]) << (8 * i)
        })
    }
    fn set(&mut self, offset: u32, width: u32, value: u32) {
        for i in 0..width {
            self.regs[(offset + i) as usize] = (value >> (8 * i)) as u8;
        }
    }
}
impl Registers for Log {
    fn read8(&mut self, offset: u32) -> u8 {
        self.ops.push((false, 1, offset, 0));
        self.get(offset, 1) as u8
    }
    fn read16(&mut self, offset: u32) -> u16 {
        self.ops.push((false, 2, offset, 0));
        self.get(offset, 2) as u16
    }
    fn read32(&mut self, offset: u32) -> u32 {
        self.ops.push((false, 4, offset, 0));
        self.get(offset, 4)
    }
    fn write8(&mut self, offset: u32, value: u8) {
        self.ops.push((true, 1, offset, value.into()));
        self.set(offset, 1, value.into());
    }
    fn write16(&mut self, offset: u32, value: u16) {
        self.ops.push((true, 2, offset, value.into()));
        self.set(offset, 2, value.into());
    }
    fn write32(&mut self, offset: u32, value: u32) {
        self.ops.push((true, 4, offset, value));
        self.set(offset, 4, value);
    }
}

fn smoke_sdhci_port_generic_is_exact_passthrough() -> TestResult {
    let mut io = Ported::new(Log::default(), Profile::GENERIC, None);
    io.write16(TRANSFER_MODE, 0x0023);
    io.write16(COMMAND, 0x353a);
    io.write8(HOST_CONTROL, CTRL_HISPD);
    io.write8(POWER_CONTROL, POWER_ON);
    io.write16(CLOCK_CONTROL, 0);
    let _ = io.read32(CAPABILITIES);
    io.clock_changed(400_000);
    let expected = [
        (true, 2, TRANSFER_MODE, 0x0023),
        (true, 2, COMMAND, 0x353a),
        (true, 1, HOST_CONTROL, u32::from(CTRL_HISPD)),
        (true, 1, POWER_CONTROL, u32::from(POWER_ON)),
        (true, 2, CLOCK_CONTROL, 0),
        (false, 4, CAPABILITIES, 0),
    ];
    if io.inner().ops != expected || io.base_clock_hz().is_some() {
        return TestResult::Fail("generic profile changed register traffic");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/port",
    smoke_sdhci_port_generic_is_exact_passthrough
);

fn smoke_sdhci_port_iproc_shadows_until_command() -> TestResult {
    let mut io = Ported::new(Log::default(), IPROC_BCM2835, Some(250_000_000));
    // A non-slow clock skips the post-write delay; behaviour is identical.
    io.clock_changed(25_000_000);
    io.write16(BLOCK_SIZE, 0x0200);
    io.write16(BLOCK_COUNT, 0x0003);
    io.write16(TRANSFER_MODE, 0x0037);
    if io.read16(TRANSFER_MODE) != 0x0037 || io.read16(BLOCK_COUNT) != 0x0003 {
        return TestResult::Fail("shadowed registers not read back");
    }
    if io.inner().ops.iter().any(|op| op.0) {
        return TestResult::Fail("shadowed write reached the bus before COMMAND");
    }
    io.write16(COMMAND, 0x353a);
    let writes: Vec<_> = io.inner().ops.iter().filter(|op| op.0).copied().collect();
    if writes
        != [
            (true, 4, BLOCK_SIZE, 0x0003_0200),
            (true, 4, TRANSFER_MODE, 0x353a_0037),
        ]
    {
        return TestResult::Fail("block/command not issued as two 32-bit writes");
    }
    if io.inner().ops.iter().any(|op| op.1 != 4) {
        return TestResult::Fail("iproc 32-bit-only host saw a narrow access");
    }
    // Byte write is a 32-bit read-modify-write; NO_HISPD_BIT drops HISPD.
    io.write8(HOST_CONTROL, CTRL_HISPD | CTRL_4BITBUS);
    if io.inner().get(HOST_CONTROL, 1) != u32::from(CTRL_4BITBUS) {
        return TestResult::Fail("NO_HISPD_BIT set HISPD or byte RMW wrong");
    }
    let (caps, caps1) = IPROC_BCM2835.caps.unwrap();
    if io.read32(CAPABILITIES) != caps
        || io.read32(CAPABILITIES_1) != caps1
        || caps & (CAPS_CAN_DO_SDMA | CAPS_CAN_DO_ADMA2) != 0
        || io.base_clock_hz() != Some(250_000_000)
    {
        return TestResult::Fail("bcm2835 caps override or platform clock wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/port",
    smoke_sdhci_port_iproc_shadows_until_command
);

fn smoke_sdhci_port_intel_ops() -> TestResult {
    let mut log = Log::default();
    log.set(HOST_VERSION, 2, u32::from(SPEC_300));
    log.set(
        CLOCK_CONTROL,
        2,
        u32::from(0x0100 | CLK_INT_EN | CLK_CARD_EN),
    );
    let mut io = Ported::new(log, PCI_INTEL_BYT_SDIO, None);
    io.write16(CLOCK_CONTROL, 0);
    let writes: Vec<_> = io
        .inner()
        .ops
        .iter()
        .filter(|op| op.0 && op.2 == CLOCK_CONTROL)
        .map(|op| op.3)
        .collect();
    if writes != [u32::from(0x0100 | CLK_INT_EN), 0] {
        return TestResult::Fail("card clock not stopped separately first");
    }
    io.inner_mut().set(
        CLOCK_CONTROL,
        2,
        u32::from(0x0100 | CLK_INT_EN | CLK_CARD_EN),
    );
    io.write8(HOST_CONTROL, CTRL_HISPD);
    if io.inner().get(HOST_CONTROL2, 2) & u32::from(CTRL2_UHS_MASK) != u32::from(CTRL2_UHS_SDR25)
        || io.inner().get(CLOCK_CONTROL, 2) & u32::from(CLK_CARD_EN) == 0
    {
        return TestResult::Fail("Intel high speed did not select SDR25 / restore clock");
    }
    if pci(0x8086, 0x0f15, 0x1093, 0x7884).is_some()
        || pci(0x8086, 0x0f15, 0, 0) != Some(PCI_INTEL_BYT_SDIO)
        || pci(0x8086, 0x0f14, 0, 0).is_some()
        || pci(0x1180, 0x0f15, 0, 0).is_some()
    {
        return TestResult::Fail("sdhci_pci_ids SDIO match differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sdio/sdhci/port", smoke_sdhci_port_intel_ops);

fn smoke_sdhci_port_acpi_and_of_tables() -> TestResult {
    if acpi("80860F14", Some("2")) != Some(ACPI_INT_SDIO)
        || acpi("80860F14", Some("1")).is_some()
        || acpi("80860F14", None).is_some()
        || acpi("INT33BB", Some("3")).is_some()
        || acpi("80865AD0", Some("7")) != Some(ACPI_INT_SDIO)
        || acpi("PNP0D40", None).is_some()
    {
        return TestResult::Fail("sdhci_acpi_uids SDIO slot match differs from Linux");
    }
    if of("brcm,bcm2835-sdhci") != Some(IPROC_BCM2835)
        || of("brcm,bcm2711-emmc2").map(|p| p.min_clock_hz) != Some(Some(200_000))
        || of("brcm,bcm2835-sdhost").is_some()
        || ACPI_INT_SDIO.pm_caps != PmFlags::KEEP_POWER
    {
        return TestResult::Fail("sdhci_iproc_of_match differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/port",
    smoke_sdhci_port_acpi_and_of_tables
);
