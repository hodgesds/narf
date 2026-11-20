use super::*;
use alloc::collections::BTreeMap;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const ROM: u32 = 0x1810_0000;
const PCIE: u32 = 0x1801_2000;

struct Bus {
    words: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    reads: usize,
}

impl Backplane for Bus {
    fn read32(&mut self, address: u32) -> Result<u32, Error> {
        if !valid_address(address) {
            return Err(Error::Address);
        }
        self.reads += 1;
        Ok(*self.words.get(&address).unwrap_or(&0))
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), Error> {
        if !valid_address(address) {
            return Err(Error::Address);
        }
        self.writes.push((address, value));
        Ok(())
    }
}

fn bus(revision: u8) -> Bus {
    // Literal AI descriptors: component-A, component-B, 4-KiB slave,
    // 4-KiB slave wrapper. PCIe has a master port and master wrapper.
    let words = [
        0x4bf8_0001,
        0x2808_0001,
        0x1800_0005,
        0x1811_0085,
        0x4bf8_3c01,
        (u32::from(revision) << 24) | 0x0000_4001,
        0x0000_0003,
        PCIE | 5,
        0x1811_20c5,
        0x4bf8_3e01,
        0x0708_0001,
        0x1800_2005,
        0x1811_4085,
        0x0000_000f,
    ];
    let mut bus = Bus {
        words: BTreeMap::new(),
        writes: Vec::new(),
        reads: 0,
    };
    // AI, chip revision 3, BCM43602 (0xaa52), independent of PCI DID.
    bus.words.insert(ENUM_BASE, 0x1003_aa52);
    bus.words.insert(EROM_POINTER, ROM);
    for (index, word) in words.into_iter().enumerate() {
        bus.words.insert(ROM + index as u32 * 4, word);
    }
    bus.words
        .insert(PCIE + pcie_registers(revision).mailbox_status, 0xa5);
    bus
}

fn smoke_brcmf_chip_discovery_parks_discovered_pcie_core() -> TestResult {
    for revision in [13, 63, 64, 65] {
        let mut bus = bus(revision);
        let chip = match Chip::discover(&mut bus) {
            Ok(chip) => chip,
            Err(_) => return TestResult::Fail("literal AI core map rejected"),
        };
        if chip.id != 43602
            || chip.revision != 3
            || chip.cores.len() != 3
            || chip
                .core(CORE_ARM_CR4)
                .is_none_or(|core| core.base != 0x1800_2000)
            || chip
                .core(CORE_PCIE2)
                .is_none_or(|core| core.revision != revision || core.base != PCIE)
            || !bus.writes.is_empty()
        {
            return TestResult::Fail("chip discovery confused identity, core map, or revision");
        }
        if chip.park_pcie(&mut bus).is_err() {
            return TestResult::Fail("discovered PCIe core did not park");
        }
        let (mask, status, mailbox_mask) = if revision >= 64 {
            (0xc14, 0xc30, 0xc34)
        } else {
            (0x24, 0x48, 0x4c)
        };
        if bus.writes
            != vec![
                (PCIE + mask, 0),
                (PCIE + mailbox_mask, 0),
                (PCIE + status, 0xa5),
            ]
        {
            return TestResult::Fail("PCIe parking used fixed BAR enum or wrong interrupt ABI");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_chip_discovery_parks_discovered_pcie_core
);

fn smoke_brcmf_chip_erom_extended_regions_preserve_alignment() -> TestResult {
    let mut bus = bus(13);
    let words = [
        0x4bf8_0001,
        0x2808_0001,
        // A 64-bit address with a nonzero high word must be skipped,
        // never truncated into the ChipCommon register base.
        0x1900_000d,
        1,
        // An explicit 64-bit size descriptor and its high word must
        // both be consumed before looking for the next region.
        0x1900_1035,
        0x0000_1008,
        0,
        0x1800_0005,
        0x1811_0085,
        0x4bf8_3c01,
        0x0d00_4001,
        3,
        PCIE | 5,
        0x1811_20c5,
        15,
    ];
    for (index, word) in words.into_iter().enumerate() {
        bus.words.insert(ROM + index as u32 * 4, word);
    }
    match Chip::discover(&mut bus) {
        Ok(chip)
            if chip
                .core(CORE_CHIPCOMMON)
                .is_some_and(|core| core.base == ENUM_BASE)
                && chip.core(CORE_PCIE2).is_some_and(|core| core.base == PCIE) =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("extended EROM words desynchronized core discovery"),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_chip_erom_extended_regions_preserve_alignment
);

fn smoke_brcmf_chip_discovery_is_bounded_and_fail_closed() -> TestResult {
    let mut malformed = bus(13);
    malformed.words.insert(ROM + 4, 5);
    if !matches!(Chip::discover(&mut malformed), Err(Error::MalformedErom))
        || !malformed.writes.is_empty()
    {
        return TestResult::Fail("malformed component pair accepted or wrote device");
    }
    let mut alias = bus(13);
    alias.words.insert(ROM + 7 * 4, ENUM_BASE | 5);
    if !matches!(Chip::discover(&mut alias), Err(Error::MalformedErom)) {
        return TestResult::Fail("aliased PCIe/ChipCommon register regions accepted");
    }
    let mut missing = bus(13);
    missing.words.insert(ROM + 4 * 4, 15);
    if !matches!(Chip::discover(&mut missing), Err(Error::MissingCore)) {
        return TestResult::Fail("missing PCIe core accepted");
    }
    let mut endless = bus(13);
    endless.words.clear();
    endless.words.insert(ENUM_BASE, 0x1003_aa52);
    endless.words.insert(EROM_POINTER, ROM);
    if !matches!(Chip::discover(&mut endless), Err(Error::EromLimit))
        || endless.reads > MAX_EROM_WORDS + 2
    {
        return TestResult::Fail("unterminated EROM exceeded descriptor work bound");
    }
    let mut invalid = bus(13);
    invalid.words.insert(EROM_POINTER, 0xffff_fffc);
    if !matches!(Chip::discover(&mut invalid), Err(Error::Address)) || invalid.reads != 2 {
        return TestResult::Fail("untrusted EROM pointer escaped backplane bounds");
    }
    let mut gone = bus(64);
    let chip = Chip::discover(&mut gone).unwrap();
    gone.words.insert(PCIE + 0xc30, u32::MAX);
    if chip.park_pcie(&mut gone) != Err(Error::Gone) || gone.writes.len() != 2 {
        return TestResult::Fail("device-gone mailbox status was acknowledged");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_chip_discovery_is_bounded_and_fail_closed
);
