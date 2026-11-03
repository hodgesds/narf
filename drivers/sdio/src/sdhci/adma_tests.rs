use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_sdhci_adma_mode_selection_matches_setup_host() -> TestResult {
    let adma = CAPS_CAN_DO_ADMA2 | CAPS_CAN_DO_SDMA;
    if select(SPEC_300 as u8, adma) != Some(Mode::Adma32)
        || select(SPEC_300 as u8, adma | CAPS_CAN_64BIT) != Some(Mode::Adma64)
        // ADMA needs spec 2.00; a v1 host keeps SDMA.
        || select(SPEC_100 as u8, adma) != Some(Mode::Sdma)
        // 64-bit without v4 mode removes SDMA.
        || select(SPEC_200 as u8, CAPS_CAN_DO_SDMA | CAPS_CAN_64BIT).is_some()
        || select(SPEC_400 as u8, 0).is_some()
    {
        return TestResult::Fail("DMA mode selection differs from sdhci_setup_host");
    }
    if Mode::Adma32.without_adma(adma) != Some(Mode::Sdma)
        || Mode::Adma64.without_adma(adma | CAPS_CAN_64BIT).is_some()
        || Mode::Adma32.without_adma(CAPS_CAN_DO_ADMA2).is_some()
        || Mode::Adma64.dma_mask() != u64::MAX
        || Mode::Adma32.dma_mask() != u64::from(u32::MAX)
        || Mode::Adma64.host_control() != CTRL_ADMA64
    {
        return TestResult::Fail("ADMA buffer-failure fallback or mask wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/adma",
    smoke_sdhci_adma_mode_selection_matches_setup_host
);

fn smoke_sdhci_adma_descriptor_layout_32_and_64() -> TestResult {
    let mut table = vec![0u8; 4 * DESC_SIZE_64];
    let segment = Segment {
        addr: 0x1234_5000,
        len: 1536,
    };
    let built = table_pre(&mut table, DESC_SIZE_32, &[segment], 0x9000, false);
    if built
        != Ok(Table {
            descriptors: 2,
            align: vec![],
        })
        || table[..16]
            != [
                0x21, 0, 0x00, 0x06, 0x00, 0x50, 0x34, 0x12, 3, 0, 0, 0, 0, 0, 0, 0,
            ]
    {
        return TestResult::Fail("32-bit TRAN + NOP/END/VALID layout wrong");
    }
    let mut table = vec![0u8; 4 * DESC_SIZE_64];
    let high = Segment {
        addr: 0x0000_0012_8000_0000,
        len: 512,
    };
    if table_pre(&mut table, DESC_SIZE_64, &[high], 0, false).map(|t| t.descriptors) != Ok(2)
        || read_desc(&table, 0, DESC_SIZE_64) != Some((ATTR_TRAN_VALID, 512, high.addr))
        || read_desc(&table, 1, DESC_SIZE_64) != Some((ATTR_NOP_END_VALID, 0, 0))
    {
        return TestResult::Fail("64-bit 12-byte descriptor layout wrong");
    }
    if table_pre(&mut table, DESC_SIZE_32, &[high], 0, false) != Err(TableError::Address) {
        return TestResult::Fail("32-bit descriptor accepted an address above 4 GiB");
    }
    // SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC: END rides on the last TRAN.
    let mut table = vec![0u8; 4 * DESC_SIZE_32];
    if table_pre(&mut table, DESC_SIZE_32, &[segment], 0, true).map(|t| t.descriptors) != Ok(1)
        || read_desc(&table, 0, DESC_SIZE_32)
            != Some((ATTR_TRAN_VALID | ATTR_END, 1536, segment.addr))
    {
        return TestResult::Fail("NO_ENDATTR_IN_NOPDESC end marking wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/adma",
    smoke_sdhci_adma_descriptor_layout_32_and_64
);

fn smoke_sdhci_adma_64k_split_and_align_buffer() -> TestResult {
    let mut table = vec![0u8; 8 * DESC_SIZE_32];
    // Exactly 64 KiB stays one descriptor whose length encodes as 0.
    let full = Segment {
        addr: 0x10_0000,
        len: MAX_ADMA,
    };
    if table_pre(&mut table, DESC_SIZE_32, &[full], 0, false).map(|t| t.descriptors) != Ok(2)
        || read_desc(&table, 0, DESC_SIZE_32) != Some((ATTR_TRAN_VALID, 0, 0x10_0000))
    {
        return TestResult::Fail("64 KiB descriptor not encoded as length 0");
    }
    // Beyond 64 KiB: 32 KiB pieces until the rest fits.
    let long = Segment {
        addr: 0x20_0000,
        len: MAX_ADMA + 4096,
    };
    let built = table_pre(&mut table, DESC_SIZE_32, &[long], 0, false);
    if built.map(|t| t.descriptors) != Ok(3)
        || read_desc(&table, 0, DESC_SIZE_32) != Some((ATTR_TRAN_VALID, 0x8000, 0x20_0000))
        || read_desc(&table, 1, DESC_SIZE_32)
            != Some((ATTR_TRAN_VALID, (0x8000 + 4096) as u16, 0x20_8000))
        || read_desc(&table, 2, DESC_SIZE_32) != Some((ATTR_NOP_END_VALID, 0, 0))
    {
        return TestResult::Fail("over-64 KiB segment split differs from Linux");
    }
    // A misaligned head goes through a 4-byte align-buffer slot.
    let odd = Segment {
        addr: 0x30_0001,
        len: 64,
    };
    let built = table_pre(&mut table, DESC_SIZE_32, &[odd], 0x4000, false);
    if built
        != Ok(Table {
            descriptors: 3,
            align: vec![AlignSlot {
                segment: 0,
                slot: 0,
                bytes: 3,
            }],
        })
        || read_desc(&table, 0, DESC_SIZE_32) != Some((ATTR_TRAN_VALID, 3, 0x4000))
        || read_desc(&table, 1, DESC_SIZE_32) != Some((ATTR_TRAN_VALID, 61, 0x30_0004))
    {
        return TestResult::Fail("unaligned head did not use the align buffer");
    }
    let too_small = &mut [0u8; DESC_SIZE_32][..];
    if table_pre(too_small, DESC_SIZE_32, &[full], 0, false) != Err(TableError::Overflow) {
        return TestResult::Fail("table overflow not refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/sdhci/adma",
    smoke_sdhci_adma_64k_split_and_align_buffer
);
