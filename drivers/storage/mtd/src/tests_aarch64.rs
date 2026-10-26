//! aarch64-only smokes for `narf-drivers-storage-mtd` — the CFI
//! binding against the live QEMU virt device tree (DT programme
//! step 6). This is also the first execution of the production
//! CFI query sequence against QEMU's pflash model: the unit
//! smokes run it against a modelled chip.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_cfi_dt_banks_bound_live() -> TestResult {
    // The frame's probe-all walk ran before the smoke phase: the
    // virt cfi-flash node (two 64 MiB banks) must have produced
    // two MTD devices whose geometry came from the CFI query.
    let list = crate::registry::list();
    let banks = list.iter().filter(|d| d.name().starts_with("cfi@")).count();
    if banks != 2 {
        return TestResult::Fail("CFI DT binding did not register both virt banks");
    }
    for dev in list.iter().filter(|d| d.name().starts_with("cfi@")) {
        if dev.size() != 0x400_0000 {
            return TestResult::Fail("CFI bank size is not the queried 64 MiB");
        }
        if dev.erase_size() == 0 || dev.size() % dev.erase_size() as u64 != 0 {
            return TestResult::Fail("CFI bank erase geometry is incoherent");
        }
        let mut buf = [0u8; 16];
        if dev.read(0, &mut buf).is_err() {
            return TestResult::Fail("CFI bank read at offset 0 failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("storage-mtd", smoke_cfi_dt_banks_bound_live);
