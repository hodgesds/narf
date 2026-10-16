//! Register-bus models: validate physical offsets and posted-write ordering.
use super::registers::{self, Error, Io};
use super::regs::*;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Read(u32),
    Write(u32, u32),
}
struct Model {
    len: u64,
    selector: u32,
    ops: Vec<Op>,
    refuse_selector: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            len: 0x100000,
            selector: 0xabcd1234,
            ops: Vec::new(),
            refuse_selector: false,
        }
    }
}
impl Io for Model {
    fn len(&self) -> u64 {
        self.len
    }
    fn read(&mut self, offset: u32) -> u32 {
        assert!(u64::from(offset) + 4 <= self.len);
        self.ops.push(Op::Read(offset));
        if offset == MT_HIF_REMAP_L1 {
            self.selector
        } else {
            0x7922
        }
    }
    fn write(&mut self, offset: u32, value: u32) {
        assert!(u64::from(offset) + 4 <= self.len);
        self.ops.push(Op::Write(offset, value));
        if offset == MT_HIF_REMAP_L1 && !self.refuse_selector {
            self.selector = value;
        }
    }
}

fn mt76_identity_read_selects_flushes_and_restores_l1() -> TestResult {
    let mut io = Model::new();
    if registers::transaction(&mut io, MT_HW_CHIPID, None) != Ok(0x7922)
        || io.selector != 0xabcd1234
        || io.ops
            != vec![
                Op::Read(0xfe24c),
                Op::Write(0xfe24c, 0xabcd7001),
                Op::Read(0xfe24c),
                Op::Read(0x40200),
                Op::Write(0xfe24c, 0xabcd1234),
                Op::Read(0xfe24c),
            ]
    {
        return TestResult::Fail("L1 page field, posted flush, or latch restore");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_identity_read_selects_flushes_and_restores_l1
);

fn mt76_ownership_access_uses_fixed_window_without_l1() -> TestResult {
    let mut io = Model::new();
    if registers::transaction(&mut io, MT_CONN_ON_LPCTL, Some(2)) != Ok(2)
        || io.ops != vec![Op::Write(0xe0010, 2)]
    {
        return TestResult::Fail("ownership CSR used an indirect/invalid window");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_ownership_access_uses_fixed_window_without_l1
);

fn mt76_invalid_register_accesses_issue_no_io() -> TestResult {
    for (addr, len, error) in [
        (MT_HW_CHIPID + 1, 0x100000, Error::Alignment),
        (0xffffffff, 0x100000, Error::Alignment),
        (0xdead0000, 0x100000, Error::Unsupported),
        (MT_HW_CHIPID, 0xfe24f, Error::Bounds),
        (MT_CONN_ON_LPCTL, 0xe0013, Error::Bounds),
        (0xffffc, 0xfffff, Error::Bounds),
    ] {
        let mut io = Model::new();
        io.len = len;
        if registers::transaction(&mut io, addr, None) != Err(error) || !io.ops.is_empty() {
            return TestResult::Fail("invalid access touched hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_invalid_register_accesses_issue_no_io
);

fn mt76_l1_write_flushes_before_restoring_page() -> TestResult {
    let mut io = Model::new();
    if registers::transaction(&mut io, 0x18000140, Some(0x55)) != Ok(0x55)
        || io.ops
            != vec![
                Op::Read(0xfe24c),
                Op::Write(0xfe24c, 0xabcd1800),
                Op::Read(0xfe24c),
                Op::Write(0x40140, 0x55),
                Op::Read(0xfe24c),
                Op::Write(0xfe24c, 0xabcd1234),
                Op::Read(0xfe24c),
            ]
    {
        return TestResult::Fail("L1 write was not flushed before restoration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_l1_write_flushes_before_restoring_page
);

fn mt76_fixed_windows_have_exclusive_bounds() -> TestResult {
    for (addr, expected) in [
        (0x7c06fffc, 0xefffc),
        (0x74030188, 0x10188),
        (0x54000208, 0x2208),
        (0x820e43fc, 0x213fc),
        (0x000ffffc, 0xffffc),
    ] {
        let mapped = match registers::plan(addr, 0x100000) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("valid fixed register rejected"),
        };
        if mapped.offset != expected || mapped.page.is_some() {
            return TestResult::Fail("fixed map selected the wrong window");
        }
    }
    if registers::plan(0x820e4400, 0x100000) != Err(Error::Unsupported) {
        return TestResult::Fail("one-past-end fixed address accepted");
    }
    let mut io = Model::new();
    io.selector = u32::MAX;
    if registers::transaction(&mut io, MT_HW_CHIPID, None) != Err(Error::DeviceGone)
        || io.ops != vec![Op::Read(0xfe24c)]
    {
        return TestResult::Fail("removed device selector was written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_fixed_windows_have_exclusive_bounds
);

fn mt76_rejected_l1_page_never_accesses_window() -> TestResult {
    let mut io = Model::new();
    io.refuse_selector = true;
    if registers::transaction(&mut io, MT_HW_CHIPID, None) != Err(Error::RemapRejected)
        || io.ops.iter().any(|op| matches!(op, Op::Read(offset) | Op::Write(offset, _) if *offset != MT_HIF_REMAP_L1))
        || io.selector != 0xabcd1234 {
        return TestResult::Fail("rejected selector accessed the wrong chip page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_rejected_l1_page_never_accesses_window
);

fn mt76_unimplemented_bringup_never_publishes_rings() -> TestResult {
    let mmio = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: this boundary is explicitly side-effect-free until a retained
    // transport exists. A zero mapping makes an accidental MMIO access fault.
    let outcome = unsafe { super::bringup::full_bring_up(&mmio, Default::default()) };
    if !matches!(outcome, Err(super::bringup::BringUpError::NotImplemented)) {
        return TestResult::Fail("unimplemented transport published DMA readiness");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_unimplemented_bringup_never_publishes_rings
);

fn mt76_ownership_handshake_uses_the_real_bar_csr() -> TestResult {
    // Exercise the production ownership path against owned memory. A CLR
    // write leaves OWN_SYNC clear, as a device granting ownership would.
    let mut words = vec![0u32; 0x100000 / 4];
    let mmio = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x100000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: owned, aligned storage covers all validated production accesses.
    if unsafe { super::mac::take_driver_own(&mmio) }.is_err()
        || words[0xe0010 / 4] != PCIE_LPCR_HOST_CLR_OWN
        || words[MT_HIF_REMAP_L1 as usize / 4] != 0
    {
        return TestResult::Fail("ownership touched the wrong register or L1 latch");
    }
    let invalid = narf_bus::MmioRegion {
        virt: 0,
        len: 0,
        ..mmio
    };
    // SAFETY: rejected by the production bounds check before dereferencing.
    if unsafe { super::mac::take_driver_own(&invalid) }
        != Err(super::mac::PowerError::InvalidWindow)
    {
        return TestResult::Fail("ownership entered its wait with invalid geometry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_ownership_handshake_uses_the_real_bar_csr
);
