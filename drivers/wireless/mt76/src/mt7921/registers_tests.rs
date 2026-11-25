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
        if offset == MT_HIF_REMAP_L1 || offset == MT7925_HIF_REMAP_L1 {
            self.selector
        } else {
            0x7922
        }
    }
    fn write(&mut self, offset: u32, value: u32) {
        assert!(u64::from(offset) + 4 <= self.len);
        self.ops.push(Op::Write(offset, value));
        if (offset == MT_HIF_REMAP_L1 || offset == MT7925_HIF_REMAP_L1) && !self.refuse_selector {
            self.selector = value;
        }
    }
}

fn mt76_identity_read_selects_flushes_and_restores_l1() -> TestResult {
    let mut io = Model::new();
    if registers::transaction(MTK_DEV_MT7922, &mut io, MT_HW_CHIPID, None) != Ok(0x7922)
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
    if registers::transaction(MTK_DEV_MT7922, &mut io, MT_CONN_ON_LPCTL, Some(2)) != Ok(2)
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

/// MT7925 L1 golden: the probe's `MT_HW_CHIPID` read programs the
/// 7925 selector (`0x155024`, page in the HIGH half) and lands the
/// slab at `0x130000` — not the CONNAC2 selector/window. Both 7925
/// PCI ids behave the same. Upstream `mt7925/pci.c:141-156`
/// (`mt7925_reg_map_l1`) at torvalds/linux 8d7fe9885c62.
fn mt76_mt7925_l1_transaction_uses_high_half_page_and_130000_window() -> TestResult {
    for did in [MTK_DEV_MT7925, MTK_DEV_MT7925_ALT] {
        let mut io = Model::new();
        // Real 7925 BAR0 is 2 MiB; the 7925 selector 0x155024 needs it.
        io.len = 0x200000;
        // MT_HW_CHIPID (0x70010200): page 0x7001, offset 0x0200.
        // Initial selector 0xabcd1234: high half becomes the page,
        // low half is preserved.
        if registers::transaction(did, &mut io, MT_HW_CHIPID, None) != Ok(0x7922)
            || io.selector != 0xabcd1234
            || io.ops
                != vec![
                    Op::Read(0x155024),
                    Op::Write(0x155024, 0x70011234),
                    Op::Read(0x155024),
                    Op::Read(0x130200),
                    Op::Write(0x155024, 0xabcd1234),
                    Op::Read(0x155024),
                ]
        {
            return TestResult::Fail("MT7925 L1 selector, page field, or window wrong");
        }
    }
    // The 7925 selector past a 1 MiB BAR fails closed with no I/O.
    let mut io = Model::new();
    if registers::transaction(MTK_DEV_MT7925, &mut io, MT_HW_CHIPID, None) != Err(Error::Bounds)
        || !io.ops.is_empty()
    {
        return TestResult::Fail("MT7925 L1 past the mapped BAR was attempted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_mt7925_l1_transaction_uses_high_half_page_and_130000_window
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
        if registers::transaction(MTK_DEV_MT7922, &mut io, addr, None) != Err(error)
            || !io.ops.is_empty()
        {
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
    if registers::transaction(MTK_DEV_MT7922, &mut io, 0x18000140, Some(0x55)) != Ok(0x55)
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
        let mapped = match registers::plan(MTK_DEV_MT7922, addr, 0x100000) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("valid fixed register rejected"),
        };
        if mapped.offset != expected || mapped.page.is_some() {
            return TestResult::Fail("fixed map selected the wrong window");
        }
    }
    if registers::plan(MTK_DEV_MT7922, 0x820e4400, 0x100000) != Err(Error::Unsupported) {
        return TestResult::Fail("one-past-end fixed address accepted");
    }
    let mut io = Model::new();
    io.selector = u32::MAX;
    if registers::transaction(MTK_DEV_MT7922, &mut io, MT_HW_CHIPID, None) != Err(Error::DeviceGone)
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
    if registers::transaction(MTK_DEV_MT7922, &mut io, MT_HW_CHIPID, None) != Err(Error::RemapRejected)
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
    if unsafe { super::mac::take_driver_own(&mmio, MTK_DEV_MT7922) }.is_err()
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
    if unsafe { super::mac::take_driver_own(&invalid, MTK_DEV_MT7922) }
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

// ── MT7925 (CONNAC3) fixed map ─────────────────────────────────────

/// Entry-for-entry golden test: `FIXED_MT7925` must match upstream
/// `default_fixed_map` (torvalds/linux 8d7fe9885c62,
/// mt7925/pci.c:178-232) exactly — same windows, same order, same
/// lengths. A wrong window makes every later register read garbage,
/// so this asserts the whole table, not a spot check. The upstream
/// terminator `{ 0, 0, 0 }` is not part of the table.
fn mt76_mt7925_fixed_map_matches_upstream_default_fixed_map() -> TestResult {
    const UPSTREAM: &[(u32, u32, u32)] = &[
        (0x830c0000, 0x000000, 0x0001000),
        (0x54000000, 0x002000, 0x0001000),
        (0x55000000, 0x003000, 0x0001000),
        (0x56000000, 0x004000, 0x0001000),
        (0x57000000, 0x005000, 0x0001000),
        (0x58000000, 0x006000, 0x0001000),
        (0x59000000, 0x007000, 0x0001000),
        (0x820c0000, 0x008000, 0x0004000),
        (0x820c8000, 0x00c000, 0x0002000),
        (0x820cc000, 0x00e000, 0x0002000),
        (0x74030000, 0x010000, 0x0001000),
        (0x820e0000, 0x020000, 0x0000400),
        (0x820e1000, 0x020400, 0x0000200),
        (0x820e2000, 0x020800, 0x0000400),
        (0x820e3000, 0x020c00, 0x0000400),
        (0x820e4000, 0x021000, 0x0000400),
        (0x820e5000, 0x021400, 0x0000800),
        (0x820ce000, 0x021c00, 0x0000200),
        (0x820e7000, 0x021e00, 0x0000200),
        (0x820cf000, 0x022000, 0x0001000),
        (0x820e9000, 0x023400, 0x0000200),
        (0x820ea000, 0x024000, 0x0000200),
        (0x820eb000, 0x024200, 0x0000400),
        (0x820ec000, 0x024600, 0x0000200),
        (0x820ed000, 0x024800, 0x0000800),
        (0x820ca000, 0x026000, 0x0002000),
        (0x820d0000, 0x030000, 0x0010000),
        (0x40000000, 0x070000, 0x0010000),
        (0x00400000, 0x080000, 0x0010000),
        (0x00410000, 0x090000, 0x0010000),
        (0x820f0000, 0x0a0000, 0x0000400),
        (0x820f1000, 0x0a0600, 0x0000200),
        (0x820f2000, 0x0a0800, 0x0000400),
        (0x820f3000, 0x0a0c00, 0x0000400),
        (0x820f4000, 0x0a1000, 0x0000400),
        (0x820f5000, 0x0a1400, 0x0000800),
        (0x820f7000, 0x0a1e00, 0x0000200),
        (0x820f9000, 0x0a3400, 0x0000200),
        (0x820fa000, 0x0a4000, 0x0000200),
        (0x820fb000, 0x0a4200, 0x0000400),
        (0x820fc000, 0x0a4600, 0x0000200),
        (0x820fd000, 0x0a4800, 0x0000800),
        (0x820c4000, 0x0a8000, 0x0004000),
        (0x820b0000, 0x0ae000, 0x0001000),
        (0x80020000, 0x0b0000, 0x0010000),
        (0x81020000, 0x0c0000, 0x0010000),
        (0x7c020000, 0x0d0000, 0x0010000),
        (0x7c060000, 0x0e0000, 0x0010000),
        (0x7c000000, 0x0f0000, 0x0010000),
        (0x70020000, 0x1f0000, 0x0010000),
        (0x7c500000, 0x060000, 0x200000),
    ];
    let table = registers::FIXED_MT7925;
    if table.len() != UPSTREAM.len() {
        return TestResult::Fail("MT7925 fixed map length differs from upstream");
    }
    for (want, got) in UPSTREAM.iter().zip(table.iter()) {
        if want != got {
            return TestResult::Fail("MT7925 fixed map entry differs from upstream");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_mt7925_fixed_map_matches_upstream_default_fixed_map
);

/// `plan()` dispatches on the device id: both MT7925 ids select the
/// CONNAC3 windows, CONNAC2 ids keep the old table, and the windows
/// both chips share (identity via L1, ownership CSR) agree.
/// The PP length change (0x1000 -> 0x2000) is pinned by the
/// entry-for-entry test above, not here: the dropped CONNAC2 window
/// 0x820cd000 covered the same BAR0 offsets, so `plan()` cannot tell
/// the two tables apart at those addresses.
fn mt76_mt7925_plan_uses_connac3_windows() -> TestResult {
    if !registers::is_mt7925(MTK_DEV_MT7925) || !registers::is_mt7925(MTK_DEV_MT7925_ALT) {
        return TestResult::Fail("MT7925 ids do not select the CONNAC3 table");
    }
    for did in [
        MTK_DEV_MT7961,
        MTK_DEV_MT7922,
        MTK_DEV_MT7921,
        MTK_DEV_MT7921_ALT,
        MTK_DEV_MT7920,
    ] {
        if registers::is_mt7925(did) {
            return TestResult::Fail("CONNAC2 id selects the CONNAC3 table");
        }
    }
    // The 7925 BAR0 offsets reach 0x260000 (remap tail), so the
    // geometry checks use a 0x300000 window, not the 1 MiB probe BAR.
    let len = 0x300000;
    // New windows, head of each, on both MT7925 ids.
    for did in [MTK_DEV_MT7925, MTK_DEV_MT7925_ALT] {
        for (addr, expected) in [
            (0x830c0000, 0x000000),
            (0x56000000, 0x004000),
            (0x57000000, 0x005000),
            (0x820ca000, 0x026000),
            (0x820c4000, 0x0a8000),
            (0x820b0000, 0x0ae000),
            (0x70020000, 0x1f0000),
            (0x7c500000, 0x060000),
        ] {
            let mapped = match registers::plan(did, addr, len) {
                Ok(plan) => plan,
                Err(_) => return TestResult::Fail("MT7925 window rejected"),
            };
            if mapped.offset != expected || mapped.page.is_some() {
                return TestResult::Fail("MT7925 window maps to the wrong BAR0 offset");
            }
        }
    }
    // The same addresses on CONNAC2: new windows are unsupported, and
    // 0x70020000 falls through to the shared L1 range instead.
    if registers::plan(MTK_DEV_MT7922, 0x830c0000, len).is_ok()
        || registers::plan(MTK_DEV_MT7922, 0x7c500000, len).is_ok()
    {
        return TestResult::Fail("CONNAC2 accepts an MT7925-only window");
    }
    match registers::plan(MTK_DEV_MT7922, 0x70020000, len) {
        Ok(plan) if plan.page == Some(0x7002) => {}
        _ => return TestResult::Fail("CONNAC2 0x70020000 does not use L1"),
    }
    // PCIe MAC shrank 0x10000 -> 0x1000: the tail word still maps, the
    // first word past the window is unsupported on MT7925 but maps on
    // CONNAC2.
    if registers::plan(MTK_DEV_MT7925, 0x74030ffc, len).map(|plan| plan.offset) != Ok(0x10ffc)
        || registers::plan(MTK_DEV_MT7925, 0x74031000, len) != Err(Error::Unsupported)
        || registers::plan(MTK_DEV_MT7922, 0x74031000, len).map(|plan| plan.offset) != Ok(0x11000)
    {
        return TestResult::Fail("PCIe MAC window length differs from the per-chip table");
    }
    // Remap window: 2 MiB at BAR0 0x60000; the last word maps, the
    // first word past it is unsupported.
    if registers::plan(MTK_DEV_MT7925, 0x7c500000 + 0x200000 - 4, len).map(|plan| plan.offset)
        != Ok(0x25fffc)
        || registers::plan(MTK_DEV_MT7925, 0x7c500000 + 0x200000, len) != Err(Error::Unsupported)
    {
        return TestResult::Fail("MT7925 remap window bounds differ from upstream");
    }
    // Dropped window: 0x820cd000 has no MT7925 entry of its own; it now
    // routes through the lengthened PP window to the same BAR0 offset.
    if registers::plan(MTK_DEV_MT7925, 0x820cd000, len).map(|plan| plan.offset) != Ok(0x0f000)
        || registers::plan(MTK_DEV_MT7925, 0x820cdffc, len).map(|plan| plan.offset) != Ok(0x0fffc)
    {
        return TestResult::Fail("dropped 0x820cd000 window does not route via PP");
    }
    // The identity register routes through L1 on both chips: same page
    // (0x7001), but the window base is per-chip (0x40000 CONNAC2,
    // 0x130000 MT7925). The ownership CSR is a fixed window on both.
    for (did, expected) in [(MTK_DEV_MT7922, 0x40200), (MTK_DEV_MT7925, 0x130200)] {
        if registers::plan(did, MT_HW_CHIPID, len).map(|plan| (plan.offset, plan.page))
            != Ok((expected, Some(0x7001)))
            || registers::plan(did, MT_CONN_ON_LPCTL, len).map(|plan| (plan.offset, plan.page))
                != Ok((0xe0010, None))
        {
            return TestResult::Fail("shared identity/ownership window differs by chip");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_mt7925_plan_uses_connac3_windows
);
