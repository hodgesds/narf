use super::*;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Case {
    chip: ChipId,
    kind: Kind,
    length: usize,
    descriptor: &'static [u8],
}
include!("command/golden.rs");
fn smoke_rtw89_fwcmd_descriptor_matches_linux() -> TestResult {
    for c in GOLDEN {
        if descriptor(c.chip, c.kind, c.length).as_deref() != Ok(c.descriptor) {
            return TestResult::Fail("native Linux CH12 descriptor bytes");
        }
    }
    for length in [0, 2021, usize::MAX] {
        if descriptor(ChipId::Rtl8852B, Kind::Section, length).is_ok() {
            return TestResult::Fail("command length outside AX bound");
        }
    }
    if descriptor(ChipId::Rtl8922A, Kind::Header, 72) != Err(Error::Unsupported) {
        return TestResult::Fail("BE used AX firmware command descriptor");
    }
    if txbd(0x12_3456_7890, 2044) != Ok([0xfc, 7, 0x80, 0x44, 0x90, 0x78, 0x56, 0x34])
        || txbd((1 << 40) - 2044, 2044).is_err()
        || txbd((1 << 40) - 2043, 2044) != Err(Error::BadAddress)
        || txbd(0, 0) != Err(Error::BadLength)
        || txbd(0, 2045) != Err(Error::BadLength)
    {
        return TestResult::Fail("literal TXBD full packet extent/high address/LS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_fwcmd_descriptor_matches_linux
);
#[derive(Debug)]
struct Allocation {
    identity: usize,
    dropped: Arc<AtomicUsize>,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
fn allocation(identity: usize, count: &Arc<AtomicUsize>) -> Allocation {
    Allocation {
        identity,
        dropped: count.clone(),
    }
}
fn smoke_rtw89_ch12_multitag_retirement_and_wrap() -> TestResult {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut queue = CommandQueue::new(4).unwrap();
    let mut retired_ids = Vec::new();
    for n in 0..100 {
        let expected = (n % 4) as u16;
        let next = ((n + 1) % 4) as u16;
        let mut observed = None;
        if queue
            .submit(allocation(n, &dropped), |slot, wp, owner| {
                observed = Some((slot, wp, owner.identity));
                Ok(())
            })
            .ok()
            != Some(expected)
            || observed != Some((expected, next, n))
            || queue.write_pointer() != next
        {
            return TestResult::Fail("retained command publication/wrap");
        }
        let retired = queue.observe(next).unwrap();
        retired_ids.extend(retired.iter().map(|owner| owner.identity));
        drop(retired);
        if dropped.load(Ordering::SeqCst) != n.saturating_sub(7) {
            return TestResult::Fail(
                "CH12 multi-tag released before eight later consumed commands",
            );
        }
    }
    if retired_ids != (0..92).collect::<Vec<_>>() {
        return TestResult::Fail("multi-tag command retirement order");
    }
    drop(queue);
    if dropped.load(Ordering::SeqCst) != 92 {
        return TestResult::Fail("drop freed last eight device-referenced commands");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ch12_multitag_retirement_and_wrap
);
fn smoke_rtw89_ch12_failure_full_and_bad_pointer_keep_dma() -> TestResult {
    let dropped = Arc::new(AtomicUsize::new(0));
    {
        let mut queue = CommandQueue::new(4).unwrap();
        for n in 0..3 {
            queue
                .submit(allocation(n, &dropped), |_, _, _| Ok(()))
                .unwrap();
        }
        let mut calls = 0;
        let result = queue.submit(allocation(3, &dropped), |_, _, _| {
            calls += 1;
            Ok(())
        });
        if !matches!(result, Err((Error::Full, Some(_)))) || calls != 0 {
            return TestResult::Fail("full ring touched hardware or lost unissued resource");
        }
        drop(result);
        if queue.observe(4).err() != Some(Error::BadIndex) || dropped.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("bad read pointer changed ownership");
        }
    }
    if dropped.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("invalid device pointer permitted DMA free");
    }
    {
        let mut queue = CommandQueue::new(4).unwrap();
        if !matches!(
            queue.submit(allocation(4, &dropped), |_, _, _| Err(Error::Publish)),
            Err((Error::Publish, None))
        ) || queue.observe(1).err() != Some(Error::Terminal)
        {
            return TestResult::Fail("ambiguous doorbell failure released command");
        }
        let mut calls = 0;
        let result = queue.submit(allocation(5, &dropped), |_, _, _| {
            calls += 1;
            Ok(())
        });
        if !matches!(result, Err((Error::Terminal, Some(_)))) || calls != 0 {
            return TestResult::Fail("failed publish accepted another command");
        }
        drop(result);
    }
    if dropped.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("drop freed an ambiguously published DMA mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ch12_failure_full_and_bad_pointer_keep_dma
);
