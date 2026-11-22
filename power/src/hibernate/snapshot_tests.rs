use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A frame filled with a pattern is in the snapshot with its contents, no
/// copy frame is saved, the saved frames come in ascending order, and saved
/// plus copy frames fit in RAM (free frames are not saved).
fn snapshot_copies_frames_in_use() -> TestResult {
    let Ok(marked) = frame::alloc_frame() else {
        return TestResult::Fail("no frame to mark");
    };
    // SAFETY: a frame this test owns, through the direct map.
    let page = unsafe { &mut *marked.start_address().kernel_mut_ptr::<[u8; 4096]>() };
    for (i, byte) in page.iter_mut().enumerate() {
        *byte = (i as u8) ^ 0xA5;
    }
    let prealloc = match preallocate() {
        Ok(prealloc) => prealloc,
        Err(why) => {
            frame::free_frame(marked);
            return match why {
                SnapshotError::NoMemory { .. } => TestResult::Skip("not enough free memory"),
                SnapshotError::Grew { .. } => TestResult::Fail("preallocation grew"),
            };
        }
    };
    let capacity = prealloc.capacity();
    let copy_pfns: Vec<u64> = prealloc
        .snapshot
        .copies
        .iter()
        .map(|&f| pfn_of(f))
        .collect();
    let irqs = narf_arch::interrupts_enabled();
    // SAFETY: the copy's preconditions hold for the frames this test checks:
    // nothing else touches them, and the walk only reads.
    let snapshot = unsafe {
        narf_arch::disable_interrupts();
        let snapshot = prealloc.copy();
        if irqs {
            narf_arch::enable_interrupts();
        }
        snapshot
    };
    let mut snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(_) => {
            frame::free_frame(marked);
            return TestResult::Fail("the copy outgrew its preallocation");
        }
    };
    snapshot.release_spare();
    let pfns = snapshot.pfns();
    let ascending = pfns.windows(2).all(|w| w[0] < w[1]);
    let marked_pfn = pfn_of(marked);
    let copied = pfns.binary_search(&marked_pfn).ok().is_some_and(|i| {
        let (pfn, page) = snapshot.page(i);
        pfn == marked_pfn
            && page
                .iter()
                .enumerate()
                .all(|(i, &byte)| byte == (i as u8) ^ 0xA5)
    });
    let ram: u64 = frame::saveable_ram_ranges()
        .iter()
        .map(|&(start, end)| end - start)
        .sum();
    let copies_saved = copy_pfns.iter().any(|pfn| pfns.binary_search(pfn).is_ok());
    let len = snapshot.len();
    drop(snapshot);
    frame::free_frame(marked);
    if len == 0 || len > capacity || !ascending {
        return TestResult::Fail("the snapshot's frame list is empty, too long or unordered");
    }
    if !copied {
        return TestResult::Fail("a frame in use was not saved with its contents");
    }
    if len as u64 + capacity as u64 > ram {
        return TestResult::Fail("saved and copy frames outnumber RAM: free frames were saved");
    }
    if copies_saved {
        return TestResult::Fail("a copy frame was saved");
    }
    TestResult::Pass
}
kernel_test_in!("power/hibernate", snapshot_copies_frames_in_use);

/// The RAM ranges are sorted, disjoint and non-empty.
fn snapshot_ranges_are_merged() -> TestResult {
    let ranges = frame::saveable_ram_ranges();
    if ranges.is_empty() {
        return TestResult::Fail("no RAM to save");
    }
    if ranges.iter().any(|&(start, end)| start >= end)
        || ranges.windows(2).any(|w| w[0].1 >= w[1].0)
    {
        return TestResult::Fail("the RAM ranges overlap, touch or are empty");
    }
    TestResult::Pass
}
kernel_test_in!("power/hibernate", snapshot_ranges_are_merged);
