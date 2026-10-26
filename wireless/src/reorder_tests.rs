use super::*;
use alloc::{sync::Arc, vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_reorder_rejects_invalid_window_timeout_and_non12bit_sequence() -> TestResult {
    for window in [0, 65, 255] {
        if !matches!(Reorder::<u16>::new(window, 100), Err(Error::Window)) {
            return TestResult::Fail("invalid RX BA window allocated an owner");
        }
    }
    if !matches!(Reorder::<u16>::new(1, 0), Err(Error::Timeout)) {
        return TestResult::Fail("unbounded zero-timeout reorder owner admitted");
    }
    let mut r = Reorder::new(4, 100).unwrap();
    if r.push(4096, 0, 1) != Err(Error::Sequence)
        || r.advance(65535, 0) != Err(Error::Sequence)
        || r.head().is_some()
        || r.buffered() != 0
    {
        return TestResult::Fail("non12bit input changed auto-sequence ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_rejects_invalid_window_timeout_and_non12bit_sequence
);

fn smoke_reorder_auto_sequence_and_holes_release_original_items_in_order() -> TestResult {
    let mut r = Reorder::new(4, 100).unwrap();
    if r.head().is_some()
        || r.push(100, 0, vec![0x80, 9]).unwrap() != [vec![0x80, 9]]
        || !r.push(102, 1, vec![0x82, 11]).unwrap().is_empty()
        || !r.push(104, 2, vec![0x84, 13]).unwrap().is_empty()
        || !r.push(103, 3, vec![0x83, 12]).unwrap().is_empty()
        || r.buffered() != 3
        || r.head() != Some(101)
        || r.push(101, 4, vec![0x81, 10]).unwrap()
            != [
                vec![0x81, 10],
                vec![0x82, 11],
                vec![0x83, 12],
                vec![0x84, 13],
            ]
        || r.buffered() != 0
        || r.head() != Some(105)
    {
        return TestResult::Fail("native opaque MPDU bytes were changed or released before holes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_auto_sequence_and_holes_release_original_items_in_order
);

fn smoke_reorder_all_windows_bound_full_reverse_burst_without_stack_arrays() -> TestResult {
    for window in 1..=64 {
        let mut r = Reorder::new(window, 1000).unwrap();
        if r.window() != window || r.push(100, 0, 100).unwrap() != [100] {
            return TestResult::Fail("reorder window/first-native sequence binding");
        }
        let mut released = Vec::new();
        for sequence in (101..=100 + u16::from(window)).rev() {
            released.extend(r.push(sequence, 1, sequence).unwrap());
            if r.buffered() > usize::from(window) {
                return TestResult::Fail("reorder storage exceeded negotiated window");
            }
        }
        if released != (101..=100 + u16::from(window)).collect::<Vec<_>>()
            || r.buffered() != 0
            || r.head() != Some(101 + u16::from(window))
        {
            return TestResult::Fail("reverse native burst did not release one ordered window");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_all_windows_bound_full_reverse_burst_without_stack_arrays
);

fn smoke_reorder_duplicate_old_and_half_range_cannot_replace_or_refresh() -> TestResult {
    let mut r = Reorder::new(8, 100).unwrap();
    r.push(10, 0, 10).unwrap();
    if !r.push(12, 10, 120).unwrap().is_empty()
        || !r.push(12, 50, 999).unwrap().is_empty()
        || r.buffered() != 1
        || !r.expire(109).unwrap().is_empty()
        || r.expire(110).unwrap() != [120]
        || !r.push(10, 111, 1000).unwrap().is_empty()
        || !r.push(2061, 111, 1001).unwrap().is_empty()
        || r.head() != Some(13)
        || r.buffered() != 0
        || r.push(13, 112, 130).unwrap() != [130]
    {
        return TestResult::Fail(
            "duplicate/old/ambiguous MPDU replaced bytes or postponed hole timeout",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_duplicate_old_and_half_range_cannot_replace_or_refresh
);

fn smoke_reorder_non_power_of_two_window_survives12bit_wrap_and_bar() -> TestResult {
    let mut r = Reorder::new(3, 100).unwrap();
    if r.push(4094, 0, 1).unwrap() != [1]
        || !r.push(1, 1, 4).unwrap().is_empty()
        || !r.push(0, 2, 3).unwrap().is_empty()
        || r.push(4095, 3, 2).unwrap() != [2, 3, 4]
        || r.head() != Some(2)
        || r.buffered() != 0
        || !r.push(4094, 4, 99).unwrap().is_empty()
    {
        return TestResult::Fail("window3 modulo alias across4095→0 lost native MPDUs");
    }
    r.clear();
    if !r.advance(4095, 5).unwrap().is_empty()
        || !r.push(0, 6, 6).unwrap().is_empty()
        || r.push(4095, 7, 5).unwrap() != [5, 6]
        || r.head() != Some(1)
    {
        return TestResult::Fail("explicit native BAR head did not cross12bit wrap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_non_power_of_two_window_survives12bit_wrap_and_bar
);

fn smoke_reorder_future_window_advance_releases_owned_prefix_and_skips_empty_gap() -> TestResult {
    let mut r = Reorder::new(4, 100).unwrap();
    r.push(10, 0, 10).unwrap();
    r.push(13, 1, 13).unwrap();
    r.push(12, 2, 12).unwrap();
    if r.push(16, 3, 16).unwrap() != [12, 13]
        || r.head() != Some(14)
        || r.buffered() != 1
        || r.push(14, 4, 14).unwrap() != [14]
        || r.push(15, 5, 15).unwrap() != [15, 16]
    {
        return TestResult::Fail("future MPDU evicted/reordered wrong bounded prefix");
    }
    r.push(18, 6, 18).unwrap();
    if r.push(1000, 7, 1000).unwrap() != [18]
        || r.head() != Some(997)
        || r.buffered() != 1
        || r.expire(107).unwrap() != [1000]
        || r.head() != Some(1001)
    {
        return TestResult::Fail("large native sequence gap exceeded window or lost ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_future_window_advance_releases_owned_prefix_and_skips_empty_gap
);

fn smoke_reorder_native_bar_advances_holes_without_moving_backwards() -> TestResult {
    let mut r = Reorder::new(8, 100).unwrap();
    r.push(100, 0, 100).unwrap();
    r.push(104, 1, 104).unwrap();
    r.push(102, 2, 102).unwrap();
    if r.advance(103, 3).unwrap() != [102]
        || r.head() != Some(103)
        || r.push(103, 4, 103).unwrap() != [103, 104]
        || !r.advance(104, 5).unwrap().is_empty()
        || !r.advance(2153, 5).unwrap().is_empty()
        || r.head() != Some(105)
        || !r.advance(107, 6).unwrap().is_empty()
        || !r.push(106, 7, 999).unwrap().is_empty()
        || r.push(107, 8, 107).unwrap() != [107]
    {
        return TestResult::Fail(
            "native BAR released wrong order or old/half-range BAR regressed head",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_native_bar_advances_holes_without_moving_backwards
);

fn smoke_reorder_oldest_arrival_bounds_holes_and_push_drives_expiry() -> TestResult {
    for drive_push in [false, true] {
        let mut r = Reorder::new(8, 100).unwrap();
        r.push(10, 0, 10).unwrap();
        r.push(14, 10, 14).unwrap();
        r.push(12, 90, 12).unwrap();
        r.push(14, 109, 999).unwrap();
        if !r.expire(0).unwrap().is_empty() || !r.expire(109).unwrap().is_empty() {
            return TestResult::Fail("early/backward clock incorrectly expired native hole");
        }
        let released = if drive_push {
            r.push(11, 110, 11).unwrap()
        } else {
            r.expire(110).unwrap()
        };
        if released != [12, 14] || r.head() != Some(15) || r.buffered() != 0 {
            return TestResult::Fail("new nearer arrival/duplicate postponed oldest bounded gap");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_oldest_arrival_bounds_holes_and_push_drives_expiry
);

struct Owned {
    drops: Arc<AtomicUsize>,
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn smoke_reorder_clear_retire_and_drop_discard_opaque_items_without_delivery() -> TestResult {
    let drops = Arc::new(AtomicUsize::new(0));
    let owned = || Owned {
        drops: drops.clone(),
    };
    let mut r = Reorder::new(4, 100).unwrap();
    let released = r.push(5, 0, owned()).unwrap();
    if released.len() != 1 || drops.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("reorder discarded item instead of returning original ownership");
    }
    drop(released);
    r.push(7, 1, owned()).unwrap();
    r.push(7, 2, owned()).unwrap(); // Duplicate incoming item only.
    r.push(5, 3, owned()).unwrap(); // Old incoming item only.
    if drops.load(Ordering::Acquire) != 3 || r.buffered() != 1 {
        return TestResult::Fail("duplicate/old input replaced or leaked retained opaque owner");
    }
    r.clear();
    if drops.load(Ordering::Acquire) != 4 || r.head().is_some() || r.buffered() != 0 {
        return TestResult::Fail("key/session clear delivered or retained obsolete epoch items");
    }
    drop(r.push(300, 4, owned()).unwrap());
    r.push(302, 5, owned()).unwrap();
    r.retire();
    if drops.load(Ordering::Acquire) != 6 {
        return TestResult::Fail("explicit reorder retirement leaked opaque native ownership");
    }
    let mut r = Reorder::new(4, 100).unwrap();
    drop(r.push(1, 0, owned()).unwrap());
    r.push(3, 1, owned()).unwrap();
    drop(r);
    if drops.load(Ordering::Acquire) != 8 {
        return TestResult::Fail("implicit session drop delivered/leaked buffered opaque owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reorder",
    smoke_reorder_clear_retire_and_drop_discard_opaque_items_without_delivery
);
