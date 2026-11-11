//! What GEM does when memory is short: how system backing walks the buddy
//! orders (ttm_pool_alloc).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// ttm_pool_alloc: the walk starts at the largest order that fits and,
/// once an order fails, never asks for it again
/// (`order = ttm_pool_alloc_find_order(order, alloc)` after `--order`): at
/// most one failed attempt per order, however large the buffer.
fn system_backing_lowers_the_order_once_as_ttm_pool_alloc() -> TestResult {
    // A 3840x2160 XRGB8888 buffer: 8448 pages.
    const PAGES: u64 = 8448;
    let run = |largest_free: u8| {
        let mut attempts: Vec<(u8, bool)> = Vec::new();
        let mut freed = 0u64;
        let mut next = 0x1_0000_0000u64;
        let chunks = alloc_blocks(
            PAGES,
            10,
            |order| {
                let ok = order <= largest_free;
                attempts.push((order, ok));
                ok.then(|| {
                    let at = next;
                    next += PAGE_SIZE << order;
                    at
                })
            },
            |_, order| freed += 1 << order,
        );
        (chunks, attempts, freed)
    };
    // Nothing fragmented: the binary decomposition, largest first.
    let (chunks, attempts, _) = run(10);
    let Ok(chunks) = chunks else {
        return TestResult::Fail("allocation with every order free");
    };
    let orders: Vec<u8> = chunks.iter().map(|c| c.1).collect();
    if orders != [10, 10, 10, 10, 10, 10, 10, 10, 8] || attempts.iter().any(|a| !a.1) {
        return TestResult::Fail("unfragmented walk is not the largest-first decomposition");
    }
    // Nothing above order 3 free: one refusal each for orders 10..=4, then
    // 1056 order-3 blocks.
    let (chunks, attempts, freed) = run(3);
    let Ok(chunks) = chunks else {
        return TestResult::Fail("allocation with only small orders free");
    };
    let pages: u64 = chunks.iter().map(|c| 1u64 << c.1).sum();
    if pages != PAGES || chunks.iter().any(|c| c.1 > 3) || freed != 0 {
        return TestResult::Fail("fragmented walk did not cover the buffer exactly");
    }
    // Buffer order: each block starts where the previous one ended.
    let contiguous = chunks
        .windows(2)
        .all(|w| w[1].0 == w[0].0 + (PAGE_SIZE << w[0].1));
    if !contiguous {
        return TestResult::Fail("blocks are not in buffer order");
    }
    let refused = attempts.iter().filter(|a| !a.1).count();
    if refused != 7 {
        return TestResult::Fail("an order the allocator refused was asked for again");
    }
    // Out of pages: everything taken so far goes back, and it is ENOMEM.
    let mut left = 100u64;
    let mut taken = 0u64;
    let mut freed = 0u64;
    let result = alloc_blocks(
        PAGES,
        10,
        |order| {
            (order == 0 && left > 0).then(|| {
                left -= 1;
                taken += 1;
                0x2_0000_0000 + taken * PAGE_SIZE
            })
        },
        |_, order| freed += 1 << order,
    );
    if result.is_ok() || freed != 100 {
        return TestResult::Fail("a failed walk kept or lost blocks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gem-pressure",
    system_backing_lowers_the_order_once_as_ttm_pool_alloc
);
