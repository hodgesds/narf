//! GFX12 DCC VRAM placement: gmc_v12_0_get_dcc_alignment and
//! amdgpu_vram_mgr_new's GFX12_DCC | VRAM_CONTIGUOUS rounding, against the
//! Linux vectors (tests/amdgpu_dcc_vram), and GEM_CREATE placing a DCC
//! buffer there.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// `gmc_v12_dcc_alignment`, `dcc_block_size` and the first-fit block plus
/// `dcc_trim_start` give Linux's answer for every line of
/// tests/amdgpu_dcc_vram/vectors.txt (the harness's buddy hands out a
/// power-of-two block at its own alignment from the first free byte, as
/// `Pool::reserve_dcc` places one).
fn dcc_vram_placement_matches_linux_vectors() -> TestResult {
    use core::fmt::Write as _;
    const VECTORS: &str = include_str!("../tests/amdgpu_dcc_vram/vectors.txt");
    let mut lines = 0;
    let mut got = alloc::string::String::new();
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("malformed vector");
        };
        let mut f = input
            .split_whitespace()
            .skip(1)
            .map(|v| v.parse::<u64>().unwrap_or(u64::MAX));
        let (minor, tccs, size, base) = (
            f.next().unwrap_or(0),
            f.next().unwrap_or(0),
            f.next().unwrap_or(0),
            f.next().unwrap_or(0),
        );
        let alignment = gmc_v12_dcc_alignment((12, 0, minor as u8), tccs as u32);
        got.clear();
        let _ = write!(got, "{alignment}");
        if alignment == 0 {
            // No DCC rounding: the buffer is asked for at its own size (the
            // harness's stand-in buddy then places it, not Linux's).
            let Some(rest) = want.strip_prefix("0 ") else {
                return TestResult::Fail("DCC alignment differs from Linux");
            };
            if rest.split_whitespace().next() != Some(&*alloc::format!("{size}")) {
                return TestResult::Fail("non-DCC size rounded");
            }
            lines += 1;
            continue;
        }
        let block = crate::amdgpu_vram::dcc_block_size(size, u64::from(alignment));
        let start = base
            .checked_next_multiple_of(block)
            .and_then(|b| crate::amdgpu_vram::dcc_trim_start(b, u64::from(alignment)));
        let _ = write!(got, " {block} {}", start.unwrap_or(u64::MAX));
        if got != want {
            return TestResult::Fail("DCC placement differs from Linux");
        }
        lines += 1;
    }
    if lines < 1500 {
        return TestResult::Fail("vectors missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    dcc_vram_placement_matches_linux_vectors
);

/// A GFX12_DCC GEM buffer on a card with a DCC alignment lands at that
/// alignment from VRAM offset 0 (a non-power-of-two one included), inside
/// the power-of-two block Linux takes, leaving the rest of the block free;
/// a buffer without the flag, or on a card without an alignment, is placed
/// as before. Its scanout pin reports it DCC-aligned.
fn gfx12_dcc_buffers_take_the_dcc_placement() -> TestResult {
    const CARD: u32 = 0xdcc0;
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            unregister_vram_heap(CARD);
            set_dcc_alignment(CARD, 0);
        }
    }
    let mut memory = alloc::vec![0u8; 4 << 20];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb800_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // The heap's pool starts 4 KiB into VRAM, so a GPU-address alignment
    // and a VRAM-offset one differ.
    let fb_base = 0x8_0000_0000u64;
    // SAFETY: this test exclusively owns memory until the registered heap and
    // every object have been dropped; no hardware accesses these mappings.
    let pool =
        unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, fb_base + 0x1000) }.unwrap();
    let _registered = Registered;
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base,
            fb_offset: 0,
            unmapped: None,
        },
    );
    let state = GemState::for_card(CARD);
    let make = |flags: u32| {
        let mut b = [0u64; 4];
        b[0] = 4096;
        b[2] = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
        b[3] = u64::from(flags);
        create(&state, b.as_mut_ptr() as usize).map(|_| b[0] as u32)
    };
    // Without an alignment (not GC 12.0.x): the ordinary first fit.
    let Ok(plain) = make(uapi::AMDGPU_GEM_CREATE_GFX12_DCC) else {
        return TestResult::Fail("DCC buffer without an alignment");
    };
    if state.get(plain).unwrap().gpu() != fb_base + 0x1000 {
        return TestResult::Fail("DCC buffer moved without an alignment");
    }
    // 12 TCCs: 16 * 12 KiB = 192 KiB, block roundup(4 KiB + 192 KiB) = 256 KiB.
    let alignment = gmc_v12_dcc_alignment((12, 0, 1), 12);
    if alignment != 196_608 || gmc_v12_dcc_alignment((12, 0, 1), 16) != 65_536 {
        return TestResult::Fail("gmc_v12_0_get_dcc_alignment");
    }
    set_dcc_alignment(CARD, u64::from(alignment));
    let before = pool.available();
    let Ok(dcc) = make(uapi::AMDGPU_GEM_CREATE_GFX12_DCC) else {
        return TestResult::Fail("DCC buffer");
    };
    let object = state.get(dcc).unwrap();
    let offset = object.gpu() - fb_base;
    // The first free 256 KiB block from VRAM offset 8 KiB is at 256 KiB;
    // trimmed to roundup(256 KiB, 192 KiB) = 384 KiB.
    if offset != 0x6_0000 || pool.available() != before - 4096 {
        return TestResult::Fail("DCC buffer not at Linux's trimmed start");
    }
    // The trimmed-off head of the block is free again.
    let Ok(after) = make(0) else {
        return TestResult::Fail("ordinary buffer");
    };
    if state.get(after).unwrap().gpu() != fb_base + 0x2000 {
        return TestResult::Fail("ordinary buffer after a DCC one");
    }
    match object.pin_scanout() {
        Ok(pin) if pin.dcc_aligned() => {}
        _ => return TestResult::Fail("DCC buffer's pin"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    gfx12_dcc_buffers_take_the_dcc_placement
);
