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
            set_gfx12_dcc(CARD, None);
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
            fb_offset: fb_base,
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
    set_gfx12_dcc(CARD, Some(u64::from(alignment)));
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

/// amdgpu_ttm_copy_mem_to_mem's copy flags and sdma_v7_0_emit_copy_buffer's
/// DCC word for a GFX12 DCC buffer: READ_DECOMPRESSED leaving VRAM,
/// WRITE_COMPRESSED with the tiling flags' DCC fields entering it; none
/// for another buffer. A GFX12 card's DCC buffer then never moves by CPU
/// copy (`GemObject::relocate`, the CPU-mapping move): `amdgpu_vm::relocate`
/// moves it from visible VRAM to system memory and back through the card's
/// transfer engine (registered apart from the heap), and without one the
/// move fails and the buffer stays where it is.
fn gfx12_dcc_buffers_move_through_the_engine() -> TestResult {
    use crate::amdgpu_sdma_navi48 as sdma;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::AtomicUsize;
    const CARD: u32 = 0xdcc1;
    const P: u64 = 4096;
    #[derive(Debug, Default)]
    struct Engine {
        reads: AtomicUsize,
        writes: AtomicUsize,
        flags: AtomicU32,
    }
    impl VramTransfer for Engine {
        fn read<'a>(
            &'a self,
            object: Arc<GemObject>,
            source: Arc<GemPlacement>,
            destination: &'a mut GemPlacement,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                if source.vram_address().is_none() || !destination.system {
                    return Err(FsError::InvalidData);
                }
                self.flags
                    .store(ttm_copy_flags(&object, true, false), Ordering::Release);
                self.reads.fetch_add(1, Ordering::AcqRel);
                // The "decompressed" contents.
                let bytes = alloc::vec![0x5au8; source.byte_len as usize];
                // SAFETY: the destination is the mover's private, newly
                // allocated system backing of this size.
                unsafe { destination.read_staging(0, bytes.as_ptr(), bytes.len()) }
            })
        }
        fn write<'a>(
            &'a self,
            object: Arc<GemObject>,
            source: Arc<GemPlacement>,
            destination: Arc<GemPlacement>,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                if !source.system || destination.vram_address().is_none() {
                    return Err(FsError::InvalidData);
                }
                self.flags
                    .store(ttm_copy_flags(&object, false, true), Ordering::Release);
                self.writes.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        }
    }
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            unregister_vram_heap(CARD);
            register_vram_transfer(CARD, None);
            set_gfx12_dcc(CARD, None);
        }
    }
    let mut memory = alloc::vec![0u8; 1 << 20];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb800_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let fb_base = 0x8_0000_0000u64;
    // SAFETY: this test exclusively owns memory until the registered heap and
    // every object have been dropped; no hardware accesses these mappings.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, fb_base) }.unwrap();
    let _registered = Registered;
    set_gfx12_dcc(CARD, Some(65_536));
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base,
            fb_offset: fb_base,
            unmapped: None,
        },
    );
    let state = GemState::for_card(CARD);
    let make = |flags: u32| {
        let mut b = [0u64; 4];
        b[0] = P;
        b[2] = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
        b[3] = u64::from(flags);
        create(&state, b.as_mut_ptr() as usize).map(|_| state.get(b[0] as u32).unwrap())
    };
    let (Ok(dcc), Ok(plain)) = (make(uapi::AMDGPU_GEM_CREATE_GFX12_DCC), make(0)) else {
        return TestResult::Fail("buffers");
    };
    // max compressed block 2, number type 3, data format 5, write
    // compress disable.
    dcc.metadata.lock().tiling = 2 << 3 | 3 << 5 | 5 << 8 | 1 << 14;
    let read = ttm_copy_flags(&dcc, true, false);
    let write = ttm_copy_flags(&dcc, false, true);
    if read != sdma::AMDGPU_COPY_FLAGS_READ_DECOMPRESSED
        || write != sdma::AMDGPU_COPY_FLAGS_WRITE_COMPRESSED | 2 << 3 | 3 << 5 | 5 << 8 | 1 << 14
        || ttm_copy_flags(&plain, true, true) != 0
    {
        return TestResult::Fail("amdgpu_ttm_copy_mem_to_mem's copy flags");
    }
    if sdma::copy_dcc_word(read) != 2 << 16 | 1 << 26
        || sdma::copy_dcc_word(write) != 5 | 3 << 9 | 2 << 18 | 2 << 24 | 1 << 26
        || sdma::copy_dcc_word(write & !(1 << 14)) != 5 | 3 << 9 | 1 << 18 | 2 << 24 | 1 << 26
        || sdma::copy_dcc_word(0) != 0
    {
        return TestResult::Fail("sdma_v7_0_emit_copy_buffer's DCC word");
    }
    if !moves_by_engine(&dcc) || moves_by_engine(&plain) {
        return TestResult::Fail("engine moves");
    }
    // No CPU copy of the compressed bytes.
    dcc.allowed_domains
        .fetch_or(u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT), Ordering::AcqRel);
    if dcc.relocate(false) != Err(FsError::Busy)
        || cpu_mapping::relocate(&dcc, false) != Err(FsError::Busy)
        || dcc.system()
    {
        return TestResult::Fail("DCC buffer CPU-copied");
    }
    let relocate = |to_vram| {
        narf_scheduler::block_on_spin(async {
            let gate = lock_placement(CARD).await;
            crate::amdgpu_vm::relocate(&gate, &dcc, to_vram).await
        })
    };
    // No engine: the move fails, the buffer stays.
    if relocate(false) != Err(FsError::Unsupported) || dcc.system() {
        return TestResult::Fail("DCC eviction without an engine");
    }
    let engine = Arc::new(Engine::default());
    register_vram_transfer(CARD, Some(engine.clone()));
    // Out (the heap may be withdrawn meanwhile, as suspend does).
    unregister_vram_heap(CARD);
    if relocate(false).is_err()
        || !dcc.system()
        || engine.reads.load(Ordering::Acquire) != 1
        || engine.flags.load(Ordering::Acquire) != read
        || dcc.load_u64(0) != Some(0x5a5a_5a5a_5a5a_5a5a)
    {
        return TestResult::Fail("DCC eviction through the engine");
    }
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base,
            fb_offset: fb_base,
            unmapped: None,
        },
    );
    if relocate(true).is_err()
        || dcc.system()
        || engine.writes.load(Ordering::Acquire) != 1
        || engine.flags.load(Ordering::Acquire) != write
        || (dcc.gpu() - fb_base) % 65_536 != 0
    {
        return TestResult::Fail("DCC restore through the engine");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    gfx12_dcc_buffers_move_through_the_engine
);
