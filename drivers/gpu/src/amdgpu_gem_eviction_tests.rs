//! Which buffers the evictions see: on an LRU card (`set_lru_eviction`,
//! Navi48) every live buffer of the card, as TTM walks its LRU, so one
//! only a framebuffer holds (CREATE_DUMB, ADDFB2, the handle closed) moves
//! too; elsewhere the opens' handle tables, as before.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn evictions_walk_every_buffer_of_an_lru_card() -> TestResult {
    const CARD: u32 = 0xe1c0;
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            unregister_vram_heap(CARD);
            set_lru_eviction(CARD, false);
        }
    }
    let mut memory = alloc::vec![0u8; 16 * 4096];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb800_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: this test exclusively owns memory until the registered heap and
    // every object have been dropped; no hardware accesses these mappings.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    let _registered = Registered;
    register_vram_heap(
        CARD,
        VramHeap {
            pool,
            fb_base: 0x8_0000_0000,
            fb_offset: 0x8_0000_0000,
            unmapped: None,
        },
    );
    let state = GemState::for_card(CARD);
    let evict = || {
        narf_scheduler::block_on_spin(async {
            let gate = lock_placement(CARD).await;
            evict_all(&gate).await
        })
    };
    // A dumb buffer whose handle is closed while a framebuffer (here, the
    // Arc a `Framebuffer::bo` holds) keeps it.
    let held = |state: &GemState| {
        let (handle, _, _) = state.create_dumb(64, 4, 32).ok()?;
        let object = state.get(handle)?;
        state.destroy_dumb(handle).then_some(object)
    };
    let Some(fb_only) = held(&state) else {
        return TestResult::Fail("framebuffer-only buffer");
    };
    // Not an LRU card: the handle tables do not hold it, so it stays.
    let (touched, result) = evict();
    restore_domains(touched);
    if result.is_err() || fb_only.system() {
        return TestResult::Fail("handle-table eviction changed");
    }
    set_lru_eviction(CARD, true);
    let Some(again) = held(&state) else {
        return TestResult::Fail("second framebuffer-only buffer");
    };
    let (touched, result) = evict();
    if result.is_err()
        || !fb_only.system()
        || !again.system()
        || touched.len() != 2
        || !touched.iter().any(|(o, _)| Arc::ptr_eq(o, &fb_only))
    {
        return TestResult::Fail("LRU eviction missed a framebuffer-only buffer");
    }
    restore_domains(touched);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    evictions_walk_every_buffer_of_an_lru_card
);
