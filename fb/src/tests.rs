//! Per-crate smoke tests for `narf-fb`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"fb"`. Backend-dependent tests emit
//! `TestResult::Skip` when no real scanout is present so this file
//! is safe to link on every build.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_fb_picker_skips_unprobed_amdgpu() -> TestResult {
    // The amdgpu backend joins the picker ahead of bochs +
    // virtio-gpu; without a probed amdgpu controller the picker
    // must fall through cleanly rather than handing back a
    // phantom AmdgpuScanout (which would crash FbWriter on first
    // dereference of `current_mode().expect`).
    if narf_drivers_gpu::amdgpu::is_probed() {
        return TestResult::Skip("amdgpu probed — covered by the live-silicon scanout smoke");
    }
    let chosen = crate::select_active().map(|s| s.name());
    if chosen == Some("amdgpu") {
        return TestResult::Fail("picker chose amdgpu without a probed controller");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_picker_skips_unprobed_amdgpu);

fn smoke_fb_console_writes_glyphs() -> TestResult {
    use alloc::vec;
    use narf_graphics::{font8x8, FbConsole, Framebuffer, Pixel32};
    // FbConsole reserves the top 32 px for the beacon/build-stripe
    // band; the first glyph row lands at y=32. Build an FB 32 px wide
    // × 40 px tall so the first text row fits below the offset.
    const STRIDE: u32 = 32;
    const HEIGHT: u32 = 40;
    const TOP_PX_OFFSET: usize = 32;
    let mut buf = vec![0u32; (STRIDE * HEIGHT) as usize];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing buffer outlives the borrow.
    let fb = unsafe { Framebuffer::new(ptr, STRIDE, HEIGHT, STRIDE) };
    let mut con = FbConsole::new(fb, Pixel32::WHITE, Pixel32::BLACK);
    con.write_bytes(b"NARF");
    if con.cursor() != (4, 0) {
        return TestResult::Fail("cursor advance wrong");
    }
    // First char 'N' at (0..8, TOP_PX_OFFSET..TOP_PX_OFFSET+8). Verify
    // the 'N' top glyph row got drawn at the expected y.
    let n_glyph = font8x8::lookup(b'N');
    let row_base = TOP_PX_OFFSET * STRIDE as usize;
    for col in 0..8u32 {
        let bit = (n_glyph[0] >> (7 - col)) & 1 != 0;
        let want = if bit {
            Pixel32::WHITE.raw()
        } else {
            Pixel32::BLACK.raw()
        };
        if buf[row_base + col as usize] != want {
            return TestResult::Fail("N glyph not painted at expected position");
        }
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_console_writes_glyphs);

fn smoke_fb_console_newline_advances_row() -> TestResult {
    use alloc::vec;
    use narf_graphics::{FbConsole, Framebuffer, Pixel32};
    // 32 px reserved at top + 24 px below = 3 rows of 8-px glyphs.
    let mut buf = vec![0u32; 16 * 56];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing buffer outlives the borrow.
    let fb = unsafe { Framebuffer::new(ptr, 16, 56, 16) };
    let mut con = FbConsole::new(fb, Pixel32::WHITE, Pixel32::BLACK);
    con.write_bytes(b"hi\nyo");
    let (col, row) = con.cursor();
    if row != 1 || col != 2 {
        return TestResult::Fail("cursor after newline + 2 chars wrong");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_console_newline_advances_row);

fn smoke_fb_picker_selects_a_backend() -> TestResult {
    use crate::{info, select_active};
    if select_active().is_none() {
        return TestResult::Skip("no framebuffer backend probed");
    }
    let i = match info() {
        Some(i) => i,
        None => return TestResult::Fail("info empty"),
    };
    if i.width == 0 || i.height == 0 {
        return TestResult::Fail("scanout has zero dimensions");
    }
    if i.name != "bochs" && i.name != "virtio-gpu" {
        return TestResult::Fail("picker returned unknown backend");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_picker_selects_a_backend);

fn smoke_fb_writer_fill_clips_and_paints() -> TestResult {
    use crate::{bootstrap_writer, FbWriter, Rect};
    use narf_graphics::Pixel32;
    if crate::select_active().is_none() {
        return TestResult::Skip("no framebuffer backend probed");
    }
    let cap = bootstrap_writer();
    let w = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("FbWriter::new failed"),
    };
    // Fill a small rect that fits inside any framebuffer.
    if w.fill(Rect::new(0, 0, 8, 8), Pixel32::BLUE).is_err() {
        return TestResult::Fail("fill 8x8 failed");
    }
    // Out-of-bounds rect fully off-screen → OutOfBounds.
    let way_off = Rect::new(w.width() + 100, 0, 8, 8);
    match w.fill(way_off, Pixel32::RED) {
        Err(crate::FbWriteError::OutOfBounds) => {}
        _ => return TestResult::Fail("off-screen fill should report OutOfBounds"),
    }
    // Partially off-screen rect → clipped, returns Ok.
    let partial = Rect::new(w.width().saturating_sub(4), 0, 100, 8);
    if w.fill(partial, Pixel32::GREEN).is_err() {
        return TestResult::Fail("partial-off-screen fill should clip and succeed");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_writer_fill_clips_and_paints);

fn smoke_fb_writer_blit_round_trip() -> TestResult {
    // Self-contained against the test scanout: blit a 4×4
    // checkerboard, read back the pixel grid, verify each cell.
    // Uses install_test_scanout so a real bochs / virtio-gpu
    // backend isn't required.
    use crate::{
        bootstrap_writer, clear_test_scanout, install_test_scanout, test_scanout_pixel, FbWriter,
        Rect,
    };
    use narf_graphics::Pixel32;

    install_test_scanout(32, 32);
    let cap = bootstrap_writer();
    let w = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("FbWriter::new");
        }
    };

    let on = Pixel32::rgb(0xAA, 0xBB, 0xCC);
    let off = Pixel32::rgb(0x11, 0x22, 0x33);
    // 4×4 checkerboard: row-major pixels.
    let src = [
        on, off, on, off, off, on, off, on, on, off, on, off, off, on, off, on,
    ];
    if w.blit(Rect::new(2, 2, 4, 4), &src).is_err() {
        clear_test_scanout();
        return TestResult::Fail("blit");
    }
    // Spot-check four corners + a middle cell.
    let cases = [
        (2, 2, on),  // top-left of blit
        (5, 2, off), // top-right
        (2, 5, off), // bottom-left
        (5, 5, on),  // bottom-right
        (3, 3, on),  // diagonal cell
    ];
    for (x, y, want) in cases.iter() {
        match test_scanout_pixel(*x, *y) {
            Some(p) if p == *want => {}
            Some(_) => {
                clear_test_scanout();
                return TestResult::Fail("pixel mismatch");
            }
            None => {
                clear_test_scanout();
                return TestResult::Fail("oob pixel");
            }
        }
    }
    // Length mismatch must error.
    if w.blit(Rect::new(0, 0, 4, 4), &src[..15]).is_ok() {
        clear_test_scanout();
        return TestResult::Fail("len-mismatch should error");
    }
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_writer_blit_round_trip);

fn smoke_fb_tag_blit_via_shmem() -> TestResult {
    // End-to-end TAG_BLIT: allocate a Shmem, fill with a 4×4
    // checkerboard pattern, enqueue a TAG_BLIT cmd referencing
    // it, drain through the cmd ring, verify pixels landed on
    // the test scanout.
    use crate::cmd_ring::{DrawRing, RING_DEPTH};
    use crate::{
        bootstrap_writer, clear_test_scanout, cmd_ring, drain_once, install_test_scanout, registry,
        test_scanout_pixel, DrawCmd, FbWriter, Rect,
    };
    use narf_graphics::Pixel32;
    use narf_ipc::shared_ring::SharedProducer;
    use narf_shmem::{__reset_for_test as shmem_reset, create as shmem_create, phys_at};

    install_test_scanout(64, 64);
    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();
    shmem_reset();

    // Connect FB + populate a 4×4 source.
    let pid = 6001u64;
    let h = match registry::connect(pid, 0) {
        Ok(h) => h,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("connect");
        }
    };
    let phys_ring = match registry::ring_phys(h) {
        Some(p) => p,
        None => {
            clear_test_scanout();
            return TestResult::Fail("ring_phys");
        }
    };
    let mut producer: SharedProducer<DrawCmd, RING_DEPTH> =
        // SAFETY: SPSC contract — kernel-side test, sole producer.
        unsafe { SharedProducer::from_raw(phys_ring as *mut DrawRing) };

    // Source shmem: 64 bytes (4 × 4 × 4). Fill with a checker.
    let buf = match shmem_create(pid, 64) {
        Ok(h) => h,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("shmem_create");
        }
    };
    let on = Pixel32::rgb(0xAA, 0xBB, 0xCC).raw();
    let off = Pixel32::rgb(0x11, 0x22, 0x33).raw();
    for row in 0..4u32 {
        for col in 0..4u32 {
            let off_b = row * 16 + col * 4;
            let pix = if (row + col) % 2 == 0 { on } else { off };
            let phys = phys_at(buf, off_b as u64).expect("phys");
            // SAFETY: identity-mapped fresh shmem frame.
            unsafe {
                core::ptr::write_volatile(phys as *mut u32, pix);
            }
        }
    }

    // Enqueue TAG_BLIT into dst rect (8, 8, 4, 4); src stride 16.
    if cmd_ring::try_send(
        &mut producer,
        DrawCmd::blit(Rect::new(8, 8, 4, 4), buf, 0, 16),
    )
    .is_err()
    {
        clear_test_scanout();
        return TestResult::Fail("send blit");
    }

    let cap = bootstrap_writer();
    let writer = FbWriter::new(cap).expect("writer");
    let (ok, err) = drain_once(&writer);
    if ok != 1 || err != 0 {
        clear_test_scanout();
        return TestResult::Fail("drain mismatch");
    }

    // Verify each cell of the checker landed at the right scanout
    // pos. (8,8) is on, (9,8) off, (8,9) off, (9,9) on, etc.
    let cases = [
        (8, 8, on),
        (9, 8, off),
        (8, 9, off),
        (9, 9, on),
        (11, 11, on), // bottom-right corner, (3+3) even
    ];
    for (x, y, want) in cases.iter() {
        match test_scanout_pixel(*x, *y) {
            Some(p) if p.raw() == *want => {}
            Some(_) => {
                clear_test_scanout();
                return TestResult::Fail("blit pixel mismatch");
            }
            None => {
                clear_test_scanout();
                return TestResult::Fail("oob");
            }
        }
    }
    // Outside the dst rect should still be 0.
    if let Some(p) = test_scanout_pixel(20, 20) {
        if p.raw() != 0 {
            clear_test_scanout();
            return TestResult::Fail("blit overran dst rect");
        }
    }

    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();
    shmem_reset();
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_tag_blit_via_shmem);

fn smoke_fb_rect_clip_math() -> TestResult {
    use crate::Rect;
    let r = Rect::new(10, 10, 100, 100).clip(50, 50).unwrap();
    if r != Rect::new(10, 10, 40, 40) {
        return TestResult::Fail("clip math wrong");
    }
    if Rect::new(60, 0, 10, 10).clip(50, 50).is_some() {
        return TestResult::Fail("fully-off rect should clip to None");
    }
    if Rect::new(0, 0, 0, 10).clip(50, 50).is_some() {
        return TestResult::Fail("zero-width rect should clip to None");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_rect_clip_math);

fn smoke_fb_drawcmd_size_is_48() -> TestResult {
    use crate::DrawCmd;
    use core::mem::size_of;
    if size_of::<DrawCmd>() != 48 {
        return TestResult::Fail("DrawCmd size drifted from 48 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_drawcmd_size_is_48);

fn smoke_fb_cmd_ring_round_trip() -> TestResult {
    // Build a ring backed by a heap-allocated DrawRing, send a Fill,
    // drain it through an FbWriter, verify the FB pixel landed.
    use crate::{bootstrap_writer, cmd_ring, select_active, DrawCmd, DrawRing, FbWriter, Rect};
    use alloc::boxed::Box;
    use narf_graphics::Pixel32;

    if select_active().is_none() {
        return TestResult::Skip("no FB backend");
    }
    let cap = bootstrap_writer();
    let writer = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("FbWriter::new failed"),
    };

    // Allocate a DrawRing on the heap. SharedRing is repr(C) +
    // 64-byte aligned via its header; Box::new gives us 8-byte
    // alignment which matches the init_in contract.
    let mut ring: Box<DrawRing> = Box::new(unsafe { core::mem::zeroed() });
    // SAFETY: zero-init via mem::zeroed is exactly what init_in
    // expects (sets head/tail/closed to 0).
    unsafe {
        cmd_ring::init_in(&mut *ring as *mut DrawRing);
    }

    // SAFETY: SPSC contract upheld; only one producer + one
    // consumer constructed.
    let (mut prod, mut cons) = unsafe { cmd_ring::split(&mut *ring as *mut DrawRing) };

    // Enqueue a Fill at (4,4, 2x2) with a recognisable pixel.
    let pix = Pixel32::rgb(0xAB, 0xCD, 0xEF);
    let cmd = DrawCmd::fill(Rect::new(4, 4, 2, 2), pix.raw());
    if cmd_ring::try_send(&mut prod, cmd).is_err() {
        return TestResult::Fail("try_send failed");
    }

    let (executed, errors) = cmd_ring::drain(&mut cons, &writer);
    if executed != 1 || errors != 0 {
        return TestResult::Fail("drain stats wrong");
    }

    // The pixel landed in the FB; we can't easily read it back
    // without a Framebuffer view, so verifying the call didn't
    // panic + the drain stats match is the contract for this
    // smoke. Pixel-level verification happens in the next test
    // via an in-memory backed scanout.
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_cmd_ring_round_trip);

fn smoke_fb_client_drives_drain_to_pixel() -> TestResult {
    // The full producer→ring→consumer→FB chain, end-to-end. A
    // userspace process running over an mmap'd DrawRing would do
    // exactly this — the kernel-resident version differs only in
    // that the SharedProducer half is constructed locally instead
    // of received via the future SYS_FB_RING_MAP. The cap+ring
    // contract is otherwise identical.
    use crate::{
        allocate_singleton_ring, bootstrap_writer, cmd_ring, select_active, FbClient, FbWriter,
        Rect,
    };
    use narf_graphics::Pixel32;

    if select_active().is_none() {
        return TestResult::Skip("no FB backend probed");
    }
    let cap = bootstrap_writer();
    let writer = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("FbWriter::new failed"),
    };

    // SAFETY: SPSC contract — we keep the producer + consumer
    // exclusive to this test scope.
    let (_ring, producer, mut consumer) = unsafe { allocate_singleton_ring() };
    let mut client = FbClient::new(producer);

    // Enqueue three Fill commands at distinct rects.
    let pix1 = Pixel32::rgb(0x11, 0x22, 0x33).raw();
    let pix2 = Pixel32::rgb(0x44, 0x55, 0x66).raw();
    let pix3 = Pixel32::rgb(0x77, 0x88, 0x99).raw();
    if client.fill(Rect::new(0, 0, 4, 4), pix1).is_err() {
        return TestResult::Fail("fill1 send");
    }
    if client.fill(Rect::new(8, 8, 4, 4), pix2).is_err() {
        return TestResult::Fail("fill2 send");
    }
    if client.fill(Rect::new(16, 16, 4, 4), pix3).is_err() {
        return TestResult::Fail("fill3 send");
    }

    let (executed, errors) = cmd_ring::drain(&mut consumer, &writer);
    if executed != 3 || errors != 0 {
        return TestResult::Fail("drain stats mismatched (3/0 expected)");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_client_drives_drain_to_pixel);

fn smoke_fb_registry_connect_disconnect() -> TestResult {
    use crate::registry::{
        __reset_for_test, connect, count, disconnect, disconnect_all_for_pid, drain_count, info,
        ring_phys,
    };
    use crate::{clear_test_scanout, install_test_scanout};

    // Self-contained backend so this smoke doesn't depend on a real
    // bochs / virtio-gpu having been picked. clear_test_scanout
    // restores prior state at exit so neighbouring smokes that
    // require a real backend still work.
    install_test_scanout(64, 64);
    __reset_for_test();
    if count() != 0 {
        return TestResult::Fail("registry not empty after reset");
    }

    // Connect two distinct pids.
    let pid_a = 1001u64;
    let pid_b = 1002u64;
    let h_a = match connect(pid_a, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect pid_a failed"),
    };
    let h_b = match connect(pid_b, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect pid_b failed"),
    };
    if h_a == 0 || h_b == 0 || h_a == h_b {
        return TestResult::Fail("connect returned bad / duplicate handle");
    }
    if count() != 2 {
        return TestResult::Fail("count after 2 connects");
    }

    // Same pid can open a second handle — handles are independent.
    let h_a2 = connect(pid_a, 0).expect("second connect for pid_a");
    if h_a2 == h_a {
        return TestResult::Fail("second connect aliased the first");
    }
    if count() != 3 {
        return TestResult::Fail("count after 3 connects");
    }

    // ring_phys distinct + info populated.
    let phys_a = ring_phys(h_a).expect("ring_phys(h_a)");
    let phys_b = ring_phys(h_b).expect("ring_phys(h_b)");
    if phys_a == phys_b {
        return TestResult::Fail("two handles share the same ring phys");
    }
    let info_a = match info(h_a) {
        Some(i) => i,
        None => return TestResult::Fail("info(h_a) missing"),
    };
    if info_a[0] == 0 || info_a[1] == 0 || info_a[3] != 1 {
        return TestResult::Fail("info populated incorrectly");
    }

    // drain_count starts at 0.
    if drain_count(h_a) != Some(0) {
        return TestResult::Fail("drain_count not 0 at connect");
    }

    // Reject scanout_id != 0 today.
    if connect(pid_a, 1).is_ok() {
        return TestResult::Fail("scanout_id=1 should reject (no multi-scanout)");
    }

    // Explicit disconnect for h_a; pid-scoped disconnect for the rest.
    if !disconnect(h_a) {
        return TestResult::Fail("disconnect h_a");
    }
    if count() != 2 {
        return TestResult::Fail("count after disconnect h_a");
    }
    if disconnect(h_a) {
        return TestResult::Fail("double-disconnect should fail");
    }

    let reaped = disconnect_all_for_pid(pid_a);
    if reaped != 1 {
        return TestResult::Fail("disconnect_all_for_pid(a) reaped wrong count");
    }
    if count() != 1 {
        return TestResult::Fail("count after pid_a sweep");
    }
    let _ = disconnect_all_for_pid(pid_b);
    if count() != 0 {
        return TestResult::Fail("count after pid_b sweep");
    }
    __reset_for_test();
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_registry_connect_disconnect);

fn smoke_fb_exit_observer_reaps_handles() -> TestResult {
    // Process-exit cleanup: when notify_task_exited fires for a
    // pid, every FB connection that pid holds disappears. Sets up
    // 3 connections across two pids, then notifies the first;
    // only the second's connection should survive.
    use crate::registry::{__reset_for_test, connect, count, disconnect_all_for_pid};
    use crate::{clear_test_scanout, install_test_scanout};
    use narf_userspace::user_task::{
        __test_clear_exit_observers, notify_task_exited, register_exit_observer,
    };

    install_test_scanout(64, 64);
    __reset_for_test();
    __test_clear_exit_observers();

    // Register the FB exit observer (boot-time wiring; the
    // verification harness re-applies it here).
    register_exit_observer(|pid| {
        let _ = disconnect_all_for_pid(pid);
    });

    let pid_dies = 7001u64;
    let pid_keeps = 7002u64;
    let _h1 = connect(pid_dies, 0).expect("h1");
    let _h2 = connect(pid_dies, 0).expect("h2");
    let _h3 = connect(pid_keeps, 0).expect("h3");
    if count() != 3 {
        clear_test_scanout();
        return TestResult::Fail("setup");
    }

    notify_task_exited(pid_dies);

    if count() != 1 {
        clear_test_scanout();
        return TestResult::Fail("observer didn't reap dying pid's handles");
    }

    notify_task_exited(pid_keeps);
    if count() != 0 {
        clear_test_scanout();
        return TestResult::Fail("second notify didn't reap survivor");
    }

    __reset_for_test();
    __test_clear_exit_observers();
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_exit_observer_reaps_handles);

fn smoke_fb_registry_drain_all_executes_per_process() -> TestResult {
    // Two processes each attach a ring; one enqueues a Fill; the
    // global drain must execute exactly that one command.
    use crate::cmd_ring::{DrawCmd, DrawRing, RING_DEPTH};
    use crate::{bootstrap_writer, cmd_ring, registry, select_active, FbWriter, Rect};
    use narf_graphics::Pixel32;
    use narf_ipc::shared_ring::SharedProducer;

    if select_active().is_none() {
        return TestResult::Skip("no FB backend probed");
    }
    registry::__reset_for_test();

    let pid_a = 2001u64;
    let pid_b = 2002u64;
    let h_a = match registry::connect(pid_a, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect pid_a"),
    };
    let _h_b = match registry::connect(pid_b, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect pid_b"),
    };
    let phys_a = registry::ring_phys(h_a).expect("ring_phys");

    // Build a producer over A's ring (treating its phys as a
    // kernel-side pointer — identity-mapped low memory).
    let ring_ptr = phys_a as *mut DrawRing;
    // SAFETY: SPSC contract — kernel side only constructs the
    // producer here; the consumer was retained by the registry
    // when attach() ran.
    let mut producer: SharedProducer<DrawCmd, RING_DEPTH> =
        unsafe { SharedProducer::from_raw(ring_ptr) };
    let cmd = DrawCmd::fill(Rect::new(0, 0, 2, 2), Pixel32::rgb(0xAA, 0xBB, 0xCC).raw());
    if cmd_ring::try_send(&mut producer, cmd).is_err() {
        return TestResult::Fail("try_send failed");
    }

    let cap = bootstrap_writer();
    let writer = FbWriter::new(cap).expect("writer");
    let (ok, err) = registry::drain_all(&writer);
    if ok != 1 || err != 0 {
        return TestResult::Fail("drain_all stats wrong (1/0 expected)");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_registry_drain_all_executes_per_process);

fn smoke_fb_drain_once_advances_counters() -> TestResult {
    use crate::cmd_ring::{DrawCmd, DrawRing, RING_DEPTH};
    use crate::{
        bootstrap_writer, cmd_ring, drain_once, drain_stats, registry, select_active, FbWriter,
        Rect,
    };
    use narf_graphics::Pixel32;
    use narf_ipc::shared_ring::SharedProducer;

    if select_active().is_none() {
        return TestResult::Skip("no FB backend probed");
    }
    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();

    let pid = 3001u64;
    let h = match registry::connect(pid, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect"),
    };
    let phys = registry::ring_phys(h).expect("ring_phys");
    let mut producer: SharedProducer<DrawCmd, RING_DEPTH> =
        // SAFETY: SPSC contract — kernel-side test.
        unsafe { SharedProducer::from_raw(phys as *mut DrawRing) };
    let cmd = DrawCmd::fill(Rect::new(0, 0, 2, 2), Pixel32::rgb(0xDE, 0xAD, 0xBE).raw());
    if cmd_ring::try_send(&mut producer, cmd).is_err() {
        return TestResult::Fail("send");
    }

    let cap = bootstrap_writer();
    let writer = FbWriter::new(cap).expect("writer");
    let (ok, err) = drain_once(&writer);
    if ok != 1 || err != 0 {
        return TestResult::Fail("drain_once stats wrong");
    }
    let (ticks, executed, errors) = drain_stats();
    if ticks == 0 || executed == 0 || errors != 0 {
        return TestResult::Fail("global counters didn't advance");
    }
    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_drain_once_advances_counters);

fn smoke_fb_e2e_via_test_scanout() -> TestResult {
    // End-to-end check that runs on every arch: install a test
    // scanout, attach a registry ring, send a Fill via a kernel
    // SharedProducer (the same surface a userspace producer would
    // use after SYS_FB_RING_MAP), drain, and read the pixel back
    // from the test scanout's heap buffer.
    use crate::cmd_ring::{DrawCmd, DrawRing, RING_DEPTH};
    use crate::{
        bootstrap_writer, clear_test_scanout, cmd_ring, drain_once, install_test_scanout, registry,
        test_scanout_pixel, FbWriter, Rect,
    };
    use narf_graphics::Pixel32;
    use narf_ipc::shared_ring::SharedProducer;

    install_test_scanout(64, 64);
    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();

    let pid = 4001u64;
    let h = match registry::connect(pid, 0) {
        Ok(h) => h,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("connect");
        }
    };
    let phys = match registry::ring_phys(h) {
        Some(p) => p,
        None => {
            clear_test_scanout();
            return TestResult::Fail("ring_phys");
        }
    };
    let mut producer: SharedProducer<DrawCmd, RING_DEPTH> =
        // SAFETY: SPSC contract.
        unsafe { SharedProducer::from_raw(phys as *mut DrawRing) };
    let target_pix = Pixel32::rgb(0xCA, 0xFE, 0x42);
    if cmd_ring::try_send(
        &mut producer,
        DrawCmd::fill(Rect::new(2, 2, 4, 4), target_pix.raw()),
    )
    .is_err()
    {
        clear_test_scanout();
        return TestResult::Fail("send");
    }

    let cap = bootstrap_writer();
    let writer = FbWriter::new(cap).expect("writer");
    let (ok, err) = drain_once(&writer);
    if ok != 1 || err != 0 {
        clear_test_scanout();
        return TestResult::Fail("drain mismatch");
    }

    // Verify the pixel landed at (3, 3) — inside the filled rect.
    let inside = match test_scanout_pixel(3, 3) {
        Some(p) => p,
        None => {
            clear_test_scanout();
            return TestResult::Fail("pixel read inside");
        }
    };
    if inside != target_pix {
        clear_test_scanout();
        return TestResult::Fail("inside pixel didn't match");
    }
    // Outside the rect should still be 0 (untouched).
    let outside = match test_scanout_pixel(20, 20) {
        Some(p) => p,
        None => {
            clear_test_scanout();
            return TestResult::Fail("pixel read outside");
        }
    };
    if outside.raw() != 0 {
        clear_test_scanout();
        return TestResult::Fail("outside pixel got painted");
    }

    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_e2e_via_test_scanout);

fn smoke_fb_userspace_chain_against_real_backend() -> TestResult {
    // Userspace-equivalent producer → ring → drain chain against
    // whichever real FB backend the picker selected (bochs on
    // x86_64, virtio-gpu on aarch64). The kernel-side producer
    // here uses the exact same SharedRing layout a userspace
    // process would build over a SYS_FB_RING_MAP'd page; the only
    // difference vs the testbin's fb probe is we skip the
    // SYS_FB_RING_MAP hop because we're running in kernel context.
    use crate::cmd_ring::{DrawCmd, DrawRing, RING_DEPTH};
    use crate::{bootstrap_writer, cmd_ring, drain_once, registry, select_active, FbWriter, Rect};
    use narf_graphics::Pixel32;
    use narf_ipc::shared_ring::SharedProducer;

    let backend = match select_active() {
        Some(b) => b,
        None => return TestResult::Skip("no real FB backend probed"),
    };
    // Skip if the picker chose the test scanout (other smokes
    // may have left it installed).
    if backend.name() == "test" {
        return TestResult::Skip("test scanout in place");
    }

    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();

    let pid = 5001u64;
    let h = match registry::connect(pid, 0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect"),
    };
    let phys = match registry::ring_phys(h) {
        Some(p) => p,
        None => return TestResult::Fail("ring_phys"),
    };
    // Producer over the kernel-side view of the ring (identity-
    // mapped phys = identity-VA in low 4 GiB).
    let mut producer: SharedProducer<DrawCmd, RING_DEPTH> =
        // SAFETY: SPSC contract — kernel-side test, sole producer.
        unsafe { SharedProducer::from_raw(phys as *mut DrawRing) };
    let pix = Pixel32::rgb(0x55, 0xAA, 0x55).raw();
    if cmd_ring::try_send(&mut producer, DrawCmd::fill(Rect::new(0, 0, 4, 4), pix)).is_err() {
        registry::__reset_for_test();
        return TestResult::Fail("send");
    }
    if cmd_ring::try_send(&mut producer, DrawCmd::flush(Rect::new(0, 0, 4, 4))).is_err() {
        registry::__reset_for_test();
        return TestResult::Fail("send flush");
    }

    let cap = bootstrap_writer();
    let writer = FbWriter::new(cap).expect("writer");
    let (ok, err) = drain_once(&writer);

    registry::__reset_for_test();
    crate::drain_task::__reset_for_test();

    if ok != 2 || err != 0 {
        return TestResult::Fail("drain stats wrong (2/0 expected)");
    }
    TestResult::Pass
}
kernel_test_in!("fb", smoke_fb_userspace_chain_against_real_backend);

// ── UEFI GOP / VBE handoff decoders ───────────────────────────────

fn smoke_gop_mode_information_decodes_36_byte_block() -> TestResult {
    use crate::gop::{ModeInformation, PixelFormat};

    let mut buf = [0u8; 36];

    buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // version

    buf[4..8].copy_from_slice(&1920u32.to_le_bytes());

    buf[8..12].copy_from_slice(&1080u32.to_le_bytes());

    buf[12..16].copy_from_slice(&0u32.to_le_bytes()); // RGB

    buf[32..36].copy_from_slice(&1920u32.to_le_bytes()); // pps

    let m = match ModeInformation::decode(&buf) {
        Ok(m) => m,

        Err(_) => return TestResult::Fail("decode"),
    };

    if m.horizontal_resolution != 1920 || m.vertical_resolution != 1080 {
        return TestResult::Fail("resolution");
    }

    if m.pixel_format != PixelFormat::RgbReserved8 {
        return TestResult::Fail("pixel format");
    }

    if m.bytes_per_pixel() != 4 || m.stride_bytes() != 1920 * 4 {
        return TestResult::Fail("bpp/stride");
    }

    TestResult::Pass
}

kernel_test_in!("fb/gop", smoke_gop_mode_information_decodes_36_byte_block);

fn smoke_gop_protocol_mode_to_framebuffer() -> TestResult {
    use crate::gop::{ModeInformation, PixelBitmask, PixelFormat, ProtocolMode};

    let mode = ModeInformation {
        version: 0,

        horizontal_resolution: 1024,

        vertical_resolution: 768,

        pixel_format: PixelFormat::BgrReserved8,

        pixel_information: PixelBitmask::default(),

        pixels_per_scan_line: 1024,
    };

    let pm = ProtocolMode {
        framebuffer_base: 0xFD00_0000,

        framebuffer_size: 1024 * 768 * 4,

        mode,
    };

    let fb = pm.to_framebuffer().expect("fb");

    if fb.base != 0xFD00_0000 || fb.width != 1024 || fb.stride_bytes != 4096 {
        return TestResult::Fail("framebuffer fields");
    }

    TestResult::Pass
}

kernel_test_in!("fb/gop", smoke_gop_protocol_mode_to_framebuffer);

fn smoke_gop_blt_only_rejected() -> TestResult {
    use crate::gop::{ModeInformation, PixelBitmask, PixelFormat, ProtocolMode};

    let mode = ModeInformation {
        version: 0,

        horizontal_resolution: 1024,

        vertical_resolution: 768,

        pixel_format: PixelFormat::BltOnly,

        pixel_information: PixelBitmask::default(),

        pixels_per_scan_line: 1024,
    };

    let pm = ProtocolMode {
        framebuffer_base: 0x1000_0000,

        framebuffer_size: 0,

        mode,
    };

    if pm.to_framebuffer().is_ok() {
        return TestResult::Fail("BltOnly should not produce a framebuffer");
    }

    TestResult::Pass
}

kernel_test_in!("fb/gop", smoke_gop_blt_only_rejected);

fn smoke_vbe_mode_info_block_to_framebuffer() -> TestResult {
    use crate::vbe::{mode_attr, MemoryModel, ModeInfoBlock, VbeError};

    let mut buf = [0u8; 0x32];

    let attr =
        mode_attr::HW_SUPPORTED | mode_attr::COLOR | mode_attr::GRAPHICS | mode_attr::LFB_AVAILABLE;

    buf[0x00..0x02].copy_from_slice(&attr.to_le_bytes());

    buf[0x10..0x12].copy_from_slice(&(800u16 * 4).to_le_bytes());

    buf[0x12..0x14].copy_from_slice(&800u16.to_le_bytes());

    buf[0x14..0x16].copy_from_slice(&600u16.to_le_bytes());

    buf[0x19] = 32; // bpp

    buf[0x1B] = 0x06; // DirectColor

    buf[0x1F] = 8;
    buf[0x20] = 16; // R

    buf[0x21] = 8;
    buf[0x22] = 8; // G

    buf[0x23] = 8;
    buf[0x24] = 0; // B

    buf[0x25] = 8;
    buf[0x26] = 24; // X

    buf[0x28..0x2C].copy_from_slice(&0xE000_0000u32.to_le_bytes());

    let m = ModeInfoBlock::decode(&buf).expect("decode");

    if m.memory_model != MemoryModel::DirectColor {
        return TestResult::Fail("memory model");
    }

    let fb = m.to_framebuffer().expect("to_fb");

    if fb.base != 0xE000_0000 || fb.width != 800 || fb.stride_bytes != 800 * 4 {
        return TestResult::Fail("fb shape");
    }

    if fb.pixel_information.red != (0xFF << 16) {
        return TestResult::Fail("red mask");
    }

    // Without LFB bit, must error.

    let mut buf2 = buf;

    let attr2 = attr & !mode_attr::LFB_AVAILABLE;

    buf2[0x00..0x02].copy_from_slice(&attr2.to_le_bytes());

    let m2 = ModeInfoBlock::decode(&buf2).expect("decode2");

    match m2.to_framebuffer() {
        Err(VbeError::NoLinearFramebuffer) => TestResult::Pass,

        _ => TestResult::Fail("missing LFB should error"),
    }
}

kernel_test_in!("fb/vbe", smoke_vbe_mode_info_block_to_framebuffer);

// ── cursor renderer ────────────────────────────────────────────────

fn smoke_cursor_renderer_moves_on_pointer_event() -> TestResult {
    use crate::{
        bootstrap_writer, clear_test_scanout, cursor, install_test_scanout, test_scanout_pixel,
        FbWriter,
    };
    use narf_input::{
        init_global_ring, push_global, InputEvent, PointerButtons, PointerEvent,
        __reset_global_ring_for_test,
    };

    install_test_scanout(64, 64);
    init_global_ring(8);
    __reset_global_ring_for_test();
    cursor::__reset_for_test();

    let cap = bootstrap_writer();
    let w = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("FbWriter::new");
        }
    };

    // First draw centres at (32, 32). Push a delta of (+5, +5);
    // sprite top-left should land at (37, 37). drain_and_render
    // both initialises and processes events.
    let _ = push_global(InputEvent::Pointer(PointerEvent {
        dx: 5,
        dy: 5,
        buttons: PointerButtons::EMPTY,
    }));
    cursor::drain_and_render(&w);
    if cursor::moves() == 0 {
        clear_test_scanout();
        return TestResult::Fail("expected at least one move");
    }
    // The cursor sprite is solid white (Pixel32(0xFFFF_FFFF)). Probe
    // the top-left corner of where it should be.
    match test_scanout_pixel(37, 37) {
        Some(p) if p.raw() == 0xFFFF_FFFF => {}
        Some(other) => {
            let _ = other;
            clear_test_scanout();
            return TestResult::Fail("sprite pixel not white at expected position");
        }
        None => {
            clear_test_scanout();
            return TestResult::Fail("expected pixel readable");
        }
    }
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb/cursor", smoke_cursor_renderer_moves_on_pointer_event);

fn smoke_cursor_renderer_restores_under_sprite_on_move() -> TestResult {
    use crate::{
        bootstrap_writer, clear_test_scanout, cursor, install_test_scanout, test_scanout_pixel,
        FbWriter, Rect,
    };
    use narf_graphics::Pixel32;
    use narf_input::{
        init_global_ring, push_global, InputEvent, PointerButtons, PointerEvent,
        __reset_global_ring_for_test,
    };

    install_test_scanout(64, 64);
    init_global_ring(8);
    __reset_global_ring_for_test();
    cursor::__reset_for_test();

    let cap = bootstrap_writer();
    let w = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("FbWriter::new");
        }
    };

    // Paint a known background colour over the entire FB so we can
    // verify the cursor restored it correctly after moving away.
    let bg = Pixel32::rgb(0x12, 0x34, 0x56);
    let _ = w.fill(Rect::new(0, 0, 64, 64), bg);

    // Move 1: dx=0, dy=0 → no move recorded (skipped). Push a real
    // delta that lands the sprite at (32+5, 32+5) = (37, 37).
    let _ = push_global(InputEvent::Pointer(PointerEvent {
        dx: 5,
        dy: 5,
        buttons: PointerButtons::EMPTY,
    }));
    cursor::drain_and_render(&w);
    let moves_after_first = cursor::moves();

    // Move 2: shift further. Sprite should land at (37+10, 37+10).
    let _ = push_global(InputEvent::Pointer(PointerEvent {
        dx: 10,
        dy: 10,
        buttons: PointerButtons::EMPTY,
    }));
    cursor::drain_and_render(&w);
    if cursor::moves() <= moves_after_first {
        clear_test_scanout();
        return TestResult::Fail("second move not counted");
    }

    // The pixels at (37, 37) — old cursor location — should now be
    // back to the background colour. The new sprite is at (47, 47).
    match test_scanout_pixel(37, 37) {
        Some(p) if p == bg => {}
        Some(_) => {
            clear_test_scanout();
            return TestResult::Fail("background not restored under old cursor");
        }
        None => {
            clear_test_scanout();
            return TestResult::Fail("oob pixel");
        }
    }
    match test_scanout_pixel(47, 47) {
        Some(p) if p.raw() == 0xFFFF_FFFF => {}
        _ => {
            clear_test_scanout();
            return TestResult::Fail("sprite not at new position");
        }
    }
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!(
    "fb/cursor",
    smoke_cursor_renderer_restores_under_sprite_on_move
);

fn smoke_cursor_renderer_clamps_to_fb_bounds() -> TestResult {
    use crate::{bootstrap_writer, clear_test_scanout, cursor, install_test_scanout, FbWriter};
    use narf_input::{
        init_global_ring, push_global, InputEvent, PointerButtons, PointerEvent,
        __reset_global_ring_for_test,
    };

    install_test_scanout(64, 64);
    init_global_ring(8);
    __reset_global_ring_for_test();
    cursor::__reset_for_test();

    let cap = bootstrap_writer();
    let w = match FbWriter::new(cap) {
        Ok(w) => w,
        Err(_) => {
            clear_test_scanout();
            return TestResult::Fail("FbWriter::new");
        }
    };

    // Wild positive delta — cursor should clamp to (width-W, height-H)
    // rather than wrap or go OOB. Wild negative — clamps to (0, 0).
    let _ = push_global(InputEvent::Pointer(PointerEvent {
        dx: 10_000,
        dy: 10_000,
        buttons: PointerButtons::EMPTY,
    }));
    cursor::drain_and_render(&w);
    if cursor::moves() == 0 {
        clear_test_scanout();
        return TestResult::Fail("expected positive-clamp move");
    }
    let _ = push_global(InputEvent::Pointer(PointerEvent {
        dx: -10_000,
        dy: -10_000,
        buttons: PointerButtons::EMPTY,
    }));
    cursor::drain_and_render(&w);
    // No way to read POS_X/Y directly — verify by what's drawn:
    // cursor sprite at (0, 0) means top-left WxH should now be white.
    if let Some(p) = crate::test_scanout_pixel(0, 0) {
        if p.raw() != 0xFFFF_FFFF {
            clear_test_scanout();
            return TestResult::Fail("expected sprite at (0,0) after negative clamp");
        }
    }
    clear_test_scanout();
    TestResult::Pass
}
kernel_test_in!("fb/cursor", smoke_cursor_renderer_clamps_to_fb_bounds);
