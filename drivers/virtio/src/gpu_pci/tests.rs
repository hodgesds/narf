//! virtio-gpu-pci smokes — clean-room, sourced from VirtIO 1.2 §5.7.
//!
//! Stage 1: PCI match table contains both transitional ids
//!   (1AF4:1050 modern, 1AF4:1010 legacy).
//! Stage 2: VirtqueueLayout for controlq + cursorq — pure-data offsets
//!   (VirtIO 1.2 §3.2.1).
//! Stage 3: pure-data builders/decoders for the six 2D commands
//!   round-trip to byte-identical output (VirtIO 1.2 §5.7.6).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    CTRL_Q_DEPTH, CTRL_Q_INDEX, CURSOR_Q_DEPTH, CURSOR_Q_INDEX,
    VIRTIO_GPU_PCI_DEVICE, VIRTIO_GPU_PCI_DEVICE_LEGACY, VIRTIO_GPU_PCI_VENDOR,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_virtio_gpu_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [VIRTIO_GPU_PCI_DEVICE, VIRTIO_GPU_PCI_DEVICE_LEGACY];
    for did in want {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: VIRTIO_GPU_PCI_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("virtio-gpu PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci", smoke_virtio_gpu_pci_match_table);

// ── Stage 2: virtqueue layout (controlq + cursorq) ─────────────────

fn smoke_virtio_gpu_pci_queue_layout() -> TestResult {
    use crate::queue::VirtqueueLayout;
    // controlq: idx 0, depth 16. VirtIO §3.2.1: desc=16*N, avail=6+2*N,
    // used 4-byte aligned with size 6+8*N.
    let base = 0x1_0000u64;
    let l = match VirtqueueLayout::new(CTRL_Q_DEPTH, base) {
        Some(l) => l,
        None    => return TestResult::Fail("controlq layout returned None"),
    };
    if l.capacity != CTRL_Q_DEPTH { return TestResult::Fail("controlq capacity"); }
    if l.desc_table != base { return TestResult::Fail("controlq desc base"); }
    let desc_size = 16u64 * CTRL_Q_DEPTH as u64;
    if l.avail_ring != base + desc_size {
        return TestResult::Fail("controlq avail offset");
    }
    let avail_end = l.avail_ring + 6 + 2 * CTRL_Q_DEPTH as u64;
    let used_expected = (avail_end + 3) & !3u64;
    if l.used_ring != used_expected {
        return TestResult::Fail("controlq used not 4-byte aligned");
    }
    // cursorq: idx 1, depth 4 — exercises the small-depth path.
    let l2 = match VirtqueueLayout::new(CURSOR_Q_DEPTH, base) {
        Some(l) => l,
        None    => return TestResult::Fail("cursorq layout returned None"),
    };
    if l2.capacity != CURSOR_Q_DEPTH { return TestResult::Fail("cursorq capacity"); }
    if l2.avail_ring != base + 16 * CURSOR_Q_DEPTH as u64 {
        return TestResult::Fail("cursorq avail offset");
    }
    if (l2.used_ring & 3) != 0 {
        return TestResult::Fail("cursorq used not 4-byte aligned");
    }
    // Both queue indices must differ — driver-side invariant.
    if CTRL_Q_INDEX == CURSOR_Q_INDEX {
        return TestResult::Fail("queue indices collide");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci", smoke_virtio_gpu_pci_queue_layout);

// ── Stage 3: command builder round-trips (VirtIO §5.7.6) ───────────

fn smoke_virtio_gpu_pci_get_display_info_round_trip() -> TestResult {
    use super::cmd::{build_get_display_info, read_hdr,
        GET_DISPLAY_INFO_LEN, VIRTIO_GPU_CMD_GET_DISPLAY_INFO};
    let mut a = [0u8; GET_DISPLAY_INFO_LEN];
    let mut b = [0u8; GET_DISPLAY_INFO_LEN];
    build_get_display_info(&mut a);
    let h = read_hdr(&a);
    if h.cmd_type != VIRTIO_GPU_CMD_GET_DISPLAY_INFO {
        return TestResult::Fail("cmd_type mismatch");
    }
    if h.flags != 0 || h.fence_id != 0 || h.ctx_id != 0 {
        return TestResult::Fail("non-zero header tail");
    }
    build_get_display_info(&mut b);
    if a != b { return TestResult::Fail("get_display_info not deterministic"); }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_get_display_info_round_trip);

fn smoke_virtio_gpu_pci_resource_create_2d_round_trip() -> TestResult {
    use super::cmd::{build_resource_create_2d, decode_resource_create_2d,
        ResourceCreate2D, RESOURCE_CREATE_2D_LEN};
    let r = ResourceCreate2D {
        resource_id: 0xCAFE_BABE,
        format:      1, // B8G8R8X8_UNORM
        width:       1024,
        height:      768,
    };
    let mut buf  = [0u8; RESOURCE_CREATE_2D_LEN];
    let mut buf2 = [0u8; RESOURCE_CREATE_2D_LEN];
    build_resource_create_2d(&mut buf, r);
    let decoded = decode_resource_create_2d(&buf);
    if decoded != r {
        return TestResult::Fail("resource_create_2d decode mismatch");
    }
    build_resource_create_2d(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("resource_create_2d round-trip not byte-identical");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_resource_create_2d_round_trip);

fn smoke_virtio_gpu_pci_attach_backing_round_trip() -> TestResult {
    use super::cmd::{build_resource_attach_backing,
        decode_resource_attach_backing, AttachBacking, ATTACH_BACKING_LEN};
    let a = AttachBacking {
        resource_id: 0x0000_0001,
        addr:        0xDEAD_BEEF_0000_1000,
        length:      4096,
    };
    let mut buf  = [0u8; ATTACH_BACKING_LEN];
    let mut buf2 = [0u8; ATTACH_BACKING_LEN];
    build_resource_attach_backing(&mut buf, a);
    let decoded = decode_resource_attach_backing(&buf);
    if decoded != a {
        return TestResult::Fail("attach_backing decode mismatch");
    }
    // nr_entries field at offset 28 must be 1.
    if u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]) != 1 {
        return TestResult::Fail("attach_backing nr_entries != 1");
    }
    build_resource_attach_backing(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("attach_backing round-trip not byte-identical");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_attach_backing_round_trip);

fn smoke_virtio_gpu_pci_set_scanout_round_trip() -> TestResult {
    use super::cmd::{build_set_scanout, decode_set_scanout,
        SetScanout, SET_SCANOUT_LEN};
    let s = SetScanout {
        x: 10, y: 20, width: 1280, height: 720,
        scanout_id: 0, resource_id: 1,
    };
    let mut buf  = [0u8; SET_SCANOUT_LEN];
    let mut buf2 = [0u8; SET_SCANOUT_LEN];
    build_set_scanout(&mut buf, s);
    let decoded = decode_set_scanout(&buf);
    if decoded != s { return TestResult::Fail("set_scanout decode mismatch"); }
    build_set_scanout(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("set_scanout round-trip not byte-identical");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_set_scanout_round_trip);

fn smoke_virtio_gpu_pci_transfer_to_host_2d_round_trip() -> TestResult {
    use super::cmd::{build_transfer_to_host_2d, decode_transfer_to_host_2d,
        TransferToHost2D, TRANSFER_TO_HOST_2D_LEN};
    let t = TransferToHost2D {
        x: 0, y: 0, width: 32, height: 32,
        offset:      0,
        resource_id: 1,
    };
    let mut buf  = [0u8; TRANSFER_TO_HOST_2D_LEN];
    let mut buf2 = [0u8; TRANSFER_TO_HOST_2D_LEN];
    build_transfer_to_host_2d(&mut buf, t);
    let decoded = decode_transfer_to_host_2d(&buf);
    if decoded != t {
        return TestResult::Fail("transfer_to_host_2d decode mismatch");
    }
    build_transfer_to_host_2d(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("transfer_to_host_2d round-trip not byte-identical");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_transfer_to_host_2d_round_trip);

fn smoke_virtio_gpu_pci_resource_flush_round_trip() -> TestResult {
    use super::cmd::{build_resource_flush, decode_resource_flush,
        ResourceFlush, RESOURCE_FLUSH_LEN};
    let r = ResourceFlush {
        x: 0, y: 0, width: 32, height: 32, resource_id: 1,
    };
    let mut buf  = [0u8; RESOURCE_FLUSH_LEN];
    let mut buf2 = [0u8; RESOURCE_FLUSH_LEN];
    build_resource_flush(&mut buf, r);
    let decoded = decode_resource_flush(&buf);
    if decoded != r {
        return TestResult::Fail("resource_flush decode mismatch");
    }
    build_resource_flush(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("resource_flush round-trip not byte-identical");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci",
    smoke_virtio_gpu_pci_resource_flush_round_trip);

fn smoke_virtio_gpu_pci_live_paint_pattern() -> TestResult {
    use crate::gpu_pci;
    if !gpu_pci::is_probed() {
        return TestResult::Skip("no virtio-gpu-pci device on this run");
    }
    // SAFETY: live device + bring_up succeeded if `is_probed`; the
    // lock guards concurrent submitters.
    let r = gpu_pci::with_controller_mut(|c| unsafe {
        c.init_scanout()?;
        c.paint_test_pattern()
    });
    match r {
        Some(Ok(())) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("paint_test_pattern failed"),
        None         => TestResult::Skip("controller missing"),
    }
}
kernel_test_in!("drivers/virtio/gpu_pci", smoke_virtio_gpu_pci_live_paint_pattern);
