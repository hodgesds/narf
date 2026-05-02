//! virtio-gpu-pci smokes — clean-room, sourced from VirtIO 1.2 §5.7.
//!
//! Stage 1: PCI match table contains both transitional ids
//!   (1AF4:1050 modern, 1AF4:1010 legacy).
//! Stage 2: VirtqueueLayout for controlq + cursorq — pure-data offsets
//!   (VirtIO 1.2 §3.2.1).

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
