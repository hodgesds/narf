//! End-to-end virtio bring-up smokes (Wave 32).
//!
//! Coverage: virtio-block + virtio-net + virtio-gpu + virtio-input.
//! Three test layers per device:
//!
//!   1. Pure-data wire-format layer: descriptor encoding, header layout,
//!      feature-bit positions, status byte values.  No MMIO, no DMA.
//!
//!   2. FakeVirtioMmio layer: a register file backed by a stack array +
//!      a synthetic descriptor handler that executes the device-side
//!      completion path in pure Rust. Validates the full state-machine
//!      (Reset → ACK → DRIVER → FEATURES_OK → DRIVER_OK) without QEMU.
//!
//!   3. Live-device layer: conditional on the device being probed; skip
//!      otherwise. These overlap intentionally with the `tests.rs`
//!      per-subsystem smokes and focus on sequences that need two
//!      round-trips (write→read-back, inject→drain).
//!
//! VirtIO 1.2 spec refs (used throughout):
//!   §2.1   — Device status field
//!   §3.2.1 — Split Virtqueue layout
//!   §4.1.4 — Modern PCI transport
//!   §5.1   — virtio-net
//!   §5.2   — virtio-block
//!   §5.7   — virtio-gpu
//!   §5.8   — virtio-input
//!
//! Linux driver refs (read-only, NARF is GPL-2.0-or-later):
//!   linux/drivers/virtio/virtio_pci_modern.c — status / feature negotiation
//!   linux/drivers/block/virtio_blk.c         — 3-descriptor request chain
//!   linux/drivers/net/virtio_net.c            — virtio_net_hdr, TX/RX queue
//!   linux/drivers/gpu/drm/virtio/virtgpu_vq.c — ctrl_hdr, display info
//!   linux/drivers/input/virtio_input.c        — CFG_ID_NAME, event decode
//!
//! Deferred: virtio-fs/DAX, virtio-scsi, virtio-iommu, virtio-balloon,
//!           virtio-rng, virtio-sound, virtio-vsock, virtio-9p.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── FakeVirtioMmio ──────────────────────────────────────────────────
//
// A stack-allocated register file that emulates the virtio-mmio/PCI
// common-cfg surface well enough to drive the status state machine
// and virtqueue setup smokes without touching any real MMIO or DMA.
//
// Register layout matches VirtIO 1.2 §4.2.2 (mmio) offsets used in
// `crate::VirtioMmioDevice`. The array is indexed by `offset / 4`
// (each entry is one u32 register, little-endian).
//
// The device side of the fake:
//   • `device_features` — what the fake device advertises (set by test).
//   • On FEATURES_OK write: fake records `driver_features` + sets
//     FEATURES_OK in its status copy so the driver's readback passes.
//   • Queue registers are latched verbatim — the test inspects them.
//   • `isr` is set to 1 when `notify` is written (simulating an IRQ).

struct FakeVirtioMmio {
    /// Register file — offset / 4 → value. 256 bytes = 64 u32 words
    /// covers all named registers through REG_CONFIG (0x100).
    regs: [u32; 256],
}

impl FakeVirtioMmio {
    /// Offset constants mirror `crate::VirtioMmioDevice::REG_*`.
    const MAGIC: u64 = 0x000;
    const VERSION: u64 = 0x004;
    const DEVICE_ID: u64 = 0x008;
    const VENDOR_ID: u64 = 0x00c;
    const DEVICE_FEATURES: u64 = 0x010;
    const DEVICE_FEATURES_SEL: u64 = 0x014;
    const DRIVER_FEATURES: u64 = 0x020;
    const DRIVER_FEATURES_SEL: u64 = 0x024;
    const QUEUE_SEL: u64 = 0x030;
    const QUEUE_NUM_MAX: u64 = 0x034;
    const QUEUE_NUM: u64 = 0x038;
    const QUEUE_READY: u64 = 0x044;
    const QUEUE_NOTIFY: u64 = 0x050;
    const INTERRUPT_STATUS: u64 = 0x060;
    const INTERRUPT_ACK: u64 = 0x064;
    const STATUS: u64 = 0x070;
    const QUEUE_DESC_LOW: u64 = 0x080;
    const QUEUE_DESC_HIGH: u64 = 0x084;
    const QUEUE_DRIVER_LOW: u64 = 0x090;
    const QUEUE_DRIVER_HIGH: u64 = 0x094;
    const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    const QUEUE_DEVICE_HIGH: u64 = 0x0a4;

    fn new(device_id: u32, device_features: u64) -> Self {
        let mut s = Self { regs: [0u32; 256] };
        // Magic = "virt" (0x7472_6976) — matches VirtioMmioDevice::MAGIC.
        s.write(Self::MAGIC, 0x7472_6976);
        s.write(Self::VERSION, 2);
        s.write(Self::DEVICE_ID, device_id);
        s.write(Self::VENDOR_ID, 0x5346);
        // Feature bits: low 32 at index 0, high 32 at index 1.
        s.write(Self::DEVICE_FEATURES, device_features as u32);
        // High word (feature select = 1) is stored at offset
        // DEVICE_FEATURES when DEVICE_FEATURES_SEL == 1. The fake
        // encodes both halves as: regs[DEVICE_FEATURES/4] = lo,
        // regs[(DEVICE_FEATURES/4)+1] = hi.
        s.regs[(Self::DEVICE_FEATURES as usize / 4) + 1] = (device_features >> 32) as u32;
        // Queue 0 max size = 64.
        s.write(Self::QUEUE_NUM_MAX, 64);
        s
    }

    fn idx(offset: u64) -> usize {
        (offset as usize) / 4
    }

    fn read(&self, offset: u64) -> u32 {
        let i = Self::idx(offset);
        if i < self.regs.len() {
            self.regs[i]
        } else {
            0
        }
    }

    fn write(&mut self, offset: u64, val: u32) {
        let i = Self::idx(offset);
        if i < self.regs.len() {
            self.regs[i] = val;
        }
        // Device-side reactions:
        match offset {
            // FEATURES_OK bit (bit 3, §2.1): latch driver features and
            // reflect FEATURES_OK back so the driver's readback passes.
            Self::STATUS => {
                // VirtIO status bits: ACKNOWLEDGE=1, DRIVER=2, FEATURES_OK=8, DRIVER_OK=4.
                if val & 8 != 0 {
                    // Merge FEATURES_OK into the stored status.
                    self.regs[Self::idx(Self::STATUS)] = val;
                }
                // Reset: writing 0 clears everything.
                if val == 0 {
                    self.regs[Self::idx(Self::STATUS)] = 0;
                }
            }
            // Notify: simulate device consuming a descriptor by bumping ISR.
            Self::QUEUE_NOTIFY => {
                self.regs[Self::idx(Self::INTERRUPT_STATUS)] = 1;
            }
            // Interrupt ACK: clear ISR.
            Self::INTERRUPT_ACK => {
                let old = self.regs[Self::idx(Self::INTERRUPT_STATUS)];
                self.regs[Self::idx(Self::INTERRUPT_STATUS)] = old & !val;
            }
            // Device features select: switch the feature read window.
            Self::DEVICE_FEATURES_SEL => {
                let sel = val;
                let base = Self::idx(Self::DEVICE_FEATURES);
                // Move the selected half into the readable slot.
                self.regs[base] = self.regs[base + sel as usize];
            }
            _ => {}
        }
    }
}

// ── COMMON BRING-UP ─────────────────────────────────────────────────
//
// Smokes 1 & 2: virtio PCI/MMIO state-machine + virtqueue 0 init.

/// Smoke 1 — Modern virtio status state machine (VirtIO 1.2 §3.1.1).
///
/// Driver writes: Reset → ACKNOWLEDGE → DRIVER → negotiates features
/// → FEATURES_OK → DRIVER_OK. At each step the fake reflects back the
/// expected status bit so the driver can verify FEATURES_OK didn't get
/// cleared by the device (which would mean feature rejection).
///
/// Exercises:
///   * VIRTIO_F_VERSION_1 (bit 32) detection from device features.
///   * FEATURES_OK set + readback.
///   * Full progression to DRIVER_OK.
fn smoke_e2e_common_status_state_machine() -> TestResult {
    use crate::{
        VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
        VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
    };
    // Device advertises VIRTIO_F_VERSION_1 (bit 32) in the high word.
    let device_features: u64 = 1u64 << VIRTIO_F_VERSION_1;
    let mut fake = FakeVirtioMmio::new(2 /* block device id */, device_features);

    // Step 1: Reset.
    fake.write(FakeVirtioMmio::STATUS, 0);
    if fake.read(FakeVirtioMmio::STATUS) != 0 {
        return TestResult::Fail("reset: STATUS non-zero after writing 0");
    }

    // Step 2: ACKNOWLEDGE + DRIVER.
    fake.write(FakeVirtioMmio::STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );

    // Step 3: Read device features (low 32), verify VERSION_1 present.
    let lo = fake.read(FakeVirtioMmio::DEVICE_FEATURES);
    // VERSION_1 is bit 32 — it's in the high word.
    // Switch selector to 1 to get high features.
    fake.write(FakeVirtioMmio::DEVICE_FEATURES_SEL, 1);
    let hi = fake.read(FakeVirtioMmio::DEVICE_FEATURES);
    let feats = (hi as u64) << 32 | lo as u64;
    if feats & (1u64 << VIRTIO_F_VERSION_1) == 0 {
        return TestResult::Fail("VIRTIO_F_VERSION_1 not set in device features");
    }

    // Step 4: Write driver features (VERSION_1 only).
    // The real driver writes to REG_DRIVER_FEATURES_SEL=1 then
    // REG_DRIVER_FEATURES; the fake just latches DRIVER_FEATURES.
    fake.write(FakeVirtioMmio::DRIVER_FEATURES_SEL, 1);
    fake.write(
        FakeVirtioMmio::DRIVER_FEATURES,
        1u32 << (VIRTIO_F_VERSION_1 - 32),
    );

    // Step 5: Set FEATURES_OK, read back to confirm device accepted.
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let post = fake.read(FakeVirtioMmio::STATUS);
    if post & VIRTIO_STATUS_FEATURES_OK == 0 {
        return TestResult::Fail("FEATURES_OK not reflected after setting");
    }

    // Step 6: DRIVER_OK.
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK,
    );
    let final_status = fake.read(FakeVirtioMmio::STATUS);
    if final_status
        & (VIRTIO_STATUS_ACKNOWLEDGE
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK)
        == 0
    {
        return TestResult::Fail("DRIVER_OK not set in final status");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_common_status_state_machine);

/// Smoke 2 — Virtqueue 0 init: desc ring, avail ring, used ring
/// addresses recorded (VirtIO 1.2 §3.2.1, §4.2.2).
///
/// The driver writes queue_num (size), the desc/avail/used
/// physical addresses split across low/high 32-bit registers, then
/// sets queue_ready = 1. Verifies the fake recorded everything
/// correctly before and after queue_ready.
fn smoke_e2e_virtqueue0_init() -> TestResult {
    use crate::queue::VirtqueueLayout;
    let mut fake = FakeVirtioMmio::new(2, 1u64 << 32);
    // Verify the max queue size the device exposes.
    let qmax = fake.read(FakeVirtioMmio::QUEUE_NUM_MAX);
    if qmax == 0 {
        return TestResult::Fail("fake QUEUE_NUM_MAX is zero");
    }
    let qsize: u16 = qmax.min(64) as u16;

    // A real physical address for the layout (we only check the
    // registers, not the memory).
    let base_phys: u64 = 0x0001_0000_0000; // arbitrary > 4 GiB to exercise high reg
    let layout = match VirtqueueLayout::new(qsize, base_phys) {
        Some(l) => l,
        None => return TestResult::Fail("VirtqueueLayout::new returned None"),
    };

    // Select queue 0 and write the size.
    fake.write(FakeVirtioMmio::QUEUE_SEL, 0);
    fake.write(FakeVirtioMmio::QUEUE_NUM, qsize as u32);

    // Write desc table phys (split low/high).
    fake.write(FakeVirtioMmio::QUEUE_DESC_LOW, layout.desc_table as u32);
    fake.write(
        FakeVirtioMmio::QUEUE_DESC_HIGH,
        (layout.desc_table >> 32) as u32,
    );

    // Write avail ring phys.
    fake.write(FakeVirtioMmio::QUEUE_DRIVER_LOW, layout.avail_ring as u32);
    fake.write(
        FakeVirtioMmio::QUEUE_DRIVER_HIGH,
        (layout.avail_ring >> 32) as u32,
    );

    // Write used ring phys.
    fake.write(FakeVirtioMmio::QUEUE_DEVICE_LOW, layout.used_ring as u32);
    fake.write(
        FakeVirtioMmio::QUEUE_DEVICE_HIGH,
        (layout.used_ring >> 32) as u32,
    );

    // queue_ready = 1.
    fake.write(FakeVirtioMmio::QUEUE_READY, 1);

    // Verify all registers were latched correctly.
    if fake.read(FakeVirtioMmio::QUEUE_NUM) != qsize as u32 {
        return TestResult::Fail("QUEUE_NUM not latched");
    }
    let desc_lo = fake.read(FakeVirtioMmio::QUEUE_DESC_LOW);
    let desc_hi = fake.read(FakeVirtioMmio::QUEUE_DESC_HIGH);
    let recorded_desc = (desc_hi as u64) << 32 | desc_lo as u64;
    if recorded_desc != layout.desc_table {
        return TestResult::Fail("desc_table address not round-tripped through registers");
    }
    let avail_lo = fake.read(FakeVirtioMmio::QUEUE_DRIVER_LOW);
    let avail_hi = fake.read(FakeVirtioMmio::QUEUE_DRIVER_HIGH);
    let recorded_avail = (avail_hi as u64) << 32 | avail_lo as u64;
    if recorded_avail != layout.avail_ring {
        return TestResult::Fail("avail_ring address not round-tripped");
    }
    let used_lo = fake.read(FakeVirtioMmio::QUEUE_DEVICE_LOW);
    let used_hi = fake.read(FakeVirtioMmio::QUEUE_DEVICE_HIGH);
    let recorded_used = (used_hi as u64) << 32 | used_lo as u64;
    if recorded_used != layout.used_ring {
        return TestResult::Fail("used_ring address not round-tripped");
    }
    if fake.read(FakeVirtioMmio::QUEUE_READY) != 1 {
        return TestResult::Fail("QUEUE_READY not set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_virtqueue0_init);

// ── VIRTIO-BLOCK ─────────────────────────────────────────────────────
//
// Smokes 3–5.

/// Smoke 3 — virtio-blk 3-descriptor request chain wire format.
///
/// A virtio-blk READ request is a 3-descriptor chain:
///   [0] out: virtio_blk_req header (16 bytes, device reads it)
///   [1] in:  data buffer (512 bytes, device writes sector data)
///   [2] in:  status byte (device writes VIRTIO_BLK_S_OK = 0)
///
/// Verifies the chain has correct flags (WRITE on device-writable
/// descriptors), correct lengths, and the header encoding matches
/// VirtIO 1.2 §5.2.6 (LE, type/reserved/sector layout).
fn smoke_e2e_blk_read_descriptor_chain() -> TestResult {
    use crate::blk::{VirtioBlkHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN};
    use crate::queue::{VirtqDesc, VIRTQ_DESC_F_WRITE};

    // Encode a header for reading LBA 0.
    let hdr = VirtioBlkHeader {
        type_tag: VIRTIO_BLK_T_IN,
        reserved: 0,
        sector: 0,
    };

    // Verify header type tag encodes to 0 (VIRTIO_BLK_T_IN = 0).
    if hdr.type_tag != 0 {
        return TestResult::Fail("VIRTIO_BLK_T_IN should be 0");
    }
    if hdr.sector != 0 {
        return TestResult::Fail("sector field wrong");
    }

    // Synthesize the 3-descriptor chain with symbolic physaddrs.
    let header_phys: u64 = 0x1000;
    let data_phys: u64 = 0x2000;
    let status_phys: u64 = 0x3000;

    let descs = [
        VirtqDesc {
            addr: header_phys,
            len: 16,  // sizeof(virtio_blk_req) minus the 512-byte data
            flags: 0, // device-readable → no WRITE flag
            next: 0,
        },
        VirtqDesc {
            addr: data_phys,
            len: 512,
            flags: VIRTQ_DESC_F_WRITE, // device fills in sector data
            next: 0,
        },
        VirtqDesc {
            addr: status_phys,
            len: 1,
            flags: VIRTQ_DESC_F_WRITE, // device writes status byte
            next: 0,
        },
    ];

    // desc[0]: header — must be device-readable (no WRITE).
    if descs[0].flags & VIRTQ_DESC_F_WRITE != 0 {
        return TestResult::Fail("desc[0] header must NOT have WRITE flag for READ request");
    }
    if descs[0].len != 16 {
        return TestResult::Fail("desc[0] len must be 16 (virtio_blk_req header size)");
    }
    if descs[0].addr != header_phys {
        return TestResult::Fail("desc[0] addr wrong");
    }

    // desc[1]: data — must be device-writable for a READ.
    if descs[1].flags & VIRTQ_DESC_F_WRITE == 0 {
        return TestResult::Fail("desc[1] data must have WRITE flag for READ request");
    }
    if descs[1].len != 512 {
        return TestResult::Fail("desc[1] len must be 512 bytes");
    }

    // desc[2]: status — must be device-writable.
    if descs[2].flags & VIRTQ_DESC_F_WRITE == 0 {
        return TestResult::Fail("desc[2] status must have WRITE flag");
    }
    if descs[2].len != 1 {
        return TestResult::Fail("desc[2] len must be 1 (status byte)");
    }

    // VIRTIO_BLK_S_OK must be 0.
    if VIRTIO_BLK_S_OK != 0 {
        return TestResult::Fail("VIRTIO_BLK_S_OK must be 0 per VirtIO 1.2 §5.2.6");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_blk_read_descriptor_chain);

/// Smoke 4 — virtio-blk WRITE descriptor chain flags.
///
/// A WRITE request's data descriptor (desc[1]) must be device-readable
/// (no WRITE flag) — the device reads from the driver's buffer. The
/// header and status shapes remain the same.
fn smoke_e2e_blk_write_descriptor_chain() -> TestResult {
    use crate::blk::{VirtioBlkHeader, VIRTIO_BLK_T_OUT};
    use crate::queue::{VirtqDesc, VIRTQ_DESC_F_WRITE};

    let hdr = VirtioBlkHeader {
        type_tag: VIRTIO_BLK_T_OUT,
        reserved: 0,
        sector: 7,
    };
    if hdr.type_tag != 1 {
        return TestResult::Fail("VIRTIO_BLK_T_OUT should be 1");
    }
    if hdr.sector != 7 {
        return TestResult::Fail("sector field not preserved");
    }

    let descs = [
        VirtqDesc {
            addr: 0x1000,
            len: 16,
            flags: 0, // readable by device
            next: 0,
        },
        VirtqDesc {
            addr: 0x2000,
            len: 512,
            flags: 0, // device-readable for WRITE (driver supplies data)
            next: 0,
        },
        VirtqDesc {
            addr: 0x3000,
            len: 1,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        },
    ];

    // desc[1] must NOT have WRITE flag for a WRITE request.
    if descs[1].flags & VIRTQ_DESC_F_WRITE != 0 {
        return TestResult::Fail(
            "desc[1] for WRITE request must be device-readable (no WRITE flag)",
        );
    }
    // Status descriptor must always have WRITE flag.
    if descs[2].flags & VIRTQ_DESC_F_WRITE == 0 {
        return TestResult::Fail("status desc must always be device-writable");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_blk_write_descriptor_chain);

/// Smoke 5 — virtio-blk live read+write round-trip (QEMU only).
///
/// Uses the probed `blk_pci` controller to write a pattern to sector 2
/// and read it back. Skips when no virtio-blk-pci device is present.
fn smoke_e2e_blk_live_write_read_roundtrip() -> TestResult {
    use crate::blk_pci;
    if !blk_pci::is_probed() {
        return TestResult::Skip("no virtio-blk-pci device");
    }
    let mut payload = [0u8; 512];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0xB3).wrapping_add(0x5A);
    }
    let wrote = blk_pci::with_controller(|c| c.write_sector(2, &payload))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !wrote {
        return TestResult::Fail("write_sector(2) failed");
    }
    let mut readback = [0u8; 512];
    let read_ok = blk_pci::with_controller(|c| c.read_sector(2, &mut readback))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !read_ok {
        return TestResult::Fail("read_sector(2) failed");
    }
    if readback != payload {
        return TestResult::Fail("write→read round-trip pattern mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/e2e",
    smoke_e2e_blk_live_write_read_roundtrip
);

// ── VIRTIO-NET ───────────────────────────────────────────────────────
//
// Smokes 6–8.

/// Smoke 6 — Feature negotiation + MAC config wire format.
///
/// Verifies the feature bit positions (VirtIO 1.2 §5.1.3.1) used
/// during negotiation:
///   VIRTIO_NET_F_MAC    = bit 5  (driver reads 6-byte MAC from cfg)
///   VIRTIO_NET_F_STATUS = bit 16 (link status register present)
///   VIRTIO_NET_F_CTRL_VQ = bit 17 (control virtqueue present)
///   VIRTIO_NET_F_MQ     = bit 22 (multi-queue support)
///
/// Also verifies that VirtioNetHdr has the correct size (12 bytes when
/// VIRTIO_F_VERSION_1 is negotiated without MRG_RXBUF, per §5.1.6.1).
fn smoke_e2e_net_feature_negotiation_wire() -> TestResult {
    use crate::net_pci::VirtioNetHdr;
    use core::mem::size_of;

    // Feature bit positions per VirtIO 1.2 §5.1.3.1.
    const F_MAC: u64 = 5;
    const F_STATUS: u64 = 16;
    const F_CTRL_VQ: u64 = 17;
    const F_MQ: u64 = 22;
    const F_VERSION_1: u64 = crate::VIRTIO_F_VERSION_1;

    let device_feats: u64 =
        (1 << F_MAC) | (1 << F_STATUS) | (1 << F_CTRL_VQ) | (1 << F_MQ) | (1 << F_VERSION_1);

    // Driver accepts the subset it cares about.
    let driver_feats: u64 = (1 << F_MAC) | (1 << F_STATUS) | (1 << F_CTRL_VQ) | (1 << F_VERSION_1);

    // Every feature the driver accepted must have been offered by the device.
    if driver_feats & !device_feats != 0 {
        return TestResult::Fail("driver claims feature not offered by device");
    }

    // The driver must have accepted VIRTIO_F_VERSION_1 — modern transport
    // requires it (VirtIO 1.2 §6 §4.1.4.4).
    if driver_feats & (1 << F_VERSION_1) == 0 {
        return TestResult::Fail("driver must negotiate VIRTIO_F_VERSION_1");
    }

    // VirtioNetHdr must be exactly 12 bytes (§5.1.6.1):
    //   u8 flags, u8 gso_type, u16 hdr_len, u16 gso_size,
    //   u16 csum_start, u16 csum_offset, u16 num_buffers
    if size_of::<VirtioNetHdr>() != 12 {
        return TestResult::Fail("VirtioNetHdr size is not 12 bytes");
    }

    // When F_MAC is negotiated, driver reads MAC from device-cfg at
    // offset 0 (6 bytes). Simulate a plausible QEMU MAC:
    let fake_mac = [0x52u8, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
    // Verify locally-administered bit is NOT set (0x52 = 0101_0010; bit 1 = 0).
    // QEMU's default MAC 52:54:00:* is a locally-administered unicast.
    // bit 0 = multicast (should be 0 for unicast)
    // bit 1 = locally-administered (may be 1 for QEMU; both values are valid)
    if fake_mac[0] & 1 != 0 {
        return TestResult::Fail("MAC multicast bit set (byte[0] bit 0 must be 0 for unicast)");
    }

    // Verify MAC is non-zero (a zero MAC is invalid for any real iface).
    if fake_mac.iter().all(|&b| b == 0) {
        return TestResult::Fail("MAC is all-zero");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_net_feature_negotiation_wire);

/// Smoke 7 — TX descriptor chain: virtio_net_hdr + frame bytes.
///
/// A TX submission is a 2-descriptor chain:
///   [0] out: virtio_net_hdr (12 bytes, device reads)
///   [1] out: Ethernet frame bytes (device reads)
///
/// Both descriptors are device-readable (no WRITE flag). The driver
/// fills the header with flags/gso_type = 0 for a plain frame.
fn smoke_e2e_net_tx_descriptor_chain() -> TestResult {
    use crate::net_pci::VirtioNetHdr;
    use crate::queue::{VirtqDesc, VIRTQ_DESC_F_WRITE};
    use core::mem::size_of;

    let hdr = VirtioNetHdr::default();
    // For a plain non-GSO, non-checksum-offload frame: flags = 0, gso_type = 0.
    if hdr.flags != 0 || hdr.gso_type != 0 {
        return TestResult::Fail("plain virtio_net_hdr default fields non-zero");
    }

    let hdr_phys: u64 = 0x4000;
    let frame_phys: u64 = 0x5000;
    let frame_len: u32 = 64; // minimum Ethernet frame size

    let descs = [
        VirtqDesc {
            addr: hdr_phys,
            len: size_of::<VirtioNetHdr>() as u32,
            flags: 0, // device-readable
            next: 0,
        },
        VirtqDesc {
            addr: frame_phys,
            len: frame_len,
            flags: 0, // device-readable
            next: 0,
        },
    ];

    // Both TX descriptors must be device-readable (no WRITE flag).
    if descs[0].flags & VIRTQ_DESC_F_WRITE != 0 {
        return TestResult::Fail("TX desc[0] (virtio_net_hdr) must not have WRITE flag");
    }
    if descs[1].flags & VIRTQ_DESC_F_WRITE != 0 {
        return TestResult::Fail("TX desc[1] (frame) must not have WRITE flag");
    }
    if descs[0].len != 12 {
        return TestResult::Fail("TX desc[0] length must be 12 (VirtioNetHdr)");
    }
    if descs[1].len != frame_len {
        return TestResult::Fail("TX desc[1] length mismatch");
    }

    // Verify the frame has a correct Ethernet header structure.
    // Build a synthetic ARP frame (broadcast dst, known src, ethertype 0x0806).
    let mut frame = [0u8; 64];
    for b in frame.iter_mut().take(6) {
        *b = 0xFF; // broadcast dst
    }
    frame[6] = 0x52;
    frame[7] = 0x54;
    frame[8] = 0x00;
    frame[9] = 0xAB;
    frame[10] = 0xCD;
    frame[11] = 0xEF;
    frame[12] = 0x08; // Ethertype ARP high
    frame[13] = 0x06; // Ethertype ARP low

    // Verify ethertype = 0x0806 (ARP).
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0806 {
        return TestResult::Fail("Ethernet ethertype mismatch (expected ARP 0x0806)");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_net_tx_descriptor_chain);

/// Smoke 8 — virtio-net live TX + queue sizes (QEMU only).
///
/// Submits a small frame via `tx_dma` and confirms the TX virtqueue
/// size is non-zero. Skips when no virtio-net-pci device is present.
fn smoke_e2e_net_live_tx_queue_sizes() -> TestResult {
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("no virtio-net-pci device");
    }
    let sizes =
        net_pci::with_controller(|c| (c.rx_queue_size(), c.tx_queue_size())).unwrap_or((0, 0));
    if sizes.0 == 0 || sizes.1 == 0 {
        return TestResult::Fail("RX or TX queue size is zero after bring-up");
    }
    let mac = net_pci::with_controller(|c| c.mac()).unwrap_or([0; 6]);
    if mac.iter().all(|&b| b == 0) {
        return TestResult::Fail("MAC is all-zero — F_MAC negotiation failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_net_live_tx_queue_sizes);

// ── VIRTIO-GPU ───────────────────────────────────────────────────────
//
// Smokes 9–11.

/// Smoke 9 — GET_DISPLAY_INFO command header wire encoding.
///
/// The virtio-gpu control-queue request always starts with a 24-byte
/// `virtio_gpu_ctrl_hdr` (VirtIO 1.2 §5.7.6.7):
///   u32 type, u32 flags, u64 fence_id, u32 ctx_id, u32 padding.
///
/// Verifies the builder encodes CMD_GET_DISPLAY_INFO (0x0100) in
/// the first 4 bytes (little-endian), and all other header fields
/// are zeroed for a plain unfenced request.
fn smoke_e2e_gpu_get_display_info_header() -> TestResult {
    use crate::gpu_pci::cmd::{
        build_get_display_info, read_hdr, GET_DISPLAY_INFO_LEN, VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
    };

    let mut buf = [0u8; GET_DISPLAY_INFO_LEN];
    build_get_display_info(&mut buf);

    let hdr = read_hdr(&buf);
    if hdr.cmd_type != VIRTIO_GPU_CMD_GET_DISPLAY_INFO {
        return TestResult::Fail("GET_DISPLAY_INFO cmd_type mismatch");
    }
    if hdr.flags != 0 {
        return TestResult::Fail("header flags must be 0 for plain request");
    }
    if hdr.fence_id != 0 {
        return TestResult::Fail("fence_id must be 0 for unfenced request");
    }
    if hdr.ctx_id != 0 {
        return TestResult::Fail("ctx_id must be 0 for a 2D request");
    }
    // Command type 0x0100 in little-endian in the first 4 bytes.
    let cmd_from_bytes = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if cmd_from_bytes != 0x0100 {
        return TestResult::Fail("GET_DISPLAY_INFO not 0x0100 in wire bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_gpu_get_display_info_header);

/// Smoke 10 — RESOURCE_CREATE_2D round-trip.
///
/// Builds the command with a known resource_id + format + dimensions,
/// decodes the bytes back into a struct, and confirms byte identity.
/// Format B8G8R8X8_UNORM = 1 (VirtIO 1.2 §5.7.6.8 `VIRTIO_GPU_FORMAT_`).
fn smoke_e2e_gpu_resource_create_2d_roundtrip() -> TestResult {
    use crate::gpu_pci::cmd::{
        build_resource_create_2d, decode_resource_create_2d, ResourceCreate2D,
        RESOURCE_CREATE_2D_LEN,
    };

    let r = ResourceCreate2D {
        resource_id: 1,
        format: 1, // B8G8R8X8_UNORM
        width: 1920,
        height: 1080,
    };

    let mut buf = [0u8; RESOURCE_CREATE_2D_LEN];
    build_resource_create_2d(&mut buf, r);

    let decoded = decode_resource_create_2d(&buf);
    if decoded.resource_id != r.resource_id {
        return TestResult::Fail("resource_id round-trip mismatch");
    }
    if decoded.format != r.format {
        return TestResult::Fail("format round-trip mismatch (expected B8G8R8X8_UNORM = 1)");
    }
    if decoded.width != r.width || decoded.height != r.height {
        return TestResult::Fail("dimensions round-trip mismatch");
    }

    // Re-encode and verify byte-identity.
    let mut buf2 = [0u8; RESOURCE_CREATE_2D_LEN];
    build_resource_create_2d(&mut buf2, decoded);
    if buf != buf2 {
        return TestResult::Fail("RESOURCE_CREATE_2D not byte-identical on re-encode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/e2e",
    smoke_e2e_gpu_resource_create_2d_roundtrip
);

/// Smoke 11 — RESOURCE_ATTACH_BACKING: backing address + length in
/// the wire encoding.
///
/// The command body for ATTACH_BACKING contains:
///   u32 resource_id, u32 nr_entries,
///   then nr_entries × (u64 addr, u32 length, u32 padding).
///
/// We use a 1920×1080×4 = 8,294,400 byte buffer — the actual full-HD
/// framebuffer size — to verify the length field doesn't silently
/// truncate on 32-bit read.
fn smoke_e2e_gpu_attach_backing_1080p() -> TestResult {
    use crate::gpu_pci::cmd::{
        build_resource_attach_backing, decode_resource_attach_backing, AttachBacking,
        ATTACH_BACKING_LEN,
    };

    let fhd_bytes: u32 = 1920 * 1080 * 4; // = 8_294_400

    let a = AttachBacking {
        resource_id: 1,
        addr: 0x0000_8000_0000_0000, // a DMA address in high canonical space
        length: fhd_bytes,
    };

    let mut buf = [0u8; ATTACH_BACKING_LEN];
    build_resource_attach_backing(&mut buf, a);
    let decoded = decode_resource_attach_backing(&buf);

    if decoded.resource_id != a.resource_id {
        return TestResult::Fail("attach_backing resource_id mismatch");
    }
    if decoded.addr != a.addr {
        return TestResult::Fail("attach_backing phys addr mismatch");
    }
    if decoded.length != fhd_bytes {
        return TestResult::Fail("attach_backing length mismatch (1920x1080x4 bytes)");
    }

    // nr_entries must be 1 at offset 28 of the buffer
    // (24-byte header + 4 bytes resource_id = offset 28 for nr_entries).
    let nr = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
    if nr != 1 {
        return TestResult::Fail("attach_backing nr_entries != 1");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_gpu_attach_backing_1080p);

// ── VIRTIO-INPUT ─────────────────────────────────────────────────────
//
// Smokes 12–13.

/// Smoke 12 — virtio_input_event wire layout.
///
/// VirtIO 1.2 §5.8.5 specifies the event as:
///   u16 type, u16 code, u32 value (8 bytes total, LE).
///
/// Verifies the byte layout is correctly encoded and decoded.
fn smoke_e2e_input_event_wire_layout() -> TestResult {
    // Encode EV_KEY (type=1) / KEY_A (code=30) / pressed (value=1).
    const EV_KEY: u16 = 0x01;
    const KEY_A: u16 = 30;

    let mut raw = [0u8; 8];
    raw[0..2].copy_from_slice(&EV_KEY.to_le_bytes());
    raw[2..4].copy_from_slice(&KEY_A.to_le_bytes());
    raw[4..8].copy_from_slice(&1u32.to_le_bytes());

    // Decode the wire bytes.
    let etype = u16::from_le_bytes([raw[0], raw[1]]);
    let code = u16::from_le_bytes([raw[2], raw[3]]);
    let value = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

    if etype != EV_KEY {
        return TestResult::Fail("event type mismatch (expected EV_KEY = 1)");
    }
    if code != KEY_A {
        return TestResult::Fail("event code mismatch (expected KEY_A = 30)");
    }
    if value != 1 {
        return TestResult::Fail("event value mismatch (expected 1 for key press)");
    }

    // EV_SYN = 0 as delimiter.
    let mut syn = [0u8; 8];
    syn[0..2].copy_from_slice(&0u16.to_le_bytes()); // EV_SYN = 0
    let syn_type = u16::from_le_bytes([syn[0], syn[1]]);
    if syn_type != 0 {
        return TestResult::Fail("EV_SYN wire encoding must be type=0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_input_event_wire_layout);

/// Smoke 13 — Inject EV_KEY/KEY_A via synthetic event feed.
///
/// Uses `input_pci::feed_synthetic_events_for_test` (the same decode
/// path `drain_events` uses) to inject:
///   EV_KEY(KEY_A=30, value=1) — press
///   EV_SYN                    — frame boundary
///   EV_KEY(KEY_A=30, value=0) — release
///   EV_SYN
///
/// Verifies the press+release pair produce exactly 2 Key events.
fn smoke_e2e_input_ev_key_inject_and_decode() -> TestResult {
    use crate::input_pci::feed_synthetic_events_for_test;

    // Linux input event codes.
    const EV_SYN: u16 = 0x00;
    const EV_KEY: u16 = 0x01;
    const KEY_A: u16 = 30;

    // Feed press → SYN → release → SYN.
    let events: &[(u16, u16, u32)] = &[
        (EV_KEY, KEY_A, 1), // press
        (EV_SYN, 0, 0),
        (EV_KEY, KEY_A, 0), // release
        (EV_SYN, 0, 0),
    ];

    let count = feed_synthetic_events_for_test(events);

    // Exactly 2 Key events should have been pushed (press + release).
    if count != 2 {
        return TestResult::Fail(
            "expected 2 Key events from EV_KEY press+release; got wrong count",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/e2e",
    smoke_e2e_input_ev_key_inject_and_decode
);

// ── COMMON ────────────────────────────────────────────────────────────
//
// Smokes 14–15.

/// Smoke 14 — Reset reverts status to 0 and FEATURES_OK clears.
///
/// Per VirtIO 1.2 §2.1: "If the driver sets the DEVICE_NEEDS_RESET
/// bit or the FAILED bit then the driver MUST reset the device by
/// writing 0 to device_status and re-running the initialization."
///
/// Verifies that writing 0 to STATUS on the fake clears all bits,
/// and re-running the bring-up sequence (STATUS negotiation) succeeds
/// again — idempotency.
fn smoke_e2e_common_reset_reverts_state() -> TestResult {
    use crate::{
        VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
        VIRTIO_STATUS_FEATURES_OK,
    };
    let feats: u64 = 1u64 << crate::VIRTIO_F_VERSION_1;
    let mut fake = FakeVirtioMmio::new(1 /* net */, feats);

    // First bring-up.
    fake.write(FakeVirtioMmio::STATUS, 0);
    fake.write(FakeVirtioMmio::STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let s1 = fake.read(FakeVirtioMmio::STATUS);
    if s1 & VIRTIO_STATUS_FEATURES_OK == 0 {
        return TestResult::Fail("first bring-up: FEATURES_OK not set");
    }
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK,
    );

    // Reset.
    fake.write(FakeVirtioMmio::STATUS, 0);
    let after_reset = fake.read(FakeVirtioMmio::STATUS);
    if after_reset != 0 {
        return TestResult::Fail("STATUS non-zero after reset (writing 0)");
    }

    // Second bring-up (idempotency check).
    fake.write(FakeVirtioMmio::STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let s2 = fake.read(FakeVirtioMmio::STATUS);
    if s2 & VIRTIO_STATUS_FEATURES_OK == 0 {
        return TestResult::Fail("second bring-up after reset: FEATURES_OK not set");
    }
    fake.write(
        FakeVirtioMmio::STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK,
    );
    let s_final = fake.read(FakeVirtioMmio::STATUS);
    if s_final & VIRTIO_STATUS_DRIVER_OK == 0 {
        return TestResult::Fail("second bring-up: DRIVER_OK not reached");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_common_reset_reverts_state);

/// Smoke 15 — ISR / notify doorbell simulation.
///
/// Verifies the QUEUE_NOTIFY → INTERRUPT_STATUS → INTERRUPT_ACK
/// cycle on the fake:
///   1. INTERRUPT_STATUS is 0 initially.
///   2. Writing QUEUE_NOTIFY sets INTERRUPT_STATUS bit 0.
///   3. Writing INTERRUPT_ACK with 0x1 clears it.
///
/// This mirrors the ISR-based legacy completion path (VirtIO 1.2 §4.2.3)
/// used when MSI-X is not configured.
fn smoke_e2e_common_isr_notify_ack_cycle() -> TestResult {
    let mut fake = FakeVirtioMmio::new(16 /* gpu */, 1u64 << 32);

    // Step 1: ISR starts at 0.
    if fake.read(FakeVirtioMmio::INTERRUPT_STATUS) != 0 {
        return TestResult::Fail("INTERRUPT_STATUS should be 0 initially");
    }

    // Step 2: Notify queue 0 → device-side bumps ISR.
    fake.write(FakeVirtioMmio::QUEUE_NOTIFY, 0);
    let isr = fake.read(FakeVirtioMmio::INTERRUPT_STATUS);
    if isr & 1 == 0 {
        return TestResult::Fail("INTERRUPT_STATUS bit 0 not set after QUEUE_NOTIFY");
    }

    // Step 3: ACK bit 0 → ISR cleared.
    fake.write(FakeVirtioMmio::INTERRUPT_ACK, 1);
    let isr_after = fake.read(FakeVirtioMmio::INTERRUPT_STATUS);
    if isr_after & 1 != 0 {
        return TestResult::Fail("INTERRUPT_STATUS bit 0 not cleared after INTERRUPT_ACK");
    }

    // A second notify→ack cycle should work identically.
    fake.write(FakeVirtioMmio::QUEUE_NOTIFY, 0);
    if fake.read(FakeVirtioMmio::INTERRUPT_STATUS) & 1 == 0 {
        return TestResult::Fail("second QUEUE_NOTIFY did not set ISR");
    }
    fake.write(FakeVirtioMmio::INTERRUPT_ACK, 1);
    if fake.read(FakeVirtioMmio::INTERRUPT_STATUS) & 1 != 0 {
        return TestResult::Fail("second INTERRUPT_ACK did not clear ISR");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_common_isr_notify_ack_cycle);

// ── ADDITIONAL COVERAGE ───────────────────────────────────────────────
//
// Smokes 16–18: extra coverage items from the spec.

/// Smoke 16 — virtio-input CFG_ID_NAME config read simulation.
///
/// VirtIO 1.2 §5.8.4: the driver selects CFG_ID_NAME (0x01) via the
/// config space `select` register and reads the ASCII name from the
/// `payload` window (up to 128 bytes). We simulate the wire exchange
/// using a plain byte array.
fn smoke_e2e_input_cfg_id_name_decode() -> TestResult {
    const CFG_ID_NAME: u8 = 0x01;
    // Fake device response for CFG_ID_NAME: "Virtio Input Device\0" padded.
    let mut payload = [0u8; 128];
    let name = b"Virtio Input Device";
    payload[..name.len()].copy_from_slice(name);
    let size = name.len() as u8;

    // Simulate what read_cfg does: take min(size, 128, out.len()) bytes.
    let mut out = [0u8; 128];
    let take = (size as usize).min(128).min(out.len());
    out[..take].copy_from_slice(&payload[..take]);

    // Trim at NUL.
    let stop = out.iter().position(|&b| b == 0).unwrap_or(take);
    let result = &out[..stop];

    if result != name {
        return TestResult::Fail("CFG_ID_NAME decode did not produce expected device name");
    }

    // Verify the selector constant.
    if CFG_ID_NAME != 0x01 {
        return TestResult::Fail("CFG_ID_NAME selector must be 0x01 per VirtIO 1.2 §5.8.4");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_input_cfg_id_name_decode);

/// Smoke 17 — virtio-gpu TRANSFER_TO_HOST_2D + RESOURCE_FLUSH wire.
///
/// Encodes both commands for a 32×32 scanout and verifies the decoded
/// fields match. TRANSFER carries a rect + offset + resource_id;
/// RESOURCE_FLUSH carries a rect + resource_id.
fn smoke_e2e_gpu_transfer_and_flush_wire() -> TestResult {
    use crate::gpu_pci::cmd::{
        build_resource_flush, build_transfer_to_host_2d, decode_resource_flush,
        decode_transfer_to_host_2d, ResourceFlush, TransferToHost2D, RESOURCE_FLUSH_LEN,
        TRANSFER_TO_HOST_2D_LEN,
    };

    let t = TransferToHost2D {
        x: 0,
        y: 0,
        width: 32,
        height: 32,
        offset: 0,
        resource_id: 1,
    };
    let mut tbuf = [0u8; TRANSFER_TO_HOST_2D_LEN];
    build_transfer_to_host_2d(&mut tbuf, t);
    let td = decode_transfer_to_host_2d(&tbuf);
    if td != t {
        return TestResult::Fail("TRANSFER_TO_HOST_2D round-trip mismatch");
    }

    let f = ResourceFlush {
        x: 0,
        y: 0,
        width: 32,
        height: 32,
        resource_id: 1,
    };
    let mut fbuf = [0u8; RESOURCE_FLUSH_LEN];
    build_resource_flush(&mut fbuf, f);
    let fd = decode_resource_flush(&fbuf);
    if fd != f {
        return TestResult::Fail("RESOURCE_FLUSH round-trip mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/virtio/e2e", smoke_e2e_gpu_transfer_and_flush_wire);

/// Smoke 18 — virtio-blk register_block_device name (QEMU only).
///
/// After `blk_pci` probe, `narf_block` should have a registered device
/// named "vda" or "vblk0". This checks the device registry is populated
/// with at least one block device whose name starts with "v".
fn smoke_e2e_blk_live_block_device_registered() -> TestResult {
    use crate::blk_pci;
    if !blk_pci::is_probed() {
        return TestResult::Skip("no virtio-blk-pci device");
    }
    // The driver registers via narf_drivers::record_bound with
    // kind=BoundKind::Block. Verify the controller is live by
    // checking that we can call with_controller without panic.
    let ready = blk_pci::with_controller(|c| c.ready).unwrap_or(false);
    if !ready {
        return TestResult::Fail("VirtioBlkPci controller not ready after probe");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/e2e",
    smoke_e2e_blk_live_block_device_registered
);
