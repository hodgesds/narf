//! Per-crate smoke tests for `narf-drivers-video`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"drivers/video"`. Probe-dependent
//! tests emit `TestResult::Skip` when the underlying device isn't
//! present so this file is safe to link on every build.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── Smoke 1: IPU PCI ID table integrity ─────────────────────────────

fn smoke_ipu_pci_id_table() -> TestResult {
    use crate::intel_ipu3::{INTEL_VENDOR, IPU3_DID, PCI_IDS as IPU3_IDS};
    use crate::intel_ipu6::{
        IPU6_DID, IPU6EP_ADLN_DID, IPU6EP_ADLP_DID, IPU6EP_MTL_DID, IPU6EP_RPLP_DID, IPU6SE_DID,
        PCI_IDS as IPU6_IDS,
    };

    // IPU3: exactly one entry, correct VID:DID.
    if IPU3_IDS.len() != 1 {
        return TestResult::Fail("IPU3 PCI_IDS should have exactly 1 entry");
    }
    if IPU3_IDS[0] != (INTEL_VENDOR, IPU3_DID) {
        return TestResult::Fail("IPU3 PCI_IDS[0] VID:DID wrong");
    }

    // IPU6: 6 entries covering all known variants.
    if IPU6_IDS.len() != 6 {
        return TestResult::Fail("IPU6 PCI_IDS should have 6 entries");
    }

    // Spot-check key IDs.
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6_DID)) {
        return TestResult::Fail("IPU6 Tiger Lake DID 0x9A19 missing");
    }
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6SE_DID)) {
        return TestResult::Fail("IPU6SE Jasper Lake DID 0x4E19 missing");
    }
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6EP_ADLP_DID)) {
        return TestResult::Fail("IPU6EP ADL-P DID 0x465D missing");
    }
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6EP_RPLP_DID)) {
        return TestResult::Fail("IPU6EP RPL-P DID 0xA75D missing");
    }
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6EP_ADLN_DID)) {
        return TestResult::Fail("IPU6EP ADL-N DID 0x462E missing");
    }
    if !IPU6_IDS.contains(&(INTEL_VENDOR, IPU6EP_MTL_DID)) {
        return TestResult::Fail("IPU6EP MTL DID 0x7D19 missing");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_ipu_pci_id_table);

// ── Smoke 2: AMD MP2 ISP PCI ID detect ──────────────────────────────

fn smoke_amd_mp2_isp_pci_id_detect() -> TestResult {
    use crate::amd_mp2_isp::{AMD_VENDOR, FIRMWARE_NAME, MP2_DID_15E4, MP2_DID_164A, PCI_IDS};

    if AMD_VENDOR != 0x1022 {
        return TestResult::Fail("AMD_VENDOR should be 0x1022");
    }
    if MP2_DID_15E4 != 0x15E4 {
        return TestResult::Fail("MP2_DID_15E4 wrong value");
    }
    if MP2_DID_164A != 0x164A {
        return TestResult::Fail("MP2_DID_164A wrong value");
    }
    if PCI_IDS.len() != 2 {
        return TestResult::Fail("AMD MP2 PCI_IDS should have 2 entries");
    }
    if !PCI_IDS.contains(&(AMD_VENDOR, MP2_DID_15E4)) {
        return TestResult::Fail("MP2 1.0 DID 0x15E4 missing from table");
    }
    if !PCI_IDS.contains(&(AMD_VENDOR, MP2_DID_164A)) {
        return TestResult::Fail("MP2 1.1 DID 0x164A missing from table");
    }
    if FIRMWARE_NAME != "amd/amdmp2.bin" {
        return TestResult::Fail("AMD MP2 firmware name wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_amd_mp2_isp_pci_id_detect);

// ── Smoke 3: BufferQueue producer/consumer FIFO ──────────────────────

fn smoke_buffer_queue_fifo() -> TestResult {
    use crate::{BufferKind, BufferQueue, CameraBuffer};

    let mut q = BufferQueue::new();
    if !q.is_empty() {
        return TestResult::Fail("fresh queue should be empty");
    }
    if q.len() != 0 {
        return TestResult::Fail("fresh queue len should be 0");
    }

    // Enqueue 3 buffers at distinct physical addresses.
    let b0 = CameraBuffer { phys: 0x1000_0000, len: 4096, kind: BufferKind::VideoCapture };
    let b1 = CameraBuffer { phys: 0x1001_0000, len: 4096, kind: BufferKind::VideoCapture };
    let b2 = CameraBuffer { phys: 0x1002_0000, len: 512, kind: BufferKind::MetaCapture };

    if !q.enqueue(b0) {
        return TestResult::Fail("enqueue b0 failed");
    }
    if !q.enqueue(b1) {
        return TestResult::Fail("enqueue b1 failed");
    }
    if !q.enqueue(b2) {
        return TestResult::Fail("enqueue b2 failed");
    }
    if q.len() != 3 {
        return TestResult::Fail("queue len should be 3 after 3 enqueues");
    }

    // Dequeue and verify FIFO order.
    let d0 = match q.dequeue() {
        Some(b) => b,
        None => return TestResult::Fail("dequeue 0 returned None"),
    };
    if d0.phys != 0x1000_0000 {
        return TestResult::Fail("FIFO order violated: expected b0 first");
    }

    let d1 = match q.dequeue() {
        Some(b) => b,
        None => return TestResult::Fail("dequeue 1 returned None"),
    };
    if d1.phys != 0x1001_0000 {
        return TestResult::Fail("FIFO order violated: expected b1 second");
    }

    let d2 = match q.dequeue() {
        Some(b) => b,
        None => return TestResult::Fail("dequeue 2 returned None"),
    };
    if d2.kind != BufferKind::MetaCapture {
        return TestResult::Fail("b2 kind should be MetaCapture");
    }
    if d2.len != 512 {
        return TestResult::Fail("b2 len should be 512");
    }

    // Queue should be empty again.
    if !q.is_empty() {
        return TestResult::Fail("queue should be empty after 3 dequeues");
    }
    if q.dequeue().is_some() {
        return TestResult::Fail("dequeue from empty queue should return None");
    }

    // Fill to capacity (8 slots) and verify overflow rejection.
    for i in 0..8u64 {
        let buf = CameraBuffer {
            phys: 0x2000_0000 + i * 0x1000,
            len: 4096,
            kind: BufferKind::VideoCapture,
        };
        if !q.enqueue(buf) {
            return TestResult::Fail("enqueue to non-full queue should not fail");
        }
    }
    let overflow = CameraBuffer { phys: 0xDEAD_BEEF, len: 1, kind: BufferKind::VideoCapture };
    if q.enqueue(overflow) {
        return TestResult::Fail("enqueue to full queue should return false");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_buffer_queue_fifo);

// ── Smoke 4: PixelFormat enum completeness and fourcc values ─────────

fn smoke_pixel_format_enum() -> TestResult {
    use crate::PixelFormat;

    // All four variants are distinct.
    if PixelFormat::Nv12 == PixelFormat::Mjpeg {
        return TestResult::Fail("PixelFormat variants must be distinct");
    }
    if PixelFormat::Yuyv == PixelFormat::Rgb565 {
        return TestResult::Fail("PixelFormat variants must be distinct");
    }

    // fourcc() returns the standard V4L2 values.
    // NV12: 'N','V','1','2' = 0x4E, 0x56, 0x31, 0x32 → LE 0x3231564E
    if PixelFormat::Nv12.fourcc() != 0x3231_564E {
        return TestResult::Fail("NV12 fourcc wrong");
    }
    // MJPEG: 'M','J','P','G' = 0x4D, 0x4A, 0x50, 0x47 → LE 0x47504A4D
    if PixelFormat::Mjpeg.fourcc() != 0x4750_4A4D {
        return TestResult::Fail("MJPEG fourcc wrong");
    }
    // YUYV: 'Y','U','Y','V' = 0x59, 0x55, 0x59, 0x56 → LE 0x56595559
    if PixelFormat::Yuyv.fourcc() != 0x5659_5559 {
        return TestResult::Fail("YUYV fourcc wrong");
    }
    // RGB565 (V4L2 RGBP): 'R','G','B','P' → LE 0x50424752
    if PixelFormat::Rgb565.fourcc() != 0x5042_4752 {
        return TestResult::Fail("RGB565 fourcc wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_pixel_format_enum);

// ── Smoke 5: IPU6 firmware name resolution ───────────────────────────

fn smoke_ipu6_firmware_name_resolution() -> TestResult {
    use crate::intel_ipu6::{
        firmware_for, IPU6EP_ADLN_DID, IPU6EP_ADLP_DID, IPU6EP_MTL_DID, IPU6EP_RPLP_DID,
        IPU6SE_DID, IPU6_DID, FW_IPU6, FW_IPU6EP, FW_IPU6EP_ADLN, FW_IPU6EP_MTL, FW_IPU6SE,
    };

    if firmware_for(IPU6_DID) != Some(FW_IPU6) {
        return TestResult::Fail("IPU6 firmware name wrong");
    }
    if firmware_for(IPU6SE_DID) != Some(FW_IPU6SE) {
        return TestResult::Fail("IPU6SE firmware name wrong");
    }
    if firmware_for(IPU6EP_ADLP_DID) != Some(FW_IPU6EP) {
        return TestResult::Fail("IPU6EP ADLP firmware name wrong");
    }
    if firmware_for(IPU6EP_RPLP_DID) != Some(FW_IPU6EP) {
        return TestResult::Fail("IPU6EP RPLP firmware name wrong");
    }
    if firmware_for(IPU6EP_ADLN_DID) != Some(FW_IPU6EP_ADLN) {
        return TestResult::Fail("IPU6EP ADLN firmware name wrong");
    }
    if firmware_for(IPU6EP_MTL_DID) != Some(FW_IPU6EP_MTL) {
        return TestResult::Fail("IPU6EP MTL firmware name wrong");
    }
    // Unknown DID must return None.
    if firmware_for(0xFFFF).is_some() {
        return TestResult::Fail("unknown DID should return None");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_ipu6_firmware_name_resolution);

// ── Smoke 6: sensor trait surface + info descriptors ─────────────────

fn smoke_sensor_info_descriptors() -> TestResult {
    use crate::sensor::{OV01A1S_INFO, OV02C10_INFO, OV05C10_INFO};

    if OV01A1S_INFO.i2c_addr != 0x60 {
        return TestResult::Fail("OV01A1S I2C addr should be 0x60");
    }
    if OV02C10_INFO.i2c_addr != 0x36 {
        return TestResult::Fail("OV02C10 I2C addr should be 0x36");
    }
    if OV05C10_INFO.i2c_addr != 0x10 {
        return TestResult::Fail("OV05C10 I2C addr should be 0x10");
    }
    if OV01A1S_INFO.mipi.num_data_lanes != 2 {
        return TestResult::Fail("OV01A1S should use 2 MIPI lanes");
    }
    if OV05C10_INFO.max_width != 2592 || OV05C10_INFO.max_height != 1944 {
        return TestResult::Fail("OV05C10 max resolution wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/video", smoke_sensor_info_descriptors);
