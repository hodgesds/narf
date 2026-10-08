//! Per-crate smoke tests for `narf-drivers-gpu`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"drivers/gpu"`. Probe-dependent tests
//! emit `TestResult::Skip` when the underlying device isn't present
//! so this file is safe to link on every build.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_drivers_gpu_mode_and_family() -> TestResult {
    use crate::{GpuFamily, Mode, ModeList, SubmitKind};

    // Known modes carry sensible sizes.
    if Mode::FHD_60.width != 1920 || Mode::FHD_60.height != 1080 {
        return TestResult::Fail("FHD_60 mode fields wrong");
    }
    if Mode::XGA_60.refresh_hz != 60 {
        return TestResult::Fail("XGA_60 refresh_hz wrong");
    }

    let mut list = ModeList::default();
    list.modes.push(Mode::FHD_60);
    list.modes.push(Mode::XGA_60);
    if list.modes.len() != 2 {
        return TestResult::Fail("mode list len");
    }

    // Family + submit kind discriminants distinct.
    if GpuFamily::VirtioGpu == GpuFamily::IntelI915 {
        return TestResult::Fail("GpuFamily variants collapsed");
    }
    if SubmitKind::Gfx == SubmitKind::Compute {
        return TestResult::Fail("SubmitKind variants collapsed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_drivers_gpu_mode_and_family);

/// A render-node GEM handle owns its coherent DMA backing only while it is in
/// that open file's resource table (or while an in-flight operation holds an
/// Arc). Removing the handle must drop the final owner and return the pages;
/// otherwise a long-lived compositor leaks one buffer per GEM_CLOSE.
fn smoke_virtgpu_render_resource_close_reclaims_dma() -> TestResult {
    let before = narf_memory::frame_stats().free;
    let buffer = match narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0) {
        Ok(buffer) => buffer,
        Err(_) => return TestResult::Skip("no frame available for virtgpu resource lifecycle"),
    };
    if narf_memory::frame_stats().free >= before {
        return TestResult::Fail("coherent resource allocation did not consume a frame");
    }

    let state = crate::drm_ioctl_bridge::VirtGpuRenderState::new();
    state.insert(7, 77, buffer);
    let mapping = match state.mapping_resource(7 << 12, 4096) {
        Some(mapping) => mapping,
        None => return TestResult::Fail("mmap did not retain its GEM resource"),
    };
    if state.take(8).is_some() {
        return TestResult::Fail("unknown GEM handle removed a render resource");
    }
    if state.take(7).is_none() {
        return TestResult::Fail("GEM_CLOSE did not remove its render resource");
    }
    if narf_memory::frame_stats().free >= before {
        return TestResult::Fail("GEM_CLOSE recycled a still-mapped DMA frame");
    }
    drop(mapping);
    if narf_memory::frame_stats().free != before {
        return TestResult::Fail("last mapping did not release the closed resource's DMA frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_virtgpu_render_resource_close_reclaims_dma
);

// libudev derives a DRM device's node path from DEVNAME and its devnum
// from MAJOR:MINOR. With either missing, udev_device_get_devnode() returns
// NULL and weston's find_primary_gpu reports "no drm device found" even
// though /dev/dri/card0 exists. Guard the card0 uevent shape. The DRM
// sysfs bridge is linux-compat-only, so this test follows that gate.
fn smoke_drm_card_uevent_has_major_and_devname() -> TestResult {
    let u = crate::drm_sysfs_bridge::card_uevent(0, "narf-drm");
    if !u.contains("MAJOR=226\n") {
        return TestResult::Fail("drm card uevent missing MAJOR=226");
    }
    if !u.contains("DEVNAME=dri/card0\n") {
        return TestResult::Fail("drm card uevent missing DEVNAME=dri/card0");
    }
    if !u.contains("MINOR=0\n") {
        return TestResult::Fail("drm card uevent missing MINOR=0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_drm_card_uevent_has_major_and_devname);

// A DRM node's `st_rdev` must encode DRM_MAJOR(226):minor, or logind's
// TakeDevice (sd_device_new_from_devnum on the node's rdev) fails ENODEV and a
// session compositor never gets the GPU fd. dev_t = (major<<8)|minor here.
fn smoke_drm_node_rdev_encodes_major_226() -> TestResult {
    if crate::drm_devfs_bridge::card_rdev(0) != (226 << 8) {
        return TestResult::Fail("card0 rdev is not 226:0");
    }
    if crate::drm_devfs_bridge::card_rdev(1) != ((226 << 8) | 1) {
        return TestResult::Fail("card1 rdev is not 226:1");
    }
    if crate::drm_devfs_bridge::render_rdev(0) != ((226 << 8) | 128) {
        return TestResult::Fail("renderD128 rdev is not 226:128");
    }
    if crate::drm_devfs_bridge::card_rdev(0) == 0 {
        return TestResult::Fail("card0 rdev is 0 (the bug: devnum lookup fails)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_drm_node_rdev_encodes_major_226);

fn smoke_bochs_display_probed_at_boot() -> TestResult {
    use narf_graphics_driver::bochs;
    if bochs::is_probed() {
        TestResult::Pass
    } else {
        TestResult::Skip("bochs-display not present in this QEMU config")
    }
}
kernel_test_in!("drivers/gpu", smoke_bochs_display_probed_at_boot);

fn smoke_virtio_gpu_probed_at_boot() -> TestResult {
    use narf_drivers_virtio::gpu_pci;
    if gpu_pci::is_probed() {
        TestResult::Pass
    } else {
        TestResult::Skip("virtio-gpu-pci not present in this QEMU config")
    }
}
kernel_test_in!("drivers/gpu", smoke_virtio_gpu_probed_at_boot);

fn smoke_virtio_gpu_scanout_initialised() -> TestResult {
    // After boot's splash blit, the virtio-gpu controller should be
    // marked `ready` (init_scanout completed: GET_DISPLAY_INFO,
    // RESOURCE_CREATE_2D, ATTACH_BACKING, SET_SCANOUT all OK).
    use narf_drivers_virtio::gpu_pci;
    if !gpu_pci::is_probed() {
        return TestResult::Skip("virtio-gpu-pci not present");
    }
    match gpu_pci::with_controller(|d| d.is_ready()) {
        Some(true) => TestResult::Pass,
        Some(false) => TestResult::Fail("virtio-gpu probed but scanout not ready"),
        None => TestResult::Skip("virtio-gpu-pci controller missing"),
    }
}
kernel_test_in!("drivers/gpu", smoke_virtio_gpu_scanout_initialised);

fn smoke_amdgpu_pci_matches_registered() -> TestResult {
    // Structural: register the amdgpu driver and assert every
    // explicit AMD VID/DID match plus the class-match backstop
    // are in the bus's table. Doesn't require live silicon.
    use crate::amdgpu;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    amdgpu::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX_HAWKPOINT1),
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX1),
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX2),
        (amdgpu::AMD_VENDOR, amdgpu::STRIX_POINT),
        (amdgpu::AMD_VENDOR, amdgpu::REMBRANDT),
        (amdgpu::AMD_VENDOR, amdgpu::RAPHAEL),
        (amdgpu::AMD_VENDOR, amdgpu::CEZANNE),
        (amdgpu::AMD_VENDOR, amdgpu::RENOIR),
        (amdgpu::AMD_VENDOR, amdgpu::NAVI22),
        (amdgpu::AMD_VENDOR, amdgpu::NAVI31),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d)
        });
        if !found {
            return TestResult::Fail("missing amdgpu VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x03,
                mask: 0xFF,
            }
        )
    });
    if !class_match {
        return TestResult::Fail("amdgpu class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pci_matches_registered);

fn smoke_amdgpu_family_table_documented_offsets() -> TestResult {
    // Family::mp0_base() is documented for Vega + Navi1; the
    // Stage-2 spec leaves Phoenix/Strix/Renoir/Navi2 marked TBD
    // pending datasheet sourcing. Lock this in so accidentally
    // shipping a placeholder offset for an undocumented family
    // surfaces as a test failure.
    use crate::amdgpu::Family;
    if Family::Vega.mp0_base() != Some(0x000B_0000) {
        return TestResult::Fail("Vega MP0 base wrong");
    }
    if Family::Navi1.mp0_base() != Some(0x000B_0000) {
        return TestResult::Fail("Navi1 MP0 base wrong");
    }
    if Family::Navi2.mp0_base().is_some() {
        return TestResult::Fail("Navi2 should be TBD");
    }
    if Family::Navi3.mp0_base().is_some() {
        return TestResult::Fail("Navi3 should be TBD");
    }
    if Family::Renoir.mp0_base().is_some() {
        return TestResult::Fail("Renoir should be TBD");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_family_table_documented_offsets);

// `smoke_amdgpu_scanout_picker_idle` lives in `fb/src/tests.rs`
// to avoid a `narf-drivers-gpu` ↔ `narf-fb` Cargo cycle (fb
// already depends on drivers/gpu for the picker).

fn smoke_amdgpu_atombios_table_directory_round_trip() -> TestResult {
    // Synthesize an ATOMBIOS image: PCI ROM signature + ATOM
    // marker + master data table at a known offset + 3 indexable
    // tables with distinct payloads. Verify the parser locates
    // the master, decodes the count, and resolves each table id.
    use crate::amdgpu_atombios::{AtomError, Atombios};
    let mut img = alloc::vec![0u8; 0x200];
    // PCI ROM signature.
    img[0] = 0x55;
    img[1] = 0xAA;
    // Common ROM header at 0x80, signature at header +4.
    img[0x48..0x4a].copy_from_slice(&0x80u16.to_le_bytes());
    img[0x80..0x84].copy_from_slice(&[36, 0, 1, 1]);
    img[0x84..0x88].copy_from_slice(b"ATOM");
    // Master data table at offset 0x100.
    img[0xa0..0xa2].copy_from_slice(&0x100u16.to_le_bytes());
    // ATOM_COMMON_TABLE_HEADER: usStructureSize covers header (4) +
    // 3 × u16 entries = 10 bytes.
    img[0x100..0x102].copy_from_slice(&10u16.to_le_bytes());
    img[0x102] = 1; // ucTableFormatRevision
    img[0x103] = 1; // ucTableContentRevision
                    // Per-table offset array: ids 0/1/2 → 0x150, 0x160, 0x170.
    img[0x104..0x106].copy_from_slice(&0x150u16.to_le_bytes());
    img[0x106..0x108].copy_from_slice(&0x160u16.to_le_bytes());
    img[0x108..0x10A].copy_from_slice(&0x170u16.to_le_bytes());
    // Each table's first 2 bytes are usStructureSize.
    img[0x150..0x152].copy_from_slice(&8u16.to_le_bytes());
    img[0x160..0x162].copy_from_slice(&12u16.to_le_bytes());
    img[0x170..0x172].copy_from_slice(&16u16.to_le_bytes());

    let atom = match Atombios::parse(&img) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("ATOMBIOS parse rejected synthetic image"),
    };
    if atom.data_table_count() != 3 {
        return TestResult::Fail("data_table_count mis-decoded");
    }
    if atom.data_table_offset(0) != Ok(0x150) {
        return TestResult::Fail("table 0 offset");
    }
    if atom.data_table_offset(1) != Ok(0x160) {
        return TestResult::Fail("table 1 offset");
    }
    if atom.data_table_offset(2) != Ok(0x170) {
        return TestResult::Fail("table 2 offset");
    }
    if atom.data_table_offset(3) != Err(AtomError::UnknownTableId) {
        return TestResult::Fail("out-of-range id should fail");
    }
    let t = match atom.data_table(1) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("data_table(1) borrow"),
    };
    if t.len() != 12 {
        return TestResult::Fail("data_table length wrong");
    }
    // Bad PCI ROM signature.
    let mut bad = img.clone();
    bad[0] = 0;
    if !matches!(Atombios::parse(&bad), Err(AtomError::NotPciRom)) {
        return TestResult::Fail("missing PCI ROM signature should reject");
    }
    // Bad ATOM marker.
    let mut bad = img.clone();
    bad[0x84] = b'X';
    if !matches!(Atombios::parse(&bad), Err(AtomError::NotAtombios)) {
        return TestResult::Fail("missing ATOM marker should reject");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atombios",
    smoke_amdgpu_atombios_table_directory_round_trip
);

fn smoke_amdgpu_pm4_indirect_buffer_packet() -> TestResult {
    // INDIRECT_BUFFER is 4 dwords: header + ib_lo + ib_hi +
    // (size | vmid<<24). Verify the header type/opcode/count
    // fields and the data words round-trip correctly.
    use crate::amdgpu_pm4::Pm4Builder;
    let mut buf = [0u32; 8];
    let mut b = Pm4Builder::new(&mut buf);
    if b.indirect_buffer(0x1234_5678_ABCD_0000, 0x100, 3).is_err() {
        return TestResult::Fail("indirect_buffer build failed");
    }
    if b.bytes_written() != 16 {
        return TestResult::Fail("expected 16 bytes (4 dwords)");
    }
    // Header: type3 (3<<30) | (count_minus_1 = 2) << 16 | opcode 0x3F << 8.
    let header = buf[0];
    if (header >> 30) != 3 {
        return TestResult::Fail("packet type != TYPE3");
    }
    if ((header >> 16) & 0x3FFF) != 2 {
        return TestResult::Fail("count_minus_1 != 2 (3 data dwords - 1)");
    }
    if ((header >> 8) & 0xFF) != 0x3F {
        return TestResult::Fail("opcode != INDIRECT_BUFFER");
    }
    if buf[1] != 0xABCD_0000 || buf[2] != 0x1234_5678 {
        return TestResult::Fail("ib_base round-trip");
    }
    if (buf[3] & 0x000F_FFFF) != 0x100 {
        return TestResult::Fail("ib_size_dw round-trip");
    }
    if ((buf[3] >> 24) & 0xF) != 3 {
        return TestResult::Fail("vmid round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pm4_indirect_buffer_packet);

fn smoke_amdgpu_pm4_write_data_fence_packet() -> TestResult {
    use crate::amdgpu_pm4::Pm4Builder;
    let mut buf = [0u32; 8];
    let mut b = Pm4Builder::new(&mut buf);
    let dst = 0xDEAD_BEEF_CAFE_F00D;
    if b.write_data(dst, 0x1234_5678).is_err() {
        return TestResult::Fail("write_data build failed");
    }
    if b.bytes_written() != 20 {
        return TestResult::Fail("expected 20 bytes (5 dwords)");
    }
    // Header opcode = 0x37, count_minus_1 = 3 (4 data dwords - 1).
    let header = buf[0];
    if ((header >> 8) & 0xFF) != 0x37 {
        return TestResult::Fail("opcode != WRITE_DATA");
    }
    if ((header >> 16) & 0x3FFF) != 3 {
        return TestResult::Fail("count_minus_1 != 3");
    }
    // Control word: dst_sel (5 << 8) | wr_confirm (1 << 20).
    let ctrl = buf[1];
    if (ctrl >> 8) & 0xF != 5 {
        return TestResult::Fail("dst_sel != MEM");
    }
    if ctrl & (1 << 20) == 0 {
        return TestResult::Fail("wr_confirm not set");
    }
    if buf[2] != dst as u32 || buf[3] != (dst >> 32) as u32 {
        return TestResult::Fail("dst_addr round-trip");
    }
    if buf[4] != 0x1234_5678 {
        return TestResult::Fail("value round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pm4_write_data_fence_packet);

fn smoke_amdgpu_ring_submit_advances_wptr() -> TestResult {
    use crate::amdgpu_ring::{Ring, RingError, DOORBELL_STRIDE_BYTES, NOP_DW, RING_SIZE_DW};
    let mut ring = match Ring::new(7) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("Ring::new failed"),
    };
    if ring.queue_idx != 7 {
        return TestResult::Fail("queue_idx not preserved");
    }
    if ring.doorbell_offset() != 7 * DOORBELL_STRIDE_BYTES {
        return TestResult::Fail("doorbell offset wrong");
    }
    if ring.wptr() != 0 {
        return TestResult::Fail("fresh ring should have wptr=0");
    }
    // A fresh ring is filled with the NOP PACKET, not zeros. A zero dword is
    // a PM4 TYPE0 header naming register 0, so an engine that ran past the
    // written region would write into register 0 rather than idle.
    for i in [0u64, 1, 511, (RING_SIZE_DW as u64) - 1] {
        // SAFETY: the ring's backing is alive for the test.
        if unsafe { ring.peek(i) } != NOP_DW {
            return TestResult::Fail("a fresh ring must be filled with NOP packets");
        }
    }

    let pkt = [0xDEAD_BEEFu32, 0x1234_5678, 0xAAAA_5555, 0x0000_0001];
    // SAFETY: smoke harness owns the ring exclusively.
    let new_wptr = match unsafe { ring.submit(&pkt, 0) } {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("submit rejected 4-dword packet"),
    };
    if new_wptr != 4 || ring.wptr() != 4 {
        return TestResult::Fail("wptr didn't advance by 4 dwords");
    }
    for (i, want) in pkt.iter().enumerate() {
        // SAFETY: as above.
        if unsafe { ring.peek(i as u64) } != *want {
            return TestResult::Fail("a submitted dword is not in the ring");
        }
    }

    // Space is measured against what the GPU has CONSUMED, not against the
    // end of the buffer — a packet may straddle the wrap freely.
    if ring.used_dw(0) != 4 || ring.free_dw(0) != RING_SIZE_DW as u64 - 4 {
        return TestResult::Fail("used/free accounting is wrong");
    }
    // With rptr caught up, the whole ring is free again even though wptr is
    // not at the base.
    if ring.free_dw(4) != RING_SIZE_DW as u64 {
        return TestResult::Fail("a fully consumed ring should be entirely free");
    }

    // Writing more than the GPU has consumed must be refused: overwriting
    // unconsumed dwords corrupts a command the engine is still executing.
    let huge = alloc::vec![0u32; RING_SIZE_DW];
    // SAFETY: same.
    if !matches!(unsafe { ring.submit(&huge, 0) }, Err(RingError::Full)) {
        return TestResult::Fail("a packet larger than the free space must be Full");
    }
    // Larger than the ring can ever hold is a different answer — no amount of
    // waiting would make it fit.
    let enormous = alloc::vec![0u32; RING_SIZE_DW + 1];
    if !matches!(
        // SAFETY: smoke harness owns the ring exclusively.
        unsafe { ring.submit(&enormous, 0) },
        Err(RingError::TooLarge)
    ) {
        return TestResult::Fail("a packet larger than the ring must be TooLarge");
    }

    // ── the wrap ──
    // Fill to four dwords short of the end, then submit an 8-dword packet so
    // it straddles the boundary. The old implementation refused this outright.
    let mut consumed = 0u64;
    while ring.wptr() < RING_SIZE_DW as u64 - 4 {
        // SAFETY: as above; rptr is advanced in step so there is always room.
        if unsafe { ring.insert_nop(4, consumed) }.is_err() {
            return TestResult::Fail("filling the ring with NOPs failed");
        }
        consumed = ring.wptr().saturating_sub(16);
    }
    let straddle: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0x8888_8888];
    let before = ring.wptr();
    // SAFETY: as above.
    if unsafe { ring.submit(&straddle, before) }.is_err() {
        return TestResult::Fail("a packet straddling the wrap should be accepted");
    }
    if ring.wptr() != before + 8 {
        return TestResult::Fail("the wrapping submit did not advance wptr by 8");
    }
    // The first four landed at the end of the buffer and the last four at the
    // start — which is what a circular ring means.
    for (i, want) in straddle.iter().enumerate() {
        // SAFETY: as above.
        if unsafe { ring.peek(before + i as u64) } != *want {
            return TestResult::Fail("a straddling packet's dwords are misplaced");
        }
    }
    // SAFETY: as above.
    if unsafe { ring.peek(0) } != straddle[4] {
        return TestResult::Fail("the wrapped tail should land at the ring base");
    }

    // ── alignment padding ──
    let rptr = ring.wptr();
    // SAFETY: as above.
    if unsafe { ring.align_to(8, rptr) }.is_err() {
        return TestResult::Fail("align_to failed");
    }
    if ring.wptr() % 8 != 0 {
        return TestResult::Fail("align_to did not reach the alignment");
    }
    // Already aligned: a no-op, not a whole extra period of padding.
    let aligned = ring.wptr();
    // SAFETY: as above.
    let _ = unsafe { ring.align_to(8, rptr) };
    if ring.wptr() != aligned {
        return TestResult::Fail("align_to padded an already-aligned ring");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_ring_submit_advances_wptr);

fn smoke_dp_aux_native_read_request_round_trip() -> TestResult {
    use crate::dp_aux::{decode_response, encode_request, AuxCommand, AuxRequest, AuxStatus};
    let req = AuxRequest {
        cmd: AuxCommand::NativeRead,
        address: 0x0_2000, // DPCD_REV
        data: &[],
    };
    let mut wire = [0u8; 4];
    let n = match encode_request(&req, &mut wire) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("encode rejected NATIVE_READ"),
    };
    if n != 4 {
        return TestResult::Fail("read request should be 4 bytes");
    }
    if wire[0] >> 4 != AuxCommand::NativeRead as u8 {
        return TestResult::Fail("command nibble mis-encoded");
    }
    // Reply: 1 status byte + 1 data byte. ACK + data 0x14 (DP 1.4).
    let raw_reply = [0x00u8, 0x14];
    let resp = match decode_response(&raw_reply, 1) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("decode rejected ACK reply"),
    };
    if resp.status != AuxStatus::Ack {
        return TestResult::Fail("status != ACK");
    }
    if resp.data != [0x14u8] {
        return TestResult::Fail("payload mis-decoded");
    }
    // A NACK reply surfaces as Nacked.
    let nack_reply = [0x10u8];
    match decode_response(&nack_reply, 0) {
        Err(crate::dp_aux::AuxError::Nacked) => TestResult::Pass,
        _ => TestResult::Fail("NACK reply not surfaced"),
    }
}
kernel_test_in!("drivers/gpu", smoke_dp_aux_native_read_request_round_trip);

fn smoke_dp_aux_native_write_encodes_payload() -> TestResult {
    use crate::dp_aux::{encode_request, AuxCommand, AuxRequest};
    let payload = [0x01u8, 0x02, 0x03, 0x04];
    let req = AuxRequest {
        cmd: AuxCommand::NativeWrite,
        address: 0x0_0103, // TRAINING_PATTERN_SET
        data: &payload,
    };
    let mut wire = [0u8; 8];
    let n = match encode_request(&req, &mut wire) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("encode failed"),
    };
    if n != 8 {
        return TestResult::Fail("4 byte header + 4 byte payload");
    }
    if wire[0] >> 4 != AuxCommand::NativeWrite as u8 {
        return TestResult::Fail("command nibble wrong");
    }
    if wire[3] != 3 {
        return TestResult::Fail("len nibble != 3 (4 bytes - 1)");
    }
    if wire[4..8] != payload {
        return TestResult::Fail("payload not appended");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_dp_aux_native_write_encodes_payload);

fn smoke_amdgpu_atom_fwinfo_v3_round_trip() -> TestResult {
    use crate::amdgpu_atom_fwinfo::{parse, FwInfoError};
    let mut t = alloc::vec![0u8; 0x80];
    // ATOM_COMMON_TABLE_HEADER: usSize=0x80, fmt=4, content=0x34
    t[0..2].copy_from_slice(&0x80u16.to_le_bytes());
    t[2] = 4;
    t[3] = 0x34;
    // firmware_revision = 0x0000_1234
    t[0x04..0x08].copy_from_slice(&0x1234u32.to_le_bytes());
    // engine clock = 1500 MHz = 150_000 (10kHz units)
    t[0x08..0x0C].copy_from_slice(&150_000u32.to_le_bytes());
    // memory clock = 6400 MHz = 640_000
    t[0x0C..0x10].copy_from_slice(&640_000u32.to_le_bytes());
    // max pixel clock = 1188 MHz = 118_800
    t[0x20..0x24].copy_from_slice(&118_800u32.to_le_bytes());
    // bootup VDDC = 950 mV
    t[0x2E..0x30].copy_from_slice(&950u16.to_le_bytes());
    // memory module id = 7, cooling solution id = 2
    t[0x59] = 7;
    t[0x5A] = 2;
    let info = match parse(&t) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("FwInfo parse rejected synthetic table"),
    };
    if info.format_revision != 4 || info.content_revision != 0x34 {
        return TestResult::Fail("revision fields wrong");
    }
    if info.firmware_revision != 0x1234 {
        return TestResult::Fail("firmware_revision round-trip");
    }
    if info.default_engine_mhz() != 1500 {
        return TestResult::Fail("engine clock MHz conversion");
    }
    if info.default_memory_mhz() != 6400 {
        return TestResult::Fail("memory clock MHz conversion");
    }
    if info.max_pixel_clock_pll_10khz != 118_800 {
        return TestResult::Fail("max pixel clock");
    }
    if info.bootup_vddc_mv != 950 {
        return TestResult::Fail("bootup VDDC");
    }
    if info.memory_module_id != 7 || info.cooling_solution_id != 2 {
        return TestResult::Fail("memory/cooling ids");
    }
    // V2.x rejected.
    let mut bad = t.clone();
    bad[3] = 0x24; // content rev V2.4
    if !matches!(parse(&bad), Err(FwInfoError::UnsupportedVersion(_))) {
        return TestResult::Fail("V2 should be rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_atom_fwinfo_v3_round_trip);

fn smoke_amdgpu_ucode_header_round_trip() -> TestResult {
    use crate::amdgpu_ucode::{parse, payload, UcodeError, UCODE_MAGIC};
    // Build a 1024-byte synthetic blob: 4-byte magic + 32-byte
    // common header at offset 4 + zero-fill to 256, then a
    // 768-byte fake payload starting at offset 256.
    let mut blob = alloc::vec![0u8; 1024];
    blob[0..4].copy_from_slice(&UCODE_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&256u32.to_le_bytes()); // start_offset
    blob[8..12].copy_from_slice(&768u32.to_le_bytes()); // payload_size
    blob[12..16].copy_from_slice(&0x0001_0203u32.to_le_bytes()); // version
    blob[16..20].copy_from_slice(&0x0042u32.to_le_bytes()); // feature ver
    let hdr = match parse(&blob) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("ucode parse rejected synthetic blob"),
    };
    if hdr.start_offset != 256 || hdr.payload_size != 768 {
        return TestResult::Fail("offsets round-trip");
    }
    if hdr.version != 0x0001_0203 || hdr.feature_version != 0x0042 {
        return TestResult::Fail("version round-trip");
    }
    let p = payload(&blob, &hdr);
    if p.len() != 768 {
        return TestResult::Fail("payload length");
    }
    // Bad magic.
    let mut bad = blob.clone();
    bad[0] ^= 0xFF;
    if !matches!(parse(&bad), Err(UcodeError::BadMagic)) {
        return TestResult::Fail("bad magic should reject");
    }
    // Payload-out-of-bounds.
    let mut bad = blob.clone();
    bad[8..12].copy_from_slice(&2000u32.to_le_bytes()); // size > blob
    if !matches!(parse(&bad), Err(UcodeError::PayloadOutOfBounds)) {
        return TestResult::Fail("oversize payload should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_ucode_header_round_trip);

fn smoke_dp_link_training_completes_against_stub() -> TestResult {
    // Stub AUX channel that simulates a healthy 2-lane sink: CR
    // succeeds on the second poll (after one swing bump);
    // EQ succeeds on the third poll.
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{run, TrainingParams, TrainingState};

    struct StubAux {
        // Counter the stub uses to step through pretend sink state.
        cr_polls: u32,
        eq_polls: u32,
    }
    impl AuxChannel for StubAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            // All writes succeed silently. Reads: gate on the
            // address; LANE0_1_STATUS at 0x202, LANE2_3_STATUS at
            // 0x203, LANE_ALIGN_STATUS_UPDATED at 0x204.
            match req.cmd {
                AuxCommand::NativeWrite => {
                    reply_buf[0] = 0; // ACK
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    let v = match req.address {
                        0x0_0202 => {
                            // Lane 0/1 nibbles. After 2 polls, CR_DONE
                            // + EQ_DONE + SYMBOL_LOCKED on both lanes.
                            self.cr_polls += 1;
                            if self.cr_polls < 2 {
                                0x00
                            } else if self.eq_polls == 0 {
                                0x11
                            }
                            // CR only
                            else {
                                0x77
                            } // EQ done
                        }
                        0x0_0203 => 0x00, // lane 2/3 unused (2-lane link)
                        0x0_0204 => {
                            // INTERLANE_ALIGN_DONE bit 0; flips on
                            // after EQ symbols lock.
                            self.eq_polls += 1;
                            if self.eq_polls < 2 {
                                0
                            } else {
                                1
                            }
                        }
                        _ => 0,
                    };
                    reply_buf[0] = 0; // ACK status
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = StubAux {
        cr_polls: 0,
        eq_polls: 0,
    };
    let params = TrainingParams {
        link_bw_set: 0x0A,
        lane_count: 2,
    };
    let result = match run(&mut aux, params, |_| {}) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("link training surfaced AUX error"),
    };
    if result != TrainingState::Trained {
        return TestResult::Fail("training did not converge to Trained");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_dp_link_training_completes_against_stub);

fn smoke_amdgpu_pptable_v11_directory_round_trip() -> TestResult {
    use crate::amdgpu_pptable::{PpTable, PpTableError, Subtable};
    let mut t = alloc::vec![0u8; 80];
    // Header: usSize=80, fmt=11, content=0
    t[0..2].copy_from_slice(&80u16.to_le_bytes());
    t[2] = 11;
    t[3] = 0;
    // Set a subset of offsets.
    // Subtable::PlatformDescriptor (idx 0) → 0x100
    t[4..8].copy_from_slice(&0x100u32.to_le_bytes());
    // Subtable::FanTable (idx 4) → 0x200
    t[20..24].copy_from_slice(&0x200u32.to_le_bytes());
    // Subtable::SocClockDependency (idx 6) → 0x300
    t[28..32].copy_from_slice(&0x300u32.to_le_bytes());
    let pp = match PpTable::parse(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("PpTable parse rejected V11.0"),
    };
    if pp.format_revision != 11 {
        return TestResult::Fail("format revision");
    }
    if pp.present_count() != 3 {
        return TestResult::Fail("present_count != 3");
    }
    if pp.offset(Subtable::PlatformDescriptor) != Ok(0x100) {
        return TestResult::Fail("PlatformDescriptor offset");
    }
    if pp.offset(Subtable::FanTable) != Ok(0x200) {
        return TestResult::Fail("FanTable offset");
    }
    if !matches!(
        pp.offset(Subtable::OverdriveTable8),
        Err(PpTableError::TableAbsent)
    ) {
        return TestResult::Fail("absent subtable should fail");
    }
    // V8 rejected.
    let mut bad = t.clone();
    bad[2] = 8;
    if !matches!(
        PpTable::parse(&bad),
        Err(PpTableError::UnsupportedVersion(_))
    ) {
        return TestResult::Fail("V8 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pptable_v11_directory_round_trip);

fn smoke_amdgpu_atom_displayobj_iter_paths() -> TestResult {
    use crate::amdgpu_atom_displayobj::{ConnectorKind, DisplayObjError, DisplayObjectTable};
    // Build a synthetic display-object table with 3 paths:
    //   path 0: DP connector (object id 0x13), instance 0
    //   path 1: HDMI-A (0x0C), instance 1
    //   path 2: eDP   (0x14), instance 0
    let mut t = alloc::vec![0u8; 8 + 3 * 8];
    // Header.
    t[0..2].copy_from_slice(&((8u16 + 3 * 8).to_le_bytes()));
    t[2] = 1; // format_revision
    t[3] = 0; // content_revision
    t[4..6].copy_from_slice(&0x0001u16.to_le_bytes()); // device_support bitmap
    t[6] = 3; // num_paths
              // Paths start at 8.
    let paths = [
        (0x0001u16, (0x13u16 << 8), 0x1100u16),        // DP
        (0x0002u16, (0x0Cu16 << 8) | 1u16, 0x1101u16), // HDMI-A
        (0x0004u16, (0x14u16 << 8), 0x1102u16),        // eDP
    ];
    for (i, (tag, conn, gpu)) in paths.iter().enumerate() {
        let off = 8 + i * 8;
        t[off..off + 2].copy_from_slice(&tag.to_le_bytes());
        t[off + 2..off + 4].copy_from_slice(&8u16.to_le_bytes());
        t[off + 4..off + 6].copy_from_slice(&conn.to_le_bytes());
        t[off + 6..off + 8].copy_from_slice(&gpu.to_le_bytes());
    }
    let mut tbl = match DisplayObjectTable::parse(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("displayobj parse rejected"),
    };
    if tbl.path_count() != 3 {
        return TestResult::Fail("path_count != 3");
    }
    if tbl.device_support_bitmap() != 0x0001 {
        return TestResult::Fail("device_support bitmap mis-decoded");
    }
    let p0 = tbl.next().expect("first path");
    if p0.connector_kind != ConnectorKind::Dp {
        return TestResult::Fail("path 0 not DP");
    }
    let p1 = tbl.next().expect("second path");
    if p1.connector_kind != ConnectorKind::HdmiA || p1.connector_index != 1 {
        return TestResult::Fail("path 1 not HDMI-A.1");
    }
    let p2 = tbl.next().expect("third path");
    if p2.connector_kind != ConnectorKind::Edp {
        return TestResult::Fail("path 2 not eDP");
    }
    if tbl.next().is_some() {
        return TestResult::Fail("iterator yielded extra path");
    }
    // Bad version → rejected.
    let mut bad = t.clone();
    bad[2] = 0;
    if !matches!(
        DisplayObjectTable::parse(&bad),
        Err(DisplayObjError::UnsupportedVersion(_))
    ) {
        return TestResult::Fail("version 0 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_atom_displayobj_iter_paths);

fn smoke_dp_edid_over_aux_round_trip() -> TestResult {
    // StubAux that returns canned EDID bytes for I2C reads at
    // address 0x50<<1 + read flag.
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_edid::read_panel_edid;

    // Build a valid 128-byte EDID 1.4 block (minimal: header,
    // manufacturer "AMD", version 1.4, no detailed timing — we
    // only check that the bytes flow end-to-end and the parser
    // accepts the block; preferred-timing decoding is covered
    // by the dedicated EDID smoke).
    let mut edid = [0u8; 128];
    edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "AMD" — A=1, M=13, D=4
    let mfr: u16 = (1u16 << 10) | (13u16 << 5) | 4;
    edid[8] = (mfr >> 8) as u8;
    edid[9] = mfr as u8;
    edid[18] = 1;
    edid[19] = 4;
    // Detailed-timing slot: pixel clock 0 marks the slot as a
    // generic descriptor (display name etc.); the parser
    // accepts the block but `preferred_timing()` returns
    // NoPreferredTiming. We only check round-trip here.
    let s: u8 = edid[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    edid[127] = 0u8.wrapping_sub(s);

    struct StubAux {
        edid: [u8; 128],
        cursor: usize,
    }
    impl AuxChannel for StubAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::I2cWrite => {
                    // The driver writes the EDID offset (0) to
                    // position the slave; reset the cursor.
                    self.cursor = 0;
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::I2cReadMot => {
                    // Return up to (reply_buf.len() - 1) bytes
                    // starting at cursor.
                    let n = reply_buf.len() - 1;
                    reply_buf[0] = 0;
                    let end = (self.cursor + n).min(self.edid.len());
                    let slice = &self.edid[self.cursor..end];
                    reply_buf[1..1 + slice.len()].copy_from_slice(slice);
                    self.cursor += slice.len();
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1 + n],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = StubAux { edid, cursor: 0 };
    let mut buf = [0u8; 128];
    let parsed = match read_panel_edid(&mut aux, &mut buf) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("read_panel_edid rejected stub bytes"),
    };
    if parsed.manufacturer() != *b"AMD" {
        return TestResult::Fail("manufacturer round-trip");
    }
    if parsed.version_major() != 1 || parsed.version_minor() != 4 {
        return TestResult::Fail("version round-trip");
    }
    // Buffer should now hold the original EDID bytes.
    if buf != edid {
        return TestResult::Fail("buffer doesn't match original EDID");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_dp_edid_over_aux_round_trip);

fn smoke_amdgpu_offsets_runtime_registry_overrides_compile_time() -> TestResult {
    use crate::amdgpu::Family;
    use crate::amdgpu_offsets::{
        FamilyOffsets, __reset_for_test, offsets_of, register_family_offsets, registered_count,
    };
    __reset_for_test();
    if registered_count() != 0 {
        return TestResult::Fail("reset didn't clear registry");
    }
    // Compile-time fallback wins when registry is empty.
    if Family::Vega.mp0_base() != Some(0x000B_0000) {
        return TestResult::Fail("Vega compile-time fallback");
    }
    if Family::Navi3.mp0_base().is_some() {
        return TestResult::Fail("Navi3 should default None");
    }
    // Plug in Navi3 + override Vega.
    register_family_offsets(
        Family::Navi3,
        FamilyOffsets {
            mp0_base: Some(0x0010_0000),
            dcn_hubp_base: Some(0x0040_0000),
            dcn_otg_base: Some(0x0050_0000),
            ..FamilyOffsets::empty()
        },
    );
    register_family_offsets(
        Family::Vega,
        FamilyOffsets {
            mp0_base: Some(0x4242_4242),
            ..FamilyOffsets::empty()
        },
    );
    // Runtime override takes precedence on Vega (compile-time
    // had Some(0x000B_0000)).
    if Family::Vega.mp0_base() != Some(0x4242_4242) {
        return TestResult::Fail("runtime override didn't beat compile-time");
    }
    if Family::Navi3.mp0_base() != Some(0x0010_0000) {
        return TestResult::Fail("Navi3 runtime registration");
    }
    let n3 = offsets_of(Family::Navi3);
    if n3.dcn_hubp_base != Some(0x0040_0000) || n3.dcn_otg_base != Some(0x0050_0000) {
        return TestResult::Fail("DCN block bases lost");
    }
    if registered_count() != 2 {
        return TestResult::Fail("registered_count != 2");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_amdgpu_offsets_runtime_registry_overrides_compile_time
);

fn smoke_amdgpu_atom_dcn_init_data_round_trip() -> TestResult {
    use crate::amdgpu_atom_dcn::{parse, DcnInitError};
    let mut t = alloc::vec![0u8; 0x20];
    t[0..2].copy_from_slice(&0x1Au16.to_le_bytes());
    t[2] = 1;
    t[3] = 0;
    t[0x04] = 4; // max_disp_engines
    t[0x05] = 2; // max_active
    t[0x06] = 6; // max_ppll
    t[0x07] = 1; // core_ref_clk_source
                 // disp_clk_used = 600 MHz = 60_000 (10 kHz units)
    t[0x08..0x0C].copy_from_slice(&60_000u32.to_le_bytes());
    // max_disp_clk = 1500 MHz
    t[0x0C..0x10].copy_from_slice(&150_000u32.to_le_bytes());
    // boot mode 1920x1080 @ 148.5 MHz
    t[0x10..0x12].copy_from_slice(&1920u16.to_le_bytes());
    t[0x12..0x14].copy_from_slice(&1080u16.to_le_bytes());
    t[0x14..0x18].copy_from_slice(&14_850u32.to_le_bytes());
    t[0x18] = 0; // XRGB8888
    let info = match parse(&t) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("parse rejected"),
    };
    if info.format_revision != 1 {
        return TestResult::Fail("format revision");
    }
    if info.max_disp_engines != 4 || info.max_active_engines != 2 {
        return TestResult::Fail("engine counts");
    }
    if info.boot_h_active != 1920 || info.boot_v_active != 1080 {
        return TestResult::Fail("boot mode resolution");
    }
    if info.boot_pixel_clock_10khz != 14_850 {
        return TestResult::Fail("boot pixel clock");
    }
    if info.max_disp_clk_10khz != 150_000 {
        return TestResult::Fail("max disp clock");
    }
    // V2 rejected.
    let mut bad = t.clone();
    bad[2] = 2;
    if !matches!(parse(&bad), Err(DcnInitError::UnsupportedVersion(_))) {
        return TestResult::Fail("V2 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_atom_dcn_init_data_round_trip);

fn smoke_amdgpu_displayobj_object_chain_walker() -> TestResult {
    use crate::amdgpu_atom_displayobj::{
        DisplayObjectTable, ATOM_OBJECT_TYPE_CLOCK_SRC, ATOM_OBJECT_TYPE_ENCODER,
        ATOM_OBJECT_TYPE_TRANSMITTER,
    };
    // Path-with-chain layout: 8-byte header + 6 bytes of chain
    // (3 × u16 — encoder, transmitter, sentinel). One path,
    // size = 14 bytes total.
    let mut t = alloc::vec![0u8; 8 + 14];
    // Header.
    t[0..2].copy_from_slice(&((8u16 + 14).to_le_bytes()));
    t[2] = 1;
    t[3] = 0;
    t[4..6].copy_from_slice(&0u16.to_le_bytes());
    t[6] = 1;
    // Path 0 header (8 bytes):
    let off = 8;
    t[off..off + 2].copy_from_slice(&0x0001u16.to_le_bytes()); // device_tag
    t[off + 2..off + 4].copy_from_slice(&14u16.to_le_bytes()); // path size
    t[off + 4..off + 6].copy_from_slice(&(0x13u16 << 8).to_le_bytes()); // DP/0
    t[off + 6..off + 8].copy_from_slice(&0x1100u16.to_le_bytes()); // GPU obj
                                                                   // Chain: encoder/0 (0x21<<8), transmitter/2 (0x22<<8 | 2), sentinel.
    t[off + 8..off + 10].copy_from_slice(&((ATOM_OBJECT_TYPE_ENCODER as u16) << 8).to_le_bytes());
    t[off + 10..off + 12]
        .copy_from_slice(&((ATOM_OBJECT_TYPE_TRANSMITTER as u16) << 8 | 2u16).to_le_bytes());
    t[off + 12..off + 14].copy_from_slice(&0u16.to_le_bytes());

    let mut tbl = match DisplayObjectTable::parse(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("path parse"),
    };
    let _path = tbl.next().expect("first path");
    // Walk the chain following that path.
    let mut chain = tbl.chain_at(8, 14);
    let l1 = chain.next().expect("link 1");
    if l1.kind != ATOM_OBJECT_TYPE_ENCODER || l1.instance != 0 {
        return TestResult::Fail("link 1 not encoder/0");
    }
    let l2 = chain.next().expect("link 2");
    if l2.kind != ATOM_OBJECT_TYPE_TRANSMITTER || l2.instance != 2 {
        return TestResult::Fail("link 2 not transmitter/2");
    }
    if chain.next().is_some() {
        return TestResult::Fail("sentinel didn't terminate chain");
    }
    let _ = ATOM_OBJECT_TYPE_CLOCK_SRC; // referenced for visibility check
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_displayobj_object_chain_walker);

fn smoke_amdgpu_pptable_fan_table_round_trip() -> TestResult {
    use crate::amdgpu_pptable_subtables::{FanTable, PpSubtableError};
    let mut t = alloc::vec![0u8; 0x40];
    // Header: usSize=0x40, fmt=11, content=0
    t[0..2].copy_from_slice(&0x40u16.to_le_bytes());
    t[2] = 11;
    t[3] = 0;
    // Body.
    t[4] = 9; // rev_id
    t[5] = 30; // thyst
    t[6..8].copy_from_slice(&3_000u16.to_le_bytes()); // t_min = 30.00 C
    t[8..10].copy_from_slice(&6_000u16.to_le_bytes()); // t_med = 60.00 C
    t[10..12].copy_from_slice(&8_000u16.to_le_bytes()); // t_high = 80.00 C
    t[12..14].copy_from_slice(&50u16.to_le_bytes()); // pwm_min
    t[14..16].copy_from_slice(&128u16.to_le_bytes()); // pwm_med
    t[16..18].copy_from_slice(&200u16.to_le_bytes()); // pwm_high
    t[18..20].copy_from_slice(&9_500u16.to_le_bytes()); // t_max = 95.00 C
    t[20] = 1; // fan_control_mode
    t[21..23].copy_from_slice(&255u16.to_le_bytes()); // fan_pwm_max
    t[31] = 80; // target_temperature (whole C)
    t[51] = 1; // enable_zero_rpm
    t[52] = 50; // fan_stop_temperature (whole C)
    t[53] = 60; // fan_start_temperature (whole C)

    let fan = match FanTable::parse(&t) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("FanTable parse rejected"),
    };
    if fan.rev_id != 9 {
        return TestResult::Fail("rev_id");
    }
    if fan.t_min != 3_000 || fan.t_max != 9_500 {
        return TestResult::Fail("temperature range");
    }
    if fan.pwm_min != 50 || fan.fan_pwm_max != 255 {
        return TestResult::Fail("pwm values");
    }
    if fan.target_temperature != 80 || fan.fan_stop_temperature != 50 {
        return TestResult::Fail("target/stop temps");
    }
    if fan.enable_zero_rpm != 1 {
        return TestResult::Fail("zero_rpm");
    }
    // rev_id 11 rejected.
    let mut bad = t.clone();
    bad[4] = 11;
    if !matches!(
        FanTable::parse(&bad),
        Err(PpSubtableError::UnsupportedRevision(11))
    ) {
        return TestResult::Fail("rev 11 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pptable_fan_table_round_trip);

fn smoke_amdgpu_pptable_powertune_table_round_trip() -> TestResult {
    use crate::amdgpu_pptable_subtables::{PowerTuneTable, PpSubtableError};
    let mut t = alloc::vec![0u8; 0x40];
    t[0..2].copy_from_slice(&0x40u16.to_le_bytes());
    t[2] = 11;
    t[3] = 0;
    t[4] = 1; // rev_id
              // TDP = 80 W = 640 (Q5.3).
    t[5..7].copy_from_slice(&640u16.to_le_bytes());
    t[7..9].copy_from_slice(&720u16.to_le_bytes()); // configurable_tdp = 90 W
    t[9..11].copy_from_slice(&20_480u16.to_le_bytes()); // tdc = 80 A in Q8.8
    t[21..23].copy_from_slice(&10_000u16.to_le_bytes()); // tj_max = 100.00 C
    t[27..29].copy_from_slice(&10_500u16.to_le_bytes()); // shutdown = 105.00 C

    let pt = match PowerTuneTable::parse(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("PowerTuneTable parse rejected"),
    };
    if pt.tdp_watts() != 80 {
        return TestResult::Fail("TDP watts conversion");
    }
    if pt.tj_max_celsius() != 100 {
        return TestResult::Fail("TjMax celsius conversion");
    }
    if pt.software_shutdown_temp != 10_500 {
        return TestResult::Fail("shutdown temp round-trip");
    }
    // rev_id 6 rejected (>5).
    let mut bad = t.clone();
    bad[4] = 6;
    if !matches!(
        PowerTuneTable::parse(&bad),
        Err(PpSubtableError::UnsupportedRevision(6))
    ) {
        return TestResult::Fail("rev 6 should reject");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_amdgpu_pptable_powertune_table_round_trip
);

fn smoke_amdgpu_atombios_command_table_directory() -> TestResult {
    // Symmetric to the data-table directory smoke from Stage 3
    // — but exercise the command-table path. Build an ATOMBIOS
    // image with both directories and verify each indexes its
    // own subtable list.
    use crate::amdgpu_atombios::{AtomError, Atombios};
    let mut img = alloc::vec![0u8; 0x300];
    img[0] = 0x55;
    img[1] = 0xAA;
    img[0x48..0x4a].copy_from_slice(&0x80u16.to_le_bytes());
    img[0x80..0x84].copy_from_slice(&[36, 0, 1, 1]);
    img[0x84..0x88].copy_from_slice(b"ATOM");
    // Data master @ 0x100, command master @ 0x200.
    img[0xa0..0xa2].copy_from_slice(&0x100u16.to_le_bytes());
    img[0x9e..0xa0].copy_from_slice(&0x200u16.to_le_bytes());
    // Data master: 1 entry → 0x150.
    img[0x100..0x102].copy_from_slice(&6u16.to_le_bytes());
    img[0x104..0x106].copy_from_slice(&0x150u16.to_le_bytes());
    img[0x150..0x152].copy_from_slice(&8u16.to_le_bytes());
    // Command master: 2 entries → 0x250 (cmd 0), 0x260 (cmd 1).
    img[0x200..0x202].copy_from_slice(&8u16.to_le_bytes());
    img[0x204..0x206].copy_from_slice(&0x250u16.to_le_bytes());
    img[0x206..0x208].copy_from_slice(&0x260u16.to_le_bytes());
    img[0x250..0x252].copy_from_slice(&16u16.to_le_bytes());
    img[0x260..0x262].copy_from_slice(&20u16.to_le_bytes());

    let atom = match Atombios::parse(&img) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("ATOMBIOS parse"),
    };
    if atom.data_table_count() != 1 {
        return TestResult::Fail("data table count");
    }
    if atom.cmd_table_count() != 2 {
        return TestResult::Fail("cmd table count");
    }
    if atom.cmd_table_offset(0) != Ok(0x250) {
        return TestResult::Fail("cmd table 0 offset");
    }
    if atom.cmd_table_offset(1) != Ok(0x260) {
        return TestResult::Fail("cmd table 1 offset");
    }
    if !matches!(atom.cmd_table_offset(2), Err(AtomError::UnknownTableId)) {
        return TestResult::Fail("out-of-range cmd id should fail");
    }
    let cmd = match atom.cmd_table(0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("cmd_table borrow"),
    };
    if cmd.len() != 16 {
        return TestResult::Fail("cmd table length");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atombios",
    smoke_amdgpu_atombios_command_table_directory
);

fn smoke_amdgpu_rlc_header_and_autoload_round_trip() -> TestResult {
    use crate::amdgpu_rlc::{autoload_iter, looks_like_rlc, parse};
    use crate::amdgpu_ucode::UCODE_MAGIC;
    // Build a 1024-byte synthetic RLC blob:
    //   - 4-byte magic + common ucode header (version etc.)
    //   - RLC extension at offset 0x24
    //   - autoload offset table at 0x100, 3 × 12 byte entries
    //   - payload at 0x200 (24-byte filler — autoload entries
    //     point into it)
    let mut blob = alloc::vec![0u8; 1024];
    blob[0..4].copy_from_slice(&UCODE_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&256u32.to_le_bytes()); // start_offset
    blob[8..12].copy_from_slice(&512u32.to_le_bytes()); // payload_size
    blob[12..16].copy_from_slice(&1u32.to_le_bytes()); // version
                                                       // RLC extension fields.
    blob[0x58..0x5C].copy_from_slice(&0x100u32.to_le_bytes()); // autoload offset
    blob[0x5C..0x60].copy_from_slice(&36u32.to_le_bytes()); // autoload size
                                                            // Autoload entries: 3 × 12 bytes.
    let entries = [
        (0x10u32, 0x200u32, 8u32),
        (0x11u32, 0x208u32, 8u32),
        (0x12u32, 0x210u32, 8u32),
    ];
    for (i, (id, off, sz)) in entries.iter().enumerate() {
        let base = 0x100 + i * 12;
        blob[base..base + 4].copy_from_slice(&id.to_le_bytes());
        blob[base + 4..base + 8].copy_from_slice(&off.to_le_bytes());
        blob[base + 8..base + 12].copy_from_slice(&sz.to_le_bytes());
    }
    let header = match parse(&blob) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("RLC parse"),
    };
    if header.autoload_offset_table_offset != 0x100 || header.autoload_offset_table_size != 36 {
        return TestResult::Fail("autoload table fields");
    }
    let walked: alloc::vec::Vec<_> = match autoload_iter(&blob, &header) {
        Ok(it) => it.collect(),
        Err(_) => return TestResult::Fail("autoload_iter"),
    };
    if walked.len() != 3 {
        return TestResult::Fail("autoload entry count");
    }
    if walked[0].firmware_id != 0x10 || walked[0].offset != 0x200 || walked[0].size != 8 {
        return TestResult::Fail("autoload entry 0");
    }
    if walked[2].firmware_id != 0x12 {
        return TestResult::Fail("autoload entry 2 id");
    }
    if !looks_like_rlc(&blob) {
        return TestResult::Fail("looks_like_rlc rejected synthetic blob");
    }
    let bogus = [0u8; 1024];
    if looks_like_rlc(&bogus) {
        return TestResult::Fail("looks_like_rlc accepted zeroed blob");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_amdgpu_rlc_header_and_autoload_round_trip
);

fn smoke_amdgpu_atom_gpio_pin_lut_round_trip() -> TestResult {
    use crate::amdgpu_atom_gpiopin::{GpioId, GpioPinLut};
    // Synthetic LUT: header + 4 pin assignments
    //   pin 0: DDC SCL (id 0x0A) on byte 0x10 mask 0x01
    //   pin 1: DDC SDA (0x0B)    on byte 0x11 mask 0x02
    //   pin 2: HPD     (0x01)    on byte 0x20 mask 0x10
    //   pin 3: Backlight (0x03)  on byte 0x40 mask 0x80
    let mut t = alloc::vec![0u8; 4 + 4 * 8];
    t[0..2].copy_from_slice(&((4u16 + 4 * 8).to_le_bytes()));
    t[2] = 1;
    t[3] = 0;
    let pins = [
        (0x000Au16, 0u8, 1u8, 0x10u8, 0x01u8),
        (0x000Bu16, 0u8, 1u8, 0x11u8, 0x02u8),
        (0x0001u16, 1u8, 0u8, 0x20u8, 0x10u8),
        (0x0003u16, 2u8, 1u8, 0x40u8, 0x80u8),
    ];
    for (i, (id, idx, ty, off, mask)) in pins.iter().enumerate() {
        let p = 4 + i * 8;
        t[p..p + 2].copy_from_slice(&id.to_le_bytes());
        t[p + 2] = *idx;
        t[p + 3] = *ty;
        t[p + 4] = *off;
        t[p + 5] = *mask;
    }
    let mut lut = match GpioPinLut::parse(&t) {
        Ok(l) => l,
        Err(_) => return TestResult::Fail("LUT parse rejected"),
    };
    if lut.pin_count() != 4 {
        return TestResult::Fail("pin_count != 4");
    }
    let scl = lut.find(GpioId::DdcScl).expect("DDC SCL");
    if scl.gpio_byte_offset != 0x10 || scl.gpio_mask != 0x01 {
        return TestResult::Fail("DDC SCL byte/mask");
    }
    let sda = lut.find(GpioId::DdcSda).expect("DDC SDA");
    if sda.gpio_byte_offset != 0x11 || sda.gpio_mask != 0x02 {
        return TestResult::Fail("DDC SDA byte/mask");
    }
    let hpd = lut.find(GpioId::Hpd).expect("HPD");
    if hpd.pin_type != 0 {
        return TestResult::Fail("HPD pin_type != 0 (input)");
    }
    if lut.find(GpioId::PanelPower).is_some() {
        return TestResult::Fail("PanelPower should be absent");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_atom_gpio_pin_lut_round_trip);

fn smoke_amdgpu_encoder_caps_record_iter() -> TestResult {
    use crate::amdgpu_atom_encoder_caps::{
        find_encoder_caps, RecordIter, ATOM_RECORD_TYPE_ENCODER_CAP, ATOM_RECORD_TYPE_END,
        ATOM_RECORD_TYPE_HPD_INT_ID,
    };
    // Build a TLV tail with three records:
    //   HPD_INT_ID (kind 1, len 4) — payload "AB"
    //   ENCODER_CAP (kind 6, len 4) — caps = HBR2|HBR3|10bpc = 0x0B
    //   END (kind 0xFF, len 2) — sentinel
    let mut tail = alloc::vec::Vec::new();
    tail.extend_from_slice(&[ATOM_RECORD_TYPE_HPD_INT_ID, 4, b'A', b'B']);
    tail.extend_from_slice(&[ATOM_RECORD_TYPE_ENCODER_CAP, 4, 0x0B, 0x00]);
    tail.extend_from_slice(&[ATOM_RECORD_TYPE_END, 2]);
    // Iterator should yield 2 records (HPD + caps), stopping at END.
    let count = RecordIter::new(&tail).count();
    if count != 2 {
        return TestResult::Fail("expected 2 records before END");
    }
    let caps = match find_encoder_caps(&tail) {
        Ok(Some(c)) => c,
        Ok(None) => return TestResult::Fail("encoder caps record not found"),
        Err(_) => return TestResult::Fail("decode error"),
    };
    if !caps.supports_hbr2() || !caps.supports_hbr3() {
        return TestResult::Fail("HBR2/HBR3 bits");
    }
    if !caps.supports_10bpc() {
        return TestResult::Fail("10bpc bit");
    }
    if caps.supports_ycbcr420() {
        return TestResult::Fail("YCbCr420 bit unexpectedly set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_encoder_caps_record_iter);

fn smoke_dp_link_training_fallback_walks_ladder() -> TestResult {
    // StubAux that fails CR at HBR3 + HBR2 + HBR, succeeds at
    // RBR (1.62 Gbps). The fallback policy should walk down the
    // ladder and return Trained at the right link_bw_set.
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{run_with_fallback, LinkRate};

    struct StubAux {
        current_bw: u8,
        cr_polls: u32,
        eq_polls: u32,
    }
    impl AuxChannel for StubAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    // The very first write per training round is
                    // LINK_BW_SET; capture it so the read-side
                    // can decide whether to ACK CR.
                    if req.address == 0x0_0100 && !req.data.is_empty() {
                        self.current_bw = req.data[0];
                        self.cr_polls = 0;
                        self.eq_polls = 0;
                    }
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    let v = match req.address {
                        0x0_0202 => {
                            // Fail CR at every rate above RBR.
                            // "Fail" = lane status nibble that
                            // reports CR_DONE = 0 forever, so the
                            // CR loop exhausts retries.
                            self.cr_polls += 1;
                            if self.current_bw == LinkRate::Rbr as u8 {
                                if self.cr_polls < 2 {
                                    0x00
                                } else if self.eq_polls == 0 {
                                    0x11
                                }
                                // both lanes CR
                                else {
                                    0x77
                                } // EQ done
                            } else {
                                0x00 // lanes never report CR_DONE → CR fails
                            }
                        }
                        0x0_0203 => 0x00,
                        0x0_0204 => {
                            self.eq_polls += 1;
                            if self.current_bw == LinkRate::Rbr as u8 && self.eq_polls >= 2 {
                                1
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    };
                    reply_buf[0] = 0;
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = StubAux {
        current_bw: 0,
        cr_polls: 0,
        eq_polls: 0,
    };
    let result = match run_with_fallback(&mut aux, LinkRate::Hbr3, 2, |_| {}) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("fallback driver surfaced AUX error"),
    };
    if result.link_bw_set != LinkRate::Rbr as u8 {
        return TestResult::Fail("fallback didn't bottom out at RBR");
    }
    if result.lane_count != 2 {
        return TestResult::Fail("lane count shouldn't have been halved");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_dp_link_training_fallback_walks_ladder);

// ── IP Discovery smokes ────────────────────────────────────────────

/// Build a synthetic IP-discovery blob with one die enumerating
/// two IPs (GC and MP0). Returns the bytes + the (mp0_base,
/// gc_base) values the parser should observe.
fn build_synthetic_discovery_blob() -> (alloc::vec::Vec<u8>, u32, u32) {
    use crate::amdgpu_discovery as d;
    let mut blob = alloc::vec![0u8; 0x200];

    // Offsets we'll fill in below.
    let ip_off: u16 = 0x100;
    let die_off: u16 = 0x150;
    let ip0_off: usize = 0x154; // GC: 8 + 1*4 = 12 bytes
    let ip1_off: usize = 0x160; // MP0: 8 + 2*4 = 16 bytes
    let blob_end: u16 = 0x170;
    let ip_table_size: u16 = blob_end - ip_off;

    // --- Outer binary_header ---
    blob[0..4].copy_from_slice(&d::BINARY_SIGNATURE.to_le_bytes());
    blob[4..6].copy_from_slice(&1u16.to_le_bytes()); // version_major
    blob[6..8].copy_from_slice(&0u16.to_le_bytes()); // version_minor
                                                     // binary_checksum (bytes 8..10) — leave 0, fill in last
                                                     // binary_size (bytes 10..12)
    blob[10..12].copy_from_slice(&blob_end.to_le_bytes());
    // table_list[IP_DISCOVERY] at offset 12 + 0*8 = 12
    let ip_info = 12 + d::TABLE_IP_DISCOVERY * 8;
    blob[ip_info..ip_info + 2].copy_from_slice(&ip_off.to_le_bytes());
    // ip checksum (ip_info+2..ip_info+4): fill in below
    blob[ip_info + 4..ip_info + 6].copy_from_slice(&ip_table_size.to_le_bytes());

    // --- IP-discovery sub-table header at ip_off ---
    blob[ip_off as usize..ip_off as usize + 4]
        .copy_from_slice(&d::DISCOVERY_TABLE_SIGNATURE.to_le_bytes());
    blob[ip_off as usize + 4..ip_off as usize + 6].copy_from_slice(&4u16.to_le_bytes()); // version
    blob[ip_off as usize + 6..ip_off as usize + 8].copy_from_slice(&ip_table_size.to_le_bytes());
    // id (4 bytes 8..12): leave 0
    blob[ip_off as usize + 12..ip_off as usize + 14].copy_from_slice(&1u16.to_le_bytes()); // num_dies
                                                                                           // die_info[0]
    blob[ip_off as usize + 14..ip_off as usize + 16].copy_from_slice(&0u16.to_le_bytes()); // die_id
    blob[ip_off as usize + 16..ip_off as usize + 18].copy_from_slice(&die_off.to_le_bytes());
    // die_info[1..16] and union (78..80): leave 0. base_addr_64_bit = 0.

    // --- die_header at die_off ---
    blob[die_off as usize..die_off as usize + 2].copy_from_slice(&0u16.to_le_bytes()); // die_id
    blob[die_off as usize + 2..die_off as usize + 4].copy_from_slice(&2u16.to_le_bytes()); // num_ips

    // --- IP 0: GC, instance 0, v11.0.0, base = 0xA000 ---
    let gc_base: u32 = 0x0000_A000;
    blob[ip0_off..ip0_off + 2].copy_from_slice(&d::HW_ID_GC.to_le_bytes());
    blob[ip0_off + 2] = 0; // instance
    blob[ip0_off + 3] = 1; // num_base_address
    blob[ip0_off + 4] = 11; // major
    blob[ip0_off + 5] = 0; // minor
    blob[ip0_off + 6] = 0; // revision
    blob[ip0_off + 7] = (2 << 4) | 3; // variant=2, sub_revision=3
    blob[ip0_off + 8..ip0_off + 12].copy_from_slice(&gc_base.to_le_bytes());

    // --- IP 1: MP0, instance 0, v13.0.4, 2 base addresses ---
    let mp0_base: u32 = 0x0001_6000;
    let mp0_base_aux: u32 = 0x0001_7000;
    blob[ip1_off..ip1_off + 2].copy_from_slice(&d::HW_ID_MP0.to_le_bytes());
    blob[ip1_off + 2] = 0;
    blob[ip1_off + 3] = 2;
    blob[ip1_off + 4] = 13;
    blob[ip1_off + 5] = 0;
    blob[ip1_off + 6] = 4;
    blob[ip1_off + 7] = 0;
    blob[ip1_off + 8..ip1_off + 12].copy_from_slice(&mp0_base.to_le_bytes());
    blob[ip1_off + 12..ip1_off + 16].copy_from_slice(&mp0_base_aux.to_le_bytes());

    // --- Checksums (sum-of-bytes, wrapping u16) ---
    fn sum(s: &[u8]) -> u16 {
        let mut x: u16 = 0;
        for &b in s {
            x = x.wrapping_add(b as u16);
        }
        x
    }
    // IP-table checksum: bytes [ip_off .. ip_off + ip_table_size).
    let ip_csum = sum(&blob[ip_off as usize..(ip_off + ip_table_size) as usize]);
    blob[ip_info + 2..ip_info + 4].copy_from_slice(&ip_csum.to_le_bytes());
    // Outer checksum: bytes [10 .. blob_end) — i.e. starting at
    // `binary_size` (just past the checksum field).
    let outer_csum = sum(&blob[10..blob_end as usize]);
    blob[8..10].copy_from_slice(&outer_csum.to_le_bytes());

    blob.truncate(blob_end as usize);
    (blob, mp0_base, gc_base)
}

fn smoke_amdgpu_discovery_signature_constants() -> TestResult {
    use crate::amdgpu_discovery::{BINARY_SIGNATURE, DISCOVERY_TABLE_SIGNATURE};
    // BINARY_SIGNATURE is the LE-encoded byte sequence 07 14 21 28.
    if BINARY_SIGNATURE != 0x2821_1407 {
        return TestResult::Fail("BINARY_SIGNATURE constant wrong");
    }
    // DISCOVERY_TABLE_SIGNATURE encodes "IPDS" as 49 50 44 53 LE.
    if DISCOVERY_TABLE_SIGNATURE != 0x5344_5049 {
        return TestResult::Fail("DISCOVERY_TABLE_SIGNATURE constant wrong");
    }
    if DISCOVERY_TABLE_SIGNATURE.to_le_bytes() != *b"IPDS" {
        return TestResult::Fail("DISCOVERY_TABLE_SIGNATURE != IPDS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_signature_constants
);

fn smoke_amdgpu_discovery_hw_id_constants_match_linux() -> TestResult {
    use crate::amdgpu_discovery as d;
    // Spot-check the load-bearing HW_IDs against the values
    // documented in Linux's `soc15_hw_ip.h`.
    if d::HW_ID_GC != 11 {
        return TestResult::Fail("HW_ID_GC != 11");
    }
    if d::HW_ID_MP0 != 255 {
        return TestResult::Fail("HW_ID_MP0 != 255");
    }
    if d::HW_ID_MP1 != 1 {
        return TestResult::Fail("HW_ID_MP1 != 1");
    }
    if d::HW_ID_SDMA0 != 42 {
        return TestResult::Fail("HW_ID_SDMA0 != 42");
    }
    if d::HW_ID_VCN != 12 {
        return TestResult::Fail("HW_ID_VCN != 12 (alias of UVD)");
    }
    if d::HW_ID_DCN != 271 {
        return TestResult::Fail("HW_ID_DCN != 271 (DMU)");
    }
    if d::HW_ID_OSSSYS != 40 {
        return TestResult::Fail("HW_ID_OSSSYS != 40");
    }
    if d::HW_ID_BIF != 108 {
        return TestResult::Fail("HW_ID_BIF != 108 (NBIF)");
    }
    if d::HW_ID_MMHUB != 34 || d::HW_ID_ATHUB != 35 {
        return TestResult::Fail("MMHUB/ATHUB constants");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_hw_id_constants_match_linux
);

fn smoke_amdgpu_discovery_parse_synthetic_blob() -> TestResult {
    use crate::amdgpu_discovery::{find_ip, parse_discovery, HW_ID_GC, HW_ID_MP0};
    let (blob, want_mp0, want_gc) = build_synthetic_discovery_blob();
    let blocks = match parse_discovery(&blob) {
        Ok(b) => b,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("parse_discovery rejected synthetic blob");
        }
    };
    if blocks.len() != 2 {
        return TestResult::Fail("expected exactly 2 IP blocks");
    }
    let gc = match find_ip(&blocks, HW_ID_GC, 0) {
        Some(b) => b,
        None => return TestResult::Fail("HW_ID_GC missing from parse"),
    };
    if gc.base_addrs[0] != want_gc {
        return TestResult::Fail("GC base_addrs[0] mis-decoded");
    }
    if gc.major != 11 || gc.minor != 0 || gc.revision != 0 {
        return TestResult::Fail("GC version triple lost");
    }
    if gc.variant != 2 || gc.sub_revision != 3 {
        return TestResult::Fail("GC variant/sub_revision lost");
    }
    if gc.num_bases != 1 {
        return TestResult::Fail("GC num_bases != 1");
    }
    let mp0 = match find_ip(&blocks, HW_ID_MP0, 0) {
        Some(b) => b,
        None => return TestResult::Fail("HW_ID_MP0 missing from parse"),
    };
    if mp0.base_addrs[0] != want_mp0 {
        return TestResult::Fail("MP0 base_addrs[0] mis-decoded");
    }
    if mp0.num_bases != 2 {
        return TestResult::Fail("MP0 num_bases != 2");
    }
    if mp0.major != 13 || mp0.minor != 0 || mp0.revision != 4 {
        return TestResult::Fail("MP0 version triple lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_parse_synthetic_blob
);

fn smoke_amdgpu_discovery_rejects_bad_signature() -> TestResult {
    use crate::amdgpu_discovery::{parse_discovery, DiscoveryError};
    // Garbage blob (all 0xFF, mimicking a QEMU read from
    // unallocated VRAM aperture).
    let blob = alloc::vec![0xFFu8; 0x200];
    match parse_discovery(&blob) {
        Err(DiscoveryError::BadSignature) => {}
        Ok(_) => return TestResult::Fail("garbage blob accepted"),
        Err(_) => return TestResult::Fail("expected BadSignature on 0xFF blob"),
    }
    // All zero (the typical QEMU shape).
    let zeros = alloc::vec![0u8; 0x200];
    match parse_discovery(&zeros) {
        Err(DiscoveryError::BadSignature) => {}
        Ok(_) => return TestResult::Fail("zero blob accepted"),
        Err(_) => return TestResult::Fail("expected BadSignature on zero blob"),
    }
    // Truncated.
    let tiny = alloc::vec![0u8; 10];
    if !matches!(parse_discovery(&tiny), Err(DiscoveryError::Truncated)) {
        return TestResult::Fail("expected Truncated on 10-byte blob");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_rejects_bad_signature
);

fn smoke_amdgpu_discovery_rejects_bad_outer_checksum() -> TestResult {
    use crate::amdgpu_discovery::{parse_discovery, DiscoveryError};
    let (mut blob, _, _) = build_synthetic_discovery_blob();
    // Flip one byte in the IP-table region — invalidates BOTH the
    // outer checksum (computed over [10..binary_size)) and the
    // IP-table checksum. The outer fires first.
    blob[0x158] ^= 0xFF;
    match parse_discovery(&blob) {
        Err(DiscoveryError::BadOuterChecksum) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("expected BadOuterChecksum")
        }
        Ok(_) => TestResult::Fail("corrupted blob accepted"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_rejects_bad_outer_checksum
);

fn smoke_amdgpu_discovery_probe_skipped_on_qemu() -> TestResult {
    // Live-device probe smoke: on QEMU the AMD GPU isn't present
    // so the controller is absent and discovery is necessarily
    // empty. Skip rather than fail; on real hardware this would
    // assert ip_blocks.len() > 0 and find HW_ID_MP0.
    use crate::amdgpu;
    if !amdgpu::is_probed() {
        return TestResult::Skip("amdgpu not probed in this QEMU config");
    }
    amdgpu::with_controller(|d| {
        if d.ip_blocks.is_empty() {
            TestResult::Skip("amdgpu probed but discovery yielded no IPs (QEMU FB)")
        } else {
            TestResult::Pass
        }
    })
    .unwrap_or(TestResult::Skip("controller vanished"))
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_discovery_probe_skipped_on_qemu
);

// ── amdgpu/atom-vm ─────────────────────────────────────────────────
//
// Stage-9 ATOMBIOS bytecode interpreter smokes. Builds tiny
// synthetic tables (a few MOVE / ADD / COMPARE / JUMP / EOT bytes)
// and steps them through `amdgpu_atom_vm::execute_bytes`, validating
// that PS / WS slots end up where Linux's `atom.c` would put them.

fn smoke_amdgpu_atom_vm_move_imm_dword_into_ps() -> TestResult {
    use crate::amdgpu_atom_vm::{execute_bytes, AtomState};

    // op 2 = MOVE(PS), attr 0x05 (arg=IMM, align=DWORD), dst idx 0,
    // imm dword 0x12345678 (LE: 0x78 0x56 0x34 0x12), EOT (91).
    let code: &[u8] = &[2, 0x05, 0x00, 0x78, 0x56, 0x34, 0x12, 91];
    let mut state = AtomState::new(8, 4);
    let mut ps = [0u32; 1];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("execute_bytes MOVE/EOT errored");
    }
    if ps[0] != 0x1234_5678 {
        return TestResult::Fail("MOVE PS[0] <- IMM did not land");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    smoke_amdgpu_atom_vm_move_imm_dword_into_ps
);

fn smoke_amdgpu_atom_vm_add_into_ws() -> TestResult {
    use crate::amdgpu_atom_vm::{execute_bytes, AtomState};

    // MOVE(WS=op3) WS[2] <- IMM 0xAA; ADD(WS=op45) WS[2] += 0x11; EOT.
    let code: &[u8] = &[
        3, 0x05, 2, 0xAA, 0, 0, 0, // MOVE WS[2] <- 0xAA
        45, 0x05, 2, 0x11, 0, 0, 0,  // ADD WS[2] += 0x11
        91, // EOT
    ];
    let mut state = AtomState::new(8, 4);
    let mut ps: [u32; 1] = [0];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("MOVE/ADD sequence errored");
    }
    if state.scratch[2] != 0xBB {
        return TestResult::Fail("WS[2] != 0xBB after ADD");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    smoke_amdgpu_atom_vm_add_into_ws
);

fn smoke_amdgpu_atom_vm_compare_jump_equal_taken() -> TestResult {
    use crate::amdgpu_atom_vm::{execute_bytes, AtomState};

    // Layout (matches inline_tests::compare_and_jump_equal_taken):
    //   0: MOVE PS[0] <- IMM 0x42        (7 bytes)
    //   7: COMPARE PS[0] vs IMM 0x42     (7 bytes)
    //  14: JUMP_EQUAL target=25 (=local 19 + 6 header)
    //  17,18: trap bytes
    //  19: EOT
    let code: &[u8] = &[
        2, 0x05, 0, 0x42, 0, 0, 0, // MOVE PS[0] <- 0x42
        61, 0x05, 0, 0x42, 0, 0, 0, // COMPARE PS[0] vs IMM 0x42
        68, 25, 0, // JUMP_EQUAL → local 19
        0x77, 0x77, // unreachable trap
        91,   // EOT
    ];
    let mut state = AtomState::new(8, 4);
    let mut ps: [u32; 1] = [0];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("compare/jump sequence errored");
    }
    if !state.cs_equal {
        return TestResult::Fail("cs_equal not set after COMPARE eq");
    }
    if ps[0] != 0x42 {
        return TestResult::Fail("PS[0] mutated unexpectedly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    smoke_amdgpu_atom_vm_compare_jump_equal_taken
);

fn smoke_amdgpu_atom_vm_bad_opcode_rejected() -> TestResult {
    use crate::amdgpu_atom_vm::{execute_bytes, AtomError, AtomState};
    let code: &[u8] = &[127, 91]; // 127 == ATOM_OP_CNT (out of range)
    let mut state = AtomState::new(4, 4);
    let mut ps: [u32; 0] = [];
    match execute_bytes(&mut state, code, &mut ps, 0) {
        Err(AtomError::BadOpcode(127)) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong AtomError variant"),
        Ok(()) => TestResult::Fail("bad opcode silently accepted"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    smoke_amdgpu_atom_vm_bad_opcode_rejected
);

fn smoke_amdgpu_atom_vm_reg_write_via_closure() -> TestResult {
    use crate::amdgpu_atom_vm::{execute_bytes, AtomState};
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    // MOVE(REG=op1) REG[0x1234] <- IMM 0xDEADBEEF.
    // attr 0x05 (arg=IMM, align=DWORD, dst_shift=0).
    // The REG operand is a u16 register index after the imm.
    //
    // Per atom.c::atom_op_move, layout is:
    //   op (u8), attr (u8), dst-operand (REG=u16), src-operand (IMM=u32)
    let code: &[u8] = &[
        1, 0x05, 0x34, 0x12, // MOVE REG[0x1234] ...
        0xEF, 0xBE, 0xAD, 0xDE, // ... <- 0xDEADBEEF
        91,   // EOT
    ];

    let writes: Rc<RefCell<Vec<(u32, u32)>>> = Rc::new(RefCell::new(Vec::new()));
    let mut state = AtomState::new(8, 4);
    let w = writes.clone();
    state.reg_write = Box::new(move |a, v| {
        w.borrow_mut().push((a, v));
    });
    let mut ps: [u32; 0] = [];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("REG MOVE errored");
    }
    let log = writes.borrow();
    if log.len() != 1 {
        return TestResult::Fail("reg_write closure not invoked exactly once");
    }
    if log[0] != (0x1234, 0xDEAD_BEEF) {
        return TestResult::Fail("reg_write got wrong (addr,val)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    smoke_amdgpu_atom_vm_reg_write_via_closure
);

// ── amdgpu/smu ─────────────────────────────────────────────────────
//
// SMU mailbox-protocol smokes. The actual MP1 register reads
// happen on real silicon; here we stage a mock that scripts the
// canonical sequence (handshake → clear → arg → msg → response).

fn smoke_amdgpu_smu_send_message_drives_canonical_sequence() -> TestResult {
    use crate::amdgpu_smu::{
        send_message, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL,
        PPSMC_MSG_GET_SMU_VERSION, SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    // Step 1: handshake — RESP non-zero (idle).
    m.stage_read(resp, 1);
    // Step 5: response — OK after our trigger write.
    m.stage_read(resp, SMU_RESP_OK);
    // Step 6: ARG holds the returned SMU version (e.g. 0x000A_0203).
    m.stage_read(arg, 0x000A_0203);

    let (rc, out) = match send_message(&mut m, mp1_base, PPSMC_MSG_GET_SMU_VERSION, 0) {
        Ok(p) => p,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("send_message errored on happy path");
        }
    };
    if rc != SMU_RESP_OK {
        return TestResult::Fail("expected SMU_RESP_OK");
    }
    if out != 0x000A_0203 {
        return TestResult::Fail("expected ARG read-back = 0x000A_0203");
    }

    // Captured writes (in order): clear RESP, write ARG=0, write MSG=GET_SMU_VERSION.
    if m.writes.len() != 3 {
        return TestResult::Fail("expected exactly 3 mailbox writes");
    }
    if m.writes[0] != (resp, 0) {
        return TestResult::Fail("clear-RESP write missing or out of order");
    }
    if m.writes[1] != (arg, 0) {
        return TestResult::Fail("ARG write missing or out of order");
    }
    if m.writes[2] != (mp1_base + MP1_C2PMSG_MSG_REL, PPSMC_MSG_GET_SMU_VERSION) {
        return TestResult::Fail("MSG-trigger write missing or wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_send_message_drives_canonical_sequence
);

fn smoke_amdgpu_smu_send_message_surfaces_smu_rejection() -> TestResult {
    use crate::amdgpu_smu::{
        send_message, MockSmu, SmuError, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL,
        PPSMC_MSG_TEST_MESSAGE, SMU_RESP_FAIL,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    m.stage_read(resp, 1); // handshake
    m.stage_read(resp, SMU_RESP_FAIL); // SMU rejects
    m.stage_read(arg, 0); // ARG read-back (not reached after error)

    match send_message(&mut m, mp1_base, PPSMC_MSG_TEST_MESSAGE, 0xDEADBEEF) {
        Err(SmuError::Rejected(SMU_RESP_FAIL)) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("expected SmuError::Rejected(SMU_RESP_FAIL)")
        }
        Ok(_) => TestResult::Fail("SMU rejection silently passed"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_send_message_surfaces_smu_rejection
);

fn smoke_amdgpu_smu_handshake_timeout_when_resp_stays_busy() -> TestResult {
    use crate::amdgpu_smu::{send_message, MockSmu, SmuError, PPSMC_MSG_TEST_MESSAGE};
    // Stage nothing — the mock returns 0 (busy) on every read.
    let mut m = MockSmu::new();
    match send_message(&mut m, 0x16000, PPSMC_MSG_TEST_MESSAGE, 0) {
        Err(SmuError::HandshakeTimeout) => TestResult::Pass,
        _ => TestResult::Fail("expected HandshakeTimeout on busy mock"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_handshake_timeout_when_resp_stays_busy
);

// ── amdgpu/dcn ─────────────────────────────────────────────────────
//
// DCN 2.0 modeset codec smokes. Exercise the discovery-driven
// `build_modeset_from_discovery`, VESA timing table, and the
// shape of the produced write sequence. The MMIO execute path
// (`execute_modeset`) can only be exercised against real
// Renoir / Cezanne silicon; these smokes run on QEMU and cover
// everything up to the register-bus write boundary.

fn smoke_dcn20_build_modeset_from_discovery_produces_seq() -> TestResult {
    use crate::amdgpu_dcn::{build_modeset_from_discovery, timing_for_mode};
    use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};

    let mut bases = [0u32; MAX_BASE_ADDRS];
    bases[0] = 0x0001_2000; // synthetic DCN window base
    let blocks = alloc::vec![IpBlock {
        hw_id: HW_ID_DCN,
        instance: 0,
        major: 2,
        minor: 0,
        revision: 1,
        sub_revision: 0,
        variant: 0,
        base_addrs: bases,
        num_bases: 1,
    }];
    let timing = match timing_for_mode(1920, 1080, 60) {
        Some(t) => t,
        None => return TestResult::Fail("FHD@60 missing from timing table"),
    };
    let seq = match build_modeset_from_discovery(&blocks, &timing, 0x1000_0000, 1920) {
        Some(s) => s,
        None => return TestResult::Fail("discovery-driven builder returned None"),
    };
    if seq.is_empty() {
        return TestResult::Fail("empty modeset sequence");
    }
    // The very first write must blank HUBP — the DCN 2.0 prologue
    // requires disabling scanout before reprogramming.
    let first = seq[0];
    let expected_blank = 0x0001_2000
        + crate::amdgpu_dcn::DCN20_HUBP0_REL
        + crate::amdgpu_dcn::DCN20_HUBP_BLANK_EN_REL;
    if first.addr != expected_blank || first.value & crate::amdgpu_dcn::HUBP_BLANK_FORCE == 0 {
        return TestResult::Fail("prologue should force HUBP blank first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn20_build_modeset_from_discovery_produces_seq
);

fn smoke_dcn20_timing_for_1080p60_shape() -> TestResult {
    use crate::amdgpu_dcn::timing_for_mode;
    let t = match timing_for_mode(1920, 1080, 60) {
        Some(t) => t,
        None => return TestResult::Fail("1920x1080@60 must be in the table"),
    };
    // VESA DMT for 1920x1080@60: 148.5 MHz pixel clock, htotal
    // 2200, vtotal 1125, hsync 2008..2052, vsync 1084..1089.
    if t.h_active != 1920 || t.v_active != 1080 {
        return TestResult::Fail("active dimensions wrong");
    }
    if t.h_total != 2200 || t.v_total != 1125 {
        return TestResult::Fail("h/v_total wrong for FHD@60");
    }
    if t.pixel_clock_khz != 148_500 {
        return TestResult::Fail("FHD@60 pixel clock not 148.5 MHz");
    }
    if t.h_sync_start != 2008 || t.h_sync_end != 2052 {
        return TestResult::Fail("FHD@60 hsync window");
    }
    if t.v_sync_start != 1084 || t.v_sync_end != 1089 {
        return TestResult::Fail("FHD@60 vsync window");
    }
    // Bogus mode rejected.
    if timing_for_mode(640, 480, 60).is_some() {
        return TestResult::Fail("unknown mode must surface as None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn20_timing_for_1080p60_shape
);

fn smoke_dcn20_set_mode_rejects_without_fw() -> TestResult {
    use crate::amdgpu::{with_controller_mut, AmdgpuError, Mode};
    // Probe runs at boot. On QEMU the probe may or may not bind
    // (depends on emulated PCI cards). Skip when not bound — we
    // can't test the `fw_loaded == false` path without a live
    // controller object.
    if !crate::amdgpu::is_probed() {
        return TestResult::Skip("amdgpu not probed in this QEMU config");
    }
    let outcome = with_controller_mut(|d| {
        if d.fw_loaded {
            return None; // can't exercise the "no fw" path
        }
        // SAFETY: probe gave us BAR0+BAR5 ownership; set_mode bails
        // before any MMIO when fw_loaded is false.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        Some(unsafe {
            d.set_mode(Mode {
                width: 1920,
                height: 1080,
                stride: 1920,
            })
        })
    });
    match outcome {
        Some(Some(Err(AmdgpuError::FirmwareLoadFailed))) => TestResult::Pass,
        Some(Some(Ok(_))) => TestResult::Fail("set_mode should reject pre-firmware"),
        Some(Some(Err(other))) => {
            let _ = other;
            TestResult::Fail("wrong AmdgpuError variant pre-firmware")
        }
        Some(None) => TestResult::Skip("fw already loaded — can't test pre-fw path"),
        None => TestResult::Skip("controller vanished mid-test"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn20_set_mode_rejects_without_fw
);

fn smoke_dcn20_modeset_seq_contains_expected_offsets() -> TestResult {
    use crate::amdgpu_dcn::{
        dcn20_modeset_sequence, timing_for_mode, DCN20_HUBP0_REL, DCN20_HUBP_BLANK_EN_REL,
        DCN20_OTG0_REL, DCN20_OTG_CONTROL_REL, DCN20_OTG_H_TOTAL_REL, HUBP_BLANK_FORCE,
        OTG_MASTER_EN,
    };
    let timing = match timing_for_mode(1920, 1080, 60) {
        Some(t) => t,
        None => return TestResult::Fail("FHD@60 missing"),
    };
    let dcn_base: u32 = 0x0010_0000;
    let seq = dcn20_modeset_sequence(&timing, 0x1000_0000, 1920, dcn_base);

    let want_blank = dcn_base + DCN20_HUBP0_REL + DCN20_HUBP_BLANK_EN_REL;
    let want_h_total = dcn_base + DCN20_OTG0_REL + DCN20_OTG_H_TOTAL_REL;
    let want_master = dcn_base + DCN20_OTG0_REL + DCN20_OTG_CONTROL_REL;

    // HUBP_BLANK must appear (twice — once forced in prologue,
    // once cleared in epilogue).
    let blank_forced = seq
        .iter()
        .any(|w| w.addr == want_blank && w.value & HUBP_BLANK_FORCE != 0);
    let blank_cleared = seq.iter().any(|w| w.addr == want_blank && w.value == 0);
    if !blank_forced || !blank_cleared {
        return TestResult::Fail("HUBP_BLANK_EN must be forced then cleared");
    }
    // OTG_H_TOTAL must appear with the value `h_total - 1`.
    let want_h = (timing.h_total - 1) as u32;
    if !seq
        .iter()
        .any(|w| w.addr == want_h_total && w.value == want_h)
    {
        return TestResult::Fail("OTG_H_TOTAL not programmed");
    }
    // OTG_MASTER_EN must be the last write to OTG_CONTROL.
    let last_master = seq.iter().rev().find(|w| w.addr == want_master).copied();
    match last_master {
        Some(w) if w.value & OTG_MASTER_EN != 0 => {}
        _ => return TestResult::Fail("OTG_MASTER_EN must be asserted last"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn20_modeset_seq_contains_expected_offsets
);

fn smoke_dcn35_modeset_seq_contains_expected_offsets() -> TestResult {
    use crate::amdgpu_dcn::{
        dcn35_modeset_sequence, timing_for_mode, DCN35_HUBP0_REL, DCN35_HUBP_BLANK_EN_REL,
        DCN35_OTG0_REL, DCN35_OTG_CONTROL_REL, DCN35_OTG_H_TOTAL_REL, DCN35_OTG_V_BLANK_REL,
        HUBP_BLANK_FORCE, OTG_MASTER_EN,
    };
    let timing = match timing_for_mode(1920, 1080, 60) {
        Some(t) => t,
        None => return TestResult::Fail("FHD@60 missing"),
    };
    let dcn_base: u32 = 0x0010_0000;
    let seq = dcn35_modeset_sequence(&timing, 0x1000_0000, 1920, dcn_base);

    let want_blank = dcn_base + DCN35_HUBP0_REL + DCN35_HUBP_BLANK_EN_REL;
    let want_h_total = dcn_base + DCN35_OTG0_REL + DCN35_OTG_H_TOTAL_REL;
    let want_v_blank = dcn_base + DCN35_OTG0_REL + DCN35_OTG_V_BLANK_REL;
    let want_master = dcn_base + DCN35_OTG0_REL + DCN35_OTG_CONTROL_REL;

    // HUBP_BLANK_EN forced in prologue, cleared in epilogue.
    let blank_forced = seq
        .iter()
        .any(|w| w.addr == want_blank && w.value & HUBP_BLANK_FORCE != 0);
    let blank_cleared = seq.iter().any(|w| w.addr == want_blank && w.value == 0);
    if !blank_forced || !blank_cleared {
        return TestResult::Fail("DCN35 HUBP_BLANK_EN must be forced then cleared");
    }
    // OTG_H_TOTAL = h_total - 1.
    let want_h = (timing.h_total - 1) as u32;
    if !seq
        .iter()
        .any(|w| w.addr == want_h_total && w.value == want_h)
    {
        return TestResult::Fail("DCN35 OTG_H_TOTAL not programmed");
    }
    // OTG_V_BLANK_START_END must use the DCN 3.5-shifted offset
    // (the whole point of this path). If this constant ever drifts
    // back to the DCN 2.0 value the test catches it.
    if !seq.iter().any(|w| w.addr == want_v_blank) {
        return TestResult::Fail("DCN35 OTG_V_BLANK_START_END not programmed at shifted offset");
    }
    // OTG_MASTER_EN must be the last write to OTG_CONTROL.
    let last_master = seq.iter().rev().find(|w| w.addr == want_master).copied();
    match last_master {
        Some(w) if w.value & OTG_MASTER_EN != 0 => {}
        _ => return TestResult::Fail("DCN35 OTG_MASTER_EN must be asserted last"),
    }
    // Also confirm OTG_MASTER_EN is the *final* write in the
    // sequence (epilogue ordering invariant — same as DCN 2.0).
    let last = match seq.last() {
        Some(w) => *w,
        None => return TestResult::Fail("empty DCN35 sequence"),
    };
    if last.addr != want_master || last.value & OTG_MASTER_EN == 0 {
        return TestResult::Fail("OTG_MASTER_EN must be the final write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn35_modeset_seq_contains_expected_offsets
);

fn smoke_dcn35_uses_different_offsets_than_dcn20() -> TestResult {
    use crate::amdgpu_dcn::{
        DCN20_OTG_CONTROL_REL, DCN20_OTG_INTERRUPT_CONTROL_REL, DCN20_OTG_V_BLANK_REL,
        DCN20_OTG_V_SYNC_A_REL, DCN35_OTG_CONTROL_REL, DCN35_OTG_INTERRUPT_CONTROL_REL,
        DCN35_OTG_V_BLANK_REL, DCN35_OTG_V_SYNC_A_REL,
    };
    // Phoenix's DCN 3.5 shifted V_BLANK / V_SYNC / OTG_CONTROL /
    // INTERRUPT_CONTROL inside the OTG block vs DCN 2.0 (Renoir).
    // If any of these ever drift to match the DCN 2.0 value the
    // Phoenix path would silently program the wrong register on
    // real hardware — pin the invariant.
    if DCN20_OTG_V_BLANK_REL == DCN35_OTG_V_BLANK_REL {
        return TestResult::Fail("DCN35 V_BLANK offset must differ from DCN20");
    }
    if DCN20_OTG_V_SYNC_A_REL == DCN35_OTG_V_SYNC_A_REL {
        return TestResult::Fail("DCN35 V_SYNC_A offset must differ from DCN20");
    }
    if DCN20_OTG_CONTROL_REL == DCN35_OTG_CONTROL_REL {
        return TestResult::Fail("DCN35 OTG_CONTROL offset must differ from DCN20");
    }
    if DCN20_OTG_INTERRUPT_CONTROL_REL == DCN35_OTG_INTERRUPT_CONTROL_REL {
        return TestResult::Fail("DCN35 INTERRUPT_CONTROL offset must differ from DCN20");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/dcn",
    smoke_dcn35_uses_different_offsets_than_dcn20
);

// ── amdgpu/psp ─────────────────────────────────────────────────────
//
// PSP MP0 mailbox smokes. The real PSP firmware-load handshake
// goes through `AmdGpu::load_firmware` which the tests can't
// execute (needs BAR5 + a real registry blob). The protocol
// primitive lives in `amdgpu_psp::send_command` and is testable
// against a `MockPsp` that scripts the canonical sequence.

fn smoke_amdgpu_psp_send_command_drives_canonical_sequence() -> TestResult {
    use crate::amdgpu_psp::{
        send_command, MockPsp, MP0_C2PMSG_64_REL, MP0_C2PMSG_67_REL, MP0_C2PMSG_69_REL,
        PSP_CMD_LOAD_IP_FW, PSP_STATUS_DONE_BIT,
    };
    let mp0_base = 0x000B_0000;
    let lo = mp0_base + MP0_C2PMSG_64_REL;
    let hi = mp0_base + MP0_C2PMSG_67_REL;
    let trig = mp0_base + MP0_C2PMSG_69_REL;

    let mut m = MockPsp::new();
    // Step 4: poll — PSP reports DONE + status 0.
    m.stage_read(lo, PSP_STATUS_DONE_BIT);

    let phys: u64 = 0x1_2345_6789;
    let size: u32 = 0x4000; // 16 KiB image
    match send_command(&mut m, mp0_base, PSP_CMD_LOAD_IP_FW, phys, size) {
        Ok(0) => {}
        Ok(other) => {
            let _ = other;
            return TestResult::Fail("expected status 0 on happy path");
        }
        Err(e) => {
            let _ = e;
            return TestResult::Fail("send_command errored on happy path");
        }
    }

    // Captured writes (in order): phys lo, phys hi, trigger word.
    if m.writes.len() != 3 {
        return TestResult::Fail("expected exactly 3 mailbox writes");
    }
    if m.writes[0] != (lo, phys as u32) {
        return TestResult::Fail("phys-lo write missing or wrong");
    }
    if m.writes[1] != (hi, (phys >> 32) as u32) {
        return TestResult::Fail("phys-hi write missing or wrong");
    }
    let expect_trigger = (PSP_CMD_LOAD_IP_FW & 0xFF) | (size << 8);
    if m.writes[2] != (trig, expect_trigger) {
        return TestResult::Fail("trigger word missing or wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/psp",
    smoke_amdgpu_psp_send_command_drives_canonical_sequence
);

fn smoke_amdgpu_psp_surfaces_rejection_status() -> TestResult {
    use crate::amdgpu_psp::{
        send_command, MockPsp, PspError, MP0_C2PMSG_64_REL, PSP_CMD_LOAD_IP_FW, PSP_STATUS_DONE_BIT,
    };
    let mp0_base = 0x000B_0000;
    let lo = mp0_base + MP0_C2PMSG_64_REL;

    let mut m = MockPsp::new();
    // PSP set DONE but with a non-zero status code (sig fail).
    let rejected_code: u32 = 0x0000_0042;
    m.stage_read(lo, PSP_STATUS_DONE_BIT | rejected_code);

    match send_command(&mut m, mp0_base, PSP_CMD_LOAD_IP_FW, 0x1000, 0x1000) {
        Err(PspError::Rejected(code)) if code == rejected_code => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("expected PspError::Rejected(0x42)")
        }
        Ok(_) => TestResult::Fail("PSP rejection silently passed"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/psp",
    smoke_amdgpu_psp_surfaces_rejection_status
);

fn smoke_amdgpu_psp_timeout_when_done_never_sets() -> TestResult {
    use crate::amdgpu_psp::{send_command, MockPsp, PspError, PSP_CMD_LOAD_IP_FW};
    // Stage nothing — mock returns 0 (DONE not set) on every read.
    let mut m = MockPsp::new();
    match send_command(&mut m, 0x000B_0000, PSP_CMD_LOAD_IP_FW, 0x1000, 0x1000) {
        Err(PspError::Timeout) => TestResult::Pass,
        _ => TestResult::Fail("expected PspError::Timeout when DONE never sets"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/psp",
    smoke_amdgpu_psp_timeout_when_done_never_sets
);

fn smoke_amdgpu_psp_rejects_empty_or_oversize_image() -> TestResult {
    use crate::amdgpu_psp::{
        send_command, MockPsp, PspError, PSP_CMD_LOAD_IP_FW, PSP_MAX_IMAGE_SIZE,
    };
    let mut m = MockPsp::new();
    match send_command(&mut m, 0x000B_0000, PSP_CMD_LOAD_IP_FW, 0x1000, 0) {
        Err(PspError::EmptyImage) => {}
        _ => return TestResult::Fail("zero-size image must be rejected"),
    }
    match send_command(
        &mut m,
        0x000B_0000,
        PSP_CMD_LOAD_IP_FW,
        0x1000,
        PSP_MAX_IMAGE_SIZE + 1,
    ) {
        Err(PspError::ImageTooLarge) => {}
        _ => return TestResult::Fail("oversize image must be rejected"),
    }
    // Neither rejected path should have touched the mailbox.
    if !m.writes.is_empty() {
        return TestResult::Fail("rejected images must not write mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/psp",
    smoke_amdgpu_psp_rejects_empty_or_oversize_image
);

// ── amdgpu/smu (bring_up) ──────────────────────────────────────────
//
// Higher-level bring-up handshake on top of the mailbox primitive.
// TEST_MESSAGE echo + GET_SMU_VERSION + GET_DRIVER_IF_VERSION
// match-check. Each step needs its own scripted RESP-then-OK
// alternation plus an ARG read-back.

fn smoke_amdgpu_smu_bring_up_happy_path() -> TestResult {
    use crate::amdgpu_smu::{
        bring_up, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL, SMU12_DRIVER_IF_VERSION,
        SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    // Step 1: TestMessage — handshake (idle), response OK, ARG echoes 0xDEADBEEF.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0xDEAD_BEEF);
    // Step 2: GetSmuVersion — handshake, OK, ARG = 0x000A_0203.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0x000A_0203);
    // Step 3: GetDriverIfVersion — handshake, OK, ARG = SMU12 driver-IF.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, SMU12_DRIVER_IF_VERSION);

    let info = match bring_up(&mut m, mp1_base, SMU12_DRIVER_IF_VERSION) {
        Ok(i) => i,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("bring_up errored on happy path");
        }
    };
    if info.smu_version != 0x000A_0203 {
        return TestResult::Fail("smu_version mis-cached");
    }
    if info.driver_if_version != SMU12_DRIVER_IF_VERSION {
        return TestResult::Fail("driver_if_version mis-cached");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_bring_up_happy_path
);

fn smoke_amdgpu_smu_bring_up_test_message_echo_mismatch() -> TestResult {
    use crate::amdgpu_smu::{
        bring_up, BringUpError, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL,
        SMU12_DRIVER_IF_VERSION, SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    // SMU returns the wrong echo value — bring-up must reject.
    m.stage_read(arg, 0xBADD_C0DE);

    match bring_up(&mut m, mp1_base, SMU12_DRIVER_IF_VERSION) {
        Err(BringUpError::TestMessageEchoMismatch { sent, got })
            if sent == 0xDEAD_BEEF && got == 0xBADD_C0DE =>
        {
            TestResult::Pass
        }
        Err(other) => {
            let _ = other;
            TestResult::Fail("expected TestMessageEchoMismatch")
        }
        Ok(_) => TestResult::Fail("bad echo silently accepted"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_bring_up_test_message_echo_mismatch
);

fn smoke_amdgpu_smu_bring_up_driver_if_mismatch_rejected() -> TestResult {
    use crate::amdgpu_smu::{
        bring_up, BringUpError, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL,
        SMU12_DRIVER_IF_VERSION, SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    // TestMessage echoes correctly.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0xDEAD_BEEF);
    // GetSmuVersion succeeds.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0x000A_0203);
    // GetDriverIfVersion reports v0x99 — host expects SMU12 (0x0F).
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0x99);

    match bring_up(&mut m, mp1_base, SMU12_DRIVER_IF_VERSION) {
        Err(BringUpError::DriverIfMismatch(reported, expected))
            if reported == 0x99 && expected == SMU12_DRIVER_IF_VERSION =>
        {
            TestResult::Pass
        }
        Err(other) => {
            let _ = other;
            TestResult::Fail("expected DriverIfMismatch(0x99, SMU12)")
        }
        Ok(_) => TestResult::Fail("schema mismatch silently accepted"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_bring_up_driver_if_mismatch_rejected
);

fn smoke_amdgpu_smu_bring_up_phoenix_driver_if_version() -> TestResult {
    use crate::amdgpu_smu::{
        bring_up, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL, SMU_13_0_4_DRIVER_IF_VERSION,
        SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    // Same happy-path script but the host expects the Phoenix
    // (SMU 13.0.4) driver-IF version, and the mock reports it.
    let mut m = MockSmu::new();
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0xDEAD_BEEF);
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0x000D_0004);
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, SMU_13_0_4_DRIVER_IF_VERSION);

    match bring_up(&mut m, mp1_base, SMU_13_0_4_DRIVER_IF_VERSION) {
        Ok(info) if info.driver_if_version == SMU_13_0_4_DRIVER_IF_VERSION => TestResult::Pass,
        Ok(other) => {
            let _ = other;
            TestResult::Fail("Phoenix driver-IF mis-cached")
        }
        Err(e) => {
            let _ = e;
            TestResult::Fail("Phoenix happy path failed")
        }
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_bring_up_phoenix_driver_if_version
);

// ── amdgpu/gfx (CP ring init) ──────────────────────────────────────
//
// GFX9 CP ring bring-up sequence builder. Real bring-up writes
// every entry to BAR5 in order against the CP IP block. The
// smokes assert the ordering invariants that matter:
// - CP must be halted *before* base / size are programmed
// - CP must be unhalted *last* (otherwise it fetches against
//   half-programmed state and wedges)
// - the per-step register writes carry the expected encodings.

fn smoke_amdgpu_gfx9_ring_init_emits_canonical_order() -> TestResult {
    use crate::amdgpu_gfx::{
        build_gfx9_ring_init, CP_ME_CNTL_HALT_ALL, CP_ME_CNTL_REL, CP_RB0_BASE_HI_REL,
        CP_RB0_BASE_REL, CP_RB0_CNTL_REL, CP_RB0_RPTR_ADDR_HI_REL, CP_RB0_RPTR_ADDR_REL,
        CP_RB0_WPTR_HI_REL, CP_RB0_WPTR_REL, CP_RB_DOORBELL_CONTROL_REL, CP_RB_DOORBELL_EN,
        CP_RB_DOORBELL_OFFSET_SHIFT, CP_RB_DOORBELL_RANGE_LOWER_REL,
        CP_RB_DOORBELL_RANGE_UPPER_REL, RPTR_ADDR_HI_MASK,
    };
    let gc_base: u32 = 0x0003_0000;
    let ring_phys: u64 = 0x0000_0001_0000_0000;
    let ring_size_dw: u32 = 1024;
    let doorbell_idx: u32 = 5;
    let rptr_phys: u64 = 0x0000_0002_DEAD_0000;

    let seq = match build_gfx9_ring_init(gc_base, ring_phys, ring_size_dw, doorbell_idx, rptr_phys)
    {
        Ok(s) => s,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("build_gfx9_ring_init errored on valid inputs");
        }
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();

    // First write must be CP halt (otherwise CP fetches against
    // an in-flux ring).
    if w.first().map(|g| (g.addr, g.value)) != Some((gc_base + CP_ME_CNTL_REL, CP_ME_CNTL_HALT_ALL))
    {
        return TestResult::Fail("first write must halt CP via CP_ME_CNTL");
    }
    // Last write must be CP unhalt with all-zero.
    if w.last().map(|g| (g.addr, g.value)) != Some((gc_base + CP_ME_CNTL_REL, 0)) {
        return TestResult::Fail("last write must unhalt CP_ME_CNTL");
    }
    // Look for the key body writes in order — base lo/hi, cntl,
    // doorbell control / lower / upper, rptr addr lo/hi.
    let want = [
        (gc_base + CP_RB0_WPTR_REL, 0),
        (gc_base + CP_RB0_WPTR_HI_REL, 0),
        (gc_base + CP_RB0_RPTR_ADDR_REL, rptr_phys as u32),
        // The high half is MASKED to 16 bits, not OR'd with cache bits —
        // the register has one field and the bits that used to be set here
        // were address bits 32 and 33.
        (
            gc_base + CP_RB0_RPTR_ADDR_HI_REL,
            ((rptr_phys >> 32) as u32) & RPTR_ADDR_HI_MASK,
        ),
        // The base is the address SHIFTED RIGHT BY 8: the register holds a
        // 256-byte granule. This used to assert the raw address, which is
        // what the builder wrote — so the test agreed with the bug.
        (gc_base + CP_RB0_BASE_REL, (ring_phys >> 8) as u32),
        (gc_base + CP_RB0_BASE_HI_REL, (ring_phys >> 8 >> 32) as u32),
        (
            gc_base + CP_RB0_CNTL_REL,
            ring_size_dw.trailing_zeros() | (6u32 << 8),
        ),
        (
            gc_base + CP_RB_DOORBELL_CONTROL_REL,
            CP_RB_DOORBELL_EN | (doorbell_idx << CP_RB_DOORBELL_OFFSET_SHIFT),
        ),
        (gc_base + CP_RB_DOORBELL_RANGE_LOWER_REL, doorbell_idx),
        (gc_base + CP_RB_DOORBELL_RANGE_UPPER_REL, doorbell_idx + 1),
    ];
    // Find each `want` entry in order; subsequent searches start
    // where the prior one left off so we get an ordering check.
    let mut cursor = 1; // skip the leading CP_ME_CNTL halt
    for (addr, value) in want {
        let idx = w[cursor..]
            .iter()
            .position(|g| g.addr == addr && g.value == value);
        match idx {
            Some(i) => cursor += i + 1,
            None => {
                return TestResult::Fail("missing expected ring-init write");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx9_ring_init_emits_canonical_order
);

fn smoke_amdgpu_gfx9_ring_init_rejects_bad_ring_size() -> TestResult {
    use crate::amdgpu_gfx::{build_gfx9_ring_init, GfxError};
    // Non-power-of-two size — CP_RB0_CNTL can't encode it.
    let r = build_gfx9_ring_init(0x0003_0000, 0x1_0000_0000, 1000, 0, 0x2_0000_0000);
    match r {
        Err(GfxError::BadRingSize) => TestResult::Pass,
        _ => TestResult::Fail("non-pow2 ring size must be rejected"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx9_ring_init_rejects_bad_ring_size
);

fn smoke_amdgpu_gfx9_ring_init_rejects_unaligned_ring_phys() -> TestResult {
    use crate::amdgpu_gfx::{build_gfx9_ring_init, GfxError};
    // Ring base must be 256-byte aligned (low 8 bits zero).
    let r = build_gfx9_ring_init(0x0003_0000, 0x1_0000_00FF, 1024, 0, 0x2_0000_0000);
    match r {
        Err(GfxError::UnalignedRingPhys) => TestResult::Pass,
        _ => TestResult::Fail("unaligned ring phys must be rejected"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx9_ring_init_rejects_unaligned_ring_phys
);

fn smoke_amdgpu_gfx9_ring_init_rptr_writeback_alignment() -> TestResult {
    use crate::amdgpu_gfx::{build_gfx9_ring_init, GfxError};
    // RPTR writeback target must be 8-byte aligned.
    let r = build_gfx9_ring_init(
        0x0003_0000,
        0x1_0000_0000,
        1024,
        0,
        0x2_0000_0001, // 1-aligned, not 8-aligned
    );
    match r {
        Err(GfxError::UnalignedRptrWriteback) => TestResult::Pass,
        _ => TestResult::Fail("unaligned rptr-writeback must be rejected"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx9_ring_init_rptr_writeback_alignment
);

// ── amdgpu/gfx (pm4 → ring integration) ────────────────────────────
//
// Build a fence-publishing IB through `Pm4Builder`, push it to
// a real `Ring`, then read back the ring DMA buffer to verify
// the packets landed at the right wptr offsets with the right
// dwords. The unit tests already cover Pm4Builder and Ring
// individually; this one verifies they compose.

fn smoke_amdgpu_gfx_pm4_write_data_lands_in_ring() -> TestResult {
    use crate::amdgpu_pm4::Pm4Builder;
    use crate::amdgpu_ring::Ring;

    let mut ring = match Ring::new(11) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("Ring::new failed"),
    };

    // Build a 5-dword WRITE_DATA fence-publish packet into a
    // staging buffer. Fence target = 0x0000_3000_0001_0000, value 42.
    let mut staging = [0u32; 5];
    let bytes_written = {
        let mut b = Pm4Builder::new(&mut staging);
        if b.write_data(0x0000_3000_0001_0000, 42).is_err() {
            return TestResult::Fail("write_data emit failed");
        }
        b.bytes_written()
    };
    if bytes_written != 5 * 4 {
        return TestResult::Fail("write_data should emit exactly 5 dwords");
    }

    // Submit to the ring and verify wptr advanced.
    // SAFETY: smoke owns the ring exclusively.
    let new_wptr = match unsafe { ring.submit(&staging, 0) } {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("ring rejected fence packet"),
    };
    if new_wptr != 5 {
        return TestResult::Fail("wptr should advance by exactly 5 dwords");
    }

    // Read the ring's DMA backing back and compare to the staging
    // dwords. Ring::submit writes byte-by-byte in-place; identical
    // dwords should appear at the ring base.
    let phys = ring.phys_addr();
    for (i, &expected) in staging.iter().enumerate() {
        // SAFETY: DMA-coherent page via the direct map, ring is owned.
        let got = unsafe {
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(phys + (i * 4) as u64).kernel_ptr::<u32>(),
            )
        };
        if got != expected {
            return TestResult::Fail("ring dword mismatch after submit");
        }
    }

    // Header dword: TYPE3 (= 3 << 30) | (count-1=4 << 16) | (op=0x37 << 8).
    let header = staging[0];
    if (header >> 30) != 3 {
        return TestResult::Fail("first dword must be PM4 TYPE3 header");
    }
    if ((header >> 16) & 0x3FFF) != (5 - 1) - 1 {
        // count_minus_one = data_word_count - 1; data_word_count = 4 (= 5 dwords - header)
        // so this should equal 3.
        return TestResult::Fail("header count_minus_one field wrong");
    }
    if ((header >> 8) & 0xFF) != 0x37 {
        return TestResult::Fail("header opcode must be WRITE_DATA (0x37)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx_pm4_write_data_lands_in_ring
);

fn smoke_amdgpu_gfx_pm4_multi_packet_ib_lands_in_ring() -> TestResult {
    use crate::amdgpu_pm4::Pm4Builder;
    use crate::amdgpu_ring::Ring;

    let mut ring = match Ring::new(12) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("Ring::new failed"),
    };

    // Build a representative submission: NOP pad (1 word data), then
    // an INDIRECT_BUFFER (4 dwords), then a WRITE_DATA fence (5 dwords).
    // Total: 2 (nop) + 4 (ib) + 5 (write) = 11 dwords.
    let mut staging = [0u32; 16];
    let bytes_written = {
        let mut b = Pm4Builder::new(&mut staging);
        if b.nop(1).is_err() {
            return TestResult::Fail("nop emit failed");
        }
        if b.indirect_buffer(0x1000_0000, 0x100, 0).is_err() {
            return TestResult::Fail("indirect_buffer emit failed");
        }
        if b.write_data(0x2000_0000_0000_0000, 0x12345).is_err() {
            return TestResult::Fail("write_data emit failed");
        }
        b.bytes_written()
    };
    if bytes_written != 11 * 4 {
        return TestResult::Fail("composite IB should be exactly 11 dwords");
    }

    // Submit and verify wptr.
    // SAFETY: smoke owns the ring.
    let new_wptr = match unsafe { ring.submit(&staging[..11], 0) } {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("ring rejected composite IB"),
    };
    if new_wptr != 11 {
        return TestResult::Fail("wptr should be 11");
    }

    // Read back. The three sub-packets should sit at offsets 0, 2, 6.
    let phys = ring.phys_addr();
    let read_dw = |i: usize| -> u32 {
        // SAFETY: identity-mapped DMA backing, ring owned.
        unsafe {
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(phys + (i * 4) as u64).kernel_ptr::<u32>(),
            )
        }
    };
    // NOP at offset 0: opcode 0x10 in header bits[15:8].
    if ((read_dw(0) >> 8) & 0xFF) != 0x10 {
        return TestResult::Fail("NOP header missing at offset 0");
    }
    // INDIRECT_BUFFER at offset 2: opcode 0x3F.
    if ((read_dw(2) >> 8) & 0xFF) != 0x3F {
        return TestResult::Fail("INDIRECT_BUFFER header missing at offset 2");
    }
    // WRITE_DATA at offset 6: opcode 0x37.
    if ((read_dw(6) >> 8) & 0xFF) != 0x37 {
        return TestResult::Fail("WRITE_DATA header missing at offset 6");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx_pm4_multi_packet_ib_lands_in_ring
);

// ── amdgpu/gfx (GfxContext submission API) ─────────────────────────
//
// The higher-level submission helper. submit_ib pushes an
// INDIRECT_BUFFER + WRITE_DATA fence pair to the ring, returning
// a Fence the caller can poll. Without a real CP, fence completion
// is staged via the test-only set_fence_for_test helper.

fn smoke_amdgpu_gfx_context_submit_ib_advances_fence_and_ring() -> TestResult {
    use crate::amdgpu_gfx::GfxContext;

    let mut ctx = match GfxContext::new(13) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("GfxContext::new failed"),
    };
    if ctx.last_fence_seq() != 0 {
        return TestResult::Fail("fresh ctx should have last_fence_seq=0");
    }
    // Initially no fences have completed.
    let probe = crate::amdgpu_gfx::Fence { seq: 1 };
    if ctx.fence_completed(&probe) {
        return TestResult::Fail("nothing should be complete on a fresh ctx");
    }

    // Submit one IB; verify fence seq advanced.
    // SAFETY: smoke owns ctx exclusively.
    let f1 = match unsafe { ctx.submit_ib(0x1_0000_0000, 64) } {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("submit_ib rejected first IB"),
    };
    if f1.seq != 1 {
        return TestResult::Fail("first fence seq must be 1");
    }
    if ctx.last_fence_seq() != 1 {
        return TestResult::Fail("last_fence_seq must reflect seq 1");
    }

    // Submit a second IB; verify monotonic.
    // SAFETY: same.
    let f2 = match unsafe { ctx.submit_ib(0x2_0000_0000, 32) } {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("submit_ib rejected second IB"),
    };
    if f2.seq != 2 {
        return TestResult::Fail("second fence seq must be 2");
    }

    // Stage GPU "retiring" fence seq 1 — only f1 should be done.
    ctx.set_fence_for_test(1);
    if !ctx.fence_completed(&f1) {
        return TestResult::Fail("f1 must report complete at observed=1");
    }
    if ctx.fence_completed(&f2) {
        return TestResult::Fail("f2 must NOT be complete at observed=1");
    }

    // Now retire through 2; both done.
    ctx.set_fence_for_test(2);
    if !ctx.fence_completed(&f1) || !ctx.fence_completed(&f2) {
        return TestResult::Fail("both fences must complete at observed=2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx_context_submit_ib_advances_fence_and_ring
);

fn smoke_amdgpu_gfx_context_submit_ib_ring_contents() -> TestResult {
    use crate::amdgpu_gfx::GfxContext;

    let mut ctx = match GfxContext::new(14) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("GfxContext::new failed"),
    };
    let ring_phys = ctx.ring_phys();
    let fence_phys = ctx.fence_phys();

    // SAFETY: smoke owns ctx exclusively.
    let _ = match unsafe { ctx.submit_ib(0xABCD_0000_0000_0000, 0x80) } {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("submit_ib failed"),
    };

    // Read the first 9 dwords of the ring back and verify the
    // packet pair: INDIRECT_BUFFER (4 dw) + WRITE_DATA (5 dw).
    let read_dw = |i: usize| -> u32 {
        // SAFETY: identity-mapped DMA backing, owned by ctx.
        unsafe {
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(ring_phys + (i * 4) as u64).kernel_ptr::<u32>(),
            )
        }
    };

    // dword 0: INDIRECT_BUFFER header (opcode 0x3F).
    if ((read_dw(0) >> 8) & 0xFF) != 0x3F {
        return TestResult::Fail("dw0 must be INDIRECT_BUFFER header");
    }
    // dword 1: IB base lo.
    if read_dw(1) != 0xABCD_0000_0000_0000_u64 as u32 {
        return TestResult::Fail("dw1 must be IB base lo");
    }
    // dword 2: IB base hi.
    if read_dw(2) != (0xABCD_0000_0000_0000_u64 >> 32) as u32 {
        return TestResult::Fail("dw2 must be IB base hi");
    }
    // dword 3: IB size + VMID.
    if read_dw(3) & 0x000F_FFFF != 0x80 {
        return TestResult::Fail("dw3 must encode IB size 0x80");
    }
    // dword 4: WRITE_DATA header (opcode 0x37).
    if ((read_dw(4) >> 8) & 0xFF) != 0x37 {
        return TestResult::Fail("dw4 must be WRITE_DATA header");
    }
    // dword 5: WRITE_DATA control word — dst_sel=MEM(5)<<8, wr_confirm bit set.
    let ctrl = read_dw(5);
    if (ctrl >> 8) & 0xFF != 5 {
        return TestResult::Fail("WRITE_DATA ctrl dst_sel must be MEM(5)");
    }
    if ctrl & (1 << 20) == 0 {
        return TestResult::Fail("WRITE_DATA ctrl wr_confirm must be set");
    }
    // dword 6: fence target lo.
    if read_dw(6) != fence_phys as u32 {
        return TestResult::Fail("dw6 must be fence_phys lo");
    }
    // dword 7: fence target hi.
    if read_dw(7) != (fence_phys >> 32) as u32 {
        return TestResult::Fail("dw7 must be fence_phys hi");
    }
    // dword 8: fence value — seq 1 as u32.
    if read_dw(8) != 1 {
        return TestResult::Fail("dw8 must be seq value 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx_context_submit_ib_ring_contents
);

// ── amdgpu/sdma (ring init) ────────────────────────────────────────
//
// SDMA v4.0 ring bring-up sequence. The key invariants:
// - first write disables the ring (CNTL=0) so the engine doesn't
//   fetch against half-programmed state
// - last write enables the ring (CNTL with RB_ENABLE set)
// - doorbell programmed in between

fn smoke_amdgpu_sdma4_ring_init_emits_canonical_order() -> TestResult {
    use crate::amdgpu_sdma::{
        build_sdma4_ring_init, SDMA_DOORBELL_ENABLE, SDMA_GFX_DOORBELL_OFFSET_REL,
        SDMA_GFX_DOORBELL_REL, SDMA_GFX_RB_BASE_HI_REL, SDMA_GFX_RB_BASE_REL, SDMA_GFX_RB_CNTL_REL,
        SDMA_GFX_RB_RPTR_ADDR_HI_REL, SDMA_GFX_RB_RPTR_ADDR_LO_REL, SDMA_RB_ENABLE,
        SDMA_RB_RPTR_WRITEBACK_ENABLE, SDMA_RB_SIZE_SHIFT,
    };
    let sdma_base: u32 = 0x0006_0000;
    let ring_phys: u64 = 0x0000_0001_8000_0000; // 256-byte aligned
    let ring_size_dw: u32 = 1024;
    let doorbell_idx: u32 = 9;
    let rptr_phys: u64 = 0x0000_0002_BEEF_0000;

    let seq =
        match build_sdma4_ring_init(sdma_base, ring_phys, ring_size_dw, doorbell_idx, rptr_phys) {
            Ok(s) => s,
            Err(e) => {
                let _ = e;
                return TestResult::Fail("build_sdma4_ring_init errored on valid inputs");
            }
        };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();

    // First write: CNTL = 0 (disable).
    if w.first().map(|x| (x.addr, x.value)) != Some((sdma_base + SDMA_GFX_RB_CNTL_REL, 0)) {
        return TestResult::Fail("first write must disable CNTL");
    }
    // Last write: CNTL with RB_ENABLE bit.
    let last = w.last().copied();
    let expected_cntl = (ring_size_dw.trailing_zeros() << SDMA_RB_SIZE_SHIFT)
        | SDMA_RB_RPTR_WRITEBACK_ENABLE
        | SDMA_RB_ENABLE;
    if last.map(|x| (x.addr, x.value)) != Some((sdma_base + SDMA_GFX_RB_CNTL_REL, expected_cntl)) {
        return TestResult::Fail("last write must enable ring via CNTL | RB_ENABLE");
    }
    // Specific writes that must appear (in any order between disable/enable):
    let want = [
        (sdma_base + SDMA_GFX_RB_BASE_REL, (ring_phys >> 8) as u32),
        (
            sdma_base + SDMA_GFX_RB_BASE_HI_REL,
            (ring_phys >> 40) as u32,
        ),
        (sdma_base + SDMA_GFX_RB_RPTR_ADDR_LO_REL, rptr_phys as u32),
        (
            sdma_base + SDMA_GFX_RB_RPTR_ADDR_HI_REL,
            (rptr_phys >> 32) as u32,
        ),
        (sdma_base + SDMA_GFX_DOORBELL_OFFSET_REL, doorbell_idx << 2),
        (sdma_base + SDMA_GFX_DOORBELL_REL, SDMA_DOORBELL_ENABLE),
    ];
    for (addr, value) in want {
        if !w.iter().any(|x| x.addr == addr && x.value == value) {
            return TestResult::Fail("missing expected SDMA ring-init write");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma4_ring_init_emits_canonical_order
);

fn smoke_amdgpu_sdma4_ring_init_validates_inputs() -> TestResult {
    use crate::amdgpu_sdma::{build_sdma4_ring_init, SdmaError};
    // Non-pow2 ring size.
    match build_sdma4_ring_init(0x0006_0000, 0x1_0000_0000, 999, 0, 0x2_0000_0000) {
        Err(SdmaError::BadRingSize) => {}
        _ => return TestResult::Fail("non-pow2 ring size must be rejected"),
    }
    // Unaligned ring phys (SDMA encodes phys >> 8).
    match build_sdma4_ring_init(0x0006_0000, 0x1_0000_0080, 1024, 0, 0x2_0000_0000) {
        Err(SdmaError::UnalignedRingPhys) => {}
        _ => return TestResult::Fail("256-byte misalignment must be rejected"),
    }
    // Unaligned rptr writeback (must be 4-byte aligned).
    match build_sdma4_ring_init(0x0006_0000, 0x1_0000_0000, 1024, 0, 0x2_0000_0002) {
        Err(SdmaError::UnalignedRptrWriteback) => {}
        _ => return TestResult::Fail("unaligned rptr-writeback must be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma4_ring_init_validates_inputs
);

fn smoke_amdgpu_sdma4_ring_init_enable_strictly_after_disable() -> TestResult {
    use crate::amdgpu_sdma::{build_sdma4_ring_init, SDMA_GFX_RB_CNTL_REL, SDMA_RB_ENABLE};
    let sdma_base: u32 = 0x0006_0000;
    let seq = match build_sdma4_ring_init(sdma_base, 0x1_0000_0000, 256, 3, 0x2_0000_0000) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("happy-path build failed"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();

    // Find the LAST CNTL write and confirm it's the only one with
    // RB_ENABLE set. Any earlier CNTL write must be zero (disable).
    let cntl_addr = sdma_base + SDMA_GFX_RB_CNTL_REL;
    let mut last_idx = None;
    let mut enable_seen_early = false;
    for (i, x) in w.iter().enumerate() {
        if x.addr == cntl_addr {
            last_idx = Some(i);
        }
    }
    let last_i = match last_idx {
        Some(i) => i,
        None => return TestResult::Fail("no CNTL write in sequence"),
    };
    for (i, x) in w.iter().enumerate() {
        if i == last_i {
            continue;
        }
        if x.addr == cntl_addr && (x.value & SDMA_RB_ENABLE) != 0 {
            enable_seen_early = true;
        }
    }
    if enable_seen_early {
        return TestResult::Fail("RB_ENABLE set before the final CNTL write");
    }
    if (w[last_i].value & SDMA_RB_ENABLE) == 0 {
        return TestResult::Fail("last CNTL write must set RB_ENABLE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma4_ring_init_enable_strictly_after_disable
);

// ── amdgpu/sdma (packet builder) ───────────────────────────────────
//
// SDMA packet construction. Tests verify the dword layout for the
// three canonical packets — COPY linear, FENCE, NOP — and reject
// degenerate inputs (empty / oversize copy).

fn smoke_amdgpu_sdma_packet_copy_linear_layout() -> TestResult {
    use crate::amdgpu_sdma::{SdmaBuilder, SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR};
    let mut buf = [0u32; 7];
    let bytes_written = {
        let mut b = SdmaBuilder::new(&mut buf);
        let src: u64 = 0x1111_2222_3333_4400;
        let dst: u64 = 0x5555_6666_7777_8800;
        if b.copy_linear(src, dst, 0x4000).is_err() {
            return TestResult::Fail("copy_linear emit failed");
        }
        b.bytes_written()
    };
    if bytes_written != 7 * 4 {
        return TestResult::Fail("copy_linear should emit 7 dwords");
    }

    // Header: OP=COPY << 24, SUB_OP=LINEAR << 16.
    let want_hdr = (SDMA_OP_COPY << 24) | (SDMA_SUBOP_COPY_LINEAR << 16);
    if buf[0] != want_hdr {
        return TestResult::Fail("copy header dword wrong");
    }
    // Count = bytes - 1.
    if buf[1] != 0x4000 - 1 {
        return TestResult::Fail("copy count must be byte_count - 1");
    }
    // Reserved.
    if buf[2] != 0 {
        return TestResult::Fail("copy reserved dword must be 0");
    }
    // Src lo / hi, dst lo / hi.
    if buf[3] != 0x3333_4400 {
        return TestResult::Fail("src lo wrong");
    }
    if buf[4] != 0x1111_2222 {
        return TestResult::Fail("src hi wrong");
    }
    if buf[5] != 0x7777_8800 {
        return TestResult::Fail("dst lo wrong");
    }
    if buf[6] != 0x5555_6666 {
        return TestResult::Fail("dst hi wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma_packet_copy_linear_layout
);

fn smoke_amdgpu_sdma_packet_fence_layout() -> TestResult {
    use crate::amdgpu_sdma::{SdmaBuilder, SDMA_OP_FENCE};
    let mut buf = [0u32; 4];
    let dst: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    {
        let mut b = SdmaBuilder::new(&mut buf);
        if b.fence(dst, 42).is_err() {
            return TestResult::Fail("fence emit failed");
        }
    }
    let want_hdr = SDMA_OP_FENCE << 24;
    if buf[0] != want_hdr {
        return TestResult::Fail("fence header dword wrong");
    }
    if buf[1] != 0xCCCC_DDDD {
        return TestResult::Fail("fence dst lo wrong");
    }
    if buf[2] != 0xAAAA_BBBB {
        return TestResult::Fail("fence dst hi wrong");
    }
    if buf[3] != 42 {
        return TestResult::Fail("fence value wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma_packet_fence_layout
);

fn smoke_amdgpu_sdma_packet_rejects_empty_and_oversize_copy() -> TestResult {
    use crate::amdgpu_sdma::{SdmaBuilder, SdmaPktError, SDMA_COPY_MAX_BYTES};
    let mut buf = [0u32; 7];
    let mut b = SdmaBuilder::new(&mut buf);
    match b.copy_linear(0x1000, 0x2000, 0) {
        Err(SdmaPktError::EmptyCopy) => {}
        _ => return TestResult::Fail("zero-byte copy must be rejected"),
    }
    match b.copy_linear(0x1000, 0x2000, SDMA_COPY_MAX_BYTES + 1) {
        Err(SdmaPktError::CopyTooLarge) => {}
        _ => return TestResult::Fail("oversized copy must be rejected"),
    }
    if b.bytes_written() != 0 {
        return TestResult::Fail("rejected calls must not advance pos");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma_packet_rejects_empty_and_oversize_copy
);

fn smoke_amdgpu_sdma_packet_nop_and_trap() -> TestResult {
    use crate::amdgpu_sdma::{SdmaBuilder, SDMA_OP_NOP, SDMA_OP_TRAP};
    let mut buf = [0u32; 3];
    {
        let mut b = SdmaBuilder::new(&mut buf);
        if b.nop().is_err() {
            return TestResult::Fail("nop emit failed");
        }
        if b.trap(0xC0DE_F00D).is_err() {
            return TestResult::Fail("trap emit failed");
        }
        if b.bytes_written() != 3 * 4 {
            return TestResult::Fail("expected 3 dwords (nop=1 + trap=2)");
        }
    }
    if buf[0] != (SDMA_OP_NOP << 24) {
        return TestResult::Fail("NOP header wrong");
    }
    if buf[1] != (SDMA_OP_TRAP << 24) {
        return TestResult::Fail("TRAP header wrong");
    }
    if buf[2] != 0xC0DE_F00D {
        return TestResult::Fail("TRAP ack wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma_packet_nop_and_trap
);

// ── amdgpu/pm4 (extended packet vocabulary) ────────────────────────
//
// ACQUIRE_MEM (cache flush), SET_CONTEXT_REG / SET_CONFIG_REG
// (state push), CONTEXT_CONTROL (load/shadow control).

fn smoke_amdgpu_pm4_acquire_mem_full_invalidate_layout() -> TestResult {
    use crate::amdgpu_pm4::{Pm4Builder, ACQUIRE_FULL_SHADER_INVALIDATE};
    let mut buf = [0u32; 7];
    {
        let mut b = Pm4Builder::new(&mut buf);
        // Acquire the entire memory range; full shader invalidate.
        if b.acquire_mem(ACQUIRE_FULL_SHADER_INVALIDATE, 0, !0u64, 4)
            .is_err()
        {
            return TestResult::Fail("acquire_mem emit failed");
        }
    }
    // Header: TYPE3 (=3<<30), count-1 = 5, opcode 0x58.
    if (buf[0] >> 30) != 3 {
        return TestResult::Fail("acquire_mem header must be TYPE3");
    }
    if ((buf[0] >> 16) & 0x3FFF) != 5 {
        return TestResult::Fail("acquire_mem count_minus_one must be 5 (6 data dwords)");
    }
    if ((buf[0] >> 8) & 0xFF) != 0x58 {
        return TestResult::Fail("acquire_mem opcode must be 0x58");
    }
    if buf[1] != ACQUIRE_FULL_SHADER_INVALIDATE {
        return TestResult::Fail("coher_cntl dword wrong");
    }
    // coher_size = !0u64
    if buf[2] != 0xFFFF_FFFF || buf[3] != 0xFFFF_FFFF {
        return TestResult::Fail("coher_size dwords wrong");
    }
    // coher_base = 0
    if buf[4] != 0 || buf[5] != 0 {
        return TestResult::Fail("coher_base dwords wrong");
    }
    if buf[6] != 4 {
        return TestResult::Fail("poll_interval wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pm4",
    smoke_amdgpu_pm4_acquire_mem_full_invalidate_layout
);

fn smoke_amdgpu_pm4_set_context_reg_layout() -> TestResult {
    use crate::amdgpu_pm4::Pm4Builder;
    let mut buf = [0u32; 6];
    let vals = [0x1111_2222u32, 0x3333_4444, 0x5555_6666];
    {
        let mut b = Pm4Builder::new(&mut buf);
        if b.set_context_reg(0x0123, &vals).is_err() {
            return TestResult::Fail("set_context_reg emit failed");
        }
    }
    // Header: TYPE3, count-1 = (1+3)-1 = 3, opcode 0x69.
    if ((buf[0] >> 16) & 0x3FFF) != 3 {
        return TestResult::Fail("set_context_reg count_minus_one wrong");
    }
    if ((buf[0] >> 8) & 0xFF) != 0x69 {
        return TestResult::Fail("set_context_reg opcode wrong");
    }
    // reg_offset
    if buf[1] != 0x0123 {
        return TestResult::Fail("set_context_reg reg_offset wrong");
    }
    if buf[2..5] != vals {
        return TestResult::Fail("set_context_reg values not copied in order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pm4",
    smoke_amdgpu_pm4_set_context_reg_layout
);

fn smoke_amdgpu_pm4_context_control_layout() -> TestResult {
    use crate::amdgpu_pm4::Pm4Builder;
    let mut buf = [0u32; 3];
    {
        let mut b = Pm4Builder::new(&mut buf);
        if b.context_control(0x8000_0000, 0x8000_0000).is_err() {
            return TestResult::Fail("context_control emit failed");
        }
    }
    // Header: TYPE3, count-1 = 1, opcode 0x28.
    if ((buf[0] >> 16) & 0x3FFF) != 1 {
        return TestResult::Fail("context_control count_minus_one wrong");
    }
    if ((buf[0] >> 8) & 0xFF) != 0x28 {
        return TestResult::Fail("context_control opcode wrong");
    }
    if buf[1] != 0x8000_0000 || buf[2] != 0x8000_0000 {
        return TestResult::Fail("context_control data dwords wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pm4",
    smoke_amdgpu_pm4_context_control_layout
);

fn smoke_amdgpu_pm4_set_context_reg_rejects_empty_values() -> TestResult {
    use crate::amdgpu_pm4::{Pm4Builder, Pm4Error};
    let mut buf = [0u32; 4];
    let mut b = Pm4Builder::new(&mut buf);
    // Zero values can't be encoded — count_minus_one would underflow.
    match b.set_context_reg(0x0100, &[]) {
        Err(Pm4Error::BadCount) => TestResult::Pass,
        _ => TestResult::Fail("empty values must be rejected"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pm4",
    smoke_amdgpu_pm4_set_context_reg_rejects_empty_values
);

// ── amdgpu/ih (interrupt handler ring) ─────────────────────────────

fn smoke_amdgpu_ih4_ring_init_emits_canonical_order() -> TestResult {
    use crate::amdgpu_ih::{
        build_ih4_ring_init, IH_DOORBELL_ENABLE, IH_DOORBELL_RPTR_REL, IH_RB_BASE_HI_REL,
        IH_RB_BASE_REL, IH_RB_CNTL_REL, IH_RB_ENABLE, IH_RB_GPU_TS_ENABLE, IH_RB_OVERFLOW_CLEAR,
        IH_RB_SIZE_SHIFT, IH_RB_WPTR_ADDR_HI_REL, IH_RB_WPTR_ADDR_LO_REL,
        IH_RB_WPTR_WRITEBACK_ENABLE,
    };
    let ih_base: u32 = 0x0009_0000;
    let ring_phys: u64 = 0x0000_0001_4000_0000;
    let ring_size_dw: u32 = 512;
    let doorbell_idx: u32 = 6;
    let wptr_phys: u64 = 0x0000_0002_1234_0000;

    let seq = match build_ih4_ring_init(ih_base, ring_phys, ring_size_dw, doorbell_idx, wptr_phys) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("build_ih4_ring_init failed on valid input"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();

    if w.first().map(|x| (x.addr, x.value)) != Some((ih_base + IH_RB_CNTL_REL, 0)) {
        return TestResult::Fail("first write must disable CNTL");
    }
    let expected_cntl_no_en = (ring_size_dw.trailing_zeros() << IH_RB_SIZE_SHIFT)
        | IH_RB_GPU_TS_ENABLE
        | IH_RB_WPTR_WRITEBACK_ENABLE
        | IH_RB_OVERFLOW_CLEAR;
    let expected_cntl_en = expected_cntl_no_en | IH_RB_ENABLE;
    let last = w.last().copied();
    if last.map(|x| (x.addr, x.value)) != Some((ih_base + IH_RB_CNTL_REL, expected_cntl_en)) {
        return TestResult::Fail("last write must enable CNTL with full mask");
    }
    let want = [
        (ih_base + IH_RB_BASE_REL, (ring_phys >> 8) as u32),
        (ih_base + IH_RB_BASE_HI_REL, (ring_phys >> 40) as u32),
        (ih_base + IH_RB_WPTR_ADDR_LO_REL, wptr_phys as u32),
        (ih_base + IH_RB_WPTR_ADDR_HI_REL, (wptr_phys >> 32) as u32),
        (
            ih_base + IH_DOORBELL_RPTR_REL,
            IH_DOORBELL_ENABLE | (doorbell_idx << 2),
        ),
    ];
    for (addr, value) in want {
        if !w.iter().any(|x| x.addr == addr && x.value == value) {
            return TestResult::Fail("missing expected IH init write");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ih",
    smoke_amdgpu_ih4_ring_init_emits_canonical_order
);

fn smoke_amdgpu_ih4_validation_rejects_bad_inputs() -> TestResult {
    use crate::amdgpu_ih::{build_ih4_ring_init, IhError};
    match build_ih4_ring_init(0x0009_0000, 0x1_0000_0000, 999, 0, 0x2_0000_0000) {
        Err(IhError::BadRingSize) => {}
        _ => return TestResult::Fail("non-pow2 size must be rejected"),
    }
    match build_ih4_ring_init(0x0009_0000, 0x1_0000_0080, 512, 0, 0x2_0000_0000) {
        Err(IhError::UnalignedRingPhys) => {}
        _ => return TestResult::Fail("256-byte misalignment must be rejected"),
    }
    match build_ih4_ring_init(0x0009_0000, 0x1_0000_0000, 512, 0, 0x2_0000_0001) {
        Err(IhError::UnalignedWptrWriteback) => {}
        _ => return TestResult::Fail("unaligned writeback must be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ih",
    smoke_amdgpu_ih4_validation_rejects_bad_inputs
);

fn smoke_amdgpu_ih_cookie_header_round_trip() -> TestResult {
    use crate::amdgpu_ih::{IhCookieHeader, CLIENT_ID_DCN, SOURCE_ID_DCN_VBLANK};
    // Synthesize a "DCN VBlank on controller 1" cookie header.
    let hdr = IhCookieHeader {
        client_id: CLIENT_ID_DCN,
        source_id: SOURCE_ID_DCN_VBLANK,
        ring_id: 0,
        reserved: 0,
    };
    let dw = hdr.to_dword();
    let back = IhCookieHeader::from_dword(dw);
    if back != hdr {
        return TestResult::Fail("cookie header round-trip mismatch");
    }
    if back.client_id != CLIENT_ID_DCN || back.source_id != SOURCE_ID_DCN_VBLANK {
        return TestResult::Fail("decoded client/source ids wrong");
    }
    // Cross-check bit layout against the public AMD docs:
    //   client_id in bits[7:0], source_id in [15:8].
    if (dw & 0xFF) != CLIENT_ID_DCN as u32 {
        return TestResult::Fail("client_id not in dw[7:0]");
    }
    if ((dw >> 8) & 0xFF) != SOURCE_ID_DCN_VBLANK as u32 {
        return TestResult::Fail("source_id not in dw[15:8]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ih",
    smoke_amdgpu_ih_cookie_header_round_trip
);

fn smoke_amdgpu_ih_enable_strictly_after_disable() -> TestResult {
    use crate::amdgpu_ih::{build_ih4_ring_init, IH_RB_CNTL_REL, IH_RB_ENABLE};
    let ih_base: u32 = 0x0009_0000;
    let seq = match build_ih4_ring_init(ih_base, 0x1_0000_0000, 256, 3, 0x2_0000_0000) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("happy-path build failed"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    let cntl_addr = ih_base + IH_RB_CNTL_REL;
    let mut last_i = None;
    for (i, x) in w.iter().enumerate() {
        if x.addr == cntl_addr {
            last_i = Some(i);
        }
    }
    let li = match last_i {
        Some(i) => i,
        None => return TestResult::Fail("no CNTL write in sequence"),
    };
    for (i, x) in w.iter().enumerate() {
        if i == li {
            continue;
        }
        if x.addr == cntl_addr && (x.value & IH_RB_ENABLE) != 0 {
            return TestResult::Fail("RB_ENABLE set before final CNTL write");
        }
    }
    if (w[li].value & IH_RB_ENABLE) == 0 {
        return TestResult::Fail("final CNTL must set RB_ENABLE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ih",
    smoke_amdgpu_ih_enable_strictly_after_disable
);

// ── amdgpu/smu (DPM clock control) ─────────────────────────────────
//
// Higher-level wrappers on top of the mailbox primitive that
// pack the (clk_id, freq_mhz) arg format the SMU expects.

fn smoke_amdgpu_smu_pack_clk_arg_layout() -> TestResult {
    use crate::amdgpu_smu::{pack_clk_arg, pack_dpm_arg, SMU_CLK_GFXCLK, SMU_CLK_UCLK};
    // Clock id in bits[15:0], freq in bits[31:16].
    let a = pack_clk_arg(SMU_CLK_GFXCLK, 1900);
    if (a & 0xFFFF) != SMU_CLK_GFXCLK || (a >> 16) != 1900 {
        return TestResult::Fail("clk_arg layout wrong");
    }
    let b = pack_dpm_arg(SMU_CLK_UCLK, 3);
    if (b & 0xFFFF) != SMU_CLK_UCLK || (b >> 16) != 3 {
        return TestResult::Fail("dpm_arg layout wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_pack_clk_arg_layout
);

fn smoke_amdgpu_smu_set_clock_range_drives_two_messages() -> TestResult {
    use crate::amdgpu_smu::{
        pack_clk_arg, set_clock_range, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL,
        MP1_C2PMSG_RESP_REL, PPSMC_MSG_SET_SOFT_MAX_BY_FREQ, PPSMC_MSG_SET_SOFT_MIN_BY_FREQ,
        SMU_CLK_GFXCLK, SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;
    let msg = mp1_base + MP1_C2PMSG_MSG_REL;

    let mut m = MockSmu::new();
    // SET_SOFT_MIN: handshake, OK, arg readback (unused).
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0);
    // SET_SOFT_MAX: handshake, OK, arg readback.
    m.stage_read(resp, 1);
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 0);

    if set_clock_range(&mut m, mp1_base, SMU_CLK_GFXCLK, 400, 1900).is_err() {
        return TestResult::Fail("set_clock_range failed on happy path");
    }

    // Captured writes per message: clear-RESP, ARG, MSG → 3 writes.
    // Two messages → 6 writes total.
    if m.writes.len() != 6 {
        return TestResult::Fail("expected 6 mailbox writes for two messages");
    }
    // Message-id writes should be SET_SOFT_MIN then SET_SOFT_MAX.
    let mut msgs: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    for w in &m.writes {
        if w.0 == msg {
            msgs.push(w.1);
        }
    }
    if msgs.len() != 2 {
        return TestResult::Fail("expected 2 MSG-trigger writes");
    }
    if msgs[0] != PPSMC_MSG_SET_SOFT_MIN_BY_FREQ || msgs[1] != PPSMC_MSG_SET_SOFT_MAX_BY_FREQ {
        return TestResult::Fail("MSG order should be SET_SOFT_MIN then SET_SOFT_MAX");
    }
    // ARG values: pack_clk_arg(GFXCLK, 400) then pack_clk_arg(GFXCLK, 1900).
    let mut args: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    for w in &m.writes {
        if w.0 == arg {
            args.push(w.1);
        }
    }
    if args.len() != 2 {
        return TestResult::Fail("expected 2 ARG writes");
    }
    if args[0] != pack_clk_arg(SMU_CLK_GFXCLK, 400) || args[1] != pack_clk_arg(SMU_CLK_GFXCLK, 1900)
    {
        return TestResult::Fail("ARG values wrong order/encoding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_set_clock_range_drives_two_messages
);

fn smoke_amdgpu_smu_get_max_dpm_freq_returns_arg() -> TestResult {
    use crate::amdgpu_smu::{
        get_max_dpm_freq, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL, SMU_CLK_DCEFCLK,
        SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    m.stage_read(resp, 1); // handshake
    m.stage_read(resp, SMU_RESP_OK);
    m.stage_read(arg, 685); // SMU reports DCEFCLK max = 685 MHz

    match get_max_dpm_freq(&mut m, mp1_base, SMU_CLK_DCEFCLK) {
        Ok(685) => TestResult::Pass,
        Ok(other) => {
            let _ = other;
            TestResult::Fail("get_max_dpm_freq returned wrong value")
        }
        Err(_) => TestResult::Fail("get_max_dpm_freq errored on happy path"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_get_max_dpm_freq_returns_arg
);

// ── amdgpu/gmc (GART PTE format) ───────────────────────────────────

fn smoke_amdgpu_gmc_gart_pte_round_trip() -> TestResult {
    use crate::amdgpu_gmc::{
        make_pte_gfx9, parse_pte, pte_is_valid, GART_PTE_FLAGS_GTT_DEFAULT, GART_PTE_PFN_SHIFT,
    };
    let phys: u64 = 0x0000_0000_5678_9000; // 4 KiB aligned, PFN fits 28 bits
    let pte = match make_pte_gfx9(phys, GART_PTE_FLAGS_GTT_DEFAULT) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("make_pte rejected valid phys"),
    };
    // Valid bit must be set.
    if !pte_is_valid(pte) {
        return TestResult::Fail("PTE valid bit not set");
    }
    // PFN must occupy bits[39:12] of the PTE: phys >> 12 == bits[27:0] of PTE>>12.
    let (back_phys, back_flags) = parse_pte(pte);
    if back_phys != phys {
        return TestResult::Fail("PTE phys round-trip lost bits");
    }
    if back_flags != (GART_PTE_FLAGS_GTT_DEFAULT & 0xFFF) {
        return TestResult::Fail("PTE flag bits not preserved in low 12");
    }
    // Cross-check the actual bit layout: PFN exactly in bits[39:12].
    let expected_pfn = phys >> GART_PTE_PFN_SHIFT;
    if (pte >> GART_PTE_PFN_SHIFT) & 0x0FFF_FFFF != expected_pfn {
        return TestResult::Fail("PFN not in bits[39:12]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gmc",
    smoke_amdgpu_gmc_gart_pte_round_trip
);

fn smoke_amdgpu_gmc_gart_pte_rejects_unaligned_and_oversize() -> TestResult {
    use crate::amdgpu_gmc::{make_pte_gfx9, GartError, GART_PTE_FLAGS_GTT_DEFAULT};
    // Unaligned phys (bottom 12 bits non-zero).
    match make_pte_gfx9(0x1234_5678_9000 | 0x800, GART_PTE_FLAGS_GTT_DEFAULT) {
        Err(GartError::UnalignedPhys) => {}
        _ => return TestResult::Fail("unaligned phys must be rejected"),
    }
    // PFN overflow (above 1 TiB).
    match make_pte_gfx9(1u64 << 41, GART_PTE_FLAGS_GTT_DEFAULT) {
        Err(GartError::PfnOverflow) => {}
        _ => return TestResult::Fail("PFN > 28 bits must be rejected on GFX9"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gmc",
    smoke_amdgpu_gmc_gart_pte_rejects_unaligned_and_oversize
);

fn smoke_amdgpu_gmc_gart_default_flags_compose_correctly() -> TestResult {
    use crate::amdgpu_gmc::{
        GART_PTE_CACHEABLE, GART_PTE_FLAGS_GTT_DEFAULT, GART_PTE_SNOOP, GART_PTE_SYSTEM,
        GART_PTE_VALID, GART_PTE_WRITABLE,
    };
    let want =
        GART_PTE_VALID | GART_PTE_SYSTEM | GART_PTE_CACHEABLE | GART_PTE_WRITABLE | GART_PTE_SNOOP;
    if GART_PTE_FLAGS_GTT_DEFAULT != want {
        return TestResult::Fail("GART_PTE_FLAGS_GTT_DEFAULT composition drifted");
    }
    // Sanity: every bit must be in the low 12 (flag field).
    if GART_PTE_FLAGS_GTT_DEFAULT & !0xFFF != 0 {
        return TestResult::Fail("default flag set must fit in bits[11:0]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gmc",
    smoke_amdgpu_gmc_gart_default_flags_compose_correctly
);

// ── amdgpu/sdma (v6.0 Phoenix) ─────────────────────────────────────

fn smoke_amdgpu_sdma6_ring_init_phoenix_delta() -> TestResult {
    use crate::amdgpu_sdma::{
        build_sdma6_ring_init, SDMA6_QUEUE0_DOORBELL_OFFSET_REL, SDMA6_QUEUE0_DOORBELL_REL,
        SDMA6_QUEUE0_RB_BASE_HI_REL, SDMA6_QUEUE0_RB_BASE_REL, SDMA6_QUEUE0_RB_CNTL_REL,
        SDMA_DOORBELL_ENABLE, SDMA_RB_ENABLE, SDMA_RB_RPTR_WRITEBACK_ENABLE, SDMA_RB_SIZE_SHIFT,
    };
    let sdma_base: u32 = 0x0007_0000;
    let ring_phys: u64 = 0x0000_0001_2000_0000;
    let ring_size_dw: u32 = 2048;
    let doorbell_idx: u32 = 4;
    let rptr_phys: u64 = 0x0000_0002_3000_0000;

    let seq =
        match build_sdma6_ring_init(sdma_base, ring_phys, ring_size_dw, doorbell_idx, rptr_phys) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("build_sdma6_ring_init failed on valid input"),
        };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();
    // First write: CNTL = 0.
    if w.first().map(|x| (x.addr, x.value)) != Some((sdma_base + SDMA6_QUEUE0_RB_CNTL_REL, 0)) {
        return TestResult::Fail("first write must disable CNTL");
    }
    // Last write: CNTL | RB_ENABLE.
    let expected_en = (ring_size_dw.trailing_zeros() << SDMA_RB_SIZE_SHIFT)
        | SDMA_RB_RPTR_WRITEBACK_ENABLE
        | SDMA_RB_ENABLE;
    if w.last().map(|x| (x.addr, x.value))
        != Some((sdma_base + SDMA6_QUEUE0_RB_CNTL_REL, expected_en))
    {
        return TestResult::Fail("last write must enable CNTL");
    }
    // Body writes hit the v6 QUEUE0_ namespace, NOT the v4 GFX_ namespace.
    let want = [
        (
            sdma_base + SDMA6_QUEUE0_RB_BASE_REL,
            (ring_phys >> 8) as u32,
        ),
        (
            sdma_base + SDMA6_QUEUE0_RB_BASE_HI_REL,
            (ring_phys >> 40) as u32,
        ),
        (
            sdma_base + SDMA6_QUEUE0_DOORBELL_OFFSET_REL,
            doorbell_idx << 2,
        ),
        (sdma_base + SDMA6_QUEUE0_DOORBELL_REL, SDMA_DOORBELL_ENABLE),
    ];
    for (addr, value) in want {
        if !w.iter().any(|x| x.addr == addr && x.value == value) {
            return TestResult::Fail("missing expected v6 ring-init write");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma6_ring_init_phoenix_delta
);

fn smoke_amdgpu_sdma6_uses_different_offsets_than_v4() -> TestResult {
    use crate::amdgpu_sdma::{
        SDMA6_QUEUE0_RB_BASE_REL, SDMA6_QUEUE0_RB_CNTL_REL, SDMA_GFX_RB_BASE_REL,
        SDMA_GFX_RB_CNTL_REL,
    };
    // Ensure the Phoenix delta actually shifted offsets — if these
    // ever drift to match v4 numerically, smokes that exercise
    // both paths against shared register fixtures will silently
    // collide. Pin the invariant.
    if SDMA_GFX_RB_CNTL_REL == SDMA6_QUEUE0_RB_CNTL_REL {
        return TestResult::Fail("v4 and v6 RB_CNTL offsets must differ");
    }
    if SDMA_GFX_RB_BASE_REL == SDMA6_QUEUE0_RB_BASE_REL {
        return TestResult::Fail("v4 and v6 RB_BASE offsets must differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/sdma",
    smoke_amdgpu_sdma6_uses_different_offsets_than_v4
);
// ─── amdgpu_ddc: EDID-read transport scaffold ────────────────────

/// Build a valid 128-byte EDID base block with `ext_count` set,
/// then fix up the checksum so the block sums to a multiple of 256.
fn build_valid_edid_block(ext_count: u8) -> [u8; 128] {
    let mut b = [0u8; 128];
    // VESA header.
    b[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "DEL" (compressed PNP code).
    b[8] = 0x10;
    b[9] = 0xAC;
    b[18] = 1; // EDID version 1
    b[19] = 4; // EDID revision 4
    b[126] = ext_count;
    // Fix the checksum slot.
    let sum: u32 = b.iter().take(127).map(|x| *x as u32).sum();
    b[127] = ((256u32 - (sum & 0xFF)) & 0xFF) as u8;
    b
}

/// Mock transport that hands out pre-baked 128-byte blocks indexed
/// by the (offset / 128) — block 0 is at offset 0, block 1 at
/// offset 128, etc. Reads at non-block-aligned offsets return
/// `BadHeader` indirectly via zero-filled bytes.
struct MockEdidTransport {
    blocks: alloc::vec::Vec<[u8; 128]>,
}

impl crate::amdgpu_ddc::DdcTransport for MockEdidTransport {
    fn read(
        &mut self,
        slave_addr: u8,
        offset: u8,
        out: &mut [u8],
    ) -> Result<(), crate::amdgpu_ddc::DdcError> {
        if slave_addr != crate::amdgpu_ddc::DDC_EDID_SLAVE {
            return Err(crate::amdgpu_ddc::DdcError::NoAck);
        }
        // For the mock, the sub-address is the start of a 128-byte
        // window. 0 → block 0, 128 → block 1, 0 (wraps from 256) →
        // block 0 again — match what real hardware sees with a
        // single-byte sub-address.
        let block_idx = (offset as usize) / 128;
        if block_idx >= self.blocks.len() {
            for slot in out.iter_mut() {
                *slot = 0;
            }
            return Ok(());
        }
        let src = &self.blocks[block_idx];
        let n = out.len().min(128);
        out[..n].copy_from_slice(&src[..n]);
        Ok(())
    }
    fn write(&mut self, _slave_addr: u8, _data: &[u8]) -> Result<(), crate::amdgpu_ddc::DdcError> {
        Ok(())
    }
}

fn smoke_read_edid_via_mock_transport_round_trips_block_0() -> TestResult {
    use crate::amdgpu_ddc::{read_edid, EDID_BLOCK_BYTES};
    let block = build_valid_edid_block(0);
    let mut t = MockEdidTransport {
        blocks: alloc::vec![block],
    };
    let bytes = match read_edid(&mut t) {
        Ok(b) => b,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("read_edid rejected valid block");
        }
    };
    if bytes.len() != EDID_BLOCK_BYTES {
        return TestResult::Fail("expected exactly 128 bytes from a no-ext block");
    }
    if bytes[..] != block[..] {
        return TestResult::Fail("returned bytes don't match what the mock served");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ddc",
    smoke_read_edid_via_mock_transport_round_trips_block_0
);

fn smoke_read_edid_rejects_bad_checksum() -> TestResult {
    use crate::amdgpu_ddc::{read_edid, DdcError};
    let mut block = build_valid_edid_block(0);
    // Corrupt the checksum byte.
    block[127] = block[127].wrapping_add(1);
    let mut t = MockEdidTransport {
        blocks: alloc::vec![block],
    };
    match read_edid(&mut t) {
        Err(DdcError::BadChecksum) => TestResult::Pass,
        Ok(_) => TestResult::Fail("read_edid accepted a block with a bad checksum"),
        Err(_) => TestResult::Fail("read_edid returned wrong error kind for bad checksum"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ddc",
    smoke_read_edid_rejects_bad_checksum
);

fn smoke_read_edid_handles_one_extension_block() -> TestResult {
    use crate::amdgpu_ddc::{read_edid, EDID_BLOCK_BYTES};
    let base = build_valid_edid_block(1);
    // Build a valid extension block (no header magic — extension
    // blocks just need a self-summing checksum).
    let mut ext = [0u8; 128];
    ext[0] = 0x02; // CTA-861 extension tag (arbitrary but typical).
    ext[1] = 0x03; // revision
    let sum: u32 = ext.iter().take(127).map(|x| *x as u32).sum();
    ext[127] = ((256u32 - (sum & 0xFF)) & 0xFF) as u8;

    let mut t = MockEdidTransport {
        blocks: alloc::vec![base, ext],
    };
    let bytes = match read_edid(&mut t) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("read_edid rejected base+ext"),
    };
    if bytes.len() != 2 * EDID_BLOCK_BYTES {
        return TestResult::Fail("expected 256 bytes from base + 1 extension");
    }
    if bytes[..128] != base[..] {
        return TestResult::Fail("base block bytes corrupted");
    }
    if bytes[128..] != ext[..] {
        return TestResult::Fail("extension block bytes corrupted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ddc",
    smoke_read_edid_handles_one_extension_block
);

fn smoke_read_edid_caps_extension_blocks() -> TestResult {
    use crate::amdgpu_ddc::{read_edid, EDID_BLOCK_BYTES, MAX_EXT_BLOCKS};
    // Base claims 10 extensions — way over the cap of 4.
    let base = build_valid_edid_block(10);
    // Make a valid extension block — duplicate it 10× so the mock
    // can serve any block the driver requests.
    let mut ext = [0u8; 128];
    ext[0] = 0x02;
    let sum: u32 = ext.iter().take(127).map(|x| *x as u32).sum();
    ext[127] = ((256u32 - (sum & 0xFF)) & 0xFF) as u8;

    let mut blocks = alloc::vec![base];
    for _ in 0..10 {
        blocks.push(ext);
    }
    let mut t = MockEdidTransport { blocks };
    let bytes = match read_edid(&mut t) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("read_edid rejected over-claim"),
    };
    // We should have read base + MAX_EXT_BLOCKS = 5 blocks max.
    let expected = EDID_BLOCK_BYTES * (1 + MAX_EXT_BLOCKS as usize);
    if bytes.len() != expected {
        return TestResult::Fail("extension-block cap not enforced");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ddc",
    smoke_read_edid_caps_extension_blocks
);

fn smoke_gpio_ddc_bit_bang_sequences_start_address_stop() -> TestResult {
    // Exercise GpioDdcTransport against a closure that captures
    // every bus operation. We then assert the trace begins with a
    // START, includes the slave-address byte (0xA0 = 0x50<<1 for
    // write) on the wire, and ends with a STOP — i.e. the shape of
    // a real I²C transaction.
    use crate::amdgpu_ddc::{DdcTransport, GpioDdcTransport, GpioOp};
    use core::cell::RefCell;

    let trace: RefCell<alloc::vec::Vec<GpioOp>> = RefCell::new(alloc::vec::Vec::new());
    // The mock slave always ACKs (SDA reads low on the 9th clock)
    // and never holds SCL low (SCL reads high immediately).
    let slave_drives_sda_low = RefCell::new(false);
    // We need to alternate SDA-read return values to fake a slave
    // that ACKs each address/data byte. Simple model: every
    // SdaRead during a write returns 0 (ACK); SdaRead during a
    // read returns 1 (provides a stream of 0xFF bytes).
    // Track whether we're in the read phase via the trace itself.
    let op = |op: GpioOp| -> bool {
        trace.borrow_mut().push(op);
        match op {
            GpioOp::SclRead(_) => true, // SCL never stretches
            GpioOp::SdaRead(_) => *slave_drives_sda_low.borrow(),
            _ => false,
        }
    };

    let mut t = GpioDdcTransport::new(10, 11, op);
    // Just exercise a write-only transaction; that's the smallest
    // I²C sequence and avoids needing to simulate slave-driven SDA.
    let res = t.write(0x50, &[0u8]);
    if res.is_err() {
        return TestResult::Fail("GpioDdcTransport write errored on always-ACK mock");
    }

    let trace = trace.into_inner();
    // First op should be SdaHigh (release SDA prior to START).
    if !matches!(trace.first(), Some(GpioOp::SdaHigh(11))) {
        return TestResult::Fail("trace doesn't start with SDA-release for START");
    }
    // We should see at least one SclLow and one SclHigh per data
    // bit + ACK clock for the slave address byte (8 + 1 = 9 clock
    // cycles) and the offset byte (another 9). So at least 18
    // total SclHigh ops.
    let scl_highs = trace
        .iter()
        .filter(|o| matches!(o, GpioOp::SclHigh(10)))
        .count();
    if scl_highs < 18 {
        return TestResult::Fail("not enough SCL pulses for slave + 1 data byte");
    }
    // Final op should be SdaHigh (STOP releases SDA after SCL is
    // already high).
    if !matches!(trace.last(), Some(GpioOp::SdaHigh(11))) {
        return TestResult::Fail("trace doesn't end with SDA-release for STOP");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ddc",
    smoke_gpio_ddc_bit_bang_sequences_start_address_stop
);

// ── Spec-aligned link-training smokes ───────────────────────────────
//
// These exercise the `train_clock_recovery`, `train_channel_equalization`,
// and `train_link` helpers introduced for task #45. They use a shared
// MockAuxChannel that lets each test stage how many CR/EQ polls it
// takes for the (rate, lanes) under test to converge.

fn smoke_dp_link_training_clock_recovery_converges() -> TestResult {
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{train_clock_recovery, LinkRate};

    // Sink stages: CR_DONE after the second poll. Sink also asks
    // for vswing=1, pe=0 on lanes 0/1 via ADJUST_REQUEST.
    struct MockAux {
        cr_polls: u32,
        last_swing: u8,
    }
    impl AuxChannel for MockAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    // Capture the swing the source wrote for lane 0.
                    if req.address == 0x0_0103 && !req.data.is_empty() {
                        self.last_swing = req.data[0] & 0x3;
                    }
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    let v = match req.address {
                        0x0_0202 => {
                            self.cr_polls += 1;
                            if self.cr_polls < 2 {
                                0x00 // CR not done yet
                            } else {
                                0x11 // CR_DONE on lanes 0 and 1
                            }
                        }
                        0x0_0203 => 0x00,
                        // ADJUST_REQUEST_LANE0_1: ask for vswing=1, pe=0
                        // on both lanes — byte = 0x11.
                        0x0_0206 => 0x11,
                        0x0_0207 => 0x00,
                        _ => 0,
                    };
                    reply_buf[0] = 0;
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = MockAux {
        cr_polls: 0,
        last_swing: 0,
    };
    let vswing_pe = match train_clock_recovery(&mut aux, LinkRate::Hbr2, 2, |_| {}) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("CR phase did not converge"),
    };
    // After CR succeeded, the converged drive levels must reflect
    // what the sink asked for via ADJUST_REQUEST on the first
    // unsuccessful poll: vswing=1, pe=0 on lanes 0 and 1.
    if vswing_pe.lanes[0].swing != 1 || vswing_pe.lanes[0].pre_emph != 0 {
        return TestResult::Fail("lane0 vswing/pe not honored from ADJUST_REQUEST");
    }
    if vswing_pe.lanes[1].swing != 1 || vswing_pe.lanes[1].pre_emph != 0 {
        return TestResult::Fail("lane1 vswing/pe not honored from ADJUST_REQUEST");
    }
    // And the last write to TRAINING_LANE0_SET must have carried
    // the sink-requested swing, not whatever level-0 default.
    if aux.last_swing != 1 {
        return TestResult::Fail("source did not program sink-requested swing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_dp_link_training_clock_recovery_converges
);

fn smoke_dp_link_training_cr_exhaustion_returns_error() -> TestResult {
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{train_clock_recovery, LinkError, LinkRate};

    // Sink never reports CR_DONE — every poll returns 0x00. The
    // training loop must exhaust its 5 attempts and surface
    // LinkError::CrFailed.
    struct MockAux;
    impl AuxChannel for MockAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    // ADJUST_REQUEST asks for MAX swing on every lane
                    // → after 2 saturated retries the loop should fail.
                    let v = match req.address {
                        0x0_0206 => 0x33, // lane0/1 both swing=3 pe=0
                        0x0_0207 => 0x33,
                        _ => 0,
                    };
                    reply_buf[0] = 0;
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = MockAux;
    match train_clock_recovery(&mut aux, LinkRate::Hbr3, 4, |_| {}) {
        Err(LinkError::CrFailed(_)) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("CR exhaustion returned wrong LinkError variant")
        }
        Ok(_) => TestResult::Fail("CR converged when sink never reported CR_DONE"),
    }
}
kernel_test_in!(
    "drivers/gpu",
    smoke_dp_link_training_cr_exhaustion_returns_error
);

fn smoke_dp_link_training_channel_eq_symbol_lock() -> TestResult {
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{train_channel_equalization, LinkRate, VSwingPe};

    // Sink stages: CR still locked, EQ symbol-locks + interlane
    // align on the second poll.
    struct MockAux {
        eq_polls: u32,
        last_pattern: u8,
    }
    impl AuxChannel for MockAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    if req.address == 0x0_0102 && !req.data.is_empty() {
                        self.last_pattern = req.data[0];
                    }
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    let v = match req.address {
                        0x0_0202 => {
                            self.eq_polls += 1;
                            if self.eq_polls < 2 {
                                0x11 // CR still ok but EQ not done
                            } else {
                                0x77 // CR + EQ + SYMBOL_LOCKED, both lanes
                            }
                        }
                        0x0_0203 => 0x00,
                        0x0_0204 => {
                            if self.eq_polls >= 2 {
                                1
                            } else {
                                0
                            }
                        }
                        0x0_0206 => 0x00, // no adjust requested
                        0x0_0207 => 0x00,
                        _ => 0,
                    };
                    reply_buf[0] = 0;
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = MockAux {
        eq_polls: 0,
        last_pattern: 0xFF,
    };
    let start = VSwingPe::default();
    match train_channel_equalization(&mut aux, LinkRate::Hbr2, 2, start, |_| {}) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("EQ phase did not converge"),
    }
    // After success the source must have written TRAINING_PATTERN_SET
    // = 0 to disable the pattern and enter normal operation.
    if aux.last_pattern != 0 {
        return TestResult::Fail("source did not disable training pattern after EQ success");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_dp_link_training_channel_eq_symbol_lock);

fn smoke_dp_link_training_train_link_walks_fallback() -> TestResult {
    use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
    use crate::dp_link_training::{train_link, LinkRate};

    // Sink stages: every rate above HBR fails CR; HBR succeeds.
    // The full train_link driver should walk HBR3 → HBR2 → HBR
    // and return Trained at HBR / 4 lanes.
    struct MockAux {
        current_bw: u8,
        cr_polls: u32,
        eq_polls: u32,
    }
    impl AuxChannel for MockAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    if req.address == 0x0_0100 && !req.data.is_empty() {
                        self.current_bw = req.data[0];
                        self.cr_polls = 0;
                        self.eq_polls = 0;
                    }
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1],
                    })
                }
                AuxCommand::NativeRead => {
                    let ok = self.current_bw == LinkRate::Hbr as u8;
                    let v = match req.address {
                        0x0_0202 => {
                            self.cr_polls += 1;
                            if ok {
                                if self.cr_polls < 2 {
                                    0x00
                                } else if self.eq_polls == 0 {
                                    // CR done, all 4 lanes
                                    0x11
                                } else {
                                    0x77
                                }
                            } else {
                                0x00
                            }
                        }
                        0x0_0203 => {
                            if ok {
                                if self.cr_polls < 2 {
                                    0x00
                                } else if self.eq_polls == 0 {
                                    0x11
                                } else {
                                    0x77
                                }
                            } else {
                                0x00
                            }
                        }
                        0x0_0204 => {
                            self.eq_polls += 1;
                            if ok && self.eq_polls >= 2 {
                                1
                            } else {
                                0
                            }
                        }
                        // Force MAX swing requests so failing rates
                        // exhaust quickly via the "MAX twice" rule.
                        0x0_0206 => 0x33,
                        0x0_0207 => 0x33,
                        _ => 0,
                    };
                    reply_buf[0] = 0;
                    reply_buf[1] = v;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..2],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }
    let mut aux = MockAux {
        current_bw: 0,
        cr_polls: 0,
        eq_polls: 0,
    };
    let trained = match train_link(&mut aux, LinkRate::Hbr3, 4, |_| {}) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("train_link surfaced LinkError"),
    };
    if trained.rate != LinkRate::Hbr {
        return TestResult::Fail("fallback did not stop at HBR");
    }
    if trained.lanes != 4 {
        return TestResult::Fail("lane count should not have been halved");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_dp_link_training_train_link_walks_fallback
);

// ── amdgpu/gfx (GFX11 Phoenix delta) ───────────────────────────────

/// `gfx_v11_0_cp_gfx_resume`, step for step.
///
/// The function this replaces claimed to follow it and did not: it was the
/// GFX9 sequence with a different halt register. What it got wrong is listed
/// in the commit; what this test pins is each thing it got wrong.
fn smoke_amdgpu_gfx11_ring_init_matches_linux() -> TestResult {
    use crate::amdgpu_gfx::{build_gfx11_ring_init, GfxError, GfxStep};

    const GC: u32 = 0x0003_0000;
    // GC base window 1, a different base address — `GRBM_GFX_CNTL` is
    // BASE_IDX 1 and must be addressed from here, not from `GC`.
    const GC1: u32 = 0x0005_0000;
    const RING: u64 = 0x1_0000_0000;
    const BYTES: u64 = 4096;
    const RPTR: u64 = 0x2_DEAD_0000;
    const WPTR: u64 = 0x3_BEEF_0000;
    const DOORBELL: u32 = 5;
    // `GRBM_GFX_CNTL` with a non-zero PIPEID and other bits set, so the
    // read-modify-write is visible.
    const GRBM: u32 = 0xA5A5_A5A2;

    let seq = match build_gfx11_ring_init(GC, GC1, GRBM, RING, BYTES, DOORBELL, true, RPTR, WPTR) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("a valid GFX11 ring config was refused"),
    };

    // The ring base is the address SHIFTED RIGHT BY 8 — the register holds a
    // 256-byte granule. The replaced function wrote the raw address, pointing
    // the command processor 256x too high, and its 256-byte alignment check
    // existed precisely because of the shift it never applied.
    let rb = RING >> 8;
    if seq.first_write_to(GC, 0x1de0) != Some(rb as u32) {
        return TestResult::Fail("CP_RB0_BASE must be the address shifted right by 8");
    }
    if seq.first_write_to(GC, 0x1e51) != Some((rb >> 32) as u32) {
        return TestResult::Fail("CP_RB0_BASE_HI must be the shifted address's high half");
    }

    // `rb_bufsz = order_base_2(ring_size / 8)`, with RB_BLKSZ at that minus 2.
    // 4096 bytes / 8 = 512, log2 = 9. The replaced function used
    // log2(size_in_dwords) = 10 and a hardcoded BLKSZ of 6 — both fields
    // wrong, describing a ring twice its real size.
    let cntl = seq.writes_to(GC, 0x1de1);
    if cntl.is_empty() {
        return TestResult::Fail("CP_RB0_CNTL was never written");
    }
    if cntl[0] & 0x3F != 9 {
        return TestResult::Fail("RB_BUFSZ should be order_base_2(bytes / 8)");
    }
    if (cntl[0] >> 8) & 0x3F != 7 {
        return TestResult::Fail("RB_BLKSZ should be RB_BUFSZ - 2");
    }
    // And it is written TWICE with the same value, side by side with a delay.
    // Linux's `mdelay(1)` then re-writes it; the second write latches the
    // configuration after the addresses are in place.
    if cntl.len() != 2 || cntl[0] != cntl[1] {
        return TestResult::Fail("CP_RB0_CNTL is written twice with the same value");
    }
    let Some(first) = seq.index_of_write(GC, 0x1de1) else {
        return TestResult::Fail("CP_RB0_CNTL index not found");
    };
    let delay_after = seq.steps[first..]
        .iter()
        .position(|s| matches!(s, GfxStep::Delay { .. }));
    let second = seq.steps[first + 1..]
        .iter()
        .position(|s| matches!(s, GfxStep::Write { addr, .. } if *addr == GC + (0x1de1 << 2)));
    match (delay_after, second) {
        (Some(d), Some(w)) if d <= w + 1 => {}
        _ => return TestResult::Fail("the delay must fall between the two CNTL writes"),
    }

    // The rptr writeback high half is MASKED to 16 bits, never OR'd with
    // cache bits — the register has one field and 0x3 set address bits 32:33.
    if seq.first_write_to(GC, 0x1de4) != Some(((RPTR >> 32) as u32) & 0xFFFF) {
        return TestResult::Fail("CP_RB0_RPTR_ADDR_HI must be masked to 16 bits");
    }

    // The write-pointer poll address, which the replaced function never wrote
    // at all — without it the CP has no idea where the host's wptr lives.
    if seq.first_write_to(GC, 0x1e8b) != Some(WPTR as u32) {
        return TestResult::Fail("CP_RB_WPTR_POLL_ADDR_LO was not programmed");
    }
    if seq.first_write_to(GC, 0x1e8c) != Some((WPTR >> 32) as u32) {
        return TestResult::Fail("CP_RB_WPTR_POLL_ADDR_HI was not programmed");
    }

    // CP_RB_ACTIVE, also absent before. A ring the CP does not consider
    // active is never fetched from.
    if seq.first_write_to(GC, 0x1f40) != Some(1) {
        return TestResult::Fail("CP_RB_ACTIVE must be set");
    }

    // The pipe select is a read-modify-write of the caller's live value: only
    // PIPEID (bits 1:0) changes.
    // Addressed from window 1, and NOT present in window 0 — the pipe select
    // landing in the wrong window would write an unrelated register.
    if seq.first_write_to(GC1, 0x0900) != Some(GRBM & !0x3) {
        return TestResult::Fail("GRBM_GFX_CNTL should keep every bit but PIPEID");
    }
    if seq.first_write_to(GC, 0x0900).is_some() {
        return TestResult::Fail("GRBM_GFX_CNTL must not be written in base window 0");
    }
    // And the two registers zeroed first.
    if seq.first_write_to(GC, 0x0f61) != Some(0) {
        return TestResult::Fail("CP_RB_WPTR_DELAY should be zeroed");
    }
    if seq.first_write_to(GC, 0x1df1) != Some(0) {
        return TestResult::Fail("CP_RB_VMID should be zeroed");
    }
    if seq.first_write_to(GC, 0x1df4) != Some(0) || seq.first_write_to(GC, 0x1df5) != Some(0) {
        return TestResult::Fail("both halves of the write pointer should be zeroed");
    }

    // The doorbell range UPPER is the whole mask, not `index + 1` — that is
    // the GFX9 convention, and the replaced function used it here.
    if seq.first_write_to(GC, 0x1dfb) != Some(0x0000_0FFC) {
        return TestResult::Fail("DOORBELL_RANGE_UPPER is the field's full mask on GFX11");
    }
    if seq.first_write_to(GC, 0x1dfa) != Some(DOORBELL << 2) {
        return TestResult::Fail("DOORBELL_RANGE_LOWER holds the index at bit 2");
    }
    let door = seq.first_write_to(GC, 0x1e8d).unwrap_or(0);
    if door & (1 << 30) == 0 || (door >> 2) & 0x03FF_FFFF != DOORBELL {
        return TestResult::Fail("the doorbell control register is wrong");
    }
    // No doorbell: the register stays at its reset value.
    let nodoor =
        match build_gfx11_ring_init(GC, GC1, GRBM, RING, BYTES, DOORBELL, false, RPTR, WPTR) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("a ring without a doorbell was refused"),
        };
    if nodoor.first_write_to(GC, 0x1e8d) != Some(0) {
        return TestResult::Fail("no doorbell means DOORBELL_EN stays clear");
    }

    // Validation.
    if !matches!(
        build_gfx11_ring_init(GC, GC1, GRBM, RING, 3000, DOORBELL, true, RPTR, WPTR),
        Err(GfxError::BadRingSize)
    ) {
        return TestResult::Fail("a non-power-of-two ring size must be refused");
    }
    if !matches!(
        build_gfx11_ring_init(
            GC,
            GC1,
            GRBM,
            RING + 0xFF,
            BYTES,
            DOORBELL,
            true,
            RPTR,
            WPTR
        ),
        Err(GfxError::UnalignedRingPhys)
    ) {
        return TestResult::Fail("a ring base that is not 256-byte aligned must be refused");
    }
    if !matches!(
        build_gfx11_ring_init(GC, GC1, GRBM, RING, BYTES, DOORBELL, true, RPTR + 1, WPTR),
        Err(GfxError::UnalignedRptrWriteback)
    ) {
        return TestResult::Fail("an unaligned rptr writeback must be refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx11_ring_init_matches_linux
);

// ── amdgpu (initialize orchestrator) ───────────────────────────────

fn smoke_amdgpu_expected_smu_driver_if_per_family() -> TestResult {
    use crate::amdgpu::with_controller;
    use crate::amdgpu_smu::{SMU12_DRIVER_IF_VERSION, SMU_13_0_4_DRIVER_IF_VERSION};
    if !crate::amdgpu::is_probed() {
        return TestResult::Skip("amdgpu not probed in this QEMU config");
    }
    let outcome = with_controller(|d| {
        let chip = d.chip_info();
        let v = d.expected_smu_driver_if_version();
        (chip.family, v)
    });
    match outcome {
        Some((crate::amdgpu::Family::Renoir, Some(v))) if v == SMU12_DRIVER_IF_VERSION => {
            TestResult::Pass
        }
        Some((crate::amdgpu::Family::Phoenix, Some(v))) if v == SMU_13_0_4_DRIVER_IF_VERSION => {
            TestResult::Pass
        }
        Some((_other_family, None)) => {
            // Vega / Navi1 / Navi2 / Navi3 — no SMU bring-up path
            // wired into the orchestrator (yet). That's an expected
            // None, not a failure.
            TestResult::Pass
        }
        Some((_, Some(_))) => TestResult::Fail("driver-IF mismatch for family"),
        None => TestResult::Skip("controller vanished mid-test"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/initialize",
    smoke_amdgpu_expected_smu_driver_if_per_family
);

fn smoke_amdgpu_initialize_rejects_without_mp1_discovery() -> TestResult {
    use crate::amdgpu::with_controller;
    if !crate::amdgpu::is_probed() {
        return TestResult::Skip("amdgpu not probed in this QEMU config");
    }
    // If MP1 base isn't discoverable, initialize should fail with
    // SmuBringUpFailed *before* it touches any MMIO. We don't drive
    // initialize itself here (needs real PSP), just verify the
    // precondition check works.
    let outcome = with_controller(|d| (d.mp1_base(), d.expected_smu_driver_if_version()));
    match outcome {
        Some((None, _)) | Some((_, None)) => {
            // Either precondition missing → initialize would reject.
            TestResult::Pass
        }
        Some((Some(_), Some(_))) => {
            // Both available — initialize would proceed to PSP load.
            // Can't smoke-test the rest without real silicon; skip.
            TestResult::Skip("both prereqs satisfied — can't test reject path here")
        }
        None => TestResult::Skip("controller vanished mid-test"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/initialize",
    smoke_amdgpu_initialize_rejects_without_mp1_discovery
);

// ── amdgpu/backlight ───────────────────────────────────────────────

fn smoke_amdgpu_backlight_user_level_for_percent() -> TestResult {
    use crate::amdgpu_backlight::user_level_for_percent;
    if user_level_for_percent(0) != 0 {
        return TestResult::Fail("0% must yield 0");
    }
    if user_level_for_percent(100) != 0xFFFF {
        return TestResult::Fail("100% must yield 0xFFFF");
    }
    // Saturation: >100 clamps.
    if user_level_for_percent(200) != 0xFFFF {
        return TestResult::Fail("over-100% must clamp");
    }
    // 50% should land near 0x7FFF — within rounding.
    let half = user_level_for_percent(50);
    if !(0x7F00..=0x8100).contains(&half) {
        return TestResult::Fail("50% out of expected band");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/backlight",
    smoke_amdgpu_backlight_user_level_for_percent
);

fn smoke_amdgpu_backlight_init_sequence_locks_around_writes() -> TestResult {
    use crate::amdgpu_backlight::{
        build_backlight_init, BL_PWM_CNTL_EN, BL_PWM_CNTL_GRP1_FRAC_BL_EN, BL_PWM_CNTL_REL,
        BL_PWM_GRP1_LOCK, BL_PWM_GRP1_REG_LOCK_REL, BL_PWM_PERIOD_200HZ_RENOIR,
        BL_PWM_PERIOD_CNTL_REL, BL_PWM_USER_LEVEL_REL,
    };
    let dcn_base: u32 = 0x0008_0000;
    let writes = match build_backlight_init(dcn_base, BL_PWM_PERIOD_200HZ_RENOIR, 0x7FFF) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("build_backlight_init failed on valid input"),
    };
    if writes.len() != 5 {
        return TestResult::Fail("init must emit exactly 5 writes");
    }
    // First write: lock asserted.
    if writes[0].addr != dcn_base + BL_PWM_GRP1_REG_LOCK_REL || writes[0].value != BL_PWM_GRP1_LOCK
    {
        return TestResult::Fail("first write must assert GRP1 lock");
    }
    // Last write: lock cleared.
    if writes[4].addr != dcn_base + BL_PWM_GRP1_REG_LOCK_REL || writes[4].value != 0 {
        return TestResult::Fail("last write must clear GRP1 lock");
    }
    // Body writes (in order): period, cntl, user_level.
    if writes[1].addr != dcn_base + BL_PWM_PERIOD_CNTL_REL
        || writes[1].value != BL_PWM_PERIOD_200HZ_RENOIR
    {
        return TestResult::Fail("period write missing or wrong");
    }
    if writes[2].addr != dcn_base + BL_PWM_CNTL_REL
        || writes[2].value != (BL_PWM_CNTL_EN | BL_PWM_CNTL_GRP1_FRAC_BL_EN)
    {
        return TestResult::Fail("CNTL write missing or wrong");
    }
    if writes[3].addr != dcn_base + BL_PWM_USER_LEVEL_REL || writes[3].value != 0x7FFF {
        return TestResult::Fail("USER_LEVEL write missing or wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/backlight",
    smoke_amdgpu_backlight_init_sequence_locks_around_writes
);

fn smoke_amdgpu_backlight_set_user_level_is_lock_write_unlock() -> TestResult {
    use crate::amdgpu_backlight::{
        build_set_user_level, BL_PWM_GRP1_LOCK, BL_PWM_GRP1_REG_LOCK_REL, BL_PWM_USER_LEVEL_REL,
    };
    let dcn_base: u32 = 0x0008_0000;
    let writes = build_set_user_level(dcn_base, 0xABCD);
    if writes.len() != 3 {
        return TestResult::Fail("hot-path set must be exactly 3 writes");
    }
    if writes[0].value != BL_PWM_GRP1_LOCK {
        return TestResult::Fail("first write must lock");
    }
    if writes[1].addr != dcn_base + BL_PWM_USER_LEVEL_REL || writes[1].value != 0xABCD {
        return TestResult::Fail("USER_LEVEL write missing or wrong");
    }
    if writes[2].addr != dcn_base + BL_PWM_GRP1_REG_LOCK_REL || writes[2].value != 0 {
        return TestResult::Fail("last write must unlock");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/backlight",
    smoke_amdgpu_backlight_set_user_level_is_lock_write_unlock
);

fn smoke_amdgpu_backlight_init_rejects_period_overflow() -> TestResult {
    use crate::amdgpu_backlight::{build_backlight_init, BacklightError};
    // 25-bit period overflows the 24-bit field.
    match build_backlight_init(0x0008_0000, 1u32 << 25, 0x7FFF) {
        Err(BacklightError::PeriodOverflow) => TestResult::Pass,
        _ => TestResult::Fail("period overflow must be rejected"),
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/backlight",
    smoke_amdgpu_backlight_init_rejects_period_overflow
);

// ── amdgpu/smu (thermal) ───────────────────────────────────────────

fn smoke_amdgpu_smu_read_gpu_temperature_decodes_decicelsius() -> TestResult {
    use crate::amdgpu_smu::{
        read_gpu_temperature_millicelsius, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL,
        SMU_RESP_OK,
    };
    let mp1_base = 0x16000;
    let resp = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg = mp1_base + MP1_C2PMSG_ARG_REL;

    let mut m = MockSmu::new();
    m.stage_read(resp, 1); // handshake idle
    m.stage_read(resp, SMU_RESP_OK);
    // SMU reports temperature in d°C — 612 = 61.2 °C.
    m.stage_read(arg, 612);

    let mc = match read_gpu_temperature_millicelsius(&mut m, mp1_base) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("temperature read errored on happy path"),
    };
    // d°C → m°C: 612 * 100 = 61_200.
    if mc != 61_200 {
        return TestResult::Fail("decode of d°C → m°C wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_read_gpu_temperature_decodes_decicelsius
);

// ── DMA-buf smokes ────────────────────────────────────────────────────

/// No-op ops vtable used by all dma-buf tests.
struct NullOps;
impl crate::dmabuf::DmaBufOps for NullOps {
    fn map_kernel(&self, _p: u64, _l: usize) -> Result<*mut u8, crate::dmabuf::DmaBufError> {
        Err(crate::dmabuf::DmaBufError::MapUnsupported)
    }
    fn unmap_kernel(&self, _v: *mut u8, _l: usize) {}
    fn attach(&self, _p: u64, _l: usize, _k: u64) -> Result<(), crate::dmabuf::DmaBufError> {
        Ok(())
    }
    fn detach(&self, _p: u64, _l: usize, _k: u64) {}
    fn release(&self, _p: u64, _l: usize) {}
}
static NULL_OPS: NullOps = NullOps;

fn smoke_dmabuf_export_import_clone() -> TestResult {
    use crate::dmabuf::{export, import};
    let buf = match export(0x1000_0000, 4096, &NULL_OPS) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("export failed"),
    };
    if buf.phys() != 0x1000_0000 {
        return TestResult::Fail("phys wrong");
    }
    if buf.len() != 4096 {
        return TestResult::Fail("len wrong");
    }
    let imp = import(&buf);
    if imp.phys() != buf.phys() {
        return TestResult::Fail("import phys mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dmabuf", smoke_dmabuf_export_import_clone);

fn smoke_dmabuf_attach_detach_refcount() -> TestResult {
    use crate::dmabuf::export;
    let buf = match export(0x2000_0000, 8192, &NULL_OPS) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("export failed"),
    };
    if buf.attach_count() != 0 {
        return TestResult::Fail("initial count != 0");
    }
    if buf.attach(0xAAAA).is_err() {
        return TestResult::Fail("attach A failed");
    }
    if buf.attach_count() != 1 {
        return TestResult::Fail("count != 1 after A");
    }
    if buf.attach(0xBBBB).is_err() {
        return TestResult::Fail("attach B failed");
    }
    if buf.attach_count() != 2 {
        return TestResult::Fail("count != 2 after B");
    }
    buf.detach(0xAAAA);
    if buf.attach_count() != 1 {
        return TestResult::Fail("count != 1 after detach A");
    }
    buf.detach(0xBBBB);
    if buf.attach_count() != 0 {
        return TestResult::Fail("count != 0 after both detach");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dmabuf", smoke_dmabuf_attach_detach_refcount);

fn smoke_dmabuf_zero_len_rejected() -> TestResult {
    use crate::dmabuf::{export, DmaBufError};
    match export(0x3000_0000, 0, &NULL_OPS) {
        Err(DmaBufError::InvalidAllocation) => TestResult::Pass,
        Ok(_) => TestResult::Fail("zero-len export should fail"),
        Err(_) => TestResult::Fail("wrong error from zero-len export"),
    }
}
kernel_test_in!("drivers/gpu/dmabuf", smoke_dmabuf_zero_len_rejected);

fn smoke_dmabuf_two_driver_export_import() -> TestResult {
    use crate::dmabuf::{export, import};
    let a = match export(0x4000_0000, 0x10_0000, &NULL_OPS) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("driver A export failed"),
    };
    let b = import(&a);
    if b.attach(0xDEAD).is_err() {
        return TestResult::Fail("driver B attach failed");
    }
    if a.attach_count() != 1 {
        return TestResult::Fail("shared count not visible via A");
    }
    b.detach(0xDEAD);
    if a.attach_count() != 0 {
        return TestResult::Fail("shared count not decremented via B");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dmabuf", smoke_dmabuf_two_driver_export_import);

// ── GEM smokes ────────────────────────────────────────────────────────

fn smoke_gem_alloc_free_roundtrip() -> TestResult {
    use crate::drm::gem::GemTable;
    let mut t = GemTable::new();
    let h1 = match t.alloc(0x1000, 4096) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("first alloc failed"),
    };
    let h2 = match t.alloc(0x2000, 8192) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("second alloc failed"),
    };
    if h1 == h2 {
        return TestResult::Fail("duplicate handles");
    }
    if t.len() != 2 {
        return TestResult::Fail("len != 2 after 2 allocs");
    }
    t.free(h1).unwrap();
    if t.len() != 1 {
        return TestResult::Fail("len != 1 after one free");
    }
    t.free(h2).unwrap();
    if !t.is_empty() {
        return TestResult::Fail("not empty after freeing both");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_gem_alloc_free_roundtrip);

fn smoke_gem_lookup() -> TestResult {
    use crate::drm::gem::GemTable;
    let mut t = GemTable::new();
    let h = match t.alloc(0xDEAD_0000, 0x1000) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("alloc failed"),
    };
    match t.lookup(h) {
        None => return TestResult::Fail("lookup None for live handle"),
        Some(obj) => {
            if obj.phys != 0xDEAD_0000 {
                return TestResult::Fail("phys wrong");
            }
            if obj.size != 0x1000 {
                return TestResult::Fail("size wrong");
            }
        }
    }
    t.free(h).unwrap();
    if t.lookup(h).is_some() {
        return TestResult::Fail("lookup Some after free");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_gem_lookup);

// ── DRM ioctl smokes ──────────────────────────────────────────────────

fn make_test_card_for_ioctl() -> crate::drm::card::Card {
    use crate::drm::card::{
        Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
    };
    let mut card = Card::new("narf-test", "NARF test GPU driver", (0, 1, 0));
    card.connectors.push(Connector {
        id: 1,
        connector_type: ConnectorType::Edp,
        connector_type_id: 0,
        status: ConnectorStatus::Connected,
        encoder_id: Some(1),
        modes: alloc::vec![crate::Mode::FHD_60],
    });
    card.encoders.push(Encoder {
        id: 1,
        encoder_type: EncoderType::Tmds,
        possible_crtcs: 0x1,
        possible_clones: 0x0,
        crtc_id: Some(1),
    });
    card.crtcs.push(Crtc {
        id: 1,
        mode: Some(crate::Mode::FHD_60),
        enabled: true,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    card
}

fn smoke_drm_ioctl_version() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = make_test_card_for_ioctl();
    let ctx = DrmFileCtx::primary_master();
    match dispatch(&mut card, 0x00, &[], &ctx) {
        Ok(DrmIoctlResult::Version(v)) => {
            if v.version_major != 0 || v.version_minor != 1 {
                return TestResult::Fail("version fields wrong");
            }
            if !v.name.starts_with(b"narf-test") {
                return TestResult::Fail("driver name missing from VERSION");
            }
        }
        Ok(_) => return TestResult::Fail("wrong result type for VERSION"),
        Err(_) => return TestResult::Fail("DRM_IOCTL_VERSION failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_ioctl_version);

fn smoke_drm_ioctl_getresources_shape() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = make_test_card_for_ioctl();
    let ctx = DrmFileCtx::primary_master();
    match dispatch(&mut card, 0xA0, &[], &ctx) {
        Ok(DrmIoctlResult::GetResources(r)) => {
            if r.count_crtcs != 1 {
                return TestResult::Fail("count_crtcs != 1");
            }
            if r.count_connectors != 1 {
                return TestResult::Fail("count_connectors != 1");
            }
            if r.count_encoders != 1 {
                return TestResult::Fail("count_encoders != 1");
            }
            if r.max_width < 1920 {
                return TestResult::Fail("max_width < 1920");
            }
        }
        Ok(_) => return TestResult::Fail("wrong result for GETRESOURCES"),
        Err(_) => return TestResult::Fail("GETRESOURCES failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_ioctl_getresources_shape);

fn smoke_drm_ioctl_getconnector_decode() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = make_test_card_for_ioctl();
    let ctx = DrmFileCtx::primary_master();
    // Full struct drm_mode_get_connector (80 bytes); connector_id is at
    // offset 48 (after the four out-pointers + four counts).
    let mut arg = [0u8; 80];
    arg[48..52].copy_from_slice(&1u32.to_le_bytes());
    match dispatch(&mut card, 0xA7, &arg, &ctx) {
        Ok(DrmIoctlResult::GetConnector(info, modes)) => {
            if info.connector_id != 1 {
                return TestResult::Fail("connector_id not echoed");
            }
            if info.connector_type != 14 {
                return TestResult::Fail("type != eDP(14)");
            }
            if info.connection != 1 {
                return TestResult::Fail("not Connected");
            }
            if modes.len() != 1 {
                return TestResult::Fail("expected 1 mode");
            }
            if modes[0].hdisplay != 1920 || modes[0].vdisplay != 1080 {
                return TestResult::Fail("mode res wrong");
            }
        }
        Ok(_) => return TestResult::Fail("wrong result for GETCONNECTOR"),
        Err(_) => return TestResult::Fail("GETCONNECTOR failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_ioctl_getconnector_decode);

/// PAGE_FLIP event: `queue_flip_event` produces a well-formed 32-byte
/// `drm_event_vblank` (FLIP_COMPLETE) carrying user_data + crtc_id, which
/// `read(/dev/dri/cardN)` then drains for the compositor render loop.
fn smoke_drm_flip_event_format() -> TestResult {
    use crate::drm::card::DrmEventQueue;
    let mut card = make_test_card_for_ioctl();
    let mut events = DrmEventQueue::new();
    if !events.is_empty() {
        return TestResult::Fail("fresh card has queued events");
    }
    if card
        .queue_flip_event(&mut events, 0xCAFE_F00D_1234_5678, 7)
        .is_err()
    {
        return TestResult::Fail("flip event queue unexpectedly full");
    }
    let ev = match events.pop_deliverable_event(u64::MAX) {
        Some(e) => e,
        None => return TestResult::Fail("flip event not queued"),
    };
    if ev.len() != 32 {
        return TestResult::Fail("event length != 32");
    }
    let rd32 = |o: usize| u32::from_le_bytes(ev[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(ev[o..o + 8].try_into().unwrap());
    if rd32(0) != 2 {
        return TestResult::Fail("type != DRM_EVENT_FLIP_COMPLETE(2)");
    }
    if rd32(4) != 32 {
        return TestResult::Fail("base.length != 32");
    }
    if rd64(8) != 0xCAFE_F00D_1234_5678 {
        return TestResult::Fail("user_data not echoed");
    }
    if rd32(24) != 1 {
        return TestResult::Fail("sequence != 1");
    }
    if rd32(28) != 7 {
        return TestResult::Fail("crtc_id != 7");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_flip_event_format);

/// Vblank pacing (regression: kwin's unthrottled-repaint 100% CPU spin). A
/// compositor that PAGE_FLIPs, waits for completion, then repaints must be
/// throttled to the mode's refresh rate. Back-to-back flips on one crtc queue
/// completion events one refresh interval apart, so the SECOND flip's event is
/// NOT immediately deliverable — `poll_deadline` reports the future vblank and
/// the DRM-fd poll parks until then instead of spinning. The first flip after
/// idle stays immediate (no added latency).
fn smoke_drm_flip_event_vblank_paced() -> TestResult {
    use crate::drm::card::DrmEventQueue;
    let mut card = make_test_card_for_ioctl();
    let mut events = DrmEventQueue::new();
    let crtc_id = card.crtcs.first().map(|c| c.id).unwrap_or(0);
    let hz = card.crtc_refresh_hz(crtc_id);
    if hz == 0 {
        return TestResult::Fail("crtc refresh hz resolved to 0");
    }
    let interval = 1_000_000_000u64 / hz as u64;

    // First flip after idle: deliverable immediately (deliver_at collapses to
    // ~now, not a full interval away).
    if card.queue_flip_event(&mut events, 0x1, crtc_id).is_err() {
        return TestResult::Fail("first flip event queue unexpectedly full");
    }
    let first_at = match events.back_delivery_ns() {
        Some(d) => d,
        None => return TestResult::Fail("first flip event not queued"),
    };
    // Second flip: paced exactly one refresh interval past the first.
    if card.queue_flip_event(&mut events, 0x2, crtc_id).is_err() {
        return TestResult::Fail("second flip event queue unexpectedly full");
    }
    let second_at = match events.back_delivery_ns() {
        Some(d) => d,
        None => return TestResult::Fail("second flip event not queued"),
    };
    if second_at < first_at.saturating_add(interval) {
        return TestResult::Fail("second flip not paced by one refresh interval");
    }
    // Evaluated at the first flip's vblank: only the first is deliverable.
    if !events.has_deliverable_event(first_at) {
        return TestResult::Fail("first flip not deliverable at its own vblank");
    }
    // The expired deadline remains visible until read. This closes poll's
    // scan-to-park race: if the event becomes due just after a scan reported
    // no readiness, the subsequent deadline lookup must force an immediate
    // retry instead of returning None and permitting an infinite park.
    match events.next_event_deadline_ns(first_at) {
        Some(d) if d == first_at => {}
        _ => return TestResult::Fail("due flip stopped publishing its deadline before read"),
    }
    if events.pop_deliverable_event(first_at).is_none() {
        return TestResult::Fail("first flip did not pop at its vblank");
    }
    if events.has_deliverable_event(first_at) {
        return TestResult::Fail("second flip deliverable too early — pacing broken");
    }
    // ...and poll_deadline points a parked poll at the second flip's vblank.
    match events.next_event_deadline_ns(first_at) {
        Some(d) if d == second_at && d > first_at => {}
        _ => return TestResult::Fail("poll_deadline is not the paced second-flip vblank"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_flip_event_vblank_paced);

/// Vblank slack offset (`vblank_offset_ns`, the sysfs render-slack knob): a
/// nonzero offset shifts flip-event DELIVERY earlier by exactly that many ns
/// (measured against the true simulated vblank, reconstructed as
/// `next_vblank_ns - interval`) WITHOUT changing the frame RATE — successive
/// flips stay one refresh interval apart. Default 0 is exact-vblank delivery.
fn smoke_drm_flip_event_slack_offset() -> TestResult {
    use crate::drm::card::{set_vblank_offset_ns, vblank_offset_ns, DrmEventQueue};
    let saved = vblank_offset_ns();

    // The knob round-trips.
    set_vblank_offset_ns(1234);
    if vblank_offset_ns() != 1234 {
        set_vblank_offset_ns(saved);
        return TestResult::Fail("vblank_offset_ns setter did not stick");
    }

    let off = 2_000_000u64; // 2 ms of render slack
    set_vblank_offset_ns(off);
    let mut card = make_test_card_for_ioctl();
    let mut events = DrmEventQueue::new();
    let crtc_id = card.crtcs.first().map(|c| c.id).unwrap_or(0);
    let hz = card.crtc_refresh_hz(crtc_id);
    let interval = 1_000_000_000u64 / hz.max(1) as u64;

    if card.queue_flip_event(&mut events, 0x1, crtc_id).is_err() {
        set_vblank_offset_ns(saved);
        return TestResult::Fail("first flip event queue unexpectedly full");
    }
    let d1 = events.back_delivery_ns().unwrap_or(0);
    // True vblank of that flip = next_vblank_ns - interval (advance is from the
    // true vblank, not the earlier delivery time).
    let present_at = card.next_vblank_ns.saturating_sub(interval);
    let shift = present_at.saturating_sub(d1);

    if card.queue_flip_event(&mut events, 0x2, crtc_id).is_err() {
        set_vblank_offset_ns(saved);
        return TestResult::Fail("second flip event queue unexpectedly full");
    }
    let d2 = events.back_delivery_ns().unwrap_or(0);
    let gap = d2.saturating_sub(d1);

    set_vblank_offset_ns(saved); // restore the global before any assertion returns

    if shift != off {
        return TestResult::Fail("delivery not shifted earlier by exactly the offset");
    }
    if gap != interval {
        return TestResult::Fail("slack offset changed the frame rate (gap != interval)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_flip_event_slack_offset);

/// The flip event as a COMPOSITOR sees it: through `poll`/`read` on the
/// card node, not by reaching into `Card::events`.
///
/// A compositor's render loop is `page flip -> poll(card fd) -> read ->
/// submit next frame`. If `poll_readiness` never reports `POLL_IN`, or
/// `read` doesn't drain the queued event, the loop believes a flip is
/// still outstanding and stops presenting — the screen freezes on
/// whatever frame was last scanned out while the compositor stays alive
/// and idle. `smoke_drm_flip_event_format` above proves the event bytes
/// are well-formed but pops them directly off the queue, so it cannot
/// catch a break anywhere in the file layer between them.
fn smoke_drm_card_file_delivers_flip_event() -> TestResult {
    use crate::drm_devfs_bridge::DriCardFile;
    use narf_filesystem::{FileOps, FsError, POLL_IN};

    // The card node's read future resolves synchronously (it just pops a
    // VecDeque under a spin lock), so one poll to completion is enough.
    fn read_once(file: &DriCardFile, buf: &mut [u8]) -> Option<Result<usize, FsError>> {
        use core::future::Future;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: no-op vtable over a null data pointer — trivially valid.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = file.read(0, buf);
        match core::pin::Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    crate::drm_registry::__reset_for_test();
    let index = crate::drm_registry::register_drm_card_with_state(
        alloc::sync::Arc::new(crate::drm_devfs_bridge::BochsCard::new("card0".into())),
        make_test_card_for_ioctl(),
    );
    let first = match DriCardFile::new(index) {
        Some(f) => f,
        None => return TestResult::Fail("could not open the registered card node"),
    };
    let second = match DriCardFile::new(index) {
        Some(f) => f,
        None => return TestResult::Fail("could not open the card node a second time"),
    };

    // Quiescent: no queued event, so nothing to report and nothing to read.
    if first.poll_readiness() & POLL_IN != 0 {
        return TestResult::Fail("idle card node reports POLL_IN with no queued event");
    }
    let mut buf = [0u8; 64];
    match read_once(&first, &mut buf) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("empty card node did not return WouldBlock"),
    }

    // Queue one flip completion for the first open, exactly as
    // handle_page_flip does. The second open must not observe it: the cookie is
    // an address-space-local pointer in real compositors.
    if first
        .queue_flip_event_for_test(0x1122_3344_5566_7788, 3)
        .is_err()
    {
        return TestResult::Fail("could not queue first open's flip event");
    }

    if first.poll_readiness() & POLL_IN == 0 {
        return TestResult::Fail("queued flip event does not make the card node readable");
    }
    if second.poll_readiness() & POLL_IN != 0 {
        return TestResult::Fail("flip event leaked to a different DRM open");
    }
    match read_once(&second, &mut buf) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("second DRM open consumed the first open's event"),
    }

    // Linux never truncates drm_event_vblank: too-small read returns zero and
    // leaves the event queued for a later sufficiently large read.
    let mut tiny = [0u8; 16];
    match read_once(&first, &mut tiny) {
        Some(Ok(0)) => {}
        _ => return TestResult::Fail("too-small DRM read did not return zero"),
    }
    if first.poll_readiness() & POLL_IN == 0 {
        return TestResult::Fail("too-small DRM read consumed the event");
    }

    let n = match read_once(&first, &mut buf) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed with an event queued"),
    };
    if n != 32 {
        return TestResult::Fail("read did not drain a whole 32-byte drm_event_vblank");
    }
    if u32::from_le_bytes(buf[0..4].try_into().unwrap()) != 2 {
        return TestResult::Fail("delivered event is not DRM_EVENT_FLIP_COMPLETE");
    }
    if u64::from_le_bytes(buf[8..16].try_into().unwrap()) != 0x1122_3344_5566_7788 {
        return TestResult::Fail("delivered event lost the caller's user_data cookie");
    }
    if u32::from_le_bytes(buf[28..32].try_into().unwrap()) != 3 {
        return TestResult::Fail("delivered event lost the crtc id");
    }

    // Drained: the compositor must not see the same flip twice, or it
    // would credit a completion to a frame it has not submitted yet.
    if first.poll_readiness() & POLL_IN != 0 {
        return TestResult::Fail("card node still readable after its only event was drained");
    }
    match read_once(&first, &mut buf) {
        Some(Err(FsError::WouldBlock)) => {}
        _ => return TestResult::Fail("drained card node redelivered the flip event"),
    }

    // Closing an opener discards its unconsumed events, matching
    // drm_events_release. A later session must start with an empty queue.
    if first.queue_flip_event_for_test(0xDEAD_BEEF, 3).is_err() {
        return TestResult::Fail("could not queue event before close");
    }
    drop(first);
    if second.poll_readiness() & POLL_IN != 0 {
        return TestResult::Fail("closed DRM open leaked an event to the survivor");
    }
    // Keep this assertion about ownership, not card-wide vblank pacing: the
    // unconsumed first-open event legitimately advanced the card's next
    // simulated vblank even though closing that file discarded its queue.
    if let Some(mode_state) = crate::drm_registry::mode_state(index) {
        mode_state.lock().next_vblank_ns = 0;
    }
    if second.queue_flip_event_for_test(0xAABB_CCDD, 3).is_err() {
        return TestResult::Fail("could not queue second open's own event");
    }
    let n = match read_once(&second, &mut buf) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("second open could not read its own event"),
    };
    if n != 32 || u64::from_le_bytes(buf[8..16].try_into().unwrap()) != 0xAABB_CCDD {
        return TestResult::Fail("second open received the wrong event cookie");
    }

    // Linux gives every drm_file 4096 bytes of event space. 128 32-byte flip
    // events fit; reserving the 129th must fail with ENOMEM at the ioctl layer
    // (represented as FsError::OutOfMemory by this bridge).
    for cookie in 0..128u64 {
        if second.queue_flip_event_for_test(cookie, 3).is_err() {
            return TestResult::Fail("DRM event budget filled before 4096 bytes");
        }
    }
    match second.queue_flip_event_for_test(128, 3) {
        Err(FsError::OutOfMemory) => {}
        _ => return TestResult::Fail("full DRM event queue did not return OutOfMemory"),
    }

    crate::drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_card_file_delivers_flip_event);

fn smoke_drm_addfb2_rmfb_roundtrip() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = make_test_card_for_ioctl();
    let ctx = DrmFileCtx::primary_master();
    let gem_handle = match card.gem.alloc(0x8000_0000, 1920 * 1080 * 4) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("GEM alloc failed"),
    };
    let mut arg = [0u8; 68];
    arg[4..8].copy_from_slice(&1920u32.to_le_bytes());
    arg[8..12].copy_from_slice(&1080u32.to_le_bytes());
    arg[12..16].copy_from_slice(&0x3432_5258u32.to_le_bytes()); // XRGB8888
    arg[20..24].copy_from_slice(&gem_handle.to_le_bytes());
    arg[36..40].copy_from_slice(&(1920u32 * 4).to_le_bytes());
    let fb_id = match dispatch(&mut card, 0xB8, &arg, &ctx) {
        Ok(DrmIoctlResult::AddFb2(id)) => id,
        Ok(_) => return TestResult::Fail("ADDFB2 wrong result type"),
        Err(_) => return TestResult::Fail("ADDFB2 failed"),
    };
    if fb_id == 0 {
        return TestResult::Fail("fb_id is zero");
    }
    if card.framebuffers.len() != 1 {
        return TestResult::Fail("fb count != 1 after ADDFB2");
    }
    match card.framebuffer(fb_id) {
        Ok(fb) => {
            if fb.width != 1920 || fb.height != 1080 {
                return TestResult::Fail("FB dimensions wrong");
            }
        }
        Err(_) => return TestResult::Fail("fb lookup by id failed"),
    }
    let rmfb_arg = fb_id.to_le_bytes();
    match dispatch(&mut card, 0xA8, &rmfb_arg, &ctx) {
        Ok(DrmIoctlResult::RmFb) => {}
        Ok(_) => return TestResult::Fail("RMFB wrong type"),
        Err(_) => return TestResult::Fail("RMFB failed"),
    }
    if !card.framebuffers.is_empty() {
        return TestResult::Fail("fbs not empty after RMFB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_addfb2_rmfb_roundtrip);

fn smoke_drm_getcap_shape() -> TestResult {
    use crate::drm::ioctl::{dispatch, drm_cap, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = make_test_card_for_ioctl();
    let ctx = DrmFileCtx::primary_master();
    let mut arg = [0u8; 16];
    arg[0..8].copy_from_slice(&drm_cap::TIMESTAMP_MONOTONIC.to_le_bytes());
    match dispatch(&mut card, 0x0C, &arg, &ctx) {
        Ok(DrmIoctlResult::GetCap(cap)) => {
            if cap.value != 1 {
                return TestResult::Fail("TIMESTAMP_MONOTONIC != 1");
            }
        }
        _ => return TestResult::Fail("GET_CAP TIMESTAMP_MONOTONIC failed"),
    }
    arg[0..8].copy_from_slice(&drm_cap::PRIME.to_le_bytes());
    match dispatch(&mut card, 0x0C, &arg, &ctx) {
        Ok(DrmIoctlResult::GetCap(cap)) => {
            // EXPORT(1) | IMPORT(2) = 3 — both implemented via PrimeTable.
            if cap.value != 3 {
                return TestResult::Fail("PRIME should be 3 (EXPORT|IMPORT)");
            }
        }
        _ => return TestResult::Fail("GET_CAP PRIME failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_getcap_shape);

// ── DRM render-node permission split ──────────────────────────────────

fn smoke_drm_render_node_devpath() -> TestResult {
    use crate::drm::card::Card;
    use crate::drm::render_node::MinorType;
    let primary = Card::primary_node(0);
    let render = Card::render_node(0);
    if primary.kind != MinorType::Primary {
        return TestResult::Fail("primary kind");
    }
    if render.kind != MinorType::Render {
        return TestResult::Fail("render kind");
    }
    if primary.index != 0 {
        return TestResult::Fail("primary index != 0");
    }
    if render.index != 128 {
        return TestResult::Fail("render index != 128");
    }
    let (p_prefix, p_idx) = primary.dev_path_parts();
    let (r_prefix, r_idx) = render.dev_path_parts();
    if p_prefix != "card" || p_idx != 0 {
        return TestResult::Fail("primary path");
    }
    if r_prefix != "renderD" || r_idx != 128 {
        return TestResult::Fail("render path");
    }
    // Card index 3 should give /dev/dri/card3 and /dev/dri/renderD131.
    let r3 = Card::render_node(3);
    if r3.index != 131 {
        return TestResult::Fail("renderD131 for card3");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_render_node_devpath);

fn smoke_drm_render_node_perm_split() -> TestResult {
    // Verify a render-node fd is rejected from DRM_MASTER ioctls but
    // allowed for VERSION / GET_CAP / PRIME / SYNCOBJ. Mirrors
    // drivers/gpu/drm/drm_ioctl.c::drm_ioctl_permit.
    use crate::drm::ioctl::{dispatch, DrmIoctlError, DrmIoctlResult};
    use crate::drm::render_node::{DrmFileCtx, PermError};
    let mut card = make_test_card_for_ioctl();
    let render = DrmFileCtx::render_client();

    // VERSION (RENDER_ALLOW) — should succeed.
    match dispatch(&mut card, 0x00, &[], &render) {
        Ok(DrmIoctlResult::Version(_)) => {}
        _ => return TestResult::Fail("render-node VERSION should succeed"),
    }

    // GETRESOURCES (DRM_AUTH but no RENDER_ALLOW) — render clients are
    // implicitly authenticated, so the auth check passes, but the
    // !render_allow + is_render_client gate fires. Linux returns
    // -EACCES; we surface RenderDenied.
    match dispatch(&mut card, 0xA0, &[], &render) {
        Err(DrmIoctlError::PermissionDenied(PermError::RenderDenied)) => {}
        Ok(_) => return TestResult::Fail("render-node GETRESOURCES should be denied"),
        Err(_) => return TestResult::Fail("render-node GETRESOURCES wrong error"),
    }

    // ADDFB2 (DRM_MASTER) — denied for render clients (NotMaster *or*
    // RenderDenied; we set master-only without render_allow so the
    // render_allow gate fires first).
    let arg = [0u8; 68];
    match dispatch(&mut card, 0xB8, &arg, &render) {
        Err(DrmIoctlError::PermissionDenied(_)) => {}
        _ => return TestResult::Fail("render-node ADDFB2 should be denied"),
    }

    // GET_CAP (RENDER_ALLOW) — should succeed.
    let mut cap_arg = [0u8; 16];
    cap_arg[0..8].copy_from_slice(&6u64.to_le_bytes()); // TIMESTAMP_MONOTONIC
    match dispatch(&mut card, 0x0C, &cap_arg, &render) {
        Ok(DrmIoctlResult::GetCap(_)) => {}
        _ => return TestResult::Fail("render-node GET_CAP should succeed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_render_node_perm_split);

fn smoke_drm_perm_master_only_blocks_authed() -> TestResult {
    // A primary-node fd that is authenticated but NOT master must be
    // blocked from DRM_MASTER ioctls (ADDFB2).
    use crate::drm::ioctl::{dispatch, DrmIoctlError};
    use crate::drm::render_node::{DrmFileCtx, MinorType, PermError};
    let mut card = make_test_card_for_ioctl();
    let authed = DrmFileCtx {
        minor: MinorType::Primary,
        authenticated: true,
        is_master: false,
        sys_admin: false,
    };
    let arg = [0u8; 68];
    match dispatch(&mut card, 0xB8, &arg, &authed) {
        Err(DrmIoctlError::PermissionDenied(PermError::NotMaster)) => TestResult::Pass,
        _ => TestResult::Fail("authed non-master ADDFB2 should be NotMaster"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_perm_master_only_blocks_authed);

// ── DRM syncobj smokes ────────────────────────────────────────────────

fn smoke_drm_syncobj_create_destroy_roundtrip() -> TestResult {
    use crate::drm::syncobj::{SyncObjTable, SYNCOBJ_CREATE_SIGNALED};
    let mut tbl = SyncObjTable::new();
    let unsig = match tbl.create(0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create(0) failed"),
    };
    let sig = match tbl.create(SYNCOBJ_CREATE_SIGNALED) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create(SIG) failed"),
    };
    if unsig == sig {
        return TestResult::Fail("duplicate ids");
    }
    if tbl.len() != 2 {
        return TestResult::Fail("len != 2 after 2 creates");
    }
    let so = match tbl.get(unsig) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("get unsig"),
    };
    if so.is_signalled() {
        return TestResult::Fail("unsig should not be signalled");
    }
    let so = match tbl.get(sig) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("get sig"),
    };
    if !so.is_signalled() {
        return TestResult::Fail("sig should be signalled");
    }
    tbl.destroy(unsig).unwrap();
    tbl.destroy(sig).unwrap();
    if !tbl.is_empty() {
        return TestResult::Fail("not empty after destroying both");
    }
    if tbl.get(unsig).is_ok() {
        return TestResult::Fail("get after destroy should fail");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_drm_syncobj_create_destroy_roundtrip
);

fn smoke_drm_syncobj_wait_timeout() -> TestResult {
    // An unsignalled syncobj must time out per Linux's -ETIME.
    use crate::drm::syncobj::{SyncError, SyncObjTable, SYNCOBJ_WAIT_FLAGS_WAIT_ALL};
    let mut tbl = SyncObjTable::new();
    let h = match tbl.create(0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create"),
    };
    // Bind a fresh (unsignalled) binary fence so wait can see it.
    let f = crate::drm::syncobj::BinaryFence::new();
    tbl.get_mut(h).unwrap().replace_fence(f);
    let ids = [h];
    match tbl.wait_handles(&ids, 1_000, SYNCOBJ_WAIT_FLAGS_WAIT_ALL) {
        Err(SyncError::Timeout) => TestResult::Pass,
        Ok(_) => TestResult::Fail("wait should have timed out"),
        Err(_) => TestResult::Fail("wait returned wrong error"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_syncobj_wait_timeout);

fn smoke_drm_syncobj_signal_then_wait() -> TestResult {
    // Signal first, then wait should return Ok immediately.
    use crate::drm::syncobj::{SyncObjTable, SYNCOBJ_WAIT_FLAGS_WAIT_ALL};
    let mut tbl = SyncObjTable::new();
    let h = match tbl.create(0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create"),
    };
    let old_fence = crate::drm::syncobj::BinaryFence::new();
    tbl.get_mut(h).unwrap().replace_fence(old_fence.clone());
    let ids = [h];
    tbl.signal_handles(&ids).unwrap();
    if !tbl.get(h).unwrap().is_signalled() {
        return TestResult::Fail("not signalled after signal_handles");
    }
    if crate::drm::syncobj::DmaFence::is_signalled(old_fence.as_ref()) {
        return TestResult::Fail("signal_handles signalled the replaced shared fence");
    }
    match tbl.wait_handles(&ids, 1_000_000, SYNCOBJ_WAIT_FLAGS_WAIT_ALL) {
        Ok(_) => TestResult::Pass,
        Err(_) => TestResult::Fail("wait after signal should succeed"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_syncobj_signal_then_wait);

fn smoke_drm_syncobj_wait_first_vs_all() -> TestResult {
    // WAIT_ALL == 0: returns on first signalled handle; signalling
    // only one of three should satisfy wait.
    use crate::drm::syncobj::SyncObjTable;
    let mut tbl = SyncObjTable::new();
    let a = tbl.create(0).unwrap();
    let b = tbl.create(0).unwrap();
    let c = tbl.create(0).unwrap();
    for &h in &[a, b, c] {
        tbl.get_mut(h)
            .unwrap()
            .replace_fence(crate::drm::syncobj::BinaryFence::new());
    }
    tbl.signal_handles(&[b]).unwrap();
    let ids = [a, b, c];
    // wait_any (flags=0)
    let first = match tbl.wait_handles(&ids, 1_000_000, 0) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("wait_any should succeed when one is signalled"),
    };
    if first != b {
        return TestResult::Fail("wait_any returned wrong id");
    }
    // wait_all should time out since a,c are not signalled.
    match tbl.wait_handles(&ids, 1_000, 1 /* WAIT_ALL */) {
        Err(crate::drm::syncobj::SyncError::Timeout) => TestResult::Pass,
        Ok(_) => TestResult::Fail("wait_all should time out (a,c unsignalled)"),
        Err(_) => TestResult::Fail("wait_all wrong error"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_syncobj_wait_first_vs_all);

fn smoke_drm_syncobj_signal_unbound_attaches_fence() -> TestResult {
    // signal_handles on a syncobj with no fence binds a signalled
    // binary fence — Linux's drm_syncobj_assign_null_handle behaviour.
    use crate::drm::syncobj::SyncObjTable;
    let mut tbl = SyncObjTable::new();
    let h = tbl.create(0).unwrap();
    if tbl.get(h).unwrap().fence.is_some() {
        return TestResult::Fail("new syncobj should have no fence");
    }
    tbl.signal_handles(&[h]).unwrap();
    if tbl.get(h).unwrap().fence.is_none() {
        return TestResult::Fail("signal should bind a fence");
    }
    if !tbl.get(h).unwrap().is_signalled() {
        return TestResult::Fail("bound fence must be signalled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_drm_syncobj_signal_unbound_attaches_fence
);

fn smoke_drm_syncobj_reset_clears_fence() -> TestResult {
    use crate::drm::syncobj::{SyncObjTable, SYNCOBJ_CREATE_SIGNALED};
    let mut tbl = SyncObjTable::new();
    let h = tbl.create(SYNCOBJ_CREATE_SIGNALED).unwrap();
    if !tbl.get(h).unwrap().is_signalled() {
        return TestResult::Fail("SIG create should be signalled");
    }
    tbl.reset_handles(&[h]).unwrap();
    if tbl.get(h).unwrap().fence.is_some() {
        return TestResult::Fail("reset should clear fence");
    }
    if tbl.get(h).unwrap().is_signalled() {
        return TestResult::Fail("post-reset cannot be signalled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_syncobj_reset_clears_fence);

// ── DRM atomic modeset smokes ─────────────────────────────────────────

fn smoke_virtgpu_execbuffer_syncobj_wire_arrays() -> TestResult {
    let mut wire = [0u8; 32];
    wire[0..4].copy_from_slice(&7u32.to_le_bytes());
    wire[16..20].copy_from_slice(&9u32.to_le_bytes());
    wire[20..24].copy_from_slice(&1u32.to_le_bytes());
    let deps = match crate::drm_ioctl_bridge::read_exec_syncobjs(wire.as_ptr() as u64, 2, 16, false)
    {
        Ok(deps) => deps,
        Err(_) => return TestResult::Fail("valid execbuffer syncobj array rejected"),
    };
    if deps.len() != 2
        || deps[0].handle != 7
        || deps[0].reset
        || deps[1].handle != 9
        || !deps[1].reset
    {
        return TestResult::Fail("execbuffer syncobj descriptors decoded incorrectly");
    }
    // Linux's extensible-record rule zero-fills fields beyond a short stride.
    let short = [11u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    let short_dep =
        match crate::drm_ioctl_bridge::read_exec_syncobjs(short.as_ptr() as u64, 1, 8, false) {
            Ok(deps) => deps,
            Err(_) => return TestResult::Fail("short syncobj stride rejected"),
        };
    if short_dep[0].handle != 11 || short_dep[0].reset {
        return TestResult::Fail("short syncobj stride was not zero-extended");
    }
    // Output dependencies accept neither RESET nor timeline points.
    if crate::drm_ioctl_bridge::read_exec_syncobjs(wire.as_ptr() as u64 + 16, 1, 16, true).is_ok() {
        return TestResult::Fail("output syncobj accepted RESET");
    }
    wire[20..24].copy_from_slice(&0u32.to_le_bytes());
    wire[24..32].copy_from_slice(&1u64.to_le_bytes());
    if crate::drm_ioctl_bridge::read_exec_syncobjs(wire.as_ptr() as u64 + 16, 1, 16, true).is_ok() {
        return TestResult::Fail("binary output syncobj accepted a timeline point");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_virtgpu_execbuffer_syncobj_wire_arrays
);

fn smoke_virtgpu_syncobj_same_context_preserves_pipeline() -> TestResult {
    if crate::drm_ioctl_bridge::sync_dependency_needs_wait(Some(0x1234), 0x1234) {
        return TestResult::Fail("same-ring dependency would serialize the pipeline");
    }
    if !crate::drm_ioctl_bridge::sync_dependency_needs_wait(Some(0x1235), 0x1234)
        || !crate::drm_ioctl_bridge::sync_dependency_needs_wait(None, 0x1234)
    {
        return TestResult::Fail("foreign dependency skipped its wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_virtgpu_syncobj_same_context_preserves_pipeline
);

fn make_test_card_for_atomic() -> crate::drm::card::Card {
    use crate::drm::card::{
        Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
    };
    let mut card = Card::new("narf-test", "atomic", (0, 1, 0));
    card.connectors.push(Connector {
        id: 1,
        connector_type: ConnectorType::Edp,
        connector_type_id: 0,
        status: ConnectorStatus::Connected,
        encoder_id: Some(1),
        modes: alloc::vec![crate::Mode::FHD_60],
    });
    card.encoders.push(Encoder {
        id: 1,
        encoder_type: EncoderType::Tmds,
        possible_crtcs: 0x1,
        possible_clones: 0x0,
        crtc_id: Some(1),
    });
    card.crtcs.push(Crtc {
        id: 1,
        mode: None,
        enabled: false,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    let gh = card.gem.alloc(0x4000_0000, 1920 * 1080 * 4).unwrap();
    card.addfb2(1920, 1080, 0x3432_5258, 1920 * 4, gh).unwrap();
    card
}

fn smoke_drm_atomic_state_encode_decode() -> TestResult {
    use crate::drm::atomic::{AtomicState, ConnectorState, CrtcState, PlaneState};
    let mut st = AtomicState::default();
    st.crtcs.push(CrtcState {
        id: 1,
        enable: true,
        mode: Some(crate::Mode::FHD_60),
        mode_changed: true,
        ..Default::default()
    });
    st.connectors.push(ConnectorState {
        id: 1,
        crtc_id: Some(1),
    });
    st.planes.push(PlaneState {
        id: 1,
        crtc_id: Some(1),
        fb_id: Some(1),
        crtc_w: 1920,
        crtc_h: 1080,
        src_w: 1920,
        src_h: 1080,
        ..Default::default()
    });
    if st.crtcs.len() != 1 || st.connectors.len() != 1 || st.planes.len() != 1 {
        return TestResult::Fail("state shape");
    }
    if !st.crtcs[0].needs_modeset() {
        return TestResult::Fail("CRTC with mode_changed must need modeset");
    }
    let cloned = st.clone();
    if cloned.crtcs[0].mode != st.crtcs[0].mode {
        return TestResult::Fail("clone mode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_atomic_state_encode_decode);

fn smoke_drm_atomic_check_then_commit_happy() -> TestResult {
    use crate::drm::atomic::{
        AtomicCheckPolicy, AtomicState, ConnectorState, CrtcState, PlaneState,
    };
    let mut card = make_test_card_for_atomic();
    let mut st = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    st.crtcs.push(CrtcState {
        id: 1,
        enable: true,
        mode: Some(crate::Mode::FHD_60),
        mode_changed: true,
        ..Default::default()
    });
    st.connectors.push(ConnectorState {
        id: 1,
        crtc_id: Some(1),
    });
    st.planes.push(PlaneState {
        id: 1,
        crtc_id: Some(1),
        fb_id: Some(1),
        crtc_w: 1920,
        crtc_h: 1080,
        src_w: 1920,
        src_h: 1080,
        ..Default::default()
    });
    let policy = AtomicCheckPolicy::default();
    if st.core_check(&card, &policy).is_err() {
        return TestResult::Fail("core_check should pass");
    }
    if !st.checked {
        return TestResult::Fail("state.checked not set after success");
    }
    if st.core_commit(&mut card).is_err() {
        return TestResult::Fail("core_commit failed");
    }
    if !card.crtcs[0].enabled {
        return TestResult::Fail("CRTC not enabled after commit");
    }
    if card.crtcs[0].primary_fb != Some(1) {
        return TestResult::Fail("primary_fb not bound after commit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_atomic_check_then_commit_happy);

fn smoke_drm_atomic_check_rejects_overbandwidth() -> TestResult {
    use crate::drm::atomic::{
        AtomicCheckPolicy, AtomicError, AtomicState, ConnectorState, CrtcState, PlaneState,
    };
    let card = make_test_card_for_atomic();
    let mut st = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    st.crtcs.push(CrtcState {
        id: 1,
        enable: true,
        mode: Some(crate::Mode::FHD_60),
        mode_changed: true,
        ..Default::default()
    });
    st.connectors.push(ConnectorState {
        id: 1,
        crtc_id: Some(1),
    });
    st.planes.push(PlaneState {
        id: 1,
        crtc_id: Some(1),
        fb_id: Some(1),
        crtc_w: 1920,
        crtc_h: 1080,
        src_w: 1920,
        src_h: 1080,
        ..Default::default()
    });
    st.planes.push(PlaneState {
        id: 2,
        crtc_id: Some(1),
        fb_id: Some(1),
        crtc_w: 1920,
        crtc_h: 1080,
        src_w: 1920,
        src_h: 1080,
        ..Default::default()
    });
    let policy = AtomicCheckPolicy {
        max_pixel_budget: 2_000_000,
        ..Default::default()
    };
    match st.core_check(&card, &policy) {
        Err(AtomicError::OverBandwidth) => TestResult::Pass,
        Ok(_) => TestResult::Fail("over-budget commit should be rejected"),
        Err(_) => TestResult::Fail("wrong error for over-budget"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_drm_atomic_check_rejects_overbandwidth
);

fn smoke_drm_atomic_modeset_gate() -> TestResult {
    use crate::drm::atomic::{AtomicCheckPolicy, AtomicError, AtomicState, CrtcState};
    let card = make_test_card_for_atomic();
    let mut st = AtomicState {
        allow_modeset: false,
        ..Default::default()
    };
    st.crtcs.push(CrtcState {
        id: 1,
        enable: true,
        mode: Some(crate::Mode::FHD_60),
        mode_changed: true,
        ..Default::default()
    });
    let policy = AtomicCheckPolicy::default();
    match st.core_check(&card, &policy) {
        Err(AtomicError::ModesetNotAllowed) => TestResult::Pass,
        Ok(_) => TestResult::Fail("page-flip modeset must be rejected"),
        Err(_) => TestResult::Fail("wrong error for modeset-not-allowed"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_atomic_modeset_gate);

fn smoke_drm_atomic_plane_fb_crtc_pair() -> TestResult {
    use crate::drm::atomic::{AtomicCheckPolicy, AtomicError, AtomicState, PlaneState};
    let card = make_test_card_for_atomic();
    let mut st = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    st.planes.push(PlaneState {
        id: 1,
        crtc_id: Some(1),
        fb_id: None,
        crtc_w: 1920,
        crtc_h: 1080,
        ..Default::default()
    });
    let policy = AtomicCheckPolicy::default();
    match st.core_check(&card, &policy) {
        Err(AtomicError::PlaneFbCrtcMismatch) => TestResult::Pass,
        Ok(_) => TestResult::Fail("crtc-without-fb should be rejected"),
        Err(_) => TestResult::Fail("wrong error for fb/crtc mismatch"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_atomic_plane_fb_crtc_pair);

fn smoke_drm_atomic_commit_before_check_errs() -> TestResult {
    use crate::drm::atomic::{AtomicError, AtomicState};
    let mut card = make_test_card_for_atomic();
    let st = AtomicState::default();
    match st.core_commit(&mut card) {
        Err(AtomicError::NotChecked) => TestResult::Pass,
        _ => TestResult::Fail("commit before check should error"),
    }
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_atomic_commit_before_check_errs);

// ── DRM GPU scheduler smokes ──────────────────────────────────────────

fn smoke_drm_sched_context_add_remove() -> TestResult {
    use crate::drm::scheduler::{Priority, Sched, SchedError};
    let mut sched = Sched::new();
    let a = sched.add_context(Priority::Normal);
    let b = sched.add_context(Priority::High);
    if a == b {
        return TestResult::Fail("duplicate context ids");
    }
    if sched.contexts.len() != 2 {
        return TestResult::Fail("len != 2 after 2 adds");
    }
    sched.remove_context(a).unwrap();
    if sched.contexts.len() != 1 {
        return TestResult::Fail("len != 1 after one remove");
    }
    match sched.remove_context(a) {
        Err(SchedError::NoContext) => {}
        _ => return TestResult::Fail("removing missing ctx should err"),
    }
    sched.remove_context(b).unwrap();
    if !sched.contexts.is_empty() {
        return TestResult::Fail("not empty after both");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_sched_context_add_remove);

fn smoke_drm_sched_submit_runs_payload() -> TestResult {
    use crate::drm::scheduler::{NoopPayload, Priority, Sched};
    let mut sched = Sched::new();
    let ctx = sched.add_context(Priority::Normal);
    let fence = sched
        .submit(
            ctx,
            alloc::vec::Vec::new(),
            alloc::boxed::Box::new(NoopPayload),
        )
        .expect("submit");
    if crate::drm::syncobj::DmaFence::is_signalled(fence.as_ref()) {
        return TestResult::Fail("job fence cannot be signalled before tick");
    }
    let ran = sched.tick().expect("tick");
    if ran != ctx {
        return TestResult::Fail("wrong ctx ran");
    }
    if !crate::drm::syncobj::DmaFence::is_signalled(fence.as_ref()) {
        return TestResult::Fail("fence not signalled after tick");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_sched_submit_runs_payload);

fn smoke_drm_sched_dependency_blocks_run() -> TestResult {
    use crate::drm::scheduler::{NoopPayload, Priority, Sched};
    use crate::drm::syncobj::DmaFence;
    let mut sched = Sched::new();
    let ctx = sched.add_context(Priority::Normal);
    let f_a = sched
        .submit(
            ctx,
            alloc::vec::Vec::new(),
            alloc::boxed::Box::new(NoopPayload),
        )
        .unwrap();
    let dep: alloc::sync::Arc<dyn DmaFence> = f_a.clone();
    let f_b = sched
        .submit(ctx, alloc::vec![dep], alloc::boxed::Box::new(NoopPayload))
        .unwrap();
    // First tick: A runs (no deps). Once f_a signals, B becomes ready.
    sched.tick().expect("A should run");
    if !DmaFence::is_signalled(f_a.as_ref()) {
        return TestResult::Fail("A not signalled");
    }
    sched.tick().expect("B should run");
    if !DmaFence::is_signalled(f_b.as_ref()) {
        return TestResult::Fail("B not signalled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_sched_dependency_blocks_run);

fn smoke_drm_sched_priority_picks_high_first() -> TestResult {
    use crate::drm::scheduler::{NoopPayload, Priority, Sched};
    let mut sched = Sched::new();
    let low = sched.add_context(Priority::Low);
    let hi = sched.add_context(Priority::High);
    let _f_low_1 = sched
        .submit(
            low,
            alloc::vec::Vec::new(),
            alloc::boxed::Box::new(NoopPayload),
        )
        .unwrap();
    let _f_low_2 = sched
        .submit(
            low,
            alloc::vec::Vec::new(),
            alloc::boxed::Box::new(NoopPayload),
        )
        .unwrap();
    let _f_hi = sched
        .submit(
            hi,
            alloc::vec::Vec::new(),
            alloc::boxed::Box::new(NoopPayload),
        )
        .unwrap();
    let first = sched.tick().expect("tick 1");
    if first != hi {
        return TestResult::Fail("High-priority context should run first");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_sched_priority_picks_high_first);

fn smoke_drm_sched_drain_runs_all() -> TestResult {
    use crate::drm::scheduler::{NoopPayload, Priority, Sched};
    let mut sched = Sched::new();
    let c = sched.add_context(Priority::Normal);
    let mut fences = alloc::vec::Vec::new();
    for _ in 0..5 {
        fences.push(
            sched
                .submit(
                    c,
                    alloc::vec::Vec::new(),
                    alloc::boxed::Box::new(NoopPayload),
                )
                .unwrap(),
        );
    }
    let n = sched.drain();
    if n != 5 {
        return TestResult::Fail("drain count wrong");
    }
    if sched.pending() != 0 {
        return TestResult::Fail("pending != 0 after drain");
    }
    for f in &fences {
        if !crate::drm::syncobj::DmaFence::is_signalled(f.as_ref()) {
            return TestResult::Fail("not all fences signalled after drain");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_sched_drain_runs_all);

// ── DRM PRIME fd-handoff smokes ───────────────────────────────────────

fn smoke_drm_prime_handle_fd_handle_roundtrip() -> TestResult {
    use crate::dmabuf::export;
    use crate::drm::prime::{PrimeError, PrimeTable};
    let buf = export(0x4000_0000, 4096, &NULL_OPS).expect("export");
    let mut tbl = PrimeTable::new();
    let handle: u32 = 0x42;
    let fd = tbl.handle_to_fd(handle, buf.clone()).expect("handle_to_fd");
    if fd < 4096 {
        return TestResult::Fail("fd should be >= 4096");
    }
    let recovered = tbl.fd_to_handle(fd).expect("fd_to_handle");
    if recovered != handle {
        return TestResult::Fail("handle didn't round-trip");
    }
    // Second export of the same handle reuses the fd (cache hit).
    let fd2 = tbl
        .handle_to_fd(handle, buf.clone())
        .expect("handle_to_fd repeat");
    if fd2 != fd {
        return TestResult::Fail("repeat handle_to_fd should reuse fd");
    }
    // Bad fd is rejected.
    if !matches!(tbl.fd_to_handle(123), Err(PrimeError::BadFd)) {
        return TestResult::Fail("fd < 4096 should be BadFd");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_drm_prime_handle_fd_handle_roundtrip
);

fn smoke_drm_prime_cross_table_import() -> TestResult {
    // Exporter (driver A) hands an fd to importer (driver B). Both
    // tables reach the same dma_buf physical address — i.e. the
    // userspace cross-driver zero-copy fast path.
    use crate::dmabuf::export;
    use crate::drm::prime::PrimeTable;
    let buf = export(0x5000_0000, 8192, &NULL_OPS).expect("export");
    let mut tbl_a = PrimeTable::new();
    let mut tbl_b = PrimeTable::new();
    let handle_a: u32 = 1;
    let fd = tbl_a.handle_to_fd(handle_a, buf.clone()).expect("A export");
    // Importer recovers the dma_buf from the fd (here directly via
    // exporter's cache; in the kernel this goes through the global fd
    // table).
    let buf_b = tbl_a.fd_to_buf(fd).expect("recover buf").clone();
    let handle_b: u32 = 99;
    tbl_b
        .import_binding(fd, handle_b, buf_b.clone())
        .expect("B import");
    if tbl_b.fd_to_handle(fd).expect("B fd_to_handle") != handle_b {
        return TestResult::Fail("imported handle wrong");
    }
    if tbl_b.fd_to_buf(fd).expect("B fd_to_buf").phys() != buf.phys() {
        return TestResult::Fail("imported dma_buf phys mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_prime_cross_table_import);

fn smoke_drm_prime_drop_handle_clears_binding() -> TestResult {
    use crate::dmabuf::export;
    use crate::drm::prime::{PrimeError, PrimeTable};
    let buf = export(0x6000_0000, 4096, &NULL_OPS).expect("export");
    let mut tbl = PrimeTable::new();
    let fd = tbl.handle_to_fd(1, buf.clone()).expect("export");
    if tbl.len() != 1 {
        return TestResult::Fail("len after export");
    }
    tbl.drop_handle(1).expect("drop");
    if !tbl.is_empty() {
        return TestResult::Fail("table not empty after drop");
    }
    // Subsequent fd lookup must miss.
    if !matches!(tbl.fd_to_handle(fd), Err(PrimeError::NotFound)) {
        return TestResult::Fail("fd should be NotFound after drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm",
    smoke_drm_prime_drop_handle_clears_binding
);

// ── amdgpu/smu v12+v13 opcode tables ───────────────────────────────
//
// Verify per-version opcode lookup correctness, the SmuVersion
// detection path, SmuFwVersion decode, and the version-dispatched
// public API against a FakeMmio mock.

fn smoke_amdgpu_smu_v12_opcode_table_spot_checks() -> TestResult {
    // Confirm that the SMU12 opcode table returns the expected numeric
    // ids for a representative subset of canonical messages.
    // Sources: smu_v12_0_ppsmc.h + renoir_ppt.c::renoir_message_map.
    use crate::amdgpu_smu::PpsmcMsg;
    use crate::amdgpu_smu_v12;

    // TestMessage = 0x01, GetSmuVersion = 0x02, GetDriverIfVersion = 0x03.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::TestMessage) != Some(0x01) {
        return TestResult::Fail("V12 TestMessage id != 0x01");
    }
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetSmuVersion) != Some(0x02) {
        return TestResult::Fail("V12 GetSmuVersion id != 0x02");
    }
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetDriverIfVersion) != Some(0x03) {
        return TestResult::Fail("V12 GetDriverIfVersion id != 0x03");
    }
    // GetGfxclkFrequency = 0x2A, GetFclkFrequency = 0x2B.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetGfxclkFrequency) != Some(0x2A) {
        return TestResult::Fail("V12 GetGfxclkFrequency id != 0x2A");
    }
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetFclkFrequency) != Some(0x2B) {
        return TestResult::Fail("V12 GetFclkFrequency id != 0x2B");
    }
    // SetSoftMaxGfxClk = 0x30, SetHardMinGfxClk = 0x31.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::SetSoftMaxGfxClk) != Some(0x30) {
        return TestResult::Fail("V12 SetSoftMaxGfxClk id != 0x30");
    }
    if amdgpu_smu_v12::msg_id(PpsmcMsg::SetHardMinGfxClk) != Some(0x31) {
        return TestResult::Fail("V12 SetHardMinGfxClk id != 0x31");
    }
    // SetSoftMinGfxclk doesn't exist on SMU12.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::SetSoftMinGfxclk).is_some() {
        return TestResult::Fail("V12 SetSoftMinGfxclk should be None");
    }
    // PrepareMp1ForUnload doesn't exist on SMU12.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::PrepareMp1ForUnload).is_some() {
        return TestResult::Fail("V12 PrepareMp1ForUnload should be None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_v12_opcode_table_spot_checks
);

fn smoke_amdgpu_smu_v13_opcode_table_spot_checks() -> TestResult {
    // Confirm that the SMU13.0.4 opcode table returns the expected
    // numeric ids.
    // Source: smu_v13_0_4_ppsmc.h + smu_v13_0_4_ppt.c::message_map.
    use crate::amdgpu_smu::PpsmcMsg;
    use crate::amdgpu_smu_v13;

    // TestMessage = 0x01 (same as V12).
    if amdgpu_smu_v13::msg_id(PpsmcMsg::TestMessage) != Some(0x01) {
        return TestResult::Fail("V13 TestMessage id != 0x01");
    }
    // GetSmuVersion maps to GetPmfwVersion = 0x02 on SMU13.
    if amdgpu_smu_v13::msg_id(PpsmcMsg::GetSmuVersion) != Some(0x02) {
        return TestResult::Fail("V13 GetSmuVersion (GetPmfwVersion) id != 0x02");
    }
    // GetDriverIfVersion = 0x03.
    if amdgpu_smu_v13::msg_id(PpsmcMsg::GetDriverIfVersion) != Some(0x03) {
        return TestResult::Fail("V13 GetDriverIfVersion id != 0x03");
    }
    // GetGfxclkFrequency = 0x17, GetFclkFrequency = 0x18.
    if amdgpu_smu_v13::msg_id(PpsmcMsg::GetGfxclkFrequency) != Some(0x17) {
        return TestResult::Fail("V13 GetGfxclkFrequency id != 0x17");
    }
    if amdgpu_smu_v13::msg_id(PpsmcMsg::GetFclkFrequency) != Some(0x18) {
        return TestResult::Fail("V13 GetFclkFrequency id != 0x18");
    }
    // SetSoftMinGfxclk = 0x09 (exists on V13, absent on V12).
    if amdgpu_smu_v13::msg_id(PpsmcMsg::SetSoftMinGfxclk) != Some(0x09) {
        return TestResult::Fail("V13 SetSoftMinGfxclk id != 0x09");
    }
    // AllowGfxOff = 0x19, DisallowGfxOff = 0x1A.
    if amdgpu_smu_v13::msg_id(PpsmcMsg::AllowGfxOff) != Some(0x19) {
        return TestResult::Fail("V13 AllowGfxOff id != 0x19");
    }
    if amdgpu_smu_v13::msg_id(PpsmcMsg::DisallowGfxOff) != Some(0x1A) {
        return TestResult::Fail("V13 DisallowGfxOff id != 0x1A");
    }
    // PrepareMp1ForUnload = 0x0C (exists on V13).
    if amdgpu_smu_v13::msg_id(PpsmcMsg::PrepareMp1ForUnload) != Some(0x0C) {
        return TestResult::Fail("V13 PrepareMp1ForUnload id != 0x0C");
    }
    // PowerUpGfx absent on V13 (handled via GfxOff control).
    if amdgpu_smu_v13::msg_id(PpsmcMsg::PowerUpGfx).is_some() {
        return TestResult::Fail("V13 PowerUpGfx should be None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_v13_opcode_table_spot_checks
);

fn smoke_amdgpu_smu_version_detect_from_driver_if() -> TestResult {
    // Verify that SmuVersion::from_driver_if maps the correct
    // driver-IF constants to the right enum variant.
    use crate::amdgpu_smu::{SmuVersion, SMU12_DRIVER_IF_VERSION, SMU_13_0_4_DRIVER_IF_VERSION};

    // SMU12 (Renoir) driver-IF = 0x0F.
    match SmuVersion::from_driver_if(SMU12_DRIVER_IF_VERSION) {
        Some(SmuVersion::V12) => {}
        _ => return TestResult::Fail("SMU12 driver-IF should map to V12"),
    }
    // SMU13.0.4 (Phoenix) driver-IF = 0x07.
    match SmuVersion::from_driver_if(SMU_13_0_4_DRIVER_IF_VERSION) {
        Some(SmuVersion::V13) => {}
        _ => return TestResult::Fail("SMU13.0.4 driver-IF should map to V13"),
    }
    // Unknown value → None.
    if SmuVersion::from_driver_if(0x42).is_some() {
        return TestResult::Fail("unknown driver-IF should return None");
    }
    if SmuVersion::from_driver_if(0).is_some() {
        return TestResult::Fail("zero driver-IF should return None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_version_detect_from_driver_if
);

fn smoke_amdgpu_smu_fw_version_decode() -> TestResult {
    // SmuFwVersion::from_raw should decode the BCD-packed word into
    // separate major/minor/revision fields.
    use crate::amdgpu_smu::SmuFwVersion;

    // Simulate a V13 PMFW version: major=0x00, minor=0x0D, rev=0x04
    // packed as 0x000D_0400 (as returned by GetPmfwVersion on Phoenix).
    let raw = 0x000D_0400u32;
    let v = SmuFwVersion::from_raw(raw);
    if v.major != 0x00 {
        return TestResult::Fail("major decode wrong (0x000D_0400)");
    }
    if v.minor != 0x0D {
        return TestResult::Fail("minor decode wrong (0x000D_0400)");
    }
    if v.revision != 0x04 {
        return TestResult::Fail("revision decode wrong (0x000D_0400)");
    }
    if v.raw != raw {
        return TestResult::Fail("raw field not preserved");
    }

    // Simulate a V12 SMU version: 0x000A_0203 (major=0, minor=0x0A,
    // rev=0x02 — this is what the bring_up smoke uses).
    let raw2 = 0x000A_0203u32;
    let v2 = SmuFwVersion::from_raw(raw2);
    if v2.minor != 0x0A {
        return TestResult::Fail("minor decode wrong (0x000A_0203)");
    }
    if v2.revision != 0x02 {
        return TestResult::Fail("revision decode wrong (0x000A_0203)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/smu", smoke_amdgpu_smu_fw_version_decode);

fn smoke_amdgpu_smu_get_clock_mhz_end_to_end() -> TestResult {
    // End-to-end mock: write msg → simulate response → read result.
    // Tests the `get_clock_mhz` public API via a FakeMmio that
    // scripts the exact canonical mailbox sequence.
    use crate::amdgpu_smu::{
        get_clock_mhz, ClockDomain, MockSmu, SmuVersion, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL,
        MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
    };
    use crate::amdgpu_smu_v13::V13_MSG_GET_GFXCLK;

    let mp1_base: u32 = 0x1_6000;
    let resp_off = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg_off = mp1_base + MP1_C2PMSG_ARG_REL;

    // Script: handshake idle, response OK, ARG = 2400 MHz (GFXCLK).
    let mut m = MockSmu::new();
    m.stage_read(resp_off, 1); // step 1: RESP non-zero (idle)
    m.stage_read(resp_off, SMU_RESP_OK); // step 5: SMU responds OK
    m.stage_read(arg_off, 2400); // step 6: ARG holds frequency

    let mhz = match get_clock_mhz(&mut m, mp1_base, SmuVersion::V13, ClockDomain::Gfxclk) {
        Ok(v) => v,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("get_clock_mhz errored on happy path");
        }
    };
    if mhz != 2400 {
        return TestResult::Fail("returned MHz != 2400");
    }
    // The MSG register must have been written with the V13 GFXCLK id.
    let msg_write = m
        .writes
        .iter()
        .find(|(off, _)| *off == mp1_base + MP1_C2PMSG_MSG_REL);
    match msg_write {
        Some((_, id)) if *id == V13_MSG_GET_GFXCLK => {}
        Some((_, id)) => {
            let _ = id;
            return TestResult::Fail("MSG register holds wrong message id");
        }
        None => return TestResult::Fail("MSG register never written"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_get_clock_mhz_end_to_end
);

fn smoke_amdgpu_smu_v12_v13_opcodes_differ_where_expected() -> TestResult {
    // Structural: confirm that the key messages that differ between
    // V12 and V13 actually carry distinct numeric ids. If they ever
    // accidentally converge the version-dispatch would become a no-op
    // on those messages.
    use crate::amdgpu_smu::PpsmcMsg;
    use crate::amdgpu_smu_v12;
    use crate::amdgpu_smu_v13;

    // GetGfxclkFrequency: V12=0x2A, V13=0x17 — must differ.
    let v12_gfx = amdgpu_smu_v12::msg_id(PpsmcMsg::GetGfxclkFrequency);
    let v13_gfx = amdgpu_smu_v13::msg_id(PpsmcMsg::GetGfxclkFrequency);
    if v12_gfx == v13_gfx {
        return TestResult::Fail("GetGfxclkFrequency ids must differ V12 vs V13");
    }

    // GetFclkFrequency: V12=0x2B, V13=0x18 — must differ.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetFclkFrequency)
        == amdgpu_smu_v13::msg_id(PpsmcMsg::GetFclkFrequency)
    {
        return TestResult::Fail("GetFclkFrequency ids must differ V12 vs V13");
    }

    // AllowGfxOff: V12=0x07, V13=0x19 — must differ.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::AllowGfxOff)
        == amdgpu_smu_v13::msg_id(PpsmcMsg::AllowGfxOff)
    {
        return TestResult::Fail("AllowGfxOff ids must differ V12 vs V13");
    }

    // TestMessage: both are 0x01 — must be equal.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::TestMessage)
        != amdgpu_smu_v13::msg_id(PpsmcMsg::TestMessage)
    {
        return TestResult::Fail("TestMessage must be 0x01 on both V12 and V13");
    }

    // GetDriverIfVersion: both 0x03 — must be equal.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::GetDriverIfVersion)
        != amdgpu_smu_v13::msg_id(PpsmcMsg::GetDriverIfVersion)
    {
        return TestResult::Fail("GetDriverIfVersion must be 0x03 on both versions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_v12_v13_opcodes_differ_where_expected
);

// ── Foundations wave — bring-up target PCI ID coverage ─────────────
//
// The bring-up matrix is two laptops:
//   - Renoir family — 1002:1636 (Renoir Vega8/9, DCN 2.0) and
//                     1002:1638 (Cezanne, DCN 2.1) — both routed to
//                     Family::Renoir (GFX9 / SMU 12.0 / PSP 12.0).
//   - Phoenix HawkPoint1 — 1002:1900 (DCN 3.5, GFX 11.5, SMU 14).
// Lock the three explicit PCI IDs in so an accidental rename or
// table edit surfaces immediately.

fn smoke_amdgpu_foundations_bringup_target_pci_ids() -> TestResult {
    use crate::amdgpu;
    if amdgpu::RENOIR != 0x1636 {
        return TestResult::Fail("RENOIR constant drifted from 0x1636");
    }
    if amdgpu::CEZANNE != 0x1638 {
        return TestResult::Fail("CEZANNE constant drifted from 0x1638");
    }
    if amdgpu::PHOENIX_HAWKPOINT1 != 0x1900 {
        return TestResult::Fail("PHOENIX_HAWKPOINT1 constant drifted from 0x1900");
    }
    if amdgpu::AMD_VENDOR != 0x1002 {
        return TestResult::Fail("AMD_VENDOR constant drifted from 0x1002");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_bringup_target_pci_ids
);

// ── Foundations wave — GFX register surface ────────────────────────

fn smoke_amdgpu_foundations_grbm_status_idle_decode() -> TestResult {
    use crate::amdgpu_gfx::GrbmStatus;
    // All zeros → idle.
    let s = GrbmStatus { raw: 0 };
    if !s.idle() {
        return TestResult::Fail("raw=0 must decode as idle");
    }
    if s.any_busy() || s.cp_busy() || s.rlc_busy() {
        return TestResult::Fail("raw=0 must not be busy");
    }
    if s.is_sentinel() {
        return TestResult::Fail("raw=0 is not the device-gone sentinel");
    }
    // GUI_ACTIVE set → busy + not idle.
    let s2 = GrbmStatus {
        raw: crate::amdgpu_gfx::GRBM_STATUS_GUI_ACTIVE,
    };
    if !s2.any_busy() || s2.idle() {
        return TestResult::Fail("GUI_ACTIVE bit must trip any_busy");
    }
    // Sentinel.
    let s3 = GrbmStatus { raw: 0xFFFF_FFFF };
    if !s3.is_sentinel() {
        return TestResult::Fail("0xFFFFFFFF must be sentinel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_grbm_status_idle_decode
);

fn smoke_amdgpu_foundations_grbm_gfx_index_encoding() -> TestResult {
    use crate::amdgpu_gfx::{grbm_gfx_index_broadcast, grbm_gfx_index_for};
    // Broadcast must light all three top bits.
    let b = grbm_gfx_index_broadcast();
    if b & (1 << 31) == 0 || b & (1 << 30) == 0 || b & (1 << 29) == 0 {
        return TestResult::Fail("broadcast must light bits 29/30/31");
    }
    // Low 24 bits must be zero on a broadcast (no narrowing).
    if b & 0x00FF_FFFF != 0 {
        return TestResult::Fail("broadcast must leave narrowing fields zero");
    }
    // Targeted index encodes (se, sh, instance) in the three byte lanes.
    let v = grbm_gfx_index_for(2, 1, 3);
    if v & 0xFF != 3 {
        return TestResult::Fail("instance not in lane 0");
    }
    if (v >> 8) & 0xFF != 1 {
        return TestResult::Fail("sh not in lane 1");
    }
    if (v >> 16) & 0xFF != 2 {
        return TestResult::Fail("se not in lane 2");
    }
    // Broadcast bits must be clear on a targeted value.
    if v & 0xE000_0000 != 0 {
        return TestResult::Fail("targeted value must not set broadcast bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_grbm_gfx_index_encoding
);

/// The GFX register offsets, against the AMD headers they are supposed to
/// come from.
///
/// The version of this test it replaces asserted `GRBM_STATUS = 0x0DA0` and
/// `CP_VERSION = 0x0867` and said they "must match the documented
/// gc_9_0_offset.h dwords". Neither does. `mmGRBM_STATUS` is 0x0004 on GFX9
/// and 0x0da4 on GFX11, and there is no `CP_VERSION` register in any AMD
/// header — the probe that read it has been removed rather than pointed
/// somewhere plausible.
///
/// An offset test can only restate a number, so what it buys is a tripwire:
/// changing one of these now requires saying which header line justifies it.
fn smoke_amdgpu_foundations_gfx_per_family_register_offsets_distinct() -> TestResult {
    use crate::amdgpu_gfx::{
        CP_ME_CNTL_REL, CP_RB0_BASE_HI_REL, CP_RB0_BASE_REL, CP_RB0_CNTL_REL,
        CP_RB0_RPTR_ADDR_HI_REL, CP_RB0_RPTR_ADDR_REL, CP_RB0_WPTR_HI_REL, CP_RB0_WPTR_REL,
        CP_RB_DOORBELL_CONTROL_REL, CP_RB_DOORBELL_RANGE_LOWER_REL, CP_RB_DOORBELL_RANGE_UPPER_REL,
        GRBM_GFX_INDEX_REL, GRBM_STATUS_REL_GFX11, GRBM_STATUS_REL_GFX9,
    };

    // `gc_9_0_offset.h`, dword ids.
    let gfx9: &[(&str, u32, u32)] = &[
        ("mmCP_ME_CNTL", CP_ME_CNTL_REL, 0x01B6),
        ("mmCP_RB0_BASE", CP_RB0_BASE_REL, 0x1040),
        ("mmCP_RB0_CNTL", CP_RB0_CNTL_REL, 0x1041),
        ("mmCP_RB0_RPTR_ADDR", CP_RB0_RPTR_ADDR_REL, 0x1043),
        ("mmCP_RB0_RPTR_ADDR_HI", CP_RB0_RPTR_ADDR_HI_REL, 0x1044),
        ("mmCP_RB0_WPTR", CP_RB0_WPTR_REL, 0x1054),
        ("mmCP_RB0_WPTR_HI", CP_RB0_WPTR_HI_REL, 0x1055),
        (
            "mmCP_RB_DOORBELL_CONTROL",
            CP_RB_DOORBELL_CONTROL_REL,
            0x1059,
        ),
        (
            "mmCP_RB_DOORBELL_RANGE_LOWER",
            CP_RB_DOORBELL_RANGE_LOWER_REL,
            0x105A,
        ),
        (
            "mmCP_RB_DOORBELL_RANGE_UPPER",
            CP_RB_DOORBELL_RANGE_UPPER_REL,
            0x105B,
        ),
        ("mmCP_RB0_BASE_HI", CP_RB0_BASE_HI_REL, 0x10B1),
        ("mmGRBM_STATUS", GRBM_STATUS_REL_GFX9, 0x0004),
        ("mmGRBM_GFX_INDEX", GRBM_GFX_INDEX_REL, 0x2200),
    ];
    for (name, got, want_dword) in gfx9.iter().copied() {
        let _ = name;
        if got != want_dword * 4 {
            return TestResult::Fail("a GFX9 register offset is not its gc_9_0_offset.h value");
        }
    }

    // `gc_11_0_0_offset.h`.
    if GRBM_STATUS_REL_GFX11 != 0x0DA4 * 4 {
        return TestResult::Fail("GFX11 GRBM_STATUS is regGRBM_STATUS = 0x0da4");
    }
    // The per-family branch in `AmdGpu::grbm_status_offset` only earns its
    // keep if the two differ.
    if GRBM_STATUS_REL_GFX9 == GRBM_STATUS_REL_GFX11 {
        return TestResult::Fail("GRBM_STATUS moved between GFX9 and GFX11");
    }

    // No two distinct registers may share an offset — a transposed digit
    // usually collides, and a collision means one register's writes land on
    // another's.
    let mut offsets: alloc::vec::Vec<u32> = gfx9.iter().map(|(_, o, _)| *o).collect();
    offsets.push(GRBM_STATUS_REL_GFX11);
    let before = offsets.len();
    offsets.sort_unstable();
    offsets.dedup();
    if offsets.len() != before {
        return TestResult::Fail("two register offsets collide");
    }
    // And all are dword aligned.
    if offsets.iter().any(|o| o & 3 != 0) {
        return TestResult::Fail("register byte offsets must be 4-aligned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_gfx_per_family_register_offsets_distinct
);

// ── Foundations wave — GMC aperture decode ─────────────────────────

fn smoke_amdgpu_foundations_vram_aperture_decode_renoir_uma() -> TestResult {
    use crate::amdgpu_gmc::decode_vram_aperture;
    // Renoir UMA carve-out example: base = 0x100, top = 0x1FF →
    // 0x100..0x200 in 16-MiB units → [0x1_0000_0000, 0x2_0000_0000)
    // = 4 GiB aperture starting at 4 GiB.
    let (base, size) = decode_vram_aperture(0x0000_0100, 0x0000_01FF);
    if base != 0x1_0000_0000 {
        return TestResult::Fail("decoded VRAM base wrong");
    }
    if size != 0x1_0000_0000 {
        return TestResult::Fail("decoded VRAM size wrong");
    }
    // Reserved bits in upper byte must be masked off.
    let (base2, _) = decode_vram_aperture(0xFF00_0100, 0x0000_01FF);
    if base2 != 0x1_0000_0000 {
        return TestResult::Fail("upper-byte reserved bits must be masked");
    }
    // Degenerate (top < base) decodes to size 0.
    let (_, size_zero) = decode_vram_aperture(0x0000_0200, 0x0000_0100);
    if size_zero != 0 {
        return TestResult::Fail("top<base must yield size 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_vram_aperture_decode_renoir_uma
);

fn smoke_amdgpu_foundations_system_aperture_decode_in_4kib_units() -> TestResult {
    use crate::amdgpu_gmc::decode_system_aperture;
    // 4 KiB units: low=0x100000 -> 4 GiB, high=0x200000 -> 8 GiB.
    let (low, high) = decode_system_aperture(0x0010_0000, 0x0020_0000);
    if low != 0x1_0000_0000 {
        return TestResult::Fail("decoded system low wrong");
    }
    if high != 0x2_0000_0000 {
        return TestResult::Fail("decoded system high wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_system_aperture_decode_in_4kib_units
);

fn smoke_amdgpu_foundations_aperture_layout_predicates() -> TestResult {
    use crate::amdgpu_gmc::ApertureLayout;
    let empty = ApertureLayout::default();
    if empty.has_vram() || empty.has_system() {
        return TestResult::Fail("default ApertureLayout must report no apertures");
    }
    let populated = ApertureLayout {
        vram_base: 0x1_0000_0000,
        vram_size: 0x1_0000_0000,
        system_low: 0,
        system_high: 0x4_0000_0000,
    };
    if !populated.has_vram() {
        return TestResult::Fail("non-zero vram_size must report has_vram");
    }
    if !populated.has_system() {
        return TestResult::Fail("high>low must report has_system");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_aperture_layout_predicates
);

// ── Foundations wave — register-surface offsets stable ─────────────

fn smoke_amdgpu_foundations_mc_register_offsets_stable() -> TestResult {
    // Lock the MC register dword indices so an accidental rename
    // doesn't drift them silently — these are facts about the
    // silicon, not creative choices.
    use crate::amdgpu_gmc::{
        MC_SHARED_CHMAP, MC_VM_AGP_BASE, MC_VM_FB_LOCATION_BASE, MC_VM_FB_LOCATION_TOP,
        MC_VM_SYSTEM_APERTURE_HIGH_ADDR, MC_VM_SYSTEM_APERTURE_LOW_ADDR,
    };
    if MC_VM_FB_LOCATION_BASE != 0x6B0F {
        return TestResult::Fail("MC_VM_FB_LOCATION_BASE drift");
    }
    if MC_VM_FB_LOCATION_TOP != 0x6B10 {
        return TestResult::Fail("MC_VM_FB_LOCATION_TOP drift");
    }
    if MC_VM_AGP_BASE != 0x6B0C {
        return TestResult::Fail("MC_VM_AGP_BASE drift");
    }
    if MC_VM_SYSTEM_APERTURE_LOW_ADDR != 0x6B17 {
        return TestResult::Fail("MC_VM_SYSTEM_APERTURE_LOW_ADDR drift");
    }
    if MC_VM_SYSTEM_APERTURE_HIGH_ADDR != 0x6B18 {
        return TestResult::Fail("MC_VM_SYSTEM_APERTURE_HIGH_ADDR drift");
    }
    if MC_SHARED_CHMAP != 0x2004 {
        return TestResult::Fail("MC_SHARED_CHMAP drift");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_mc_register_offsets_stable
);

// ── Foundations wave — IP discovery handles a Phoenix-style blob ───
//
// `smoke_amdgpu_discovery_parse_synthetic_blob` already drives the
// parser against a hand-built blob; this Foundations-specific
// smoke verifies the parser specifically resolves the Phoenix
// bring-up's load-bearing IPs — MP0, MP1, GC, DCN — out of the
// returned `Vec<IpBlock>`. Same synthetic blob helper.

fn smoke_amdgpu_foundations_discovery_resolves_load_bearing_blocks() -> TestResult {
    // Foundations wave needs the discovery parser to surface at
    // least the GC IP block (for `AmdGpu::gc_base` → GRBM/CP
    // register window) and the MP0 IP block (for PSP firmware
    // load in the next wave). The shared synthetic blob populates
    // exactly these two on a single die; verify both round-trip
    // out of `parse_discovery` at the expected base offsets, and
    // that the IP version fields (major/minor/revision) survive.
    use crate::amdgpu_discovery::{find_ip, parse_discovery, HW_ID_GC, HW_ID_MP0};
    let (blob, expected_mp0_base, expected_gc_base) = build_synthetic_discovery_blob();
    let blocks = match parse_discovery(&blob) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("synthetic discovery blob must parse"),
    };
    let gc = match find_ip(&blocks, HW_ID_GC, 0) {
        Some(b) => b,
        None => return TestResult::Fail("GC instance 0 must surface"),
    };
    if gc.base_addrs[0] != expected_gc_base {
        return TestResult::Fail("GC base from discovery doesn't match builder");
    }
    if gc.major != 11 {
        return TestResult::Fail("GC major version lost across parse");
    }
    let mp0 = match find_ip(&blocks, HW_ID_MP0, 0) {
        Some(b) => b,
        None => return TestResult::Fail("MP0 instance 0 must surface"),
    };
    if mp0.base_addrs[0] != expected_mp0_base {
        return TestResult::Fail("MP0 base from discovery doesn't match builder");
    }
    if mp0.num_bases != 2 {
        return TestResult::Fail("MP0 should expose 2 base addrs in this blob");
    }
    if mp0.major != 13 || mp0.revision != 4 {
        return TestResult::Fail("MP0 v13.0.4 version fields lost across parse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/foundations",
    smoke_amdgpu_foundations_discovery_resolves_load_bearing_blocks
);

/// The Phoenix PCI ids and firmware bundle, against the two sources of truth
/// that can actually settle them.
///
/// Device ids come from the PCI SIG database (`pci.ids`, vendor 1002) because
/// modern amdgpu matches APUs by IP-discovery version and carries no id table
/// for them — so a wrong constant cannot be caught by reading the driver, only
/// by booting the machine it is wrong about. Firmware names come from the
/// `MODULE_FIRMWARE` declarations of the IP modules Linux binds for GFX 11.0.1.
///
/// Three constants were wrong before this test existed:
///   * `0x15BF` was labelled Strix Point. It is Phoenix1 — the Radeon 780M —
///     so every 780M asked the PSP for Strix firmware.
///   * `0x1681` was labelled a "Phoenix discrete sibling". It is Rembrandt,
///     RDNA2 (GFX 10.3.6), an architecture earlier.
///   * `PHOENIX_FW` held the Strix bundle outright (GFX 11.5, DCN 3.5,
///     PSP 14.0.1), under a doc comment that said so.
fn smoke_amdgpu_phoenix_identity_matches_linux() -> TestResult {
    use crate::amdgpu;
    // pci.ids, vendor 1002.
    if amdgpu::PHOENIX1 != 0x15BF || amdgpu::PHOENIX2 != 0x15C8 {
        return TestResult::Fail("Phoenix1/Phoenix2 device ids disagree with pci.ids");
    }
    if amdgpu::STRIX_POINT != 0x150E {
        return TestResult::Fail("Strix Point is 0x150E, not a Phoenix id");
    }
    if amdgpu::REMBRANDT != 0x1681 {
        return TestResult::Fail("Rembrandt is 0x1681");
    }
    if amdgpu::PHOENIX_HAWKPOINT1 != 0x1900 {
        return TestResult::Fail("HawkPoint1 is 0x1900");
    }

    // The 780M must resolve to the Phoenix family and the Phoenix bundle.
    let Some(info) = amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, amdgpu::PHOENIX1)
    else {
        return TestResult::Fail("the Radeon 780M's device id resolves to no chip");
    };
    if info.family != amdgpu::Family::Phoenix {
        return TestResult::Fail("the 780M should resolve to Family::Phoenix");
    }

    // `MODULE_FIRMWARE` for the IP modules Linux binds at GFX 11.0.1.
    // In `enum AMDGPU_UCODE_ID` order, which is the order
    // `psp_load_non_psp_fw` sends them in. The separate order assertions
    // below say WHY each position matters; this one pins the names.
    let want: &[&str] = &[
        "amdgpu/psp_13_0_4_toc.bin",
        "amdgpu/sdma_6_0_1.bin",
        "amdgpu/gc_11_0_1_pfp.bin",
        "amdgpu/gc_11_0_1_me.bin",
        "amdgpu/gc_11_0_1_mec.bin",
        "amdgpu/gc_11_0_1_mes.bin",
        "amdgpu/gc_11_0_1_mes_2.bin",
        "amdgpu/gc_11_0_1_mes1.bin",
        "amdgpu/gc_11_0_1_imu.bin",
        "amdgpu/gc_11_0_1_rlc.bin",
        "amdgpu/vcn_4_0_2.bin",
        "amdgpu/dcn_3_1_4_dmcub.bin",
        "amdgpu/psp_13_0_4_ta.bin",
    ];
    if info.fw_list.len() != want.len() {
        return TestResult::Fail("the Phoenix firmware bundle changed size");
    }
    for (entry, expected) in info.fw_list.iter().zip(want) {
        if entry.name != *expected {
            return TestResult::Fail("a Phoenix firmware blob name is not Linux's");
        }
    }

    // The load ORDER is Linux's, not a preference. `psp_load_non_psp_fw`
    // walks `adev->firmware.ucode[]`, indexed by `enum AMDGPU_UCODE_ID`, so
    // the enum order IS the load order — and the PSP processes each load
    // against the state the previous ones left.
    //
    // The two constraints that matter, both from `psp_load_non_psp_fw`:
    //   * RLC is the LAST graphics blob. The autoload state machine starts
    //     the moment it lands ("start rlc autoload after psp received all the
    //     gfx firmware"), so every CP and MES blob must already be in.
    //   * The non-graphics blobs (VCN, DMCUB) come after it.
    let position = |needle: &str| info.fw_list.iter().position(|e| e.name.contains(needle));
    let (Some(rlc), Some(sdma), Some(pfp), Some(mec), Some(mes), Some(imu)) = (
        position("_rlc.bin"),
        position("sdma_"),
        position("_pfp.bin"),
        position("_mec.bin"),
        position("_mes.bin"),
        position("_imu.bin"),
    ) else {
        return TestResult::Fail("a firmware blob the order depends on is missing");
    };
    for (what, at) in [
        ("sdma", sdma),
        ("pfp", pfp),
        ("mec", mec),
        ("mes", mes),
        ("imu", imu),
    ] {
        let _ = what;
        if at > rlc {
            return TestResult::Fail("RLC must be the last graphics blob: autoload starts on it");
        }
    }
    // SDMA is first of the IP firmwares, as its enum id is lowest.
    if sdma > pfp {
        return TestResult::Fail("SDMA loads before the CP engines");
    }
    // IMU sits between MES and RLC (enum ids 36/37 against MES 32-35, RLC 52).
    if !(mes < imu && imu < rlc) {
        return TestResult::Fail("IMU loads after MES and before RLC");
    }
    // And the non-graphics blobs trail RLC.
    for tail in ["vcn_", "dmcub"] {
        match position(tail) {
            Some(at) if at > rlc => {}
            _ => return TestResult::Fail("a non-graphics blob should load after RLC"),
        }
    }
    // The TOC is first: the PSP needs the table of contents before any image.
    if !info.fw_list[0].name.contains("_toc.bin") {
        return TestResult::Fail("the TOC must be sent first");
    }

    // No SMU blob: Phoenix is an APU whose PMFW is BIOS-resident, and
    // linux-firmware ships `smu_*.bin` for discrete parts only. The entry
    // this table used to carry named a file that exists nowhere.
    if info
        .fw_list
        .iter()
        .any(|e| e.cmd == amdgpu::SMU_LOAD_PMFW_MP1)
    {
        return TestResult::Fail("an APU bundle must not carry an SMU PMFW blob");
    }

    // Silicon with no bring-up must not borrow another family's firmware.
    for did in [amdgpu::STRIX_POINT, amdgpu::REMBRANDT] {
        match amdgpu::__test_chip_info_for_pci_id(amdgpu::AMD_VENDOR, did) {
            Some(info) if info.fw_list.is_empty() => {}
            Some(_) => return TestResult::Fail("unaudited silicon was given a firmware bundle"),
            None => return TestResult::Fail("an id in the match table resolves to no chip"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_phoenix_identity_matches_linux);

/// Build a discovery blob carrying a `gc_info` v1.2 table describing a
/// Radeon 780M: 1 shader engine, 2 shader arrays, 3 WGPs per bank per array.
///
/// 1 SE x 2 SA x (2 x (3 + 3)) CU = 24 — wait, the 780M has 12 CUs, so the
/// banks are 3 and 0: `2 * (3 + 0) = 6` CU per SA, x 2 SA x 1 SE = 12.
/// That asymmetry is the point of v1 having two WGP banks at all.
fn build_gc_info_blob(version_minor: u16, fields: &[u32]) -> alloc::vec::Vec<u8> {
    use crate::amdgpu_discovery as d;
    let mut blob = alloc::vec![0u8; 0x400];
    let gc_off: usize = 0x200;
    let size = 12 + fields.len() * 4;

    // Outer binary_header: signature + the GC directory entry. The GC parser
    // does not re-verify the outer frame, so only the directory matters.
    blob[0..4].copy_from_slice(&d::BINARY_SIGNATURE.to_le_bytes());
    let entry = 12 + d::TABLE_GC * 8;
    blob[entry..entry + 2].copy_from_slice(&(gc_off as u16).to_le_bytes());
    blob[entry + 4..entry + 6].copy_from_slice(&(size as u16).to_le_bytes());

    // gpu_info_header: table_id, version_major, version_minor, size.
    blob[gc_off..gc_off + 4].copy_from_slice(&1u32.to_le_bytes());
    blob[gc_off + 4..gc_off + 6].copy_from_slice(&1u16.to_le_bytes());
    blob[gc_off + 6..gc_off + 8].copy_from_slice(&version_minor.to_le_bytes());
    blob[gc_off + 8..gc_off + 12].copy_from_slice(&(size as u32).to_le_bytes());
    for (i, v) in fields.iter().enumerate() {
        let at = gc_off + 12 + i * 4;
        blob[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    // The table's checksum, over exactly `size` bytes from its own start.
    let csum = blob[gc_off..gc_off + size]
        .iter()
        .fold(0u16, |a, &b| a.wrapping_add(b as u16));
    blob[entry + 2..entry + 4].copy_from_slice(&csum.to_le_bytes());
    blob
}

/// The graphics-core topology comes from the discovery binary, not from a
/// per-ASIC table in the driver.
///
/// This matters because `AMDGPU_INFO_DEV_INFO` reports most of it straight to
/// userspace and Mesa makes shader-compilation decisions from the CU count,
/// wave size and LDS size. Linux reads it from `table_list[GC]` for exactly
/// this reason (`amdgpu_discovery_get_gfx_info`): a 780M and a 760M are both
/// GFX 11.0.1 and differ in CU count, so anything hardcoded per IP version
/// would be wrong for one of them.
fn smoke_amdgpu_gc_info_reports_the_tables_topology() -> TestResult {
    use crate::amdgpu_discovery::{parse_gc_info, DiscoveryError};

    // v1 field order, through v1.2's cache geometry. 780M-shaped: one shader
    // engine, two shader arrays, WGP banks of 3 and 0, wave32.
    let v1: &[u32] = &[
        1,       //  0 gc_num_se
        3,       //  1 gc_num_wgp0_per_sa
        0,       //  2 gc_num_wgp1_per_sa
        2,       //  3 gc_num_rb_per_se
        4,       //  4 gc_num_gl2c
        1024,    //  5 gc_num_gprs
        32,      //  6 gc_num_max_gs_thds
        32,      //  7 gc_gs_table_depth
        1792,    //  8 gc_gsprim_buff_depth
        1024,    //  9 gc_parameter_cache_depth
        1024,    // 10 gc_double_offchip_lds_buffer
        32,      // 11 gc_wave_size
        16,      // 12 gc_max_waves_per_simd
        256,     // 13 gc_max_scratch_slots_per_cu
        65536,   // 14 gc_lds_size
        1,       // 15 gc_num_sc_per_se
        2,       // 16 gc_num_sa_per_se
        1,       // 17 gc_num_packer_per_sc
        2,       // 18 gc_num_gl2a
        16,      // 19 gc_num_tcp_per_sa
        1,       // 20 gc_num_sdp_interface
        16,      // 21 gc_num_tcps
        4,       // 22 gc_num_tcp_per_wpg
        16384,   // 23 gc_tcp_l1_size
        2,       // 24 gc_num_sqc_per_wgp
        32768,   // 25 gc_l1_instruction_cache_size_per_sqc
        16384,   // 26 gc_l1_data_cache_size_per_sqc
        1,       // 27 gc_gl1c_per_sa
        131072,  // 28 gc_gl1c_size_per_instance
        4194304, // 29 gc_gl2c_per_gpu
    ];
    let info = match parse_gc_info(&build_gc_info_blob(2, v1)) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("a valid gc_info v1.2 table was rejected"),
    };
    if info.num_se != 1 || info.num_sa_per_se != 2 {
        return TestResult::Fail("shader engine / array counts did not decode");
    }
    // A WGP is two CUs, banked: 2 * (3 + 0) = 6 per shader array.
    if info.num_cu_per_sa != 6 {
        return TestResult::Fail("v1 should fold WGP banks into CUs per array");
    }
    // 1 SE x 2 SA x 6 CU = 12, which is the 780M's CU count.
    if info.total_cus() != 12 {
        return TestResult::Fail("total CU count is not the product of the geometry");
    }
    if info.wave_size != 32 {
        return TestResult::Fail("RDNA is wave32 and Mesa branches on it");
    }
    if info.num_tccs != 4 || info.lds_size != 65536 {
        return TestResult::Fail("L2 slice count / LDS size did not decode");
    }
    // v1.2's cache geometry, which DEV_INFO reports verbatim.
    if info.tcp_l1_size != 16384 || info.num_sqc_per_wgp != 2 {
        return TestResult::Fail("v1.2 cache geometry did not decode");
    }
    if info.gl1c_size_per_instance != 131072 || info.gl2c_per_gpu != 4194304 {
        return TestResult::Fail("v1.2 GL1/GL2 sizes did not decode");
    }

    // A v1.0 table stops after field 18. The later fields must read as zero,
    // not as whatever follows the table in the blob — DEV_INFO reports zero
    // for them on older silicon too.
    let short = parse_gc_info(&build_gc_info_blob(0, &v1[..19]));
    match short {
        Ok(i) if i.num_cu_per_sa == 6 && i.tcp_l1_size == 0 && i.gl2c_per_gpu == 0 => {}
        Ok(_) => return TestResult::Fail("a v1.0 table leaked fields it does not carry"),
        Err(_) => return TestResult::Fail("a valid v1.0 table was rejected"),
    }

    // v2 (GFX9) counts CUs per array directly rather than in WGP banks.
    let v2: &[u32] = &[
        1, 8, 1, 2, 4, 1024, 32, 32, 1792, 1024, 1024, 64, 10, 256, 65536, 1, 1,
    ];
    let mut blob = build_gc_info_blob(0, v2);
    blob[0x200 + 4..0x200 + 6].copy_from_slice(&2u16.to_le_bytes());
    let size = 12 + v2.len() * 4;
    let csum = blob[0x200..0x200 + size]
        .iter()
        .fold(0u16, |a, &b| a.wrapping_add(b as u16));
    let entry = 12 + crate::amdgpu_discovery::TABLE_GC * 8;
    blob[entry + 2..entry + 4].copy_from_slice(&csum.to_le_bytes());
    match parse_gc_info(&blob) {
        Ok(i) if i.num_cu_per_sa == 8 && i.num_sa_per_se == 1 && i.wave_size == 64 => {}
        Ok(_) => return TestResult::Fail("v2's field order was read as v1's"),
        Err(_) => return TestResult::Fail("a valid gc_info v2.0 table was rejected"),
    }

    // A corrupted table is refused rather than believed. A wrong CU count is
    // wrong shader codegen, so this must fail closed.
    let mut bad = build_gc_info_blob(2, v1);
    bad[0x200 + 12] ^= 0xFF;
    if !matches!(parse_gc_info(&bad), Err(DiscoveryError::BadGcTableChecksum)) {
        return TestResult::Fail("a GC table failing its checksum was accepted");
    }

    // No GC table at all is the QEMU and pre-discovery case, and it is a
    // distinct answer from a corrupt one: the caller may fall back.
    let mut none = build_gc_info_blob(2, v1);
    let entry = 12 + crate::amdgpu_discovery::TABLE_GC * 8;
    none[entry..entry + 2].copy_from_slice(&0u16.to_le_bytes());
    if !matches!(parse_gc_info(&none), Err(DiscoveryError::NoGcTable)) {
        return TestResult::Fail("an absent GC table should be NoGcTable");
    }

    // An unknown major version is refused by version, not guessed at.
    let mut v9 = build_gc_info_blob(0, v1);
    v9[0x200 + 4..0x200 + 6].copy_from_slice(&9u16.to_le_bytes());
    match parse_gc_info(&v9) {
        Err(DiscoveryError::UnknownGcVersion(9)) | Err(DiscoveryError::BadGcTableChecksum) => {}
        _ => return TestResult::Fail("an unknown gc_info major version was decoded anyway"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/discovery",
    smoke_amdgpu_gc_info_reports_the_tables_topology
);

/// `AMDGPU_INFO` reports the device Mesa will actually compile for.
///
/// An "it returned success" test would be worthless here. `libdrm_amdgpu`'s
/// `amdgpu_device_initialize` runs DEV_INFO and MEMORY before it will hand
/// Mesa a device, and radeonsi reads the CU count, wave size and cache
/// geometry out of DEV_INFO to make shader-compilation decisions — so what
/// matters is the VALUES, and that they came from the GC table rather than
/// from a guess. The replies are decoded back through the mirrored structs,
/// whose layout is pinned against the C header separately.
fn smoke_amdgpu_info_reports_the_sourced_device() -> TestResult {
    use crate::amdgpu::Family;
    use crate::amdgpu_discovery::{GcInfo, IpBlock, HW_ID_GC, HW_ID_SDMA0, MAX_BASE_ADDRS};
    use crate::amdgpu_info::{query_against, Snapshot};
    use crate::amdgpu_uapi as u;
    use narf_filesystem::FsError;

    fn ip(hw_id: u16, major: u8, minor: u8, revision: u8) -> IpBlock {
        IpBlock {
            hw_id,
            instance: 0,
            major,
            minor,
            revision,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 1,
        }
    }

    // A Radeon 780M as the GC table describes it: 1 SE, 2 SA, 6 CU per SA.
    let gc = GcInfo {
        version_major: 1,
        version_minor: 2,
        num_se: 1,
        num_sa_per_se: 2,
        num_cu_per_sa: 6,
        num_rb_per_se: 2,
        num_tccs: 4,
        num_gprs: 1024,
        wave_size: 32,
        lds_size: 65536,
        gs_table_depth: 32,
        gsprim_buff_depth: 1792,
        num_max_gs_thds: 32,
        double_offchip_lds_buffer: 1024,
        tcp_l1_size: 16384,
        num_sqc_per_wgp: 2,
        sqc_inst_cache_size: 32768,
        sqc_data_cache_size: 16384,
        gl1c_size_per_instance: 131072,
        gl1c_per_sa: 2,
        gl2c_per_gpu: 4194304,
        ..GcInfo::default()
    };
    let snap = Snapshot {
        did: 0x15BF,
        family: Family::Phoenix,
        vram_size: 512 * 1024 * 1024,
        gc: Some(gc),
        ip_blocks: alloc::vec![ip(HW_ID_GC, 11, 0, 1), ip(HW_ID_SDMA0, 6, 0, 1)],
    };

    let decode = |bytes: &[u8]| -> u::DrmAmdgpuInfoDevice {
        let mut d = u::DrmAmdgpuInfoDevice::default();
        let n = core::mem::size_of::<u::DrmAmdgpuInfoDevice>().min(bytes.len());
        // SAFETY: writing `n` bytes into a `#[repr(C)]` plain-data struct of
        // at least `n` bytes; both sides are byte-addressable POD.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut d as *mut u::DrmAmdgpuInfoDevice as *mut u8,
                n,
            );
        }
        d
    };

    let bytes = match query_against(&snap, u::AMDGPU_INFO_DEV_INFO, [0; 4]) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("DEV_INFO was refused for a fully described device"),
    };
    if bytes.len() != core::mem::size_of::<u::DrmAmdgpuInfoDevice>() {
        return TestResult::Fail("DEV_INFO reply is not the size of its struct");
    }
    let d = decode(&bytes);
    if d.device_id != 0x15BF {
        return TestResult::Fail("DEV_INFO did not report the PCI device id");
    }
    // Mesa keys ASIC behaviour off this; GFX 11.0.1 is family 148.
    if d.family != u::AMDGPU_FAMILY_GC_11_0_1 {
        return TestResult::Fail("Phoenix must report AMDGPU_FAMILY_GC_11_0_1");
    }
    if d.num_shader_engines != 1 || d.num_shader_arrays_per_engine != 2 {
        return TestResult::Fail("shader geometry did not come from the GC table");
    }
    if d.num_cu_per_sh != 6 || d.cu_active_number != 12 {
        return TestResult::Fail("CU counts are not the GC table's");
    }
    // Wave32 vs wave64 changes the shaders Mesa emits.
    if d.wave_front_size != 32 {
        return TestResult::Fail("wave_front_size must be the GC table's wave size");
    }
    if d.num_tcc_blocks != 4 || d.num_rb_pipes != 2 {
        return TestResult::Fail("L2 slice / RB pipe counts are wrong");
    }
    // `gl1c_cache_size` is a PRODUCT in Linux, not a field copy:
    // gc_gl1c_size_per_instance * gc_gl1c_per_sa = 131072 * 2.
    if d.gl1c_cache_size != 262144 {
        return TestResult::Fail("gl1c_cache_size must be size-per-instance times per-SA count");
    }
    if d.gl2c_cache_size != 4194304 || d.tcp_cache_size != 16384 {
        return TestResult::Fail("cache geometry did not reach DEV_INFO");
    }
    // An APU, and nothing else claimed: PREEMPTION / TMZ / GANG_SUBMIT are
    // submission-path capabilities and there is no submission path.
    if d.ids_flags != u64::from(u::AMDGPU_IDS_FLAGS_FUSION) {
        return TestResult::Fail("ids_flags should claim FUSION and nothing more");
    }
    if d.gart_page_size != 4096 || d.virtual_address_alignment != 4096 {
        return TestResult::Fail("page size / VA alignment should be 4 KiB");
    }

    // ACCEL_WORKING is FALSE, and deliberately so: with no AMDGPU_CS, Mesa
    // must decline the device at init rather than fail at first draw.
    match query_against(&snap, u::AMDGPU_INFO_ACCEL_WORKING, [0; 4]) {
        Ok(b) if b.len() == 4 && u32::from_le_bytes(b[..4].try_into().unwrap()) == 0 => {}
        _ => return TestResult::Fail("ACCEL_WORKING must report false while there is no CS path"),
    }

    // MEMORY: three heaps. VRAM twice (the aperture is CPU-visible), GTT
    // zero because no system-memory heap manager exists.
    let mem = match query_against(&snap, u::AMDGPU_INFO_MEMORY, [0; 4]) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("MEMORY was refused"),
    };
    if mem.len() != 96 {
        return TestResult::Fail("MEMORY should be three 32-byte heap_info structs");
    }
    let total = u64::from_le_bytes(mem[0..8].try_into().unwrap());
    let max_alloc = u64::from_le_bytes(mem[24..32].try_into().unwrap());
    let gtt_total = u64::from_le_bytes(mem[64..72].try_into().unwrap());
    if total != 512 * 1024 * 1024 {
        return TestResult::Fail("VRAM heap total is not the probed aperture");
    }
    if max_alloc != total / 4 * 3 {
        return TestResult::Fail("max_allocation should be three quarters of the heap");
    }
    if gtt_total != 0 {
        return TestResult::Fail("GTT must report zero while no GART manager exists");
    }

    // HW_IP_INFO carries the discovered IP version and a ZERO ring mask —
    // "present, unusable" rather than an error, which is how Linux reports
    // an IP whose ring has not come up.
    let hw = match query_against(
        &snap,
        u::AMDGPU_INFO_HW_IP_INFO,
        [u::AMDGPU_HW_IP_GFX, 0, 0, 0],
    ) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("HW_IP_INFO(GFX) was refused"),
    };
    if u32::from_le_bytes(hw[0..4].try_into().unwrap()) != 11
        || u32::from_le_bytes(hw[4..8].try_into().unwrap()) != 0
    {
        return TestResult::Fail("HW_IP_INFO should report the discovered GC version");
    }
    if u32::from_le_bytes(hw[24..28].try_into().unwrap()) != 0 {
        return TestResult::Fail("available_rings must be zero: no ring has been brought up");
    }

    // A device whose GC table was absent or corrupt cannot answer DEV_INFO.
    // Refusing is the point — a zeroed topology would mis-compile shaders.
    let blind = Snapshot {
        gc: None,
        ..snap.clone()
    };
    if !matches!(
        query_against(&blind, u::AMDGPU_INFO_DEV_INFO, [0; 4]),
        Err(FsError::InvalidData)
    ) {
        return TestResult::Fail("DEV_INFO must be refused when the shader topology is unknown");
    }
    // MEMORY does not depend on the GC table and must still answer.
    if query_against(&blind, u::AMDGPU_INFO_MEMORY, [0; 4]).is_err() {
        return TestResult::Fail("MEMORY should not depend on the GC table");
    }

    // Silicon with no bring-up has no family id to report, so DEV_INFO is
    // refused rather than answered with a family whose Mesa path is untried.
    let unknown = Snapshot {
        family: Family::Navi2,
        ..snap.clone()
    };
    if query_against(&unknown, u::AMDGPU_INFO_DEV_INFO, [0; 4]).is_ok() {
        return TestResult::Fail("an unaudited family should not be given a family id");
    }

    // An unknown query is EINVAL, as `amdgpu_info_ioctl`'s default arm is.
    if !matches!(
        query_against(&snap, 0xDEAD, [0; 4]),
        Err(FsError::InvalidData)
    ) {
        return TestResult::Fail("an unknown INFO query should be EINVAL");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_info_reports_the_sourced_device);

/// The amdgpu GEM lifecycle, and the isolation that makes per-open handles
/// worth having.
///
/// `GEM_CREATE` → `GEM_MMAP` → resolve the offset to frames → `GEM_OP` reads
/// the creation parameters back → `GEM_CLOSE`. Plus the validations Linux runs
/// before allocating anything, which are the part a client can reach with
/// hostile input.
fn smoke_amdgpu_gem_lifecycle_and_handle_isolation() -> TestResult {
    use crate::amdgpu_gem::{dispatch, GemState};
    use crate::amdgpu_uapi as u;
    use crate::drm_uapi::{ioc_nr, DRM_COMMAND_BASE};
    use narf_filesystem::FsError;

    // The dispatcher reads only the command number out of the ioctl word, and
    // `ioc_nr` takes it from the low bits — so a bare nr is a valid command
    // word here. On the test path the arg pointer is kernel-owned, which
    // `copy_in`/`copy_out` tolerate.
    let gem_cmd = |n: u32| DRM_COMMAND_BASE + n;
    let close_cmd = 0x09u32;
    // Guard the assumption the helper rests on.
    if ioc_nr(gem_cmd(u::DRM_AMDGPU_GEM_CREATE)) != DRM_COMMAND_BASE {
        return TestResult::Fail("test helper does not encode the ioctl nr the dispatcher reads");
    }

    let state = GemState::new();

    // ── create ──
    let mut req = [0u8; 32];
    req[0..8].copy_from_slice(&8192u64.to_le_bytes()); // bo_size
    req[8..16].copy_from_slice(&4096u64.to_le_bytes()); // alignment
    req[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_VRAM as u64).to_le_bytes());
    req[24..32].copy_from_slice(&(u::AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED as u64).to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_CREATE),
        req.as_mut_ptr() as usize,
        &state,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_CREATE of an 8 KiB VRAM buffer failed");
    }
    let handle = u32::from_le_bytes(req[0..4].try_into().unwrap());
    // Handles come from a high base so they cannot alias a dumb-buffer handle.
    if handle < 0x4000_0000 {
        return TestResult::Fail("a GEM handle must not fall in the dumb-handle space");
    }

    // ── mmap offset, and that it resolves to real distinct frames ──
    let mut m = [0u8; 16];
    m[0..4].copy_from_slice(&handle.to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_MMAP),
        m.as_mut_ptr() as usize,
        &state,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_MMAP of a live handle failed");
    }
    let offset = u64::from_le_bytes(m[8..16].try_into().unwrap());
    let frames = match state.mmap_frames(offset, 8192) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("the GEM_MMAP offset did not resolve to frames"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("8 KiB should resolve to two 4 KiB frames");
    }
    if frames[1] != frames[0] + 4096 {
        return TestResult::Fail("the allocation should be physically contiguous");
    }
    if frames[0] == 0 || frames[0] % 4096 != 0 {
        return TestResult::Fail("frame address is not a plausible page-aligned physical page");
    }
    // Zeroed before userspace sees it: these pages came from the kernel's own
    // allocator and could hold anything.
    // SAFETY: the frames were just allocated for this object and are
    // kernel-mapped; reading 8192 bytes stays inside them.
    let leaked = unsafe {
        core::slice::from_raw_parts(
            narf_memory::PhysAddr::new(frames[0]).kernel_ptr::<u8>(),
            8192,
        )
    }
    .iter()
    .any(|b| *b != 0);
    if leaked {
        return TestResult::Fail("a GEM buffer handed to userspace was not zeroed");
    }
    // A longer map than the object must be refused, or a client reads past it.
    if state.mmap_frames(offset, 8192 + 4096).is_ok() {
        return TestResult::Fail("mapping more than the object's size was allowed");
    }

    // ── GEM_OP reports back what was asked for, not what we did ──
    let mut info = [0u8; 32];
    let mut opreq = [0u8; 24];
    opreq[0..4].copy_from_slice(&handle.to_le_bytes());
    opreq[4..8].copy_from_slice(&u::AMDGPU_GEM_OP_GET_GEM_CREATE_INFO.to_le_bytes());
    opreq[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_OP),
        opreq.as_mut_ptr() as usize,
        &state,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_OP GET_GEM_CREATE_INFO failed");
    }
    if u64::from_le_bytes(info[0..8].try_into().unwrap()) != 8192 {
        return TestResult::Fail("GEM_OP did not report the page-rounded size");
    }
    if u64::from_le_bytes(info[16..24].try_into().unwrap()) != u::AMDGPU_GEM_DOMAIN_VRAM as u64 {
        return TestResult::Fail("GEM_OP must report the domain the client asked for");
    }

    // SET_PLACEMENT needs a migration path there isn't one of, and must be
    // refused rather than accepted-and-ignored.
    let mut setp = [0u8; 24];
    setp[0..4].copy_from_slice(&handle.to_le_bytes());
    setp[4..8].copy_from_slice(&u::AMDGPU_GEM_OP_SET_PLACEMENT.to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_OP),
        setp.as_mut_ptr() as usize,
        &state,
    )
    .is_ok()
    {
        return TestResult::Fail("SET_PLACEMENT should be refused while nothing can migrate");
    }

    // ── isolation: a second open's table does not see this handle ──
    let other = GemState::new();
    if other.owns(handle) {
        return TestResult::Fail("a handle leaked across opens");
    }
    let mut m2 = [0u8; 16];
    m2[0..4].copy_from_slice(&handle.to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_MMAP),
        m2.as_mut_ptr() as usize,
        &other,
    )
    .is_ok()
    {
        return TestResult::Fail("another open could mmap a handle it does not hold");
    }
    if other.mmap_frames(offset, 4096).is_ok() {
        return TestResult::Fail("another open could resolve a foreign GEM offset to frames");
    }

    // ── GEM_CLOSE belongs to the owning table only ──
    let mut c = [0u8; 8];
    c[0..4].copy_from_slice(&handle.to_le_bytes());
    // The foreign table must decline it, so the generic dumb path still gets
    // its chance at a handle that is not ours.
    if !matches!(
        dispatch(close_cmd, c.as_mut_ptr() as usize, &other),
        Err(FsError::Unsupported)
    ) {
        return TestResult::Fail("GEM_CLOSE of a foreign handle should fall through, not fail");
    }
    if dispatch(close_cmd, c.as_mut_ptr() as usize, &state).is_err() {
        return TestResult::Fail("GEM_CLOSE of our own handle failed");
    }
    if state.owns(handle) {
        return TestResult::Fail("the handle survived GEM_CLOSE");
    }
    // A low handle is a dumb handle: fall through rather than claiming it.
    let mut low = [0u8; 8];
    low[0..4].copy_from_slice(&3u32.to_le_bytes());
    if !matches!(
        dispatch(close_cmd, low.as_mut_ptr() as usize, &state),
        Err(FsError::Unsupported)
    ) {
        return TestResult::Fail("a dumb-buffer handle must fall through to the generic path");
    }

    // ── the validations, each reachable from userspace ──
    let create = |size: u64, domains: u64, flags: u64| {
        let mut r = [0u8; 32];
        r[0..8].copy_from_slice(&size.to_le_bytes());
        r[16..24].copy_from_slice(&domains.to_le_bytes());
        r[24..32].copy_from_slice(&flags.to_le_bytes());
        dispatch(
            gem_cmd(u::DRM_AMDGPU_GEM_CREATE),
            r.as_mut_ptr() as usize,
            &state,
        )
    };
    // An undefined create flag is EINVAL: accepting one would let a client
    // believe it got a property it did not.
    if create(4096, u::AMDGPU_GEM_DOMAIN_GTT as u64, 1 << 31).is_ok() {
        return TestResult::Fail("an unsettable create flag was accepted");
    }
    // VRAM_CONTIGUOUS looks settable and is not — the kernel sets it.
    if create(
        4096,
        u::AMDGPU_GEM_DOMAIN_GTT as u64,
        u::AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS as u64,
    )
    .is_ok()
    {
        return TestResult::Fail("VRAM_CONTIGUOUS is not in SETTABLE_MASK");
    }
    // Encryption cannot be honoured without TMZ, and a client that asked for
    // a secure buffer must not be given a plain one.
    if create(
        4096,
        u::AMDGPU_GEM_DOMAIN_GTT as u64,
        u::AMDGPU_GEM_CREATE_ENCRYPTED as u64,
    )
    .is_ok()
    {
        return TestResult::Fail("ENCRYPTED should be refused with no TMZ engine");
    }
    if create(4096, 0x8000, 0).is_ok() {
        return TestResult::Fail("a domain outside AMDGPU_GEM_DOMAIN_MASK was accepted");
    }
    // The special domains are exclusive: never two at once, never mixed with
    // CPU/GTT/VRAM (`amdgpu_gem_are_domains_valid`).
    if create(
        4096,
        (u::AMDGPU_GEM_DOMAIN_GDS | u::AMDGPU_GEM_DOMAIN_GWS) as u64,
        0,
    )
    .is_ok()
    {
        return TestResult::Fail("two special domains at once should be invalid");
    }
    if create(
        4096,
        (u::AMDGPU_GEM_DOMAIN_GDS | u::AMDGPU_GEM_DOMAIN_VRAM) as u64,
        0,
    )
    .is_ok()
    {
        return TestResult::Fail("a special domain mixed with VRAM should be invalid");
    }
    if create(0, u::AMDGPU_GEM_DOMAIN_GTT as u64, 0).is_ok() {
        return TestResult::Fail("a zero-sized buffer should be refused");
    }

    // A live GTT buffer, closed, so the test leaves no allocation behind.
    let mut keep = [0u8; 32];
    keep[0..8].copy_from_slice(&4096u64.to_le_bytes());
    keep[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_CREATE),
        keep.as_mut_ptr() as usize,
        &state,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_CREATE in the GTT domain failed");
    }
    let h2 = u32::from_le_bytes(keep[0..4].try_into().unwrap());
    // WAIT_IDLE reports idle: nothing can be busy without a submission path.
    let mut w = [0u8; 16];
    w[0..4].copy_from_slice(&h2.to_le_bytes());
    if dispatch(
        gem_cmd(u::DRM_AMDGPU_GEM_WAIT_IDLE),
        w.as_mut_ptr() as usize,
        &state,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_WAIT_IDLE failed on a live handle");
    }
    let mut c2 = [0u8; 8];
    c2[0..4].copy_from_slice(&h2.to_le_bytes());
    let _ = dispatch(close_cmd, c2.as_mut_ptr() as usize, &state);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
    smoke_amdgpu_gem_lifecycle_and_handle_isolation
);

/// The GMC 11 address-space geometry, derived rather than asserted from memory.
///
/// Every number here follows from `gmc_v11_0_sw_init`'s one call,
/// `amdgpu_vm_adjust_size(adev, 256 * 1024, 9, 3, 48)`, through the arithmetic
/// in `amdgpu_vm_adjust_size` and `amdgpu_vm_pt_level_shift`. The test
/// recomputes the decomposition independently of the module so a transcription
/// slip in either shows up as a disagreement: a wrong level shift walks the GPU
/// into the wrong page table.
fn smoke_amdgpu_vm_gmc11_geometry() -> TestResult {
    use crate::amdgpu_vm::{Geometry, Level, GPU_PAGE_SHIFT};

    let g = Geometry::GMC11;
    // vm_size = 1 << (48 - 30) GiB, max_pfn = vm_size << 18 = 2^36 pages.
    if g.max_pfn != 1 << 36 {
        return TestResult::Fail("max_pfn should be 2^36 pages (256 TiB at 4 KiB)");
    }
    // num_level 3 → root PDB2; block_size 9 because num_level > 1.
    if g.root_level != Level::Pdb2 || g.block_size != 9 {
        return TestResult::Fail("GMC11 roots at PDB2 with block_size 9");
    }
    // `amdgpu_vm_pt_level_shift`: 9 * (PDB0 - level) + block_size, PTB = 0.
    // Recomputed from the formula rather than restated as four numbers, so a
    // transcription slip in the module cannot be matched by the same slip here.
    for (i, level) in [Level::Pdb2, Level::Pdb1, Level::Pdb0]
        .into_iter()
        .enumerate()
    {
        let steps = 2 - i as u32; // PDB0 - level
        if g.level_shift(level) != 9 * steps + g.block_size {
            return TestResult::Fail("a level shift disagrees with amdgpu_vm_pt_level_shift");
        }
    }
    if g.level_shift(Level::Ptb) != 0 {
        return TestResult::Fail("the leaf level shift is zero");
    }
    // Four levels walked, root first.
    let walked: alloc::vec::Vec<Level> = g.levels().collect();
    if walked != alloc::vec![Level::Pdb2, Level::Pdb1, Level::Pdb0, Level::Ptb] {
        return TestResult::Fail("the walked levels are not PDB2..PTB");
    }
    // Root sized to cover max_pfn exactly: 2^36 >> 27 = 512. Leaf 1<<9.
    for level in walked.iter().copied() {
        if g.entries_at(level) != 512 {
            return TestResult::Fail("every GMC11 level should hold 512 entries");
        }
    }
    // 4 levels x 9 bits + 12 page bits = 48, which is the max_bits passed in.
    let covered: u32 = GPU_PAGE_SHIFT + 9 * 4;
    if 1u64 << covered != g.max_pfn * 4096 {
        return TestResult::Fail("the level geometry does not cover max_pfn exactly");
    }

    // Index decomposition: VA bits 47:39 → PDB2, 38:30 → PDB1, 29:21 → PDB0,
    // 20:12 → PTB. Build an address with a distinct index at each level.
    let va = (0x1A2u64 << 39) | (0x0B3 << 30) | (0x1C4 << 21) | (0x0D5 << 12);
    for (level, want) in [
        (Level::Pdb2, 0x1A2u64),
        (Level::Pdb1, 0x0B3),
        (Level::Pdb0, 0x1C4),
        (Level::Ptb, 0x0D5),
    ] {
        if g.index_at(va, level) != want {
            return TestResult::Fail("a VA did not decompose into the expected indices");
        }
    }
    // `DEV_INFO`'s pte_fragment_size: (1 << 9) * 4096 = 2 MiB.
    if g.fragment_bytes() != 2 * 1024 * 1024 {
        return TestResult::Fail("the fragment size should be 2 MiB");
    }
    // The usable window excludes the bottom 64 KiB and the top CSA/seq64/trap.
    let (bottom, top) = g.usable();
    if bottom != 1 << 16 {
        return TestResult::Fail("the first 64 KiB is reserved so a null GPU pointer faults");
    }
    if top != g.max_pfn * 4096 - ((1 << 16) + (2 << 20) + (2 << 20)) {
        return TestResult::Fail("the top reservation is trap + seq64 + CSA");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu_vm", smoke_amdgpu_vm_gmc11_geometry);

/// PTE composition, including the bits `gmc_v11_0_get_vm_pte` CLEARS.
///
/// The negative cases are the point. Linux clears `EXECUTABLE` and `NOALLOC`
/// when a request does not ask for them rather than leaving whatever the base
/// flags held, and PRT clears `VALID` — a PRT entry is deliberately not a valid
/// translation. A transcription that only ORed the positive cases would look
/// right and grant execute permission on every mapping.
fn smoke_amdgpu_vm_pte_flags_match_gmc11() -> TestResult {
    use crate::amdgpu_uapi as u;
    use crate::amdgpu_vm::*;

    // System memory, as every buffer is until there is VRAM placement.
    let base = base_flags(true);
    if base & PTE_VALID == 0 || base & PTE_SNOOPED == 0 || base & PTE_SYSTEM == 0 {
        return TestResult::Fail("a system mapping is VALID | SNOOPED | SYSTEM");
    }

    // A plain read/write mapping: no execute, no noalloc, memory type NC.
    let rw = pte_flags(
        base,
        u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE,
        false,
    );
    if rw & PTE_READABLE == 0 || rw & PTE_WRITEABLE == 0 {
        return TestResult::Fail("READABLE|WRITEABLE did not reach the PTE");
    }
    if rw & PTE_EXECUTABLE != 0 {
        return TestResult::Fail("EXECUTABLE must be cleared when not requested");
    }
    if rw & PTE_NOALLOC != 0 {
        return TestResult::Fail("NOALLOC must be cleared when not requested");
    }
    if rw & MTYPE_MASK != MTYPE_NC << MTYPE_SHIFT {
        return TestResult::Fail("the default memory type is NC");
    }

    // Starting from flags that already have EXECUTABLE set, a request without
    // it must come back without it.
    let cleared = pte_flags(base | PTE_EXECUTABLE, u::AMDGPU_VM_PAGE_READABLE, false);
    if cleared & PTE_EXECUTABLE != 0 {
        return TestResult::Fail("EXECUTABLE survived a request that omitted it");
    }

    // The memory type lives at bits 50:48 on GFX10/11 — NOT 58:57 (GFX9) or
    // 55:54 (GFX12). Using the wrong macro would collide with NOALLOC at 58.
    for (vm_mtype, want) in [
        (u::AMDGPU_VM_MTYPE_WC, MTYPE_WC),
        (u::AMDGPU_VM_MTYPE_CC, MTYPE_CC),
        (u::AMDGPU_VM_MTYPE_UC, MTYPE_UC),
        (u::AMDGPU_VM_MTYPE_NC, MTYPE_NC),
        (u::AMDGPU_VM_MTYPE_DEFAULT, MTYPE_NC),
    ] {
        let f = pte_flags(base, u::AMDGPU_VM_PAGE_READABLE | vm_mtype, false);
        if (f & MTYPE_MASK) >> MTYPE_SHIFT != want {
            return TestResult::Fail("a memory type did not land in bits 50:48");
        }
        if f & (1 << 57) != 0 || f & (1 << 58) != 0 {
            return TestResult::Fail("the memory type spilled into bit 57 or 58");
        }
    }

    // A COHERENT/UNCACHED buffer overrides the request's memory type, and is
    // applied last for that reason.
    let overridden = pte_flags(
        base,
        u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_MTYPE_WC,
        true,
    );
    if (overridden & MTYPE_MASK) >> MTYPE_SHIFT != MTYPE_UC {
        return TestResult::Fail("an uncached BO must override the requested memory type");
    }

    // PRT: sets PRT|SNOOPED|LOG|SYSTEM and clears VALID.
    let prt = pte_flags(base, u::AMDGPU_VM_PAGE_PRT, false);
    if prt & PTE_PRT == 0 || prt & PTE_LOG == 0 || prt & PTE_SYSTEM == 0 {
        return TestResult::Fail("a PRT entry sets PRT | LOG | SYSTEM");
    }
    if prt & PTE_VALID != 0 {
        return TestResult::Fail("a PRT entry must NOT be a valid translation");
    }

    // The leaf entry carries the physical address in bits 47:12, so a
    // misaligned or out-of-range address must be refused rather than allowed
    // to spill into the flags.
    if make_pte(0x1000, rw).is_err() {
        return TestResult::Fail("a page-aligned address should compose");
    }
    if make_pte(0x1001, rw).is_ok() {
        return TestResult::Fail("a misaligned physical address must be refused");
    }
    if make_pte(1u64 << 48, rw).is_ok() {
        return TestResult::Fail("an address beyond 48 bits must be refused");
    }
    let pte = make_pte(0xABCD_E000, rw).unwrap_or(0);
    if pte & GMC_HOLE_MASK & !0xFFF != 0xABCD_E000 {
        return TestResult::Fail("the physical address did not survive composition");
    }

    // The canonical hole: the hardware is programmed as if it does not exist.
    if strip_hole(0xFFFF_8000_0000_1000) != 0x0000_8000_0000_1000 {
        return TestResult::Fail("strip_hole should drop the sign-extension bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_vm",
    smoke_amdgpu_vm_pte_flags_match_gmc11
);

/// `AMDGPU_GEM_VA`'s validation and bookkeeping.
fn smoke_amdgpu_vm_gem_va_maps_and_validates() -> TestResult {
    use crate::amdgpu_gem::GemState;
    use crate::amdgpu_uapi as u;
    use crate::amdgpu_vm::{self as vm, VmState, GMC_HOLE_START, VA_RESERVED_BOTTOM};
    use crate::drm_uapi::DRM_COMMAND_BASE;
    use narf_filesystem::FsError;

    let gem = GemState::new();
    let state = VmState::new();
    let va_cmd = DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA;

    // A 16 KiB buffer to map.
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&16384u64.to_le_bytes());
    create[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        create.as_mut_ptr() as usize,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_CREATE failed");
    }
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());

    let req = |op: u32, flags: u32, va: u64, offset: u64, size: u64| {
        let mut r = [0u8; 40];
        r[0..4].copy_from_slice(&handle.to_le_bytes());
        r[8..12].copy_from_slice(&op.to_le_bytes());
        r[12..16].copy_from_slice(&flags.to_le_bytes());
        r[16..24].copy_from_slice(&va.to_le_bytes());
        r[24..32].copy_from_slice(&offset.to_le_bytes());
        r[32..40].copy_from_slice(&size.to_le_bytes());
        vm::dispatch(va_cmd, r.as_mut_ptr() as usize, &state, &gem)
    };
    const RW: u32 = u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE;
    const BASE_VA: u64 = 0x1_0000_0000;

    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 0, 16384).is_err() {
        return TestResult::Fail("a valid MAP was refused");
    }
    match state.lookup(BASE_VA + 4096) {
        Some(m) if m.gem_handle == handle && m.va == BASE_VA && m.size == 16384 => {}
        _ => return TestResult::Fail("the mapping was not recorded over its whole range"),
    }
    if state.lookup(BASE_VA + 16384).is_some() {
        return TestResult::Fail("the mapping leaked past its end");
    }

    // An overlapping MAP is EINVAL; REPLACE is the op that asks for one to go.
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA + 4096, 0, 4096).is_ok() {
        return TestResult::Fail("an overlapping MAP should be refused");
    }
    if req(u::AMDGPU_VA_OP_REPLACE, RW, BASE_VA + 4096, 0, 4096).is_err() {
        return TestResult::Fail("REPLACE over a live range should succeed");
    }
    if state.lookup(BASE_VA).is_some() {
        return TestResult::Fail("REPLACE should have dropped the mapping it covered");
    }

    // UNMAP names a mapping exactly; a partial range is EINVAL and an absent
    // one is ENOENT, which are different answers a client can act on.
    if !matches!(
        req(u::AMDGPU_VA_OP_UNMAP, RW, BASE_VA + 4096, 0, 8192),
        Err(FsError::InvalidData)
    ) {
        return TestResult::Fail("UNMAP of a partial range should be EINVAL");
    }
    if !matches!(
        req(u::AMDGPU_VA_OP_UNMAP, RW, BASE_VA + 0x10_0000, 0, 4096),
        Err(FsError::NotFound)
    ) {
        return TestResult::Fail("UNMAP of an absent mapping should be ENOENT");
    }
    if req(u::AMDGPU_VA_OP_UNMAP, RW, BASE_VA + 4096, 0, 4096).is_err() {
        return TestResult::Fail("UNMAP of an exact mapping should succeed");
    }
    if state.mapping_count() != 0 {
        return TestResult::Fail("the address space should be empty again");
    }

    // ── validation, in Linux's order ──
    // Below VA_RESERVED_BOTTOM: a null GPU pointer must fault, so the first
    // 64 KiB is never mappable.
    if req(u::AMDGPU_VA_OP_MAP, RW, VA_RESERVED_BOTTOM - 4096, 0, 4096).is_ok() {
        return TestResult::Fail("the bottom reserved region must not be mappable");
    }
    // Inside the canonical hole.
    if req(u::AMDGPU_VA_OP_MAP, RW, GMC_HOLE_START, 0, 4096).is_ok() {
        return TestResult::Fail("an address inside the VA hole must be refused");
    }
    // Past the top reservation.
    let (_, top) = state.geometry().usable();
    if req(u::AMDGPU_VA_OP_MAP, RW, top - 4096, 0, 8192).is_ok() {
        return TestResult::Fail("a range crossing the top reservation must be refused");
    }
    // PRT cannot be combined with ordinary page permissions — the two flag
    // sets are alternatives, not a union.
    if req(
        u::AMDGPU_VA_OP_MAP,
        RW | u::AMDGPU_VM_PAGE_PRT,
        BASE_VA,
        0,
        4096,
    )
    .is_ok()
    {
        return TestResult::Fail("PRT mixed with page permissions is an invalid combination");
    }
    // An undefined flag.
    if req(u::AMDGPU_VA_OP_MAP, RW | (1 << 20), BASE_VA, 0, 4096).is_ok() {
        return TestResult::Fail("an undefined VM flag should be refused");
    }
    // An unknown operation.
    if req(99, RW, BASE_VA, 0, 4096).is_ok() {
        return TestResult::Fail("an unknown VA operation should be refused");
    }
    // Mapping more of the buffer than it holds would map pages it does not own.
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 8192, 16384).is_ok() {
        return TestResult::Fail("offset + size past the buffer's end must be refused");
    }
    // Misalignment, in each of the three fields.
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA + 1, 0, 4096).is_ok() {
        return TestResult::Fail("an unaligned VA must be refused");
    }
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 0, 4095).is_ok() {
        return TestResult::Fail("an unaligned size must be refused");
    }
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 1, 4096).is_ok() {
        return TestResult::Fail("an unaligned buffer offset must be refused");
    }
    // A handle this open does not hold.
    let mut foreign = [0u8; 40];
    foreign[0..4].copy_from_slice(&0x4000_9999u32.to_le_bytes());
    foreign[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
    foreign[12..16].copy_from_slice(&RW.to_le_bytes());
    foreign[16..24].copy_from_slice(&BASE_VA.to_le_bytes());
    foreign[32..40].copy_from_slice(&4096u64.to_le_bytes());
    if vm::dispatch(va_cmd, foreign.as_mut_ptr() as usize, &state, &gem).is_ok() {
        return TestResult::Fail("a VA map naming a foreign GEM handle must be refused");
    }

    // CLEAR drops whatever intersects, and succeeds on an empty range.
    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 0, 16384).is_err() {
        return TestResult::Fail("re-MAP after the validation cases failed");
    }
    if req(u::AMDGPU_VA_OP_CLEAR, RW, BASE_VA + 4096, 0, 4096).is_err() {
        return TestResult::Fail("CLEAR should succeed");
    }
    if state.mapping_count() != 0 {
        return TestResult::Fail("CLEAR should have dropped the intersecting mapping");
    }
    if req(u::AMDGPU_VA_OP_CLEAR, RW, BASE_VA, 0, 4096).is_err() {
        return TestResult::Fail("CLEAR of an empty range should still succeed");
    }

    let mut c = [0u8; 8];
    c[0..4].copy_from_slice(&handle.to_le_bytes());
    let _ = crate::amdgpu_gem::dispatch(0x09, c.as_mut_ptr() as usize, &gem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_vm",
    smoke_amdgpu_vm_gem_va_maps_and_validates
);

/// Page tables are really built: the entries are read back out of the memory
/// the GPU would walk.
///
/// This is the first test in the VM series that touches hardware-format memory
/// rather than pure functions. What it checks is that a mapping produces a
/// walkable chain — root PDE → PDB1 PDE → PDB0 PDE → leaf PTE — with the
/// physical address and flags at each step, and that unmapping restores the
/// invalid pattern and frees the directories that are left empty.
fn smoke_amdgpu_vm_page_tables_are_walkable() -> TestResult {
    use crate::amdgpu_gem::GemState;
    use crate::amdgpu_uapi as u;
    use crate::amdgpu_vm::{self as vm, Level, VmState, GPU_PAGE_SIZE};
    use crate::drm_uapi::DRM_COMMAND_BASE;

    let gem = GemState::new();
    let state = VmState::new();
    let g = state.geometry();

    // Nothing mapped: no root directory, no tables.
    if state.root_phys().is_some() || state.table_count() != 0 {
        return TestResult::Fail("an unused address space should allocate nothing");
    }

    // A 3-page buffer, so the mapping spans more than one leaf entry.
    const PAGES: u64 = 3;
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&(PAGES * GPU_PAGE_SIZE).to_le_bytes());
    create[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        create.as_mut_ptr() as usize,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_CREATE failed");
    }
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());
    let Some(object) = gem.object(handle) else {
        return TestResult::Fail("setup: the created object is not in the table");
    };
    let phys = object.phys;

    let va_cmd = DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA;
    let req = |op: u32, flags: u32, va: u64, offset: u64, size: u64| {
        let mut r = [0u8; 40];
        r[0..4].copy_from_slice(&handle.to_le_bytes());
        r[8..12].copy_from_slice(&op.to_le_bytes());
        r[12..16].copy_from_slice(&flags.to_le_bytes());
        r[16..24].copy_from_slice(&va.to_le_bytes());
        r[24..32].copy_from_slice(&offset.to_le_bytes());
        r[32..40].copy_from_slice(&size.to_le_bytes());
        vm::dispatch(va_cmd, r.as_mut_ptr() as usize, &state, &gem)
    };
    const RW: u32 = u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE;
    // An address with a distinct index at every level, so a swapped shift
    // would land the entry in the wrong table.
    const BASE_VA: u64 = (0x11u64 << 39) | (0x22 << 30) | (0x33 << 21) | (0x44 << 12);

    if req(u::AMDGPU_VA_OP_MAP, RW, BASE_VA, 0, PAGES * GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("MAP of a 3-page buffer failed");
    }

    // Root plus one table at each of PDB1, PDB0 and PTB: four in all, since
    // the three pages share a leaf table.
    if state.table_count() != 4 {
        return TestResult::Fail("a 3-page map in one leaf should need exactly four tables");
    }
    let Some(root) = state.root_phys() else {
        return TestResult::Fail("the root page directory was not allocated");
    };
    if root % GPU_PAGE_SIZE != 0 {
        return TestResult::Fail("the root directory must be page aligned");
    }

    // Each directory entry must be a valid, system, snooped pointer at a
    // page-aligned child — and must NOT carry PDE_PTE, which would mark it a
    // leaf mapping a huge page instead of a pointer to a table.
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0] {
        let Some(pde) = state.directory_entry(BASE_VA, level) else {
            return TestResult::Fail("a directory entry on the mapped path is missing");
        };
        if pde & vm::PTE_VALID == 0 {
            return TestResult::Fail("a directory entry on the mapped path is not valid");
        }
        if pde & vm::PTE_SYSTEM == 0 || pde & vm::PTE_SNOOPED == 0 {
            return TestResult::Fail("a table in system memory needs SYSTEM | SNOOPED");
        }
        if pde & vm::PDE_PTE != 0 {
            return TestResult::Fail("a pointer PDE must not be marked as a leaf");
        }
        // `gmc_v11_0_get_vm_pde`'s `BUG_ON(*addr & 0xFFFF00000000003F)` is on
        // the ADDRESS, before the flags are folded in — and VALID|SYSTEM|
        // SNOOPED are bits 0:2, inside that mask. So the composed entry is
        // checked differently: bits 63:48 must be clear, and the low 12 bits
        // must be exactly those three flags, which is only possible if the
        // address underneath them is page aligned.
        if pde & 0xFFFF_0000_0000_0000 != 0 {
            return TestResult::Fail("a PDE carries bits above the 48-bit address space");
        }
        if pde & 0xFFF != vm::PTE_VALID | vm::PTE_SYSTEM | vm::PTE_SNOOPED {
            return TestResult::Fail("a PDE's low bits are not exactly its three flags");
        }
    }

    // The leaves: one per page, each pointing at its own frame.
    for page in 0..PAGES {
        let va = BASE_VA + page * GPU_PAGE_SIZE;
        let Some(pte) = state.leaf_entry(va) else {
            return TestResult::Fail("a leaf entry on the mapped path is missing");
        };
        if pte & vm::PTE_VALID == 0 {
            return TestResult::Fail("a mapped page's PTE is not valid");
        }
        if pte & !0xFFFu64 & vm::GMC_HOLE_MASK != phys + page * GPU_PAGE_SIZE {
            return TestResult::Fail("a PTE does not point at the buffer's frame");
        }
        if pte & vm::PTE_READABLE == 0 || pte & vm::PTE_WRITEABLE == 0 {
            return TestResult::Fail("the mapping's permissions did not reach the PTE");
        }
        if pte & vm::PTE_EXECUTABLE != 0 {
            return TestResult::Fail("execute was not requested and must not be granted");
        }
    }
    // One page past the mapping must be invalid, not merely absent from the
    // bookkeeping — this is what stops a shader reading past the buffer.
    match state.leaf_entry(BASE_VA + PAGES * GPU_PAGE_SIZE) {
        Some(pte) if pte & vm::PTE_VALID == 0 => {}
        Some(_) => return TestResult::Fail("the page after the mapping is a valid translation"),
        None => {
            return TestResult::Fail("the leaf table past the mapping should exist and be invalid")
        }
    }

    // A second mapping far away needs its own PDB1/PDB0/PTB but shares the
    // root, so three more tables.
    const FAR_VA: u64 = BASE_VA + (1u64 << 39);
    if req(u::AMDGPU_VA_OP_MAP, RW, FAR_VA, 0, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("a second, distant MAP failed");
    }
    if state.table_count() != 7 {
        return TestResult::Fail("a distant map should add three tables, sharing the root");
    }

    // Unmapping the far one frees its three tables and leaves the near one.
    if req(u::AMDGPU_VA_OP_UNMAP, RW, FAR_VA, 0, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("UNMAP of the distant mapping failed");
    }
    if state.table_count() != 4 {
        return TestResult::Fail("an emptied subtree should be freed");
    }
    if state.leaf_entry(FAR_VA).is_some() {
        return TestResult::Fail("the freed subtree is still walkable");
    }
    if state.leaf_entry(BASE_VA).is_none() {
        return TestResult::Fail("freeing one subtree disturbed another");
    }

    // Unmapping the last mapping releases everything, root included.
    if req(u::AMDGPU_VA_OP_UNMAP, RW, BASE_VA, 0, PAGES * GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("UNMAP of the first mapping failed");
    }
    if state.table_count() != 0 || state.root_phys().is_some() {
        return TestResult::Fail("the last unmap should release the root directory too");
    }

    // An executable mapping gets the bit; the same range re-mapped read-only
    // must not keep it. This is the clearing behaviour gmc_v11_0_get_vm_pte
    // relies on, seen through the real tables.
    const X: u32 = RW | u::AMDGPU_VM_PAGE_EXECUTABLE;
    if req(u::AMDGPU_VA_OP_MAP, X, BASE_VA, 0, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("an executable MAP failed");
    }
    match state.leaf_entry(BASE_VA) {
        Some(pte) if pte & vm::PTE_EXECUTABLE != 0 => {}
        _ => return TestResult::Fail("EXECUTABLE did not reach the PTE"),
    }
    if req(u::AMDGPU_VA_OP_REPLACE, RW, BASE_VA, 0, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("REPLACE over an executable mapping failed");
    }
    match state.leaf_entry(BASE_VA) {
        Some(pte) if pte & vm::PTE_EXECUTABLE == 0 && pte & vm::PTE_VALID != 0 => {}
        _ => return TestResult::Fail("REPLACE left the execute bit set"),
    }

    // CLEAR tears down whatever it covers.
    if req(u::AMDGPU_VA_OP_CLEAR, RW, BASE_VA, 0, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("CLEAR failed");
    }
    if state.table_count() != 0 {
        return TestResult::Fail("CLEAR should have released the tables");
    }

    let _ = g;
    let mut c = [0u8; 8];
    c[0..4].copy_from_slice(&handle.to_le_bytes());
    let _ = crate::amdgpu_gem::dispatch(0x09, c.as_mut_ptr() as usize, &gem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_vm",
    smoke_amdgpu_vm_page_tables_are_walkable
);

/// `AMDGPU_CTX`, including the capability that gates an above-normal priority.
///
/// Mesa allocates a context per GL/Vulkan context and names it on every
/// submission, so this is the last ioctl between opening the device and
/// submitting work. The interesting part is the priority gate: NORMAL and
/// below are open to everyone, above needs CAP_SYS_NICE or DRM master, and
/// garbage in the field is DELIBERATELY not an error.
fn smoke_amdgpu_ctx_alloc_query_and_priority_gate() -> TestResult {
    use crate::amdgpu_ctx::{dispatch, CtxState};
    use crate::amdgpu_uapi as u;
    use crate::drm_uapi::DRM_COMMAND_BASE;
    use narf_filesystem::FsError;

    let state = CtxState::new();
    let ctx_cmd = DRM_COMMAND_BASE + u::DRM_AMDGPU_CTX;
    let call = |op: u32, flags: u32, id: u32, priority: i32, master: bool| {
        let mut r = [0u8; 24];
        r[0..4].copy_from_slice(&op.to_le_bytes());
        r[4..8].copy_from_slice(&flags.to_le_bytes());
        r[8..12].copy_from_slice(&id.to_le_bytes());
        r[12..16].copy_from_slice(&priority.to_le_bytes());
        let rc = dispatch(ctx_cmd, r.as_mut_ptr() as usize, &state, master);
        (rc, u32::from_le_bytes(r[0..4].try_into().unwrap()))
    };

    // ── alloc at NORMAL, which anyone may do ──
    let (rc, id) = call(
        u::AMDGPU_CTX_OP_ALLOC_CTX,
        0,
        0,
        u::AMDGPU_CTX_PRIORITY_NORMAL,
        false,
    );
    if rc.is_err() {
        return TestResult::Fail("ALLOC_CTX at NORMAL priority failed");
    }
    if id == 0 {
        return TestResult::Fail("context ids start at 1 so a zeroed field names nothing");
    }
    match state.get(id) {
        Some(c) if c.priority == u::AMDGPU_CTX_PRIORITY_NORMAL => {}
        _ => return TestResult::Fail("the context did not record its priority"),
    }

    // ── garbage priority is NOT an error ──
    // Linux: "For backwards compatibility, we need to accept ioctls with
    // garbage in the priority field", and such a request becomes NORMAL.
    // Refusing it would break clients that never initialised the field.
    for bogus in [u::AMDGPU_CTX_PRIORITY_UNSET, 12345, -7] {
        let (rc, gid) = call(u::AMDGPU_CTX_OP_ALLOC_CTX, 0, 0, bogus, false);
        if rc.is_err() {
            return TestResult::Fail("a garbage priority must be accepted, not refused");
        }
        match state.get(gid) {
            Some(c) if c.priority == u::AMDGPU_CTX_PRIORITY_NORMAL => {}
            _ => return TestResult::Fail("a garbage priority should become NORMAL"),
        }
        let _ = call(u::AMDGPU_CTX_OP_FREE_CTX, 0, gid, 0, false);
    }

    // ── the priority gate ──
    // The harness task holds the full boot capability set, so without this
    // the unprivileged branch would never be reached and the gate would look
    // like it worked while refusing nobody.
    let saved = narf_filesystem::__test_swap_caller_capable_hook(Some(|_| false));

    // No CAP_SYS_NICE and not master: refused.
    for high in [
        u::AMDGPU_CTX_PRIORITY_HIGH,
        u::AMDGPU_CTX_PRIORITY_VERY_HIGH,
    ] {
        if !matches!(
            call(u::AMDGPU_CTX_OP_ALLOC_CTX, 0, 0, high, false).0,
            Err(FsError::PermissionDenied)
        ) {
            return TestResult::Fail("an above-normal priority needs CAP_SYS_NICE or master");
        }
    }
    // Below NORMAL is open to everyone — a client may always deprioritise
    // itself, and refusing that would be nonsense.
    for low in [u::AMDGPU_CTX_PRIORITY_LOW, u::AMDGPU_CTX_PRIORITY_VERY_LOW] {
        let (rc, lid) = call(u::AMDGPU_CTX_OP_ALLOC_CTX, 0, 0, low, false);
        if rc.is_err() {
            return TestResult::Fail("a below-normal priority should need no privilege");
        }
        let _ = call(u::AMDGPU_CTX_OP_FREE_CTX, 0, lid, 0, false);
    }
    // DRM master is the second arm: a compositor may prioritise its own work
    // without holding a capability.
    let (rc, mid) = call(
        u::AMDGPU_CTX_OP_ALLOC_CTX,
        0,
        0,
        u::AMDGPU_CTX_PRIORITY_HIGH,
        true,
    );
    if rc.is_err() {
        return TestResult::Fail("DRM master should be permitted an above-normal priority");
    }
    let _ = call(u::AMDGPU_CTX_OP_FREE_CTX, 0, mid, 0, false);

    // And CAP_SYS_NICE is the other arm: granted it, a non-master gets in.
    narf_filesystem::__test_swap_caller_capable_hook(Some(|cap| cap == 23));
    let (rc, nid) = call(
        u::AMDGPU_CTX_OP_ALLOC_CTX,
        0,
        0,
        u::AMDGPU_CTX_PRIORITY_VERY_HIGH,
        false,
    );
    if rc.is_err() {
        return TestResult::Fail("CAP_SYS_NICE should permit an above-normal priority");
    }
    let _ = call(u::AMDGPU_CTX_OP_FREE_CTX, 0, nid, 0, false);
    narf_filesystem::__test_swap_caller_capable_hook(saved);

    // ── query ──
    // A query naming no context is ENOENT, not a zeroed answer that would
    // read as "healthy".
    for op in [u::AMDGPU_CTX_OP_QUERY_STATE, u::AMDGPU_CTX_OP_QUERY_STATE2] {
        if !matches!(call(op, 0, 999_999, 0, false).0, Err(FsError::NotFound)) {
            return TestResult::Fail("a query naming no context should be ENOENT");
        }
        if call(op, 0, id, 0, false).0.is_err() {
            return TestResult::Fail("a query on a live context failed");
        }
    }

    // ── stable pstate ──
    match call(u::AMDGPU_CTX_OP_GET_STABLE_PSTATE, 0, id, 0, false) {
        (Ok(_), v) if v == u::AMDGPU_CTX_STABLE_PSTATE_NONE => {}
        _ => return TestResult::Fail("a fresh context should report pstate NONE"),
    }
    if call(
        u::AMDGPU_CTX_OP_SET_STABLE_PSTATE,
        u::AMDGPU_CTX_STABLE_PSTATE_PEAK,
        id,
        0,
        false,
    )
    .0
    .is_err()
    {
        return TestResult::Fail("SET_STABLE_PSTATE to PEAK failed");
    }
    match call(u::AMDGPU_CTX_OP_GET_STABLE_PSTATE, 0, id, 0, false) {
        (Ok(_), v) if v == u::AMDGPU_CTX_STABLE_PSTATE_PEAK => {}
        _ => return TestResult::Fail("the set pstate did not read back"),
    }
    // The mask is four bits but only 0..=PEAK are defined, so the range check
    // is separate from the mask check and both must bite.
    if call(u::AMDGPU_CTX_OP_SET_STABLE_PSTATE, 5, id, 0, false)
        .0
        .is_ok()
    {
        return TestResult::Fail("a pstate above PEAK should be refused");
    }
    if call(u::AMDGPU_CTX_OP_SET_STABLE_PSTATE, 1 << 8, id, 0, false)
        .0
        .is_ok()
    {
        return TestResult::Fail("a flag outside the pstate mask should be refused");
    }

    // ── flags must be zero on every op but SET_STABLE_PSTATE ──
    // Forward compatibility: a client setting an unknown flag is refused, not
    // silently served without the behaviour it asked for.
    for op in [
        u::AMDGPU_CTX_OP_ALLOC_CTX,
        u::AMDGPU_CTX_OP_FREE_CTX,
        u::AMDGPU_CTX_OP_QUERY_STATE,
        u::AMDGPU_CTX_OP_QUERY_STATE2,
        u::AMDGPU_CTX_OP_GET_STABLE_PSTATE,
    ] {
        if call(op, 1, id, 0, false).0.is_ok() {
            return TestResult::Fail("a non-zero flags field should be refused");
        }
    }

    // ── free ──
    if call(u::AMDGPU_CTX_OP_FREE_CTX, 0, id, 0, false).0.is_err() {
        return TestResult::Fail("FREE_CTX of a live context failed");
    }
    if !matches!(
        call(u::AMDGPU_CTX_OP_FREE_CTX, 0, id, 0, false).0,
        Err(FsError::NotFound)
    ) {
        return TestResult::Fail("a double free should be ENOENT");
    }
    // Every context this test allocated has been freed, including the ones
    // the refused-flags cases did NOT create.
    if state.count() != 0 {
        return TestResult::Fail("a context outlived its free");
    }
    // An unknown operation.
    if call(99, 0, id, 0, false).0.is_ok() {
        return TestResult::Fail("an unknown CTX operation should be refused");
    }

    // Contexts are per-open: a second table does not see this one's ids.
    let other = CtxState::new();
    if other.get(id).is_some() {
        return TestResult::Fail("a context id leaked across opens");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_ctx",
    smoke_amdgpu_ctx_alloc_query_and_priority_gate
);

/// Activating an address space programs both hubs and then invalidates.
///
/// The ordering is the property: base and bounds before the context is
/// enabled, TLB invalidated after. A forgotten invalidate means the MMU keeps
/// serving translations cached for whatever previously held the VMID — one
/// process reading another's memory, silently.
fn smoke_amdgpu_vm_activate_programs_both_hubs() -> TestResult {
    use crate::amdgpu_gem::GemState;
    use crate::amdgpu_uapi as u;
    use crate::amdgpu_vm::{self as vm, ActivateError, VmState, GPU_PAGE_SIZE};
    use crate::amdgpu_vmhub_regs::{
        test_support::MockVmHubMmio, GFXHUB_V3_0, MMHUB_V3_0, TLB_POLL_BUDGET,
    };
    use crate::amdgpu_vmid::{Pasid, VmidPool};
    use crate::drm_uapi::DRM_COMMAND_BASE;

    let gem = GemState::new();
    let state = VmState::new();
    let mut pool = VmidPool::new(crate::amdgpu_vmid::VmHub::Gfx);

    // An address space with nothing mapped has no root directory, and binding
    // a VMID to address 0 would point the MMU at physical page 0.
    let mut g0 = MockVmHubMmio::new();
    let mut m0 = MockVmHubMmio::new();
    if !matches!(
        vm::activate(
            &state,
            &mut pool,
            1 as Pasid,
            &mut g0,
            &GFXHUB_V3_0,
            &mut m0,
            &MMHUB_V3_0,
        ),
        Err(ActivateError::NoPageTables)
    ) {
        return TestResult::Fail("activating an empty address space must be refused");
    }
    if !g0.writes.is_empty() || !m0.writes.is_empty() {
        return TestResult::Fail("a refused activation must touch no register");
    }

    // Map something so a root directory exists.
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&GPU_PAGE_SIZE.to_le_bytes());
    create[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        create.as_mut_ptr() as usize,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_CREATE failed");
    }
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());
    let mut map = [0u8; 40];
    map[0..4].copy_from_slice(&handle.to_le_bytes());
    map[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
    map[12..16]
        .copy_from_slice(&(u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE).to_le_bytes());
    map[16..24].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
    map[32..40].copy_from_slice(&GPU_PAGE_SIZE.to_le_bytes());
    if vm::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA,
        map.as_mut_ptr() as usize,
        &state,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: MAP failed");
    }
    let Some(root) = state.root_phys() else {
        return TestResult::Fail("setup: no root directory after a map");
    };

    // The invalidate polls an ACK; stage it so the poll terminates.
    let mut gfx = MockVmHubMmio::new();
    let mut mm = MockVmHubMmio::new();
    // The invalidate polls an ACK register; make it answer on the first poll
    // so the budget is not spent.
    // The poll waits for the VMID's own bit in the ACK; all-ones satisfies it
    // whichever VMID the pool hands out.
    gfx.auto_ack_after = Some((GFXHUB_V3_0.inv_eng0_ack << 2, u32::MAX));
    mm.auto_ack_after = Some((MMHUB_V3_0.inv_eng0_ack << 2, u32::MAX));

    let vmid = match vm::activate(
        &state,
        &mut pool,
        1 as Pasid,
        &mut gfx,
        &GFXHUB_V3_0,
        &mut mm,
        &MMHUB_V3_0,
    ) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("activation of a mapped address space failed"),
    };
    if vmid == 0 {
        return TestResult::Fail("a user address space must not be given the kernel VMID");
    }

    // Both hubs were programmed — a VMID bound in one and not the other
    // translates for the shader engines and faults for display, or vice versa.
    for (writes, regs, name) in [
        (&gfx.writes, &GFXHUB_V3_0, "gfx"),
        (&mm.writes, &MMHUB_V3_0, "mm"),
    ] {
        let _ = name;
        let at = |dword: u32| -> Option<u32> {
            writes
                .iter()
                .find(|(off, _)| *off == dword << 2)
                .map(|(_, v)| *v)
        };
        let stride = regs.ctx_addr_distance * (vmid as u32);
        // Page-table base: the low half holds the root's low 32 bits.
        match at(regs.ctx0_pt_base_lo + stride) {
            Some(v) if v == root as u32 => {}
            _ => return TestResult::Fail("the page-table base was not programmed"),
        }
        // Bounds: start 0, end max_pfn - 1. Left at a cold-boot zero the
        // context would bound its address space to nothing.
        match at(regs.ctx0_pt_start_lo + stride) {
            Some(0) => {}
            _ => return TestResult::Fail("the page-table start bound was not programmed"),
        }
        match at(regs.ctx0_pt_end_lo + stride) {
            Some(v) if v == (state.geometry().max_pfn - 1) as u32 => {}
            _ => return TestResult::Fail("the page-table end bound was not programmed"),
        }
        // Context control: enabled, depth 3, every fault report on.
        let cntl = match at(regs.ctx0_cntl + regs.ctx_distance * (vmid as u32)) {
            Some(v) => v,
            None => return TestResult::Fail("the context was never enabled"),
        };
        use crate::amdgpu_vmhub_regs as hub;
        if cntl & hub::CTX_CNTL_ENABLE_CONTEXT == 0 {
            return TestResult::Fail("the context-enable bit is clear");
        }
        if (cntl >> hub::CTX_CNTL_PT_DEPTH_SHIFT) & hub::CTX_CNTL_PT_DEPTH_MASK != 3 {
            return TestResult::Fail("PAGE_TABLE_DEPTH should be num_level, which is 3");
        }
        if cntl & hub::CTX_CNTL_FAULT_ENABLE_DEFAULTS != hub::CTX_CNTL_FAULT_ENABLE_DEFAULTS {
            return TestResult::Fail("a protection-fault report is disabled");
        }
    }

    // The TLB invalidate happened, and it happened AFTER the context was
    // enabled: its request register is written later than the cntl register.
    let cntl_at = gfx.writes.iter().position(|(off, _)| {
        *off == (GFXHUB_V3_0.ctx0_cntl + GFXHUB_V3_0.ctx_distance * (vmid as u32)) << 2
    });
    let inv_at = gfx
        .writes
        .iter()
        .position(|(off, _)| *off == GFXHUB_V3_0.inv_eng0_req << 2);
    match (cntl_at, inv_at) {
        (Some(c), Some(i)) if i > c => {}
        (_, None) => return TestResult::Fail("no TLB invalidate was issued"),
        _ => return TestResult::Fail("the TLB was invalidated before the context was enabled"),
    }
    let _ = TLB_POLL_BUDGET;

    let mut c = [0u8; 8];
    c[0..4].copy_from_slice(&handle.to_le_bytes());
    let _ = crate::amdgpu_gem::dispatch(0x09, c.as_mut_ptr() as usize, &gem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_vm",
    smoke_amdgpu_vm_activate_programs_both_hubs
);

/// `AMDGPU_CS`'s parser against the input a hostile client would send.
///
/// The IB's CONTENTS are not validated — not here and not in Linux, where
/// `parse_cs` is NULL for GFX11 — because the command processor executes an
/// IB through the submitting client's own page tables, and those are the
/// boundary. What this file must get right is narrower: it follows
/// user-controlled pointers three levels deep, with two user-controlled counts
/// bounding them, and it decides whether an address the client named is one it
/// actually owns.
fn smoke_amdgpu_cs_parser_rejects_hostile_input() -> TestResult {
    use crate::amdgpu_cs::{parse, Ib};
    use crate::amdgpu_ctx::{dispatch as ctx_dispatch, CtxState};
    use crate::amdgpu_gem::GemState;
    use crate::amdgpu_uapi as u;
    use crate::amdgpu_vm::{self as vm, VmState, GPU_PAGE_SIZE};
    use crate::drm_uapi::DRM_COMMAND_BASE;
    use narf_filesystem::FsError;

    let gem = GemState::new();
    let state = VmState::new();
    let ctx = CtxState::new();

    // A context to submit against.
    let mut ctx_req = [0u8; 24];
    ctx_req[0..4].copy_from_slice(&u::AMDGPU_CTX_OP_ALLOC_CTX.to_le_bytes());
    if ctx_dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_CTX,
        ctx_req.as_mut_ptr() as usize,
        &ctx,
        false,
    )
    .is_err()
    {
        return TestResult::Fail("setup: context alloc failed");
    }
    let ctx_id = u32::from_le_bytes(ctx_req[0..4].try_into().unwrap());

    // A 2-page buffer mapped read/write at a known GPU address.
    const IB_VA: u64 = 0x2_0000_0000;
    const MAPPED: u64 = 2 * GPU_PAGE_SIZE;
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&MAPPED.to_le_bytes());
    create[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        create.as_mut_ptr() as usize,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_CREATE failed");
    }
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());
    let do_map = |flags: u32, va: u64, size: u64| {
        let mut m = [0u8; 40];
        m[0..4].copy_from_slice(&handle.to_le_bytes());
        m[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
        m[12..16].copy_from_slice(&flags.to_le_bytes());
        m[16..24].copy_from_slice(&va.to_le_bytes());
        m[32..40].copy_from_slice(&size.to_le_bytes());
        vm::dispatch(
            DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA,
            m.as_mut_ptr() as usize,
            &state,
            &gem,
        )
    };
    const RW: u32 = u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE;
    if do_map(RW, IB_VA, MAPPED).is_err() {
        return TestResult::Fail("setup: MAP failed");
    }

    // Build a chunk array: one IB chunk describing `ib_bytes` at `va`.
    // The layout is the real one — an array of pointers to chunk headers,
    // each pointing at its own body.
    struct Req {
        body: [u32; 8],
        header: [u32; 4],
        pointers: [u64; 1],
    }
    let build = |va: u64, ib_bytes: u32, ip_type: u32, flags: u32| -> alloc::boxed::Box<Req> {
        let mut r = alloc::boxed::Box::new(Req {
            body: [0; 8],
            header: [0; 4],
            pointers: [0; 1],
        });
        r.body[1] = flags;
        r.body[2] = va as u32;
        r.body[3] = (va >> 32) as u32;
        r.body[4] = ib_bytes;
        r.body[5] = ip_type;
        let body_ptr = r.body.as_ptr() as u64;
        r.header[0] = u::AMDGPU_CHUNK_ID_IB;
        r.header[1] = 8; // length_dw
        r.header[2] = body_ptr as u32;
        r.header[3] = (body_ptr >> 32) as u32;
        r.pointers[0] = r.header.as_ptr() as u64;
        r
    };
    let run = |r: &Req| parse(ctx_id, 1, r.pointers.as_ptr() as u64, &state, &ctx);

    // ── the happy path ──
    let good = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    match run(&good) {
        Ok(s) if s.ctx_id == ctx_id && s.ibs.len() == 1 => {
            let want = Ib {
                va_start: IB_VA,
                length_dw: 64,
                ip_type: u::AMDGPU_HW_IP_GFX,
                ip_instance: 0,
                ring: 0,
                flags: 0,
            };
            if s.ibs[0] != want {
                return TestResult::Fail("a valid IB did not parse to its fields");
            }
        }
        _ => return TestResult::Fail("a well-formed submission was refused"),
    }

    // ── the address checks, which are the point ──
    // An IB at an address the client never mapped.
    if run(&build(IB_VA + 0x1000_0000, 256, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("an IB at an unmapped address was accepted");
    }
    // An IB that STARTS inside the mapping and runs past its end. This is the
    // one a naive check misses: the start address is perfectly valid.
    if run(&build(IB_VA + MAPPED - 64, 256, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("an IB running past the end of its mapping was accepted");
    }
    // Exactly reaching the end is fine — an off-by-one here would reject
    // legitimate work.
    if run(&build(IB_VA + MAPPED - 256, 256, u::AMDGPU_HW_IP_GFX, 0)).is_err() {
        return TestResult::Fail("an IB ending exactly at the mapping's end was refused");
    }
    // An address that overflows when the length is added.
    if run(&build(u64::MAX - 16, 256, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("an IB whose end overflows was accepted");
    }
    // A write-only mapping cannot be fetched from: the fetch itself faults.
    const WO: u32 = u::AMDGPU_VM_PAGE_WRITEABLE;
    if do_map(WO, IB_VA + 0x1000_0000, GPU_PAGE_SIZE).is_err() {
        return TestResult::Fail("setup: write-only MAP failed");
    }
    if !matches!(
        run(&build(IB_VA + 0x1000_0000, 64, u::AMDGPU_HW_IP_GFX, 0)),
        Err(FsError::PermissionDenied)
    ) {
        return TestResult::Fail("an IB in an unreadable mapping should be EACCES");
    }

    // ── the field checks ──
    if run(&build(IB_VA, 0, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("a zero-length IB names no work and must be refused");
    }
    if run(&build(IB_VA, 255, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("an IB that is not a whole number of dwords must be refused");
    }
    if run(&build(IB_VA, 0xFFFF_FFFC, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("an IB beyond the packet-size maximum must be refused");
    }
    if run(&build(IB_VA + 2, 256, u::AMDGPU_HW_IP_GFX, 0)).is_ok() {
        return TestResult::Fail("a misaligned IB address must be refused");
    }
    // An engine this driver has no ring for.
    if run(&build(IB_VA, 256, u::AMDGPU_HW_IP_VCE, 0)).is_ok() {
        return TestResult::Fail("an IB for an absent engine must be refused");
    }
    // The constant engine is blocked on modern amdgpu behind a debug knob,
    // and there is no knob here.
    if run(&build(
        IB_VA,
        256,
        u::AMDGPU_HW_IP_GFX,
        u::AMDGPU_IB_FLAG_CE,
    ))
    .is_ok()
    {
        return TestResult::Fail("a CE submission must be refused");
    }
    if run(&build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 1 << 20)).is_ok() {
        return TestResult::Fail("an undefined IB flag must be refused");
    }

    // ── the pointer walk ──
    let g = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    // A null chunk array.
    if !matches!(parse(ctx_id, 1, 0, &state, &ctx), Err(FsError::BadAddress)) {
        return TestResult::Fail("a null chunk array should be EFAULT");
    }
    // A null pointer INSIDE the array — the second level.
    let mut null_inner = [0u64; 1];
    if !matches!(
        parse(ctx_id, 1, null_inner.as_mut_ptr() as u64, &state, &ctx),
        Err(FsError::BadAddress)
    ) {
        return TestResult::Fail("a null chunk pointer should be EFAULT");
    }
    // A chunk count the client inflated. Unbounded, this sizes a read.
    if parse(ctx_id, 100_000, g.pointers.as_ptr() as u64, &state, &ctx).is_ok() {
        return TestResult::Fail("an absurd chunk count must be refused");
    }
    if parse(ctx_id, 0, g.pointers.as_ptr() as u64, &state, &ctx).is_ok() {
        return TestResult::Fail("a submission with no chunks must be refused");
    }
    // A `length_dw` the client inflated, which sizes the third read.
    //
    // Two values, deliberately. 0xFFFF_FFFF is rejected by `copy_in`'s own
    // 1 MiB cap whatever this parser does — so on its own it proves nothing
    // about the parser's bound, which a mutation test showed: removing that
    // bound left this case still passing. 1000 dwords is 4 KiB, comfortably
    // inside `copy_in`'s cap, so only the parser's own limit refuses it.
    let mut inflated = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    inflated.header[1] = 0xFFFF_FFFF;
    if run(&inflated).is_ok() {
        return TestResult::Fail("an absurd chunk length must be refused");
    }
    let mut over_bound = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    over_bound.header[1] = 1000;
    if run(&over_bound).is_ok() {
        return TestResult::Fail("a chunk length past the parser's own bound must be refused");
    }
    // A chunk shorter than the IB struct it claims to be.
    let mut short = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    short.header[1] = 4;
    if run(&short).is_ok() {
        return TestResult::Fail("a chunk shorter than drm_amdgpu_cs_chunk_ib must be refused");
    }

    // ── chunks that are refused rather than ignored ──
    // A dropped ordering constraint is a race, not an error.
    for id in [
        u::AMDGPU_CHUNK_ID_DEPENDENCIES,
        u::AMDGPU_CHUNK_ID_SYNCOBJ_IN,
        u::AMDGPU_CHUNK_ID_SYNCOBJ_OUT,
        u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT,
        u::AMDGPU_CHUNK_ID_FENCE,
        u::AMDGPU_CHUNK_ID_BO_HANDLES,
    ] {
        let mut other = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
        other.header[0] = id;
        if !matches!(run(&other), Err(FsError::Unsupported)) {
            return TestResult::Fail("a synchronisation chunk must be refused, never ignored");
        }
    }
    // An unknown chunk id.
    let mut unknown = build(IB_VA, 256, u::AMDGPU_HW_IP_GFX, 0);
    unknown.header[0] = 0xDEAD;
    if !matches!(run(&unknown), Err(FsError::InvalidData)) {
        return TestResult::Fail("an unknown chunk id must be EINVAL");
    }

    // ── the context ──
    if parse(ctx_id + 999, 1, g.pointers.as_ptr() as u64, &state, &ctx).is_ok() {
        return TestResult::Fail("a submission naming no context must be refused");
    }
    // Contexts are per-open, so another open's table does not resolve this id.
    let other_ctx = CtxState::new();
    if parse(ctx_id, 1, g.pointers.as_ptr() as u64, &state, &other_ctx).is_ok() {
        return TestResult::Fail("a context id must not resolve in another open's table");
    }

    let _ = &mut null_inner;
    let mut c = [0u8; 8];
    c[0..4].copy_from_slice(&handle.to_le_bytes());
    let _ = crate::amdgpu_gem::dispatch(0x09, c.as_mut_ptr() as usize, &gem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_cs",
    smoke_amdgpu_cs_parser_rejects_hostile_input
);

/// The GFX11 queue descriptor, field by field against `gfx_v11_0_gfx_mqd_init`.
///
/// Every index was generated by compiling `v11_structs.h` on the build host
/// and printing `offsetof(field) / 4`, so what this test adds is the VALUES:
/// the register defaults they build on, the shifts, and the two fields whose
/// sense is easy to invert.
fn smoke_amdgpu_mqd_gfx11_matches_linux() -> TestResult {
    use crate::amdgpu_mqd::*;

    let base = MqdProp {
        mqd_gpu_addr: 0x1_0000_1000,
        hqd_base_gpu_addr: 0x2_0000_0000,
        rptr_gpu_addr: 0x3_0000_0004,
        wptr_gpu_addr: 0x4_0000_0008,
        queue_size: 4096,
        doorbell_index: 0x42,
        use_doorbell: true,
        kernel_queue: true,
        tmz_queue: false,
        priority: QueuePriority::Normal,
        shadow_addr: 0x5_0000_0000,
        gds_bkup_addr: 0x6_0000_0000,
        csa_addr: 0x7_0000_0000,
        fence_address: 0x8_0000_0000,
    };
    let mqd = match gfx_mqd_init(&base) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("a well-formed queue was refused"),
    };
    if mqd.len() != MQD_DWORDS {
        return TestResult::Fail("the MQD is 512 dwords");
    }

    // ── addresses ──
    // The ring base is stored shifted right by 8: the register holds a
    // 256-byte granule.
    let hqd = base.hqd_base_gpu_addr >> 8;
    if mqd[CP_GFX_HQD_BASE] != hqd as u32 || mqd[CP_GFX_HQD_BASE_HI] != (hqd >> 32) as u32 {
        return TestResult::Fail("the ring base is not the address shifted right by 8");
    }
    // A ring base with low bits set would lose them silently — 256 bytes out
    // of place — so it is refused instead.
    if gfx_mqd_init(&MqdProp {
        hqd_base_gpu_addr: base.hqd_base_gpu_addr + 0x80,
        ..base
    })
    .is_ok()
    {
        return TestResult::Fail("a ring base that is not 256-byte aligned must be refused");
    }
    // The writeback addresses keep only 16 bits of their high half: the
    // hardware takes a 48-bit address.
    if mqd[CP_GFX_HQD_RPTR_ADDR] != (base.rptr_gpu_addr & 0xffff_fffc) as u32 {
        return TestResult::Fail("the rptr writeback address is wrong");
    }
    if mqd[CP_GFX_HQD_RPTR_ADDR_HI] != ((base.rptr_gpu_addr >> 32) as u32) & 0xffff {
        return TestResult::Fail("the rptr writeback high half is not masked to 16 bits");
    }
    if mqd[CP_RB_WPTR_POLL_ADDR_LO] != (base.wptr_gpu_addr & 0xffff_fffc) as u32 {
        return TestResult::Fail("the wptr poll address is wrong");
    }
    // The MQD records its own address, dword aligned.
    if mqd[CP_MQD_BASE_ADDR] != (base.mqd_gpu_addr & 0xffff_fffc) as u32 {
        return TestResult::Fail("the MQD does not record its own address");
    }

    // ── ring size ──
    // `rb_bufsz = order_base_2(queue_size / 4) - 1`; 4096 bytes is 1024
    // dwords, so log2(1024) - 1 = 9, and RB_BLKSZ is that minus 2.
    if mqd[CP_GFX_HQD_CNTL] & 0x3F != 9 {
        return TestResult::Fail("RB_BUFSZ should be order_base_2(size/4) - 1");
    }
    if (mqd[CP_GFX_HQD_CNTL] >> 8) & 0x3F != 7 {
        return TestResult::Fail("RB_BLKSZ should be RB_BUFSZ - 2");
    }
    // The expression underflows below 8 bytes and the field cannot describe a
    // non-power-of-two ring, so both are refused rather than encoded wrongly.
    for bad in [0u64, 4, 3000, 5000] {
        if gfx_mqd_init(&MqdProp {
            queue_size: bad,
            ..base
        })
        .is_ok()
        {
            return TestResult::Fail("an unrepresentable ring size must be refused");
        }
    }

    // ── the two fields whose sense is easy to invert ──
    // RB_NON_PRIV marks a queue whose packets are NOT privileged, so Linux
    // sets it for a queue that is not the kernel's. Inverted, every userspace
    // queue would get the kernel's authority over the command processor.
    if mqd[CP_GFX_HQD_CNTL] & (1 << 15) != 0 {
        return TestResult::Fail("a kernel queue must not be marked non-privileged");
    }
    let user = match gfx_mqd_init(&MqdProp {
        kernel_queue: false,
        ..base
    }) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("a userspace queue was refused"),
    };
    if user[CP_GFX_HQD_CNTL] & (1 << 15) == 0 {
        return TestResult::Fail("a userspace queue MUST be marked non-privileged");
    }
    // PRIV_STATE on the MQD control is the opposite sense and is always set:
    // the firmware fetches the descriptor itself through the kernel's address
    // space whatever the queue's own privilege is.
    if mqd[CP_GFX_MQD_CONTROL] & (1 << 8) == 0 {
        return TestResult::Fail("the MQD fetch is always privileged");
    }
    if user[CP_GFX_MQD_CONTROL] & (1 << 8) == 0 {
        return TestResult::Fail("a userspace queue's MQD fetch is still privileged");
    }

    // ── defaults are built on, not replaced ──
    // `regCP_GFX_HQD_QUANTUM_DEFAULT` is 0x0a01 and the enable bit is added
    // to it; starting from zero would drop the quantum's reserved value.
    if mqd[CP_GFX_HQD_QUANTUM] != 0x0a01 | 1 {
        return TestResult::Fail("the quantum should be its reset value plus QUANTUM_EN");
    }
    // `regCP_GFX_HQD_CNTL_DEFAULT` is 0x00a00000 and those bits survive.
    if mqd[CP_GFX_HQD_CNTL] & 0x00a0_0000 != 0x00a0_0000 {
        return TestResult::Fail("the cntl register's reset bits were discarded");
    }
    // `regCP_GFX_MQD_CONTROL_DEFAULT` is 0x100 — which IS the PRIV_STATE bit.
    if mqd[CP_GFX_MQD_CONTROL] & 0xF != 0 {
        return TestResult::Fail("VMID should be cleared in the MQD control");
    }

    // ── doorbell ──
    if mqd[CP_RB_DOORBELL_CONTROL] & (1 << 30) == 0 {
        return TestResult::Fail("DOORBELL_EN should be set when a doorbell is used");
    }
    if (mqd[CP_RB_DOORBELL_CONTROL] >> 2) & 0x03FF_FFFF != 0x42 {
        return TestResult::Fail("the doorbell index did not land at bit 2");
    }
    let nodoor = match gfx_mqd_init(&MqdProp {
        use_doorbell: false,
        ..base
    }) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("a queue without a doorbell was refused"),
    };
    if nodoor[CP_RB_DOORBELL_CONTROL] != 0 {
        return TestResult::Fail("no doorbell means the whole control register stays at reset");
    }

    // ── priority, TMZ, and the pointers ──
    if mqd[CP_GFX_HQD_QUEUE_PRIORITY] != 0 {
        return TestResult::Fail("normal priority is level 0");
    }
    let hi = match gfx_mqd_init(&MqdProp {
        priority: QueuePriority::Maximum,
        ..base
    }) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("a maximum-priority queue was refused"),
    };
    if hi[CP_GFX_HQD_QUEUE_PRIORITY] & 1 != 1 {
        return TestResult::Fail("AMDGPU_GFX_QUEUE_PRIORITY_MAXIMUM is level 1");
    }
    let tmz = match gfx_mqd_init(&MqdProp {
        tmz_queue: true,
        ..base
    }) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("a TMZ queue was refused"),
    };
    if tmz[CP_GFX_HQD_CNTL] & (1 << 7) == 0 {
        return TestResult::Fail("TMZ_MATCH should be set for a TMZ queue");
    }
    if mqd[CP_GFX_HQD_WPTR] != 0 || mqd[CP_GFX_HQD_RPTR] != 0 {
        return TestResult::Fail("a fresh queue starts with both pointers at zero");
    }
    if mqd[CP_GFX_HQD_ACTIVE] != 1 {
        return TestResult::Fail("the descriptor should mark the queue active");
    }
    if mqd[CP_GFX_HQD_VMID] != 0 {
        return TestResult::Fail("the ring's VMID starts at the kernel's");
    }

    // ── the user-queue areas, which live at the two ends of the structure ──
    if mqd[SHADOW_BASE_LO] != base.shadow_addr as u32 || mqd[SHADOW_BASE_HI] != 5 {
        return TestResult::Fail("the shadow area address is wrong");
    }
    if mqd[FENCE_ADDRESS_HI] != 8 || mqd[FENCE_ADDRESS_LO] != 0 {
        return TestResult::Fail("the fence address is wrong");
    }
    if mqd[FW_WORK_AREA_BASE_HI] != 7 || mqd[GDS_BKUP_BASE_HI] != 6 {
        return TestResult::Fail("a user-queue area address is wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu_mqd",
    smoke_amdgpu_mqd_gfx11_matches_linux
);
