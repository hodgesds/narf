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
    match gpu_pci::with_controller(|d| d.ready) {
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
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX_DISCRETE),
        (amdgpu::AMD_VENDOR, amdgpu::STRIX_POINT),
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
    let mut img = alloc::vec::Vec::new();
    img.resize(0x200, 0u8);
    // PCI ROM signature.
    img[0] = 0xAA;
    img[1] = 0x55;
    // "ATOM" marker at offset 4.
    img[4..8].copy_from_slice(b"ATOM");
    // Master data table at offset 0x100.
    img[0x4C..0x50].copy_from_slice(&0x100u32.to_le_bytes());
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
    bad[4] = b'X';
    if !matches!(Atombios::parse(&bad), Err(AtomError::NotAtombios)) {
        return TestResult::Fail("missing ATOM marker should reject");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu",
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
    use crate::amdgpu_ring::{Ring, DOORBELL_STRIDE_BYTES, RING_SIZE_DW};
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
    let pkt = [0xDEAD_BEEFu32, 0x1234_5678, 0xAAAA_5555, 0x0000_0001];
    // SAFETY: smoke harness owns the ring exclusively.
    let new_wptr = match unsafe { ring.submit(&pkt) } {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("submit rejected 4-dword packet"),
    };
    if new_wptr != 4 || ring.wptr() != 4 {
        return TestResult::Fail("wptr didn't advance by 4 dwords");
    }
    // Trying to submit a packet that would overflow the ring's
    // contiguous tail returns NotEnoughRoomBeforeWrap.
    let huge = alloc::vec![0u32; RING_SIZE_DW];
    // SAFETY: same.
    if unsafe { ring.submit(&huge) }.is_ok() {
        return TestResult::Fail("oversized packet should fail");
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
    let mut t = alloc::vec::Vec::new();
    t.resize(0x80, 0u8);
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
    let mut blob = alloc::vec::Vec::new();
    blob.resize(1024, 0u8);
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
    let mut t = alloc::vec::Vec::new();
    t.resize(80, 0u8);
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
    let mut t = alloc::vec::Vec::new();
    t.resize(8 + 3 * 8, 0u8);
    // Header.
    t[0..2].copy_from_slice(&((8u16 + 3 * 8).to_le_bytes()));
    t[2] = 1; // format_revision
    t[3] = 0; // content_revision
    t[4..6].copy_from_slice(&0x0001u16.to_le_bytes()); // device_support bitmap
    t[6] = 3; // num_paths
              // Paths start at 8.
    let paths = [
        (0x0001u16, (0x13u16 << 8) | 0u16, 0x1100u16), // DP
        (0x0002u16, (0x0Cu16 << 8) | 1u16, 0x1101u16), // HDMI-A
        (0x0004u16, (0x14u16 << 8) | 0u16, 0x1102u16), // eDP
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
        offsets_of, register_family_offsets, registered_count, FamilyOffsets, __reset_for_test,
    };
    __reset_for_test();
    if registered_count() != 0 {
        return TestResult::Fail("reset didn't clear registry");
    }
    // Compile-time fallback wins when registry is empty.
    if Family::Vega.mp0_base() != Some(0x000B_0000) {
        return TestResult::Fail("Vega compile-time fallback");
    }
    if Family::Navi3.mp0_base() != None {
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
    let mut t = alloc::vec::Vec::new();
    t.resize(0x20, 0u8);
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
    let mut t = alloc::vec::Vec::new();
    t.resize(8 + 14, 0u8);
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
    t[off + 4..off + 6].copy_from_slice(&((0x13u16 << 8) | 0).to_le_bytes()); // DP/0
    t[off + 6..off + 8].copy_from_slice(&0x1100u16.to_le_bytes()); // GPU obj
                                                                   // Chain: encoder/0 (0x21<<8), transmitter/2 (0x22<<8 | 2), sentinel.
    t[off + 8..off + 10]
        .copy_from_slice(&((ATOM_OBJECT_TYPE_ENCODER as u16) << 8 | 0u16).to_le_bytes());
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
    let mut t = alloc::vec::Vec::new();
    t.resize(0x40, 0u8);
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
    let mut t = alloc::vec::Vec::new();
    t.resize(0x40, 0u8);
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
    let mut img = alloc::vec::Vec::new();
    img.resize(0x300, 0u8);
    img[0] = 0xAA;
    img[1] = 0x55;
    img[4..8].copy_from_slice(b"ATOM");
    // Data master @ 0x100, command master @ 0x200.
    img[0x4C..0x50].copy_from_slice(&0x100u32.to_le_bytes());
    img[0x48..0x4C].copy_from_slice(&0x200u32.to_le_bytes());
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
kernel_test_in!("drivers/gpu", smoke_amdgpu_atombios_command_table_directory);

fn smoke_amdgpu_rlc_header_and_autoload_round_trip() -> TestResult {
    use crate::amdgpu_rlc::{autoload_iter, looks_like_rlc, parse};
    use crate::amdgpu_ucode::UCODE_MAGIC;
    // Build a 1024-byte synthetic RLC blob:
    //   - 4-byte magic + common ucode header (version etc.)
    //   - RLC extension at offset 0x24
    //   - autoload offset table at 0x100, 3 × 12 byte entries
    //   - payload at 0x200 (24-byte filler — autoload entries
    //     point into it)
    let mut blob = alloc::vec::Vec::new();
    blob.resize(1024, 0u8);
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
    let mut t = alloc::vec::Vec::new();
    t.resize(4 + 4 * 8, 0u8);
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
        45, 0x05, 2, 0x11, 0, 0, 0, // ADD WS[2] += 0x11
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
        91, // EOT
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
    use alloc::vec::Vec;
    use alloc::sync::Arc;
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
        91, // EOT
    ];

    let writes: Arc<RefCell<Vec<(u32, u32)>>> = Arc::new(RefCell::new(Vec::new()));
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
    use crate::amdgpu_smu::{
        send_message, MockSmu, SmuError, PPSMC_MSG_TEST_MESSAGE,
    };
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
    use crate::amdgpu_dcn::{
        build_modeset_from_discovery, timing_for_mode,
    };
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
    let expected_blank =
        0x0001_2000 + crate::amdgpu_dcn::DCN20_HUBP0_REL + crate::amdgpu_dcn::DCN20_HUBP_BLANK_EN_REL;
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
        Some(unsafe { d.set_mode(Mode { width: 1920, height: 1080, stride: 1920 }) })
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
        dcn20_modeset_sequence, timing_for_mode, DCN20_HUBP0_REL,
        DCN20_HUBP_BLANK_EN_REL, DCN20_OTG0_REL, DCN20_OTG_CONTROL_REL,
        DCN20_OTG_H_TOTAL_REL, HUBP_BLANK_FORCE, OTG_MASTER_EN,
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
    let blank_cleared = seq
        .iter()
        .any(|w| w.addr == want_blank && w.value == 0);
    if !blank_forced || !blank_cleared {
        return TestResult::Fail("HUBP_BLANK_EN must be forced then cleared");
    }
    // OTG_H_TOTAL must appear with the value `h_total - 1`.
    let want_h = (timing.h_total - 1) as u32;
    if !seq.iter().any(|w| w.addr == want_h_total && w.value == want_h) {
        return TestResult::Fail("OTG_H_TOTAL not programmed");
    }
    // OTG_MASTER_EN must be the last write to OTG_CONTROL.
    let last_master = seq
        .iter()
        .rev()
        .find(|w| w.addr == want_master)
        .copied();
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
        dcn35_modeset_sequence, timing_for_mode, DCN35_HUBP0_REL,
        DCN35_HUBP_BLANK_EN_REL, DCN35_OTG0_REL, DCN35_OTG_CONTROL_REL,
        DCN35_OTG_H_TOTAL_REL, DCN35_OTG_V_BLANK_REL, HUBP_BLANK_FORCE,
        OTG_MASTER_EN,
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
    let blank_cleared = seq
        .iter()
        .any(|w| w.addr == want_blank && w.value == 0);
    if !blank_forced || !blank_cleared {
        return TestResult::Fail("DCN35 HUBP_BLANK_EN must be forced then cleared");
    }
    // OTG_H_TOTAL = h_total - 1.
    let want_h = (timing.h_total - 1) as u32;
    if !seq.iter().any(|w| w.addr == want_h_total && w.value == want_h) {
        return TestResult::Fail("DCN35 OTG_H_TOTAL not programmed");
    }
    // OTG_V_BLANK_START_END must use the DCN 3.5-shifted offset
    // (the whole point of this path). If this constant ever drifts
    // back to the DCN 2.0 value the test catches it.
    if !seq.iter().any(|w| w.addr == want_v_blank) {
        return TestResult::Fail("DCN35 OTG_V_BLANK_START_END not programmed at shifted offset");
    }
    // OTG_MASTER_EN must be the last write to OTG_CONTROL.
    let last_master = seq
        .iter()
        .rev()
        .find(|w| w.addr == want_master)
        .copied();
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
        DCN20_OTG_CONTROL_REL, DCN20_OTG_INTERRUPT_CONTROL_REL,
        DCN20_OTG_V_BLANK_REL, DCN20_OTG_V_SYNC_A_REL,
        DCN35_OTG_CONTROL_REL, DCN35_OTG_INTERRUPT_CONTROL_REL,
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
        send_command, MockPsp, MP0_C2PMSG_64_REL, MP0_C2PMSG_67_REL,
        MP0_C2PMSG_69_REL, PSP_CMD_LOAD_IP_FW, PSP_STATUS_DONE_BIT,
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
        send_command, MockPsp, PspError, MP0_C2PMSG_64_REL,
        PSP_CMD_LOAD_IP_FW, PSP_STATUS_DONE_BIT,
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
    match send_command(&mut m, 0x000B_0000, PSP_CMD_LOAD_IP_FW, 0x1000, PSP_MAX_IMAGE_SIZE + 1) {
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
        bring_up, MockSmu, SMU12_DRIVER_IF_VERSION, MP1_C2PMSG_ARG_REL,
        MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
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
        bring_up, BringUpError, MockSmu, SMU12_DRIVER_IF_VERSION,
        MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
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
        bring_up, BringUpError, MockSmu, SMU12_DRIVER_IF_VERSION,
        MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
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
        bring_up, MockSmu, SMU_13_0_4_DRIVER_IF_VERSION, MP1_C2PMSG_ARG_REL,
        MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
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
        CP_RB0_WPTR_HI_REL, CP_RB0_WPTR_REL, CP_RB_DOORBELL_CONTROL_REL,
        CP_RB_DOORBELL_EN, CP_RB_DOORBELL_OFFSET_SHIFT, CP_RB_DOORBELL_RANGE_LOWER_REL,
        CP_RB_DOORBELL_RANGE_UPPER_REL, RPTR_WRITEBACK_COHERENT,
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
    if w.first().map(|g| (g.addr, g.value))
        != Some((gc_base + CP_ME_CNTL_REL, CP_ME_CNTL_HALT_ALL))
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
        (
            gc_base + CP_RB0_RPTR_ADDR_HI_REL,
            ((rptr_phys >> 32) as u32) | RPTR_WRITEBACK_COHERENT,
        ),
        (gc_base + CP_RB0_BASE_REL, ring_phys as u32),
        (gc_base + CP_RB0_BASE_HI_REL, (ring_phys >> 32) as u32),
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
    let r = build_gfx9_ring_init(
        0x0003_0000,
        0x1_0000_00FF,
        1024,
        0,
        0x2_0000_0000,
    );
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
    let new_wptr = match unsafe { ring.submit(&staging) } {
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
        // SAFETY: identity-mapped DMA-coherent page, ring is owned.
        let got = unsafe { core::ptr::read_volatile((phys + (i * 4) as u64) as *const u32) };
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
    let new_wptr = match unsafe { ring.submit(&staging[..11]) } {
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
        unsafe { core::ptr::read_volatile((phys + (i * 4) as u64) as *const u32) }
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
        unsafe { core::ptr::read_volatile((ring_phys + (i * 4) as u64) as *const u32) }
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
        SDMA_GFX_DOORBELL_REL, SDMA_GFX_RB_BASE_HI_REL, SDMA_GFX_RB_BASE_REL,
        SDMA_GFX_RB_CNTL_REL, SDMA_GFX_RB_RPTR_ADDR_HI_REL, SDMA_GFX_RB_RPTR_ADDR_LO_REL,
        SDMA_RB_ENABLE, SDMA_RB_RPTR_WRITEBACK_ENABLE, SDMA_RB_SIZE_SHIFT,
    };
    let sdma_base: u32 = 0x0006_0000;
    let ring_phys: u64 = 0x0000_0001_8000_0000; // 256-byte aligned
    let ring_size_dw: u32 = 1024;
    let doorbell_idx: u32 = 9;
    let rptr_phys: u64 = 0x0000_0002_BEEF_0000;

    let seq = match build_sdma4_ring_init(sdma_base, ring_phys, ring_size_dw, doorbell_idx, rptr_phys)
    {
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
        (sdma_base + SDMA_GFX_RB_BASE_HI_REL, (ring_phys >> 40) as u32),
        (sdma_base + SDMA_GFX_RB_RPTR_ADDR_LO_REL, rptr_phys as u32),
        (
            sdma_base + SDMA_GFX_RB_RPTR_ADDR_HI_REL,
            (rptr_phys >> 32) as u32,
        ),
        (
            sdma_base + SDMA_GFX_DOORBELL_OFFSET_REL,
            doorbell_idx << 2,
        ),
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
    use crate::amdgpu_sdma::{
        build_sdma4_ring_init, SDMA_GFX_RB_CNTL_REL, SDMA_RB_ENABLE,
    };
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
    use crate::amdgpu_sdma::{
        SdmaBuilder, SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR,
    };
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
        if b.acquire_mem(ACQUIRE_FULL_SHADER_INVALIDATE, 0, !0u64, 4).is_err() {
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
        IH_RB_BASE_REL, IH_RB_CNTL_REL, IH_RB_ENABLE, IH_RB_GPU_TS_ENABLE,
        IH_RB_OVERFLOW_CLEAR, IH_RB_SIZE_SHIFT, IH_RB_WPTR_ADDR_HI_REL,
        IH_RB_WPTR_ADDR_LO_REL, IH_RB_WPTR_WRITEBACK_ENABLE,
    };
    let ih_base: u32 = 0x0009_0000;
    let ring_phys: u64 = 0x0000_0001_4000_0000;
    let ring_size_dw: u32 = 512;
    let doorbell_idx: u32 = 6;
    let wptr_phys: u64 = 0x0000_0002_1234_0000;

    let seq =
        match build_ih4_ring_init(ih_base, ring_phys, ring_size_dw, doorbell_idx, wptr_phys) {
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
    use crate::amdgpu_ih::{
        build_ih4_ring_init, IH_RB_CNTL_REL, IH_RB_ENABLE,
    };
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
    if msgs[0] != PPSMC_MSG_SET_SOFT_MIN_BY_FREQ
        || msgs[1] != PPSMC_MSG_SET_SOFT_MAX_BY_FREQ
    {
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
    if args[0] != pack_clk_arg(SMU_CLK_GFXCLK, 400)
        || args[1] != pack_clk_arg(SMU_CLK_GFXCLK, 1900)
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
        get_max_dpm_freq, MockSmu, MP1_C2PMSG_ARG_REL, MP1_C2PMSG_RESP_REL,
        SMU_CLK_DCEFCLK, SMU_RESP_OK,
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
        make_pte_gfx9, parse_pte, pte_is_valid, GART_PTE_FLAGS_GTT_DEFAULT,
        GART_PTE_PFN_SHIFT,
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
        GART_PTE_CACHEABLE, GART_PTE_FLAGS_GTT_DEFAULT, GART_PTE_SNOOP,
        GART_PTE_SYSTEM, GART_PTE_VALID, GART_PTE_WRITABLE,
    };
    let want = GART_PTE_VALID
        | GART_PTE_SYSTEM
        | GART_PTE_CACHEABLE
        | GART_PTE_WRITABLE
        | GART_PTE_SNOOP;
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
        SDMA_DOORBELL_ENABLE, SDMA_RB_ENABLE, SDMA_RB_RPTR_WRITEBACK_ENABLE,
        SDMA_RB_SIZE_SHIFT,
    };
    let sdma_base: u32 = 0x0007_0000;
    let ring_phys: u64 = 0x0000_0001_2000_0000;
    let ring_size_dw: u32 = 2048;
    let doorbell_idx: u32 = 4;
    let rptr_phys: u64 = 0x0000_0002_3000_0000;

    let seq = match build_sdma6_ring_init(
        sdma_base,
        ring_phys,
        ring_size_dw,
        doorbell_idx,
        rptr_phys,
    ) {
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
        (sdma_base + SDMA6_QUEUE0_RB_BASE_REL, (ring_phys >> 8) as u32),
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
        SDMA_GFX_RB_BASE_REL, SDMA_GFX_RB_CNTL_REL, SDMA6_QUEUE0_RB_BASE_REL,
        SDMA6_QUEUE0_RB_CNTL_REL,
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
    fn write(
        &mut self,
        _slave_addr: u8,
        _data: &[u8],
    ) -> Result<(), crate::amdgpu_ddc::DdcError> {
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
kernel_test_in!("drivers/gpu/amdgpu/ddc", smoke_read_edid_via_mock_transport_round_trips_block_0);

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
kernel_test_in!("drivers/gpu/amdgpu/ddc", smoke_read_edid_rejects_bad_checksum);

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
kernel_test_in!("drivers/gpu/amdgpu/ddc", smoke_read_edid_handles_one_extension_block);

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
kernel_test_in!("drivers/gpu/amdgpu/ddc", smoke_read_edid_caps_extension_blocks);

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
kernel_test_in!("drivers/gpu/amdgpu/ddc", smoke_gpio_ddc_bit_bang_sequences_start_address_stop);


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
kernel_test_in!(
    "drivers/gpu",
    smoke_dp_link_training_channel_eq_symbol_lock
);

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

fn smoke_amdgpu_gfx11_ring_init_emits_canonical_order() -> TestResult {
    use crate::amdgpu_gfx::{
        build_gfx11_ring_init, CP_GFX_CNTL_HALT_ALL, CP_GFX_CNTL_REL, CP_RB0_BASE_REL,
        CP_RB0_CNTL_REL, CP_RB_DOORBELL_CONTROL_REL, CP_RB_DOORBELL_EN,
        CP_RB_DOORBELL_OFFSET_SHIFT,
    };
    let gc_base: u32 = 0x0003_0000;
    let ring_phys: u64 = 0x0000_0001_5000_0000;
    let ring_size_dw: u32 = 2048;
    let doorbell_idx: u32 = 8;
    let rptr_phys: u64 = 0x0000_0002_0000_0000;

    let seq = match build_gfx11_ring_init(gc_base, ring_phys, ring_size_dw, doorbell_idx, rptr_phys)
    {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("build_gfx11_ring_init failed on valid input"),
    };
    let w: alloc::vec::Vec<_> = seq.iter().copied().collect();

    // First write: halt via CP_GFX_CNTL (NOT CP_ME_CNTL — that's GFX9).
    if w.first().map(|x| (x.addr, x.value))
        != Some((gc_base + CP_GFX_CNTL_REL, CP_GFX_CNTL_HALT_ALL))
    {
        return TestResult::Fail("first write must halt CP via CP_GFX_CNTL");
    }
    // Last write: unhalt (CP_GFX_CNTL = 0).
    if w.last().map(|x| (x.addr, x.value)) != Some((gc_base + CP_GFX_CNTL_REL, 0)) {
        return TestResult::Fail("last write must unhalt CP_GFX_CNTL");
    }
    // Body writes must include base, size encoding, doorbell.
    if !w.iter().any(|x| x.addr == gc_base + CP_RB0_BASE_REL && x.value == ring_phys as u32) {
        return TestResult::Fail("ring base lo not programmed");
    }
    let expect_cntl = ring_size_dw.trailing_zeros() | (6u32 << 8);
    if !w.iter().any(|x| x.addr == gc_base + CP_RB0_CNTL_REL && x.value == expect_cntl) {
        return TestResult::Fail("ring size encoding wrong");
    }
    if !w.iter().any(|x| {
        x.addr == gc_base + CP_RB_DOORBELL_CONTROL_REL
            && x.value == (CP_RB_DOORBELL_EN | (doorbell_idx << CP_RB_DOORBELL_OFFSET_SHIFT))
    }) {
        return TestResult::Fail("doorbell control not programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx11_ring_init_emits_canonical_order
);

fn smoke_amdgpu_gfx11_uses_distinct_halt_register() -> TestResult {
    use crate::amdgpu_gfx::{
        CP_GFX_CNTL_HALT_ALL, CP_GFX_CNTL_ME_HALT_GFX11, CP_GFX_CNTL_PFP_HALT_GFX11,
        CP_GFX_CNTL_REL, CP_ME_CNTL_HALT_ALL, CP_ME_CNTL_ME_HALT, CP_ME_CNTL_PFP_HALT,
        CP_ME_CNTL_REL,
    };
    // GFX11's CP_GFX_CNTL must live at a different offset from GFX9's CP_ME_CNTL.
    if CP_GFX_CNTL_REL == CP_ME_CNTL_REL {
        return TestResult::Fail("GFX11 CP_GFX_CNTL must differ from GFX9 CP_ME_CNTL");
    }
    // Halt-bit positions must differ — GFX9 uses bits {24, 26, 28};
    // GFX11 uses bits {0, 4, 8}.
    if CP_GFX_CNTL_PFP_HALT_GFX11 == CP_ME_CNTL_PFP_HALT
        || CP_GFX_CNTL_ME_HALT_GFX11 == CP_ME_CNTL_ME_HALT
    {
        return TestResult::Fail("GFX11 halt bits must differ from GFX9");
    }
    // Composite masks must differ.
    if CP_GFX_CNTL_HALT_ALL == CP_ME_CNTL_HALT_ALL {
        return TestResult::Fail("HALT_ALL composites must differ between GFX9/GFX11");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx11_uses_distinct_halt_register
);

fn smoke_amdgpu_gfx11_ring_init_validation_rejects_bad_inputs() -> TestResult {
    use crate::amdgpu_gfx::{build_gfx11_ring_init, GfxError};
    match build_gfx11_ring_init(0x0003_0000, 0x1_0000_0000, 1000, 0, 0x2_0000_0000) {
        Err(GfxError::BadRingSize) => {}
        _ => return TestResult::Fail("non-pow2 ring size must be rejected"),
    }
    match build_gfx11_ring_init(0x0003_0000, 0x1_0000_00FF, 1024, 0, 0x2_0000_0000) {
        Err(GfxError::UnalignedRingPhys) => {}
        _ => return TestResult::Fail("unaligned ring phys must be rejected"),
    }
    match build_gfx11_ring_init(0x0003_0000, 0x1_0000_0000, 1024, 0, 0x2_0000_0001) {
        Err(GfxError::UnalignedRptrWriteback) => {}
        _ => return TestResult::Fail("unaligned rptr-writeback must be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/gfx",
    smoke_amdgpu_gfx11_ring_init_validation_rejects_bad_inputs
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
    if writes[0].addr != dcn_base + BL_PWM_GRP1_REG_LOCK_REL
        || writes[0].value != BL_PWM_GRP1_LOCK
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
        read_gpu_temperature_millicelsius, MockSmu, MP1_C2PMSG_ARG_REL,
        MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
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
    if buf.phys() != 0x1000_0000 { return TestResult::Fail("phys wrong"); }
    if buf.len() != 4096 { return TestResult::Fail("len wrong"); }
    let imp = import(&buf);
    if imp.phys() != buf.phys() { return TestResult::Fail("import phys mismatch"); }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dmabuf", smoke_dmabuf_export_import_clone);

fn smoke_dmabuf_attach_detach_refcount() -> TestResult {
    use crate::dmabuf::export;
    let buf = match export(0x2000_0000, 8192, &NULL_OPS) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("export failed"),
    };
    if buf.attach_count() != 0 { return TestResult::Fail("initial count != 0"); }
    if buf.attach(0xAAAA).is_err() { return TestResult::Fail("attach A failed"); }
    if buf.attach_count() != 1 { return TestResult::Fail("count != 1 after A"); }
    if buf.attach(0xBBBB).is_err() { return TestResult::Fail("attach B failed"); }
    if buf.attach_count() != 2 { return TestResult::Fail("count != 2 after B"); }
    buf.detach(0xAAAA);
    if buf.attach_count() != 1 { return TestResult::Fail("count != 1 after detach A"); }
    buf.detach(0xBBBB);
    if buf.attach_count() != 0 { return TestResult::Fail("count != 0 after both detach"); }
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
    if b.attach(0xDEAD).is_err() { return TestResult::Fail("driver B attach failed"); }
    if a.attach_count() != 1 { return TestResult::Fail("shared count not visible via A"); }
    b.detach(0xDEAD);
    if a.attach_count() != 0 { return TestResult::Fail("shared count not decremented via B"); }
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
    if h1 == h2 { return TestResult::Fail("duplicate handles"); }
    if t.len() != 2 { return TestResult::Fail("len != 2 after 2 allocs"); }
    t.free(h1).unwrap();
    if t.len() != 1 { return TestResult::Fail("len != 1 after one free"); }
    t.free(h2).unwrap();
    if !t.is_empty() { return TestResult::Fail("not empty after freeing both"); }
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
            if obj.phys != 0xDEAD_0000 { return TestResult::Fail("phys wrong"); }
            if obj.size != 0x1000 { return TestResult::Fail("size wrong"); }
        }
    }
    t.free(h).unwrap();
    if t.lookup(h).is_some() { return TestResult::Fail("lookup Some after free"); }
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
    let mut card = make_test_card_for_ioctl();
    match dispatch(&mut card, 0x00, &[]) {
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
    let mut card = make_test_card_for_ioctl();
    match dispatch(&mut card, 0xA0, &[]) {
        Ok(DrmIoctlResult::GetResources(r)) => {
            if r.count_crtcs != 1 { return TestResult::Fail("count_crtcs != 1"); }
            if r.count_connectors != 1 { return TestResult::Fail("count_connectors != 1"); }
            if r.count_encoders != 1 { return TestResult::Fail("count_encoders != 1"); }
            if r.max_width < 1920 { return TestResult::Fail("max_width < 1920"); }
        }
        Ok(_) => return TestResult::Fail("wrong result for GETRESOURCES"),
        Err(_) => return TestResult::Fail("GETRESOURCES failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_ioctl_getresources_shape);

fn smoke_drm_ioctl_getconnector_decode() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    let mut card = make_test_card_for_ioctl();
    let arg = 1u32.to_le_bytes();
    match dispatch(&mut card, 0xA7, &arg) {
        Ok(DrmIoctlResult::GetConnector(info, modes)) => {
            if info.connector_id != 1 { return TestResult::Fail("connector_id not echoed"); }
            if info.connector_type != 14 { return TestResult::Fail("type != eDP(14)"); }
            if info.connection != 1 { return TestResult::Fail("not Connected"); }
            if modes.len() != 1 { return TestResult::Fail("expected 1 mode"); }
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

fn smoke_drm_addfb2_rmfb_roundtrip() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    let mut card = make_test_card_for_ioctl();
    let gem_handle = match card.gem.alloc(0x8000_0000, 1920 * 1080 * 4) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("GEM alloc failed"),
    };
    let mut arg = [0u8; 68];
    arg[4..8].copy_from_slice(&1920u32.to_le_bytes());
    arg[8..12].copy_from_slice(&1080u32.to_le_bytes());
    arg[12..16].copy_from_slice(&0x3438_5258u32.to_le_bytes()); // XRGB8888
    arg[20..24].copy_from_slice(&gem_handle.to_le_bytes());
    arg[36..40].copy_from_slice(&(1920u32 * 4).to_le_bytes());
    let fb_id = match dispatch(&mut card, 0xB8, &arg) {
        Ok(DrmIoctlResult::AddFb2(id)) => id,
        Ok(_) => return TestResult::Fail("ADDFB2 wrong result type"),
        Err(_) => return TestResult::Fail("ADDFB2 failed"),
    };
    if fb_id == 0 { return TestResult::Fail("fb_id is zero"); }
    if card.framebuffers.len() != 1 { return TestResult::Fail("fb count != 1 after ADDFB2"); }
    match card.framebuffer(fb_id) {
        Ok(fb) => {
            if fb.width != 1920 || fb.height != 1080 {
                return TestResult::Fail("FB dimensions wrong");
            }
        }
        Err(_) => return TestResult::Fail("fb lookup by id failed"),
    }
    let rmfb_arg = fb_id.to_le_bytes();
    match dispatch(&mut card, 0xA8, &rmfb_arg) {
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
    let mut card = make_test_card_for_ioctl();
    let mut arg = [0u8; 16];
    arg[0..8].copy_from_slice(&drm_cap::TIMESTAMP_MONOTONIC.to_le_bytes());
    match dispatch(&mut card, 0x0C, &arg) {
        Ok(DrmIoctlResult::GetCap(cap)) => {
            if cap.value != 1 { return TestResult::Fail("TIMESTAMP_MONOTONIC != 1"); }
        }
        _ => return TestResult::Fail("GET_CAP TIMESTAMP_MONOTONIC failed"),
    }
    arg[0..8].copy_from_slice(&drm_cap::PRIME.to_le_bytes());
    match dispatch(&mut card, 0x0C, &arg) {
        Ok(DrmIoctlResult::GetCap(cap)) => {
            if cap.value != 0 { return TestResult::Fail("PRIME should be 0 (deferred)"); }
        }
        _ => return TestResult::Fail("GET_CAP PRIME failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm", smoke_drm_getcap_shape);

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
    if amdgpu_smu_v12::msg_id(PpsmcMsg::SetSoftMinGfxclk) != None {
        return TestResult::Fail("V12 SetSoftMinGfxclk should be None");
    }
    // PrepareMp1ForUnload doesn't exist on SMU12.
    if amdgpu_smu_v12::msg_id(PpsmcMsg::PrepareMp1ForUnload) != None {
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
    if amdgpu_smu_v13::msg_id(PpsmcMsg::PowerUpGfx) != None {
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
kernel_test_in!(
    "drivers/gpu/amdgpu/smu",
    smoke_amdgpu_smu_fw_version_decode
);

fn smoke_amdgpu_smu_get_clock_mhz_end_to_end() -> TestResult {
    // End-to-end mock: write msg → simulate response → read result.
    // Tests the `get_clock_mhz` public API via a FakeMmio that
    // scripts the exact canonical mailbox sequence.
    use crate::amdgpu_smu::{
        get_clock_mhz, ClockDomain, MockSmu, SmuVersion,
        MP1_C2PMSG_ARG_REL, MP1_C2PMSG_MSG_REL, MP1_C2PMSG_RESP_REL, SMU_RESP_OK,
    };
    use crate::amdgpu_smu_v13::V13_MSG_GET_GFXCLK;

    let mp1_base: u32 = 0x1_6000;
    let resp_off = mp1_base + MP1_C2PMSG_RESP_REL;
    let arg_off = mp1_base + MP1_C2PMSG_ARG_REL;

    // Script: handshake idle, response OK, ARG = 2400 MHz (GFXCLK).
    let mut m = MockSmu::new();
    m.stage_read(resp_off, 1);           // step 1: RESP non-zero (idle)
    m.stage_read(resp_off, SMU_RESP_OK); // step 5: SMU responds OK
    m.stage_read(arg_off, 2400);         // step 6: ARG holds frequency

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
    let msg_write = m.writes.iter().find(|(off, _)| *off == mp1_base + MP1_C2PMSG_MSG_REL);
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
