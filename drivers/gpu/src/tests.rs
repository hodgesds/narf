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
