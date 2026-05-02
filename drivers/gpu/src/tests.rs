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
    if list.modes.len() != 2 { return TestResult::Fail("mode list len"); }

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
        Some(true)  => TestResult::Pass,
        Some(false) => TestResult::Fail("virtio-gpu probed but scanout not ready"),
        None        => TestResult::Skip("virtio-gpu-pci controller missing"),
    }
}
kernel_test_in!("drivers/gpu", smoke_virtio_gpu_scanout_initialised);

fn smoke_amdgpu_pci_matches_registered() -> TestResult {
    // Structural: register the amdgpu driver and assert every
    // explicit AMD VID/DID match plus the class-match backstop
    // are in the bus's table. Doesn't require live silicon.
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use crate::amdgpu;
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
        let found = regs.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d));
        if !found {
            return TestResult::Fail("missing amdgpu VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m|
        matches!(m.kind, MatchKind::Class {
            class: 0x03, mask: 0xFF,
        }));
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
    if Family::Vega.mp0_base()  != Some(0x000B_0000) {
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
    use crate::amdgpu_atombios::{Atombios, AtomError};
    let mut img = alloc::vec::Vec::new();
    img.resize(0x200, 0u8);
    // PCI ROM signature.
    img[0] = 0xAA; img[1] = 0x55;
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
        Ok(a)  => a,
        Err(_) => return TestResult::Fail("ATOMBIOS parse rejected synthetic image"),
    };
    if atom.data_table_count() != 3 {
        return TestResult::Fail("data_table_count mis-decoded");
    }
    if atom.data_table_offset(0) != Ok(0x150) { return TestResult::Fail("table 0 offset"); }
    if atom.data_table_offset(1) != Ok(0x160) { return TestResult::Fail("table 1 offset"); }
    if atom.data_table_offset(2) != Ok(0x170) { return TestResult::Fail("table 2 offset"); }
    if atom.data_table_offset(3) != Err(AtomError::UnknownTableId) {
        return TestResult::Fail("out-of-range id should fail");
    }
    let t = match atom.data_table(1) {
        Ok(s)  => s,
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
kernel_test_in!("drivers/gpu", smoke_amdgpu_atombios_table_directory_round_trip);

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
    use crate::amdgpu_ring::{Ring, RING_SIZE_DW, DOORBELL_STRIDE_BYTES};
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
        Ok(w)  => w,
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
    use crate::dp_aux::{encode_request, decode_response,
        AuxCommand, AuxRequest, AuxStatus};
    let req = AuxRequest {
        cmd: AuxCommand::NativeRead,
        address: 0x0_2000, // DPCD_REV
        data: &[],
    };
    let mut wire = [0u8; 4];
    let n = match encode_request(&req, &mut wire) {
        Ok(n)  => n,
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
        Ok(r)  => r,
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
        Ok(n)  => n,
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
    t[0x59] = 7; t[0x5A] = 2;
    let info = match parse(&t) {
        Ok(i)  => i,
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
    use crate::amdgpu_ucode::{parse, payload, UCODE_MAGIC, UcodeError};
    // Build a 1024-byte synthetic blob: 4-byte magic + 32-byte
    // common header at offset 4 + zero-fill to 256, then a
    // 768-byte fake payload starting at offset 256.
    let mut blob = alloc::vec::Vec::new();
    blob.resize(1024, 0u8);
    blob[0..4].copy_from_slice(&UCODE_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&256u32.to_le_bytes());   // start_offset
    blob[8..12].copy_from_slice(&768u32.to_le_bytes());  // payload_size
    blob[12..16].copy_from_slice(&0x0001_0203u32.to_le_bytes()); // version
    blob[16..20].copy_from_slice(&0x0042u32.to_le_bytes());      // feature ver
    let hdr = match parse(&blob) {
        Ok(h)  => h,
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
    use crate::dp_aux::{
        AuxChannel, AuxRequest, AuxResponse, AuxStatus, AuxError,
        AuxCommand,
    };
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
                    reply_buf[0] = 0;   // ACK
                    Ok(AuxResponse { status: AuxStatus::Ack, data: &reply_buf[1..1] })
                }
                AuxCommand::NativeRead => {
                    let v = match req.address {
                        0x0_0202 => {
                            // Lane 0/1 nibbles. After 2 polls, CR_DONE
                            // + EQ_DONE + SYMBOL_LOCKED on both lanes.
                            self.cr_polls += 1;
                            if self.cr_polls < 2 { 0x00 }
                            else if self.eq_polls == 0 { 0x11 } // CR only
                            else { 0x77 }                       // EQ done
                        }
                        0x0_0203 => 0x00, // lane 2/3 unused (2-lane link)
                        0x0_0204 => {
                            // INTERLANE_ALIGN_DONE bit 0; flips on
                            // after EQ symbols lock.
                            self.eq_polls += 1;
                            if self.eq_polls < 2 { 0 } else { 1 }
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
    let mut aux = StubAux { cr_polls: 0, eq_polls: 0 };
    let params = TrainingParams { link_bw_set: 0x0A, lane_count: 2 };
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
        Ok(p)  => p,
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
    if !matches!(pp.offset(Subtable::OverdriveTable8), Err(PpTableError::TableAbsent)) {
        return TestResult::Fail("absent subtable should fail");
    }
    // V8 rejected.
    let mut bad = t.clone();
    bad[2] = 8;
    if !matches!(PpTable::parse(&bad), Err(PpTableError::UnsupportedVersion(_))) {
        return TestResult::Fail("V8 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pptable_v11_directory_round_trip);

fn smoke_amdgpu_atom_displayobj_iter_paths() -> TestResult {
    use crate::amdgpu_atom_displayobj::{
        ConnectorKind, DisplayObjectTable, DisplayObjError,
    };
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
        Ok(p)  => p,
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
    if !matches!(DisplayObjectTable::parse(&bad), Err(DisplayObjError::UnsupportedVersion(_))) {
        return TestResult::Fail("version 0 should reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_atom_displayobj_iter_paths);

fn smoke_dp_edid_over_aux_round_trip() -> TestResult {
    // StubAux that returns canned EDID bytes for I2C reads at
    // address 0x50<<1 + read flag.
    use crate::dp_aux::{
        AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus,
    };
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

    struct StubAux { edid: [u8; 128], cursor: usize }
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
                    Ok(AuxResponse { status: AuxStatus::Ack, data: &reply_buf[1..1] })
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
        Ok(e)  => e,
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
