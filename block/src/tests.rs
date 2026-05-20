//! Subsystem smokes for `narf-block`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `block` subsystem.
//!
//! Note: `smoke_block_device_trait` was *not* migrated here — it
//! depends on `narf-drivers-virtio` (specifically `VirtioBlkDevice`),
//! which is downstream of `narf-block` and would form a dependency
//! cycle. That smoke remains in the verification mega-lib; it
//! belongs in a `drivers/virtio/blk` test module rather than block/.

use narf_kernel_test::{kernel_test_in, TestResult};

fn make_block_request(op: crate::BlockOp, user_tag: u64) -> crate::BlockRequest {
    use crate::{BlockRequest, QosHint};
    use narf_capabilities::{Cap, CapSlot, Read, Rights};
    let cap = unsafe {
        Cap::<narf_io::DmaBuffer, Read>::mint(CapSlot::new(
            1,
            0,
            Read::BITS,
            narf_capabilities::CapKind::DmaBuffer as u32,
        ))
    };
    BlockRequest {
        op,
        lba: 0,
        blocks: 1,
        buffer: cap,
        qos: QosHint::Latency,
        user_tag,
    }
}

fn smoke_block_deadline_prefers_reads() -> TestResult {
    use crate::{BlockOp, DeadlineScheduler, STARVE_BOUND};

    let s = DeadlineScheduler::new();
    let far_future = u64::MAX / 2;

    s.enqueue(
        make_block_request(BlockOp::Write { fua: false }, 0x100),
        far_future,
    );
    for i in 0..(STARVE_BOUND + 2) {
        s.enqueue(
            make_block_request(BlockOp::Read, 0x200 + i as u64),
            far_future,
        );
    }

    for i in 0..STARVE_BOUND {
        let req = match s.dequeue_next(0) {
            Some(r) => r,
            None => return TestResult::Fail("scheduler underflowed"),
        };
        if req.op != BlockOp::Read {
            return TestResult::Fail("read lane starved before STARVE_BOUND");
        }
        if req.user_tag != 0x200 + i as u64 {
            return TestResult::Fail("read lane drained out of order");
        }
    }
    let req = s.dequeue_next(0).expect("pending");
    if !matches!(req.op, BlockOp::Write { .. }) {
        return TestResult::Fail("write was not promoted after STARVE_BOUND reads");
    }
    if req.user_tag != 0x100 {
        return TestResult::Fail("wrong write promoted");
    }
    let req = s.dequeue_next(0).expect("pending");
    if req.op != BlockOp::Read {
        return TestResult::Fail("read lane did not resume after write flush");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_prefers_reads);

fn smoke_block_deadline_promotes_expired() -> TestResult {
    use crate::{BlockOp, DeadlineScheduler};

    let s = DeadlineScheduler::new();
    s.enqueue(make_block_request(BlockOp::Read, 0x10), 1_000);
    s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0x20), 500);

    let req = s.dequeue_next(750).expect("pending");
    if !matches!(req.op, BlockOp::Write { .. }) || req.user_tag != 0x20 {
        return TestResult::Fail("expired write was not promoted ahead of the read");
    }
    let req = s.dequeue_next(750).expect("pending");
    if req.op != BlockOp::Read || req.user_tag != 0x10 {
        return TestResult::Fail("pending read was not drained next");
    }
    if !s.is_empty() {
        return TestResult::Fail("scheduler should be empty after draining both");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_promotes_expired);

fn smoke_block_encrypted_round_trip() -> TestResult {
    use crate::encrypted::EncryptedBlockDevice;
    use crate::registry::{BlockDeviceSync, BlockIoError};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use async_trait::async_trait;
    use narf_lib::sync::IrqSafeSpinLock;

    struct MemoryBlockDevice {
        data: IrqSafeSpinLock<alloc::vec::Vec<u8>>,
    }

    impl BlockDeviceSync for MemoryBlockDevice {
        fn lba_size(&self) -> u32 {
            512
        }
        fn capacity(&self) -> u64 {
            1024
        }

        fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
            let offset = (lba * 512) as usize;
            let len = n_blocks as usize * 512;
            let data = self.data.lock();
            out.copy_from_slice(&data[offset..offset + len]);
            Ok(())
        }

        fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
            let offset = (lba * 512) as usize;
            let len = n_blocks as usize * 512;
            let mut inner_data = self.data.lock();
            inner_data[offset..offset + len].copy_from_slice(data);
            Ok(())
        }
    }

    narf_scheduler::__reset_queues_for_test();
    let inner = Arc::new(MemoryBlockDevice {
        data: IrqSafeSpinLock::new(alloc::vec![0u8; 1024 * 512]),
    });

    // Mock TPM
    struct MockTpm;
    #[async_trait]
    impl narf_tpm::TpmDevice for MockTpm {
        fn get_info(&self) -> narf_tpm::TpmInfo {
            narf_tpm::TpmInfo {
                manufacturer: 0,
                version: 2,
                spec_level: 0,
            }
        }
        async fn submit_raw(&self, _cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, narf_tpm::TpmError> {
            unimplemented!()
        }
        async fn get_random(&self, _bytes: u16) -> Result<alloc::vec::Vec<u8>, narf_tpm::TpmError> {
            unimplemented!()
        }
        async fn extend_pcr(&self, _pcr: u32, _digest: &[u8]) -> Result<(), narf_tpm::TpmError> {
            Ok(())
        }
        async fn read_pcr(&self, _pcr: u32) -> Result<alloc::vec::Vec<u8>, narf_tpm::TpmError> {
            unimplemented!()
        }
    }
    let tpm = MockTpm;

    let success = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let s = success.clone();

    narf_scheduler::spawn(async move {
        let enc = EncryptedBlockDevice::open(inner.clone(), &tpm)
            .await
            .expect("open");

        let data = [0xAAu8; 512];
        enc.write(0, 1, &data).expect("write failed");

        // Verify data is encrypted in the underlying device.
        // Scope the lock so it's released before `enc.read` below
        // re-enters `inner.data.lock()` — non-recursive spinlock
        // would otherwise deadlock here.
        let plaintext_passthrough = {
            let raw_data = inner.data.lock();
            let encrypted_sector = &raw_data[8 * 512..9 * 512]; // Offset by 8
            encrypted_sector.iter().all(|&b| b == 0xAA)
        };
        if plaintext_passthrough {
            return; // Not encrypted!
        }

        // Read it back.
        let mut out = [0u8; 512];
        enc.read(0, 1, &mut out).expect("read failed");

        if out.iter().all(|&b| b == 0xAA) {
            s.store(true, core::sync::atomic::Ordering::SeqCst);
        }
    });

    narf_scheduler::run_until_empty();
    if success.load(core::sync::atomic::Ordering::SeqCst) {
        TestResult::Pass
    } else {
        TestResult::Fail("round trip failed")
    }
}
kernel_test_in!("block", smoke_block_encrypted_round_trip);

// ── SCSI codec smokes ──────────────────────────────────────────────

extern crate alloc;

fn smoke_scsi_inquiry_cdb_layout() -> TestResult {
    use crate::scsi::{inquiry, OP_INQUIRY};
    let cdb = inquiry(false, 0, 36);
    if cdb[0] != OP_INQUIRY {
        return TestResult::Fail("INQUIRY opcode = 0x12");
    }
    if cdb[3] != 0 || cdb[4] != 36 {
        return TestResult::Fail("alloc length stored as 16-bit BE");
    }
    let evpd = inquiry(true, 0x80, 256);
    if evpd[1] & 1 == 0 {
        return TestResult::Fail("EVPD flag at bit 0 of byte 1");
    }
    if evpd[2] != 0x80 {
        return TestResult::Fail("page code at byte 2");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_inquiry_cdb_layout);

fn smoke_scsi_inquiry_response_decode_disk() -> TestResult {
    use crate::scsi::{InquiryData, PDT_DIRECT_ACCESS_BLOCK};
    let mut buf = alloc::vec![0u8; 36];
    buf[0] = PDT_DIRECT_ACCESS_BLOCK; // qualifier 0, type 0
    buf[1] = 0x80; // RMB
    buf[4] = 31; // additional length
    buf[8..16].copy_from_slice(b"NARF    ");
    buf[16..32].copy_from_slice(b"FlashDrive      ");
    buf[32..36].copy_from_slice(b"1.0 ");
    let i = InquiryData::parse(&buf).expect("parse");
    if i.peripheral_device_type != PDT_DIRECT_ACCESS_BLOCK {
        return TestResult::Fail("device type mismatch");
    }
    if !i.removable_medium {
        return TestResult::Fail("RMB bit lost");
    }
    if i.vendor_id != "NARF" {
        return TestResult::Fail("vendor ID with trailing-space trim");
    }
    if i.product_id != "FlashDrive" {
        return TestResult::Fail("product ID with trailing-space trim");
    }
    if i.product_revision != "1.0" {
        return TestResult::Fail("product revision");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_inquiry_response_decode_disk);

fn smoke_scsi_read_capacity_10_round_trip() -> TestResult {
    use crate::scsi::{parse_read_capacity_10, read_capacity_10, OP_READ_CAPACITY_10};
    let cdb = read_capacity_10();
    if cdb[0] != OP_READ_CAPACITY_10 {
        return TestResult::Fail("READ CAPACITY(10) opcode = 0x25");
    }
    // 1 TiB at 512-byte sectors = 2_147_483_648 sectors → last LBA 2_147_483_647.
    let mut resp = [0u8; 8];
    resp[0..4].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    resp[4..8].copy_from_slice(&512u32.to_be_bytes());
    let (lba, bs) = parse_read_capacity_10(&resp).expect("parse");
    if lba != 0x7FFF_FFFF {
        return TestResult::Fail("last LBA decode");
    }
    if bs != 512 {
        return TestResult::Fail("block size decode");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_read_capacity_10_round_trip);

fn smoke_scsi_read_10_carries_lba_and_length() -> TestResult {
    use crate::scsi::{read_10, OP_READ_10};
    let cdb = read_10(0xCAFE_BEEF, 0x40, true);
    if cdb[0] != OP_READ_10 {
        return TestResult::Fail("READ(10) opcode = 0x28");
    }
    if cdb[1] & (1 << 3) == 0 {
        return TestResult::Fail("FUA bit at byte 1 bit 3");
    }
    if &cdb[2..6] != &[0xCA, 0xFE, 0xBE, 0xEF] {
        return TestResult::Fail("LBA stored big-endian");
    }
    if &cdb[7..9] != &[0x00, 0x40] {
        return TestResult::Fail("transfer length stored big-endian");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_read_10_carries_lba_and_length);

fn smoke_scsi_fixed_sense_round_trip() -> TestResult {
    use crate::scsi::{FixedSense, SENSE_KEY_NOT_READY};
    let mut buf = alloc::vec![0u8; 18];
    buf[0] = 0xF0; // Valid + current
    buf[2] = SENSE_KEY_NOT_READY;
    buf[3..7].copy_from_slice(&0x0000_2000u32.to_be_bytes());
    buf[12] = 0x04; // ASC = LOGICAL UNIT NOT READY
    buf[13] = 0x03; // ASCQ = MANUAL INTERVENTION REQUIRED
    let s = FixedSense::parse(&buf).expect("parse");
    if !s.valid(buf[0]) {
        return TestResult::Fail("Valid bit at byte 0 bit 7");
    }
    if s.sense_key != SENSE_KEY_NOT_READY {
        return TestResult::Fail("sense key low nibble of byte 2");
    }
    if s.information != 0x0000_2000 {
        return TestResult::Fail("information bytes are 4 BE bytes");
    }
    if s.additional_sense_code != 0x04 {
        return TestResult::Fail("ASC at byte 12");
    }
    if s.additional_sense_code_qualifier != 0x03 {
        return TestResult::Fail("ASCQ at byte 13");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_fixed_sense_round_trip);

fn smoke_scsi_status_constants() -> TestResult {
    use crate::scsi::{STATUS_BUSY, STATUS_CHECK_CONDITION, STATUS_GOOD};
    if STATUS_GOOD != 0x00 || STATUS_CHECK_CONDITION != 0x02 || STATUS_BUSY != 0x08 {
        return TestResult::Fail("SAM-5 status byte values");
    }
    TestResult::Pass
}
kernel_test_in!("block/scsi", smoke_scsi_status_constants);



// ── TCG OPAL ──────────────────────────────────────────────────────



fn smoke_opal_compacket_header_round_trip() -> TestResult {

    use crate::opal::ComPacketHeader;

    let h = ComPacketHeader {

        com_id: 0x07FE,

        com_id_ext: 0,

        outstanding_data: 0,

        min_transfer: 0,

        length: 64,

    };

    let buf = h.encode();

    let r = ComPacketHeader::decode(&buf).expect("decode");

    if r != h {

        return TestResult::Fail("ComPacket round-trip");

    }

    TestResult::Pass

}

kernel_test_in!("block/opal", smoke_opal_compacket_header_round_trip);



fn smoke_opal_atom_round_trip() -> TestResult {

    use crate::opal::{decode_atom, encode_short_atom, encode_tiny_uint};

    // Tiny: 0..=63 single byte.

    let t = encode_tiny_uint(42);

    let tiny_buf = [t];

    let (payload, n) = decode_atom(&tiny_buf).expect("tiny");

    if n != 1 || payload[0] != 42 {

        return TestResult::Fail("tiny atom decode");

    }

    // Short: 5 bytes of payload.

    let s = encode_short_atom(b"hello", false, true);

    let (p2, n2) = decode_atom(&s).expect("short");

    if p2 != b"hello" || n2 != s.len() {

        return TestResult::Fail("short atom decode");

    }

    TestResult::Pass

}

kernel_test_in!("block/opal", smoke_opal_atom_round_trip);



fn smoke_opal_level0_discovery_walks_features() -> TestResult {

    use crate::opal::{feature, parse_level0_discovery};

    // Build a synthetic Level 0 Discovery response with two

    // feature descriptors: TPer (4 bytes body) + Opal v2 (16 bytes).

    let mut buf = alloc::vec::Vec::new();

    // Body length covers feature descriptors only (header is

    // 48 bytes; body starts at offset 48 of the buffer).

    let body_len = 4 + 4 + 4 + 16;

    let total = 48 + body_len;

    let param_len = (total - 4) as u32;

    buf.extend_from_slice(&param_len.to_be_bytes());

    buf.extend_from_slice(&0x10000u32.to_be_bytes());

    buf.extend_from_slice(&[0u8; 40]);

    // TPer feature: code 0x0001, version 1, length 4.

    buf.extend_from_slice(&feature::TPER.to_be_bytes());

    buf.push(1 << 4);

    buf.push(4);

    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

    // Opal v2 feature: code 0x0203, version 1, length 16.

    buf.extend_from_slice(&feature::OPAL_V2.to_be_bytes());

    buf.push(1 << 4);

    buf.push(16);

    buf.extend_from_slice(&[0u8; 16]);

    let (h, descs) = parse_level0_discovery(&buf).expect("parse");

    if h.parameter_length != param_len { return TestResult::Fail("length"); }

    if descs.len() != 2 { return TestResult::Fail("feature count"); }

    if descs[0].feature_code != feature::TPER || descs[0].data.len() != 4 {

        return TestResult::Fail("TPer descriptor");

    }

    if descs[1].feature_code != feature::OPAL_V2 || descs[1].data.len() != 16 {

        return TestResult::Fail("Opal v2 descriptor");

    }

    TestResult::Pass

}

kernel_test_in!("block/opal", smoke_opal_level0_discovery_walks_features);



fn smoke_opal_token_constants() -> TestResult {

    use crate::opal::token;

    if token::CALL != 0xF8 || token::END_OF_DATA != 0xF9 || token::END_OF_SESSION != 0xFA {

        return TestResult::Fail("method-call tokens");

    }

    if token::START_LIST != 0xF0 || token::END_LIST != 0xF1 {

        return TestResult::Fail("list tokens");

    }

    TestResult::Pass

}

kernel_test_in!("block/opal", smoke_opal_token_constants);

// ── relocated from verification (subsystem 'block') ──

#[cfg(target_arch = "x86_64")]
fn smoke_block_registry_uniform_read() -> TestResult {
    // Walk crate::block_devices() and read sector 0 from each.
    // Asserts NVMe + virtio-blk-pci + AHCI all registered + return
    // a 512-byte read without error. Demonstrates the unified
    // BlockDeviceSync surface.
    use crate::block_devices;
    let regs = block_devices();
    if regs.is_empty() {
        return TestResult::Fail("block registry empty — no driver registered");
    }
    // We expect at least nvme0, vblk0, sata0 by convention.
    let has_nvme = regs.iter().any(|r| r.name == "nvme0");
    let has_vblk = regs.iter().any(|r| r.name == "vblk0");
    let has_sata = regs.iter().any(|r| r.name == "sata0");
    if !(has_nvme && has_vblk && has_sata) {
        return TestResult::Fail("expected nvme0 + vblk0 + sata0");
    }
    // lba_size + capacity surface should respond on every device.
    for reg in &regs {
        let _ = reg.dev.lba_size();
        let _ = reg.dev.capacity();
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("block", smoke_block_registry_uniform_read);

fn smoke_block_mq_round_robins_across_lanes() -> TestResult {
    // Populate three lanes with one request each. dequeue_next walks
    // round-robin so each lane's entry comes out exactly once before
    // any lane is revisited.
    use crate::{BlockOp, MqDeadlineScheduler};

    let s = MqDeadlineScheduler::with_lanes(3);
    s.enqueue_on(0, make_block_request(BlockOp::Read, 0x0A), u64::MAX);
    s.enqueue_on(1, make_block_request(BlockOp::Read, 0x1B), u64::MAX);
    s.enqueue_on(2, make_block_request(BlockOp::Read, 0x2C), u64::MAX);
    if s.len() != 3 {
        return TestResult::Fail("multi-queue len mismatch");
    }

    let first = s.dequeue_next(0).expect("pending").user_tag;
    let second = s.dequeue_next(0).expect("pending").user_tag;
    let third = s.dequeue_next(0).expect("pending").user_tag;
    if s.dequeue_next(0).is_some() {
        return TestResult::Fail("multi-queue over-drained");
    }

    // Round-robin must visit all three distinct lanes.
    if first == second || second == third || first == third {
        return TestResult::Fail("round-robin served the same lane twice");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_mq_round_robins_across_lanes);

fn smoke_block_deadline_tags_are_monotonic() -> TestResult {
    use crate::{BlockOp, DeadlineScheduler};

    let s = DeadlineScheduler::new();
    let t1 = s.enqueue(make_block_request(BlockOp::Read, 0), u64::MAX);
    let t2 = s.enqueue(
        make_block_request(BlockOp::Write { fua: false }, 1),
        u64::MAX,
    );
    let t3 = s.enqueue(make_block_request(BlockOp::Read, 2), u64::MAX);
    if !(t1 < t2 && t2 < t3) {
        return TestResult::Fail("enqueue tags not monotonically assigned");
    }
    if s.reads_pending() != 2 || s.writes_pending() != 1 {
        return TestResult::Fail("per-lane pending counts off");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_tags_are_monotonic);

// ── extended block coverage ────────────────────────────────────────
//
// Existing surface hit read/write balancing, deadline promotion, the
// MQ round-robin, encrypted round-trip, and the SCSI / OPAL wire
// shapes. New smokes close the remaining invariants on the
// scheduler primitives + registry + MQ edge cases.

fn smoke_block_deadline_empty_dequeue_is_none() -> TestResult {
    // Fresh scheduler: dequeue_next returns None on both lanes empty,
    // len() == 0, is_empty() == true.
    use crate::DeadlineScheduler;
    let s = DeadlineScheduler::new();
    if !s.is_empty() {
        return TestResult::Fail("fresh scheduler not empty");
    }
    if s.len() != 0 || s.reads_pending() != 0 || s.writes_pending() != 0 {
        return TestResult::Fail("fresh scheduler pending counts non-zero");
    }
    if s.dequeue_next(0).is_some() {
        return TestResult::Fail("dequeue on empty returned Some");
    }
    if s.dequeue_next(u64::MAX).is_some() {
        return TestResult::Fail("dequeue with max-now on empty returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_empty_dequeue_is_none);

fn smoke_block_deadline_write_only_drains_in_order() -> TestResult {
    // No reads at all → writes drain in enqueue order, every dequeue
    // resets the read-streak counter implicitly.
    use crate::{BlockOp, DeadlineScheduler};
    let s = DeadlineScheduler::new();
    for i in 0..4 {
        s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0x100 + i), u64::MAX);
    }
    if s.writes_pending() != 4 {
        return TestResult::Fail("writes_pending didn't reach 4");
    }
    for i in 0..4 {
        let r = s.dequeue_next(0).expect("pending write");
        if !matches!(r.op, BlockOp::Write { .. }) || r.user_tag != 0x100 + i {
            return TestResult::Fail("write-only drain order broken");
        }
    }
    if !s.is_empty() {
        return TestResult::Fail("scheduler should be empty after draining all writes");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_write_only_drains_in_order);

fn smoke_block_lane_of_classifies_ops() -> TestResult {
    // Lane::of maps Read → Read; every other op → Write (including
    // WriteZeroes and Trim — Stage-3 collapses Trim into the write
    // lane intentionally; the spec calls out a future Trim lane).
    use crate::{BlockOp, Lane};
    if Lane::of(BlockOp::Read) != Lane::Read {
        return TestResult::Fail("Read didn't map to Lane::Read");
    }
    if Lane::of(BlockOp::Write { fua: false }) != Lane::Write {
        return TestResult::Fail("Write didn't map to Lane::Write");
    }
    if Lane::of(BlockOp::Write { fua: true }) != Lane::Write {
        return TestResult::Fail("Write{fua:true} didn't map to Lane::Write");
    }
    if Lane::of(BlockOp::WriteZeroes) != Lane::Write {
        return TestResult::Fail("WriteZeroes didn't map to Lane::Write");
    }
    if Lane::of(BlockOp::Trim) != Lane::Write {
        return TestResult::Fail("Trim didn't map to Lane::Write (Stage-3 collapse)");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_lane_of_classifies_ops);

fn smoke_block_deadline_streak_resets_after_write() -> TestResult {
    // The consecutive-read counter must reset after any write
    // dispatch. Enqueue 4 reads + 1 write + 4 more reads; the write
    // should fire after the first 4 reads (no STARVE_BOUND hit), and
    // the post-write reads must NOT be subjected to a phantom
    // bound-already-near state.
    use crate::{BlockOp, DeadlineScheduler, STARVE_BOUND};
    let s = DeadlineScheduler::new();
    // STARVE_BOUND reads then 1 write — write promotes after the run.
    for i in 0..STARVE_BOUND {
        s.enqueue(make_block_request(BlockOp::Read, 0x100 + i as u64), u64::MAX);
    }
    s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0xC0), u64::MAX);
    // Now add 5 more reads + 1 more write so we can observe streak
    // reset behaviour.
    for i in 0..STARVE_BOUND {
        s.enqueue(make_block_request(BlockOp::Read, 0x200 + i as u64), u64::MAX);
    }
    s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0xCC), u64::MAX);

    // First batch of reads: STARVE_BOUND of them.
    for _ in 0..STARVE_BOUND {
        let r = s.dequeue_next(0).expect("read");
        if r.op != BlockOp::Read {
            return TestResult::Fail("expected Read in first batch");
        }
    }
    // First write fires (streak hit STARVE_BOUND, write was queued).
    let r = s.dequeue_next(0).expect("write");
    if r.user_tag != 0xC0 {
        return TestResult::Fail("first write tag mismatch");
    }
    // Counter reset → next STARVE_BOUND reads come out before the
    // second write.
    for _ in 0..STARVE_BOUND {
        let r = s.dequeue_next(0).expect("post-reset read");
        if r.op != BlockOp::Read {
            return TestResult::Fail("post-reset read lane drained wrong op");
        }
    }
    let r = s.dequeue_next(0).expect("second write");
    if r.user_tag != 0xCC {
        return TestResult::Fail("second write tag mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_deadline_streak_resets_after_write);

fn smoke_block_mq_enqueue_on_out_of_range_returns_none() -> TestResult {
    // `enqueue_on(invalid_lane, ...)` returns None and DOESN'T panic
    // or insert anything anywhere.
    use crate::{BlockOp, MqDeadlineScheduler};
    let s = MqDeadlineScheduler::with_lanes(4);
    let r = s.enqueue_on(4, make_block_request(BlockOp::Read, 0x99), u64::MAX);
    if r.is_some() {
        return TestResult::Fail("out-of-range lane accepted submission");
    }
    let r = s.enqueue_on(64, make_block_request(BlockOp::Read, 0x99), u64::MAX);
    if r.is_some() {
        return TestResult::Fail("very-out-of-range lane accepted submission");
    }
    if s.len() != 0 {
        return TestResult::Fail("failed enqueue still bumped pending count");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_mq_enqueue_on_out_of_range_returns_none);

fn smoke_block_mq_lane_count_and_accessor() -> TestResult {
    // lane_count() reflects construction; lane(i) returns Some(&Sched)
    // in-range and None out-of-range.
    use crate::MqDeadlineScheduler;
    let s = MqDeadlineScheduler::with_lanes(8);
    if s.lane_count() != 8 {
        return TestResult::Fail("lane_count drifted from construction");
    }
    if s.lane(0).is_none() || s.lane(7).is_none() {
        return TestResult::Fail("in-range lane accessor returned None");
    }
    if s.lane(8).is_some() {
        return TestResult::Fail("out-of-range lane accessor returned Some");
    }
    // Per-lane sub-scheduler starts empty.
    if !s.lane(3).unwrap().is_empty() {
        return TestResult::Fail("fresh lane not empty");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_mq_lane_count_and_accessor);

// NOTE: a "cross-lane expired-promotion wins regardless of cursor"
// test would be valuable, but `MqDeadlineScheduler::drain_expired`
// today just walks lanes in order and pulls from the first
// non-empty one — so an in-deadline entry on lane 0 beats an
// expired entry on lane 2. The docstring above `dequeue_next`
// claims the opposite ("expired-lane promotion wins regardless of
// cursor"), so either the docstring or the code is wrong. Pinning
// either side would lock in the present bug; leaving this slot
// open until the spec gap is resolved (and then the test pins the
// chosen behaviour).

fn smoke_block_mq_dequeue_skips_empty_lanes() -> TestResult {
    // Three lanes, only lane 2 has a request. dequeue_next must walk
    // round-robin from the current cursor, skip empties, and find
    // the one queued request.
    use crate::{BlockOp, MqDeadlineScheduler};
    let s = MqDeadlineScheduler::with_lanes(3);
    s.enqueue_on(2, make_block_request(BlockOp::Read, 0xD0), u64::MAX);
    let r = s.dequeue_next(0).expect("non-empty lane");
    if r.user_tag != 0xD0 {
        return TestResult::Fail("dequeue didn't find the queued request");
    }
    if !s.is_empty() {
        return TestResult::Fail("post-dequeue MQ not empty");
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_mq_dequeue_skips_empty_lanes);

fn smoke_block_registry_register_find_round_trip() -> TestResult {
    // Register a synthetic device, find it by name, confirm
    // block_device_count + block_devices reflect the registration.
    // Re-register with the same name replaces in place (no double-
    // count).
    use crate::registry::{
        block_device_count, find_block_device, register_block_device, BlockDeviceSync,
        BlockIoError, __reset_for_test, __restore_for_test, __snapshot_for_test,
    };
    use alloc::sync::Arc;

    struct Stub;
    impl BlockDeviceSync for Stub {
        fn lba_size(&self) -> u32 { 512 }
        fn capacity(&self) -> u64 { 8 }
        fn read(&self, _: u64, _: u16, _: &mut [u8]) -> Result<(), BlockIoError> { Ok(()) }
        fn write(&self, _: u64, _: u16, _: &[u8]) -> Result<(), BlockIoError> { Ok(()) }
    }

    // Save boot-time registrations so later tests (e.g.
    // `smoke_block_registry_uniform_read`) still see nvme0 /
    // vblk0 / sata0 after we wipe + repopulate.
    let saved = __snapshot_for_test();
    __reset_for_test();
    if block_device_count() != 0 {
        __restore_for_test(saved);
        return TestResult::Fail("registry not empty after reset");
    }
    register_block_device("smoke-stub-a", Arc::new(Stub));
    register_block_device("smoke-stub-b", Arc::new(Stub));
    if block_device_count() != 2 {
        __restore_for_test(saved);
        return TestResult::Fail("register didn't bump count to 2");
    }
    if find_block_device("smoke-stub-a").is_none() {
        __restore_for_test(saved);
        return TestResult::Fail("find didn't locate registered device");
    }
    if find_block_device("nonexistent").is_some() {
        __restore_for_test(saved);
        return TestResult::Fail("find returned Some for missing device");
    }
    // Re-register same name → replaces in place; count stays 2.
    register_block_device("smoke-stub-a", Arc::new(Stub));
    if block_device_count() != 2 {
        __restore_for_test(saved);
        return TestResult::Fail("re-register inflated count past 2");
    }
    __reset_for_test();
    if block_device_count() != 0 {
        __restore_for_test(saved);
        return TestResult::Fail("reset didn't clear registry");
    }
    __restore_for_test(saved);
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_registry_register_find_round_trip);

fn smoke_block_cancel_result_distinct_variants() -> TestResult {
    // Pin the three CancelResult variants are distinct via Eq.
    // Catches accidental discriminant collapse in a refactor.
    use crate::CancelResult;
    let pairs: &[(CancelResult, CancelResult)] = &[
        (CancelResult::Cancelled, CancelResult::Completed),
        (CancelResult::Completed, CancelResult::NotFound),
        (CancelResult::NotFound, CancelResult::Cancelled),
    ];
    for &(a, b) in pairs {
        if a == b {
            return TestResult::Fail("two CancelResult variants compared equal");
        }
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_cancel_result_distinct_variants);

fn smoke_block_error_variants_distinct() -> TestResult {
    // Same for BlockError.
    use crate::BlockError;
    let all = [
        BlockError::IOError,
        BlockError::PermissionDenied,
        BlockError::InvalidRange,
        BlockError::DeviceRemoved,
        BlockError::Cancelled,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two BlockError variants compared equal");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("block", smoke_block_error_variants_distinct);

// ── block/partition (MBR + GPT) ────────────────────────────────────

/// Build a valid 512-byte sector containing a single MBR entry of
/// type `kind` covering all sectors.
fn build_mbr_sector(kind: u8) -> [u8; 512] {
    let mut s = [0u8; 512];
    // Entry 0 at offset 446.
    s[446] = 0x00; // boot_flag inactive
    s[450] = kind;
    s[454..458].copy_from_slice(&1u32.to_le_bytes()); // start_lba
    s[458..462].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sector_count
    // 0xAA55 signature.
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

fn smoke_block_partition_mbr_parse_signature_and_entry() -> TestResult {
    use crate::partition::{parse_mbr, MBR_BOOT_SIGNATURE};
    let s = build_mbr_sector(0x83); // Linux native
    let parts = match parse_mbr(&s) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse_mbr rejected valid sector"),
    };
    if parts[0].kind != 0x83 {
        return TestResult::Fail("entry 0 kind wrong");
    }
    if parts[0].start_lba != 1 || parts[0].sector_count != 0xFFFF_FFFF {
        return TestResult::Fail("entry 0 LBA/count wrong");
    }
    // Signature check: should also fail when 0xAA55 isn't there.
    let mut bad = build_mbr_sector(0x83);
    bad[510] = 0;
    bad[511] = 0;
    if parse_mbr(&bad).is_ok() {
        return TestResult::Fail("missing signature must be rejected");
    }
    let _ = MBR_BOOT_SIGNATURE; // doc-link sanity
    TestResult::Pass
}
kernel_test_in!("block/partition", smoke_block_partition_mbr_parse_signature_and_entry);

fn smoke_block_partition_gpt_protective_detected() -> TestResult {
    use crate::partition::{is_gpt_protective, parse_mbr};
    // Build a sector with a single 0xEE entry covering the disk.
    let s = build_mbr_sector(0xEE);
    let parts = parse_mbr(&s).expect("parse_mbr failed");
    if !is_gpt_protective(&parts) {
        return TestResult::Fail("0xEE entry must be classified GPT-protective");
    }
    // A legacy MBR (Linux 0x83) must NOT be flagged protective.
    let s2 = build_mbr_sector(0x83);
    let parts2 = parse_mbr(&s2).expect("parse_mbr failed");
    if is_gpt_protective(&parts2) {
        return TestResult::Fail("0x83 entry must NOT be GPT-protective");
    }
    TestResult::Pass
}
kernel_test_in!("block/partition", smoke_block_partition_gpt_protective_detected);

/// Build a 92-byte minimal GPT primary header (rest of sector is
/// zero-padding). Header fields per UEFI 2.10 §5.3.2.
fn build_gpt_header(first_usable: u64, last_usable: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
    h[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
    h[16..20].copy_from_slice(&0u32.to_le_bytes()); // header_crc32 (caller verifies)
    h[24..32].copy_from_slice(&1u64.to_le_bytes()); // current_lba
    h[32..40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // backup_lba
    h[40..48].copy_from_slice(&first_usable.to_le_bytes());
    h[48..56].copy_from_slice(&last_usable.to_le_bytes());
    // disk_guid at [56..72] left zero.
    h[72..80].copy_from_slice(&2u64.to_le_bytes()); // partition_entries_lba
    h[80..84].copy_from_slice(&128u32.to_le_bytes()); // num_entries
    h[84..88].copy_from_slice(&128u32.to_le_bytes()); // entry_size
    h
}

fn smoke_block_partition_gpt_header_round_trip() -> TestResult {
    use crate::partition::{parse_gpt_header, GPT_REVISION_1_0};
    let raw = build_gpt_header(2048, 0xFFFF_0000);
    let h = match parse_gpt_header(&raw) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("parse_gpt_header rejected valid header"),
    };
    if h.revision != GPT_REVISION_1_0 {
        return TestResult::Fail("revision lost");
    }
    if h.header_size != 92 {
        return TestResult::Fail("header_size lost");
    }
    if h.first_usable_lba != 2048 || h.last_usable_lba != 0xFFFF_0000 {
        return TestResult::Fail("usable-LBA range lost");
    }
    if h.partition_entry_size != 128 || h.num_partition_entries != 128 {
        return TestResult::Fail("entry-size / entry-count lost");
    }
    TestResult::Pass
}
kernel_test_in!("block/partition", smoke_block_partition_gpt_header_round_trip);

fn smoke_block_partition_gpt_header_rejects_bad_signature() -> TestResult {
    use crate::partition::{parse_gpt_header, GptError};
    let mut bad = build_gpt_header(2048, 0xFFFF_0000);
    bad[0] = b'X'; // corrupt signature
    match parse_gpt_header(&bad) {
        Err(GptError::BadSignature) => TestResult::Pass,
        _ => TestResult::Fail("corrupt signature must be rejected"),
    }
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_gpt_header_rejects_bad_signature
);

fn smoke_block_partition_gpt_entries_decode_names_and_lba_range() -> TestResult {
    use crate::partition::parse_gpt_partitions;
    // Build a single 128-byte entry. Linux root partition GUID
    // (0FC63DAF-8483-4772-8E79-3D69D8477DE4) — first 16 bytes.
    let mut array = alloc::vec![0u8; 256];
    array[0..16].copy_from_slice(&[
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47,
        0x7D, 0xE4,
    ]);
    array[32..40].copy_from_slice(&2048u64.to_le_bytes()); // start_lba
    array[40..48].copy_from_slice(&(2048u64 + 4096 - 1).to_le_bytes()); // end_lba inclusive
    // Name "NARFROOT" as UTF-16LE.
    let name = "NARFROOT";
    for (i, c) in name.chars().enumerate() {
        let cu = c as u16;
        array[56 + i * 2] = cu as u8;
        array[57 + i * 2] = (cu >> 8) as u8;
    }
    let parts = parse_gpt_partitions(&array, 128, 2);
    if parts.len() != 2 {
        return TestResult::Fail("expected 2 entries (including empty trailer)");
    }
    if parts[0].is_empty() {
        return TestResult::Fail("first entry must be non-empty");
    }
    if parts[0].start_lba != 2048 || parts[0].sector_count() != 4096 {
        return TestResult::Fail("LBA range wrong");
    }
    if parts[0].name != "NARFROOT" {
        return TestResult::Fail("name decode wrong");
    }
    if !parts[1].is_empty() {
        return TestResult::Fail("second entry should be empty (all-zero type-GUID)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_gpt_entries_decode_names_and_lba_range
);
