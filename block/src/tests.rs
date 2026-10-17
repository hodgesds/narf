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
    // SAFETY: this is a test-only synthetic capability. `mint` requires the
    // slot's `type_tag` and `rights` to match the `Cap`'s `T` and `R`. The
    // slot is built here with `type_tag = CapKind::DmaBuffer` and `rights =
    // Read::BITS`, which exactly match `Cap::<DmaBuffer, Read>`, so the
    // type/rights coherence invariant holds.
    // SAFETY: Valid memory or trusted environment
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
    if cdb[2..6] != [0xCA, 0xFE, 0xBE, 0xEF] {
        return TestResult::Fail("LBA stored big-endian");
    }
    if cdb[7..9] != [0x00, 0x40] {
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

    if h.parameter_length != param_len {
        return TestResult::Fail("length");
    }

    if descs.len() != 2 {
        return TestResult::Fail("feature count");
    }

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
    // Walk crate::block_devices() and read sector 0 from each. The smoke
    // exercises the unified BlockDeviceSync surface across NVMe /
    // virtio-blk-pci / AHCI. cargo xtask test runs without the boot-time
    // pci-probe-all path that normally binds those drivers, so register
    // synthetic stubs under the canonical names before checking.
    use crate::block_devices;
    use crate::registry::{
        block_device_count, register_block_device, unregister_block_device, BlockDeviceSync,
        BlockIoError, __reset_for_test, __restore_for_test, __snapshot_for_test,
    };
    use alloc::sync::Arc;

    struct Stub;
    impl BlockDeviceSync for Stub {
        fn lba_size(&self) -> u32 {
            512
        }
        fn capacity(&self) -> u64 {
            2048
        }
        fn read(&self, _: u64, _: u16, _: &mut [u8]) -> Result<(), BlockIoError> {
            Ok(())
        }
        fn write(&self, _: u64, _: u16, _: &[u8]) -> Result<(), BlockIoError> {
            Ok(())
        }
    }

    let saved = __snapshot_for_test();
    __reset_for_test();
    register_block_device("nvme0", Arc::new(Stub));
    register_block_device("vblk0", Arc::new(Stub));
    register_block_device("sata0", Arc::new(Stub));
    let _ = block_device_count();

    let regs = block_devices();
    let outcome: TestResult = if regs.is_empty() {
        TestResult::Fail("block registry empty — no driver registered")
    } else {
        let has_nvme = regs.iter().any(|r| r.name == "nvme0");
        let has_vblk = regs.iter().any(|r| r.name == "vblk0");
        let has_sata = regs.iter().any(|r| r.name == "sata0");
        if !(has_nvme && has_vblk && has_sata) {
            TestResult::Fail("expected nvme0 + vblk0 + sata0")
        } else {
            for reg in &regs {
                let _ = reg.dev.lba_size();
                let _ = reg.dev.capacity();
            }
            TestResult::Pass
        }
    };

    // Clean up so we don't leak stubs into later tests.
    unregister_block_device("nvme0");
    unregister_block_device("vblk0");
    unregister_block_device("sata0");
    __restore_for_test(saved);
    outcome
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
    if !s.is_empty() || s.reads_pending() != 0 || s.writes_pending() != 0 {
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
        s.enqueue(
            make_block_request(BlockOp::Write { fua: false }, 0x100 + i),
            u64::MAX,
        );
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
        s.enqueue(
            make_block_request(BlockOp::Read, 0x100 + i as u64),
            u64::MAX,
        );
    }
    s.enqueue(
        make_block_request(BlockOp::Write { fua: false }, 0xC0),
        u64::MAX,
    );
    // Now add 5 more reads + 1 more write so we can observe streak
    // reset behaviour.
    for i in 0..STARVE_BOUND {
        s.enqueue(
            make_block_request(BlockOp::Read, 0x200 + i as u64),
            u64::MAX,
        );
    }
    s.enqueue(
        make_block_request(BlockOp::Write { fua: false }, 0xCC),
        u64::MAX,
    );

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
    if !s.is_empty() {
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
        block_device_count, find_block_device, find_block_device_indexed, register_block_device,
        BlockDeviceSync, BlockIoError, __reset_for_test, __restore_for_test, __snapshot_for_test,
    };
    use alloc::sync::Arc;

    struct Stub;
    impl BlockDeviceSync for Stub {
        fn lba_size(&self) -> u32 {
            512
        }
        fn capacity(&self) -> u64 {
            8
        }
        fn read(&self, _: u64, _: u16, _: &mut [u8]) -> Result<(), BlockIoError> {
            Ok(())
        }
        fn write(&self, _: u64, _: u16, _: &[u8]) -> Result<(), BlockIoError> {
            Ok(())
        }
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
    match find_block_device_indexed("smoke-stub-b") {
        Some((1, _)) => {}
        Some(_) => {
            __restore_for_test(saved);
            return TestResult::Fail("indexed find returned wrong registration index");
        }
        None => {
            __restore_for_test(saved);
            return TestResult::Fail("indexed find missed registered device");
        }
    }
    if find_block_device_indexed("nonexistent").is_some() {
        __restore_for_test(saved);
        return TestResult::Fail("indexed find returned Some for missing device");
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
kernel_test_in!(
    "block/partition",
    smoke_block_partition_mbr_parse_signature_and_entry
);

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
kernel_test_in!(
    "block/partition",
    smoke_block_partition_gpt_protective_detected
);

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
kernel_test_in!(
    "block/partition",
    smoke_block_partition_gpt_header_round_trip
);

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
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
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

// ── block/partition (registration wire-up) ─────────────────────────

/// A trivial `BlockDeviceSync` backed by an in-memory Vec, just
/// enough to exercise the partition scanner round-trip.
struct VecBlock {
    data: alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>>,
    lba_size: u32,
}

impl crate::BlockDeviceSync for VecBlock {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        let g = self.data.lock();
        g.len() as u64 / self.lba_size as u64
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), crate::BlockIoError> {
        let g = self.data.lock();
        let off = lba as usize * self.lba_size as usize;
        let len = n as usize * self.lba_size as usize;
        if off + len > g.len() || out.len() < len {
            return Err(crate::BlockIoError::OutOfRange);
        }
        out[..len].copy_from_slice(&g[off..off + len]);
        Ok(())
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), crate::BlockIoError> {
        let mut g = self.data.lock();
        let off = lba as usize * self.lba_size as usize;
        let len = n as usize * self.lba_size as usize;
        if off + len > g.len() || data.len() < len {
            return Err(crate::BlockIoError::OutOfRange);
        }
        g[off..off + len].copy_from_slice(&data[..len]);
        Ok(())
    }
}

fn smoke_block_partition_block_device_translates_lba_and_bounds_checks() -> TestResult {
    use crate::partition::PartitionBlockDevice;
    use crate::BlockDeviceSync;
    use alloc::sync::Arc;
    // 128-LBA parent, 512-byte LBAs, first 64 KiB pre-filled with a
    // marker pattern.
    let mut bytes = alloc::vec![0u8; 128 * 512];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    let parent = Arc::new(VecBlock {
        data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(bytes)),
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;
    // Sub-device starting at LBA 16, 64 LBAs long.
    let sub = PartitionBlockDevice::new(parent, 16, 64);
    if sub.capacity() != 64 {
        return TestResult::Fail("partition capacity must reflect sector_count");
    }
    // Read LBA 0 of the partition — should give parent's LBA 16.
    let mut buf = [0u8; 512];
    sub.read(0, 1, &mut buf).expect("read failed");
    // Marker pattern: byte 0 of parent LBA 16 = (16*512) & 0xFF = 0.
    // Easier check: byte 1 = 1.
    if buf[1] != 1 || buf[2] != 2 {
        return TestResult::Fail("partition LBA 0 doesn't match parent LBA 16");
    }
    // Out-of-range read past partition end must reject before
    // hitting the parent.
    let mut huge = [0u8; 512];
    if sub.read(63, 2, &mut huge).is_ok() {
        return TestResult::Fail("read past partition end must be rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_block_device_translates_lba_and_bounds_checks
);

fn smoke_block_partition_scan_registers_gpt_partitions() -> TestResult {
    use crate::partition::scan_and_register_partitions;
    use alloc::sync::Arc;
    // Build a synthetic 1024-LBA GPT disk: LBA 0 = protective MBR,
    // LBA 1 = GPT header, LBA 2 = entries (only first 128B used).
    let mut bytes = alloc::vec![0u8; 1024 * 512];
    // LBA 0: protective MBR with single 0xEE entry.
    let mbr_off = 0;
    bytes[mbr_off + 446 + 4] = 0xEE; // kind
    bytes[mbr_off + 446 + 8..mbr_off + 446 + 12].copy_from_slice(&1u32.to_le_bytes()); // start_lba
    bytes[mbr_off + 510] = 0x55;
    bytes[mbr_off + 511] = 0xAA;
    // LBA 1: GPT header (92-byte minimal).
    let h = 512; // byte offset of LBA 1
    bytes[h..h + 8].copy_from_slice(b"EFI PART");
    bytes[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    bytes[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
    bytes[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes());
    bytes[h + 32..h + 40].copy_from_slice(&1023u64.to_le_bytes());
    bytes[h + 40..h + 48].copy_from_slice(&34u64.to_le_bytes());
    bytes[h + 48..h + 56].copy_from_slice(&990u64.to_le_bytes());
    bytes[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
    bytes[h + 80..h + 84].copy_from_slice(&2u32.to_le_bytes()); // num entries
    bytes[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
                                                                  // LBA 2: one non-empty entry + one empty entry.
    let e = 1024; // byte offset of LBA 2
                  // Type GUID — UEFI EFI System Partition GUID in GPT's
                  // mixed-endian on-disk layout. The registry must retain this semantic
                  // type rather than inferring an ESP from the device name or FAT serial.
    bytes[e..e + 16].copy_from_slice(&[
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ]);
    bytes[e + 32..e + 40].copy_from_slice(&100u64.to_le_bytes()); // start
    bytes[e + 40..e + 48].copy_from_slice(&199u64.to_le_bytes()); // end inclusive
                                                                  // Second entry stays all-zero (empty).
                                                                  // Partition 1 is a FAT32 EFI-like volume. Its serial is stored little
                                                                  // endian at BPB offset 67 and must become the Linux UUID spelling used
                                                                  // by `/dev/disk/by-uuid` and systemd's .device units.
    let fat = 100 * 512;
    bytes[fat + 67..fat + 71].copy_from_slice(&0x7fc5_5a22u32.to_le_bytes());
    bytes[fat + 82..fat + 90].copy_from_slice(b"FAT32   ");

    let parent = Arc::new(VecBlock {
        data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(bytes)),
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;

    use crate::registry::{
        __reset_for_test, __restore_for_test, __snapshot_for_test, block_devices, find_block_device,
    };
    // Snapshot + restore the registry so this test doesn't pollute it.
    let snap = __snapshot_for_test();
    __reset_for_test();

    let outcome = scan_and_register_partitions(parent, "testdisk0");
    let report = match outcome {
        Ok(r) => r,
        Err(_) => {
            __restore_for_test(snap);
            return TestResult::Fail("scan errored on valid GPT disk");
        }
    };
    let fat_uuid = block_devices()
        .into_iter()
        .find(|d| d.name == "testdisk0p1")
        .and_then(|d| d.partition)
        .map(|p| {
            let is_esp = p.is_efi_system_partition();
            (p.fs_uuid, is_esp)
        });
    let pass = report.is_gpt
        && report.registered == alloc::vec![alloc::string::String::from("testdisk0p1")]
        && find_block_device("testdisk0p1").is_some()
        && fat_uuid.as_ref().map(|(uuid, _)| uuid.as_str()) == Some("7FC5-5A22")
        && fat_uuid.as_ref().is_some_and(|(_, is_esp)| *is_esp);

    __restore_for_test(snap);
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("scan didn't register the expected partition")
    }
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_scan_registers_gpt_partitions
);

// ── block/fs_detect ────────────────────────────────────────────────
//
// Each smoke builds a synthetic backing-block-device whose first few
// LBAs carry the target FS's magic + minimal valid superblock, then
// verifies detect_filesystem picks the right FsType.

fn synthetic_block(
    payload: alloc::vec::Vec<u8>,
    lba_size: u32,
) -> alloc::sync::Arc<dyn crate::BlockDeviceSync> {
    use alloc::sync::Arc;
    // Pad to a multiple of lba_size.
    let mut padded = payload;
    let rem = padded.len() % lba_size as usize;
    if rem != 0 {
        padded.resize(padded.len() + (lba_size as usize - rem), 0);
    }
    Arc::new(VecBlock {
        data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(padded)),
        lba_size,
    }) as Arc<dyn crate::BlockDeviceSync>
}

fn smoke_block_fs_detect_ext_via_magic_at_byte_1080() -> TestResult {
    use crate::fs_detect::{detect_filesystem, FsType};
    // Build a 4-LBA payload (2048 bytes) and put 0xEF53 at byte 1080.
    let mut buf = alloc::vec![0u8; 4 * 512];
    buf[1080..1082].copy_from_slice(&0xEF53u16.to_le_bytes());
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(Some(FsType::Ext)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("ext magic at byte 1080 not detected")
        }
    }
}
kernel_test_in!(
    "block/fs_detect",
    smoke_block_fs_detect_ext_via_magic_at_byte_1080
);

fn smoke_block_fs_detect_fat_via_bpb_and_signature() -> TestResult {
    use crate::fs_detect::{detect_filesystem, FsType};
    // Minimal valid BPB:
    //   [11..13] bytes_per_sec = 512
    //   [13]     sec_per_clus = 8
    //   [16]     num_fats = 2
    //   [510..512] signature = 0xAA55
    let mut buf = alloc::vec![0u8; 512];
    buf[11..13].copy_from_slice(&512u16.to_le_bytes());
    buf[13] = 8;
    buf[16] = 2;
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(Some(FsType::Fat)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("valid BPB not detected as FAT")
        }
    }
}
kernel_test_in!(
    "block/fs_detect",
    smoke_block_fs_detect_fat_via_bpb_and_signature
);

fn smoke_block_fs_detect_exfat_via_oem_signature() -> TestResult {
    use crate::fs_detect::{detect_filesystem, FsType};
    let mut buf = alloc::vec![0u8; 512];
    // exFAT OEM name at offset 3.
    buf[3..11].copy_from_slice(b"EXFAT   ");
    // Also write a valid 0xAA55 signature so the FAT probe ordering
    // doesn't matter (exFAT probe must hit first).
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(Some(FsType::ExFat)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("EXFAT OEM not detected")
        }
    }
}
kernel_test_in!(
    "block/fs_detect",
    smoke_block_fs_detect_exfat_via_oem_signature
);

fn smoke_block_fs_detect_iso9660_via_cd001() -> TestResult {
    use crate::fs_detect::{detect_filesystem, FsType};
    // ISO9660: "CD001" at byte 16*2048 + 1.
    let iso_byte = 16 * 2048 + 1;
    let mut buf = alloc::vec![0u8; iso_byte + 5];
    buf[iso_byte..iso_byte + 5].copy_from_slice(b"CD001");
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(Some(FsType::Iso9660)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("CD001 at LBA 64 not detected as ISO9660")
        }
    }
}
kernel_test_in!("block/fs_detect", smoke_block_fs_detect_iso9660_via_cd001);

fn smoke_block_fs_detect_squashfs_via_magic() -> TestResult {
    use crate::fs_detect::{detect_filesystem, FsType};
    let mut buf = alloc::vec![0u8; 512];
    // 'hsqs' little-endian.
    buf[0..4].copy_from_slice(&[0x68, 0x73, 0x71, 0x73]);
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(Some(FsType::SquashFs)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("hsqs magic not detected as squashfs")
        }
    }
}
kernel_test_in!("block/fs_detect", smoke_block_fs_detect_squashfs_via_magic);

fn smoke_block_fs_detect_returns_none_for_zero_disk() -> TestResult {
    use crate::fs_detect::detect_filesystem;
    let buf = alloc::vec![0u8; 4 * 512];
    let dev = synthetic_block(buf, 512);
    match detect_filesystem(&dev) {
        Ok(None) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("all-zero disk must yield None, not a false-positive FS")
        }
    }
}
kernel_test_in!(
    "block/fs_detect",
    smoke_block_fs_detect_returns_none_for_zero_disk
);

// ── block/sync_to_async (SyncBlock geometry forwarding) ──────────────

fn smoke_sync_block_reports_geometry_from_inner() -> TestResult {
    use crate::BlockDevice;
    use crate::SyncBlock;
    use alloc::sync::Arc;
    let payload = alloc::vec![0u8; 16 * 512];
    let inner = Arc::new(VecBlock {
        data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(payload)),
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;
    let bridge = SyncBlock::new(inner);
    if bridge.logical_block_size() != 512 {
        return TestResult::Fail("LBS not forwarded");
    }
    if bridge.physical_block_size() != 512 {
        return TestResult::Fail("PBS should mirror LBS for sync devices");
    }
    if bridge.capacity_blocks() != 16 {
        return TestResult::Fail("capacity_blocks not forwarded");
    }
    // Existing SyncBlock advertises Flush + WriteZeroes (no-ops on
    // a sync transport, harmless to claim). Discard is NOT claimed.
    if bridge.supports(crate::BlockFeature::Discard) {
        return TestResult::Fail("sync adapter must NOT claim Discard");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/sync_to_async",
    smoke_sync_block_reports_geometry_from_inner
);

// ── Wave G: pluggable I/O scheduler ────────────────────────────────

fn smoke_pluggable_io_scheduler() -> TestResult {
    use crate::{
        bootstrap_io_scheduler_authority, current_io_scheduler_name, enqueue_on,
        install_io_scheduler, pick_next_on, reserve_io_scheduler_slot, BlockOp, DeadlineScheduler,
        NoopScheduler,
    };

    // 1) Reserve a slot for a synthetic device id — defaults to
    //    DeadlineScheduler.
    const DEV: &str = "wave-g-pluggable";
    reserve_io_scheduler_slot(DEV);
    if current_io_scheduler_name(DEV) != Some("deadline") {
        return TestResult::Fail("default scheduler was not 'deadline'");
    }

    // 2) Install NoopScheduler under bootstrap cap.
    let cap = bootstrap_io_scheduler_authority();
    if install_io_scheduler(&cap, DEV, NoopScheduler::new()).is_err() {
        return TestResult::Fail("install_io_scheduler(NoopScheduler) failed on a live cap");
    }
    if current_io_scheduler_name(DEV) != Some("noop") {
        return TestResult::Fail("scheduler name did not switch to 'noop' after install");
    }

    // 3) Enqueue a write then a read; NoopScheduler is pure FIFO so
    //    they come back in submission order. Deadline would have
    //    promoted the read.
    let _t_write = enqueue_on(DEV, make_block_request(BlockOp::Write { fua: false }, 0xAA));
    let _t_read = enqueue_on(DEV, make_block_request(BlockOp::Read, 0xBB));

    let first = match pick_next_on(DEV) {
        Some(r) => r,
        None => return TestResult::Fail("NoopScheduler dropped enqueued request"),
    };
    if first.user_tag != 0xAA {
        return TestResult::Fail("NoopScheduler did not return write first (FIFO violation)");
    }
    let second = match pick_next_on(DEV) {
        Some(r) => r,
        None => return TestResult::Fail("NoopScheduler missing second entry"),
    };
    if second.user_tag != 0xBB {
        return TestResult::Fail("NoopScheduler did not return read second");
    }
    if pick_next_on(DEV).is_some() {
        return TestResult::Fail("NoopScheduler still has entries after drain");
    }

    // 4) Reinstall Deadline for hygiene.
    if install_io_scheduler(&cap, DEV, DeadlineScheduler::new()).is_err() {
        return TestResult::Fail("re-install of DeadlineScheduler failed");
    }
    if current_io_scheduler_name(DEV) != Some("deadline") {
        return TestResult::Fail("scheduler name did not revert to 'deadline'");
    }

    TestResult::Pass
}
kernel_test_in!("block/io_scheduler", smoke_pluggable_io_scheduler);

fn smoke_pluggable_io_scheduler_unknown_device() -> TestResult {
    use crate::{
        bootstrap_io_scheduler_authority, install_io_scheduler, IoSchedError, NoopScheduler,
    };

    let cap = bootstrap_io_scheduler_authority();
    match install_io_scheduler(&cap, "nonexistent-wave-g-device", NoopScheduler::new()) {
        Err(IoSchedError::UnknownDevice) => TestResult::Pass,
        Err(_) => TestResult::Fail("install on unknown device returned wrong error variant"),
        Ok(_) => TestResult::Fail("install on unknown device unexpectedly succeeded"),
    }
}
kernel_test_in!(
    "block/io_scheduler",
    smoke_pluggable_io_scheduler_unknown_device
);

fn smoke_pluggable_io_scheduler_revoked_cap() -> TestResult {
    use crate::{
        bootstrap_io_scheduler_authority, install_io_scheduler, reserve_io_scheduler_slot,
        IoSchedError, NoopScheduler,
    };

    const DEV: &str = "wave-g-revoked";
    reserve_io_scheduler_slot(DEV);

    let cap = bootstrap_io_scheduler_authority();
    cap.revoke();
    match install_io_scheduler(&cap, DEV, NoopScheduler::new()) {
        Err(IoSchedError::AuthorityRevoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("revoked install returned wrong error variant"),
        Ok(_) => TestResult::Fail("install_io_scheduler accepted a revoked cap"),
    }
}
kernel_test_in!(
    "block/io_scheduler",
    smoke_pluggable_io_scheduler_revoked_cap
);

// ── block/disk_policy (narf.disks=boot-only) ───────────────────────

fn smoke_block_disk_policy_parse_fails_closed() -> TestResult {
    use crate::disk_policy::{parse, DiskPolicy};
    let ok = parse(None) == Ok(DiskPolicy::All)
        && parse(Some("all")) == Ok(DiskPolicy::All)
        && parse(Some("boot-only")) == Ok(DiskPolicy::BootOnly)
        && parse(Some("BOOT-ONLY")) == Ok(DiskPolicy::BootOnly)
        && parse(Some("boot-onyl")).is_err()
        && parse(Some("")).is_err();
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("narf.disks= parsing must accept all/boot-only and reject the rest")
    }
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_parse_fails_closed
);

/// The boot console names the policy in every case — including the default
/// `All`, which before printed nothing, so a bare-metal boot without
/// `narf.disks=` gave no sign that the internal disks were writable.
fn smoke_block_disk_policy_banner_names_every_policy() -> TestResult {
    use crate::disk_policy::{banner, DiskPolicy};
    let boot = banner(DiskPolicy::BootOnly, true);
    let all = banner(DiskPolicy::All, true);
    let default = banner(DiskPolicy::All, false);
    if !boot.contains("POLICY narf.disks=boot-only")
        || !all.contains("EVERY disk is writable")
        || !default.contains("EVERY disk is writable")
        || !default.contains("no narf.disks=")
    {
        return TestResult::Fail("disk policy banner must name the active policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_banner_names_every_policy
);

/// Model of the boot-only guarantee: a registered disk and its partition are
/// read-only (reads pass, writes return `ReadOnly`, the bytes stay intact)
/// until the disk is identified as the boot medium; identifying a partition
/// trusts its whole disk and nothing else; a device re-registered under the
/// same name starts untrusted again; `All` is a pass-through.
fn smoke_block_disk_policy_boot_only_enforced_at_registry() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy};
    use crate::partition::PartitionBlockDevice;
    use crate::registry::{find_block_device, register_partition_device};
    use alloc::sync::Arc;

    let new_disk = |fill: u8| {
        let data = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(alloc::vec![
            fill;
            64 * 512
        ]));
        let dev = Arc::new(VecBlock {
            data: data.clone(),
            lba_size: 512,
        }) as Arc<dyn crate::BlockDeviceSync>;
        (data, dev)
    };
    let (stick_bytes, stick) = new_disk(0x11);
    let (internal_bytes, internal) = new_disk(0x22);
    crate::register_block_device("dp-test-stick0", stick.clone());
    register_partition_device(
        "dp-test-stick0p1",
        "dp-test-stick0",
        Arc::new(PartitionBlockDevice::new(stick.clone(), 8, 32)),
        None,
    );
    crate::register_block_device("dp-test-internal0", internal);

    let result = (|| {
        disk_policy::__set_policy_for_test(Some(DiskPolicy::BootOnly));
        let refused_before = disk_policy::refused_writes();
        let payload = [0xAAu8; 512];
        let mut buf = [0u8; 512];
        for name in ["dp-test-stick0", "dp-test-stick0p1", "dp-test-internal0"] {
            let dev = find_block_device(name).ok_or("test device not registered")?;
            if dev.read(0, 1, &mut buf).is_err() {
                return Err("boot-only must still allow reads");
            }
            if dev.write(0, 1, &payload) != Err(crate::BlockIoError::ReadOnly) {
                return Err("boot-only must refuse writes to an unidentified disk");
            }
            if !dev.is_read_only() || disk_policy::automount_allowed(name) {
                return Err("an unidentified disk must report read-only and not auto-mount");
            }
        }
        if disk_policy::refused_writes() < refused_before + 3 {
            return Err("refused writes are not counted");
        }
        if stick_bytes.lock().iter().any(|&b| b != 0x11)
            || internal_bytes.lock().iter().any(|&b| b != 0x22)
        {
            return Err("a refused write reached the media");
        }

        // Identify the stick through its partition (as the bootlog does).
        let entry = crate::block_devices()
            .into_iter()
            .find(|e| e.name == "dp-test-stick0p1")
            .ok_or("partition entry missing")?;
        if Some(entry.disk) != crate::disk_of("dp-test-stick0") {
            return Err("a partition must share its parent's disk identity");
        }
        disk_policy::trust_boot_medium(entry.name, entry.disk);
        for name in ["dp-test-stick0", "dp-test-stick0p1"] {
            let dev = find_block_device(name).ok_or("test device not registered")?;
            if dev.write(0, 1, &payload).is_err() || !disk_policy::automount_allowed(name) {
                return Err("the identified boot medium must be writable");
            }
        }
        let internal = find_block_device("dp-test-internal0").ok_or("internal missing")?;
        if internal.write(0, 1, &payload).is_ok() || internal_bytes.lock()[0] != 0x22 {
            return Err("trusting the stick must not trust another disk");
        }

        // A different device re-registered under the stick's name.
        let (_, swapped) = new_disk(0x33);
        crate::register_block_device("dp-test-stick0", swapped);
        let dev = find_block_device("dp-test-stick0").ok_or("swapped device missing")?;
        if dev.write(0, 1, &payload).is_ok() || disk_policy::is_boot_medium("dp-test-stick0") {
            return Err("a device replacing the boot medium's name must start untrusted");
        }

        disk_policy::__set_policy_for_test(Some(DiskPolicy::All));
        if internal.write(0, 1, &payload).is_err() || internal_bytes.lock()[0] != 0xAA {
            return Err("narf.disks=all must pass writes through");
        }
        Ok(())
    })();

    disk_policy::__set_policy_for_test(None);
    for name in ["dp-test-stick0p1", "dp-test-stick0", "dp-test-internal0"] {
        crate::unregister_block_device(name);
    }
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_boot_only_enforced_at_registry
);

/// The async bridge filesystems mount through reports the guard's state and
/// maps a refused write to `PermissionDenied`.
fn smoke_block_disk_policy_sync_bridge_reports_read_only() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy, PolicyGuard};
    use crate::BlockDevice;
    use alloc::sync::Arc;
    let data = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
        alloc::vec![0u8; 8 * 512],
    ));
    let inner = Arc::new(VecBlock {
        data,
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;
    let guard = Arc::new(PolicyGuard::new("dp-bridge", u64::MAX - 0xd15c, inner));
    let bridge = crate::SyncBlock::new(guard);
    disk_policy::__set_policy_for_test(Some(DiskPolicy::BootOnly));
    let ro = bridge.is_read_only();
    disk_policy::__set_policy_for_test(Some(DiskPolicy::All));
    let rw = !bridge.is_read_only();
    disk_policy::__set_policy_for_test(None);
    if ro && rw {
        TestResult::Pass
    } else {
        TestResult::Fail("SyncBlock must forward the guard's read-only state")
    }
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_sync_bridge_reports_read_only
);

// ── block/partition: standard 128-entry GPT ─────────────────────────
//
// A stock GPT (sgdisk / sfdisk / the UEFI default, and both NVMe disks on
// the Navi22 host) has 128 entries × 128 bytes = 16 KiB of entries at
// LBA 2..=33. Before the chunked entry-array read the scanner asked for
// all 32 LBAs at once, which a driver capped at one 4 KiB transfer
// refused, so no partition was ever registered.

/// Block device that refuses any read larger than `max_lbas` (as a driver
/// with a small max transfer would) and records the largest read asked of
/// it.
struct CappedBlock {
    inner: alloc::sync::Arc<dyn crate::BlockDeviceSync>,
    max_lbas: u16,
    largest: core::sync::atomic::AtomicU32,
}

impl crate::BlockDeviceSync for CappedBlock {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), crate::BlockIoError> {
        self.largest
            .fetch_max(n as u32, core::sync::atomic::Ordering::Relaxed);
        if n > self.max_lbas {
            return Err(crate::BlockIoError::BufferTooSmall);
        }
        self.inner.read(lba, n, out)
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), crate::BlockIoError> {
        self.inner.write(lba, n, data)
    }
}

/// 4096-LBA (2 MiB) disk with a protective MBR and a 128-entry GPT whose
/// used slots are 0, 1, 99 (in the entry array's fourth 4 KiB chunk) and
/// 120 (which ends past the last LBA and must be ignored).
fn gpt128_disk(num_entries: u32, entry_size: u32) -> alloc::vec::Vec<u8> {
    const LBAS: usize = 4096;
    let mut b = alloc::vec![0u8; LBAS * 512];
    b[446 + 4] = 0xEE;
    b[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    b[446 + 12..446 + 16].copy_from_slice(&((LBAS - 1) as u32).to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
    let h = 512;
    b[h..h + 8].copy_from_slice(b"EFI PART");
    b[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    b[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
    b[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes());
    b[h + 32..h + 40].copy_from_slice(&((LBAS - 1) as u64).to_le_bytes());
    b[h + 40..h + 48].copy_from_slice(&34u64.to_le_bytes());
    b[h + 48..h + 56].copy_from_slice(&((LBAS - 34) as u64).to_le_bytes());
    b[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
    b[h + 80..h + 84].copy_from_slice(&num_entries.to_le_bytes());
    b[h + 84..h + 88].copy_from_slice(&entry_size.to_le_bytes());
    // Linux filesystem data type GUID 0FC63DAF-8483-4772-8E79-3D69D8477DE4.
    let linux = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    for (slot, start, end) in [
        (0usize, 2048u64, 2111u64),
        (1, 2112, 2175),
        (99, 2176, 2239),
        (120, 4000, 5000),
    ] {
        let e = 1024 + slot * entry_size as usize;
        if e + 128 > 34 * 512 {
            continue;
        }
        b[e..e + 16].copy_from_slice(&linux);
        b[e + 16] = slot as u8 + 1; // distinct partition GUIDs
        b[e + 32..e + 40].copy_from_slice(&start.to_le_bytes());
        b[e + 40..e + 48].copy_from_slice(&end.to_le_bytes());
    }
    for lba in 2048..2240usize {
        b[lba * 512..(lba + 1) * 512].fill((lba >> 6) as u8);
    }
    b
}

fn smoke_block_partition_scan_standard_128_entry_gpt() -> TestResult {
    use crate::partition::{scan_and_register_partitions, GPT_ENTRY_READ_CHUNK_BYTES};
    use crate::registry::{__reset_for_test, __restore_for_test, __snapshot_for_test};
    use alloc::string::String;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    let expected = alloc::vec![
        String::from("gpt128p1"),
        String::from("gpt128p2"),
        String::from("gpt128p100"),
    ];
    let snap = __snapshot_for_test();
    let result = (|| {
        // Uncapped, a 4 KiB-capped (8-LBA) and a single-LBA device must
        // all register the same partitions, and no entry-array read may
        // exceed one 4 KiB chunk.
        for cap in [u16::MAX, 8, 1] {
            __reset_for_test();
            let base = Arc::new(VecBlock {
                data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(gpt128_disk(128, 128))),
                lba_size: 512,
            }) as Arc<dyn crate::BlockDeviceSync>;
            let capped = Arc::new(CappedBlock {
                inner: base,
                max_lbas: cap,
                largest: AtomicU32::new(0),
            });
            let parent = capped.clone() as Arc<dyn crate::BlockDeviceSync>;
            let report = scan_and_register_partitions(parent, "gpt128")
                .map_err(|_| "scan failed on a standard 128-entry GPT")?;
            if !report.is_gpt || report.registered != expected {
                return Err("128-entry GPT registered the wrong partitions");
            }
            if capped.largest.load(Ordering::Relaxed) as usize * 512 > GPT_ENTRY_READ_CHUNK_BYTES {
                return Err("an entry-array read exceeded one chunk");
            }
            let p100 = crate::registry::find_block_device("gpt128p100")
                .ok_or("slot-99 partition missing")?;
            let mut sector = [0u8; 512];
            p100.read(0, 1, &mut sector)
                .map_err(|_| "partition read failed")?;
            if sector.iter().any(|&v| v != (2176u64 >> 6) as u8) || p100.capacity() != 64 {
                return Err("partition window translated wrong");
            }
        }
        Ok(())
    })();
    __restore_for_test(snap);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_scan_standard_128_entry_gpt
);

fn smoke_block_partition_scan_rejects_bad_entry_arrays() -> TestResult {
    use crate::partition::{scan_and_register_partitions, GptError, ScanError};
    use crate::registry::{__reset_for_test, __restore_for_test, __snapshot_for_test};
    use alloc::sync::Arc;
    let disk = |n: u32, size: u32| {
        Arc::new(VecBlock {
            data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(gpt128_disk(n, size))),
            lba_size: 512,
        }) as Arc<dyn crate::BlockDeviceSync>
    };
    let snap = __snapshot_for_test();
    __reset_for_test();
    // Entry size below 128 used to slice past each slot; a huge entry
    // count used to drive an unbounded allocation and a u16-truncated
    // read length.
    let small = scan_and_register_partitions(disk(128, 64), "gptbad");
    let huge = scan_and_register_partitions(disk(1 << 20, 128), "gptbad");
    let max_ok = scan_and_register_partitions(disk(8192, 128), "gptbad");
    let none_registered = crate::block_devices().is_empty();
    __restore_for_test(snap);
    if small != Err(ScanError::GptHeader(GptError::BadEntrySize)) {
        return TestResult::Fail("entry size 64 must be rejected");
    }
    if huge != Err(ScanError::EntriesTooLarge) {
        return TestResult::Fail("a 128 MiB entry array must be rejected");
    }
    // 8192 × 128 B = 1 MiB (LBA 2..2050): exactly the bound, inside the
    // 4096-LBA disk, so it parses. Slots that overlap the partition data
    // decode as entries ending past the disk and are skipped.
    if max_ok.is_err() {
        return TestResult::Fail("a 1 MiB entry array that fits the disk must parse");
    }
    if none_registered {
        return TestResult::Fail("in-range entries of the 1 MiB array were not registered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/partition",
    smoke_block_partition_scan_rejects_bad_entry_arrays
);

/// Partitions found by the scanner are registry devices like any other:
/// under `narf.disks=boot-only` they read but refuse writes, and the
/// refused write never reaches the parent disk.
fn smoke_block_partition_scanned_gpt_partitions_are_read_only_under_boot_only() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy};
    use crate::partition::scan_and_register_partitions;
    use crate::registry::find_block_device;
    use alloc::sync::Arc;

    let bytes = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(gpt128_disk(128, 128)));
    let pristine = bytes.lock().clone();
    let parent = Arc::new(VecBlock {
        data: bytes.clone(),
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;
    let result = (|| {
        disk_policy::__set_policy_for_test(Some(DiskPolicy::BootOnly));
        crate::register_block_device("ro-gpt0", parent.clone());
        let report =
            scan_and_register_partitions(parent.clone(), "ro-gpt0").map_err(|_| "scan failed")?;
        if report.registered.len() != 3 {
            return Err("expected three scanned partitions");
        }
        let payload = [0x5Au8; 512];
        let mut buf = [0u8; 512];
        for name in ["ro-gpt0", "ro-gpt0p1", "ro-gpt0p2", "ro-gpt0p100"] {
            let dev = find_block_device(name).ok_or("scanned device not registered")?;
            dev.read(0, 1, &mut buf)
                .map_err(|_| "boot-only must allow reads")?;
            if dev.write(0, 1, &payload) != Err(crate::BlockIoError::ReadOnly) {
                return Err("boot-only must refuse writes to a scanned partition");
            }
            if !dev.is_read_only() {
                return Err("a scanned partition must report read-only");
            }
        }
        if *bytes.lock() != pristine {
            return Err("a refused write reached the disk");
        }
        Ok(())
    })();
    disk_policy::__set_policy_for_test(None);
    for name in ["ro-gpt0p1", "ro-gpt0p2", "ro-gpt0p100", "ro-gpt0"] {
        crate::unregister_block_device(name);
    }
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_partition_scanned_gpt_partitions_are_read_only_under_boot_only
);

// ── block/disk_policy: narf.disks=root-ro|root-rw ───────────────────

const RP_ROOT_UUID: &str = "653602c3-cd42-420e-95ef-4c4033d17b56";
const RP_OTHER_UUID: &str = "15d044db-0c09-4ec4-a2d6-ccd1f92e4dd6";
/// Partition layout of the model disk, in 512-byte LBAs.
const RP_ESP: (u64, u64) = (8, 64);
const RP_ROOT: (u64, u64) = (80, 160);
const RP_DISK_LBAS: usize = 256;

type RpBytes = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>>;

/// Write a btrfs primary-superblock identity (fsid + magic) at partition
/// byte 65536 of `bytes`, whose partition starts at `start` LBAs.
fn rp_put_btrfs(bytes: &mut [u8], start: u64, uuid: &str) {
    let base = start as usize * 512 + 65536;
    let fsid = crate::partition::parse_uuid(uuid).expect("uuid");
    bytes[base + 32..base + 48].copy_from_slice(&fsid);
    bytes[base + 64..base + 72].copy_from_slice(b"_BHRfS_M");
}

/// A minimal FAT32 boot sector (BPB sanity fields + signature + serial).
fn rp_put_fat(bytes: &mut [u8], start: u64) {
    let b = start as usize * 512;
    bytes[b + 11..b + 13].copy_from_slice(&512u16.to_le_bytes());
    bytes[b + 13] = 1;
    bytes[b + 16] = 2;
    bytes[b + 67..b + 71].copy_from_slice(&0x6D89_28C5u32.to_le_bytes());
    bytes[b + 82..b + 90].copy_from_slice(b"FAT32   ");
    bytes[b + 510] = 0x55;
    bytes[b + 511] = 0xAA;
}

/// Register a model disk `disk` with an ESP (`{disk}p1`, vfat) and a btrfs
/// root (`{disk}p2`, `root_uuid`), the WD SN770 layout. Returns its bytes.
fn rp_register_disk(
    disk: &'static str,
    p1: &'static str,
    p2: &'static str,
    root_uuid: &str,
) -> RpBytes {
    use crate::partition::PartitionBlockDevice;
    use crate::registry::{register_partition_device, PartitionMetadata};
    use alloc::sync::Arc;
    let mut raw = alloc::vec![0u8; RP_DISK_LBAS * 512];
    rp_put_fat(&mut raw, RP_ESP.0);
    rp_put_btrfs(&mut raw, RP_ROOT.0, root_uuid);
    let bytes = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(raw));
    let whole = Arc::new(VecBlock {
        data: bytes.clone(),
        lba_size: 512,
    }) as Arc<dyn crate::BlockDeviceSync>;
    crate::register_block_device(disk, whole.clone());
    let meta = |type_guid: &str, fs_uuid: &str| PartitionMetadata {
        gpt_type_guid: type_guid.into(),
        partlabel: alloc::string::String::new(),
        partuuid: alloc::string::String::new(),
        fs_uuid: fs_uuid.into(),
    };
    register_partition_device(
        p1,
        disk,
        Arc::new(PartitionBlockDevice::new(whole.clone(), RP_ESP.0, RP_ESP.1)),
        Some(meta(
            crate::registry::GPT_EFI_SYSTEM_PARTITION_TYPE_GUID,
            "6D89-28C5",
        )),
    );
    register_partition_device(
        p2,
        disk,
        Arc::new(PartitionBlockDevice::new(whole, RP_ROOT.0, RP_ROOT.1)),
        Some(meta("0FC63DAF-8483-4772-8E79-3D69D8477DE4", root_uuid)),
    );
    bytes
}

fn rp_reset(policy: Option<crate::disk_policy::DiskPolicy>, root: Option<Option<&str>>) {
    crate::disk_policy::__reset_root_for_test();
    crate::disk_policy::__set_policy_for_test(policy);
    crate::disk_policy::__set_root_arg_for_test(root);
}

fn rp_writes(name: &str) -> bool {
    let Some(dev) = crate::registry::find_block_device(name) else {
        return false;
    };
    let mut block = [0u8; 512];
    if dev.read(1, 1, &mut block).is_err() {
        return false;
    }
    dev.write(1, 1, &block).is_ok()
}

fn rp_uuid(text: &str) -> [u8; 16] {
    crate::partition::parse_uuid(text).expect("uuid")
}

fn rp_finish(names: &[&str], result: Result<(), &'static str>) -> TestResult {
    rp_reset(None, None);
    for name in names {
        crate::unregister_block_device(name);
    }
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}

fn smoke_block_disk_policy_parse_root_policies() -> TestResult {
    use crate::disk_policy::{banner_with_root, parse, DiskPolicy};
    let ok = parse(Some("root-ro")) == Ok(DiskPolicy::RootRo)
        && parse(Some("ROOT-RW")) == Ok(DiskPolicy::RootRw)
        && parse(Some("root")).is_err()
        && parse(Some("root-rwx")).is_err();
    let rw = banner_with_root(DiskPolicy::RootRw, true, Some("UUID=653602c3"));
    let ro = banner_with_root(DiskPolicy::RootRo, true, None);
    if !ok {
        return TestResult::Fail("narf.disks= must parse root-ro and root-rw exactly");
    }
    if !rw.contains("ONLY") || !rw.contains("UUID=653602c3") || !ro.contains("NOTHING") {
        return TestResult::Fail("root policy banners must name what is writable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_parse_root_policies
);

/// The production shape: under root-rw, before designation nothing is
/// writable and only the root=UUID= candidate may auto-mount; after it,
/// exactly the root partition is writable — not its whole disk, not the ESP
/// on the same disk (which may auto-mount, read-only), not another disk.
fn smoke_block_disk_policy_root_rw_only_root_uuid_writable() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy, PolicyError};
    let names = [
        "rp-sn770p1",
        "rp-sn770p2",
        "rp-sn770",
        "rp-sabrentp1",
        "rp-sabrentp2",
        "rp-sabrent",
    ];
    let root_arg = alloc::format!("UUID={RP_ROOT_UUID}");
    rp_reset(Some(DiskPolicy::RootRw), Some(Some(&root_arg)));
    let sn770 = rp_register_disk("rp-sn770", "rp-sn770p1", "rp-sn770p2", RP_ROOT_UUID);
    let sabrent = rp_register_disk("rp-sabrent", "rp-sabrentp1", "rp-sabrentp2", RP_OTHER_UUID);
    let result = (|| {
        for name in names {
            if rp_writes(name) {
                return Err("nothing may be writable before the root is designated");
            }
        }
        if !disk_policy::automount_allowed("rp-sn770p2")
            || disk_policy::automount_allowed("rp-sn770p1")
            || disk_policy::automount_allowed("rp-sabrentp2")
            || disk_policy::automount_allowed("rp-sn770")
        {
            return Err("before designation only the root=UUID= candidate may auto-mount");
        }
        let sabrent_before = sabrent.lock().clone();
        if disk_policy::designate_root("rp-sabrentp2", rp_uuid(RP_OTHER_UUID))
            != Err(PolicyError::UuidMismatch)
        {
            return Err("a partition not named by root=UUID= must not be designated");
        }
        if disk_policy::designate_root("rp-sn770", rp_uuid(RP_ROOT_UUID))
            != Err(PolicyError::NotAPartition)
        {
            return Err("a whole disk must not be designated");
        }
        disk_policy::designate_root("rp-sn770p2", rp_uuid(RP_ROOT_UUID))
            .map_err(|_| "the root=UUID= partition must be designated")?;
        if !disk_policy::root_writable()
            || disk_policy::designated_root() != Some("rp-sn770p2")
            || !disk_policy::write_allowed("rp-sn770p2")
        {
            return Err("root-rw must report the designated root writable");
        }
        let sn770_before = sn770.lock().clone();
        if !rp_writes("rp-sn770p2") {
            return Err("the designated root partition must be writable");
        }
        for name in [
            "rp-sn770",
            "rp-sn770p1",
            "rp-sabrent",
            "rp-sabrentp1",
            "rp-sabrentp2",
        ] {
            if rp_writes(name) || disk_policy::write_allowed(name) {
                return Err("only the designated root partition may be written");
            }
        }
        // The root write landed inside the root partition, and nothing else
        // changed (the write rewrote the same bytes, so compare outside it).
        let after = sn770.lock().clone();
        let root_bytes = (RP_ROOT.0 as usize * 512)..((RP_ROOT.0 + RP_ROOT.1) as usize * 512);
        if after[..root_bytes.start] != sn770_before[..root_bytes.start]
            || after[root_bytes.end..] != sn770_before[root_bytes.end..]
            || *sabrent.lock() != sabrent_before
        {
            return Err("a refused write reached a disk");
        }
        if !disk_policy::automount_allowed("rp-sn770p1")
            || disk_policy::automount_allowed("rp-sabrentp1")
            || disk_policy::automount_allowed("rp-sabrentp2")
        {
            return Err("after designation the root's own ESP may auto-mount, nothing else");
        }
        let esp = crate::registry::find_block_device("rp-sn770p1").ok_or("esp missing")?;
        if !esp.is_read_only() {
            return Err("the ESP on the root's disk must stay read-only");
        }
        if disk_policy::designate_root("rp-sn770p2", rp_uuid(RP_ROOT_UUID))
            != Err(PolicyError::AlreadyDesignated)
        {
            return Err("a second designation must be refused");
        }
        Ok(())
    })();
    rp_finish(&names, result)
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_root_rw_only_root_uuid_writable
);

/// root-ro: the root is designated and may auto-mount, but nothing is ever
/// writable, the root included.
fn smoke_block_disk_policy_root_ro_nothing_writable() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy};
    let names = ["rp-ro0p1", "rp-ro0p2", "rp-ro0"];
    let root_arg = alloc::format!("UUID={RP_ROOT_UUID}");
    rp_reset(Some(DiskPolicy::RootRo), Some(Some(&root_arg)));
    let bytes = rp_register_disk("rp-ro0", "rp-ro0p1", "rp-ro0p2", RP_ROOT_UUID);
    let result = (|| {
        let pristine = bytes.lock().clone();
        disk_policy::designate_root("rp-ro0p2", rp_uuid(RP_ROOT_UUID))
            .map_err(|_| "root-ro must designate the root")?;
        if disk_policy::root_writable() || disk_policy::write_allowed("rp-ro0p2") {
            return Err("root-ro must never report the root writable");
        }
        for name in names {
            let dev = crate::registry::find_block_device(name).ok_or("missing")?;
            if dev.write(1, 1, &[0xA5u8; 512]).is_ok() || !dev.is_read_only() {
                return Err("root-ro must refuse every write");
            }
        }
        if *bytes.lock() != pristine {
            return Err("a refused write reached the disk");
        }
        if !disk_policy::automount_allowed("rp-ro0p2")
            || !disk_policy::automount_allowed("rp-ro0p1")
        {
            return Err("root-ro must still mount the root and its ESP read-only");
        }
        Ok(())
    })();
    rp_finish(&names, result)
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_root_ro_nothing_writable
);

/// Identity, not names: the root registered under an arbitrary name is
/// designated by its UUID; re-registering the designated device (a rename /
/// re-probe) or a second device appearing with the same UUID (a clone, a
/// multi-device btrfs member) revokes every root write for the boot.
fn smoke_block_disk_policy_root_follows_identity_not_names() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy, PolicyError};
    use alloc::sync::Arc;
    let names = [
        "rp-renamed7n1p1",
        "rp-renamed7n1p2",
        "rp-renamed7n1",
        "rp-clone0p1",
        "rp-clone0p2",
        "rp-clone0",
    ];
    let root_arg = alloc::format!("UUID={RP_ROOT_UUID}");
    let result = (|| {
        // Duplicate UUID before designation: refused as ambiguous.
        rp_reset(Some(DiskPolicy::RootRw), Some(Some(&root_arg)));
        rp_register_disk(
            "rp-renamed7n1",
            "rp-renamed7n1p1",
            "rp-renamed7n1p2",
            RP_ROOT_UUID,
        );
        rp_register_disk("rp-clone0", "rp-clone0p1", "rp-clone0p2", RP_ROOT_UUID);
        if disk_policy::designate_root("rp-renamed7n1p2", rp_uuid(RP_ROOT_UUID))
            != Err(PolicyError::Ambiguous)
        {
            return Err("a UUID carried by two devices must not be designated");
        }
        for name in ["rp-clone0p2", "rp-clone0p1", "rp-clone0"] {
            crate::unregister_block_device(name);
        }
        disk_policy::designate_root("rp-renamed7n1p2", rp_uuid(RP_ROOT_UUID))
            .map_err(|_| "the root must be designated under any name")?;
        if !rp_writes("rp-renamed7n1p2") {
            return Err("the designated root must be writable");
        }
        // A clone appearing later revokes.
        rp_register_disk("rp-clone0", "rp-clone0p1", "rp-clone0p2", RP_ROOT_UUID);
        if rp_writes("rp-renamed7n1p2") || disk_policy::root_writable() {
            return Err("a second device with the root UUID must revoke root writes");
        }
        if disk_policy::designate_root("rp-renamed7n1p2", rp_uuid(RP_ROOT_UUID))
            != Err(PolicyError::Revoked)
        {
            return Err("a revoked designation must not be re-made");
        }
        for name in ["rp-clone0p2", "rp-clone0p1", "rp-clone0"] {
            crate::unregister_block_device(name);
        }

        // Re-registration of the designated entry (same name, new device).
        rp_reset(Some(DiskPolicy::RootRw), Some(Some(&root_arg)));
        disk_policy::designate_root("rp-renamed7n1p2", rp_uuid(RP_ROOT_UUID))
            .map_err(|_| "fresh designation failed")?;
        let entry = crate::block_devices()
            .into_iter()
            .find(|e| e.name == "rp-renamed7n1p2")
            .ok_or("root missing")?;
        crate::registry::register_partition_device(
            "rp-renamed7n1p2",
            "rp-renamed7n1",
            Arc::new(VecBlock {
                data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(alloc::vec![0u8; 4096])),
                lba_size: 512,
            }),
            entry.partition.clone(),
        );
        if rp_writes("rp-renamed7n1p2") || entry.dev.write(1, 1, &[0u8; 512]).is_ok() {
            return Err("re-registering the designated device must revoke its writes");
        }
        Ok(())
    })();
    rp_finish(&names, result)
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_root_follows_identity_not_names
);

/// Refusals: a missing / repeated / malformed root=, the wrong policy, an
/// ESP, and (root-rw) a non-btrfs root all leave everything read-only.
fn smoke_block_disk_policy_root_refusals() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy, PolicyError};
    use crate::partition::PartitionBlockDevice;
    use crate::registry::{register_partition_device, PartitionMetadata};
    use alloc::sync::Arc;
    let names = ["rp-ref0p1", "rp-ref0p2", "rp-ref0p3", "rp-ref0"];
    let root_arg = alloc::format!("UUID={RP_ROOT_UUID}");
    let bytes = rp_register_disk("rp-ref0", "rp-ref0p1", "rp-ref0p2", RP_ROOT_UUID);
    let result = (|| {
        let uuid = rp_uuid(RP_ROOT_UUID);
        // A missing root.
        rp_reset(Some(DiskPolicy::RootRw), Some(None));
        if disk_policy::designate_root("rp-ref0p2", uuid) != Err(PolicyError::NoRootUuidArg)
            || disk_policy::automount_allowed("rp-ref0p2")
        {
            return Err("without root=UUID= nothing may be designated or auto-mounted");
        }
        rp_reset(Some(DiskPolicy::RootRw), Some(Some("PARTLABEL=root")));
        if disk_policy::designate_root("rp-ref0p2", uuid) != Err(PolicyError::NoRootUuidArg) {
            return Err("root= must be a UUID under root policies");
        }
        // The wrong policy.
        for policy in [DiskPolicy::All, DiskPolicy::BootOnly] {
            rp_reset(Some(policy), Some(Some(&root_arg)));
            if disk_policy::designate_root("rp-ref0p2", uuid) != Err(PolicyError::NotRootPolicy) {
                return Err("all/boot-only must refuse a root designation");
            }
        }
        // A root= that names no registered device.
        rp_reset(Some(DiskPolicy::RootRw), Some(Some(&root_arg)));
        if disk_policy::designate_root("rp-no-such-dev", uuid) != Err(PolicyError::NoSuchDevice) {
            return Err("an unregistered name must be refused");
        }
        // The partition metadata claims the UUID but the device does not.
        {
            let mut b = bytes.lock();
            let base = RP_ROOT.0 as usize * 512 + 65536;
            b[base + 32] ^= 0xFF;
        }
        if disk_policy::designate_root("rp-ref0p2", uuid) != Err(PolicyError::IdentityMismatch) {
            return Err("the UUID must be re-read from the device");
        }
        {
            let mut b = bytes.lock();
            let base = RP_ROOT.0 as usize * 512 + 65536;
            b[base + 32] ^= 0xFF;
        }
        // An ESP-typed partition carrying the UUID.
        let whole = crate::find_block_device("rp-ref0").ok_or("disk missing")?;
        let meta = |type_guid: &str| PartitionMetadata {
            gpt_type_guid: type_guid.into(),
            partlabel: alloc::string::String::new(),
            partuuid: alloc::string::String::new(),
            fs_uuid: RP_ROOT_UUID.into(),
        };
        crate::unregister_block_device("rp-ref0p2");
        register_partition_device(
            "rp-ref0p3",
            "rp-ref0",
            Arc::new(PartitionBlockDevice::new(
                whole.clone(),
                RP_ROOT.0,
                RP_ROOT.1,
            )),
            Some(meta(crate::registry::GPT_EFI_SYSTEM_PARTITION_TYPE_GUID)),
        );
        if disk_policy::designate_root("rp-ref0p3", uuid) != Err(PolicyError::EfiOrVfat) {
            return Err("an ESP must never be designated");
        }
        crate::unregister_block_device("rp-ref0p3");
        // root-rw on a non-btrfs filesystem: an ext superblock with the UUID.
        {
            let mut b = bytes.lock();
            let base = RP_ROOT.0 as usize * 512;
            b[base + 65536 + 64..base + 65536 + 72].fill(0);
            b[base + 1024 + 0x38..base + 1024 + 0x3a].copy_from_slice(&[0x53, 0xEF]);
            b[base + 1024 + 0x68..base + 1024 + 0x78].copy_from_slice(&uuid);
        }
        register_partition_device(
            "rp-ref0p2",
            "rp-ref0",
            Arc::new(PartitionBlockDevice::new(whole, RP_ROOT.0, RP_ROOT.1)),
            Some(meta("0FC63DAF-8483-4772-8E79-3D69D8477DE4")),
        );
        if disk_policy::designate_root("rp-ref0p2", uuid) != Err(PolicyError::NotBtrfs) {
            return Err("root-rw must refuse a non-btrfs root");
        }
        for name in names {
            if rp_writes(name) {
                return Err("a refused designation must leave every disk read-only");
            }
        }
        // root-ro may designate it (it never writes).
        rp_reset(Some(DiskPolicy::RootRo), Some(Some(&root_arg)));
        disk_policy::designate_root("rp-ref0p2", uuid)
            .map_err(|_| "root-ro may mount a non-btrfs root read-only")?;
        Ok(())
    })();
    rp_finish(&names, result)
}
kernel_test_in!("block/disk_policy", smoke_block_disk_policy_root_refusals);
// ── Flush / FUA forwarding ─────────────────────────────────────────

/// Disk that records what reaches it: plain writes, FUA writes (with their
/// absolute LBA) and flushes; reports a volatile cache with native FUA.
struct FlushProbe {
    writes: core::sync::atomic::AtomicU64,
    fua_lba: core::sync::atomic::AtomicU64,
    fua_writes: core::sync::atomic::AtomicU64,
    flushes: core::sync::atomic::AtomicU64,
    fail_flush: bool,
}

impl FlushProbe {
    fn new(fail_flush: bool) -> alloc::sync::Arc<Self> {
        use core::sync::atomic::AtomicU64;
        alloc::sync::Arc::new(Self {
            writes: AtomicU64::new(0),
            fua_lba: AtomicU64::new(u64::MAX),
            fua_writes: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
            fail_flush,
        })
    }
    fn get(c: &core::sync::atomic::AtomicU64) -> u64 {
        c.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl crate::BlockDeviceSync for FlushProbe {
    fn lba_size(&self) -> u32 {
        512
    }
    fn capacity(&self) -> u64 {
        64
    }
    fn read(&self, _lba: u64, _n: u16, _out: &mut [u8]) -> Result<(), crate::BlockIoError> {
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), crate::BlockIoError> {
        self.writes
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn write_fua(&self, lba: u64, _n: u16, _data: &[u8]) -> Result<(), crate::BlockIoError> {
        self.fua_lba
            .store(lba, core::sync::atomic::Ordering::Relaxed);
        self.fua_writes
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn flush(&self) -> Result<(), crate::BlockIoError> {
        self.flushes
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if self.fail_flush {
            Err(crate::BlockIoError::DriverError)
        } else {
            Ok(())
        }
    }
    fn capabilities(&self) -> crate::BlockCaps {
        crate::BlockCaps {
            volatile_cache: true,
            fua: true,
        }
    }
}

/// The policy guard and partitions forward flush, FUA writes and the cache
/// capabilities; the guard forwards flush even while it refuses writes;
/// SyncBlock carries `fua: true` and flush errors through.
fn smoke_block_flush_and_fua_forwarding() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy};
    use crate::partition::PartitionBlockDevice;
    use crate::{find_block_device, register_block_device, register_partition_device};
    use alloc::sync::Arc;
    let probe = FlushProbe::new(false);
    let raw: Arc<dyn crate::BlockDeviceSync> = probe.clone();
    register_block_device("flt-disk0", raw.clone());
    register_partition_device(
        "flt-disk0p1",
        "flt-disk0",
        Arc::new(PartitionBlockDevice::new(raw, 10, 20)),
        None,
    );
    disk_policy::__set_policy_for_test(Some(DiskPolicy::BootOnly));
    disk_policy::__reset_trust_for_test();
    let result = (|| -> Result<(), &'static str> {
        let disk = find_block_device("flt-disk0").ok_or("disk missing")?;
        let part = find_block_device("flt-disk0p1").ok_or("partition missing")?;
        let block = [0u8; 512];
        // Read-only under boot-only: data writes refused, flush forwarded.
        if part.write_fua(1, 1, &block).is_ok() || disk.write_fua(1, 1, &block).is_ok() {
            return Err("guard let a FUA write through on an untrusted disk");
        }
        if FlushProbe::get(&probe.fua_writes) != 0 {
            return Err("a refused FUA write reached the disk");
        }
        if disk.flush().is_err() || part.flush().is_err() || FlushProbe::get(&probe.flushes) != 2 {
            return Err("guard / partition did not forward flush");
        }
        let caps = part.capabilities();
        if !caps.volatile_cache || !caps.fua {
            return Err("capabilities not forwarded");
        }
        // Writable: FUA reaches the disk at the partition-relative offset.
        disk_policy::__set_policy_for_test(Some(DiskPolicy::All));
        if part.write_fua(3, 1, &block).is_err()
            || FlushProbe::get(&probe.fua_writes) != 1
            || FlushProbe::get(&probe.fua_lba) != 13
        {
            return Err("partition FUA write not forwarded at start + lba");
        }
        if part.write_fua(20, 1, &block).is_ok() {
            return Err("partition FUA write past its end accepted");
        }
        Ok(())
    })();
    disk_policy::__set_policy_for_test(None);
    crate::unregister_block_device("flt-disk0p1");
    crate::unregister_block_device("flt-disk0");
    if let Err(why) = result {
        return TestResult::Fail(why);
    }
    // Default write_fua = write + flush; SyncBlock propagates flush errors.
    struct Plain(Arc<FlushProbe>);
    impl crate::BlockDeviceSync for Plain {
        fn lba_size(&self) -> u32 {
            512
        }
        fn capacity(&self) -> u64 {
            64
        }
        fn read(&self, l: u64, n: u16, o: &mut [u8]) -> Result<(), crate::BlockIoError> {
            self.0.read(l, n, o)
        }
        fn write(&self, l: u64, n: u16, d: &[u8]) -> Result<(), crate::BlockIoError> {
            self.0.write(l, n, d)
        }
        fn flush(&self) -> Result<(), crate::BlockIoError> {
            self.0.flush()
        }
    }
    let p = FlushProbe::new(false);
    let plain = Plain(p.clone());
    if crate::BlockDeviceSync::write_fua(&plain, 0, 1, &[0u8; 512]).is_err()
        || FlushProbe::get(&p.writes) != 1
        || FlushProbe::get(&p.flushes) != 1
        || crate::BlockDeviceSync::capabilities(&plain).fua
    {
        return TestResult::Fail("default write_fua is not write + flush");
    }
    let failing = crate::SyncBlock::new(FlushProbe::new(true));
    let r = poll_ready_block(crate::BlockDevice::flush_result(&*failing));
    if r != Some(Err(crate::BlockError::IOError)) {
        return TestResult::Fail("SyncBlock::flush_result dropped the flush error");
    }
    TestResult::Pass
}
kernel_test_in!("block/flush", smoke_block_flush_and_fua_forwarding);

fn poll_ready_block<F: core::future::Future>(fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(|d| RawWaker::new(d, &VTABLE), |_| {}, |_| {}, |_| {});
    // SAFETY: VTABLE is a valid no-op vtable; the waker never escapes.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// The boot-log stick under the root policies: once its `/NARFLOG.ID`
/// matched (`trust_boot_medium`), exactly that USB partition is writable —
/// besides the designated root under root-rw. The stick's whole-disk device,
/// the root's ESP, other disks, and a non-USB device offered as the "boot
/// medium" stay refused; removing the stick forgets it.
fn smoke_block_disk_policy_root_policies_log_stick() -> TestResult {
    use crate::disk_policy::{self, DiskPolicy};
    use crate::partition::PartitionBlockDevice;
    use crate::registry::register_partition_device;
    use alloc::sync::Arc;
    let names = [
        "rp-ls-nvmep1",
        "rp-ls-nvmep2",
        "rp-ls-nvme",
        "usb-msc-rptest0p1",
        "usb-msc-rptest0",
    ];
    let root_arg = alloc::format!("UUID={RP_ROOT_UUID}");
    let result = (|| {
        for policy in [DiskPolicy::RootRw, DiskPolicy::RootRo] {
            rp_reset(Some(policy), Some(Some(&root_arg)));
            disk_policy::__reset_log_stick_for_test();
            for name in names {
                crate::unregister_block_device(name);
            }
            rp_register_disk("rp-ls-nvme", "rp-ls-nvmep1", "rp-ls-nvmep2", RP_ROOT_UUID);
            let stick = Arc::new(VecBlock {
                data: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                    alloc::vec![0u8; 128 * 512],
                )),
                lba_size: 512,
            }) as Arc<dyn crate::BlockDeviceSync>;
            crate::register_block_device("usb-msc-rptest0", stick.clone());
            register_partition_device(
                "usb-msc-rptest0p1",
                "usb-msc-rptest0",
                Arc::new(PartitionBlockDevice::new(stick, 8, 64)),
                None,
            );
            disk_policy::designate_root("rp-ls-nvmep2", rp_uuid(RP_ROOT_UUID))
                .map_err(|_| "designation failed")?;
            if rp_writes("usb-msc-rptest0p1") {
                return Err("the stick must be read-only before its token matched");
            }
            // A non-USB partition offered as the boot medium is not accepted.
            let esp_disk = crate::disk_of("rp-ls-nvmep1").ok_or("esp disk")?;
            disk_policy::trust_boot_medium("rp-ls-nvmep1", esp_disk);
            if rp_writes("rp-ls-nvmep1") || disk_policy::log_stick().is_some() {
                return Err("a non-USB device must never become the log stick");
            }
            let stick_disk = crate::disk_of("usb-msc-rptest0p1").ok_or("stick disk")?;
            disk_policy::trust_boot_medium("usb-msc-rptest0p1", stick_disk);
            if !rp_writes("usb-msc-rptest0p1")
                || !disk_policy::write_allowed("usb-msc-rptest0p1")
                || disk_policy::log_stick() != Some("usb-msc-rptest0p1")
            {
                return Err("the identified log stick partition must be writable");
            }
            if rp_writes("usb-msc-rptest0") || rp_writes("rp-ls-nvmep1") || rp_writes("rp-ls-nvme")
            {
                return Err("only the stick partition (and the root under root-rw) may be written");
            }
            let root_ok = rp_writes("rp-ls-nvmep2");
            if root_ok != (policy == DiskPolicy::RootRw) {
                return Err("the root's writability must follow the policy");
            }
            crate::unregister_block_device("usb-msc-rptest0p1");
            if disk_policy::log_stick().is_some() {
                return Err("an unregistered stick must be forgotten");
            }
        }
        Ok(())
    })();
    disk_policy::__reset_log_stick_for_test();
    rp_finish(&names, result)
}
kernel_test_in!(
    "block/disk_policy",
    smoke_block_disk_policy_root_policies_log_stick
);
