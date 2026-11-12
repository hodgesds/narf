//! CID-matched completion tracking smokes (#1619): a fake controller
//! wired to RAM (BAR = coherent page, after `tests_dsm`) with
//! pre-posted CQEs, driving the REAL `submit_raw_ms` loop — no QEMU
//! NVMe device needed, so these run on every arch.
//!
//! Fixture discipline: the CQE bytes are laid out from the NVMe base
//! spec itself (§4.6: 16-byte entry, `cid` at bytes 12..13, phase
//! tag in `status` bit 0) and the AER event word from §5.2 — never
//! from the driver's own constants. The `cmd_specific` words are
//! pure test sentinels, asserted by round-trip equality only, never
//! by decoded meaning; the AER error status is likewise a stand-in
//! nonzero status (the matcher keys on CID + phase, never on the
//! status value, so no specific status code is asserted here).

use narf_bus::{BarKind, MmioRegion};
use narf_io::alloc_coherent;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use super::admin::{CNS_CONTROLLER, OPC_IDENTIFY};
use super::mq::{Cmd, CmdOutcome, CmdResources, IoQueue};
use super::{Controller, Cqe, IoOpcode, Queue, Sqe};

/// Queue depth of the fake controller: the admin depth, so the AER
/// tables (sized `ADMIN_Q_DEPTH - 1`) are exercised at their real
/// bound — including across the #1647 raise to 8.
const CID_FAKE_DEPTH: u16 = super::ADMIN_Q_DEPTH;

/// Sentinel `cmd_specific` for the awaited completion: the issue
/// number, so a failure message names what was expected.
const OWN_SENTINEL: u32 = 0xC1D0_1619;
/// Sentinel `cmd_specific` for the stray AER event word.
const AER_EVENT: u32 = 0x5A5A_0002;
/// Sentinel `cmd_specific` for the stray I/O completion.
const IO_STRAY_SENTINEL: u32 = 0x5A5A_1619;
/// AER error completion status: phase tag 1 + nonzero NVMe status.
/// (See the module docs: the exact status code is a stand-in.)
const AER_ERR_STATUS: u16 = 1 | (0x02 << 1);

/// A `Controller` wired to RAM: the BAR is a 2-page coherent buffer
/// (doorbell offsets at 0x1000+ land in the second page) and the
/// admin + first I/O queue SQ/CQ pages are coherent pages the test
/// pre-posts CQEs into. Nothing here executes on hardware: the
/// doorbell writes land in RAM and the completions are pre-posted,
/// so `submit_raw_ms`'s wait returns from the staged entries.
/// The SQ/CQ pages are owned by `ctrl` (inside the `Queue`s); the
/// struct keeps alive only what `ctrl` does not own — the BAR
/// mapping's backing page and the identify page.
pub(super) struct FakeCidCtrl {
    pub(super) ctrl: Controller,
    /// Keeps the fake BAR mapping alive for `ctrl`'s lifetime.
    _bar: narf_io::DmaBuffer,
    /// Keeps the identify page alive (PRP1 for the admin test).
    _id_page: narf_io::DmaBuffer,
    /// CQ pages, for pre-posting completions.
    cq_admin: *const u8,
    pub(super) cq_io: *const u8,
    /// DMA address of the identify page (PRP1 for the admin test).
    pub(super) id_dma: u64,
}

fn fake_cid_controller() -> Option<FakeCidCtrl> {
    fake_cid_controller_with(None)
}

/// [`fake_cid_controller`] whose I/O queue is IRQ-driven on `vector`.
pub(super) fn fake_cid_controller_with(vector: Option<u8>) -> Option<FakeCidCtrl> {
    let sq_admin = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let cq_admin = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let sq_io = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let cq_io = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let bar = alloc_coherent(8192, DomainId::DRIVER_0).ok()?;
    let id_page = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let cq_admin_ptr = cq_admin.cpu_ptr::<u8>();
    let cq_io_ptr = cq_io.cpu_ptr::<u8>();
    let id_dma = id_page.dma_addr().raw();

    // Zero both CQ pages so unstaged slots read as stale entries
    // (phase bit 0 != cq_phase 1) however the allocator hands the
    // pages back; only the CQEs a test stages may complete.
    // SAFETY: both are live 4 KiB coherent pages.
    unsafe {
        core::ptr::write_bytes(cq_admin_ptr as *mut u8, 0, 4096);
        core::ptr::write_bytes(cq_io_ptr as *mut u8, 0, 4096);
    }

    let mut ctrl = Controller::new(0);
    // SAFETY: the fake BAR is a live 8 KiB coherent page; doorbell
    // offsets (0x1000+) land inside it. Mirrors `tests_dsm`.
    let bar_region = MmioRegion {
        phys: narf_memory::PhysAddr::new(bar.dma_addr().raw()),
        virt: bar.cpu_ptr::<u8>() as u64,
        len: bar.len() as u64,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    ctrl.bar0_region = Some(bar_region);
    ctrl.admin = Some(Queue {
        sq_buf: sq_admin,
        cq_buf: cq_admin,
        qid: 0,
        depth: CID_FAKE_DEPTH,
        sq_tail: 0,
        cq_head: 0,
        cq_phase: 1,
        db_stride: 4,
        next_cid: 0,
        stray_aer: [0; (super::ADMIN_Q_DEPTH - 1) as usize],
        stray_aer_len: 0,
        aer_cids: [0; (super::ADMIN_Q_DEPTH - 1) as usize],
        aer_cids_len: 0,
    });
    ctrl.io_queues.push(IoQueue::new(
        1,
        CID_FAKE_DEPTH,
        sq_io,
        cq_io,
        bar_region,
        4,
        vector,
    ));
    if let Some(v) = vector {
        ctrl.io_irq_vectors.push(v);
    }

    Some(FakeCidCtrl {
        ctrl,
        _bar: bar,
        _id_page: id_page,
        cq_admin: cq_admin_ptr,
        cq_io: cq_io_ptr,
        id_dma,
    })
}

fn smoke_nvme_cid_stray_aer_no_poison() -> TestResult {
    // A stray AER error completion at the admin CQ head must not
    // poison the admin submit waiting behind it: `submit_raw_ms`
    // has to skip the AER CQE (stash its event word for
    // `drain_aer`) and return the IDENTIFY completion carrying its
    // own CID. Before CID matching, the AER CQE was consumed as
    // the IDENTIFY completion — spurious success, and the identify
    // page parsed before the controller wrote it.
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;

    // Post 1 AER (CID 0). On real hardware any AER can complete
    // with an error status at any time — QEMU completes an AER
    // past its accepted 3 with an error — so the staged CQE below
    // models that stray AER error completion (NVMe §5.2).
    if ctrl.post_aer_commands(1).is_err() {
        return TestResult::Fail("post_aer_commands failed");
    }
    if ctrl.aer_outstanding() != 1 {
        return TestResult::Fail("aer_outstanding != 1 after post");
    }

    // Pre-post the admin CQ: slot 0 = the stray AER error
    // completion (CID 0, the posted AER), slot 1 = our IDENTIFY
    // completion (CID 1 — the CID `submit_raw` assigns next).
    // CQE layout per base spec §4.6.
    // SAFETY: `cq_admin` is a live 4 KiB coherent page; two
    // 16-byte CQEs at slots 0..1.
    unsafe {
        core::ptr::write_volatile(
            fake.cq_admin.add(0) as *mut Cqe,
            Cqe {
                cmd_specific: AER_EVENT,
                _resv: 0,
                sq_head: 0,
                sq_id: 0,
                cid: 0,
                status: AER_ERR_STATUS,
            },
        );
        core::ptr::write_volatile(
            fake.cq_admin.add(16) as *mut Cqe,
            Cqe {
                cmd_specific: OWN_SENTINEL,
                _resv: 0,
                sq_head: 1,
                sq_id: 0,
                cid: 1,
                status: 1,
            },
        );
    }

    // IDENTIFY CONTROLLER into the fake identify page.
    // `submit_raw` auto-assigns CID 1.
    let mut sqe = Sqe::zero();
    sqe.cdw0 = OPC_IDENTIFY as u32;
    sqe.nsid = 0;
    sqe.prp1 = fake.id_dma;
    sqe.cdw10 = CNS_CONTROLLER as u32;
    let cqe = {
        let Some(admin) = ctrl.admin.as_mut() else {
            return TestResult::Fail("fake controller has no admin queue");
        };
        let Some(bar0) = ctrl.bar0_region.as_ref() else {
            return TestResult::Fail("fake controller has no BAR0");
        };
        // SAFETY: fake admin queue + RAM-backed BAR; the staged
        // CQEs complete the wait synchronously.
        match unsafe { admin.submit_raw(bar0, sqe) } {
            Ok(c) => c,
            Err(_) => {
                return TestResult::Fail("submit_raw failed with stray AER ahead");
            }
        }
    };
    if cqe.cmd_specific != OWN_SENTINEL {
        return TestResult::Fail("admin submit consumed the stray AER CQE (poisoned)");
    }
    if cqe.cid != 1 {
        return TestResult::Fail("returned CQE does not carry our CID");
    }
    if ctrl.stray_aer_len() != 1 {
        return TestResult::Fail("stray AER event was not stashed");
    }
    if ctrl.aer_outstanding() != 0 {
        return TestResult::Fail("stray AER CID still tracked after stash");
    }

    // Drain the stash: decodes the event and reposts one AER.
    if ctrl.drain_aer() != 1 {
        return TestResult::Fail("drain_aer did not drain the stashed event");
    }
    if ctrl.aer_outstanding() != 1 {
        return TestResult::Fail("drain_aer did not repost the AER");
    }
    if ctrl.stray_aer_len() != 0 {
        return TestResult::Fail("stash not empty after drain");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cid_stray_aer_no_poison);

fn smoke_nvme_cid_io_stray_dropped() -> TestResult {
    // The same matcher on an I/O queue: a stray completion at the
    // head (another submitter's late CQE — only reachable once
    // submissions share a queue) must be consumed and dropped, and
    // `submit_raw` must return OUR CQE. I/O strays are never
    // stashed: no AERs live on I/O queues, so the admin stash
    // must stay empty.
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;

    // Pre-post the I/O CQ: slot 0 = stray (CID 9, never assigned),
    // slot 1 = our completion (CID 0 — the CID `submit_raw`
    // assigns next on this fresh queue).
    // SAFETY: `cq_io` is a live 4 KiB coherent page; two 16-byte
    // CQEs at slots 0..1.
    unsafe {
        core::ptr::write_volatile(
            fake.cq_io.add(0) as *mut Cqe,
            Cqe {
                cmd_specific: IO_STRAY_SENTINEL,
                _resv: 0,
                sq_head: 0,
                sq_id: 1,
                cid: 9,
                status: 1,
            },
        );
        core::ptr::write_volatile(
            fake.cq_io.add(16) as *mut Cqe,
            Cqe {
                cmd_specific: OWN_SENTINEL,
                _resv: 0,
                sq_head: 1,
                sq_id: 1,
                cid: 0,
                status: 1,
            },
        );
    }

    // NVM Read, 1 block at LBA 0, into the identify page (nothing
    // DMAs it — the completions are staged, so no transfer runs).
    let mut sqe = Sqe::zero();
    sqe.cdw0 = IoOpcode::Read as u32;
    sqe.nsid = 1;
    sqe.prp1 = fake.id_dma;
    sqe.cdw10 = 0;
    sqe.cdw11 = 0;
    sqe.cdw12 = 0;
    let strays0 = super::stray_cqe_drops();
    match io_submit(ctrl, sqe) {
        CmdOutcome::Completed {
            status: 0,
            cmd_specific,
            ..
        } if cmd_specific == OWN_SENTINEL => {}
        CmdOutcome::Completed { .. } => {
            return TestResult::Fail("I/O submit consumed the stray CQE (poisoned)");
        }
        _ => return TestResult::Fail("I/O submit failed with stray ahead"),
    }
    if super::stray_cqe_drops() != strays0 + 1 {
        return TestResult::Fail("the stray was not counted");
    }
    if ctrl.stray_aer_len() != 0 {
        return TestResult::Fail("I/O stray was stashed as an AER event");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cid_io_stray_dropped);

/// One CQ slot as the two little-endian qwords of base spec §4.6:
/// qword 0 = DW0 (command specific) + DW1 (reserved), qword 1 = SQ head
/// (bytes 8..9), SQ id (10..11, here 1), CID (12..13), status + phase tag
/// (14..15).
fn cqe_words(cmd_specific: u32, sq_head: u16, cid: u16, status: u16) -> [u64; 2] {
    [
        cmd_specific as u64,
        sq_head as u64 | (1 << 16) | ((cid as u64) << 32) | ((status as u64) << 48),
    ]
}

fn smoke_nvme_cqe_sample_never_mixes_occupants() -> TestResult {
    // A slot of a wrapped CQ still holds its previous occupant — an older
    // command's CID under the old phase tag — when the controller posts the
    // awaited completion into it, and the host may be reading the slot at
    // that moment. Model the controller posting the WHOLE new entry after
    // each possible number of host loads. Whatever the interleaving, a
    // sample whose phase tag is fresh must be the new entry in full: with
    // the old occupant's CID under the fresh tag the waiter drops its own
    // completion as a stray and times out on a command that completed.
    const OLD_CID: u16 = 0x52BC;
    const NEW_CID: u16 = 0x52C0;
    const OLD_RESULT: u32 = 0x0BAD_0BAD;
    let old = cqe_words(OLD_RESULT, 1, OLD_CID, 0); // stale phase tag 0
    let new = cqe_words(OWN_SENTINEL, 1, NEW_CID, 1); // fresh phase tag 1

    for post_after in 0..=2usize {
        let slot = core::cell::Cell::new(old);
        let loads = core::cell::Cell::new(0usize);
        let cqe = Cqe::sample(|word| {
            if loads.get() == post_after {
                slot.set(new);
            }
            loads.set(loads.get() + 1);
            slot.get()[word]
        });
        if loads.get() != 2 {
            return TestResult::Fail("a CQE sample is not exactly two qword loads");
        }
        if cqe.status & 1 != 1 {
            // Not a completion yet: the waiter polls again.
            if post_after == 0 {
                return TestResult::Fail("an entry posted before the sample read as stale");
            }
            continue;
        }
        if cqe.cid != NEW_CID {
            return TestResult::Fail("fresh phase tag sampled with the previous occupant's CID");
        }
        if cqe.cmd_specific != OWN_SENTINEL || cqe.sq_head != 1 || cqe.sq_id != 1 {
            return TestResult::Fail("fresh phase tag sampled with stale result fields");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cqe_sample_never_mixes_occupants);

fn smoke_nvme_peek_cqe_decodes_spec_layout() -> TestResult {
    // `peek_cqe` over real memory: bytes laid out from base spec §4.6 must
    // decode to the same fields, at a non-zero slot index.
    let Ok(page) = alloc_coherent(4096, DomainId::DRIVER_0) else {
        return TestResult::Fail("alloc_coherent failed");
    };
    let bytes: [u8; 16] = [
        0x19, 0x16, 0xD0, 0xC1, // DW0: command specific
        0, 0, 0, 0, // DW1: reserved
        0x03, 0x00, // SQ head pointer
        0x01, 0x00, // SQ identifier
        0xC0, 0x52, // command identifier
        0x05, 0x00, // phase tag 1 + status field 2
    ];
    // SAFETY: slot 2 (bytes 32..48) of a live 4 KiB coherent page.
    let cqe = unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cpu_mut_ptr::<u8>().add(32), 16);
        super::peek_cqe(&page, 2)
    };
    if cqe.cmd_specific != OWN_SENTINEL
        || cqe.sq_head != 3
        || cqe.sq_id != 1
        || cqe.cid != 0x52C0
        || cqe.status != 5
    {
        return TestResult::Fail("peek_cqe decoded a field from the wrong bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_peek_cqe_decodes_spec_layout);

/// Stage one CQE (base spec §4.6 layout, phase tag 1, status 0) into slot
/// `slot` of a fake CQ page.
///
/// # Safety
/// `cq` is a live 4 KiB coherent page and `slot` is inside it.
pub(super) unsafe fn stage_cqe(
    cq: *const u8,
    slot: usize,
    cid: u16,
    sq_id: u16,
    cmd_specific: u32,
) {
    // SAFETY: per this function's contract.
    unsafe {
        core::ptr::write_volatile(
            cq.add(slot * 16) as *mut Cqe,
            Cqe {
                cmd_specific,
                _resv: 0,
                sq_head: 0,
                sq_id,
                cid,
                status: 1,
            },
        );
    }
}

/// Post `sqe` on the fake controller's I/O queue (tags rotate from 0) and
/// wait for its outcome the way the gate-held paths do.
fn io_submit(ctrl: &Controller, sqe: Sqe) -> CmdOutcome {
    let q = ctrl.io_queues()[0].clone();
    let Some(tag) = q.try_alloc_tag(None) else {
        return CmdOutcome::TimedOut;
    };
    let Ok(id) = q.post(tag, sqe, CmdResources::default()) else {
        return CmdOutcome::Reset;
    };
    Cmd::new(q, id).wait_sync()
}

fn smoke_nvme_stray_drop_is_counted() -> TestResult {
    // A stray completion is never dropped silently: both matchers — the
    // polled `submit_raw_ms` loop and the IRQ path's `try_take_io_cqe` —
    // count it (and report the 1st, 10th, 100th ...), while a stray AER on
    // the admin queue, which is stashed rather than dropped, is not counted.
    use super::log_due_decade;
    for (n, due) in [
        (1u64, true),
        (2, false),
        (9, false),
        (10, true),
        (11, false),
        (99, false),
        (100, true),
        (101, false),
        (1000, true),
        (u64::MAX, false),
    ] {
        if log_due_decade(n) != due {
            return TestResult::Fail("stray log rate limit is not 1st/10th/100th");
        }
    }
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;

    // Polled matcher: stray (CID 9) ahead of ours (CID 0).
    // SAFETY: `cq_io` is a live 4 KiB coherent page; slots 0..1.
    unsafe {
        stage_cqe(fake.cq_io, 0, 9, 1, IO_STRAY_SENTINEL);
        stage_cqe(fake.cq_io, 1, 0, 1, OWN_SENTINEL);
    }
    let mut sqe = Sqe::zero();
    sqe.cdw0 = IoOpcode::Read as u32;
    sqe.nsid = 1;
    sqe.prp1 = fake.id_dma;
    let before = super::stray_cqe_drops();
    if !matches!(
        io_submit(ctrl, sqe),
        CmdOutcome::Completed { status: 0, .. }
    ) {
        return TestResult::Fail("polled submit failed with a stray ahead");
    }
    if super::stray_cqe_drops() != before + 1 {
        return TestResult::Fail("polled matcher did not count the dropped stray");
    }

    // Completion reaper (the ISR's and every waiter's path): a stray
    // (CID 0x77) at the head with no command under that tag is consumed,
    // counted, and reported as nobody's.
    // SAFETY: slot 2 of the same page.
    unsafe { stage_cqe(fake.cq_io, 2, 0x77, 1, IO_STRAY_SENTINEL) };
    let q = ctrl.io_queues()[0].clone();
    if !q.cq_has_fresh() || q.process_cq(false) != 1 {
        return TestResult::Fail("the reaper did not consume the stray");
    }
    if super::stray_cqe_drops() != before + 2 {
        return TestResult::Fail("the reaper did not count the dropped stray");
    }
    if q.cq_has_fresh() {
        return TestResult::Fail("the stray was not consumed from the CQ");
    }

    // Admin queue: an outstanding AER's completion ahead of ours is
    // stashed, not dropped — it must not count as a stray.
    if ctrl.post_aer_commands(1).is_err() {
        return TestResult::Fail("post_aer_commands failed");
    }
    // SAFETY: `cq_admin` is a live 4 KiB coherent page; slots 0..1.
    unsafe {
        stage_cqe(fake.cq_admin, 0, 0, 0, AER_EVENT);
        stage_cqe(fake.cq_admin, 1, 1, 0, OWN_SENTINEL);
    }
    let mut sqe = Sqe::zero();
    sqe.cdw0 = OPC_IDENTIFY as u32;
    sqe.prp1 = fake.id_dma;
    sqe.cdw10 = CNS_CONTROLLER as u32;
    {
        let (Some(admin), Some(bar0)) = (ctrl.admin.as_mut(), ctrl.bar0_region.as_ref()) else {
            return TestResult::Fail("fake controller has no admin queue / BAR0");
        };
        // SAFETY: fake admin queue + RAM-backed BAR; staged CQEs.
        if unsafe { admin.submit_raw(bar0, sqe) }.is_err() {
            return TestResult::Fail("admin submit failed with a stray AER ahead");
        }
    }
    if super::stray_cqe_drops() != before + 2 {
        return TestResult::Fail("a stashed AER completion was counted as a dropped stray");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_stray_drop_is_counted);

fn smoke_nvme_timeout_is_counted() -> TestResult {
    // A command whose completion never arrives is reported where the
    // timeout is declared (opcode, CID, queue, CQ head, CSTS, vector,
    // interrupt state, elapsed) and counted. Nothing is staged, so the
    // real wait runs out its (short) budget against a silent CQ. The
    // command stays in flight at the queue — its pages are the device's
    // until a reset — and the controller is marked dead.
    let _budget = ShortIoBudget::set(20);
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;
    let mut sqe = Sqe::zero();
    sqe.cdw0 = IoOpcode::Read as u32;
    sqe.nsid = 1;
    sqe.prp1 = fake.id_dma;
    let before = super::command_timeouts();
    let r = ctrl.submit_io_sync(sqe, CmdResources::default());
    if !matches!(r, Err(super::NvmeError::CompletionTimeout)) {
        return TestResult::Fail("a silent CQ did not time the command out");
    }
    if super::command_timeouts() != before + 1 {
        return TestResult::Fail("the timeout was not counted exactly once");
    }
    if !ctrl.is_dead() {
        return TestResult::Fail("a timeout did not mark the controller dead");
    }
    let q = ctrl.io_queues()[0].clone();
    if q.in_flight() != 1 || q.cq_has_fresh() {
        return TestResult::Fail("a timed-out command was released, or a CQ entry consumed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_timeout_is_counted);

fn smoke_nvme_polled_last_look_finds_completion() -> TestResult {
    // The owner looks at the CQ once more after its budget is spent, and
    // that look walks past a stray: with the wait made blind (the
    // late-completion hook) and the CQ holding a stray followed by our
    // completion, the command must still succeed — counted as a late
    // completion, not as a timeout — and the stray must be counted.
    let _budget = ShortIoBudget::set(20);
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;
    // SAFETY: `cq_io` is a live 4 KiB coherent page; slots 0..1.
    unsafe {
        stage_cqe(fake.cq_io, 0, 9, 1, IO_STRAY_SENTINEL);
        stage_cqe(fake.cq_io, 1, 0, 1, OWN_SENTINEL);
    }
    let mut sqe = Sqe::zero();
    sqe.cdw0 = IoOpcode::Read as u32;
    sqe.nsid = 1;
    sqe.prp1 = fake.id_dma;
    let (late0, timeouts0, strays0) = (
        super::late_completions(),
        super::command_timeouts(),
        super::stray_cqe_drops(),
    );
    super::IO_LATE_FOR_TEST.store(1, core::sync::atomic::Ordering::Release);
    let r = ctrl.submit_io_sync(sqe, CmdResources::default());
    let taken = super::IO_LATE_FOR_TEST.swap(0, core::sync::atomic::Ordering::AcqRel) == 0;
    if !taken {
        return TestResult::Fail("the submit never took the fault: nothing was tested");
    }
    match r {
        Ok(dw0) if dw0 == OWN_SENTINEL => {}
        Ok(_) => return TestResult::Fail("the last look returned the wrong completion"),
        Err(_) => return TestResult::Fail("a completion sitting in the CQ was declared lost"),
    }
    if super::late_completions() != late0 + 1 || super::command_timeouts() != timeouts0 {
        return TestResult::Fail("late completion not counted, or counted as a timeout");
    }
    if super::stray_cqe_drops() != strays0 + 1 {
        return TestResult::Fail("the stray ahead of the late completion was not counted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_polled_last_look_finds_completion);

// ── Async path (`submit_io_begin` / `submit_io_poll` / `submit_io_irq_async`) ──
//
// Driven against the RAM-backed controller: the "device" is whatever the
// test stages into the CQ, and the queue's interrupt is whatever the test
// feeds to `narf_interrupts::on_irq` — so a wake that is not the command's
// completion, a completion with no interrupt, and a completion that never
// comes are each exact, not a matter of timing.

/// A [`fake_cid_controller`] whose I/O queue is IRQ-driven on a freshly
/// allocated vector and whose primary namespace accepts one-block I/O.
/// The vector is released when the fixture drops.
struct FakeAsyncCtrl {
    fake: FakeCidCtrl,
    vector: u8,
}

impl Drop for FakeAsyncCtrl {
    fn drop(&mut self) {
        let _ = narf_interrupts::vector::free(self.vector);
    }
}

fn fake_async_controller() -> Option<FakeAsyncCtrl> {
    let vector = narf_interrupts::vector::alloc().ok()?;
    let mut fake = fake_cid_controller_with(Some(vector))?;
    fake.ctrl.ns_usable = true;
    fake.ctrl.lba_bytes = 512;
    fake.ctrl.nsze = 1024;
    // Model a controller that was enabled: a command that times out on it
    // may still be live in the device.
    fake.ctrl.stop_confirmed = false;
    Some(FakeAsyncCtrl { fake, vector })
}

/// A waker that does nothing: the tests poll by hand.
fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn no_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    unsafe fn no_op(_: *const ()) {}
    const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
    // SAFETY: the vtable's functions ignore the (null) data pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) }
}

/// Shortened I/O budget for one async smoke, restored on every exit.
struct ShortIoBudget;

impl ShortIoBudget {
    fn set(ms: u64) -> Self {
        super::IO_TIMEOUT_MS_FOR_TEST.store(ms, core::sync::atomic::Ordering::Release);
        ShortIoBudget
    }
}

impl Drop for ShortIoBudget {
    fn drop(&mut self) {
        super::IO_TIMEOUT_MS_FOR_TEST.store(0, core::sync::atomic::Ordering::Release);
    }
}

fn smoke_nvme_async_spurious_wake_is_not_a_lost_completion() -> TestResult {
    // The queue's vector firing is a reason to look at the CQ, not proof
    // that this command completed: the late MSI of an earlier polled Flush
    // on the same queue, or another queue sharing the vector, bumps it
    // too. The async wait must go round again — the pre-fix path declared
    // the completion lost on the spot (controller dead,
    // `CompletionTimeout`). And a completion that arrives with NO
    // interrupt must still be found, by the wait's poll slice, long
    // before the command's budget.
    use core::future::Future;
    use core::task::{Context, Poll};
    let Some(mut fx) = fake_async_controller() else {
        return TestResult::Fail("fake async controller setup failed");
    };
    let vector = fx.vector;
    let cq_io = fx.fake.cq_io;
    let buf_ptr: *const narf_io::DmaBuffer = &fx.fake._id_page;
    let timeouts0 = super::command_timeouts();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let outcome = {
        // SAFETY: the identify page lives in `fx`, which outlives this
        // block; the future only reads the buffer's address and length.
        let buf = unsafe { &*buf_ptr };
        let mut fut =
            core::pin::pin!(fx
                .fake
                .ctrl
                .submit_io_irq_async(IoOpcode::Read as u8, 0, 1, buf));
        if fut.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("async read resolved with nothing in the CQ");
        }
        // An interrupt on the queue's vector that is not our completion.
        for _ in 0..3 {
            narf_interrupts::on_irq(vector);
            if fut.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail(
                    "a spurious wake ended the wait (completion declared lost)",
                );
            }
        }
        // Our completion, with no interrupt at all.
        // SAFETY: `cq_io` is the fake queue's live CQ page; slot 0.
        unsafe { stage_cqe(cq_io, 0, 0, 1, OWN_SENTINEL) };
        let give_up = narf_time::Deadline::after_ms(super::ASYNC_CQ_POLL_MS * 8);
        loop {
            if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
                break Some(r);
            }
            if give_up.expired() {
                break None;
            }
            core::hint::spin_loop();
        }
    };
    match outcome {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("async read failed although its CQE arrived"),
        None => return TestResult::Fail("a completion without an interrupt was never polled"),
    }
    if fx.fake.ctrl.is_dead() || super::command_timeouts() != timeouts0 {
        return TestResult::Fail("a completed async command left the controller dead / timed out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/async",
    smoke_nvme_async_spurious_wake_is_not_a_lost_completion
);

fn smoke_nvme_async_timeout_checks_cq_before_failing() -> TestResult {
    // Polling before the deadline: "not yet" is not an error and a stray
    // at the head is consumed without ending the command. At the deadline
    // the CQ is looked at one last time: a completion sitting there is
    // taken (late completion, no timeout); only an empty CQ makes the
    // command lost (timeout counted, controller dead).
    use core::future::Future;
    use core::task::{Context, Poll};
    let budget = ShortIoBudget::set(40);
    let Some(mut fx) = fake_async_controller() else {
        return TestResult::Fail("fake async controller setup failed");
    };
    let cq_io = fx.fake.cq_io;
    let buf_ptr: *const narf_io::DmaBuffer = &fx.fake._id_page;
    // SAFETY: the identify page lives in `fx` for the whole test.
    let buf = unsafe { &*buf_ptr };
    let ctrl = &mut fx.fake.ctrl;
    let (late0, timeouts0, strays0) = (
        super::late_completions(),
        super::command_timeouts(),
        super::stray_cqe_drops(),
    );

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // Command 1 (tag 0): a stray first, then its completion after expiry.
    {
        let mut fut = core::pin::pin!(ctrl.submit_io_irq_async(IoOpcode::Read as u8, 0, 1, buf));
        if fut.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("an in-flight command with an empty CQ was not 'not yet'");
        }
        // SAFETY: `cq_io` is the fake queue's live CQ page; slots 0..1.
        unsafe { stage_cqe(cq_io, 0, 0x55, 1, IO_STRAY_SENTINEL) };
        if fut.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("a stray at the head ended the command");
        }
        if super::stray_cqe_drops() != strays0 + 1 {
            return TestResult::Fail("the stray was not consumed and counted");
        }
        // SAFETY: as above.
        unsafe { stage_cqe(cq_io, 1, 0, 1, OWN_SENTINEL) };
        super::IO_LATE_FOR_TEST.store(0, core::sync::atomic::Ordering::Release);
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(60));
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(())) => {}
            _ => {
                return TestResult::Fail("a completion in the CQ at the deadline was declared lost")
            }
        }
    }
    if super::late_completions() != late0 + 1
        || super::command_timeouts() != timeouts0
        || ctrl.is_dead()
    {
        return TestResult::Fail("the last look's completion was not a late completion");
    }

    // Command 2 (tag 1): nothing ever arrives.
    {
        let mut fut = core::pin::pin!(ctrl.submit_io_irq_async(IoOpcode::Read as u8, 0, 1, buf));
        if fut.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("second command resolved with nothing in the CQ");
        }
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(60));
        if !matches!(
            fut.as_mut().poll(&mut cx),
            Poll::Ready(Err(super::NvmeError::CompletionTimeout))
        ) {
            return TestResult::Fail(
                "a command with no completion did not time out at its deadline",
            );
        }
    }
    drop(budget);
    if super::command_timeouts() != timeouts0 + 1 || !ctrl.is_dead() {
        return TestResult::Fail(
            "the lost command was not counted / the controller not marked dead",
        );
    }
    // Dead and never confirmed disabled: its buffers may still be DMA
    // targets (what `nvme_submit_blocking` keys its buffer retention on).
    if !ctrl.may_still_dma() {
        return TestResult::Fail("a dead, never-stopped controller reads as DMA-quiet");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/async",
    smoke_nvme_async_timeout_checks_cq_before_failing
);

fn smoke_nvme_aer_drain_drops_orphan_admin_completion() -> TestResult {
    // The late completion of an admin command that timed out has no
    // waiter. Sitting at the admin CQ head it used to stop the AER drain
    // cold — every event behind it stayed undelivered until some later
    // admin command happened to drop it. The drain now drops it itself
    // (counted as a stray) and delivers the AER behind it.
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;
    if ctrl.post_aer_commands(1).is_err() || ctrl.aer_outstanding() != 1 {
        return TestResult::Fail("post_aer_commands failed");
    }
    // Slot 0: an orphan (CID 7 — neither the AER, CID 0, nor anything
    // waited for). Slot 1: the AER's completion.
    // SAFETY: `cq_admin` is a live 4 KiB coherent page; slots 0..1.
    unsafe {
        stage_cqe(fake.cq_admin, 0, 7, 0, IO_STRAY_SENTINEL);
        stage_cqe(fake.cq_admin, 1, 0, 0, AER_EVENT);
    }
    let strays0 = super::stray_cqe_drops();
    let drain = ctrl.drain_aer_events();
    if drain.drained != 1 {
        return TestResult::Fail("an orphan completion at the head blocked the AER drain");
    }
    if super::stray_cqe_drops() != strays0 + 1 {
        return TestResult::Fail("the orphan admin completion was not counted as a stray");
    }
    if ctrl.aer_outstanding() != 1 {
        return TestResult::Fail("the drained AER was not reposted");
    }
    if ctrl.admin.as_ref().map(|q| q.cq_head) != Some(2) {
        return TestResult::Fail("the drain did not consume both entries");
    }
    // Nothing fresh left: a second drain is a no-op.
    if ctrl.drain_aer_events().drained != 0 || super::stray_cqe_drops() != strays0 + 1 {
        return TestResult::Fail("an empty admin CQ drained or dropped something");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme",
    smoke_nvme_aer_drain_drops_orphan_admin_completion
);

fn smoke_nvme_admin_data_buffer_parked_on_timeout() -> TestResult {
    // An admin command with a data buffer (Identify, Security Send /
    // Receive) that times out may still be live in the device, so its
    // buffer is not freed with the error: it is parked in `in_flight_dma`
    // until the controller is confirmed stopped. A completion — even an
    // error status — means the device is done with the buffer, which is
    // then freed as before. (The timeout half waits out the real 5 s
    // admin budget.)
    let Some(mut fake) = fake_cid_controller() else {
        return TestResult::Fail("fake CID controller setup failed");
    };
    let ctrl = &mut fake.ctrl;
    let mut out = [0u32; 4];

    // CID 0: completes with an error status (phase tag 1, status 2).
    // SAFETY: `cq_admin` is a live 4 KiB coherent page; slot 0.
    unsafe {
        core::ptr::write_volatile(
            fake.cq_admin as *mut Cqe,
            Cqe {
                cmd_specific: 0,
                _resv: 0,
                sq_head: 0,
                sq_id: 0,
                cid: 0,
                status: AER_ERR_STATUS,
            },
        );
    }
    if !matches!(
        ctrl.identify_ns_list(0, &mut out),
        Err(super::NvmeError::CommandFailed { .. })
    ) {
        return TestResult::Fail("an error-status Identify did not report CommandFailed");
    }
    if !ctrl.in_flight_dma.is_empty() {
        return TestResult::Fail("a completed command's buffer was parked");
    }

    // CID 1: never completes.
    let timeouts0 = super::command_timeouts();
    if !matches!(
        ctrl.identify_ns_list(0, &mut out),
        Err(super::NvmeError::CompletionTimeout)
    ) {
        return TestResult::Fail("a silent admin CQ did not time the Identify out");
    }
    if super::command_timeouts() != timeouts0 + 1 {
        return TestResult::Fail("the admin timeout was not counted");
    }
    if ctrl.in_flight_dma.len() != 1 {
        return TestResult::Fail("a timed-out admin command's data buffer was freed");
    }
    // An admin timeout does not take the controller's I/O down with it.
    if ctrl.is_dead() {
        return TestResult::Fail("an admin timeout marked the controller dead");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme",
    smoke_nvme_admin_data_buffer_parked_on_timeout
);
