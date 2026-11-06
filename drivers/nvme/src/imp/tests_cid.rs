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
use narf_lib::sync::IrqSafeSpinLock;

use super::admin::{CNS_CONTROLLER, OPC_IDENTIFY};
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
struct FakeCidCtrl {
    ctrl: Controller,
    /// Keeps the fake BAR mapping alive for `ctrl`'s lifetime.
    _bar: narf_io::DmaBuffer,
    /// Keeps the identify page alive (PRP1 for the admin test).
    _id_page: narf_io::DmaBuffer,
    /// CQ pages, for pre-posting completions.
    cq_admin: *const u8,
    cq_io: *const u8,
    /// DMA address of the identify page (PRP1 for the admin test).
    id_dma: u64,
}

fn fake_cid_controller() -> Option<FakeCidCtrl> {
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
    ctrl.bar0_region = Some(MmioRegion {
        phys: narf_memory::PhysAddr::new(bar.dma_addr().raw()),
        virt: bar.cpu_ptr::<u8>() as u64,
        len: bar.len() as u64,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    });
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
    ctrl.io_queues.push(Queue {
        sq_buf: sq_io,
        cq_buf: cq_io,
        qid: 1,
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
    ctrl.io_queue_locks.push(IrqSafeSpinLock::new(()));

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
    let cqe = {
        let Some(io) = ctrl.io_queues.first_mut() else {
            return TestResult::Fail("fake controller has no I/O queue");
        };
        let Some(bar0) = ctrl.bar0_region.as_ref() else {
            return TestResult::Fail("fake controller has no BAR0");
        };
        // SAFETY: fake I/O queue + RAM-backed BAR; the staged
        // CQEs complete the wait synchronously.
        match unsafe { io.submit_raw(bar0, sqe) } {
            Ok(c) => c,
            Err(_) => {
                return TestResult::Fail("I/O submit_raw failed with stray ahead");
            }
        }
    };
    if cqe.cmd_specific != OWN_SENTINEL {
        return TestResult::Fail("I/O submit consumed the stray CQE (poisoned)");
    }
    if cqe.cid != 0 {
        return TestResult::Fail("returned I/O CQE does not carry our CID");
    }
    if ctrl.stray_aer_len() != 0 {
        return TestResult::Fail("I/O stray was stashed as an AER event");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cid_io_stray_dropped);
