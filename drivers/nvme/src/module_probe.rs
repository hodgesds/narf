//! Loadable-module NVMe driver: a polled NVMe host that publishes each
//! controller's first namespace as a module-backed disk.
//!
//! Everything goes through KSYMTAB exports (`modules/src/kabi.rs`); a module
//! build links no kernel crate, and xtask's `nm -u` gate enforces it. The
//! probe resets the controller, builds one admin and one I/O queue pair in
//! module-owned DMA buffers, identifies namespace 1, and registers
//! `nvme<N>n1` with `narf_blk_register`. Each block request then runs to
//! completion inside the request callback: the kernel copies sector data
//! between the caller's buffer and this module's data buffer
//! (`narf_blk_copy_in` / `narf_blk_copy_out`), and the module submits one
//! command and waits on the completion queue's phase bit with
//! `narf_dma_wait8`. No interrupts are used.
//!
//! This is deliberately the smallest correct NVMe host, the module-ABI proof
//! for storage. The built-in driver (`imp`) remains the full one: multiple
//! queues, MSI-X, every namespace, AER, power states and shutdown.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// QEMU's emulated NVMe controller (Red Hat, Inc.).
const VENDOR: u16 = 0x1B36;
const DEVICE: u16 = 0x0010;

// Controller registers (NVMe 1.4 §3.1).
const REG_CAP: u64 = 0x00;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELL_BASE: u64 = 0x1000;

const CC_EN: u32 = 1 << 0;
/// 64-byte submission entries (2^6) and 16-byte completion entries (2^4).
const CC_IOSQES_IOCQES: u32 = (6 << 16) | (4 << 20);
const CSTS_RDY: u32 = 1 << 0;

// Admin opcodes.
const ADMIN_CREATE_SQ: u32 = 0x01;
const ADMIN_CREATE_CQ: u32 = 0x05;
const ADMIN_IDENTIFY: u32 = 0x06;
// NVM opcodes.
const IO_FLUSH: u32 = 0x00;
const IO_WRITE: u32 = 0x01;
const IO_READ: u32 = 0x02;

/// Entries per queue. Requests are serialised per disk by the kernel, so a
/// queue never holds more than one command; the depth only bounds the ring.
const QUEUE_DEPTH: u32 = 16;
const SQE_LEN: u64 = 64;
const CQE_LEN: u64 = 16;
const PAGE: u64 = 4096;
/// Per-request data buffer: 64 KiB in 16 pages, described by a fixed PRP list.
const DATA_PAGES: u64 = 16;
const DATA_LEN: u64 = DATA_PAGES * PAGE;
/// Namespace this driver publishes.
const NSID: u32 = 1;

/// Per-wait limit of `narf_dma_wait8` / `narf_mmio_wait32` (1 s).
const WAIT_NS: u64 = 1_000_000_000;
/// One command may take this many waits before it is declared lost.
const COMMAND_WAITS: u32 = 5;

const EIO: i32 = -5;
const ENOMEM: i32 = -12;
const EBUSY: i32 = -16;
const EEXIST: i32 = -17;
const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const ENOSPC: i32 = -28;
const ETIMEDOUT: i32 = -110;

// `narf_blk_*` request ops and register flags.
const BLK_READ: u32 = 0;
const BLK_WRITE: u32 = 1;
const BLK_FLUSH: u32 = 2;
const BLK_FLAG_VOLATILE_CACHE: u64 = 1 << 0;

const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
    fn narf_printk(ptr: *const u8, len: usize) -> i32;
    fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
    fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
    fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
    fn narf_mmio_write32(dev: u64, bar: u64, off: u64, value: u32) -> i32;
    fn narf_mmio_wait32(
        dev: u64,
        bar: u64,
        off: u64,
        mask: u32,
        expected: u32,
        timeout_ns: u64,
    ) -> i32;
    fn narf_dma_alloc(dev: u64, len: usize) -> u64;
    fn narf_dma_addr(dev: u64, dma: u64, off: u64, out: *mut u64) -> i32;
    fn narf_dma_write(dev: u64, dma: u64, off: u64, src: *const u8, len: usize) -> i32;
    fn narf_dma_read(dev: u64, dma: u64, off: u64, dst: *mut u8, len: usize) -> i32;
    fn narf_dma_wait8(dev: u64, dma: u64, off: u64, mask: u8, expected: u8, timeout_ns: u64)
        -> i32;
    fn narf_blk_register(
        dev: u64,
        name: *const u8,
        name_len: usize,
        geometry: *const u64,
        request: usize,
        cookie: u64,
    ) -> i32;
    fn narf_blk_copy_in(
        dev: u64,
        request: u64,
        dma: u64,
        dma_off: u64,
        req_off: usize,
        len: usize,
    ) -> i32;
    fn narf_blk_copy_out(
        dev: u64,
        request: u64,
        dma: u64,
        dma_off: u64,
        req_off: usize,
        len: usize,
    ) -> i32;
}

/// One submission/completion queue pair.
struct Queue {
    sq: AtomicU64,
    cq: AtomicU64,
    sq_doorbell: AtomicU64,
    cq_doorbell: AtomicU64,
    tail: AtomicU32,
    head: AtomicU32,
    phase: AtomicU32,
}

impl Queue {
    const fn new() -> Self {
        Self {
            sq: AtomicU64::new(0),
            cq: AtomicU64::new(0),
            sq_doorbell: AtomicU64::new(0),
            cq_doorbell: AtomicU64::new(0),
            tail: AtomicU32::new(0),
            head: AtomicU32::new(0),
            phase: AtomicU32::new(1),
        }
    }
}

struct Controller {
    dev: AtomicU64,
    bar: AtomicU64,
    admin: Queue,
    io: Queue,
    /// The data buffer, the device addresses of its pages 0 and 1, and the
    /// PRP list page.
    data: AtomicU64,
    data_addr: AtomicU64,
    page1_addr: AtomicU64,
    prp_list_addr: AtomicU64,
    lba_size: AtomicU32,
    /// Serialises commands; the kernel already serialises requests per disk,
    /// so this only guards against a probe racing its own first request.
    busy: AtomicBool,
    ready: AtomicBool,
}

impl Controller {
    const fn new() -> Self {
        Self {
            dev: AtomicU64::new(0),
            bar: AtomicU64::new(0),
            admin: Queue::new(),
            io: Queue::new(),
            data: AtomicU64::new(0),
            data_addr: AtomicU64::new(0),
            page1_addr: AtomicU64::new(0),
            prp_list_addr: AtomicU64::new(0),
            lba_size: AtomicU32::new(0),
            busy: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        }
    }
}

/// Module builds have no allocator. Slots are never recycled while module
/// text is live, so a stale cookie cannot reach a newer controller.
const MAX_CONTROLLERS: usize = 4;
static CONTROLLERS: [Controller; MAX_CONTROLLERS] = [const { Controller::new() }; MAX_CONTROLLERS];

/// Zeroes for clearing queue memory (in `.rodata`; a stack array would
/// lower to a `memset` call the module cannot link).
static ZEROES: [u8; 256] = [0; 256];

fn log(msg: &[u8]) {
    // SAFETY: `msg` is live for the call.
    unsafe {
        let _ = narf_printk(msg.as_ptr(), msg.len());
    }
}

fn mmio_read(dev: u64, bar: u64, off: u64) -> Result<u32, i32> {
    let mut value = 0u32;
    // SAFETY: the kernel validates the context and BAR bounds; `value` is a
    // writable local.
    match unsafe { narf_mmio_read32(dev, bar, off, &mut value) } {
        0 => Ok(value),
        rc => Err(rc),
    }
}

fn mmio_write(dev: u64, bar: u64, off: u64, value: u32) -> Result<(), i32> {
    // SAFETY: as `mmio_read`.
    match unsafe { narf_mmio_write32(dev, bar, off, value) } {
        0 => Ok(()),
        rc => Err(rc),
    }
}

fn mmio_write64(dev: u64, bar: u64, off: u64, value: u64) -> Result<(), i32> {
    mmio_write(dev, bar, off, value as u32)?;
    mmio_write(dev, bar, off + 4, (value >> 32) as u32)
}

/// Wait for `CSTS.RDY == expected` for up to `waits` seconds.
fn wait_ready(dev: u64, bar: u64, expected: bool, waits: u32) -> Result<(), i32> {
    let want = if expected { CSTS_RDY } else { 0 };
    for _ in 0..waits {
        // SAFETY: CSTS is a read-only status register.
        match unsafe { narf_mmio_wait32(dev, bar, REG_CSTS, CSTS_RDY, want, WAIT_NS) } {
            0 => return Ok(()),
            ETIMEDOUT => continue,
            rc => return Err(rc),
        }
    }
    Err(ETIMEDOUT)
}

fn dma_alloc(dev: u64, len: u64) -> Result<u64, i32> {
    // SAFETY: the buffer belongs to this device context until unload.
    match unsafe { narf_dma_alloc(dev, len as usize) } {
        0 => Err(ENOMEM),
        handle => Ok(handle),
    }
}

fn dma_addr(dev: u64, dma: u64, off: u64) -> Result<u64, i32> {
    let mut addr = 0u64;
    // SAFETY: `addr` is a writable local; the kernel checks the range.
    match unsafe { narf_dma_addr(dev, dma, off, &mut addr) } {
        0 if addr != 0 => Ok(addr),
        0 => Err(EIO),
        rc => Err(rc),
    }
}

fn dma_write(dev: u64, dma: u64, off: u64, bytes: &[u8]) -> Result<(), i32> {
    // SAFETY: `bytes` is live for the call; the kernel checks the range.
    match unsafe { narf_dma_write(dev, dma, off, bytes.as_ptr(), bytes.len()) } {
        0 => Ok(()),
        rc => Err(rc),
    }
}

fn dma_zero(dev: u64, dma: u64, len: u64) -> Result<(), i32> {
    let mut off = 0;
    while off < len {
        dma_write(dev, dma, off, &ZEROES)?;
        off += ZEROES.len() as u64;
    }
    Ok(())
}

fn dma_read_u64(dev: u64, dma: u64, off: u64) -> Result<u64, i32> {
    let mut bytes = [0u8; 8];
    // SAFETY: `bytes` is a writable local; the kernel checks the range.
    match unsafe { narf_dma_read(dev, dma, off, bytes.as_mut_ptr(), bytes.len()) } {
        0 => Ok(u64::from_le_bytes(bytes)),
        rc => Err(rc),
    }
}

fn dma_read_u8(dev: u64, dma: u64, off: u64) -> Result<u8, i32> {
    let mut byte = 0u8;
    // SAFETY: as `dma_read_u64`.
    match unsafe { narf_dma_read(dev, dma, off, &mut byte, 1) } {
        0 => Ok(byte),
        rc => Err(rc),
    }
}

// A submission entry is sixteen little-endian dwords; on a little-endian CPU
// the `[u32; 16]` in memory is already that byte image, so it is written to
// the queue as is (no byte-shuffling loop for the compiler to lower into
// library calls the module cannot link).
#[cfg(not(target_endian = "little"))]
compile_error!("nvme.ko writes submission entries in native byte order");

/// Submit one command on `queue` and wait for its completion. `dw[0]` holds
/// the opcode; the command id is filled in here.
fn execute(dev: u64, bar: u64, queue: &Queue, dw: &mut [u32; 16]) -> Result<(), i32> {
    let (sq, cq) = (
        queue.sq.load(Ordering::Relaxed),
        queue.cq.load(Ordering::Relaxed),
    );
    let tail = queue.tail.load(Ordering::Relaxed);
    let head = queue.head.load(Ordering::Relaxed);
    let phase = queue.phase.load(Ordering::Relaxed) as u8;
    dw[0] = (dw[0] & 0xFF) | (tail << 16);
    // SAFETY: `dw` is 64 readable bytes; the kernel checks the SQ range.
    if unsafe { narf_dma_write(dev, sq, u64::from(tail) * SQE_LEN, dw.as_ptr().cast(), 64) } != 0 {
        return Err(EIO);
    }
    let next_tail = (tail + 1) % QUEUE_DEPTH;
    mmio_write(
        dev,
        bar,
        queue.sq_doorbell.load(Ordering::Relaxed),
        next_tail,
    )?;
    queue.tail.store(next_tail, Ordering::Relaxed);

    // Completion dword 3: command id [15:0], phase [16], status [31:17], so
    // the phase tag is bit 0 of byte 14.
    let status_off = u64::from(head) * CQE_LEN + 14;
    let mut waited = ETIMEDOUT;
    for _ in 0..COMMAND_WAITS {
        // SAFETY: the completion entry is inside the live CQ buffer.
        waited = unsafe { narf_dma_wait8(dev, cq, status_off, 1, phase, WAIT_NS) };
        if waited != ETIMEDOUT {
            break;
        }
    }
    if waited != 0 {
        // The controller may still complete into this slot later; stop
        // using the controller rather than guess at the ring state.
        return Err(waited);
    }
    let mut status = [0u8; 2];
    // SAFETY: `status` is a writable local; the range is inside the CQ.
    if unsafe { narf_dma_read(dev, cq, status_off, status.as_mut_ptr(), 2) } != 0 {
        return Err(EIO);
    }
    let next_head = (head + 1) % QUEUE_DEPTH;
    if next_head == 0 {
        queue.phase.store(u32::from(phase ^ 1), Ordering::Relaxed);
    }
    queue.head.store(next_head, Ordering::Relaxed);
    mmio_write(
        dev,
        bar,
        queue.cq_doorbell.load(Ordering::Relaxed),
        next_head,
    )?;
    if u16::from_le_bytes(status) >> 1 != 0 {
        return Err(EIO);
    }
    Ok(())
}

fn split(addr: u64) -> (u32, u32) {
    (addr as u32, (addr >> 32) as u32)
}

/// Data pointer dwords 6..=9 for a transfer of `len` bytes from the start
/// of the data buffer: PRP1 is page 0; PRP2 is page 1 for a two-page
/// transfer, else the fixed list naming pages 1.. .
fn prps(ctrl: &Controller, len: u64) -> (u32, u32, u32, u32) {
    let (p1l, p1h) = split(ctrl.data_addr.load(Ordering::Relaxed));
    let prp2 = if len <= PAGE {
        0
    } else if len <= 2 * PAGE {
        ctrl.page1_addr.load(Ordering::Relaxed)
    } else {
        ctrl.prp_list_addr.load(Ordering::Relaxed)
    };
    let (p2l, p2h) = split(prp2);
    (p1l, p1h, p2l, p2h)
}

/// Bring the controller up and identify namespace 1. Returns
/// `(lba_size, capacity, max_blocks, volatile_cache)`.
fn bring_up(ctrl: &Controller, dev: u64, bar: u64) -> Result<(u32, u64, u32, bool), i32> {
    let cap_lo = mmio_read(dev, bar, REG_CAP)?;
    let cap_hi = mmio_read(dev, bar, REG_CAP + 4)?;
    if cap_lo == u32::MAX && cap_hi == u32::MAX {
        return Err(ENODEV);
    }
    // CAP.TO is in 500 ms units; CAP.DSTRD spaces the doorbells.
    let waits = ((cap_lo >> 24) & 0xFF).div_ceil(2).max(1) + 1;
    let stride = 4u64 << (cap_hi & 0xF);
    let mqes = (cap_lo & 0xFFFF) + 1;
    if mqes < QUEUE_DEPTH || (cap_hi >> 5) & 1 == 0 {
        // Too shallow, or no NVM command set (CAP.CSS bit 0 = bit 37).
        return Err(ENODEV);
    }

    // Reset: clear CC.EN and wait for CSTS.RDY to drop.
    mmio_write(dev, bar, REG_CC, 0)?;
    wait_ready(dev, bar, false, waits)?;

    let admin_sq = dma_alloc(dev, PAGE)?;
    let admin_cq = dma_alloc(dev, PAGE)?;
    let io_sq = dma_alloc(dev, PAGE)?;
    let io_cq = dma_alloc(dev, PAGE)?;
    let data = dma_alloc(dev, DATA_LEN)?;
    let prp_list = dma_alloc(dev, PAGE)?;
    for queue in [admin_cq, io_cq] {
        dma_zero(dev, queue, PAGE)?;
    }
    let data_addr = dma_addr(dev, data, 0)?;
    let prp_list_addr = dma_addr(dev, prp_list, 0)?;
    if data_addr % PAGE != 0 || prp_list_addr % PAGE != 0 {
        return Err(EINVAL);
    }
    for page in 0..DATA_PAGES {
        let addr = dma_addr(dev, data, page * PAGE)?;
        if addr % PAGE != 0 {
            return Err(EINVAL);
        }
        if page == 1 {
            ctrl.page1_addr.store(addr, Ordering::Relaxed);
        }
        // The list names pages 1.. (PRP1 covers page 0).
        if page > 0 {
            dma_write(dev, prp_list, (page - 1) * 8, &addr.to_le_bytes())?;
        }
    }

    let queues = [
        (&ctrl.admin, admin_sq, admin_cq, 0u64),
        (&ctrl.io, io_sq, io_cq, 1u64),
    ];
    for (queue, sq, cq, qid) in queues {
        queue.sq.store(sq, Ordering::Relaxed);
        queue.cq.store(cq, Ordering::Relaxed);
        queue
            .sq_doorbell
            .store(DOORBELL_BASE + 2 * qid * stride, Ordering::Relaxed);
        queue
            .cq_doorbell
            .store(DOORBELL_BASE + (2 * qid + 1) * stride, Ordering::Relaxed);
        queue.tail.store(0, Ordering::Relaxed);
        queue.head.store(0, Ordering::Relaxed);
        queue.phase.store(1, Ordering::Relaxed);
    }
    ctrl.data.store(data, Ordering::Relaxed);
    ctrl.data_addr.store(data_addr, Ordering::Relaxed);
    ctrl.prp_list_addr.store(prp_list_addr, Ordering::Relaxed);

    // Admin queue, then enable (NVM command set, 4 KiB pages, round robin).
    let depth = QUEUE_DEPTH - 1;
    mmio_write(dev, bar, REG_AQA, (depth << 16) | depth)?;
    mmio_write64(dev, bar, REG_ASQ, dma_addr(dev, admin_sq, 0)?)?;
    mmio_write64(dev, bar, REG_ACQ, dma_addr(dev, admin_cq, 0)?)?;
    mmio_write(dev, bar, REG_CC, CC_EN | CC_IOSQES_IOCQES)?;
    wait_ready(dev, bar, true, waits)?;

    let (dl, dh) = split(data_addr);
    // Identify controller (CNS 1): MDTS at byte 77, VWC at byte 525.
    execute(
        dev,
        bar,
        &ctrl.admin,
        &mut [
            ADMIN_IDENTIFY,
            0,
            0,
            0,
            0,
            0,
            dl,
            dh,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ],
    )?;
    let mdts = dma_read_u8(dev, data, 77)?;
    let volatile_cache = dma_read_u8(dev, data, 525)? & 1 != 0;
    // Identify namespace 1 (CNS 0): NSZE at 0, FLBAS at 26, LBA formats at 128.
    execute(
        dev,
        bar,
        &ctrl.admin,
        &mut [
            ADMIN_IDENTIFY,
            NSID,
            0,
            0,
            0,
            0,
            dl,
            dh,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    )?;
    let capacity = dma_read_u64(dev, data, 0)?;
    let flbas = dma_read_u8(dev, data, 26)?;
    let format = u64::from((flbas & 0xF) | ((flbas >> 1) & 0x30));
    let lbads = dma_read_u8(dev, data, 128 + 4 * format + 2)?;
    if capacity == 0 || !(9..=12).contains(&lbads) {
        return Err(ENODEV);
    }
    let lba_size = 1u32 << lbads;

    // One I/O completion queue (physically contiguous, polled: no IEN), then
    // its submission queue.
    let (cql, cqh) = split(dma_addr(dev, io_cq, 0)?);
    let size = depth << 16 | 1;
    execute(
        dev,
        bar,
        &ctrl.admin,
        &mut [
            ADMIN_CREATE_CQ,
            0,
            0,
            0,
            0,
            0,
            cql,
            cqh,
            0,
            0,
            size,
            1,
            0,
            0,
            0,
            0,
        ],
    )?;
    let (sql, sqh) = split(dma_addr(dev, io_sq, 0)?);
    execute(
        dev,
        bar,
        &ctrl.admin,
        &mut [
            ADMIN_CREATE_SQ,
            0,
            0,
            0,
            0,
            0,
            sql,
            sqh,
            0,
            0,
            size,
            (1 << 16) | 1,
            0,
            0,
            0,
            0,
        ],
    )?;

    // MDTS is a power of two in units of the minimum page size (4 KiB); 0
    // means no limit. The data buffer is the other bound.
    let mut max_bytes = DATA_LEN;
    if mdts != 0 && mdts < 32 {
        max_bytes = max_bytes.min(PAGE << mdts);
    }
    // A shift, not a division: the module cannot link the divide-by-zero panic.
    let max_blocks = (max_bytes >> lbads) as u32;
    Ok((lba_size, capacity, max_blocks, volatile_cache))
}

/// `narf_blk_register` request callback. `cookie` is the controller slot.
extern "C" fn on_request(cookie: u64, request: u64, op: u32, lba: u64, count: u32) -> i32 {
    let Some(ctrl) = CONTROLLERS.get(cookie as usize) else {
        return ENODEV;
    };
    if !ctrl.ready.load(Ordering::Acquire) {
        return ENODEV;
    }
    if ctrl
        .busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return EBUSY;
    }
    let rc = match run_request(ctrl, request, op, lba, count) {
        Ok(()) => 0,
        Err(rc) => {
            if rc == ETIMEDOUT {
                ctrl.ready.store(false, Ordering::Release);
            }
            rc
        }
    };
    ctrl.busy.store(false, Ordering::Release);
    rc
}

fn run_request(ctrl: &Controller, request: u64, op: u32, lba: u64, count: u32) -> Result<(), i32> {
    let dev = ctrl.dev.load(Ordering::Relaxed);
    let bar = ctrl.bar.load(Ordering::Relaxed);
    let data = ctrl.data.load(Ordering::Relaxed);
    if op == BLK_FLUSH {
        return execute(
            dev,
            bar,
            &ctrl.io,
            &mut [IO_FLUSH, NSID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }
    let len = u64::from(count) * u64::from(ctrl.lba_size.load(Ordering::Relaxed));
    if count == 0 || count > 0x1_0000 || len > DATA_LEN {
        return Err(EINVAL);
    }
    let opcode = match op {
        BLK_READ => IO_READ,
        BLK_WRITE => IO_WRITE,
        _ => return Err(EINVAL),
    };
    if op == BLK_WRITE {
        // SAFETY: kernel export; the kernel checks the request and DMA range.
        let rc = unsafe { narf_blk_copy_in(dev, request, data, 0, 0, len as usize) };
        if rc != 0 {
            return Err(rc);
        }
    }
    let (p1l, p1h, p2l, p2h) = prps(ctrl, len);
    let (sl, sh) = split(lba);
    execute(
        dev,
        bar,
        &ctrl.io,
        &mut [
            opcode,
            NSID,
            0,
            0,
            0,
            0,
            p1l,
            p1h,
            p2l,
            p2h,
            sl,
            sh,
            count - 1,
            0,
            0,
            0,
        ],
    )?;
    if op == BLK_READ {
        // SAFETY: as above.
        let rc = unsafe { narf_blk_copy_out(dev, request, data, 0, 0, len as usize) };
        if rc != 0 {
            return Err(rc);
        }
    }
    Ok(())
}

fn reserve(dev: u64) -> Result<usize, i32> {
    if dev == 0 {
        return Err(EINVAL);
    }
    for (slot, ctrl) in CONTROLLERS.iter().enumerate() {
        match ctrl
            .dev
            .compare_exchange(0, dev, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(slot),
            Err(existing) if existing == dev => return Err(EBUSY),
            Err(_) => {}
        }
    }
    Err(ENOSPC)
}

/// C-ABI probe thunk.
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    let slot = match reserve(dev) {
        Ok(slot) => slot,
        Err(rc) => return rc,
    };
    let Some(ctrl) = CONTROLLERS.get(slot) else {
        return ENOSPC;
    };
    // SAFETY: kernel export; `dev` is the call-gated token of this probe.
    if unsafe { narf_pci_enable(dev, PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER) } != 0 {
        return EIO;
    }
    // SAFETY: kernel export; BAR 0 belongs to `dev`.
    let bar = unsafe { narf_bar_map(dev, 0) };
    if bar == 0 {
        return EIO;
    }
    ctrl.bar.store(bar, Ordering::Relaxed);
    let (lba_size, capacity, max_blocks, volatile_cache) = match bring_up(ctrl, dev, bar) {
        Ok(geometry) => geometry,
        Err(rc) => {
            log(b"nvme(.ko): controller bring-up failed\n");
            return rc;
        }
    };
    ctrl.lba_size.store(lba_size, Ordering::Relaxed);
    ctrl.ready.store(true, Ordering::Release);

    let flags = if volatile_cache {
        BLK_FLAG_VOLATILE_CACHE
    } else {
        0
    };
    let geometry = [u64::from(lba_size), capacity, u64::from(max_blocks), flags];
    // `nvme<N>n1`: the first free controller number, 0..=9.
    let mut name = *b"nvme0n1";
    let mut rc = EEXIST;
    for n in 0..10u8 {
        if let Some(digit) = name.get_mut(4) {
            *digit = b'0' + n;
        }
        // SAFETY: `name` and `geometry` are live locals; `on_request` stays
        // mapped until the kernel retires this module's disks at unload.
        rc = unsafe {
            narf_blk_register(
                dev,
                name.as_ptr(),
                name.len(),
                geometry.as_ptr(),
                on_request as usize,
                slot as u64,
            )
        };
        if rc != EEXIST {
            break;
        }
    }
    if rc != 0 {
        ctrl.ready.store(false, Ordering::Release);
        log(b"nvme(.ko): disk registration failed\n");
        return rc;
    }
    log(b"nvme(.ko): polled controller live, registered ");
    log(&name);
    log(b"\n");
    0
}

/// Register the QEMU NVMe match through the kernel ABI.
pub fn register() {
    const NAME: &[u8] = b"nvme-qemu";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
