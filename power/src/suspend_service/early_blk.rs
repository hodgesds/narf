//! The early polled block reader (power-suspend design §6.3): a
//! minimal, read-only virtio-blk driver for the resume
//! environment, small enough to run before the scheduler, the
//! device model, and the block layer exist.
//!
//! Why a separate reader instead of the running driver: the running
//! virtio stack (`drivers/virtio`) is async, initcall-staged, and
//! bound to the bus/device model — none of which has run when the
//! resume environment stands up, and for S4 the state it would
//! restore *is* the image being read. This reader is the design's
//! priced subset: one device, one queue, one request in flight,
//! polled completion, no interrupts, no writes. It cribs register
//! layouts and ring discipline from the running driver, per the
//! design, but shares no code with it.
//!
//! Transport: virtio-mmio (VirtIO 1.2 §4.2.2), the flat register
//! window native to the aarch64 `virt` platform and to QEMU's
//! mmio transports. The queue/request core is written against the
//! [`EarlyTransport`] seam (registers + DMA window), so a PCI
//! common-config front end can slot in later without touching it;
//! that front end is the named remainder of this lane, not a
//! silent gap.
//!
//! Everything the reader touches is byte-level little-endian
//! accesses through the seam — no pointer casting, no `unsafe` in
//! this module. Bytes read from the device are untrusted input
//! until the image pipeline's AEAD verification says otherwise;
//! this reader's job is only to move ciphertext faithfully and to
//! fail — typed and bounded — when the device misbehaves.
//!
//! Mutable queue state lives behind `Cell`/`RefCell` because the
//! image-store surface (`ImageStore`) reads through `&self`, the
//! same shape the running block layer's `BlockDeviceSync` uses.
//! The resume environment is a single pre-scheduler context and
//! one request is ever in flight, so the cells are never contended;
//! they exist to satisfy the trait shape, not to synchronise.

use alloc::vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{compiler_fence, fence, Ordering};

use super::format::ImageStore;
use super::ServiceError;

// ── VirtIO 1.2 §4.2.2 register map (virtio-mmio) ────────────────────
// Values agree with drivers/virtio's VirtioMmioDevice REG_* table;
// they are restated here because the resume environment must not
// depend on the driver crate (see the module docs).

const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
const REG_QUEUE_DEVICE_LOW: u64 = 0x0a0;
const REG_QUEUE_DEVICE_HIGH: u64 = 0x0a4;
/// Device-specific configuration starts here (§4.2.2); for
/// virtio-blk the capacity in 512-byte sectors is the u64 at
/// offset 0 (§5.2.4).
const REG_CONFIG: u64 = 0x100;

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION_MODERN: u32 = 2;
const VIRTIO_ID_BLOCK: u32 = 2;

// Device status bits (VirtIO 1.2 §2.1).
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

/// `VIRTIO_F_VERSION_1` is feature bit 32: word 1, bit 0 of the
/// feature registers (selected via the §4.2.2 SEL registers).
const FEATURE_VERSION_1_WORD: u32 = 1;
const FEATURE_VERSION_1_BIT: u32 = 1 << 0;

// virtio-blk request types and status (VirtIO 1.2 §5.2.6).
const BLK_T_IN: u32 = 0;
const BLK_S_OK: u8 = 0;
const BLK_S_IOERR: u8 = 1;
const BLK_S_UNSUPP: u8 = 2;
/// Status byte value the driver plants before submission; a
/// completion that leaves it untouched is a protocol violation.
const STATUS_PENDING: u8 = 0xff;

// Split-ring constants (VirtIO 1.2 §2.6).
const DESC_LEN: u64 = 16;
const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

/// Sector size the virtio-blk protocol counts in (§5.2.4: the
/// capacity and every request are in 512-byte units).
pub const SECTOR_LEN: u64 = 512;
/// Largest queue this reader negotiates. One request is ever in
/// flight and a request chain is three descriptors, so depth is
/// not a performance property here; a small queue keeps the DMA
/// window small.
pub const QUEUE_SIZE_CAP: u16 = 16;
/// CPU-side staging size for offset-general store reads.
const STAGE_LEN: usize = 64 * 1024;
/// Bound on the completion poll. QEMU-class devices complete a
/// cached read effectively inline; the bound exists so a wedged
/// device is a typed refusal, never a hang of the resume path.
const POLL_LIMIT: u64 = 50_000_000;
/// Bound on the post-reset status poll (same reasoning).
const RESET_POLL_LIMIT: u64 = 1_000_000;

/// The reader's hardware seam: the virtio-mmio register window
/// plus the DMA window the queue structures live in. Production
/// implements this over a mapped register window and the direct
/// map; fixtures implement it over a device model. All register
/// accesses are 32-bit (the §4.2.2 register width); device
/// configuration is read through the same offsets
/// (`REG_CONFIG` + n). DMA accesses are byte copies between the
/// caller's buffer and device-visible memory at a physical
/// address — they are how queue memory crosses the seam without
/// this module ever casting a pointer.
pub trait EarlyTransport {
    /// Read the 32-bit register (or device-config word) at
    /// `offset` from the window base.
    fn read_u32(&self, offset: u64) -> u32;
    /// Write the 32-bit register at `offset`.
    fn write_u32(&self, offset: u64, value: u32);
    /// Copy `out.len()` bytes of device-visible memory at
    /// physical address `phys` into `out`.
    fn dma_read(&self, phys: u64, out: &mut [u8]);
    /// Copy `data` into device-visible memory at `phys`.
    fn dma_write(&self, phys: u64, data: &[u8]);
}

/// Early-reader failure. Every variant is a refusal: the resume
/// environment treats them all as "no verified image from this
/// device" and routes accordingly (design §6.2 step 5's refuse
/// posture starts here).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EarlyBlkError {
    /// No virtio device at the window (magic mismatch).
    BadMagic,
    /// The transport is not a modern (version 2) device; this
    /// reader does not speak the legacy queue programming.
    LegacyVersion(u32),
    /// The window is a virtio device, but not a block device.
    NotBlockDevice(u32),
    /// The device does not offer VIRTIO_F_VERSION_1, or dropped
    /// FEATURES_OK when the driver accepted only that bit.
    FeaturesRefused,
    /// The device reports no queues, or a queue too small for a
    /// three-descriptor request chain.
    QueueUnusable(u16),
    /// The DMA window is too small for the negotiated queue plus
    /// one bounce sector.
    MemoryTooSmall,
    /// The device reports zero capacity.
    NoCapacity,
    /// A read length was not a whole number of sectors.
    Misaligned,
    /// The requested range lies beyond the device's capacity.
    OutOfRange,
    /// A bounded poll expired (reset or completion): the device
    /// is wedged, not slow.
    Timeout,
    /// The device completed the request with an error status
    /// (VIRTIO_BLK_S_*), or set the FAILED status bit mid-flight.
    DeviceError(u8),
    /// The device violated the queue protocol (used element for a
    /// descriptor that was not submitted, status byte untouched).
    ProtocolViolation,
}

impl EarlyBlkError {
    /// The image-store boundary collapses reader failures into
    /// the service's store error, exactly as `BlockStore`
    /// collapses `BlockIoError` — the pipeline above does not
    /// grade I/O failures, it refuses on all of them.
    fn to_service(self) -> ServiceError {
        ServiceError::Store
    }
}

fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn wr_u16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_le_bytes());
}

fn wr_u32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_le_bytes());
}

fn wr_u64(b: &mut [u8], v: u64) {
    b[..8].copy_from_slice(&v.to_le_bytes());
}

/// DMA-window layout for the negotiated queue, computed from the
/// spec's ring geometry (§2.6): descriptor table, avail ring,
/// used ring (4-aligned), then the request header/status slots,
/// then the data bounce area.
#[derive(Copy, Clone, Debug)]
struct Layout {
    desc: u64,
    avail: u64,
    used: u64,
    header: u64,
    status: u64,
    bounce: u64,
    bounce_len: usize,
}

impl Layout {
    fn compute(queue_size: u16, dma_len: usize) -> Option<Self> {
        let qs = u64::from(queue_size);
        let desc = 0u64;
        let avail = desc + DESC_LEN * qs;
        let avail_len = 4 + 2 * qs + 2;
        let used = (avail + avail_len + 3) & !3;
        let used_len = 4 + 8 * qs + 2;
        let header = (used + used_len + 15) & !15;
        let status = header + 16;
        let bounce = (status + 1 + SECTOR_LEN - 1) & !(SECTOR_LEN - 1);
        if bounce + SECTOR_LEN > dma_len as u64 {
            return None;
        }
        let bounce_len = ((dma_len as u64 - bounce) / SECTOR_LEN * SECTOR_LEN) as usize;
        Some(Self {
            desc,
            avail,
            used,
            header,
            status,
            bounce,
            bounce_len,
        })
    }
}

/// A polled, read-only virtio-blk reader over [`EarlyTransport`].
///
/// One request is in flight at a time and completion is polled,
/// so the reader needs no scheduler, no interrupts, and no locks;
/// it is shaped for the resume environment's pre-scheduler
/// context. It never writes to the device —
/// [`ImageStore::write_all`] refuses — because sealing belongs to
/// the running system; the resume side only ever reads
/// ciphertext.
pub struct PolledBlkReader<T: EarlyTransport> {
    transport: RefCell<T>,
    dma_base: u64,
    layout: Layout,
    queue_size: u16,
    capacity_sectors: u64,
    /// Next avail-ring index value to publish (wrapping, §2.6.5).
    avail_idx: Cell<u16>,
    /// Used-ring index up to which completions were consumed.
    used_seen: Cell<u16>,
}

impl<T: EarlyTransport> PolledBlkReader<T> {
    /// Stand the device up: identify it, reset it, run the §2.1
    /// feature handshake accepting only `VIRTIO_F_VERSION_1`,
    /// program queue 0 inside the DMA window at `dma_base`
    /// (`dma_len` bytes of device-visible memory, reached through
    /// the transport's DMA accessors), and set DRIVER_OK. On any
    /// failure the error is the refusal.
    pub fn open(transport: T, dma_base: u64, dma_len: usize) -> Result<Self, EarlyBlkError> {
        let t = &transport;
        if t.read_u32(REG_MAGIC) != VIRTIO_MAGIC {
            return Err(EarlyBlkError::BadMagic);
        }
        let version = t.read_u32(REG_VERSION);
        if version != VIRTIO_VERSION_MODERN {
            return Err(EarlyBlkError::LegacyVersion(version));
        }
        let device_id = t.read_u32(REG_DEVICE_ID);
        if device_id != VIRTIO_ID_BLOCK {
            return Err(EarlyBlkError::NotBlockDevice(device_id));
        }

        // Reset, and wait (bounded) for the device to confirm.
        t.write_u32(REG_STATUS, 0);
        let mut spins = 0u64;
        while t.read_u32(REG_STATUS) != 0 {
            spins += 1;
            if spins >= RESET_POLL_LIMIT {
                return Err(EarlyBlkError::Timeout);
            }
        }
        t.write_u32(REG_STATUS, STATUS_ACKNOWLEDGE);
        t.write_u32(REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Features (§2.1 steps 3–5): read both words; the only
        // bit this reader accepts is VERSION_1 (word 1, bit 0).
        // A device without it speaks the legacy queue protocol,
        // which this reader refuses rather than approximates.
        t.write_u32(REG_DEVICE_FEATURES_SEL, 0);
        let _low = t.read_u32(REG_DEVICE_FEATURES);
        t.write_u32(REG_DEVICE_FEATURES_SEL, FEATURE_VERSION_1_WORD);
        let high = t.read_u32(REG_DEVICE_FEATURES);
        if high & FEATURE_VERSION_1_BIT == 0 {
            return Err(EarlyBlkError::FeaturesRefused);
        }
        t.write_u32(REG_DRIVER_FEATURES_SEL, 0);
        t.write_u32(REG_DRIVER_FEATURES, 0);
        t.write_u32(REG_DRIVER_FEATURES_SEL, FEATURE_VERSION_1_WORD);
        t.write_u32(REG_DRIVER_FEATURES, FEATURE_VERSION_1_BIT);
        t.write_u32(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        if t.read_u32(REG_STATUS) & STATUS_FEATURES_OK == 0 {
            return Err(EarlyBlkError::FeaturesRefused);
        }

        // Queue 0: size, layout, addresses, ready.
        t.write_u32(REG_QUEUE_SEL, 0);
        let max = t.read_u32(REG_QUEUE_NUM_MAX) as u16;
        if max == 0 {
            return Err(EarlyBlkError::QueueUnusable(0));
        }
        let queue_size = max.min(QUEUE_SIZE_CAP);
        if queue_size < 3 {
            return Err(EarlyBlkError::QueueUnusable(queue_size));
        }
        let layout = Layout::compute(queue_size, dma_len).ok_or(EarlyBlkError::MemoryTooSmall)?;
        t.write_u32(REG_QUEUE_NUM, u32::from(queue_size));
        t.write_u32(REG_QUEUE_DESC_LOW, (dma_base + layout.desc) as u32);
        t.write_u32(REG_QUEUE_DESC_HIGH, ((dma_base + layout.desc) >> 32) as u32);
        t.write_u32(REG_QUEUE_DRIVER_LOW, (dma_base + layout.avail) as u32);
        t.write_u32(
            REG_QUEUE_DRIVER_HIGH,
            ((dma_base + layout.avail) >> 32) as u32,
        );
        t.write_u32(REG_QUEUE_DEVICE_LOW, (dma_base + layout.used) as u32);
        t.write_u32(
            REG_QUEUE_DEVICE_HIGH,
            ((dma_base + layout.used) >> 32) as u32,
        );
        t.write_u32(REG_QUEUE_READY, 1);

        // Capacity (§5.2.4): u64 sectors at config offset 0.
        let cap_lo = t.read_u32(REG_CONFIG);
        let cap_hi = t.read_u32(REG_CONFIG + 4);
        let capacity_sectors = u64::from(cap_lo) | (u64::from(cap_hi) << 32);
        if capacity_sectors == 0 {
            return Err(EarlyBlkError::NoCapacity);
        }

        t.write_u32(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );

        Ok(Self {
            transport: RefCell::new(transport),
            dma_base,
            layout,
            queue_size,
            capacity_sectors,
            avail_idx: Cell::new(0),
            used_seen: Cell::new(0),
        })
    }

    /// Device capacity in 512-byte sectors (§5.2.4).
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// The negotiated queue size.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Read whole sectors starting at `first_sector` into `out`
    /// (`out.len()` must be a sector multiple). Transfers move in
    /// bounce-sized spans through the DMA window; a short final
    /// span is normal.
    pub fn read_sectors(&self, first_sector: u64, out: &mut [u8]) -> Result<(), EarlyBlkError> {
        if out.len() % SECTOR_LEN as usize != 0 {
            return Err(EarlyBlkError::Misaligned);
        }
        let sectors = (out.len() / SECTOR_LEN as usize) as u64;
        let end = first_sector
            .checked_add(sectors)
            .ok_or(EarlyBlkError::OutOfRange)?;
        if end > self.capacity_sectors {
            return Err(EarlyBlkError::OutOfRange);
        }
        let span_max = (self.layout.bounce_len / SECTOR_LEN as usize) as u64;
        let mut done: u64 = 0;
        while done < sectors {
            let span = (sectors - done).min(span_max);
            let start = (done * SECTOR_LEN) as usize;
            let bytes = (span * SECTOR_LEN) as usize;
            self.submit_read(first_sector + done, &mut out[start..start + bytes])?;
            done += span;
        }
        Ok(())
    }

    /// One T_IN request whose data payload is exactly `out`
    /// (sector-multiple, no larger than the DMA bounce area):
    /// header → data (device-written) → status descriptor chain,
    /// kicked, then the used ring polled to completion.
    fn submit_read(&self, sector: u64, out: &mut [u8]) -> Result<(), EarlyBlkError> {
        debug_assert!(!out.is_empty() && out.len() <= self.layout.bounce_len);
        let t = self.transport.borrow();

        // Header (§5.2.6): type, reserved, sector — little-endian.
        let mut header = [0u8; 16];
        wr_u32(&mut header, BLK_T_IN);
        wr_u64(&mut header[8..], sector);
        t.dma_write(self.dma_base + self.layout.header, &header);
        t.dma_write(self.dma_base + self.layout.status, &[STATUS_PENDING]);

        // Descriptor chain (§2.6): 0 header (device-read),
        // 1 data (device-written), 2 status (device-written).
        let mut descs = [0u8; 3 * DESC_LEN as usize];
        let mut put_desc = |i: usize, addr: u64, len: u32, flags: u16, next: u16| {
            let at = i * DESC_LEN as usize;
            wr_u64(&mut descs[at..], addr);
            wr_u32(&mut descs[at + 8..], len);
            wr_u16(&mut descs[at + 12..], flags);
            wr_u16(&mut descs[at + 14..], next);
        };
        put_desc(0, self.dma_base + self.layout.header, 16, DESC_F_NEXT, 1);
        put_desc(
            1,
            self.dma_base + self.layout.bounce,
            out.len() as u32,
            DESC_F_NEXT | DESC_F_WRITE,
            2,
        );
        put_desc(2, self.dma_base + self.layout.status, 1, DESC_F_WRITE, 0);
        t.dma_write(self.dma_base + self.layout.desc, &descs);

        // Publish the head in the avail ring, then the index,
        // with the entry write ordered before the index write
        // (§2.6.5: the device must never see an index pointing at
        // an unwritten entry).
        let avail_idx = self.avail_idx.get();
        let slot = avail_idx % self.queue_size;
        let mut entry = [0u8; 2];
        wr_u16(&mut entry, 0);
        t.dma_write(
            self.dma_base + self.layout.avail + 4 + 2 * u64::from(slot),
            &entry,
        );
        compiler_fence(Ordering::Release);
        let published = avail_idx.wrapping_add(1);
        let mut idx = [0u8; 2];
        wr_u16(&mut idx, published);
        t.dma_write(self.dma_base + self.layout.avail + 2, &idx);
        self.avail_idx.set(published);

        // Kick queue 0, then poll the used index (bounded). The
        // FAILED bit is checked while polling so a device that
        // gives up mid-flight is a fast typed refusal, not a
        // timeout.
        t.write_u32(REG_QUEUE_NOTIFY, 0);
        let seen = self.used_seen.get();
        let mut spins = 0u64;
        let used_idx = loop {
            let mut raw = [0u8; 2];
            t.dma_read(self.dma_base + self.layout.used + 2, &mut raw);
            let idx = rd_u16(&raw);
            if idx != seen {
                break idx;
            }
            if t.read_u32(REG_STATUS) & STATUS_FAILED != 0 {
                return Err(EarlyBlkError::DeviceError(BLK_S_IOERR));
            }
            spins += 1;
            if spins >= POLL_LIMIT {
                return Err(EarlyBlkError::Timeout);
            }
        };

        // Consume exactly one completion (one request in flight,
        // so the new used element is the one at the old index).
        fence(Ordering::SeqCst);
        let elem_slot = seen % self.queue_size;
        let mut elem = [0u8; 8];
        t.dma_read(
            self.dma_base + self.layout.used + 4 + 8 * u64::from(elem_slot),
            &mut elem,
        );
        let head_id = u32::from_le_bytes([elem[0], elem[1], elem[2], elem[3]]);
        if head_id != 0 {
            return Err(EarlyBlkError::ProtocolViolation);
        }
        self.used_seen.set(used_idx);

        let mut status = [0u8; 1];
        t.dma_read(self.dma_base + self.layout.status, &mut status);
        match status[0] {
            BLK_S_OK => {}
            STATUS_PENDING => return Err(EarlyBlkError::ProtocolViolation),
            BLK_S_IOERR | BLK_S_UNSUPP => return Err(EarlyBlkError::DeviceError(status[0])),
            other => return Err(EarlyBlkError::DeviceError(other)),
        }

        // Move the payload out of the DMA window.
        t.dma_read(self.dma_base + self.layout.bounce, out);
        Ok(())
    }
}

impl<T: EarlyTransport> ImageStore for PolledBlkReader<T> {
    fn len_bytes(&self) -> u64 {
        self.capacity_sectors * SECTOR_LEN
    }

    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        if out.is_empty() {
            return Ok(());
        }
        // Sector-window iteration: align the span down/up to
        // whole sectors, move it through a staging buffer in
        // sector-sized requests, and copy out exactly the bytes
        // asked for. The image pipeline reads at arbitrary
        // offsets (the sealed body sits mid-page), so this
        // generality is load-bearing, not decorative.
        let first_sector = offset / SECTOR_LEN;
        let within = (offset % SECTOR_LEN) as usize;
        let total = within + out.len();
        let span_sectors = (total as u64).div_ceil(SECTOR_LEN);
        let window = span_sectors * SECTOR_LEN;
        let mut stage = vec![0u8; STAGE_LEN];
        let mut produced = 0usize; // bytes of `out` filled
        let mut skipped = 0usize; // window bytes consumed
        let mut at_sector = first_sector;
        let mut remaining = window;
        while remaining > 0 {
            let piece = remaining.min(STAGE_LEN as u64);
            self.read_sectors(at_sector, &mut stage[..piece as usize])
                .map_err(EarlyBlkError::to_service)?;
            let piece = piece as usize;
            // Intersect this piece's window span with the
            // caller's [within, within + out.len()) span.
            let lo = within.max(skipped);
            let hi = (within + out.len()).min(skipped + piece);
            if hi > lo {
                out[lo - within..hi - within].copy_from_slice(&stage[lo - skipped..hi - skipped]);
                produced += hi - lo;
            }
            skipped += piece;
            at_sector += piece as u64 / SECTOR_LEN;
            remaining -= piece as u64;
        }
        debug_assert_eq!(produced, out.len());
        Ok(())
    }

    fn write_all(&self, _offset: u64, _data: &[u8]) -> Result<(), ServiceError> {
        // Read-only by design (see the type docs): the resume
        // environment never writes the suspend partition.
        Err(ServiceError::Store)
    }

    fn flush(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}
