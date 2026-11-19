//! `usb-storage.ko`: a Bulk-Only Transport mass-storage driver written only
//! against KSYMTAB exports (`modules/src/kabi.rs`); xtask's `nm -u` gate
//! enforces that the `.ko` links nothing else.
//!
//! Bring-up runs from completions, the way a USB module probe must (the
//! probe itself cannot block): the probe reads the configuration descriptor,
//! finds the BOT interface's bulk pair, and submits `narf_usb_configure`;
//! its completion submits `SET_CONFIGURATION`; that completion runs the SCSI
//! bring-up (TEST UNIT READY, INQUIRY, READ CAPACITY(10)) and registers the
//! stick as `usb-msc<N>` with `narf_blk_register`.
//!
//! From then on every SCSI command is synchronous, because a block request
//! callback must finish its request before returning: CBW out, data, CSW
//! in, each a callback-less bulk request waited with `narf_usb_wait`, which
//! polls the transfer inline. Read data is handed to the request with
//! `narf_blk_fill`, write data taken with `narf_blk_fetch`, through one
//! 4 KiB module buffer per device.
//!
//! Deliberately small, the module-ABI proof for USB storage: LUN 0 only,
//! READ/WRITE(10) (media up to 2 TiB), and no BOT reset recovery. A stall or
//! phase error takes the device offline (requests then fail) rather than
//! being cleared, since clearing a halt is a control request and control
//! requests complete in kernel tasks. The built-in `msc` binder remains the
//! full driver.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::codec::{self, Cdb};

const NAME: &[u8] = b"usb-storage";

/// `narf_register_usb_driver` match flags: interface class, subclass and
/// protocol.
const MATCH_INTERFACE: u16 = (1 << 1) | (1 << 2) | (1 << 3);
/// Standard `SET_CONFIGURATION`.
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

/// Largest transfer one `narf_usb_submit` accepts, and so the largest data
/// phase: one SCSI command moves at most this much.
const XFER: usize = 4096;
/// Configuration descriptor buffer.
const CONFIG_BUF: usize = 512;
/// Per-wait limit of `narf_usb_wait` (1 s) and waits per transfer.
const WAIT_NS: u64 = 1_000_000_000;
const TRANSFER_WAITS: u32 = 5;
/// TEST UNIT READY attempts while the medium reports it is becoming ready.
const READY_TRIES: u32 = 10;

const EIO: i32 = -5;
const EAGAIN: i32 = -11;
const EBUSY: i32 = -16;
const EEXIST: i32 = -17;
const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const ENOSPC: i32 = -28;
const ETIMEDOUT: i32 = -110;
/// The CSW reported CHECK CONDITION (status 1): sense data explains it.
const ECHECK: i32 = -121;

// `narf_blk_*` request ops and register flags.
const BLK_READ: u32 = 0;
const BLK_WRITE: u32 = 1;
const BLK_FLUSH: u32 = 2;
const BLK_FLAG_VOLATILE_CACHE: u64 = 1 << 0;

// Bring-up stages.
const ST_CONFIGURE: u32 = 1;
const ST_SET_CONFIG: u32 = 2;
const ST_READY: u32 = 3;
const ST_FAILED: u32 = 4;

unsafe extern "C" {
    fn narf_printk(ptr: *const u8, len: usize) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn narf_register_usb_driver(
        name: *const u8,
        name_len: usize,
        match_flags: u16,
        vendor: u16,
        product: u16,
        class: u8,
        subclass: u8,
        protocol: u8,
        probe: usize,
    ) -> i32;
    fn narf_usb_config_descriptor(dev: u64, buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    fn narf_usb_configure(
        dev: u64,
        endpoints: *const u8,
        count: usize,
        callback: usize,
        cookie: u64,
        out_urb: *mut u64,
    ) -> i32;
    fn narf_usb_control(
        dev: u64,
        setup: *const u8,
        data: *const u8,
        len: usize,
        callback: usize,
        cookie: u64,
        out_urb: *mut u64,
    ) -> i32;
    fn narf_usb_submit(
        dev: u64,
        endpoint: u8,
        data: *const u8,
        len: usize,
        callback: usize,
        cookie: u64,
        out_urb: *mut u64,
    ) -> i32;
    fn narf_usb_poll(dev: u64, urb: u64, buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    fn narf_usb_wait(dev: u64, urb: u64, timeout_ns: u64) -> i32;
    fn narf_usb_cancel(dev: u64, urb: u64) -> i32;
    fn narf_blk_register(
        dev: u64,
        name: *const u8,
        name_len: usize,
        geometry: *const u64,
        request: usize,
        cookie: u64,
    ) -> i32;
    fn narf_blk_fill(dev: u64, request: u64, req_off: usize, src: *const u8, len: usize) -> i32;
    fn narf_blk_fetch(dev: u64, request: u64, req_off: usize, dst: *mut u8, len: usize) -> i32;
}

/// One device's 4 KiB data buffer. Only the thread holding that device's
/// `busy` flag touches it.
struct Buffer(UnsafeCell<[u8; XFER]>);

// SAFETY: every access goes through `Device::with_buffer`, which requires
// the device's `busy` flag, so no two threads use one buffer at once.
unsafe impl Sync for Buffer {}

struct Device {
    token: AtomicU64,
    bulk_in: AtomicU32,
    bulk_out: AtomicU32,
    config_value: AtomicU32,
    stage: AtomicU32,
    setup_urb: AtomicU64,
    lba_size: AtomicU32,
    tag: AtomicU32,
    /// Serialises SCSI commands (bring-up and block requests).
    busy: AtomicBool,
    /// Guards `stage`/`setup_urb` between a submit and its completion.
    setup_lock: AtomicBool,
}

impl Device {
    const fn new() -> Self {
        Self {
            token: AtomicU64::new(0),
            bulk_in: AtomicU32::new(0),
            bulk_out: AtomicU32::new(0),
            config_value: AtomicU32::new(0),
            stage: AtomicU32::new(0),
            setup_urb: AtomicU64::new(0),
            lba_size: AtomicU32::new(0),
            tag: AtomicU32::new(1),
            busy: AtomicBool::new(false),
            setup_lock: AtomicBool::new(false),
        }
    }

    fn lock_setup(&self) {
        while self
            .setup_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock_setup(&self) {
        self.setup_lock.store(false, Ordering::Release);
    }

    /// Claim the device for one SCSI command sequence.
    fn claim(&self) -> bool {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release(&self) {
        self.busy.store(false, Ordering::Release);
    }
}

/// Module builds have no allocator. Slots are never recycled while module
/// text is live, so a stale cookie cannot reach a newer device.
const MAX_DEVICES: usize = 4;
static DEVICES: [Device; MAX_DEVICES] = [const { Device::new() }; MAX_DEVICES];
static BUFFERS: [Buffer; MAX_DEVICES] = [const { Buffer(UnsafeCell::new([0; XFER])) }; MAX_DEVICES];

fn log(msg: &[u8]) {
    // SAFETY: `msg` is live for the call.
    unsafe {
        let _ = narf_printk(msg.as_ptr(), msg.len());
    }
}

/// Find the first BOT SCSI interface's bulk IN/OUT pair.
/// `(bConfigurationValue, bulk_in, bulk_out)`.
fn parse_config(cfg: &[u8]) -> Option<(u8, u8, u8)> {
    let &[_, 0x02, _, _, _, config_value, ..] = cfg else {
        return None;
    };
    let (mut bulk_in, mut bulk_out) = (0u8, 0u8);
    let mut in_bot = false;
    let mut rest = cfg;
    while let Some(&len) = rest.first() {
        let len = usize::from(len);
        if len < 2 {
            break;
        }
        let Some((d, tail)) = rest.split_at_checked(len) else {
            break;
        };
        match *d {
            [_, 0x04, _, _, _, class, subclass, protocol, ..] if len >= 9 => {
                if in_bot {
                    break; // The BOT interface's endpoints are done.
                }
                in_bot = class == codec::INTERFACE_CLASS
                    && subclass == codec::INTERFACE_SUBCLASS
                    && protocol == codec::INTERFACE_PROTOCOL;
            }
            [_, 0x05, address, attributes, ..] if len >= 7 && in_bot && attributes & 0x03 == 2 => {
                if address & 0x80 != 0 && bulk_in == 0 {
                    bulk_in = address;
                } else if address & 0x80 == 0 && bulk_out == 0 {
                    bulk_out = address;
                }
            }
            _ => {}
        }
        rest = tail;
    }
    (bulk_in != 0 && bulk_out != 0).then_some((config_value, bulk_in, bulk_out))
}

/// Submit one callback-less bulk request and wait for it. For IN, `data`
/// is the receive buffer and its length the transfer length; for OUT it is
/// sent. Returns the bytes transferred.
fn bulk(token: u64, endpoint: u8, data: &mut [u8]) -> Result<usize, i32> {
    let is_in = endpoint & 0x80 != 0;
    let mut urb = 0u64;
    let send = if is_in {
        core::ptr::null()
    } else {
        data.as_ptr()
    };
    // SAFETY: an OUT `data` names `len` readable bytes (copied at submit);
    // an IN request takes no pointer. `urb` is writable; no callback.
    let rc = unsafe { narf_usb_submit(token, endpoint, send, data.len(), 0, 0, &mut urb) };
    if rc != 0 {
        return Err(rc);
    }
    let mut waited = ETIMEDOUT;
    for _ in 0..TRANSFER_WAITS {
        // SAFETY: `urb` is this module's own, callback-less request.
        waited = unsafe { narf_usb_wait(token, urb, WAIT_NS) };
        if waited != ETIMEDOUT {
            break;
        }
    }
    if waited != 0 {
        // SAFETY: as above. The request stays owned by the kernel until it
        // is terminal; the device is taken offline, so it is never reused.
        unsafe {
            let _ = narf_usb_cancel(token, urb);
        }
        return Err(waited);
    }
    let mut actual = 0usize;
    let (buf, len) = if is_in {
        (data.as_mut_ptr(), data.len())
    } else {
        (core::ptr::null_mut(), 0)
    };
    // SAFETY: an IN `buf` names `len` writable bytes; `actual` is writable.
    let status = unsafe { narf_usb_poll(token, urb, buf, len, &mut actual) };
    if status != 0 {
        return Err(status);
    }
    Ok(actual)
}

/// Which way a command's data phase moves, and how much.
enum Data<'a> {
    None,
    In(&'a mut [u8]),
    Out(&'a mut [u8]),
}

/// Run one BOT command: CBW, optional data phase, CSW. Returns the bytes
/// the data phase moved, or `ECHECK` when the device answered CHECK
/// CONDITION.
fn command(dev: &Device, cdb: &Cdb, data: Data<'_>) -> Result<usize, i32> {
    let token = dev.token.load(Ordering::Acquire);
    let bulk_in = dev.bulk_in.load(Ordering::Relaxed) as u8;
    let bulk_out = dev.bulk_out.load(Ordering::Relaxed) as u8;
    let tag = dev.tag.fetch_add(1, Ordering::Relaxed);
    let (len, data_in) = match &data {
        Data::None => (0, false),
        Data::In(buf) => (buf.len(), true),
        Data::Out(buf) => (buf.len(), false),
    };
    let mut cbw = codec::cbw(tag, len as u32, data_in, 0, cdb);
    if bulk(token, bulk_out, &mut cbw)? != codec::CBW_LEN {
        return Err(EIO);
    }
    let moved = match data {
        Data::None => 0,
        Data::In(buf) => bulk(token, bulk_in, buf)?,
        Data::Out(buf) => bulk(token, bulk_out, buf)?,
    };
    let mut csw = [0u8; codec::CSW_LEN];
    if bulk(token, bulk_in, &mut csw)? != codec::CSW_LEN {
        return Err(EIO);
    }
    let Some(status) = codec::decode_csw(&csw) else {
        return Err(EIO);
    };
    if status.tag != tag {
        return Err(EIO);
    }
    match status.status {
        codec::CSW_PASSED => Ok(moved),
        codec::CSW_FAILED => Err(ECHECK),
        _ => Err(EIO),
    }
}

/// Run `f` with the device's data buffer. The caller holds `busy`.
fn with_buffer<R>(slot: usize, f: impl FnOnce(&mut [u8; XFER]) -> R) -> Option<R> {
    let buffer = BUFFERS.get(slot)?;
    // SAFETY: the caller holds this device's `busy` flag (see `Buffer`).
    Some(f(unsafe { &mut *buffer.0.get() }))
}

/// TEST UNIT READY until the medium is ready (clearing the UNIT ATTENTION
/// a fresh device reports with REQUEST SENSE), then INQUIRY and READ
/// CAPACITY(10). Returns `(block_len, block_count)`.
fn scsi_bring_up(dev: &Device, slot: usize) -> Result<(u32, u64), i32> {
    let mut ready = false;
    for _ in 0..READY_TRIES {
        match command(dev, &codec::test_unit_ready(), Data::None) {
            Ok(_) => {
                ready = true;
                break;
            }
            Err(ECHECK) => {
                with_buffer(slot, |buf| {
                    let (sense, _) = buf.split_at_mut(18);
                    command(dev, &codec::request_sense(18), Data::In(sense))
                })
                .ok_or(ENODEV)??;
            }
            Err(rc) => return Err(rc),
        }
    }
    if !ready {
        return Err(EAGAIN);
    }
    let peripheral = with_buffer(slot, |buf| {
        let (response, _) = buf.split_at_mut(36);
        command(dev, &codec::inquiry(36), Data::In(&mut *response)).map(|_| response[0])
    })
    .ok_or(ENODEV)??;
    // Peripheral qualifier 0, device type 0: a direct-access block device.
    if peripheral != 0 {
        return Err(ENODEV);
    }
    let mut capacity = [0u8; 8];
    if command(dev, &codec::read_capacity10(), Data::In(&mut capacity))? != capacity.len() {
        return Err(EIO);
    }
    let (last_lba, block_len) = codec::decode_read_capacity10(&capacity);
    // 0xFFFF_FFFF means "use READ CAPACITY(16)": larger than this driver's
    // READ/WRITE(10) can address.
    if last_lba == u32::MAX || !(512..=4096).contains(&block_len) || !block_len.is_power_of_two() {
        return Err(ENODEV);
    }
    Ok((block_len, u64::from(last_lba) + 1))
}

/// SCSI bring-up and disk registration, run from the `SET_CONFIGURATION`
/// completion.
fn publish(dev: &Device, slot: usize) {
    if !dev.claim() {
        dev.stage.store(ST_FAILED, Ordering::Release);
        return;
    }
    let geometry = scsi_bring_up(dev, slot);
    dev.release();
    let (block_len, blocks) = match geometry {
        Ok(geometry) => geometry,
        Err(_) => {
            dev.stage.store(ST_FAILED, Ordering::Release);
            log(b"usb-storage(.ko): SCSI bring-up failed\n");
            return;
        }
    };
    dev.lba_size.store(block_len, Ordering::Relaxed);
    dev.stage.store(ST_READY, Ordering::Release);

    // Shift, not divide: the module cannot link the divide-by-zero panic.
    let max_blocks = (XFER as u64) >> block_len.trailing_zeros();
    // Removable media may cache writes; flush sends SYNCHRONIZE CACHE.
    let geometry = [
        u64::from(block_len),
        blocks,
        max_blocks,
        BLK_FLAG_VOLATILE_CACHE,
    ];
    let token = dev.token.load(Ordering::Acquire);
    // `usb-msc<N>`, the built-in binder's naming: the first free 0..=9.
    let mut name = *b"usb-msc0";
    let mut rc = EEXIST;
    for n in 0..10u8 {
        if let Some(digit) = name.last_mut() {
            *digit = b'0' + n;
        }
        // SAFETY: `name` and `geometry` are live locals; `on_request` stays
        // mapped until the kernel retires this module's disks.
        rc = unsafe {
            narf_blk_register(
                token,
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
        dev.stage.store(ST_FAILED, Ordering::Release);
        log(b"usb-storage(.ko): disk registration failed\n");
        return;
    }
    log(b"usb-storage(.ko): BOT device live, registered ");
    log(&name);
    log(b"\n");
}

/// `narf_blk_register` request callback. `cookie` is the device slot.
extern "C" fn on_request(cookie: u64, request: u64, op: u32, lba: u64, count: u32) -> i32 {
    let slot = cookie as usize;
    let Some(dev) = DEVICES.get(slot) else {
        return ENODEV;
    };
    if dev.stage.load(Ordering::Acquire) != ST_READY {
        return ENODEV;
    }
    if !dev.claim() {
        return EBUSY;
    }
    let rc = match run_request(dev, slot, request, op, lba, count) {
        Ok(()) => 0,
        Err(rc) => {
            // A failed command may leave the bulk pipes mid-transport (a
            // stall or phase error wants a reset recovery this driver does
            // not do). CHECK CONDITION is a clean answer and keeps it live.
            if rc != ECHECK {
                dev.stage.store(ST_FAILED, Ordering::Release);
            }
            EIO
        }
    };
    dev.release();
    rc
}

fn run_request(
    dev: &Device,
    slot: usize,
    request: u64,
    op: u32,
    lba: u64,
    count: u32,
) -> Result<(), i32> {
    let token = dev.token.load(Ordering::Acquire);
    if op == BLK_FLUSH {
        return command(dev, &codec::synchronize_cache10(), Data::None).map(|_| ());
    }
    let block_len = dev.lba_size.load(Ordering::Relaxed);
    let len = count as usize * block_len as usize;
    let (Ok(lba), Ok(blocks)) = (u32::try_from(lba), u16::try_from(count)) else {
        return Err(EINVAL);
    };
    if count == 0 || len > XFER {
        return Err(EINVAL);
    }
    with_buffer(slot, |buf| {
        let (data, _) = buf.split_at_mut(len);
        match op {
            BLK_READ => {
                if command(dev, &codec::read10(lba, blocks), Data::In(&mut *data))? != len {
                    return Err(EIO);
                }
                // SAFETY: `data` names `len` readable bytes of module memory.
                match unsafe { narf_blk_fill(token, request, 0, data.as_ptr(), len) } {
                    0 => Ok(()),
                    rc => Err(rc),
                }
            }
            BLK_WRITE => {
                // SAFETY: `data` names `len` writable bytes of module memory.
                match unsafe { narf_blk_fetch(token, request, 0, data.as_mut_ptr(), len) } {
                    0 => {}
                    rc => return Err(rc),
                }
                if command(dev, &codec::write10(lba, blocks), Data::Out(&mut *data))? != len {
                    return Err(EIO);
                }
                Ok(())
            }
            _ => Err(EINVAL),
        }
    })
    .ok_or(ENODEV)?
}

const fn cookie(slot: usize) -> u64 {
    slot as u64
}

/// Submit bring-up stage `stage` (configure, then `SET_CONFIGURATION`).
/// The caller holds the setup lock.
fn submit_setup(dev: &Device, slot: usize, stage: u32) -> i32 {
    let token = dev.token.load(Ordering::Acquire);
    let mut urb = 0u64;
    let rc = if stage == ST_CONFIGURE {
        let endpoints = [
            dev.bulk_in.load(Ordering::Relaxed) as u8,
            dev.bulk_out.load(Ordering::Relaxed) as u8,
        ];
        // SAFETY: `endpoints` is readable, `urb` writable, and `on_setup`
        // stays mapped until unload retires this device's context.
        unsafe {
            narf_usb_configure(
                token,
                endpoints.as_ptr(),
                endpoints.len(),
                on_setup as usize,
                cookie(slot),
                &mut urb,
            )
        }
    } else {
        let value = dev.config_value.load(Ordering::Relaxed) as u8;
        let setup = [0x00, STD_REQ_SET_CONFIGURATION, value, 0, 0, 0, 0, 0];
        // SAFETY: `setup` names 8 readable bytes; no data stage; as above.
        unsafe {
            narf_usb_control(
                token,
                setup.as_ptr(),
                core::ptr::null(),
                0,
                on_setup as usize,
                cookie(slot),
                &mut urb,
            )
        }
    };
    if rc == 0 {
        dev.stage.store(stage, Ordering::Release);
        dev.setup_urb.store(urb, Ordering::Release);
    }
    rc
}

/// Completion of a bring-up request.
extern "C" fn on_setup(cookie: u64) -> i32 {
    let slot = cookie as usize;
    let Some(dev) = DEVICES.get(slot) else {
        return ENODEV;
    };
    dev.lock_setup();
    let token = dev.token.load(Ordering::Acquire);
    let stage = dev.stage.load(Ordering::Acquire);
    let mut n = 0usize;
    // SAFETY: neither bring-up request returns data; `n` is writable.
    let status = unsafe {
        narf_usb_poll(
            token,
            dev.setup_urb.load(Ordering::Acquire),
            core::ptr::null_mut(),
            0,
            &mut n,
        )
    };
    if status == EAGAIN {
        dev.unlock_setup();
        return 0;
    }
    if status != 0 || !(ST_CONFIGURE..=ST_SET_CONFIG).contains(&stage) {
        dev.stage.store(ST_FAILED, Ordering::Release);
        dev.unlock_setup();
        log(b"usb-storage(.ko): bring-up request failed\n");
        return 0;
    }
    if stage == ST_CONFIGURE {
        if submit_setup(dev, slot, ST_SET_CONFIG) != 0 {
            dev.stage.store(ST_FAILED, Ordering::Release);
            log(b"usb-storage(.ko): could not set the configuration\n");
        }
        dev.unlock_setup();
        return 0;
    }
    dev.unlock_setup();
    publish(dev, slot);
    0
}

extern "C" fn probe_c(token: u64, _reserved: u64) -> i32 {
    // Uninitialised on purpose (no `memset` in the `.ko`): the kernel writes
    // `cfg_len` bytes and only those are read.
    let mut cfg = core::mem::MaybeUninit::<[u8; CONFIG_BUF]>::uninit();
    let mut cfg_len = 0usize;
    // SAFETY: `cfg` is writable for CONFIG_BUF bytes; `cfg_len` is writable.
    let rc = unsafe {
        narf_usb_config_descriptor(token, cfg.as_mut_ptr().cast(), CONFIG_BUF, &mut cfg_len)
    };
    if rc != 0 {
        return if rc == ENODEV { ENODEV } else { EINVAL };
    }
    // SAFETY: on success the kernel initialised the first `cfg_len` bytes,
    // and `cfg_len <= CONFIG_BUF` (it refuses a short buffer).
    let cfg =
        unsafe { core::slice::from_raw_parts(cfg.as_ptr().cast::<u8>(), cfg_len.min(CONFIG_BUF)) };
    let Some((config_value, bulk_in, bulk_out)) = parse_config(cfg) else {
        return ENODEV;
    };
    let Some((slot, dev)) = DEVICES.iter().enumerate().find(|(_, d)| {
        d.token
            .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return ENOSPC;
    };
    dev.config_value
        .store(u32::from(config_value), Ordering::Relaxed);
    dev.bulk_in.store(u32::from(bulk_in), Ordering::Relaxed);
    dev.bulk_out.store(u32::from(bulk_out), Ordering::Relaxed);
    // Hold the setup lock across submit: the completion may run on another
    // CPU before `submit_setup` has recorded the request id.
    dev.lock_setup();
    let rc = submit_setup(dev, slot, ST_CONFIGURE);
    dev.unlock_setup();
    if rc != 0 {
        dev.stage.store(ST_FAILED, Ordering::Release);
        return rc;
    }
    0
}

/// Register the BOT interface match through the kernel ABI.
pub fn register() {
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn and the
    // loader unregisters the match before unmapping this image.
    let rc = unsafe {
        narf_register_usb_driver(
            NAME.as_ptr(),
            NAME.len(),
            MATCH_INTERFACE,
            0,
            0,
            codec::INTERFACE_CLASS,
            codec::INTERFACE_SUBCLASS,
            codec::INTERFACE_PROTOCOL,
            probe_c as usize,
        )
    };
    if rc != 0 {
        log(b"usb-storage(.ko): match registration failed\n");
    }
}
