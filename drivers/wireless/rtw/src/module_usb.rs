//! rtw88-USB loadable-module datapath — enumerate, chip-config read, firmware
//! download, and MAC/FIFO bring-up. See
//! `drivers/wireless/specification/rtw88-usb-module-datapath.md`.
//!
//! The per-chip probe (`probe_8821cu`/`probe_8822bu`) drives a real rtw88 USB
//! device entirely through the exported C-ABI (no kernel crates, so the `.ko`'s
//! undefined-symbol set stays within the ABI):
//!
//! 1. **Enumerate** (event-driven, mirroring `drivers/usb/ftdi`: one
//!    outstanding URB advanced from `on_event` under a per-device busy lock) —
//!    configuration descriptor (bulk IN + the bulk-OUT pipe count), bulk
//!    endpoint configuration, and a Realtek `REG_SYS_CFG1` read (vendor control
//!    `0xC0`/`0x05`/`wValue=addr`).
//! 2. **Firmware download** (synchronous: `narf_usb_wait`) — fetch the chip's
//!    firmware blob via `narf_firmware_*`, validate the image header, then DDMA
//!    every section to the chip (`run`/`section`/`page`, ported from
//!    `firmware_transport.rs`/`usb_firmware.rs`) over `narf_usb_*` EP0 control
//!    + BEACON reserved-page bulk writes.
//! 3. **MAC/FIFO bring-up** (synchronous) — the shared
//!    `narf-drivers-wireless-rtl-chip` `mac::prepare`, run over the module's
//!    `UsbRegIo` (the same register sequence the builtin driver programs),
//!    with the queue/page rows derived from the bulk-OUT pipe count.
//!
//! PHY/RF/IQK/station bring-up, netdev publication and the cfg80211 control
//! plane are the remaining stages.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_drivers_wireless_rtl_chip::mac as chip_mac;
use narf_drivers_wireless_rtl_chip::{ChipError, RegIo};

/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;

/// Realtek vendor control: IN request type and the register command request
/// (`narf_drivers_wireless_rtl_usb::{REALTEK_USB_READ, REALTEK_USB_CMD_REQ}`).
const REALTEK_USB_READ: u8 = 0xC0;
/// Realtek vendor control: OUT request type for register writes.
const REALTEK_USB_WRITE: u8 = 0x40;
const REALTEK_USB_CMD_REQ: u8 = 0x05;
/// `rtw88::usb::REG_SYS_CFG1` — the chip-configuration word read as the
/// enumerate proof (32-bit).
const REG_SYS_CFG1: u16 = 0xF0;

/// RTL8821CU VID/PIDs (`rtw88::usb::RTL8821CU_IDS`).
const RTL8821CU_IDS: &[(u16, u16)] = &[
    (0x0BDA, 0x2006),
    (0x0BDA, 0x8731),
    (0x0BDA, 0x8811),
    (0x0BDA, 0xB820),
    (0x0BDA, 0xB82B),
    (0x0BDA, 0xC80C),
    (0x0BDA, 0xC811),
    (0x0BDA, 0xC820),
    (0x0BDA, 0xC821),
    (0x0BDA, 0xC82A),
    (0x0BDA, 0xC82B),
    (0x2001, 0x331D),
    (0x7392, 0xC811),
    (0x7392, 0xD811),
    (0x2C4E, 0x0105),
];
/// RTL8822BU VID/PIDs (`rtw88::usb::RTL8822BU_IDS`).
const RTL8822BU_IDS: &[(u16, u16)] = &[
    (0x0BDA, 0xB812),
    (0x0BDA, 0xB82C),
    (0x0BDA, 0x2102),
    (0x7392, 0xB822),
    (0x7392, 0xC822),
    (0x7392, 0xD822),
    (0x7392, 0xE822),
    (0x7392, 0xF822),
    (0x0BDA, 0xB81A),
    (0x0B05, 0x1841),
    (0x0B05, 0x184C),
    (0x0B05, 0x19AA),
    (0x0B05, 0x1870),
    (0x0B05, 0x1874),
    (0x2001, 0x331E),
    (0x2001, 0x331C),
    (0x2001, 0x331F),
    (0x13B1, 0x0043),
    (0x13B1, 0x0045),
    (0x2357, 0x012D),
    (0x2357, 0x0138),
    (0x2357, 0x0115),
    (0x2357, 0x012E),
    (0x2357, 0x0116),
    (0x2357, 0x0117),
    (0x0846, 0x9055),
    (0x0E66, 0x0025),
    (0x04CA, 0x8602),
    (0x20F4, 0x808A),
    (0x20F4, 0x805A),
    (0x056E, 0x4011),
    (0x2C4E, 0x0107),
    (0x2C4E, 0x010A),
    (0x2001, 0x3322),
    (0x0411, 0x03D1),
];

/// Largest configuration descriptor this stage parses.
const CONFIG_BUF: usize = 512;

// ── Bring-up stages ────────────────────────────────────────────────────────
const ST_CONFIGURE: u32 = 1;
const ST_READ_CFG: u32 = 2;
/// Enumerated: endpoints configured + chip-config word read.
const ST_UP: u32 = 3;
/// Firmware blob fetched (`narf_firmware_*`) and its header validated.
const ST_FW_PARSED: u32 = 4;
/// Firmware sections written to the chip and the MCU released (download done).
const ST_FW_DOWNLOADED: u32 = 5;
/// MAC/FIFO bring-up (`mac::prepare`) complete over the synchronous `UsbRegIo`.
const ST_MAC_UP: u32 = 6;
const ST_FAILED: u32 = 0xff;

/// rtw88 TX descriptor length / firmware page size (`usb::TX_DESC`, `fw` page).
const TX_DESC: usize = 48;
const FW_PAGE: usize = 4096;
/// BEACON transmit queue selector for reserved-page firmware writes
/// (`usb::QSEL_BEACON`).
const QSEL_BEACON: u8 = 0x10;
/// Synchronous per-transfer wait, matching the native 2 s download cap.
const USB_WAIT_NS: u64 = 2_000_000_000;
/// Single outstanding-URB event kind (one request in flight per device).
const EV_SETUP: u64 = 1;

const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;
/// `-EAGAIN`: a poll with no terminal completion yet.
const EAGAIN: i32 = -11;

unsafe extern "C" {
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
    fn narf_usb_poll(dev: u64, urb: u64, buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn narf_usb_submit(
        dev: u64,
        endpoint: u8,
        data: *const u8,
        len: usize,
        callback: usize,
        cookie: u64,
        out_urb: *mut u64,
    ) -> i32;
    fn narf_usb_wait(dev: u64, urb: u64, timeout_ns: u64) -> i32;
    fn narf_firmware_open(
        name: *const u8,
        name_len: usize,
        out_handle: *mut u64,
        out_size: *mut usize,
    ) -> i32;
    fn narf_firmware_read(
        handle: u64,
        offset: u64,
        buf: *mut u8,
        len: usize,
        out_len: *mut usize,
    ) -> i32;
    fn narf_firmware_close(handle: u64) -> i32;
}

/// rtw88 firmware header length (`firmware_transport.rs::HEADER`).
const FW_HEADER: usize = 64;
/// Per-section checksum trailer (`firmware_transport.rs::CHECKSUM`).
const FW_CHECKSUM: usize = 8;
/// `firmware_transport.rs::MAX_IMAGE`.
const FW_MAX_IMAGE: usize = 1024 * 1024;

/// The registered firmware blob name for a representative chip `did`
/// (`firmware_transport.rs::filename`).
fn fw_name(did: u16) -> Option<&'static str> {
    match did {
        0xC821 => Some("rtw88/rtw8821c_fw.bin"),
        0xB822 => Some("rtw88/rtw8822b_fw.bin"),
        _ => None,
    }
}

/// Little-endian u32 at `off` (bounds-checked; `None` on overrun).
fn word(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One downloadable firmware section: a chip memory `address` and the blob
/// byte range (`blob_off`..`blob_off+len`) carrying its body + 8-byte checksum.
#[derive(Clone, Copy, Default)]
struct FwSection {
    address: u32,
    blob_off: u32,
    len: u32,
}

/// Validate the 64-byte rtw88 firmware header for `did` against the total blob
/// `size`, filling `sections` with the enabled sections and returning
/// `(version, count)`. A faithful port of `firmware_transport.rs::parse`
/// (section OCP bases/sizes + checksum trailers must exactly span the blob);
/// it records byte ranges rather than copying bodies.
fn parse_fw_header(
    did: u16,
    header: &[u8],
    size: usize,
    sections: &mut [FwSection; 3],
) -> Result<(u16, usize), ()> {
    let signature: [u8; 2] = match did {
        0xC821 => [0x21, 0x88],
        0xB822 => [0x22, 0x88],
        _ => return Err(()),
    };
    if header.len() < FW_HEADER
        || !(FW_HEADER..=FW_MAX_IMAGE).contains(&size)
        || header[..2] != signature
    {
        return Err(());
    }
    let imem_base = if did == 0xB822 { 0 } else { 0x30000 };
    let has_emem = header[0x18] & 0x10 != 0 && word(header, 0x34).ok_or(())? != 0;
    // (base, limit, size-field, address-field, enabled)
    let plan = [
        (0x20_0000u32, 0x30_0000u32, 0x24usize, 0x20usize, true),
        (imem_base, 0x10_0000, 0x30, 0x3c, true),
        (0x10_0000, 0x20_0000, 0x34, 0x38, has_emem),
    ];
    let mut offset = FW_HEADER as u32;
    let mut count = 0usize;
    for (base, limit, size_at, addr_at, enabled) in plan {
        if !enabled {
            continue;
        }
        let sec_size = word(header, size_at).ok_or(())?;
        let address = word(header, addr_at).ok_or(())? & 0x7fff_ffff;
        let length = sec_size.checked_add(FW_CHECKSUM as u32).ok_or(())?;
        if sec_size == 0
            || address != base
            || address.checked_add(length).is_none_or(|end| end > limit)
        {
            return Err(());
        }
        sections[count] = FwSection {
            address,
            blob_off: offset,
            len: length,
        };
        count += 1;
        offset = offset.checked_add(length).ok_or(())?;
    }
    // The header's sections + checksums must span exactly the blob.
    if offset as usize != size {
        return Err(());
    }
    Ok((u16::from_le_bytes([header[4], header[5]]), count))
}

/// One claimed USB device's enumerate state. One outstanding URB at a time,
/// serialised by `busy`.
struct Device {
    token: AtomicU64,
    busy: AtomicBool,
    stage: AtomicU32,
    bulk_in: AtomicU32,
    bulk_out: AtomicU32,
    /// Number of bulk-OUT pipes on the first interface (2..=4), selecting the
    /// `rqpn_table`/`page_table` row for the MAC queue/FIFO programming.
    bulk_out_count: AtomicU32,
    config_value: AtomicU32,
    urb: AtomicU64,
    chip_cfg: AtomicU32,
    /// Representative chip `did` (set by the per-chip probe) selecting the
    /// firmware name and header signature.
    did: AtomicU32,
    /// Parsed firmware version once `ST_FW_PARSED` is reached.
    fw_version: AtomicU32,
}

impl Device {
    const fn new() -> Self {
        Self {
            token: AtomicU64::new(0),
            busy: AtomicBool::new(false),
            stage: AtomicU32::new(0),
            bulk_in: AtomicU32::new(0),
            bulk_out: AtomicU32::new(0),
            bulk_out_count: AtomicU32::new(0),
            config_value: AtomicU32::new(0),
            urb: AtomicU64::new(0),
            chip_cfg: AtomicU32::new(0),
            did: AtomicU32::new(0),
            fw_version: AtomicU32::new(0),
        }
    }

    fn lock(&self) {
        while self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.busy.store(false, Ordering::Release);
    }
}

const MAX_DEVICES: usize = 4;
static DEVICES: [Device; MAX_DEVICES] = [const { Device::new() }; MAX_DEVICES];

/// `(slot, event)` folded into the completion cookie.
fn cookie(slot: usize, event: u64) -> u64 {
    ((slot as u64) << 8) | event
}

/// Find the first interface's bulk IN endpoint, its first bulk OUT endpoint,
/// and the count of bulk OUT pipes. Returns
/// `(bConfigurationValue, bulk_in, bulk_out, bulk_out_count)`. Slice patterns +
/// `split_at` only — no indexing that could panic.
fn parse_config(cfg: &[u8]) -> Option<(u8, u8, u8, u8)> {
    let &[_, 0x02, _, _, _, config_value, ..] = cfg else {
        return None;
    };
    let (mut bulk_in, mut bulk_out) = (0u8, 0u8);
    let mut bulk_out_count = 0u8;
    let mut in_first_interface = false;
    let mut rest = cfg;
    while let Some(&len) = rest.first() {
        let len = usize::from(len);
        if len < 2 {
            break;
        }
        let Some((d, tail)) = rest.split_at_checked(len) else {
            break;
        };
        match d {
            [_, 0x04, ..] if len >= 9 => {
                if in_first_interface {
                    break; // Only the first interface.
                }
                in_first_interface = true;
            }
            &[_, 0x05, address, attributes, ..] if len >= 7 && in_first_interface => {
                if attributes & 0x03 == 2 {
                    if address & 0x80 != 0 {
                        if bulk_in == 0 {
                            bulk_in = address;
                        }
                    } else {
                        if bulk_out == 0 {
                            bulk_out = address;
                        }
                        bulk_out_count = bulk_out_count.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
        rest = tail;
    }
    (bulk_in != 0 && bulk_out != 0).then_some((config_value, bulk_in, bulk_out, bulk_out_count))
}

/// Claim the first free device slot for `token`.
fn claim(token: u64) -> Option<usize> {
    DEVICES.iter().position(|dev| {
        dev.token
            .compare_exchange(0, token, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    })
}

/// RTL8821CU devices probe with the 8821c firmware/header identity.
extern "C" fn probe_8821cu(dev_token: u64, _reserved: u64) -> i32 {
    start_probe(dev_token, 0xC821)
}

/// RTL8822BU devices probe with the 8822b firmware/header identity.
extern "C" fn probe_8822bu(dev_token: u64, _reserved: u64) -> i32 {
    start_probe(dev_token, 0xB822)
}

fn start_probe(dev_token: u64, did: u16) -> i32 {
    let Some(slot) = claim(dev_token) else {
        return EBUSY;
    };
    let dev = &DEVICES[slot];
    dev.did.store(u32::from(did), Ordering::Relaxed);

    // Configuration descriptor is a synchronous read. Uninitialised on purpose
    // (no `memset` in the `.ko`): the kernel writes `cfg_len` bytes and only
    // those are read.
    let mut cfg = core::mem::MaybeUninit::<[u8; CONFIG_BUF]>::uninit();
    let mut cfg_len = 0usize;
    // SAFETY: `cfg` is writable for CONFIG_BUF bytes; `cfg_len` is writable.
    let rc = unsafe {
        narf_usb_config_descriptor(dev_token, cfg.as_mut_ptr().cast(), CONFIG_BUF, &mut cfg_len)
    };
    if rc != 0 {
        dev.token.store(0, Ordering::Release);
        return rc;
    }
    // SAFETY: on success the kernel initialised the first `cfg_len` bytes, and
    // `cfg_len <= CONFIG_BUF` (the export refuses a short buffer).
    let cfg =
        unsafe { core::slice::from_raw_parts(cfg.as_ptr().cast::<u8>(), cfg_len.min(CONFIG_BUF)) };
    let Some((config_value, bulk_in, bulk_out, bulk_out_count)) = parse_config(cfg) else {
        dev.token.store(0, Ordering::Release);
        return EIO;
    };
    dev.config_value
        .store(u32::from(config_value), Ordering::Relaxed);
    dev.bulk_in.store(u32::from(bulk_in), Ordering::Relaxed);
    dev.bulk_out.store(u32::from(bulk_out), Ordering::Relaxed);
    dev.bulk_out_count
        .store(u32::from(bulk_out_count), Ordering::Relaxed);

    // Configure the bulk endpoints; completion advances the state machine.
    let endpoints = [bulk_in, bulk_out];
    let mut urb = 0u64;
    // SAFETY: `endpoints` is readable for its length; `urb` is writable;
    // `on_event` stays mapped until the loader retires this device's context.
    let rc = unsafe {
        narf_usb_configure(
            dev_token,
            endpoints.as_ptr(),
            endpoints.len(),
            on_event as usize,
            cookie(slot, EV_SETUP),
            &mut urb,
        )
    };
    if rc != 0 {
        dev.token.store(0, Ordering::Release);
        return rc;
    }
    dev.stage.store(ST_CONFIGURE, Ordering::Release);
    dev.urb.store(urb, Ordering::Release);
    0
}

/// Submit the Realtek vendor control read of `REG_SYS_CFG1` (4 bytes IN). The
/// data returns via `narf_usb_poll`, as the device-descriptor read does.
fn submit_read_cfg(dev: &Device, slot: usize) -> i32 {
    let token = dev.token.load(Ordering::Acquire);
    let [a0, a1] = REG_SYS_CFG1.to_le_bytes();
    let setup = [REALTEK_USB_READ, REALTEK_USB_CMD_REQ, a0, a1, 0, 0, 4, 0];
    let mut urb = 0u64;
    // SAFETY: `setup` names 8 readable bytes; no OUT data stage (IN data is
    // returned by `poll`); `urb` is writable; `on_event` stays mapped.
    let rc = unsafe {
        narf_usb_control(
            token,
            setup.as_ptr(),
            core::ptr::null(),
            0,
            on_event as usize,
            cookie(slot, EV_SETUP),
            &mut urb,
        )
    };
    if rc == 0 {
        dev.stage.store(ST_READ_CFG, Ordering::Release);
        dev.urb.store(urb, Ordering::Release);
    } else {
        dev.stage.store(ST_FAILED, Ordering::Release);
    }
    rc
}

/// One outstanding-URB completion. Poll the current URB and advance.
fn on_setup(dev: &Device, slot: usize) {
    let token = dev.token.load(Ordering::Acquire);
    let urb = dev.urb.load(Ordering::Acquire);
    match dev.stage.load(Ordering::Acquire) {
        ST_CONFIGURE => {
            let mut n = 0usize;
            // SAFETY: no data expected from configure; null/0 output is valid.
            let status = unsafe { narf_usb_poll(token, urb, core::ptr::null_mut(), 0, &mut n) };
            if status == EAGAIN {
                return;
            }
            if status != 0 {
                dev.stage.store(ST_FAILED, Ordering::Release);
                return;
            }
            submit_read_cfg(dev, slot);
        }
        ST_READ_CFG => {
            let mut buf = [0u8; 4];
            let mut n = 0usize;
            // SAFETY: `buf` is writable for its length; `n` is writable.
            let status = unsafe { narf_usb_poll(token, urb, buf.as_mut_ptr(), buf.len(), &mut n) };
            if status == EAGAIN {
                return;
            }
            if status != 0 || n < 4 {
                dev.stage.store(ST_FAILED, Ordering::Release);
                return;
            }
            dev.chip_cfg
                .store(u32::from_le_bytes(buf), Ordering::Release);
            dev.stage.store(ST_UP, Ordering::Release);
            // Enumeration proven. Fetch the firmware over `narf_firmware_*`,
            // validate its header, and DDMA every section to the chip over
            // `narf_usb_*`, then run the shared MAC/FIFO bring-up. Firmware
            // fetch, the download transfers and the MAC register sequence are
            // all synchronous (poll/wait), so the whole stage runs inline on
            // this completion.
            dev.stage.store(ST_FW_PARSED, Ordering::Release);
            if !firmware_download(dev) {
                dev.stage.store(ST_FAILED, Ordering::Release);
                return;
            }
            dev.stage.store(ST_FW_DOWNLOADED, Ordering::Release);
            if mac_up(dev) {
                dev.stage.store(ST_MAC_UP, Ordering::Release);
            } else {
                dev.stage.store(ST_FAILED, Ordering::Release);
            }
        }
        _ => {}
    }
}

// ── Synchronous narf_usb_* register I/O ─────────────────────────────────────
//
// The firmware download is a long, task-context sequence of short EP0/bulk
// transfers. Rather than thread each through the `on_event` state machine, it
// submits with no callback and blocks on `narf_usb_wait` — a synchronous
// `UsbControl`/`Bulk` over the C-ABI (used by the download; also the basis for
// the later MAC/PHY/station stages).

/// Submit result: wait for the URB and consume it, optionally into `buf`.
fn sync_done(token: u64, urb: u64, buf: *mut u8, len: usize) -> bool {
    // SAFETY: `urb` came from a submit on `token`; wait blocks until terminal.
    if unsafe { narf_usb_wait(token, urb, USB_WAIT_NS) } != 0 {
        return false;
    }
    let mut n = 0usize;
    // SAFETY: `buf` is writable for `len` (or null/0); `n` is writable.
    unsafe { narf_usb_poll(token, urb, buf, len, &mut n) == 0 }
}

/// Realtek EP0 register write of `data` (1/2/4 bytes) at `addr`.
fn ctl_out(token: u64, addr: u16, data: &[u8]) -> bool {
    let [a0, a1] = addr.to_le_bytes();
    let [l0, l1] = (data.len() as u16).to_le_bytes();
    let setup = [REALTEK_USB_WRITE, REALTEK_USB_CMD_REQ, a0, a1, 0, 0, l0, l1];
    let mut urb = 0u64;
    // SAFETY: `setup` is 8 bytes; `data` is `len` readable; callback 0 (we
    // poll). The kernel copies before returning.
    let rc = unsafe {
        narf_usb_control(
            token,
            setup.as_ptr(),
            data.as_ptr(),
            data.len(),
            0,
            0,
            &mut urb,
        )
    };
    rc == 0 && sync_done(token, urb, core::ptr::null_mut(), 0)
}

/// Realtek EP0 register read of `out.len()` (1/2/4) bytes at `addr`.
fn ctl_in(token: u64, addr: u16, out: &mut [u8]) -> bool {
    let [a0, a1] = addr.to_le_bytes();
    let [l0, l1] = (out.len() as u16).to_le_bytes();
    let setup = [REALTEK_USB_READ, REALTEK_USB_CMD_REQ, a0, a1, 0, 0, l0, l1];
    let mut urb = 0u64;
    // SAFETY: `setup` 8 bytes; IN request (no OUT data stage); callback 0.
    let rc =
        unsafe { narf_usb_control(token, setup.as_ptr(), core::ptr::null(), 0, 0, 0, &mut urb) };
    rc == 0 && sync_done(token, urb, out.as_mut_ptr(), out.len())
}

/// Synchronous bulk-OUT of `data` on `ep`.
fn bulk_out(token: u64, ep: u8, data: &[u8]) -> bool {
    let mut urb = 0u64;
    // SAFETY: `data` is `len` readable; callback 0 (we poll).
    let rc = unsafe { narf_usb_submit(token, ep, data.as_ptr(), data.len(), 0, 0, &mut urb) };
    rc == 0 && sync_done(token, urb, core::ptr::null_mut(), 0)
}

fn reg_read8(t: u64, a: u16) -> Option<u8> {
    let mut b = [0u8; 1];
    ctl_in(t, a, &mut b).then_some(b[0])
}
fn reg_read16(t: u64, a: u16) -> Option<u16> {
    let mut b = [0u8; 2];
    ctl_in(t, a, &mut b).then(|| u16::from_le_bytes(b))
}
fn reg_read32(t: u64, a: u16) -> Option<u32> {
    let mut b = [0u8; 4];
    ctl_in(t, a, &mut b).then(|| u32::from_le_bytes(b))
}
fn reg_write8(t: u64, a: u16, v: u8) -> Option<()> {
    ctl_out(t, a, &v.to_le_bytes()).then_some(())
}
fn reg_write16(t: u64, a: u16, v: u16) -> Option<()> {
    ctl_out(t, a, &v.to_le_bytes()).then_some(())
}
fn reg_write32(t: u64, a: u16, v: u32) -> Option<()> {
    ctl_out(t, a, &v.to_le_bytes()).then_some(())
}
fn reg_update8(t: u64, a: u16, clear: u8, set: u8) -> Option<()> {
    let v = reg_read8(t, a)?;
    reg_write8(t, a, v & !clear | set)
}
/// Poll a 32-bit register until `value & mask == target` (`firmware_transport
/// ::poll`): up to 1000 reads, `u32::MAX` means the device vanished.
fn reg_poll32(t: u64, a: u16, mask: u32, target: u32) -> Option<()> {
    for _ in 0..1000 {
        let v = reg_read32(t, a)?;
        if v == u32::MAX {
            return None;
        }
        if v & mask == target {
            return Some(());
        }
    }
    None
}

/// [`RegIo`] over the `.ko`'s synchronous `narf_usb_*` EP0 control path.
///
/// The shared `narf-drivers-wireless-rtl-chip` bring-up (`mac::prepare`, and
/// the PHY/RF/station stages as they move) runs against this adapter in the
/// module build; the builtin driver supplies its own `RegIo` over the native
/// transport. (The firmware download above predates the trait and still uses
/// the free `reg_*`/`ctl_*` helpers, which `UsbRegIo` wraps.)
struct UsbRegIo {
    token: u64,
}

impl RegIo for UsbRegIo {
    // Each width wraps a blocking `narf_usb_*` EP0 control transfer, so the
    // futures are immediately ready; `async fn` satisfies the trait's `+ Send`
    // bound since `UsbRegIo` holds only a `u64` token.
    async fn read8(&mut self, reg: u16) -> Result<u8, ChipError> {
        reg_read8(self.token, reg).ok_or(ChipError::Access)
    }
    async fn read16(&mut self, reg: u16) -> Result<u16, ChipError> {
        reg_read16(self.token, reg).ok_or(ChipError::Access)
    }
    async fn read32(&mut self, reg: u16) -> Result<u32, ChipError> {
        reg_read32(self.token, reg).ok_or(ChipError::Access)
    }
    async fn write8(&mut self, reg: u16, value: u8) -> Result<(), ChipError> {
        reg_write8(self.token, reg, value).ok_or(ChipError::Access)
    }
    async fn write16(&mut self, reg: u16, value: u16) -> Result<(), ChipError> {
        reg_write16(self.token, reg, value).ok_or(ChipError::Access)
    }
    async fn write32(&mut self, reg: u16, value: u32) -> Result<(), ChipError> {
        reg_write32(self.token, reg, value).ok_or(ChipError::Access)
    }
    async fn delay_us(&mut self, us: u32) {
        // Coarse busy delay; the bring-up's real pacing is register readback.
        // The volatile counter keeps the loop from being optimised away.
        let mut spin = 0u32;
        for _ in 0..us.saturating_mul(40) {
            // SAFETY: `spin` is a local; the volatile access blocks DCE.
            unsafe { core::ptr::write_volatile(&mut spin, spin.wrapping_add(1)) };
        }
    }
}

/// Drive a `RegIo` bring-up future to completion synchronously. The module's
/// `RegIo` futures never pend (each wraps a blocking `narf_usb_*` call), so a
/// no-op waker + single poll chain suffices — no allocator, no runtime.
fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    const VT: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VT),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: the vtable's clone returns a valid RawWaker; wake/drop are no-ops.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        core::hint::spin_loop();
    }
}

// ── Freestanding mem intrinsics ─────────────────────────────────────────────
//
// `build-module` extracts only this crate's objects (dropping the
// `compiler_builtins` members), and the `nm -u` gate permits only the KSYMTAB
// C-ABI as undefined — so a `.ko` must carry any `memset`/`memcpy` it needs.
// The firmware-page assembly zero-pads a descriptor buffer, which aarch64
// codegen lowers to `memset`. These volatile-loop definitions satisfy it; the
// `write_volatile` prevents LLVM from folding the loop back into a `memset`
// call (self-recursion). Firmware download is not perf-critical.

/// # Safety
/// `dest` names `n` writable bytes.
#[no_mangle]
unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: `i < n` and the caller guarantees `n` writable bytes.
        unsafe { core::ptr::write_volatile(dest.add(i), c as u8) };
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` and `src` name `n` writable/readable bytes and do not overlap.
#[no_mangle]
unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: `i < n`; caller guarantees the ranges and non-overlap.
        unsafe { core::ptr::write_volatile(dest.add(i), core::ptr::read(src.add(i))) };
        i += 1;
    }
    dest
}

// ── TX descriptor + reserved-page firmware write ────────────────────────────

/// `usb::descriptor`/`fill_checksum` for a reserved-page BEACON firmware write.
///
/// Returned as an explicit element literal (not a zero-filled `[0u8; N]`) so
/// the `.ko` emits no `memset`. Only W0 (bytes 0..4) and W1 (4..8) are nonzero
/// in the first 32 bytes, so the word-7 XOR checksum is computed arithmetically
/// instead of by scanning the buffer.
fn beacon_descriptor(size: u16) -> [u8; TX_DESC] {
    // W0: TXPKTSIZE | OFFSET(TX_DESC) << 16 | LS << 26.
    let w0 = u32::from(size) | (TX_DESC as u32) << 16 | 1 << 26;
    // W1: QSEL(BEACON) << 8 (BEACON is not QSEL_HIGH, so no MORE_DATA).
    let w1 = u32::from(QSEL_BEACON & 0x1f) << 8;
    // `fill_checksum` XORs the eight u16 halves of bytes 0..32; only W0/W1 are
    // nonzero (word-7's low 16 bits start at zero), so the sum is their halves.
    let sum = (w0 as u16) ^ ((w0 >> 16) as u16) ^ (w1 as u16) ^ ((w1 >> 16) as u16);
    let [a, b, c, d] = w0.to_le_bytes();
    let [e, f, g, h] = w1.to_le_bytes();
    let [s0, s1] = sum.to_le_bytes();
    [
        a, b, c, d, e, f, g, h, // bytes 0..8  (W0, W1)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // bytes 8..28 (20)
        s0, s1, 0, 0, // bytes 28..32 (word-7: checksum low 16, high 16 = 0)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // bytes 32..48 (16)
    ]
}

/// `usb_firmware.rs::page`: write one reserved-page firmware chunk (`want`
/// bytes, ≤ one page, read straight from the firmware `handle` at `blob_off`)
/// to the BEACON pipe and wait for a fresh BCN_VALID receipt.
///
/// The packet is assembled in an uninitialised buffer — the descriptor is
/// written in place and the firmware body is copied by the kernel directly
/// into the buffer via `narf_firmware_read` — so the `.ko` emits no `memset`
/// or `memcpy` (`build-module` drops the `compiler_builtins` mem objects).
fn write_page(token: u64, ep: u8, handle: u64, blob_off: u32, want: usize) -> Option<()> {
    let beacon = reg_read8(token, 0x550)?;
    reg_write16(token, 0x204, 1 << 15)?;
    if reg_read16(token, 0x204)? & 1 << 15 != 0 {
        return None;
    }
    let cr = reg_read8(token, 0x101)?;
    reg_write8(token, 0x101, cr | 1)?;
    reg_write8(token, 0x550, beacon & !8 | 16)?;

    // `usb::reserved_page_packet`: descriptor + data, grown by one pad byte
    // when descriptor+payload is a 512-byte multiple.
    let mut size = want;
    if (size + TX_DESC) & 511 == 0 {
        size += 1;
    }
    let total = TX_DESC + size;
    if want > FW_PAGE || total > TX_DESC + FW_PAGE + 1 {
        return None;
    }
    let mut packet = core::mem::MaybeUninit::<[u8; TX_DESC + FW_PAGE + 1]>::uninit();
    let base = packet.as_mut_ptr().cast::<u8>();
    let desc = beacon_descriptor(size as u16);
    // SAFETY: `base` owns TX_DESC+FW_PAGE+1 bytes; `desc` is TX_DESC bytes; the
    // const-size copy inlines (no `memcpy`).
    unsafe { core::ptr::copy_nonoverlapping(desc.as_ptr(), base, TX_DESC) };
    let mut got = 0usize;
    // SAFETY: `base + TX_DESC` is writable for `want` (< buffer); `got` writable.
    let rc = unsafe {
        narf_firmware_read(
            handle,
            u64::from(blob_off),
            base.add(TX_DESC),
            want,
            &mut got,
        )
    };
    if rc != 0 || got != want {
        return None;
    }
    if size > want {
        // SAFETY: single pad byte inside the buffer.
        unsafe { base.add(TX_DESC + want).write(0) };
    }
    // SAFETY: bytes [0, total) are all initialised (descriptor + body + pad).
    let packet = unsafe { core::slice::from_raw_parts(base, total) };
    if !bulk_out(token, ep, packet) {
        return None;
    }
    // BCN_VALID (REG_FIFOPAGE_CTRL_2 bit 15) proves the page landed.
    reg_poll32(token, 0x204, 1 << 15, 1 << 15)
}

/// `firmware_transport.rs::section`: DDMA one firmware section's body (streamed
/// from the firmware handle in page-sized chunks) to chip memory `address`.
fn write_section(token: u64, ep: u8, handle: u64, section: &FwSection) -> Option<()> {
    let control = reg_read32(token, 0x1208)?;
    if control == u32::MAX {
        return None;
    }
    reg_write32(token, 0x1208, control | 1 << 25)?;
    let mut done = 0u32;
    let mut part = 0u32;
    while done < section.len {
        let want = (section.len - done).min(FW_PAGE as u32) as usize;
        write_page(token, ep, handle, section.blob_off + done, want)?;
        reg_poll32(token, 0x1208, 1 << 31, 0)?;
        let control = 1 << 31 | 1 << 29 | if part != 0 { 1 << 24 } else { 0 } | want as u32;
        reg_write32(token, 0x1200, 0x1878_0000 + 48)?;
        reg_write32(token, 0x1204, section.address + part * FW_PAGE as u32)?;
        reg_write32(token, 0x1208, control)?;
        reg_poll32(token, 0x1208, 1 << 31, 0)?;
        done += want as u32;
        part += 1;
    }
    let control = reg_read8(token, 0x80)?;
    if reg_read32(token, 0x1208)? & 1 << 27 != 0 {
        return None; // checksum
    }
    let bits = if section.address < 0x200000 {
        0x18
    } else {
        0x60
    };
    reg_write8(token, 0x80, control | bits)
}

/// `firmware_transport.rs::run`: bring the 8051 down, DDMA every section, then
/// release the MCU and wait for the firmware-ready report.
fn run_download(
    token: u64,
    ep: u8,
    handle: u64,
    sections: &[FwSection; 3],
    count: usize,
) -> Option<()> {
    // CPU down (`cpu(false)`): clear FEN_CPUEN then SYS_FUNC_EN FWDL.
    reg_update8(token, 3, 4, 0)?;
    reg_update8(token, 0x1d, 1, 0)?;
    // Download-enable preamble (`run`): toggle MCUFWDL + checksum init.
    reg_update8(token, 0x1082, 1, 0)?;
    reg_update8(token, 9, 0x40, 0)?;
    reg_update8(token, 0x1082, 0, 1)?;
    reg_update8(token, 9, 0, 0x40)?;
    let control = reg_read16(token, 0x80)? & 0x3800 | 1;
    reg_write16(token, 0x80, control)?;
    for section in &sections[..count] {
        write_section(token, ep, handle, section)?;
    }
    reg_write32(token, 0x210, 4)?;
    let control = reg_read16(token, 0x80)?;
    if control & 0x50 != 0x50 {
        return None; // checksum report
    }
    reg_write16(token, 0x80, (control | 1 << 14) & !1)?;
    // CPU up (`cpu(true)`): SYS_FUNC_EN FWDL then FEN_CPUEN.
    reg_update8(token, 0x1d, 0, 1)?;
    reg_update8(token, 3, 0, 4)?;
    // Firmware-ready report; a timeout here (`Error::Ready`) is tolerated.
    let _ = reg_poll32(token, 0x80, 0xffff & !0x3000, 0xc078);
    // Close the MAC/DMA gates (`finish_dma`).
    let cr = reg_read8(token, 0x100)?;
    reg_write8(token, 0x100, cr & !0xcf)?;
    for register in [0xb0, 0xb8, 0x10b8] {
        reg_write32(token, register, 0)?;
    }
    Some(())
}

/// Fetch the chip firmware through `narf_firmware_*`, validate the header, and
/// DDMA every section to the chip over `narf_usb_*`. Returns true once the
/// firmware-ready gate is closed.
fn firmware_download(dev: &Device) -> bool {
    let did = dev.did.load(Ordering::Acquire) as u16;
    let token = dev.token.load(Ordering::Acquire);
    let ep = dev.bulk_out.load(Ordering::Acquire) as u8;
    let Some(name) = fw_name(did) else {
        return false;
    };
    let mut handle = 0u64;
    let mut size = 0usize;
    // SAFETY: `name` is 'static readable; `handle`/`size` are writable.
    if unsafe { narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) } != 0 {
        return false;
    }
    let ok = (|| {
        let mut header = [0u8; FW_HEADER];
        let mut got = 0usize;
        // SAFETY: `header` is writable for its length; `got` writable.
        let rc =
            unsafe { narf_firmware_read(handle, 0, header.as_mut_ptr(), header.len(), &mut got) };
        if rc != 0 || got < FW_HEADER {
            return false;
        }
        let mut sections = [FwSection::default(); 3];
        let Ok((version, count)) = parse_fw_header(did, &header, size, &mut sections) else {
            return false;
        };
        dev.fw_version.store(u32::from(version), Ordering::Release);
        run_download(token, ep, handle, &sections, count).is_some()
    })();
    // SAFETY: `handle` came from the matching open above.
    let close = unsafe { narf_firmware_close(handle) };
    ok && close == 0
}

/// Run the shared MAC/FIFO bring-up (`mac::prepare`) over the module's
/// synchronous [`UsbRegIo`] once the firmware is downloaded. The queue/page
/// rows come from the bulk-out pipe count; the burst defaults to High — the
/// `narf_usb_*` C-ABI does not expose the enumerated device speed, and High is
/// the common case for these dongles (a wrong burst only detunes RX DMA
/// aggregation, it does not break bring-up).
fn mac_up(dev: &Device) -> bool {
    /// `rtw_usb_init_burst_pkt_len` selector for a High-speed device.
    const BURST_HIGH: u8 = 1;
    let did = dev.did.load(Ordering::Acquire) as u16;
    let token = dev.token.load(Ordering::Acquire);
    let bulkout = dev.bulk_out_count.load(Ordering::Acquire) as usize;
    let Some(params) = chip_mac::usb_mac_params(did, bulkout, BURST_HIGH) else {
        return false;
    };
    let mut io = UsbRegIo { token };
    block_on(chip_mac::prepare(&mut io, did, params)).is_ok()
}

extern "C" fn on_event(cookie: u64) -> i32 {
    let slot = (cookie >> 8) as usize;
    let Some(dev) = DEVICES.get(slot) else {
        return EINVAL;
    };
    if dev.token.load(Ordering::Acquire) == 0 {
        return ENODEV;
    }
    dev.lock();
    if cookie & 0xff == EV_SETUP {
        on_setup(dev, slot);
    }
    dev.unlock();
    0
}

pub fn register() {
    const NAME_8821CU: &[u8] = b"rtw88-8821cu-usb-module";
    const NAME_8822BU: &[u8] = b"rtw88-8822bu-usb-module";
    for (name, ids, probe) in [
        (NAME_8821CU, RTL8821CU_IDS, probe_8821cu as usize),
        (NAME_8822BU, RTL8822BU_IDS, probe_8822bu as usize),
    ] {
        for &(vendor, product) in ids {
            // SAFETY: `name` is 'static; `probe` is a valid extern "C" fn; the
            // loader unregisters every match before unmapping this image.
            unsafe {
                narf_register_usb_driver(
                    name.as_ptr(),
                    name.len(),
                    MATCH_VENDOR_PRODUCT,
                    vendor,
                    product,
                    0,
                    0,
                    0,
                    probe,
                );
            }
        }
    }
}
