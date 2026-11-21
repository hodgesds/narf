//! Stage 1 of the rtw88-USB loadable-module datapath — enumerate + Realtek
//! control proof. See `drivers/wireless/specification/rtw88-usb-module-datapath.md`.
//!
//! `probe_c` drives a real rtw88 USB device entirely through the `narf_usb_*`
//! C-ABI (no kernel crates, so the `.ko`'s undefined-symbol set stays within
//! the exported ABI): it fetches the configuration descriptor, configures the
//! first interface's bulk IN/OUT endpoints, then reads the chip's
//! `REG_SYS_CFG1` via the Realtek vendor control request (`bmRequestType 0xC0`,
//! `bRequest 0x05`, `wValue = addr`). Reaching the `UP` stage with a plausible
//! chip-config word proves the module speaks to the device.
//!
//! Firmware download, MAC/PHY/IQK/station bring-up, netdev publication and the
//! cfg80211 control plane are later stages. Firmware in particular needs a
//! `narf_firmware_*` blob-fetch export that does not exist yet.
//!
//! The state machine mirrors `drivers/usb/ftdi` (one outstanding URB per
//! device, advanced from the `on_event` completion callback under a per-device
//! busy lock).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;

/// Realtek vendor control: IN request type and the register command request
/// (`narf_drivers_wireless_rtl_usb::{REALTEK_USB_READ, REALTEK_USB_CMD_REQ}`).
const REALTEK_USB_READ: u8 = 0xC0;
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
const ST_FAILED: u32 = 0xff;
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

/// Validate the 64-byte rtw88 firmware header for `did` against the total blob
/// `size`, returning the firmware version. A faithful header-level port of
/// `firmware_transport.rs::parse` (section OCP bases/sizes + checksum trailers
/// must exactly span the blob); it does not copy the section bodies.
fn parse_fw_header(did: u16, header: &[u8], size: usize) -> Result<u16, ()> {
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
    // (kind base, limit, size-field, address-field, enabled)
    let plan = [
        (0x20_0000u32, 0x30_0000u32, 0x24usize, 0x20usize, true),
        (imem_base, 0x10_0000, 0x30, 0x3c, true),
        (0x10_0000, 0x20_0000, 0x34, 0x38, has_emem),
    ];
    let mut offset = FW_HEADER;
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
        offset = offset.checked_add(length as usize).ok_or(())?;
    }
    // The header's sections + checksums must span exactly the blob.
    if offset != size {
        return Err(());
    }
    Ok(u16::from_le_bytes([header[4], header[5]]))
}

/// One claimed USB device's enumerate state. One outstanding URB at a time,
/// serialised by `busy`.
struct Device {
    token: AtomicU64,
    busy: AtomicBool,
    stage: AtomicU32,
    bulk_in: AtomicU32,
    bulk_out: AtomicU32,
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

/// Find the first interface's bulk IN and OUT endpoints. Returns
/// `(bConfigurationValue, bulk_in, bulk_out)`. Slice patterns + `split_at`
/// only — no indexing that could panic.
fn parse_config(cfg: &[u8]) -> Option<(u8, u8, u8)> {
    let &[_, 0x02, _, _, _, config_value, ..] = cfg else {
        return None;
    };
    let (mut bulk_in, mut bulk_out) = (0u8, 0u8);
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
                    if address & 0x80 != 0 && bulk_in == 0 {
                        bulk_in = address;
                    } else if address & 0x80 == 0 && bulk_out == 0 {
                        bulk_out = address;
                    }
                }
            }
            _ => {}
        }
        rest = tail;
    }
    (bulk_in != 0 && bulk_out != 0).then_some((config_value, bulk_in, bulk_out))
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
    let Some((config_value, bulk_in, bulk_out)) = parse_config(cfg) else {
        dev.token.store(0, Ordering::Release);
        return EIO;
    };
    dev.config_value
        .store(u32::from(config_value), Ordering::Relaxed);
    dev.bulk_in.store(u32::from(bulk_in), Ordering::Relaxed);
    dev.bulk_out.store(u32::from(bulk_out), Ordering::Relaxed);

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
            // Enumeration proven; fetch + validate the firmware blob. The
            // `narf_firmware_*` calls are synchronous (no URB), so this runs
            // inline on this completion.
            if fetch_and_parse_firmware(dev) {
                dev.stage.store(ST_FW_PARSED, Ordering::Release);
            } else {
                dev.stage.store(ST_FAILED, Ordering::Release);
            }
        }
        _ => {}
    }
}

/// Fetch this chip's firmware through the `narf_firmware_*` ABI and validate
/// its header. The section-download to the chip (cpu reset, download-enable,
/// reserved-page bulk writes, checksum) is the next sub-stage.
fn fetch_and_parse_firmware(dev: &Device) -> bool {
    let did = dev.did.load(Ordering::Acquire) as u16;
    let Some(name) = fw_name(did) else {
        return false;
    };
    let mut handle = 0u64;
    let mut size = 0usize;
    // SAFETY: `name` is 'static readable; `handle`/`size` are writable.
    let rc = unsafe { narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
    if rc != 0 {
        return false;
    }
    let mut header = [0u8; FW_HEADER];
    let mut got = 0usize;
    // SAFETY: `header` is writable for its length; `got` is writable.
    let rc = unsafe { narf_firmware_read(handle, 0, header.as_mut_ptr(), header.len(), &mut got) };
    // SAFETY: `handle` came from the matching open above.
    let close = unsafe { narf_firmware_close(handle) };
    if rc != 0 || got < FW_HEADER || close != 0 {
        return false;
    }
    match parse_fw_header(did, &header, size) {
        Ok(version) => {
            dev.fw_version.store(u32::from(version), Ordering::Release);
            true
        }
        Err(()) => false,
    }
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
