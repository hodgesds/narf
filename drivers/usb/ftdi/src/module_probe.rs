//! Loadable FTDI USB-serial driver over the USB datapath C-ABI.
//!
//! The `.ko` half of this crate. It holds only an opaque device token and
//! request ids; every transfer goes through the `narf_usb_*` KSYMTAB
//! exports, and every step of the driver runs in a completion callback the
//! kernel calls in task context, in the module's own isolation domain.
//!
//! Per device:
//!
//! 1. **probe** reads the probed configuration descriptor, finds the first
//!    interface's bulk IN/OUT pair, and reads the device descriptor
//!    (control IN) to learn the part and so its baud clock.
//! 2. **bring-up**, one request per completion: endpoint configuration,
//!    SET_CONFIGURATION, FTDI reset, 115200 baud, 8N1, DTR+RTS, no flow
//!    control. Same values the built-in driver programs (`crate::codec`).
//! 3. **run**: publish `/dev/ttyUSB<N>`; keep one bulk-IN posted, strip the
//!    two FTDI status bytes and hand the payload to the node's readers;
//!    on every writer kick or TX completion, move queued bytes to bulk-OUT.
//!
//! A module build links ONLY KSYMTAB imports (xtask's `nm -u` gate), so
//! there is no allocator here: device state is a fixed table of atomics.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::codec;

const FTDI_VID: u16 = 0x0403;
/// Single-interface parts this module drives: FT232BM/R (QEMU's
/// `usb-serial`), FT-X, FT232H. Multi-port FT2232H/FT4232H stay built-in.
const PIDS: &[u16] = &[0x6001, 0x6015, 0x6014];
/// The one H-series (120 MHz baud clock) part in [`PIDS`].
const PID_FT232H: u16 = 0x6014;

const NAME: &[u8] = b"ftdi_sio-module";
const BAUD: u32 = 115_200;
/// `(wValue, wIndex)` for SET_BAUD_RATE, folded at compile time (the `.ko`
/// carries no out-of-line division helpers).
const BAUD_BM: (u16, u16) = codec::divisor_to_wvalue_windex(codec::calc_divisor_bm(BAUD), 0);
const BAUD_H: (u16, u16) = codec::divisor_to_wvalue_windex(codec::calc_divisor_h(BAUD), 0);
/// `narf_usb_serial_register` family code for `ftdi_sio`.
const FAMILY_FTDI: u32 = 1;
/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;
/// Standard `SET_CONFIGURATION`.
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;
/// Standard `GET_DESCRIPTOR`, and the DEVICE descriptor type.
const STD_REQ_GET_DESCRIPTOR: u8 = 0x06;
const DESC_DEVICE: u8 = 0x01;
const DEVICE_DESC_LEN: usize = 18;

const EAGAIN: i32 = -11;
const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const ENOSPC: i32 = -28;

const MAX_DEVICES: usize = 8;
/// Largest configuration descriptor this driver parses.
const CONFIG_BUF: usize = 512;
/// Bulk transfer size: one full-speed packet.
const PACKET: usize = 64;

// Cookie = (device slot << 8) | event.
const EV_SETUP: u64 = 1;
const EV_RX: u64 = 2;
const EV_TX: u64 = 3;
const EV_KICK: u64 = 4;

/// Bring-up steps, in order. `stage` names the request in flight.
const ST_DEVICE_DESC: u32 = 1;
const ST_CONFIGURE: u32 = 2;
const ST_SET_CONFIG: u32 = 3;
const ST_RESET: u32 = 4;
const ST_BAUD: u32 = 5;
const ST_DATA: u32 = 6;
const ST_MODEM: u32 = 7;
const ST_FLOW: u32 = 8;
const ST_RUNNING: u32 = 9;
const ST_FAILED: u32 = 0xff;

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
    fn narf_usb_serial_register(
        dev: u64,
        family: u32,
        kick: usize,
        cookie: u64,
        out_port: *mut u32,
    ) -> i32;
    fn narf_usb_serial_tx(
        dev: u64,
        port: u32,
        buf: *mut u8,
        len: usize,
        out_len: *mut usize,
    ) -> i32;
    fn narf_usb_serial_rx(dev: u64, port: u32, data: *const u8, len: usize) -> i32;
}

struct Device {
    token: AtomicU64,
    /// Serialises this device's callbacks (writer kicks can race the pump).
    busy: AtomicBool,
    stage: AtomicU32,
    config_value: AtomicU32,
    bulk_in: AtomicU32,
    bulk_out: AtomicU32,
    h_series: AtomicBool,
    port: AtomicU32,
    setup_urb: AtomicU64,
    rx_urb: AtomicU64,
    tx_urb: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
}

impl Device {
    const fn new() -> Self {
        Self {
            token: AtomicU64::new(0),
            busy: AtomicBool::new(false),
            stage: AtomicU32::new(0),
            config_value: AtomicU32::new(0),
            bulk_in: AtomicU32::new(0),
            bulk_out: AtomicU32::new(0),
            h_series: AtomicBool::new(false),
            port: AtomicU32::new(0),
            setup_urb: AtomicU64::new(0),
            rx_urb: AtomicU64::new(0),
            tx_urb: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
        }
    }

    fn lock(&self) {
        while self
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.busy.store(false, Ordering::Release);
    }
}

static DEVICES: [Device; MAX_DEVICES] = [const { Device::new() }; MAX_DEVICES];

fn log(msg: &[u8]) {
    // SAFETY: `msg` is a live, readable byte slice for the call.
    unsafe {
        narf_printk(msg.as_ptr(), msg.len());
    }
}

/// `prefix` + decimal `value` + `suffix`, without an allocator.
///
/// Three console writes rather than one assembled line: this code is linked
/// alone into the `.ko`, so it avoids anything (slice copies, range
/// indexing) that would compile to an out-of-line `memcpy` or `core` panic
/// path the loader cannot resolve.
fn log_num(prefix: &[u8], value: u64, suffix: &[u8]) {
    let mut digits = [b'0'; 20];
    let mut first = digits.len();
    let mut v = value;
    for slot in digits.iter_mut().rev() {
        *slot = b'0' + (v % 10) as u8;
        first -= 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    log(prefix);
    if let Some(number) = digits.get(first..) {
        log(number);
    }
    log(suffix);
}

fn cookie(slot: usize, event: u64) -> u64 {
    ((slot as u64) << 8) | event
}

/// Find the first interface's bulk IN and OUT endpoints. Returns
/// `(bConfigurationValue, bulk_in, bulk_out)`. Slice patterns and `get`
/// only: no indexing that could panic.
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

extern "C" fn probe_c(dev_token: u64, _reserved: u64) -> i32 {
    // Uninitialised on purpose (no `memset` in the `.ko`): the kernel writes
    // `cfg_len` bytes and only those are read.
    let mut cfg = core::mem::MaybeUninit::<[u8; CONFIG_BUF]>::uninit();
    let mut cfg_len = 0usize;
    // SAFETY: `cfg` is writable for CONFIG_BUF bytes; `cfg_len` is writable.
    let rc = unsafe {
        narf_usb_config_descriptor(dev_token, cfg.as_mut_ptr().cast(), CONFIG_BUF, &mut cfg_len)
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
            .compare_exchange(0, dev_token, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return ENOSPC;
    };
    dev.config_value
        .store(u32::from(config_value), Ordering::Relaxed);
    dev.bulk_in.store(u32::from(bulk_in), Ordering::Relaxed);
    dev.bulk_out.store(u32::from(bulk_out), Ordering::Relaxed);
    dev.rx_urb.store(0, Ordering::Relaxed);
    dev.tx_urb.store(0, Ordering::Relaxed);
    dev.rx_bytes.store(0, Ordering::Relaxed);
    dev.tx_bytes.store(0, Ordering::Relaxed);
    dev.h_series.store(false, Ordering::Relaxed);
    // Hold the device lock across submit: the completion may run on another
    // CPU before `submit_setup` has recorded the request id.
    dev.lock();
    let rc = submit_setup(dev, slot, ST_DEVICE_DESC);
    dev.unlock();
    if rc != 0 {
        dev.stage.store(0, Ordering::Release);
        dev.token.store(0, Ordering::Release);
        return rc;
    }
    0
}

/// Submit the control request for bring-up stage `stage`.
fn submit_setup(dev: &Device, slot: usize, stage: u32) -> i32 {
    let token = dev.token.load(Ordering::Acquire);
    let mut urb = 0u64;
    if stage == ST_CONFIGURE {
        let endpoints = [
            dev.bulk_in.load(Ordering::Relaxed) as u8,
            dev.bulk_out.load(Ordering::Relaxed) as u8,
        ];
        // SAFETY: `endpoints` is readable for its length, `urb` is
        // writable, and `on_event` stays mapped until unload retires this
        // device's context.
        let rc = unsafe {
            narf_usb_configure(
                token,
                endpoints.as_ptr(),
                endpoints.len(),
                on_event as usize,
                cookie(slot, EV_SETUP),
                &mut urb,
            )
        };
        if rc == 0 {
            dev.stage.store(stage, Ordering::Release);
            dev.setup_urb.store(urb, Ordering::Release);
        }
        return rc;
    }
    let mut length = 0u16;
    let (request_type, request, value, index) = match stage {
        ST_DEVICE_DESC => {
            length = DEVICE_DESC_LEN as u16;
            (0x80, STD_REQ_GET_DESCRIPTOR, u16::from(DESC_DEVICE) << 8, 0)
        }
        ST_SET_CONFIG => (
            0x00,
            STD_REQ_SET_CONFIGURATION,
            dev.config_value.load(Ordering::Relaxed) as u16,
            0,
        ),
        // wValue 0 = reset SIO (purge both FIFOs and the line state).
        ST_RESET => (codec::RT_HOST_TO_DEV, codec::REQ_RESET, 0, 0),
        ST_BAUD => {
            let (value, index) = if dev.h_series.load(Ordering::Relaxed) {
                BAUD_H
            } else {
                BAUD_BM
            };
            (
                codec::RT_HOST_TO_DEV,
                codec::REQ_SET_BAUD_RATE,
                value,
                index,
            )
        }
        // 8 data bits, no parity, one stop bit.
        ST_DATA => (
            codec::RT_HOST_TO_DEV,
            codec::REQ_SET_DATA,
            8 | codec::DATA_PARITY_NONE | codec::DATA_STOP_BITS_1,
            0,
        ),
        ST_MODEM => (
            codec::RT_HOST_TO_DEV,
            codec::REQ_MODEM_CTRL,
            codec::encode_modem_ctrl(true, true),
            0,
        ),
        ST_FLOW => (
            codec::RT_HOST_TO_DEV,
            codec::REQ_SET_FLOW_CTRL,
            0,
            codec::FLOW_DISABLE,
        ),
        _ => return EINVAL,
    };
    let [v0, v1] = value.to_le_bytes();
    let [i0, i1] = index.to_le_bytes();
    let [l0, l1] = length.to_le_bytes();
    let setup = [request_type, request, v0, v1, i0, i1, l0, l1];
    // SAFETY: `setup` names 8 readable bytes; IN or no data stage, so no
    // data pointer; `urb` is writable; `on_event` stays mapped until unload.
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
        dev.stage.store(stage, Ordering::Release);
        dev.setup_urb.store(urb, Ordering::Release);
    }
    rc
}

fn on_setup(dev: &Device, slot: usize) {
    let token = dev.token.load(Ordering::Acquire);
    let stage = dev.stage.load(Ordering::Acquire);
    if !(ST_DEVICE_DESC..ST_RUNNING).contains(&stage) {
        return;
    }
    let mut desc = [0u8; DEVICE_DESC_LEN];
    let mut n = 0usize;
    // SAFETY: `desc` is writable for its length (only the device
    // descriptor request returns data); `n` is writable.
    let status = unsafe {
        narf_usb_poll(
            token,
            dev.setup_urb.load(Ordering::Acquire),
            desc.as_mut_ptr(),
            desc.len(),
            &mut n,
        )
    };
    if status == EAGAIN {
        return;
    }
    if status != 0 {
        dev.stage.store(ST_FAILED, Ordering::Release);
        log_num(b"ftdi_sio: bring-up step ", u64::from(stage), b" failed\n");
        return;
    }
    if stage == ST_DEVICE_DESC {
        if n < DEVICE_DESC_LEN || u16::from_le_bytes([desc[8], desc[9]]) != FTDI_VID {
            dev.stage.store(ST_FAILED, Ordering::Release);
            log(b"ftdi_sio: unexpected device descriptor\n");
            return;
        }
        let pid = u16::from_le_bytes([desc[10], desc[11]]);
        dev.h_series.store(pid == PID_FT232H, Ordering::Relaxed);
    }
    if stage < ST_FLOW {
        if submit_setup(dev, slot, stage + 1) != 0 {
            dev.stage.store(ST_FAILED, Ordering::Release);
            log_num(
                b"ftdi_sio: could not submit step ",
                u64::from(stage + 1),
                b"\n",
            );
        }
        return;
    }
    // Bring-up complete: publish the node and start receiving.
    let mut port = 0u32;
    // SAFETY: `port` is writable; `on_event` stays mapped until unload.
    let rc = unsafe {
        narf_usb_serial_register(
            token,
            FAMILY_FTDI,
            on_event as usize,
            cookie(slot, EV_KICK),
            &mut port,
        )
    };
    if rc != 0 {
        dev.stage.store(ST_FAILED, Ordering::Release);
        log(b"ftdi_sio: serial node registration failed\n");
        return;
    }
    dev.port.store(port, Ordering::Release);
    dev.stage.store(ST_RUNNING, Ordering::Release);
    log_num(
        b"ftdi_sio: module driver bound ttyUSB",
        u64::from(port),
        b"\n",
    );
    submit_rx(dev, slot);
    pump_tx(dev, slot);
}

fn submit_rx(dev: &Device, slot: usize) {
    let token = dev.token.load(Ordering::Acquire);
    let mut urb = 0u64;
    // SAFETY: IN transfer, so no data pointer; `urb` is writable;
    // `on_event` stays mapped until unload.
    let rc = unsafe {
        narf_usb_submit(
            token,
            dev.bulk_in.load(Ordering::Relaxed) as u8,
            core::ptr::null(),
            PACKET,
            on_event as usize,
            cookie(slot, EV_RX),
            &mut urb,
        )
    };
    dev.rx_urb
        .store(if rc == 0 { urb } else { 0 }, Ordering::Release);
}

fn on_rx(dev: &Device, slot: usize) {
    let token = dev.token.load(Ordering::Acquire);
    let urb = dev.rx_urb.load(Ordering::Acquire);
    if urb == 0 {
        return;
    }
    let mut packet = core::mem::MaybeUninit::<[u8; PACKET]>::uninit();
    let mut n = 0usize;
    // SAFETY: `packet` is writable for PACKET bytes; `n` is writable.
    let status = unsafe { narf_usb_poll(token, urb, packet.as_mut_ptr().cast(), PACKET, &mut n) };
    if status == EAGAIN {
        return;
    }
    dev.rx_urb.store(0, Ordering::Release);
    if status == ENODEV {
        return; // Detached: the kernel retired the context.
    }
    if status == 0 {
        // SAFETY: a successful poll initialised the first `n <= PACKET` bytes.
        let packet =
            unsafe { core::slice::from_raw_parts(packet.as_ptr().cast::<u8>(), n.min(PACKET)) };
        if let Some((_modem, _line, payload)) = codec::split_rx_packet(packet) {
            if !payload.is_empty() {
                // SAFETY: `payload` is a live readable slice of `packet`.
                let accepted = unsafe {
                    narf_usb_serial_rx(
                        token,
                        dev.port.load(Ordering::Acquire),
                        payload.as_ptr(),
                        payload.len(),
                    )
                };
                if accepted > 0 {
                    dev.rx_bytes.fetch_add(accepted as u64, Ordering::Relaxed);
                }
            }
        }
    }
    // Stalls and transaction errors on an idle line are not fatal: repost.
    submit_rx(dev, slot);
}

/// Move queued writer bytes to bulk-OUT if no transmit is in flight.
fn pump_tx(dev: &Device, slot: usize) {
    if dev.stage.load(Ordering::Acquire) != ST_RUNNING || dev.tx_urb.load(Ordering::Acquire) != 0 {
        return;
    }
    let token = dev.token.load(Ordering::Acquire);
    let mut chunk = core::mem::MaybeUninit::<[u8; PACKET]>::uninit();
    let mut n = 0usize;
    // SAFETY: `chunk` is writable for PACKET bytes; `n` is writable.
    let rc = unsafe {
        narf_usb_serial_tx(
            token,
            dev.port.load(Ordering::Acquire),
            chunk.as_mut_ptr().cast(),
            PACKET,
            &mut n,
        )
    };
    if rc != 0 || n == 0 || n > PACKET {
        return;
    }
    let mut urb = 0u64;
    // SAFETY: the kernel initialised `chunk[..n]`; it is copied before
    // return; `urb` is
    // writable; `on_event` stays mapped until unload.
    let rc = unsafe {
        narf_usb_submit(
            token,
            dev.bulk_out.load(Ordering::Relaxed) as u8,
            chunk.as_ptr().cast(),
            n,
            on_event as usize,
            cookie(slot, EV_TX),
            &mut urb,
        )
    };
    if rc == 0 {
        dev.tx_urb.store(urb, Ordering::Release);
    }
}

fn on_tx(dev: &Device, slot: usize) {
    let token = dev.token.load(Ordering::Acquire);
    let urb = dev.tx_urb.load(Ordering::Acquire);
    if urb == 0 {
        return;
    }
    let mut n = 0usize;
    // SAFETY: OUT transfer, no data to copy back; `n` is writable.
    let status = unsafe { narf_usb_poll(token, urb, core::ptr::null_mut(), 0, &mut n) };
    if status == EAGAIN {
        return;
    }
    dev.tx_urb.store(0, Ordering::Release);
    if status == 0 {
        dev.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    if status != ENODEV {
        pump_tx(dev, slot);
    }
}

/// Every completion and writer kick lands here, in task context and in
/// this module's isolation domain.
extern "C" fn on_event(cookie: u64) -> i32 {
    let slot = (cookie >> 8) as usize;
    let Some(dev) = DEVICES.get(slot) else {
        return EINVAL;
    };
    if dev.token.load(Ordering::Acquire) == 0 {
        return ENODEV;
    }
    dev.lock();
    match cookie & 0xff {
        EV_SETUP => on_setup(dev, slot),
        EV_RX => on_rx(dev, slot),
        EV_TX => on_tx(dev, slot),
        EV_KICK => pump_tx(dev, slot),
        _ => {}
    }
    dev.unlock();
    0
}

pub fn register() {
    for &pid in PIDS {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn and
        // the loader unregisters the match before unmapping this image.
        let rc = unsafe {
            narf_register_usb_driver(
                NAME.as_ptr(),
                NAME.len(),
                MATCH_VENDOR_PRODUCT,
                FTDI_VID,
                pid,
                0,
                0,
                0,
                probe_c as usize,
            )
        };
        if rc != 0 {
            log_num(
                b"ftdi_sio: match registration failed for pid ",
                u64::from(pid),
                b"\n",
            );
        }
    }
}
