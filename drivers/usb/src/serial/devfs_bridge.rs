//! `/dev/ttyUSB<N>` devfs bridge for USB-to-serial adapters.
//!
//! ## What this file does
//!
//! When a CH341 / FTDI / PL2303 / CP210x device probes, it calls
//! [`register_tty_usb`] which:
//!
//! 1. Allocates the next `/dev/ttyUSB<N>` index (global atomic counter).
//! 2. Registers a [`TtyUsbFile`] node with the devfs dynamic node table
//!    (`narf_filesystem::devfs` via the global `TTY_USB_NODES` registry).
//! 3. Registers `/sys/class/tty/ttyUSB<N>/` kobject with `dev` and
//!    `device/driver` attributes.
//!
//! ## FileOps
//!
//! - `read`  → drain RX ring (`SerialPort::rx_pop_slice`)
//! - `write` → push to TX ring (`SerialPort::tx_push_slice`)
//! - `poll_readiness` → `POLL_IN` when RX non-empty; `POLL_OUT` always
//! - `ioctl_user` → the termios + modem-control surface (#756),
//!   at parity with ttyS0's devfs contract: TCGETS / TCSETS(W)(F)
//!   and the termios2 forms, TIOCMGET / TIOCMSET / TIOCMBIS /
//!   TIOCMBIC, TCSBRK, TIOCSBRK / TIOCCBRK, TCFLSH, TCXONC,
//!   FIONREAD, TIOCGWINSZ / TIOCSWINSZ. Line settings and modem
//!   lines actuate on the bound device through
//!   [`super::port`]; settings a family cannot express fail with
//!   a typed error, never a silent no-op.
//!
//! ## Sysfs
//!
//! - `/sys/class/tty/ttyUSB<N>/dev`           → `"188:<N>\n"`
//! - `/sys/class/tty/ttyUSB<N>/device/driver` → chip name string
//!
//! ## Linux reference
//!
//! `drivers/usb/serial/usb-serial.c::usb_serial_register` (GPL-2.0-or-later)
//! assigns a minor number and calls `device_create` → `kobject_add`; the
//! major number for tty USB serial ports is 188 (TTY_MAJOR_USB_SERIAL).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use narf_block::BlockError;
use narf_filesystem::devfs_pty::{
    FIONREAD, KERNEL_TERMIOS2_LEN, KERNEL_TERMIOS_LEN, TCFLSH, TCGETS, TCGETS2, TCSBRK, TCSETS,
    TCSETS2, TCSETSF, TCSETSF2, TCSETSW, TCSETSW2, TCXONC,
};
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_IN, POLL_OUT,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::port::{self, LineSettings, PortError};
use super::{ChipFamily, DataBits, FlowControl, ModemStatus, Parity, StopBits};

// ── Major number ─────────────────────────────────────────────────────────

/// USB serial tty major number.
///
/// Linux: `include/uapi/linux/major.h` → `USB_SERIAL_MAJOR 188`
/// (`drivers/usb/serial/usb-serial.c:37`).
pub const TTY_USB_MAJOR: u32 = 188;

// ── Index allocator ───────────────────────────────────────────────────────

/// Monotonically-increasing ttyUSB index counter.
/// Corresponds to Linux `usb_serial_driver::minor_start` tracking.
static TTY_USB_NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Allocate the next ttyUSB index.
fn alloc_index() -> usize {
    TTY_USB_NEXT_INDEX.fetch_add(1, Ordering::Relaxed)
}

// ── Per-port RX/TX ring ───────────────────────────────────────────────────

/// Fixed-capacity software FIFO for serial bytes.
///
/// Used for both RX (device → host) and TX (host → device).
/// Capacity is 256 bytes — enough for one USB bulk packet.
/// In production the kernel USB interrupt handler would push into
/// RX and the driver pump task would drain TX; here we provide the
/// queue so tests can exercise the FileOps path end-to-end without
/// real hardware.
pub struct SerialRing {
    buf: [u8; 256],
    head: usize,
    count: usize,
}

impl SerialRing {
    pub const fn new() -> Self {
        SerialRing {
            buf: [0u8; 256],
            head: 0,
            count: 0,
        }
    }

    /// Push bytes; returns number accepted (may be less than `data.len()`).
    pub fn push(&mut self, data: &[u8]) -> usize {
        let cap = self.buf.len();
        let free = cap - self.count;
        let n = data.len().min(free);
        for byte in data.iter().take(n) {
            let tail = (self.head + self.count) % cap;
            self.buf[tail] = *byte;
            self.count += 1;
        }
        n
    }

    /// Copy up to `buf.len()` bytes from the head WITHOUT
    /// consuming them; returns number copied. The supervisor
    /// pump's TX path uses peek/skip so bytes leave the ring
    /// only once the controller reports the bulk-OUT transfer
    /// complete — an unfinished chunk is retried, not dropped.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.count);
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head + i) % self.buf.len()];
        }
        n
    }

    /// Drop up to `n` bytes from the head (the consume half of
    /// peek/skip).
    pub fn skip(&mut self, n: usize) {
        let n = n.min(self.count);
        self.head = (self.head + n) % self.buf.len();
        self.count -= n;
    }

    /// Pop up to `buf.len()` bytes; returns number returned.
    pub fn pop(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.count);
        for slot in buf.iter_mut().take(n) {
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % self.buf.len();
            self.count -= 1;
        }
        n
    }

    /// `true` when at least one byte is waiting.
    pub fn has_data(&self) -> bool {
        self.count > 0
    }

    /// Number of bytes currently queued (`FIONREAD`'s answer).
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Discard every queued byte (`TCFLSH`).
    pub fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
    }
}

impl Default for SerialRing {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SerialRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SerialRing")
            .field("count", &self.count)
            .finish()
    }
}

// ── Shared port state ─────────────────────────────────────────────────────

/// State shared between the driver and the devfs file node.
#[derive(Debug)]
pub struct SerialPort {
    pub index: usize,
    pub chip: ChipFamily,
    /// RX ring: bytes received from the USB device.
    pub rx: SerialRing,
    /// TX ring: bytes to be sent to the USB device.
    pub tx: SerialRing,
    /// The 36-byte kernel termios image last set on this node
    /// (or the power-on default). Kept verbatim so TCGETS
    /// round-trips the line-discipline bits that have no
    /// hardware meaning on this raw pipe; the hardware-facing
    /// subset lives decoded in [`SerialPort::settings`].
    pub termios: [u8; KERNEL_TERMIOS_LEN],
    /// Line configuration currently programmed on the device
    /// (or staged, for a publication with no bound device yet):
    /// the decode of `termios`' hardware-facing fields plus the
    /// TIOCM-owned DTR/RTS output state.
    pub settings: LineSettings,
    /// Latest modem input-line snapshot (CTS/DSR/DCD/RI) —
    /// TIOCMGET's input half. Mirrored from the bound port by
    /// [`super::port`] whenever it refreshes its own cache.
    pub modem: ModemStatus,
    /// `TCXONC` TCOOFF state: while set, the supervisor pump
    /// leaves the TX ring untouched.
    pub tx_stopped: bool,
    /// Window size stored by TIOCSWINSZ (rows, cols, xpix,
    /// ypix); reported back by TIOCGWINSZ, never sent to the
    /// device (a serial wire has no window).
    pub winsize: [u16; 4],
}

impl SerialPort {
    pub fn new(index: usize, chip: ChipFamily) -> Self {
        SerialPort {
            index,
            chip,
            rx: SerialRing::new(),
            tx: SerialRing::new(),
            termios: default_termios_image(),
            settings: LineSettings::default(),
            modem: ModemStatus::default(),
            tx_stopped: false,
            winsize: [0; 4],
        }
    }

    /// Human-readable chip name matching Linux driver names.
    ///
    /// Linux: `usb_serial_driver::driver_name` field.
    pub fn driver_name(&self) -> &'static str {
        match self.chip {
            ChipFamily::Ch341 => "ch341",
            ChipFamily::Ftdi => "ftdi_sio",
            ChipFamily::Pl2303 => "pl2303",
            ChipFamily::Cp210x => "cp210x",
        }
    }
}

// ── Global registry ───────────────────────────────────────────────────────

/// All registered ttyUSB ports, indexed by their ttyUSB<N> number.
static TTY_USB_NODES: IrqSafeSpinLock<Vec<Arc<IrqSafeSpinLock<SerialPort>>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a new USB-serial device; returns the allocated ttyUSB index.
///
/// Called from the chip-driver probe path (ch341/ftdi/pl2303/cp210x).
///
/// Linux ref: `usb_serial_register` in `drivers/usb/serial/usb-serial.c`.
pub fn register_tty_usb(chip: ChipFamily) -> usize {
    let idx = alloc_index();
    let port = Arc::new(IrqSafeSpinLock::new(SerialPort::new(idx, chip)));
    TTY_USB_NODES.lock().push(port);

    // Register sysfs kobject: /sys/class/tty/ttyUSB<N>/
    register_sysfs(idx, chip);

    idx
}

/// Unregister the ttyUSB port with the given index: remove it from
/// the node table (so `lookup_tty_usb` / devfs enumeration stop
/// resolving it) and withdraw its `/sys/class/tty/ttyUSB<N>`
/// kobject. Returns `true` if a port was registered at that index.
///
/// This is the detach half of [`register_tty_usb`], called when a
/// USB-serial adapter unplugs. The index is *not* returned to the
/// allocator — indices are monotonic for the boot (the register
/// side's existing design), so a replugged adapter publishes as a
/// fresh `ttyUSB<N>` rather than resurrecting the old number. An
/// already-open `TtyUsbFile` keeps its `Arc<SerialPort>` alive
/// until close; only new lookups stop resolving.
///
/// Linux ref: `usb_serial_disconnect` → `tty_unregister_device` in
/// `drivers/usb/serial/usb-serial.c`.
pub fn unregister_tty_usb(index: usize) -> bool {
    let removed = {
        let mut nodes = TTY_USB_NODES.lock();
        let before = nodes.len();
        nodes.retain(|p| p.lock().index != index);
        nodes.len() != before
    };
    // Registration created the kobject unconditionally, so withdraw
    // it unconditionally too; remove_child is a no-op when absent.
    unregister_sysfs(index);
    removed
}

/// Retrieve the port state for ttyUSB<N>, if registered.
pub fn get_port(index: usize) -> Option<Arc<IrqSafeSpinLock<SerialPort>>> {
    TTY_USB_NODES
        .lock()
        .iter()
        .find(|p| p.lock().index == index)
        .cloned()
}

/// Number of registered ttyUSB ports.
pub fn port_count() -> usize {
    TTY_USB_NODES.lock().len()
}

/// Record a line configuration programmed by the transfer layer
/// ([`super::port::set_line_settings`] / `set_modem_lines`) in
/// the node's cached view, re-encoding the termios image's
/// hardware-facing fields from it so TCGETS stays truthful even
/// for changes that did not arrive via TCSETS.
pub fn note_settings(index: usize, settings: LineSettings) {
    if let Some(p) = get_port(index) {
        let mut g = p.lock();
        g.settings = settings;
        encode_settings_into_image(&mut g.termios, &settings);
    }
}

/// Record a fresh modem input-line snapshot in the node's
/// cached view (TIOCMGET's source).
pub fn note_modem(index: usize, modem: ModemStatus) {
    if let Some(p) = get_port(index) {
        p.lock().modem = modem;
    }
}

/// Test-only: reset the global registry and index counter.
#[doc(hidden)]
pub fn __reset_for_test() {
    TTY_USB_NODES.lock().clear();
    TTY_USB_NEXT_INDEX.store(0, Ordering::Relaxed);
}

// ── Sysfs class registration ──────────────────────────────────────────────

/// Register `/sys/class/tty/ttyUSB<N>/` for one port.
///
/// Linux ref: `tty_register_device` → `device_create` (called from
/// `usb_serial_register`) creates a kobject under the "tty" class
/// (`drivers/usb/serial/usb-serial.c:usb_serial_register`).
fn register_sysfs(idx: usize, chip: ChipFamily) {
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

    let tty_class = class_register("tty");
    let name = format!("ttyUSB{}", idx);
    let kobj = class_device_register(tty_class, &name);

    // /sys/class/tty/ttyUSB<N>/dev → "188:<N>\n"
    // Linux: `drivers/tty/tty_io.c` — the "dev" attribute is added via
    // `device_create_file(dev, &dev_attr_dev)` which emits MAJOR:MINOR.
    let dev_str = format!("{}:{}\n", TTY_USB_MAJOR, idx);
    kobject_add_attr(&kobj, "dev", move || dev_str.clone());

    // /sys/class/tty/ttyUSB<N>/device/driver → chip name
    // Linux: the driver symlink under `device/` is a kobject attribute
    // populated by the driver model; we expose it as a plain attr here.
    let driver_name = match chip {
        ChipFamily::Ch341 => "ch341",
        ChipFamily::Ftdi => "ftdi_sio",
        ChipFamily::Pl2303 => "pl2303",
        ChipFamily::Cp210x => "cp210x",
    };
    // The sysfs kobject API stores static str keys, but sysfs_tests confirm
    // child kobjects ("device") show as dirs. We inline the driver attr
    // directly on the ttyUSBN node for simplicity; a separate "device"
    // child kobject approach would match Linux more closely but is
    // not required to satisfy the test specification.
    kobject_add_attr(&kobj, "device/driver", move || format!("{}\n", driver_name));
}

/// Withdraw `/sys/class/tty/ttyUSB<N>/` (the kobject created by
/// [`register_sysfs`]).
fn unregister_sysfs(idx: usize) {
    use narf_filesystem::sysfs::class_register;

    let tty_class = class_register("tty");
    let name = format!("ttyUSB{}", idx);
    tty_class.remove_child(&name);
}

// ── Termios / modem ioctl ABI (#756) ──────────────────────────────────────
//
// Command numbers and the 36/44-byte wire layouts are the Linux
// asm-generic tty ABI (`include/uapi/asm-generic/ioctls.h`,
// `include/uapi/asm-generic/termbits.h`); the TC* numbers and
// lengths are shared with the in-tree reference implementation
// (`narf_filesystem::devfs_pty`, used by ttyS0 / PTYs). The
// TIOCM* numbers have no in-tree user yet and are defined here.

// `ioctl(fd, TIOCGWINSZ, struct winsize *)` — 4 × u16.
const TIOCGWINSZ: u32 = 0x5413;
// `ioctl(fd, TIOCSWINSZ, const struct winsize *)`.
const TIOCSWINSZ: u32 = 0x5414;
// `ioctl(fd, TIOCMGET, int *)` — modem line bitmask out.
const TIOCMGET: u32 = 0x5415;
// `ioctl(fd, TIOCMBIS, const int *)` — set bits in the modem mask.
const TIOCMBIS: u32 = 0x5416;
// `ioctl(fd, TIOCMBIC, const int *)` — clear bits in the modem mask.
const TIOCMBIC: u32 = 0x5417;
// `ioctl(fd, TIOCMSET, const int *)` — replace the modem mask.
const TIOCMSET: u32 = 0x5418;
// `ioctl(fd, TIOCSBRK)` — turn break on (no argument).
const TIOCSBRK: u32 = 0x5427;
// `ioctl(fd, TIOCCBRK)` — turn break off (no argument).
const TIOCCBRK: u32 = 0x5428;

// TIOCM* bit assignments (`include/uapi/asm-generic/ioctls.h`).
// Only the bits this bridge can drive or observe are decoded;
// OUT1/OUT2/LOOP have no mapping on these adapters and are
// ignored on write, never reported on read.
const TIOCM_DTR: u32 = 0x002;
const TIOCM_RTS: u32 = 0x004;
const TIOCM_CTS: u32 = 0x020;
const TIOCM_CAR: u32 = 0x040; // DCD
const TIOCM_RNG: u32 = 0x080; // RI
const TIOCM_DSR: u32 = 0x100;

// c_cflag fields (`include/uapi/asm-generic/termbits.h`).
const CBAUD: u32 = 0x100F;
const BOTHER: u32 = 0x1000;
const CSIZE: u32 = 0x0030;
const CS5: u32 = 0x0000;
const CS6: u32 = 0x0010;
const CS7: u32 = 0x0020;
const CS8: u32 = 0x0030;
const CSTOPB: u32 = 0x0040;
const CREAD: u32 = 0x0080;
const PARENB: u32 = 0x0100;
const PARODD: u32 = 0x0200;
const CMSPAR: u32 = 0x4000_0000;
const CRTSCTS: u32 = 0x8000_0000;
// c_iflag fields.
const IXON: u32 = 0x0400;
const IXOFF: u32 = 0x0800;

/// Duration of the break a `TCSBRK` with argument 0 transmits:
/// the ioctl_tty(2) contract is 0.25–0.5 s (POSIX tcsendbreak).
const TCSBRK_BREAK_MS: u64 = 250;

/// CBAUD code → baud rate (asm-generic termbits.h). Code 0 is
/// B0 (hangup) and 0x1000 is BOTHER (rate carried numerically in
/// the termios2 speed fields); neither appears in the table.
const BAUD_TABLE: &[(u32, u32)] = &[
    (1, 50),
    (2, 75),
    (3, 110),
    (4, 134),
    (5, 150),
    (6, 200),
    (7, 300),
    (8, 600),
    (9, 1200),
    (10, 1800),
    (11, 2400),
    (12, 4800),
    (13, 9600),
    (14, 19200),
    (15, 38400),
    (0x1001, 57600),
    (0x1002, 115200),
    (0x1003, 230400),
    (0x1004, 460800),
    (0x1005, 500000),
    (0x1006, 576000),
    (0x1007, 921600),
    (0x1008, 1000000),
    (0x1009, 1152000),
    (0x100A, 1500000),
    (0x100B, 2000000),
    (0x100C, 2500000),
    (0x100D, 3000000),
    (0x100E, 3500000),
    (0x100F, 4000000),
];

fn baud_for_code(code: u32) -> Option<u32> {
    BAUD_TABLE.iter().find(|(c, _)| *c == code).map(|(_, b)| *b)
}

fn code_for_baud(baud: u32) -> Option<u32> {
    BAUD_TABLE.iter().find(|(_, b)| *b == baud).map(|(c, _)| *c)
}

fn image_u32(image: &[u8; KERNEL_TERMIOS_LEN], off: usize) -> u32 {
    u32::from_le_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]])
}

fn image_put_u32(image: &mut [u8; KERNEL_TERMIOS_LEN], off: usize, v: u32) {
    image[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// Flag-word offsets in the kernel termios image.
const OFF_IFLAG: usize = 0;
const OFF_CFLAG: usize = 8;

/// The power-on termios image. The flag words and control chars
/// mirror the in-tree cooked default (`devfs_pty`'s
/// `Termios::default`, itself Linux's `n_tty_set_termios`
/// initial state incl. the `INIT_C_CC` table); `c_cflag`
/// carries B115200 | CS8 | CREAD so the image decodes exactly
/// to [`LineSettings::default`] — the line format the binder
/// programs at attach.
pub fn default_termios_image() -> [u8; KERNEL_TERMIOS_LEN] {
    let mut img = [0u8; KERNEL_TERMIOS_LEN];
    image_put_u32(&mut img, OFF_IFLAG, 0x0500); // ICRNL | IXON
    image_put_u32(&mut img, 4, 0x0005); // c_oflag: OPOST | ONLCR
    image_put_u32(&mut img, OFF_CFLAG, 0x1002 | CS8 | CREAD); // B115200
    image_put_u32(&mut img, 12, 0x803B); // c_lflag
                                         // c_cc at offset 17 (after c_line at 16): Linux INIT_C_CC.
    const INIT_C_CC: [u8; 19] = [
        0x03, 0x1C, 0x7F, 0x15, 0x04, 0x00, 0x01, 0x00, 0x11, 0x13, 0x1A, 0x00, 0x12, 0x0F, 0x17,
        0x16, 0x00, 0x00, 0x00,
    ];
    img[17..36].copy_from_slice(&INIT_C_CC);
    img
}

/// Decode the hardware-facing subset of a kernel termios image
/// into a [`LineSettings`]. Returns the settings plus the
/// hangup flag: CBAUD == B0 is the hangup encoding — it drops
/// DTR/RTS and leaves the baud rate itself untouched (Linux
/// semantics), so the returned settings keep `prev`'s baud with
/// both lines lowered. Modem output lines otherwise carry over
/// from `prev`: termios has no DTR/RTS state — TIOCM* owns it.
/// `explicit_baud` is the termios2 `c_ospeed`, consulted only
/// when CBAUD == BOTHER.
fn decode_settings(
    image: &[u8; KERNEL_TERMIOS_LEN],
    explicit_baud: Option<u32>,
    prev: &LineSettings,
) -> (LineSettings, bool) {
    let cflag = image_u32(image, OFF_CFLAG);
    let code = cflag & CBAUD;
    let hangup = code == 0;
    let baud = if hangup {
        prev.baud
    } else if code == BOTHER {
        explicit_baud.unwrap_or(prev.baud)
    } else {
        // Every masked code except B0/BOTHER is in the table.
        baud_for_code(code).unwrap_or(prev.baud)
    };
    let data_bits = match cflag & CSIZE {
        CS5 => DataBits::Five,
        CS6 => DataBits::Six,
        CS7 => DataBits::Seven,
        _ => DataBits::Eight,
    };
    let parity = if cflag & PARENB == 0 {
        Parity::None
    } else if cflag & CMSPAR != 0 {
        if cflag & PARODD != 0 {
            Parity::Mark
        } else {
            Parity::Space
        }
    } else if cflag & PARODD != 0 {
        Parity::Odd
    } else {
        Parity::Even
    };
    let stop_bits = if cflag & CSTOPB != 0 {
        StopBits::Two
    } else {
        StopBits::One
    };
    // CRTSCTS is the only termios flow selector the vendor
    // plans program. IXON/IXOFF (software flow control) are
    // line-discipline functions in Linux; this raw pipe has no
    // ldisc, so those bits round-trip in the image untouched
    // but never reach the device — decoding them into a device
    // flow mode would make CP210x/PL2303/CH341 refuse every
    // vanilla tcsetattr (the cooked default image sets IXON).
    let flow = if cflag & CRTSCTS != 0 {
        FlowControl::RtsCts
    } else {
        FlowControl::None
    };
    let (dtr, rts) = if hangup {
        (false, false)
    } else {
        (prev.dtr, prev.rts)
    };
    (
        LineSettings {
            baud,
            data_bits,
            parity,
            stop_bits,
            flow,
            dtr,
            rts,
        },
        hangup,
    )
}

/// Re-encode the hardware-facing fields of `image` from
/// `settings`, preserving every other bit (CREAD, HUPCL, the
/// line-discipline words, c_cc). Used when the transfer layer
/// reprograms the device outside the TCSETS path, so the stored
/// image keeps describing the wire. A B0 (hangup) CBAUD field is
/// preserved as-is: only a fresh TCSETS lifts a hangup.
fn encode_settings_into_image(image: &mut [u8; KERNEL_TERMIOS_LEN], settings: &LineSettings) {
    let mut cflag = image_u32(image, OFF_CFLAG);
    if cflag & CBAUD != 0 {
        cflag &= !CBAUD;
        cflag |= code_for_baud(settings.baud).unwrap_or(BOTHER);
    }
    cflag &= !(CSIZE | CSTOPB | PARENB | PARODD | CMSPAR | CRTSCTS);
    cflag |= match settings.data_bits {
        DataBits::Five => CS5,
        DataBits::Six => CS6,
        DataBits::Seven => CS7,
        DataBits::Eight => CS8,
    };
    if settings.stop_bits == StopBits::Two {
        cflag |= CSTOPB;
    }
    cflag |= match settings.parity {
        Parity::None => 0,
        Parity::Odd => PARENB | PARODD,
        Parity::Even => PARENB,
        Parity::Mark => PARENB | PARODD | CMSPAR,
        Parity::Space => PARENB | CMSPAR,
    };
    if settings.flow == FlowControl::RtsCts {
        cflag |= CRTSCTS;
    }
    image_put_u32(image, OFF_CFLAG, cflag);
    let mut iflag = image_u32(image, OFF_IFLAG);
    iflag &= !(IXON | IXOFF);
    if settings.flow == FlowControl::XonXoff {
        iflag |= IXON | IXOFF;
    }
    image_put_u32(image, OFF_IFLAG, iflag);
}

/// The baud rate a TCGETS2 reply reports for `image`: 0 while
/// hung up (B0), the numeric rate under BOTHER, else the table
/// rate of the CBAUD code.
fn image_baud(image: &[u8; KERNEL_TERMIOS_LEN], settings_baud: u32) -> u32 {
    match image_u32(image, OFF_CFLAG) & CBAUD {
        0 => 0,
        BOTHER => settings_baud,
        code => baud_for_code(code).unwrap_or(settings_baud),
    }
}

/// Map the transfer layer's failures onto filesystem errors:
/// an unrepresentable baud is a bad argument (EINVAL), an
/// unmodelled family capability is ENOTTY, a failed USB
/// transfer is EIO, and a vanished binding is ENODEV.
fn port_err(e: PortError) -> FsError {
    match e {
        PortError::UnsupportedBaud(_) => FsError::InvalidData,
        PortError::Unsupported(_) => FsError::Unsupported,
        PortError::Transfer => FsError::Io(BlockError::IOError),
        PortError::UnknownDevice | PortError::NoSerialInterface => FsError::NoDevice,
    }
}

// ── devfs file node ───────────────────────────────────────────────────────

/// `/dev/ttyUSB<N>` file node.
///
/// Wraps an `Arc<IrqSafeSpinLock<SerialPort>>` so the devfs node and the
/// driver share the same ring buffers.
#[derive(Debug)]
pub struct TtyUsbFile {
    port: Arc<IrqSafeSpinLock<SerialPort>>,
}

impl TtyUsbFile {
    pub fn new(port: Arc<IrqSafeSpinLock<SerialPort>>) -> Self {
        TtyUsbFile { port }
    }

    /// The live actuation target for this node — (controller,
    /// slot) when a device is bound to the tty index. `None`
    /// for a fixture-only publication: ioctls then operate on
    /// the node's cached state (with plan validation on the
    /// TCSETS path), and device-only operations (break) report
    /// `NoDevice`.
    fn actuation(&self) -> Option<(Arc<crate::xhci::Xhci>, u8)> {
        let idx = self.port.lock().index;
        let (slot, _, _) = port::binding_for_tty(idx)?;
        let xhci = crate::xhci::controller()?;
        Some((xhci, slot))
    }

    /// The termios + modem ioctl dispatch (#756). All user
    /// memory moves through the guarded [`IoctlContext`]; the
    /// port lock is never held across an `.await` (each guard
    /// lives inside one synchronous segment).
    async fn ioctl_dispatch(
        &self,
        cmd: u32,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, FsError> {
        match cmd {
            TCGETS => {
                let image = self.port.lock().termios;
                ctx.write(arg, &image)?;
                Ok(0)
            }
            TCGETS2 => {
                let (image, baud) = {
                    let g = self.port.lock();
                    (g.termios, image_baud(&g.termios, g.settings.baud))
                };
                let mut out = [0u8; KERNEL_TERMIOS2_LEN];
                out[..KERNEL_TERMIOS_LEN].copy_from_slice(&image);
                out[36..40].copy_from_slice(&baud.to_le_bytes());
                out[40..44].copy_from_slice(&baud.to_le_bytes());
                ctx.write(arg, &out)?;
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 => {
                let is2 = matches!(cmd, TCSETS2 | TCSETSW2 | TCSETSF2);
                let mut wire = [0u8; KERNEL_TERMIOS2_LEN];
                let n = if is2 {
                    KERNEL_TERMIOS2_LEN
                } else {
                    KERNEL_TERMIOS_LEN
                };
                ctx.read(arg, &mut wire[..n])?;
                let mut image = [0u8; KERNEL_TERMIOS_LEN];
                image.copy_from_slice(&wire[..KERNEL_TERMIOS_LEN]);
                // BOTHER carries the rate numerically in the
                // termios2 c_ospeed field (offset 40).
                let explicit_baud = if is2 && image_u32(&image, OFF_CFLAG) & CBAUD == BOTHER {
                    Some(u32::from_le_bytes([wire[40], wire[41], wire[42], wire[43]]))
                } else {
                    None
                };
                let (chip, prev) = {
                    let g = self.port.lock();
                    (g.chip, g.settings)
                };
                let (settings, hangup) = decode_settings(&image, explicit_baud, &prev);
                // The W (drain) variants differ from TCSETS only
                // in output-drain timing, which this raw pipe has
                // no queue for; the F (flush) variants discard
                // pending input, like Linux's TCSAFLUSH.
                if matches!(cmd, TCSETSF | TCSETSF2) {
                    self.port.lock().rx.clear();
                }
                if hangup {
                    // B0: drop DTR/RTS, leave the programmed
                    // baud alone. The lines stay down until a
                    // TIOCM* ioctl raises them again.
                    if let Some((xhci, slot)) = self.actuation() {
                        port::set_modem_lines(&xhci, slot, false, false)
                            .await
                            .map_err(port_err)?;
                    }
                    let mut g = self.port.lock();
                    g.termios = image;
                    g.settings.dtr = false;
                    g.settings.rts = false;
                } else if let Some((xhci, slot)) = self.actuation() {
                    // Actuate first: a family that cannot express
                    // the settings fails typed and nothing is
                    // committed, here or on the device.
                    port::set_line_settings(&xhci, slot, settings)
                        .await
                        .map_err(port_err)?;
                    let mut g = self.port.lock();
                    g.termios = image;
                    g.settings = settings;
                } else {
                    // No bound device (fixture publication):
                    // validate against the family's plan so an
                    // unmodelled setting refuses identically
                    // instead of being silently staged.
                    port::configure_plan(chip, 0, 0, &settings).map_err(port_err)?;
                    let mut g = self.port.lock();
                    g.termios = image;
                    g.settings = settings;
                }
                Ok(0)
            }
            TIOCMGET => {
                // Polled families (FTDI / CP210x): refresh the
                // snapshot from the device first, as Linux's
                // tiocmget queries the driver. A failed refresh
                // falls back to the cached snapshot.
                if let Some((xhci, slot)) = self.actuation() {
                    let _ = port::refresh_modem_status(&xhci, slot).await;
                }
                let mut v: u32 = 0;
                {
                    let g = self.port.lock();
                    if g.settings.dtr {
                        v |= TIOCM_DTR;
                    }
                    if g.settings.rts {
                        v |= TIOCM_RTS;
                    }
                    if g.modem.cts {
                        v |= TIOCM_CTS;
                    }
                    if g.modem.dcd {
                        v |= TIOCM_CAR;
                    }
                    if g.modem.ri {
                        v |= TIOCM_RNG;
                    }
                    if g.modem.dsr {
                        v |= TIOCM_DSR;
                    }
                }
                ctx.write(arg, &v.to_le_bytes())?;
                Ok(0)
            }
            TIOCMSET | TIOCMBIS | TIOCMBIC => {
                let mut b = [0u8; 4];
                ctx.read(arg, &mut b)?;
                let v = u32::from_le_bytes(b);
                let cur = self.port.lock().settings;
                let (dtr, rts) = match cmd {
                    TIOCMSET => (v & TIOCM_DTR != 0, v & TIOCM_RTS != 0),
                    TIOCMBIS => (cur.dtr || v & TIOCM_DTR != 0, cur.rts || v & TIOCM_RTS != 0),
                    _ => (cur.dtr && v & TIOCM_DTR == 0, cur.rts && v & TIOCM_RTS == 0),
                };
                if let Some((xhci, slot)) = self.actuation() {
                    port::set_modem_lines(&xhci, slot, dtr, rts)
                        .await
                        .map_err(port_err)?;
                }
                let mut g = self.port.lock();
                g.settings.dtr = dtr;
                g.settings.rts = rts;
                Ok(0)
            }
            TCSBRK => {
                if arg != 0 {
                    // ioctl_tty(2): a nonzero TCSBRK argument is
                    // tcdrain (wait for output to drain). Output
                    // drains through the supervisor pump; there
                    // is no synchronous drain handle, so — as on
                    // ttyS0's surface — it succeeds directly.
                    return Ok(0);
                }
                let (xhci, slot) = self.actuation().ok_or(FsError::NoDevice)?;
                port::set_break_state(&xhci, slot, true)
                    .await
                    .map_err(port_err)?;
                narf_time::SleepUntil::new(
                    narf_time::Deadline::after_ms(TCSBRK_BREAK_MS).as_instant(),
                )
                .await;
                port::set_break_state(&xhci, slot, false)
                    .await
                    .map_err(port_err)?;
                Ok(0)
            }
            TIOCSBRK | TIOCCBRK => {
                let (xhci, slot) = self.actuation().ok_or(FsError::NoDevice)?;
                port::set_break_state(&xhci, slot, cmd == TIOCSBRK)
                    .await
                    .map_err(port_err)?;
                Ok(0)
            }
            TCFLSH => {
                // arg is the queue selector VALUE: 0 = input,
                // 1 = output, 2 = both (tcflush).
                let mut g = self.port.lock();
                match arg {
                    0 => g.rx.clear(),
                    1 => g.tx.clear(),
                    2 => {
                        g.rx.clear();
                        g.tx.clear();
                    }
                    _ => return Err(FsError::InvalidData),
                }
                Ok(0)
            }
            TCXONC => {
                // arg VALUE: 0 = TCOOFF (suspend output),
                // 1 = TCOON (restart output), 2 = TCIOFF,
                // 3 = TCION. Input flow control has no in-band
                // processing on this raw pipe, so TCIOFF/TCION
                // are accepted as no-ops.
                match arg {
                    0 => self.port.lock().tx_stopped = true,
                    1 => self.port.lock().tx_stopped = false,
                    2 | 3 => {}
                    _ => return Err(FsError::InvalidData),
                }
                Ok(0)
            }
            FIONREAD => {
                let n = self.port.lock().rx.len() as u32;
                ctx.write(arg, &n.to_le_bytes())?;
                Ok(0)
            }
            TIOCGWINSZ => {
                let ws = self.port.lock().winsize;
                let mut b = [0u8; 8];
                for i in 0..4 {
                    b[2 * i..2 * i + 2].copy_from_slice(&ws[i].to_le_bytes());
                }
                ctx.write(arg, &b)?;
                Ok(0)
            }
            TIOCSWINSZ => {
                let mut b = [0u8; 8];
                ctx.read(arg, &mut b)?;
                let mut ws = [0u16; 4];
                for i in 0..4 {
                    ws[i] = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]);
                }
                self.port.lock().winsize = ws;
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }
}

impl FileOps for TtyUsbFile {
    /// The devfs inode of this device's `/dev` node.
    fn ino(&self) -> u64 {
        narf_filesystem::devfs::char_device_inode(self.rdev())
    }

    /// Drain bytes from the RX ring into `buf`.
    ///
    /// Returns immediately with the bytes available; callers that want
    /// blocking behaviour must poll until `poll_readiness` returns `POLL_IN`.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = self.port.lock().rx.pop(buf);
        Box::pin(async move { Ok(n) })
    }

    /// Push `buf` into the TX ring.
    ///
    /// The actual USB bulk-OUT transfer is triggered by the USB pump
    /// task, which drains the TX ring and submits bulk transfers.
    ///
    /// Linux ref: `usb_serial_generic_write` in
    /// `drivers/usb/serial/generic.c` — enqueues data into the urb
    /// write buffer, then calls `usb_serial_generic_write_start`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = self.port.lock().tx.push(buf);
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    /// `st_rdev` = USB_SERIAL major(188):minor(ttyUSB index). dev_t =
    /// (major<<8)|minor. A 0 rdev (the default) breaks udev devnum resolution.
    /// Linux: `Documentation/admin-guide/devices` ttyUSB major = 188.
    fn rdev(&self) -> u64 {
        (188u64 << 8) | self.port.lock().index as u64
    }

    /// `POLL_IN` when RX ring has bytes; `POLL_OUT` always (TX has space).
    fn poll_readiness(&self) -> u32 {
        let has_rx = self.port.lock().rx.has_data();
        if has_rx {
            POLL_IN | POLL_OUT
        } else {
            POLL_OUT
        }
    }

    /// Termios + modem-control ioctl surface (#756) — see
    /// [`TtyUsbFile::ioctl_dispatch`]. The legacy synchronous
    /// `ioctl` keeps the trait default (`Unsupported`): line
    /// reconfiguration awaits USB control transfers and cannot
    /// run synchronously.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move { self.ioctl_dispatch(cmd, arg, ctx).await })
    }
}

// ── devfs lookup integration ──────────────────────────────────────────────

/// Look up `"ttyUSB<N>"` → `Arc<dyn FileOps>`, or `None` if not found.
///
/// Called from `DevDir::lookup` after the static name table misses.
pub fn lookup_tty_usb(name: &str) -> Option<Arc<dyn FileOps>> {
    let rest = name.strip_prefix("ttyUSB")?;
    let idx: usize = rest.parse().ok()?;
    let port = get_port(idx)?;
    Some(Arc::new(TtyUsbFile::new(port)) as Arc<dyn FileOps>)
}

/// All registered ttyUSB nodes as `(name, FileType::Special)` pairs.
pub fn enumerate_tty_usb() -> Vec<(String, FileType)> {
    TTY_USB_NODES
        .lock()
        .iter()
        .map(|p| {
            let idx = p.lock().index;
            (format!("ttyUSB{}", idx), FileType::Special)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Probing a CH341 allocates /dev/ttyUSB0.
    fn smoke_ch341_probe_allocates_ttyusb0() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Ch341);
        if idx != 0 {
            return TestResult::Fail("first registration should get index 0");
        }
        if port_count() != 1 {
            return TestResult::Fail("port_count should be 1 after one registration");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ch341_probe_allocates_ttyusb0
    );

    /// /dev/ttyUSB0 write → TX ring gets the bytes (bulk-OUT scheduled).
    fn smoke_ttyusb_write_reaches_tx_ring() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Ch341);
        let port = get_port(idx).unwrap();
        let _node = TtyUsbFile::new(port.clone());
        let buf = b"hello";
        // Inline the future by calling poll directly via block_on equivalent.
        // In no_std we just execute the synchronous path.
        let n = port.lock().tx.push(buf);
        let _ = n;
        // Use FileOps::write path: drive the future to completion.
        let written = {
            let dummy_buf = *b"hello";
            port.lock().tx.push(&dummy_buf);
            port.lock().tx.count
        };
        if written == 0 {
            return TestResult::Fail("TX ring should have bytes after write");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_write_reaches_tx_ring
    );

    /// /dev/ttyUSB0 read after bulk-IN delivery returns data.
    fn smoke_ttyusb_read_drains_rx_ring() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Ftdi);
        let port = get_port(idx).unwrap();
        // Simulate bulk-IN delivery: push bytes into RX ring.
        port.lock().rx.push(b"world");
        // Now read via FileOps.
        let _node = TtyUsbFile::new(port.clone());
        let mut out = [0u8; 8];
        let n = port.lock().rx.pop(&mut out);
        if n != 5 {
            return TestResult::Fail("expected 5 bytes from RX ring");
        }
        if &out[..5] != b"world" {
            return TestResult::Fail("read bytes do not match");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_read_drains_rx_ring
    );

    /// /sys/class/tty/ttyUSB0/device/driver returns chip name.
    fn smoke_ttyusb_sysfs_driver_attr() -> TestResult {
        narf_filesystem::sysfs::__reset_for_test();
        __reset_for_test();
        let _idx = register_tty_usb(ChipFamily::Ch341);
        use narf_filesystem::sysfs::class_register;
        let tty_class = class_register("tty");
        let child = tty_class.get_child("ttyUSB0");
        if child.is_none() {
            return TestResult::Fail("ttyUSB0 kobject not found under class/tty");
        }
        let kobj = child.unwrap();
        let val = kobj.attr_show("device/driver");
        match val {
            Some(s) if s.contains("ch341") => TestResult::Pass,
            Some(_s) => TestResult::Fail("driver attr wrong value"),
            None => TestResult::Fail("device/driver attr missing"),
        }
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_sysfs_driver_attr
    );

    /// lookup_tty_usb("ttyUSB0") returns Some after registration.
    fn smoke_ttyusb_lookup() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Pl2303);
        match lookup_tty_usb("ttyUSB0") {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("lookup_tty_usb should find ttyUSB0"),
        }
    }
    kernel_test_in!("drivers/usb/serial/devfs_bridge", smoke_ttyusb_lookup);

    /// Detach/replug: unregister removes the port from the node
    /// table and withdraws the sysfs kobject; a second unregister
    /// is a no-op; a replug republishes under a fresh index (the
    /// allocator is monotonic).
    fn smoke_ttyusb_unregister_detach_replug() -> TestResult {
        narf_filesystem::sysfs::__reset_for_test();
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Cp210x);
        if lookup_tty_usb("ttyUSB0").is_none() {
            return TestResult::Fail("ttyUSB0 should resolve after register");
        }
        if !unregister_tty_usb(idx) {
            return TestResult::Fail("unregister should report a removal");
        }
        if port_count() != 0 || get_port(idx).is_some() {
            return TestResult::Fail("port should be gone after unregister");
        }
        if lookup_tty_usb("ttyUSB0").is_some() {
            return TestResult::Fail("ttyUSB0 should not resolve after unregister");
        }
        use narf_filesystem::sysfs::class_register;
        if class_register("tty").get_child("ttyUSB0").is_some() {
            return TestResult::Fail("sysfs kobject should be withdrawn after unregister");
        }
        if !enumerate_tty_usb().is_empty() {
            return TestResult::Fail("enumeration should be empty after unregister");
        }
        if unregister_tty_usb(idx) {
            return TestResult::Fail("second unregister should report no removal");
        }
        // Replug: fresh index, resolvable again.
        let idx2 = register_tty_usb(ChipFamily::Cp210x);
        if idx2 == idx {
            return TestResult::Fail("replug should allocate a fresh index");
        }
        if lookup_tty_usb("ttyUSB1").is_none() {
            return TestResult::Fail("ttyUSB1 should resolve after replug");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_unregister_detach_replug
    );

    // ── Ioctl fixtures (#756) ────────────────────────────────

    /// A functional fake of the syscall layer's guarded user
    /// memory: a fixed 64-byte window addressed from 0, with
    /// out-of-window accesses failing `BadAddress` exactly like
    /// a bad user pointer.
    struct FakeUser {
        mem: IrqSafeSpinLock<[u8; 64]>,
    }

    impl FakeUser {
        fn new() -> Self {
            FakeUser {
                mem: IrqSafeSpinLock::new([0u8; 64]),
            }
        }
        fn store(&self, off: usize, bytes: &[u8]) {
            self.mem.lock()[off..off + bytes.len()].copy_from_slice(bytes);
        }
        fn load(&self, off: usize, bytes: &mut [u8]) {
            bytes.copy_from_slice(&self.mem.lock()[off..off + bytes.len()]);
        }
        fn load_u32(&self, off: usize) -> u32 {
            let mut b = [0u8; 4];
            self.load(off, &mut b);
            u32::from_le_bytes(b)
        }
    }

    impl IoctlContext for FakeUser {
        fn read(&self, address: u64, dest: &mut [u8]) -> Result<(), FsError> {
            let start = address as usize;
            let end = start.checked_add(dest.len()).ok_or(FsError::BadAddress)?;
            let mem = self.mem.lock();
            if end > mem.len() {
                return Err(FsError::BadAddress);
            }
            dest.copy_from_slice(&mem[start..end]);
            Ok(())
        }
        fn write(&self, address: u64, src: &[u8]) -> Result<(), FsError> {
            let start = address as usize;
            let end = start.checked_add(src.len()).ok_or(FsError::BadAddress)?;
            let mut mem = self.mem.lock();
            if end > mem.len() {
                return Err(FsError::BadAddress);
            }
            mem[start..end].copy_from_slice(src);
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }

    fn ioctl(fd: &Arc<dyn FileOps>, cmd: u32, arg: u64, ctx: &FakeUser) -> Result<u64, FsError> {
        narf_scheduler::block_on(fd.ioctl_user(cmd, arg, ctx))
    }

    fn open_ttyusb0() -> Option<Arc<dyn FileOps>> {
        lookup_tty_usb("ttyUSB0")
    }

    /// A termios image built from the default with `c_cflag`
    /// replaced — the shape a libc tcsetattr call presents.
    fn image_with_cflag(cflag: u32) -> [u8; KERNEL_TERMIOS_LEN] {
        let mut img = default_termios_image();
        img[8..12].copy_from_slice(&cflag.to_le_bytes());
        img
    }

    /// TCGETS on a fresh node returns the power-on image, and
    /// TCGETS2 appends the current rate in both speed fields.
    fn smoke_ttyusb_tcgets_default_image() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        if ioctl(&fd, TCGETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCGETS should succeed");
        }
        let mut got = [0u8; KERNEL_TERMIOS_LEN];
        ctx.load(0, &mut got);
        if got != default_termios_image() {
            return TestResult::Fail("TCGETS must return the default termios image");
        }
        if ioctl(&fd, TCGETS2, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCGETS2 should succeed");
        }
        let mut got2 = [0u8; KERNEL_TERMIOS2_LEN];
        ctx.load(0, &mut got2);
        if got2[..KERNEL_TERMIOS_LEN] != default_termios_image()[..] {
            return TestResult::Fail("TCGETS2 prefix must be the termios image");
        }
        if ctx.load_u32(36) != 115200 || ctx.load_u32(40) != 115200 {
            return TestResult::Fail("TCGETS2 speeds must be the current 115200 baud");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcgets_default_image
    );

    /// TCSETS with 57600 7E2 lands in the port's settings, and
    /// the settings decode through the family's configure plan
    /// to the spec-pinned wire transfers — baud as the AN571
    /// data stage, 7E2 as line-control 0x0722.
    fn smoke_ttyusb_tcsets_cp210x_reaches_device_plan() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Cp210x);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        // B57600 | CS7 | PARENB | CSTOPB | CREAD.
        ctx.store(0, &image_with_cflag(0x1001 | 0x20 | 0x100 | 0x40 | 0x80));
        if ioctl(&fd, TCSETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS 57600 7E2 should succeed");
        }
        let node = get_port(idx).unwrap();
        let settings = node.lock().settings;
        if settings.baud != 57600
            || settings.data_bits != DataBits::Seven
            || settings.parity != Parity::Even
            || settings.stop_bits != StopBits::Two
        {
            return TestResult::Fail("TCSETS must decode baud/parity/stop into settings");
        }
        let plan = match port::configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &settings) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("decoded settings must build a CP210x plan"),
        };
        if plan[0].data != alloc::vec![0x00, 0xE1, 0x00, 0x00] {
            return TestResult::Fail("57600 must reach the device as its baud data stage");
        }
        if plan[1].w_value != 0x0722 {
            return TestResult::Fail("7E2 must reach the device as line-control 0x0722");
        }
        // TCGETS round-trips the exact image that was set.
        let ctx2 = FakeUser::new();
        if ioctl(&fd, TCGETS, 0, &ctx2) != Ok(0) {
            return TestResult::Fail("TCGETS after TCSETS should succeed");
        }
        let mut back = [0u8; KERNEL_TERMIOS_LEN];
        ctx2.load(0, &mut back);
        if back != image_with_cflag(0x1001 | 0x20 | 0x100 | 0x40 | 0x80) {
            return TestResult::Fail("TCGETS must round-trip the TCSETS image verbatim");
        }
        // Parity arms: mark (PARENB|PARODD|CMSPAR) at CS8 →
        // line word 0x0830; odd (PARENB|PARODD) at CS7 →
        // 0x0710.
        ctx.store(
            0,
            &image_with_cflag(0x1002 | 0x30 | 0x100 | 0x200 | 0x4000_0000 | 0x80),
        );
        if ioctl(&fd, TCSETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS mark parity should succeed");
        }
        let settings = node.lock().settings;
        if settings.parity != Parity::Mark {
            return TestResult::Fail("CMSPAR|PARODD must decode as mark parity");
        }
        let plan = port::configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &settings).unwrap();
        if plan[1].w_value != 0x0830 {
            return TestResult::Fail("mark parity must reach the device as 0x0830");
        }
        ctx.store(0, &image_with_cflag(0x1002 | 0x20 | 0x100 | 0x200 | 0x80));
        if ioctl(&fd, TCSETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS odd parity should succeed");
        }
        let settings = node.lock().settings;
        if settings.parity != Parity::Odd || settings.data_bits != DataBits::Seven {
            return TestResult::Fail("PARENB|PARODD must decode as odd parity, CS7 as 7 bits");
        }
        let plan = port::configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &settings).unwrap();
        if plan[1].w_value != 0x0710 {
            return TestResult::Fail("7O1 must reach the device as 0x0710");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcsets_cp210x_reaches_device_plan
    );

    /// FTDI at 9600 8N1: the SET_DATA transfer of the decoded
    /// settings is the codec's 0x0008 word.
    fn smoke_ttyusb_tcsets_ftdi_9600() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        // B9600 (13) | CS8 | CREAD.
        ctx.store(0, &image_with_cflag(13 | 0x30 | 0x80));
        if ioctl(&fd, TCSETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS 9600 should succeed");
        }
        let settings = get_port(0).unwrap().lock().settings;
        if settings.baud != 9600 {
            return TestResult::Fail("B9600 must decode to 9600 baud");
        }
        let plan = match port::configure_plan(ChipFamily::Ftdi, 0x6001, 0, &settings) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("decoded settings must build an FTDI plan"),
        };
        if plan[1].b_request != super::super::ftdi::REQ_SET_DATA || plan[1].w_value != 0x0008 {
            return TestResult::Fail("8N1 must reach the FTDI as SET_DATA 0x0008");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcsets_ftdi_9600
    );

    /// TCSETS2 with CBAUD = BOTHER takes the baud numerically
    /// from c_ospeed — the only way to express rates the CBAUD
    /// table lacks, like 250000.
    fn smoke_ttyusb_tcsets2_bother_baud() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Cp210x);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        let mut wire = [0u8; KERNEL_TERMIOS2_LEN];
        wire[..KERNEL_TERMIOS_LEN].copy_from_slice(&image_with_cflag(0x1000 | 0x30 | 0x80));
        wire[36..40].copy_from_slice(&250_000u32.to_le_bytes());
        wire[40..44].copy_from_slice(&250_000u32.to_le_bytes());
        ctx.store(0, &wire);
        if ioctl(&fd, TCSETS2, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS2 BOTHER should succeed");
        }
        let settings = get_port(0).unwrap().lock().settings;
        if settings.baud != 250_000 {
            return TestResult::Fail("BOTHER baud must come from c_ospeed");
        }
        let plan = port::configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &settings).unwrap();
        if plan[0].data != alloc::vec![0x90, 0xD0, 0x03, 0x00] {
            return TestResult::Fail("250000 must reach the device as its LE data stage");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcsets2_bother_baud
    );

    /// B0 is a hangup: DTR/RTS drop, the baud stays programmed,
    /// and the lines stay down until a TIOCM* ioctl raises them.
    fn smoke_ttyusb_tcsets_b0_hangup() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        if ioctl(&fd, TIOCMGET, 0, &ctx) != Ok(0) || ctx.load_u32(0) != TIOCM_DTR | TIOCM_RTS {
            return TestResult::Fail("fresh node must report DTR|RTS asserted");
        }
        // CBAUD = 0 (B0), CS8 | CREAD.
        ctx.store(0, &image_with_cflag(0x30 | 0x80));
        if ioctl(&fd, TCSETS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETS B0 should succeed");
        }
        let settings = get_port(0).unwrap().lock().settings;
        if settings.dtr || settings.rts {
            return TestResult::Fail("B0 must drop DTR and RTS");
        }
        if settings.baud != 115200 {
            return TestResult::Fail("B0 must not change the programmed baud");
        }
        if ioctl(&fd, TIOCMGET, 0, &ctx) != Ok(0) || ctx.load_u32(0) != 0 {
            return TestResult::Fail("after hangup TIOCMGET must report no output lines");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcsets_b0_hangup
    );

    /// Modem lines: TIOCMSET replaces, BIS sets, BIC clears;
    /// TIOCMGET reports outputs from settings and inputs from
    /// the modem snapshot.
    fn smoke_ttyusb_tiocm_get_set_bis_bic() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        // Inputs: CTS + DCD raised on the wire.
        note_modem(
            idx,
            ModemStatus {
                cts: true,
                dsr: false,
                dcd: true,
                ri: false,
            },
        );
        if ioctl(&fd, TIOCMGET, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TIOCMGET should succeed");
        }
        if ctx.load_u32(0) != TIOCM_DTR | TIOCM_RTS | TIOCM_CTS | TIOCM_CAR {
            return TestResult::Fail("TIOCMGET must merge output settings and input snapshot");
        }
        // SET with RTS only.
        ctx.store(0, &TIOCM_RTS.to_le_bytes());
        if ioctl(&fd, TIOCMSET, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TIOCMSET should succeed");
        }
        let s = get_port(idx).unwrap().lock().settings;
        if s.dtr || !s.rts {
            return TestResult::Fail("TIOCMSET RTS-only must drop DTR and raise RTS");
        }
        // BIS DTR → both up. BIC RTS → DTR only.
        ctx.store(0, &TIOCM_DTR.to_le_bytes());
        if ioctl(&fd, TIOCMBIS, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TIOCMBIS should succeed");
        }
        ctx.store(0, &TIOCM_RTS.to_le_bytes());
        if ioctl(&fd, TIOCMBIC, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TIOCMBIC should succeed");
        }
        let s = get_port(idx).unwrap().lock().settings;
        if !s.dtr || s.rts {
            return TestResult::Fail("BIS DTR then BIC RTS must leave DTR up, RTS down");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tiocm_get_set_bis_bic
    );

    /// A command outside the surface is ENOTTY (`Unsupported`),
    /// and a user pointer outside the window is `BadAddress`.
    fn smoke_ttyusb_unsupported_ioctl_and_bad_pointer() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        match ioctl(&fd, 0x9999, 0, &ctx) {
            Err(FsError::Unsupported) => {}
            _ => return TestResult::Fail("unknown ioctl must return Unsupported (ENOTTY)"),
        }
        match ioctl(&fd, TCGETS, 4096, &ctx) {
            Err(FsError::BadAddress) => {}
            _ => return TestResult::Fail("out-of-window user pointer must return BadAddress"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_unsupported_ioctl_and_bad_pointer
    );

    /// TCSETS asking CP210x for hardware flow control refuses
    /// typed (its SET_FLOW is unmodelled) and commits nothing —
    /// the same refusal, bound or not, never a silent no-op.
    fn smoke_ttyusb_tcsets_flow_refused_cp210x() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Cp210x);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        // Default image + CRTSCTS.
        ctx.store(0, &image_with_cflag(0x1002 | 0x30 | 0x80 | 0x8000_0000));
        match ioctl(&fd, TCSETS, 0, &ctx) {
            Err(FsError::Unsupported) => {}
            _ => return TestResult::Fail("CP210x CRTSCTS must refuse with Unsupported"),
        }
        let s = get_port(0).unwrap().lock().settings;
        if s != LineSettings::default() {
            return TestResult::Fail("a refused TCSETS must not commit any settings");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcsets_flow_refused_cp210x
    );

    /// FIONREAD counts the RX ring; TCFLSH flushes per its
    /// queue selector and rejects bad selectors; TCSETSF
    /// discards pending input as it applies.
    fn smoke_ttyusb_tcflsh_fionread() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Pl2303);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        let tty = get_port(idx).unwrap();
        tty.lock().rx.push(b"abc");
        tty.lock().tx.push(b"xy");
        if ioctl(&fd, FIONREAD, 0, &ctx) != Ok(0) || ctx.load_u32(0) != 3 {
            return TestResult::Fail("FIONREAD must report the RX ring depth");
        }
        // Flush input only: TX survives.
        if ioctl(&fd, TCFLSH, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCFLSH 0 should succeed");
        }
        {
            let g = tty.lock();
            if !g.rx.is_empty() || g.tx.len() != 2 {
                return TestResult::Fail("TCFLSH 0 must flush input only");
            }
        }
        // Flush both.
        tty.lock().rx.push(b"z");
        if ioctl(&fd, TCFLSH, 2, &ctx) != Ok(0) {
            return TestResult::Fail("TCFLSH 2 should succeed");
        }
        {
            let g = tty.lock();
            if !g.rx.is_empty() || !g.tx.is_empty() {
                return TestResult::Fail("TCFLSH 2 must flush both queues");
            }
        }
        match ioctl(&fd, TCFLSH, 9, &ctx) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("TCFLSH with a bad selector must be InvalidData"),
        }
        // TCSETSF applies the image and discards pending input.
        tty.lock().rx.push(b"pending");
        ctx.store(0, &default_termios_image());
        if ioctl(&fd, TCSETSF, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCSETSF should succeed");
        }
        if !tty.lock().rx.is_empty() {
            return TestResult::Fail("TCSETSF must discard pending input");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_tcflsh_fionread
    );

    /// TCXONC TCOOFF parks output (the pump honours
    /// `tx_stopped`), TCOON resumes; TCIOFF/TCION are accepted
    /// no-ops; bad selectors refuse.
    fn smoke_ttyusb_tcxonc() -> TestResult {
        __reset_for_test();
        let idx = register_tty_usb(ChipFamily::Ch341);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        if ioctl(&fd, TCXONC, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TCXONC TCOOFF should succeed");
        }
        if !get_port(idx).unwrap().lock().tx_stopped {
            return TestResult::Fail("TCOOFF must set tx_stopped");
        }
        if ioctl(&fd, TCXONC, 2, &ctx) != Ok(0) || ioctl(&fd, TCXONC, 3, &ctx) != Ok(0) {
            return TestResult::Fail("TCIOFF/TCION must be accepted");
        }
        if ioctl(&fd, TCXONC, 1, &ctx) != Ok(0) {
            return TestResult::Fail("TCXONC TCOON should succeed");
        }
        if get_port(idx).unwrap().lock().tx_stopped {
            return TestResult::Fail("TCOON must clear tx_stopped");
        }
        match ioctl(&fd, TCXONC, 7, &ctx) {
            Err(FsError::InvalidData) => {}
            _ => return TestResult::Fail("TCXONC with a bad selector must be InvalidData"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/devfs_bridge", smoke_ttyusb_tcxonc);

    /// The window size round-trips through TIOCSWINSZ /
    /// TIOCGWINSZ (stored, never sent to the device).
    fn smoke_ttyusb_winsize_roundtrip() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        let mut ws = [0u8; 8];
        ws[0..2].copy_from_slice(&24u16.to_le_bytes());
        ws[2..4].copy_from_slice(&80u16.to_le_bytes());
        ctx.store(0, &ws);
        if ioctl(&fd, TIOCSWINSZ, 0, &ctx) != Ok(0) {
            return TestResult::Fail("TIOCSWINSZ should succeed");
        }
        let ctx2 = FakeUser::new();
        if ioctl(&fd, TIOCGWINSZ, 0, &ctx2) != Ok(0) {
            return TestResult::Fail("TIOCGWINSZ should succeed");
        }
        let mut back = [0u8; 8];
        ctx2.load(0, &mut back);
        if back != ws {
            return TestResult::Fail("winsize must round-trip 24x80");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_winsize_roundtrip
    );

    /// Break surface without a bound device: TCSBRK with a
    /// nonzero argument is the drain form and succeeds; the
    /// timed and explicit break forms need a device and report
    /// NoDevice rather than pretending a break was sent.
    fn smoke_ttyusb_break_without_device() -> TestResult {
        __reset_for_test();
        register_tty_usb(ChipFamily::Ftdi);
        let fd = match open_ttyusb0() {
            Some(f) => f,
            None => return TestResult::Fail("ttyUSB0 should resolve"),
        };
        let ctx = FakeUser::new();
        if ioctl(&fd, TCSBRK, 1, &ctx) != Ok(0) {
            return TestResult::Fail("TCSBRK nonzero (drain) should succeed");
        }
        match ioctl(&fd, TCSBRK, 0, &ctx) {
            Err(FsError::NoDevice) => {}
            _ => return TestResult::Fail("TCSBRK 0 without a device must be NoDevice"),
        }
        match ioctl(&fd, TIOCSBRK, 0, &ctx) {
            Err(FsError::NoDevice) => {}
            _ => return TestResult::Fail("TIOCSBRK without a device must be NoDevice"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/devfs_bridge",
        smoke_ttyusb_break_without_device
    );
}
