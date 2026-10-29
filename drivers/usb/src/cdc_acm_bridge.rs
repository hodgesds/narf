//! devfs bridge for CDC-ACM ports (#753): publishes one
//! `/dev/ttyACM<N>` character device per bound ACM function,
//! mirroring the vendor-USB-serial bridge's node behaviour with
//! the CDC class's own actuation underneath.
//!
//! Unlike the vendor families (FTDI / CP210x / PL2303 / CH341),
//! an ACM device has no vendor baud registers: its line format
//! *is* the class line coding (PSTN 1.2 §6.3.10), so termios
//! decode lands directly in a [`LineCoding`], and modem output
//! lines are the class `SET_CONTROL_LINE_STATE` request. The
//! bridge owns the user-visible state — termios image, committed
//! line coding, modem snapshot, error counters — and actuates
//! hardware state through the [`AcmTransport`] seam, committing
//! only after the device accepted the change (the #759 honesty
//! rule: a STALLed request surfaces as an ioctl error and the
//! committed state is untouched).
//!
//! Wire formats follow the Linux tty ABI:
//!   * `struct termios` is the 36-byte kernel image and
//!     `struct termios2` the 44-byte image (both pinned in
//!     `filesystem::devfs_pty`); the flag values below come from
//!     `asm-generic/termbits.h` + `termbits-common.h`,
//!     `asm-generic/ioctls.h`, and `include/uapi/linux/termios.h`.
//!   * `TIOCM*` modem bits come from `termios.h`
//!     (`TIOCM_DTR`/`RTS`/`CAR`/`RNG`/`DSR`).
//!   * `TIOCGICOUNT` returns the 80-byte
//!     `struct serial_icounter_struct` from
//!     `include/uapi/linux/serial.h` (20 × `i32`).
//!   * ttyACM's major is **166** (Linux `major.h` /
//!     `Documentation/admin-guide/devices.txt`), rdev
//!     `(166 << 8) | N`, inode via
//!     `narf_filesystem::devfs::char_device_inode`, sysfs class
//!     `tty`, permissions `0660`.
//!
//! Modem *input* state comes from the device's SerialState
//! notification reports (PSTN 1.2 §6.5.3, decoded by
//! `cdc_acm::SerialState`): DCD ← `bRxCarrier`, DSR ←
//! `bTxCarrier`, RI ← `bRingSignal`. PSTN SerialState carries
//! **no CTS bit**, so `TIOCMGET` never reports CTS and the CTS
//! change counter stays 0 — both documented absences, not
//! fabricated state. Error bits (`bBreak`, `bFraming`,
//! `bParity`, `bOverrun`) are counted on their rising edge per
//! report; DCD/DSR/RI count transitions.
//!
//! Deliberate behaviours, matching Linux `cdc-acm`:
//!   * `CRTSCTS` round-trips in the termios image but never
//!     gates a commit — CDC line coding has no field to express
//!     hardware flow control in.
//!   * `TCSETSW`/`TCSETSF` behave as `TCSETS` (no output-drain
//!     wait); `TCSETSF` additionally flushes the RX ring.
//!   * `B0` is the hangup: DTR/RTS are dropped via
//!     `SET_CONTROL_LINE_STATE`; the line coding is not touched.
//!   * `TCSBRK` with a zero argument issues a native 250 ms
//!     `SEND_BREAK` (the class request carries the duration in
//!     `wValue`, so no software timing loop is needed); a
//!     non-zero argument is drain-only and issues nothing.
//!     `TCSBRKP` is not implemented.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_block::BlockError;
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_IN, POLL_OUT,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::cdc::CdcError;
use crate::cdc_acm::{
    AcmCapabilities, CdcAcmPort, LineCoding, Parity as CdcParity, SerialState,
    StopBits as CdcStopBits,
};
use crate::serial::devfs_bridge::SerialRing;

// ── tty ABI constants (Linux UAPI) ────────────────────────────

// Ioctl command numbers (asm-generic/ioctls.h) — the values the
// filesystem layer also pins for the PTY pair.
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540A;
const TCFLSH: u32 = 0x540B;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCMGET: u32 = 0x5415;
const TIOCMBIS: u32 = 0x5416;
const TIOCMBIC: u32 = 0x5417;
const TIOCMSET: u32 = 0x5418;
const FIONREAD: u32 = 0x541B;
const TIOCSBRK: u32 = 0x5427;
const TIOCCBRK: u32 = 0x5428;
const TCGETS2: u32 = 0x802C_542A;
const TCSETS2: u32 = 0x402C_542B;
const TCSETSW2: u32 = 0x402C_542C;
const TCSETSF2: u32 = 0x402C_542D;
const TIOCGICOUNT: u32 = 0x545D;

// c_cflag fields (asm-generic/termbits.h, termbits-common.h).
const CBAUD: u32 = 0x100F;
const BOTHER: u32 = 0x1000;
const CSIZE: u32 = 0x0030;
const CSTOPB: u32 = 0x0040;
const CREAD: u32 = 0x0080;
const PARENB: u32 = 0x0100;
const PARODD: u32 = 0x0200;
const HUPCL: u32 = 0x0400;
const CMSPAR: u32 = 0x4000_0000;

// Cooked-mode defaults, mirroring `filesystem::devfs_pty`'s
// Termios::default so a ttyACM node powers up behaving like
// every other tty on the system.
const DEFAULT_IFLAG: u32 = 0x0500; // ICRNL | IXON
const DEFAULT_OFLAG: u32 = 0x0005; // OPOST | ONLCR
const DEFAULT_LFLAG: u32 = 0x803B; // ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN
/// Linux `INIT_C_CC` control characters.
const INIT_CC: [u8; 19] = [
    0x03, // VINTR
    0x1C, // VQUIT
    0x7F, // VERASE
    0x15, // VKILL
    0x04, // VEOF
    0x00, // VTIME
    0x01, // VMIN
    0x00, // (unused slot)
    0x11, // VSTART
    0x13, // VSTOP
    0x1A, // VSUSP
    0x00, // VEOL
    0x12, // VREPRINT
    0x0F, // VDISCARD
    0x17, // VWERASE
    0x16, // VLNEXT
    0x00, 0x00, 0x00,
];

/// ttyACM major number (Linux major.h).
pub const TTY_ACM_MAJOR: u32 = 166;

// ── Termios ↔ CDC line-coding codec ───────────────────────────

/// Baud-rate table for the classic `CBAUD` encodings
/// (`B0`..=`B38400`, termbits-common.h) — `(cbaud value, rate)`.
const CLASSIC_BAUDS: &[(u32, u32)] = &[
    (0x0, 0),
    (0x1, 50),
    (0x2, 75),
    (0x3, 110),
    (0x4, 134),
    (0x5, 150),
    (0x6, 200),
    (0x7, 300),
    (0x8, 600),
    (0x9, 1200),
    (0xA, 1800),
    (0xB, 2400),
    (0xC, 4800),
    (0xD, 9600),
    (0xE, 19200),
    (0xF, 38400),
];

/// Baud-rate table for the extended `CBAUD` encodings
/// (`B57600`..=`B4000000`, termbits.h).
const EXTENDED_BAUDS: &[(u32, u32)] = &[
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

/// Resolve a `CBAUD` field value to a rate in bits/s.
/// `c_ospeed` supplies the rate when the field is `BOTHER`.
/// `None` for encodings outside the UAPI tables.
fn baud_for_cbaud(cbaud: u32, c_ospeed: u32) -> Option<u32> {
    if cbaud == BOTHER {
        return Some(c_ospeed);
    }
    CLASSIC_BAUDS
        .iter()
        .chain(EXTENDED_BAUDS.iter())
        .find(|(v, _)| *v == cbaud)
        .map(|(_, rate)| *rate)
}

/// The `CBAUD` field value naming `rate`, or `BOTHER` when the
/// rate has no table entry (the rate itself then travels in
/// `c_ospeed`).
fn cbaud_for_baud(rate: u32) -> u32 {
    CLASSIC_BAUDS
        .iter()
        .chain(EXTENDED_BAUDS.iter())
        .find(|(_, r)| *r == rate)
        .map(|(v, _)| *v)
        .unwrap_or(BOTHER)
}

/// Decode a `c_cflag` + rate into the CDC line coding the
/// device should be programmed with. `rate == 0` (B0) never
/// reaches here — the caller treats it as a hangup.
fn line_coding_from_termios(c_cflag: u32, rate: u32) -> LineCoding {
    let data_bits = match c_cflag & CSIZE {
        0x00 => 5,
        0x10 => 6,
        0x20 => 7,
        _ => 8,
    };
    let parity = if c_cflag & PARENB == 0 {
        CdcParity::None
    } else if c_cflag & CMSPAR != 0 {
        if c_cflag & PARODD != 0 {
            CdcParity::Mark
        } else {
            CdcParity::Space
        }
    } else if c_cflag & PARODD != 0 {
        CdcParity::Odd
    } else {
        CdcParity::Even
    };
    let stop_bits = if c_cflag & CSTOPB != 0 {
        CdcStopBits::Two
    } else {
        CdcStopBits::One
    };
    LineCoding {
        baud_rate: rate,
        data_bits,
        parity,
        stop_bits,
    }
}

/// The `c_cflag` describing a committed line coding: the
/// `CBAUD` encoding of its rate (or `BOTHER`), the `CS` field,
/// `CREAD` + `HUPCL` (the cooked defaults), and the parity /
/// stop fields the coding carries.
fn cflag_from_line_coding(coding: &LineCoding) -> u32 {
    let mut f = cbaud_for_baud(coding.baud_rate) | CREAD | HUPCL;
    f |= match coding.data_bits {
        5 => 0x00,
        6 => 0x10,
        7 => 0x20,
        _ => 0x30,
    };
    if coding.stop_bits == CdcStopBits::Two {
        f |= CSTOPB;
    }
    match coding.parity {
        CdcParity::None => {}
        CdcParity::Odd => f |= PARENB | PARODD,
        CdcParity::Even => f |= PARENB,
        CdcParity::Mark => f |= PARENB | PARODD | CMSPAR,
        CdcParity::Space => f |= PARENB | CMSPAR,
    }
    f
}

/// Build a fresh 36-byte termios image for a port whose device
/// is at `coding`: cooked flags + `INIT_C_CC`, with `c_cflag`
/// derived from the coding.
fn initial_termios_image(coding: &LineCoding) -> [u8; 36] {
    let mut img = [0u8; 36];
    img[0..4].copy_from_slice(&DEFAULT_IFLAG.to_le_bytes());
    img[4..8].copy_from_slice(&DEFAULT_OFLAG.to_le_bytes());
    img[8..12].copy_from_slice(&cflag_from_line_coding(coding).to_le_bytes());
    img[12..16].copy_from_slice(&DEFAULT_LFLAG.to_le_bytes());
    img[16] = 0; // c_line
    img[17..36].copy_from_slice(&INIT_CC);
    img
}

fn u32_at(img: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([img[off], img[off + 1], img[off + 2], img[off + 3]])
}

fn put_u32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_i32(img: &mut [u8], off: usize, v: i32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// ── Transport seam ────────────────────────────────────────────

/// Why an actuation against the device failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcmError {
    /// The device (or its controller) is gone.
    NoDevice,
    /// The class request was issued and the device refused it
    /// (STALL / transfer failure).
    Transfer,
    /// The device did not declare the capability the request
    /// needs.
    Unsupported,
}

/// Boxed future returned by [`AcmTransport`] methods.
pub type AcmFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AcmError>> + Send + 'a>>;

/// The hardware-actuation seam under a ttyACM port. Production
/// is [`XhciAcmTransport`]; tests drive the bridge through a
/// recording fake. Every method is actuation-only: "success"
/// means the device accepted the class request.
pub trait AcmTransport: Send + Sync + core::fmt::Debug {
    fn set_line_coding<'a>(&'a self, coding: LineCoding) -> AcmFuture<'a>;
    fn set_control_lines<'a>(&'a self, dtr: bool, rts: bool) -> AcmFuture<'a>;
    fn send_break<'a>(&'a self, duration_ms: u16) -> AcmFuture<'a>;
}

/// Production transport: resolves the bound device on the xHCI
/// controller and issues the class requests through
/// [`CdcAcmPort`].
#[derive(Debug)]
pub struct XhciAcmTransport {
    slot_id: u8,
    capabilities: AcmCapabilities,
}

impl XhciAcmTransport {
    pub fn new(slot_id: u8, capabilities: AcmCapabilities) -> Self {
        Self {
            slot_id,
            capabilities,
        }
    }

    fn port(&self) -> Result<CdcAcmPort, AcmError> {
        let xhci = crate::xhci::controller().ok_or(AcmError::NoDevice)?;
        CdcAcmPort::for_slot(xhci, self.slot_id).ok_or(AcmError::NoDevice)
    }

    fn map(err: CdcError) -> AcmError {
        match err {
            CdcError::Unsupported => AcmError::Unsupported,
            _ => AcmError::Transfer,
        }
    }
}

impl AcmTransport for XhciAcmTransport {
    fn set_line_coding<'a>(&'a self, coding: LineCoding) -> AcmFuture<'a> {
        Box::pin(async move { self.port()?.set_line_coding(coding).map_err(Self::map) })
    }

    fn set_control_lines<'a>(&'a self, dtr: bool, rts: bool) -> AcmFuture<'a> {
        Box::pin(async move { self.port()?.set_control_lines(dtr, rts).map_err(Self::map) })
    }

    fn send_break<'a>(&'a self, duration_ms: u16) -> AcmFuture<'a> {
        Box::pin(async move {
            // Refuse locally when the device never declared the
            // capability (the port double-checks against the
            // bound device's own descriptor copy).
            if !self.capabilities.send_break {
                return Err(AcmError::Unsupported);
            }
            self.port()?.send_break(duration_ms).map_err(Self::map)
        })
    }
}

// ── Port state ────────────────────────────────────────────────

/// User-visible state of one `/dev/ttyACM<N>` node.
#[derive(Debug)]
pub struct AcmPort {
    pub index: usize,
    transport: Arc<dyn AcmTransport>,
    /// Bytes device → user (drained from bulk-IN by the pump).
    rx: SerialRing,
    /// Bytes user → device (drained onto bulk-OUT by the pump).
    tx: SerialRing,
    /// The committed 36-byte termios image (`TCSETS` commits a
    /// user's image verbatim once the device accepted it).
    termios: [u8; 36],
    ispeed: u32,
    ospeed: u32,
    /// The line coding the device is actually programmed with —
    /// the committed mirror of `AcmDevice`'s cache.
    line_coding: LineCoding,
    /// Committed DTR output state.
    dtr: bool,
    /// Committed RTS output state.
    rts: bool,
    /// Last SerialState snapshot, once any report arrived.
    modem: Option<SerialState>,
    /// `TIOCGICOUNT` counters (see the module docs for the
    /// counting discipline).
    icount: Icount,
    /// `TCXONC` output-stop flag: the pump holds TX while set.
    tx_stopped: bool,
    /// A `TIOCSBRK` break condition is currently asserted.
    break_on: bool,
    /// Last NetworkConnection notification state, when the
    /// device reports one. No user surface consumes it yet.
    network_up: bool,
    /// Window size (`TIOCGWINSZ` round-trips it; nothing
    /// signals on change — no SIGWINCH source exists for
    /// devfs ttys).
    winsize: [u16; 4],
}

/// The `serial_icounter_struct` counters for one port.
#[derive(Clone, Copy, Debug, Default)]
struct Icount {
    dcd_changes: i32,
    dsr_changes: i32,
    rng_changes: i32,
    rx_bytes: i32,
    tx_bytes: i32,
    frame: i32,
    overrun: i32,
    parity: i32,
    brk: i32,
}

impl AcmPort {
    fn new(index: usize, transport: Arc<dyn AcmTransport>) -> Self {
        // The port powers up at the bind-time default coding —
        // the same 115200 8N1 the binder programs.
        let coding = LineCoding::N_115200_8N1;
        Self {
            index,
            transport,
            rx: SerialRing::new(),
            tx: SerialRing::new(),
            termios: initial_termios_image(&coding),
            ispeed: coding.baud_rate,
            ospeed: coding.baud_rate,
            line_coding: coding,
            dtr: true,
            rts: true,
            modem: None,
            icount: Icount::default(),
            tx_stopped: false,
            break_on: false,
            network_up: false,
            winsize: [0; 4],
        }
    }

    /// The 80-byte `serial_icounter_struct` image. `cts` stays
    /// 0 (PSTN SerialState has no CTS) and `buf_overrun` stays
    /// 0 (ring overwrites are not separately accounted).
    fn icounter_image(&self) -> [u8; 80] {
        let mut img = [0u8; 80];
        put_i32(&mut img, 4, self.icount.dsr_changes);
        put_i32(&mut img, 8, self.icount.rng_changes);
        put_i32(&mut img, 12, self.icount.dcd_changes);
        put_i32(&mut img, 16, self.icount.rx_bytes);
        put_i32(&mut img, 20, self.icount.tx_bytes);
        put_i32(&mut img, 24, self.icount.frame);
        put_i32(&mut img, 28, self.icount.overrun);
        put_i32(&mut img, 32, self.icount.parity);
        put_i32(&mut img, 36, self.icount.brk);
        img
    }

    /// The `TIOCMGET` bitmask: committed outputs, plus inputs
    /// from the latest SerialState snapshot once one arrived.
    fn tiocm_image(&self) -> i32 {
        const TIOCM_DTR: i32 = 0x002;
        const TIOCM_RTS: i32 = 0x004;
        const TIOCM_CAR: i32 = 0x040;
        const TIOCM_RNG: i32 = 0x080;
        const TIOCM_DSR: i32 = 0x100;
        let mut v = 0i32;
        if self.dtr {
            v |= TIOCM_DTR;
        }
        if self.rts {
            v |= TIOCM_RTS;
        }
        if let Some(m) = &self.modem {
            // No CTS bit: PSTN SerialState has no CTS source.
            if m.rx_carrier {
                v |= TIOCM_CAR;
            }
            if m.tx_carrier {
                v |= TIOCM_DSR;
            }
            if m.ring_signal {
                v |= TIOCM_RNG;
            }
        }
        v
    }
}

// ── Registry ──────────────────────────────────────────────────

static TTY_ACM_INDEX: AtomicUsize = AtomicUsize::new(0);
static TTY_ACM_NODES: IrqSafeSpinLock<Vec<Option<Arc<IrqSafeSpinLock<AcmPort>>>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Publish a new `/dev/ttyACM<N>` for a bound ACM device and
/// return its index. Called by the ACM bind path after the
/// device's endpoints are configured and armed.
pub fn register_tty_acm(transport: Arc<dyn AcmTransport>) -> usize {
    let index = TTY_ACM_INDEX.fetch_add(1, Ordering::Relaxed);
    let port = Arc::new(IrqSafeSpinLock::new(AcmPort::new(index, transport)));
    {
        let mut g = TTY_ACM_NODES.lock();
        if g.len() <= index {
            g.resize_with(index + 1, || None);
        }
        g[index] = Some(port);
    }
    register_sysfs(index);
    index
}

/// Withdraw the node at `index` (device detached) and its
/// `/sys/class/tty/ttyACM<N>` kobject. The index is never
/// reused — a replugged device gets a fresh number, like
/// Linux's dynamic tty numbering.
pub fn unregister_tty_acm(index: usize) {
    {
        let mut g = TTY_ACM_NODES.lock();
        if index < g.len() {
            g[index] = None;
        }
    }
    unregister_sysfs(index);
}

/// The live port at `index`, when one is published.
pub fn get_port(index: usize) -> Option<Arc<IrqSafeSpinLock<AcmPort>>> {
    let g = TTY_ACM_NODES.lock();
    g.get(index).cloned().flatten()
}

/// Number of live ttyACM nodes.
pub fn port_count() -> usize {
    TTY_ACM_NODES.lock().iter().filter(|s| s.is_some()).count()
}

/// Reset the registry to a clean slate (test reset hook, the
/// vendor bridge's pattern).
pub fn __reset_for_test() {
    TTY_ACM_NODES.lock().clear();
    TTY_ACM_INDEX.store(0, Ordering::Relaxed);
}

// ── Sysfs class registration ────────────────────────────��─────

/// Register `/sys/class/tty/ttyACM<N>/` for one port.
fn register_sysfs(idx: usize) {
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

    let tty_class = class_register("tty");
    let name = format!("ttyACM{}", idx);
    let kobj = class_device_register(tty_class, &name);

    // /sys/class/tty/ttyACM<N>/dev → "166:<N>\n"
    let dev_str = format!("{}:{}\n", TTY_ACM_MAJOR, idx);
    kobject_add_attr(&kobj, "dev", move || dev_str.clone());

    // /sys/class/tty/ttyACM<N>/device/driver → "cdc_acm"
    // (inlined on the node, the vendor bridge's simplification).
    kobject_add_attr(&kobj, "device/driver", move || String::from("cdc_acm\n"));

    // /sys/class/tty/ttyACM<N>/uevent
    let uevent = format!(
        "MAJOR={}\nMINOR={}\nDEVNAME=ttyACM{}\n",
        TTY_ACM_MAJOR, idx, idx
    );
    kobject_add_attr(&kobj, "uevent", move || uevent.clone());
}

/// Withdraw `/sys/class/tty/ttyACM<N>/`.
fn unregister_sysfs(idx: usize) {
    use narf_filesystem::sysfs::class_register;

    let tty_class = class_register("tty");
    let name = format!("ttyACM{}", idx);
    tty_class.remove_child(&name);
}

// ── Pump-facing feed/drain helpers ────────────────────────────

/// Push freshly-received device bytes into the node's RX ring,
/// counting them for `TIOCGICOUNT`.
pub fn feed_rx(index: usize, bytes: &[u8]) {
    if let Some(port) = get_port(index) {
        let mut p = port.lock();
        let accepted = p.rx.push(bytes);
        p.icount.rx_bytes = p.icount.rx_bytes.wrapping_add(accepted as i32);
    }
}

/// Copy pending TX bytes into `buf` without removing them — the
/// pump's peek half of the peek/skip discipline. Returns 0 when
/// the port is `TCXONC`-stopped or the ring is empty.
pub fn tx_peek(index: usize, buf: &mut [u8]) -> usize {
    match get_port(index) {
        Some(port) => {
            let p = port.lock();
            if p.tx_stopped {
                0
            } else {
                p.tx.peek(buf)
            }
        }
        None => 0,
    }
}

/// Drop `n` bytes from the node's TX ring after the controller
/// reported them sent, counting them for `TIOCGICOUNT`.
pub fn tx_skip(index: usize, n: usize) {
    if let Some(port) = get_port(index) {
        let mut p = port.lock();
        p.tx.skip(n);
        p.icount.tx_bytes = p.icount.tx_bytes.wrapping_add(n as i32);
    }
}

/// Fold one decoded SerialState report into the node's modem
/// snapshot + counters (#757): inputs transition-counted, error
/// bits rising-edge counted against the previous snapshot.
pub fn note_serial_state(index: usize, state: SerialState) {
    if let Some(port) = get_port(index) {
        let mut p = port.lock();
        let prev = p.modem.unwrap_or(SerialState {
            rx_carrier: false,
            tx_carrier: false,
            break_received: false,
            ring_signal: false,
            framing_error: false,
            parity_error: false,
            overrun: false,
        });
        if state.rx_carrier != prev.rx_carrier {
            p.icount.dcd_changes = p.icount.dcd_changes.wrapping_add(1);
        }
        if state.tx_carrier != prev.tx_carrier {
            p.icount.dsr_changes = p.icount.dsr_changes.wrapping_add(1);
        }
        if state.ring_signal != prev.ring_signal {
            p.icount.rng_changes = p.icount.rng_changes.wrapping_add(1);
        }
        if state.break_received && !prev.break_received {
            p.icount.brk = p.icount.brk.wrapping_add(1);
        }
        if state.framing_error && !prev.framing_error {
            p.icount.frame = p.icount.frame.wrapping_add(1);
        }
        if state.parity_error && !prev.parity_error {
            p.icount.parity = p.icount.parity.wrapping_add(1);
        }
        if state.overrun && !prev.overrun {
            p.icount.overrun = p.icount.overrun.wrapping_add(1);
        }
        p.modem = Some(state);
    }
}

/// Record a NetworkConnection notification. Retained on the
/// port for future link-state surfacing; no user ABI consumes
/// it yet.
pub fn note_network_connection(index: usize, up: bool) {
    if let Some(port) = get_port(index) {
        port.lock().network_up = up;
    }
}

// ── File handle ───────────────────────────────────────────────

#[derive(Debug)]
struct TtyAcmFile {
    port: Arc<IrqSafeSpinLock<AcmPort>>,
    index: usize,
}

fn map_acm_err(e: AcmError) -> FsError {
    match e {
        AcmError::NoDevice => FsError::NoDevice,
        AcmError::Transfer => FsError::Io(BlockError::IOError),
        AcmError::Unsupported => FsError::Unsupported,
    }
}

impl FileOps for TtyAcmFile {
    fn ino(&self) -> u64 {
        narf_filesystem::devfs::char_device_inode(self.rdev())
    }

    /// Drain bytes from the RX ring into `buf`. Returns
    /// immediately with the bytes available; callers that want
    /// blocking behaviour poll `poll_readiness` for `POLL_IN`.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = self.port.lock().rx.pop(buf);
        Box::pin(async move { Ok(n) })
    }

    /// Push `buf` into the TX ring; the ACM supervisor pump
    /// drains it onto the device's bulk-OUT endpoint.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = self.port.lock().tx.push(buf);
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    /// `st_rdev` = ttyACM major(166) : minor(index).
    fn rdev(&self) -> u64 {
        ((TTY_ACM_MAJOR as u64) << 8) | self.index as u64
    }

    /// `POLL_IN` when the RX ring has bytes; `POLL_OUT` unless
    /// output is `TCXONC`-stopped.
    fn poll_readiness(&self) -> u32 {
        let p = self.port.lock();
        let mut ev = 0u32;
        if p.rx.has_data() {
            ev |= POLL_IN;
        }
        if !p.tx_stopped {
            ev |= POLL_OUT;
        }
        ev
    }

    /// Async ioctl surface (termios / modem / break / flush /
    /// counters — the module docs have the contract). The
    /// synchronous `ioctl` keeps the trait default
    /// (`Unsupported`): line-coding and break operations await
    /// USB transfers and cannot run synchronously.
    ///
    /// Lock discipline: the port lock is never held across an
    /// await — state is snapshotted under the lock, the
    /// transport is awaited unlocked, and the commit re-locks
    /// (the `block_on` lock rule).
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            match cmd {
                TCGETS => {
                    let img = self.port.lock().termios;
                    ctx.write(arg, &img)?;
                    Ok(0)
                }
                TCGETS2 => {
                    let (img, ispeed, ospeed) = {
                        let p = self.port.lock();
                        (p.termios, p.ispeed, p.ospeed)
                    };
                    let mut out = [0u8; 44];
                    out[..36].copy_from_slice(&img);
                    put_u32(&mut out, 36, ispeed);
                    put_u32(&mut out, 40, ospeed);
                    ctx.write(arg, &out)?;
                    Ok(0)
                }
                TCSETS | TCSETSW | TCSETSF => {
                    let mut img = [0u8; 36];
                    ctx.read(arg, &mut img)?;
                    self.apply_termios(img, None, cmd == TCSETSF).await?;
                    Ok(0)
                }
                TCSETS2 | TCSETSW2 | TCSETSF2 => {
                    let mut raw = [0u8; 44];
                    ctx.read(arg, &mut raw)?;
                    let speeds = (u32_at(&raw, 36), u32_at(&raw, 40));
                    let mut img = [0u8; 36];
                    img.copy_from_slice(&raw[..36]);
                    self.apply_termios(img, Some(speeds), cmd == TCSETSF2)
                        .await?;
                    Ok(0)
                }
                TIOCMGET => {
                    let v = self.port.lock().tiocm_image();
                    ctx.write(arg, &v.to_le_bytes())?;
                    Ok(0)
                }
                TIOCMSET | TIOCMBIS | TIOCMBIC => {
                    let mut raw = [0u8; 4];
                    ctx.read(arg, &mut raw)?;
                    let val = i32::from_le_bytes(raw);
                    self.apply_tiocm(cmd, val).await?;
                    Ok(0)
                }
                TCSBRK => {
                    // arg is the wait count, by value. Non-zero =
                    // drain-only (no break); zero = send a break.
                    // PSTN SEND_BREAK carries its duration in the
                    // request itself, so a 250 ms timed break is a
                    // single class request.
                    if arg != 0 {
                        return Ok(0);
                    }
                    let transport = self.port.lock().transport.clone();
                    transport.send_break(250).await.map_err(map_acm_err)?;
                    Ok(0)
                }
                TIOCSBRK => {
                    let transport = self.port.lock().transport.clone();
                    transport.send_break(0xFFFF).await.map_err(map_acm_err)?;
                    self.port.lock().break_on = true;
                    Ok(0)
                }
                TIOCCBRK => {
                    let transport = self.port.lock().transport.clone();
                    transport.send_break(0).await.map_err(map_acm_err)?;
                    self.port.lock().break_on = false;
                    Ok(0)
                }
                TCFLSH => {
                    let mut p = self.port.lock();
                    match arg {
                        0 => p.rx.clear(),
                        1 => p.tx.clear(),
                        2 => {
                            p.rx.clear();
                            p.tx.clear();
                        }
                        _ => return Err(FsError::InvalidData),
                    }
                    Ok(0)
                }
                TCXONC => {
                    let mut p = self.port.lock();
                    match arg {
                        0 => p.tx_stopped = true,
                        1 => p.tx_stopped = false,
                        // 2/3 steer input flow; the CDC RX path
                        // has no XON/XOFF gate to steer.
                        _ => return Err(FsError::InvalidData),
                    }
                    Ok(0)
                }
                FIONREAD => {
                    let n = self.port.lock().rx.len() as i32;
                    ctx.write(arg, &n.to_le_bytes())?;
                    Ok(0)
                }
                TIOCGICOUNT => {
                    let img = self.port.lock().icounter_image();
                    ctx.write(arg, &img)?;
                    Ok(0)
                }
                TIOCGWINSZ => {
                    let ws = self.port.lock().winsize;
                    let mut out = [0u8; 8];
                    for (i, v) in ws.iter().enumerate() {
                        out[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
                    }
                    ctx.write(arg, &out)?;
                    Ok(0)
                }
                TIOCSWINSZ => {
                    let mut raw = [0u8; 8];
                    ctx.read(arg, &mut raw)?;
                    let mut p = self.port.lock();
                    for i in 0..4 {
                        p.winsize[i] = u16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]);
                    }
                    Ok(0)
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

impl TtyAcmFile {
    /// `TCSETS`-family commit path (#759): decode the image,
    /// actuate the device, and commit the user-visible state
    /// ONLY once the device accepted the change. A failed
    /// actuation returns the error with every committed field
    /// untouched.
    async fn apply_termios(
        &self,
        img: [u8; 36],
        speeds2: Option<(u32, u32)>,
        flush_rx: bool,
    ) -> Result<(), FsError> {
        let c_cflag = u32_at(&img, 8);
        let cbaud = c_cflag & CBAUD;
        // Rates: termios2 carries explicit speeds for BOTHER;
        // the classic form resolves purely from the CBAUD table
        // (a classic BOTHER has no speed word and resolves to
        // rate 0 only when c_ospeed is 0 — there is none, so a
        // classic BOTHER is invalid input).
        if speeds2.is_none() && cbaud == BOTHER {
            return Err(FsError::InvalidData);
        }
        let ospeed_hint = speeds2.map(|(_, o)| o).unwrap_or(0);
        let rate = match baud_for_cbaud(cbaud, ospeed_hint) {
            Some(r) => r,
            None => return Err(FsError::InvalidData),
        };
        let transport = self.port.lock().transport.clone();
        if rate == 0 {
            // B0 hangup: drop DTR + RTS. The line coding is not
            // part of a hangup; the stored speeds keep the last
            // real rate so a later TCGETS2 still reports it.
            transport
                .set_control_lines(false, false)
                .await
                .map_err(map_acm_err)?;
            let mut p = self.port.lock();
            p.termios = img;
            p.dtr = false;
            p.rts = false;
            return Ok(());
        }
        let coding = line_coding_from_termios(c_cflag, rate);
        transport
            .set_line_coding(coding)
            .await
            .map_err(map_acm_err)?;
        let mut p = self.port.lock();
        p.termios = img;
        p.ispeed = speeds2.map(|(i, _)| i).unwrap_or(rate);
        p.ospeed = rate;
        p.line_coding = coding;
        if flush_rx {
            p.rx.clear();
        }
        Ok(())
    }

    /// `TIOCMSET`/`BIS`/`BIC` commit path: only DTR/RTS are
    /// settable; input bits in the user's value are ignored.
    /// Actuate first, commit on success.
    async fn apply_tiocm(&self, cmd: u32, val: i32) -> Result<(), FsError> {
        const TIOCM_DTR: i32 = 0x002;
        const TIOCM_RTS: i32 = 0x004;
        let (cur_dtr, cur_rts, transport) = {
            let p = self.port.lock();
            (p.dtr, p.rts, p.transport.clone())
        };
        let (mut dtr, mut rts) = (cur_dtr, cur_rts);
        match cmd {
            TIOCMSET => {
                dtr = val & TIOCM_DTR != 0;
                rts = val & TIOCM_RTS != 0;
            }
            TIOCMBIS => {
                if val & TIOCM_DTR != 0 {
                    dtr = true;
                }
                if val & TIOCM_RTS != 0 {
                    rts = true;
                }
            }
            TIOCMBIC => {
                if val & TIOCM_DTR != 0 {
                    dtr = false;
                }
                if val & TIOCM_RTS != 0 {
                    rts = false;
                }
            }
            _ => return Err(FsError::Unsupported),
        }
        if dtr == cur_dtr && rts == cur_rts {
            return Ok(());
        }
        transport
            .set_control_lines(dtr, rts)
            .await
            .map_err(map_acm_err)?;
        let mut p = self.port.lock();
        p.dtr = dtr;
        p.rts = rts;
        Ok(())
    }
}

// ── devfs provider surface ────────────────────────────��────────

/// Resolve `"ttyACM<N>"` to its file operations, or `None`.
pub fn lookup_tty_acm(name: &str) -> Option<Arc<dyn FileOps>> {
    let idx: usize = name.strip_prefix("ttyACM")?.parse().ok()?;
    let port = get_port(idx)?;
    Some(Arc::new(TtyAcmFile { port, index: idx }) as Arc<dyn FileOps>)
}

/// All published ttyACM nodes as `(name, FileType::Special)`.
pub fn enumerate_tty_acm() -> Vec<(String, FileType)> {
    let g = TTY_ACM_NODES.lock();
    let mut out = Vec::new();
    for (i, slot) in g.iter().enumerate() {
        if slot.is_some() {
            out.push((format!("ttyACM{}", i), FileType::Special));
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A recording [`AcmTransport`] fake: captures every
    /// actuation, fails on script.
    #[derive(Debug)]
    struct FakeTransport {
        calls: IrqSafeSpinLock<Vec<FakeCall>>,
        fail_line_coding: IrqSafeSpinLock<bool>,
        break_unsupported: IrqSafeSpinLock<bool>,
    }

    // Manual Default: IrqSafeSpinLock has no Default impl (its inner
    // SpinLock does not), so the locks are constructed explicitly.
    impl Default for FakeTransport {
        fn default() -> Self {
            Self {
                calls: IrqSafeSpinLock::new(Vec::new()),
                fail_line_coding: IrqSafeSpinLock::new(false),
                break_unsupported: IrqSafeSpinLock::new(false),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeCall {
        LineCoding(LineCoding),
        ControlLines(bool, bool),
        Break(u16),
    }

    impl AcmTransport for FakeTransport {
        fn set_line_coding<'a>(&'a self, coding: LineCoding) -> AcmFuture<'a> {
            Box::pin(async move {
                self.calls.lock().push(FakeCall::LineCoding(coding));
                if *self.fail_line_coding.lock() {
                    return Err(AcmError::Transfer);
                }
                Ok(())
            })
        }
        fn set_control_lines<'a>(&'a self, dtr: bool, rts: bool) -> AcmFuture<'a> {
            Box::pin(async move {
                self.calls.lock().push(FakeCall::ControlLines(dtr, rts));
                Ok(())
            })
        }
        fn send_break<'a>(&'a self, duration_ms: u16) -> AcmFuture<'a> {
            Box::pin(async move {
                self.calls.lock().push(FakeCall::Break(duration_ms));
                if *self.break_unsupported.lock() {
                    return Err(AcmError::Unsupported);
                }
                Ok(())
            })
        }
    }

    /// In-memory [`IoctlContext`]: a 256-byte user window at
    /// base address 0x1000; out-of-window accesses fault with
    /// `BadAddress`, like a real user pointer would.
    struct FakeCtx {
        mem: IrqSafeSpinLock<[u8; 256]>,
    }

    impl FakeCtx {
        fn new() -> Self {
            Self {
                mem: IrqSafeSpinLock::new([0u8; 256]),
            }
        }
        const BASE: u64 = 0x1000;
        fn read_bytes(&self, off: usize, len: usize) -> Vec<u8> {
            self.mem.lock()[off..off + len].to_vec()
        }
        fn write_bytes(&self, off: usize, bytes: &[u8]) {
            self.mem.lock()[off..off + bytes.len()].copy_from_slice(bytes);
        }
    }

    impl IoctlContext for FakeCtx {
        fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
            if address < Self::BASE
                || address as usize - Self::BASE as usize + destination.len() > 256
            {
                return Err(FsError::BadAddress);
            }
            let off = (address - Self::BASE) as usize;
            destination.copy_from_slice(&self.mem.lock()[off..off + destination.len()]);
            Ok(())
        }
        fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
            if address < Self::BASE || address as usize - Self::BASE as usize + source.len() > 256 {
                return Err(FsError::BadAddress);
            }
            let off = (address - Self::BASE) as usize;
            self.mem.lock()[off..off + source.len()].copy_from_slice(source);
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }

    fn reset() {
        __reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
    }

    fn fresh_port() -> (usize, Arc<FakeTransport>, Arc<dyn FileOps>) {
        reset();
        let fake = Arc::new(FakeTransport::default());
        let idx = register_tty_acm(fake.clone());
        let file = lookup_tty_acm(&format!("ttyACM{}", idx)).expect("lookup");
        (idx, fake, file)
    }

    fn ioctl(fd: &Arc<dyn FileOps>, cmd: u32, arg: u64, ctx: &FakeCtx) -> Result<u64, FsError> {
        narf_scheduler::block_on(fd.ioctl_user(cmd, arg, ctx))
    }

    fn termios_image(c_cflag: u32) -> [u8; 36] {
        let coding = LineCoding::N_115200_8N1;
        let mut img = initial_termios_image(&coding);
        put_u32(&mut img, 8, c_cflag);
        img
    }

    /// Registration, lookup, enumeration, stat identity, sysfs —
    /// the node exists as major 166 minor N.
    fn bridge_register_lookup_sysfs() -> TestResult {
        let (idx, _fake, fd) = fresh_port();
        if idx != 0 {
            return TestResult::Fail("first index should be 0");
        }
        if port_count() != 1 {
            return TestResult::Fail("port count should be 1");
        }
        let names = enumerate_tty_acm();
        if names.len() != 1 || names[0].0 != "ttyACM0" {
            return TestResult::Fail("enumeration wrong");
        }
        if fd.rdev() != (TTY_ACM_MAJOR as u64) << 8 {
            return TestResult::Fail("rdev wrong");
        }
        if fd.stat().mode.perms != 0o660 {
            return TestResult::Fail("permissions wrong");
        }
        if fd.ino() != narf_filesystem::devfs::char_device_inode((TTY_ACM_MAJOR as u64) << 8) {
            return TestResult::Fail("inode not the char-device hash");
        }
        use narf_filesystem::sysfs::class_register;
        let tty_class = class_register("tty");
        let kobj = match tty_class.get_child("ttyACM0") {
            Some(k) => k,
            None => return TestResult::Fail("ttyACM0 kobject missing under class/tty"),
        };
        if kobj.attr_show("dev").as_deref() != Some("166:0\n") {
            return TestResult::Fail("sysfs dev attr wrong");
        }
        match kobj.attr_show("device/driver") {
            Some(s) if s.contains("cdc_acm") => {}
            _ => return TestResult::Fail("sysfs driver attr wrong"),
        }
        // Unregister withdraws the node + kobject; a fresh
        // registration takes the NEXT index (never reused).
        unregister_tty_acm(0);
        if lookup_tty_acm("ttyACM0").is_some() {
            return TestResult::Fail("lookup after unregister must fail");
        }
        if class_register("tty").get_child("ttyACM0").is_some() {
            return TestResult::Fail("kobject should be withdrawn after unregister");
        }
        let fake2 = Arc::new(FakeTransport::default());
        let idx2 = register_tty_acm(fake2);
        if idx2 != 1 {
            return TestResult::Fail("replug must take a fresh index");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_register_lookup_sysfs);

    /// TCGETS powers up at the cooked 115200 8N1 image; TCGETS2
    /// reports matching speeds.
    fn bridge_tcgets_default_image() -> TestResult {
        let (_idx, _f, fd) = fresh_port();
        let ctx = FakeCtx::new();
        if ioctl(&fd, TCGETS, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TCGETS failed");
        }
        let img = ctx.read_bytes(0, 36);
        if u32_at(&img, 0) != DEFAULT_IFLAG || u32_at(&img, 12) != DEFAULT_LFLAG {
            return TestResult::Fail("default flags wrong");
        }
        let cflag = u32_at(&img, 8);
        if cflag & CBAUD != 0x1002 {
            return TestResult::Fail("default CBAUD should be B115200 (0x1002)");
        }
        if cflag & CSIZE != 0x30 {
            return TestResult::Fail("default should be CS8");
        }
        if img[17 + 3] != 0x15 || img[17 + 6] != 0x01 {
            return TestResult::Fail("INIT_C_CC not in the default image");
        }
        if ioctl(&fd, TCGETS2, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TCGETS2 failed");
        }
        let img2 = ctx.read_bytes(0, 44);
        if u32_at(&img2, 36) != 115200 || u32_at(&img2, 40) != 115200 {
            return TestResult::Fail("TCGETS2 speeds wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_tcgets_default_image);

    /// TCSETS 57600 / CS7 / PARENB / CSTOPB actuates a line
    /// coding whose PSTN wire bytes are pinned
    /// ([0x00,0xE1,0x00,0x00] = 57600 LE, stop=2, parity=Even=2,
    /// bits=7), then commits — and TCGETS reads the user's
    /// image back verbatim.
    fn bridge_tcsets_actuates_and_commits() -> TestResult {
        let (_idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        // B57600 (0x1001) | CS7 (0x20) | CSTOPB | CREAD | PARENB,
        // plus an extra c_iflag bit to prove verbatim round-trip.
        let cflag = 0x1001 | 0x20 | CSTOPB | CREAD | PARENB;
        let mut img = termios_image(cflag);
        put_u32(&mut img, 0, DEFAULT_IFLAG | 0x0400);
        ctx.write_bytes(0, &img);
        if ioctl(&fd, TCSETS, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TCSETS failed");
        }
        let calls = fake.calls.lock().clone();
        if calls.len() != 1 {
            return TestResult::Fail("expected exactly one actuation");
        }
        match calls[0] {
            FakeCall::LineCoding(c) => {
                if c.encode() != [0x00, 0xE1, 0x00, 0x00, 2, 2, 7] {
                    return TestResult::Fail("line coding wire bytes wrong");
                }
            }
            _ => return TestResult::Fail("TCSETS must actuate set_line_coding"),
        }
        // Committed: TCGETS returns the user image verbatim.
        if ioctl(&fd, TCGETS, FakeCtx::BASE + 64, &ctx).is_err() {
            return TestResult::Fail("TCGETS after TCSETS failed");
        }
        let back = ctx.read_bytes(64, 36);
        if back != img.to_vec() {
            return TestResult::Fail("committed image not verbatim");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm_bridge",
        bridge_tcsets_actuates_and_commits
    );

    /// TCSETS2 with BOTHER carries the arbitrary rate in
    /// c_ospeed: 250000 baud must reach the device as
    /// [0x90,0xD0,0x03,0x00] LE.
    fn bridge_tcsets2_bother_rate() -> TestResult {
        let (_idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        let cflag = BOTHER | 0x30 | CREAD; // CS8
        let mut img = [0u8; 44];
        img[..36].copy_from_slice(&termios_image(cflag));
        put_u32(&mut img, 36, 250000);
        put_u32(&mut img, 40, 250000);
        ctx.write_bytes(0, &img);
        if ioctl(&fd, TCSETS2, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TCSETS2 failed");
        }
        let calls = fake.calls.lock().clone();
        match calls.first() {
            Some(FakeCall::LineCoding(c)) => {
                if c.baud_rate != 250000 || c.encode()[..4] != [0x90, 0xD0, 0x03, 0x00] {
                    return TestResult::Fail("BOTHER rate not carried to the device");
                }
            }
            _ => return TestResult::Fail("TCSETS2 must actuate set_line_coding"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_tcsets2_bother_rate);

    /// The #759 honesty pin: when the device refuses the line
    /// coding, the ioctl errors AND the committed image/coding
    /// stay at the previous state.
    fn bridge_tcsets_failure_commits_nothing() -> TestResult {
        let (_idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        let before = {
            let p = get_port(0).expect("port");
            let g = p.lock();
            (g.termios, g.line_coding)
        };
        *fake.fail_line_coding.lock() = true;
        let img = termios_image(0x1001 | 0x30 | CREAD);
        ctx.write_bytes(0, &img);
        match ioctl(&fd, TCSETS, FakeCtx::BASE, &ctx) {
            Err(FsError::Io(BlockError::IOError)) => {}
            _ => return TestResult::Fail("refused TCSETS must surface EIO"),
        }
        let p = get_port(0).expect("port");
        let g = p.lock();
        if g.termios != before.0 || g.line_coding != before.1 {
            return TestResult::Fail("a refused TCSETS committed state");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm_bridge",
        bridge_tcsets_failure_commits_nothing
    );

    /// B0 is a hangup: control lines drop, no line-coding
    /// request is issued, and the stored rate survives.
    fn bridge_b0_hangup() -> TestResult {
        let (_idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        let img = termios_image(0x30 | CREAD); // CBAUD field = 0 → B0
        ctx.write_bytes(0, &img);
        if ioctl(&fd, TCSETS, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("B0 TCSETS failed");
        }
        let calls = fake.calls.lock().clone();
        if calls.len() != 1 || calls[0] != FakeCall::ControlLines(false, false) {
            return TestResult::Fail("B0 must drop DTR/RTS and nothing else");
        }
        let p = get_port(0).expect("port");
        let g = p.lock();
        if g.dtr || g.rts {
            return TestResult::Fail("hangup did not commit outputs down");
        }
        if g.ospeed != 115200 || g.line_coding != LineCoding::N_115200_8N1 {
            return TestResult::Fail("hangup must not touch rate/coding");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_b0_hangup);

    /// Modem lines: TIOCMGET merges committed outputs with the
    /// SerialState inputs; TIOCMBIC actuates; TIOCMSET ignores
    /// input bits in the user's value.
    fn bridge_tiocm_paths() -> TestResult {
        let (idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        note_serial_state(
            idx,
            SerialState {
                rx_carrier: true,
                tx_carrier: true,
                break_received: false,
                ring_signal: false,
                framing_error: false,
                parity_error: false,
                overrun: false,
            },
        );
        if ioctl(&fd, TIOCMGET, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TIOCMGET failed");
        }
        let v = i32::from_le_bytes(ctx.read_bytes(0, 4).try_into().unwrap());
        // DTR|RTS (committed on) | CAR (rx_carrier) | DSR (tx_carrier).
        if v != 0x002 | 0x004 | 0x040 | 0x100 {
            return TestResult::Fail("TIOCMGET merge wrong");
        }
        // BIC DTR → actuation (false, true).
        ctx.write_bytes(0, &0x002i32.to_le_bytes());
        if ioctl(&fd, TIOCMBIC, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TIOCMBIC failed");
        }
        let calls = fake.calls.lock().clone();
        if calls.last() != Some(&FakeCall::ControlLines(false, true)) {
            return TestResult::Fail("TIOCMBIC did not actuate DTR down");
        }
        // SET with input bits set must only drive outputs:
        // value asks RTS on + DTR off (inputs CAR/DSR also set).
        ctx.write_bytes(0, &(0x040i32 | 0x100 | 0x004).to_le_bytes());
        if ioctl(&fd, TIOCMSET, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TIOCMSET failed");
        }
        let calls = fake.calls.lock().clone();
        if calls.last() != Some(&FakeCall::ControlLines(false, true)) {
            return TestResult::Fail("TIOCMSET must ignore input bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_tiocm_paths);

    /// Break paths: TCSBRK arg semantics + TIOCSBRK/TIOCCBRK
    /// durations + the capability refusal surfacing.
    fn bridge_break_paths() -> TestResult {
        let (_idx, fake, fd) = fresh_port();
        let ctx = FakeCtx::new();
        if ioctl(&fd, TIOCSBRK, 0, &ctx).is_err() {
            return TestResult::Fail("TIOCSBRK failed");
        }
        if ioctl(&fd, TIOCCBRK, 0, &ctx).is_err() {
            return TestResult::Fail("TIOCCBRK failed");
        }
        if ioctl(&fd, TCSBRK, 0, &ctx).is_err() {
            return TestResult::Fail("TCSBRK(0) failed");
        }
        // TCSBRK with a non-zero wait count issues nothing.
        let n_before = fake.calls.lock().len();
        if ioctl(&fd, TCSBRK, 1, &ctx).is_err() {
            return TestResult::Fail("TCSBRK(1) failed");
        }
        if fake.calls.lock().len() != n_before {
            return TestResult::Fail("TCSBRK(1) must not issue a break");
        }
        let calls = fake.calls.lock().clone();
        let breaks: Vec<u16> = calls
            .iter()
            .filter_map(|c| match c {
                FakeCall::Break(d) => Some(*d),
                _ => None,
            })
            .collect();
        if breaks != alloc::vec![0xFFFF, 0, 250] {
            return TestResult::Fail("break durations wrong");
        }
        // A device without the send-break capability refuses.
        *fake.break_unsupported.lock() = true;
        match ioctl(&fd, TIOCSBRK, 0, &ctx) {
            Err(FsError::Unsupported) => {}
            _ => return TestResult::Fail("capability-less break must be Unsupported"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_break_paths);

    /// SerialState counting: transitions + rising-edge errors,
    /// pinned into the TIOCGICOUNT byte layout.
    fn bridge_serial_state_counters() -> TestResult {
        let (idx, _f, fd) = fresh_port();
        let ctx = FakeCtx::new();
        let mut s = SerialState {
            rx_carrier: true,
            tx_carrier: false,
            break_received: false,
            ring_signal: false,
            framing_error: true,
            parity_error: false,
            overrun: false,
        };
        note_serial_state(idx, s); // DCD transition 1, frame 1
        note_serial_state(idx, s); // same report again: no new counts
        s.framing_error = false;
        s.parity_error = true;
        s.break_received = true;
        note_serial_state(idx, s); // parity 1, brk 1
        if ioctl(&fd, TIOCGICOUNT, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TIOCGICOUNT failed");
        }
        let img = ctx.read_bytes(0, 80);
        let at = |off: usize| i32::from_le_bytes(img[off..off + 4].try_into().unwrap());
        if at(12) != 1 {
            return TestResult::Fail("dcd counter wrong (offset 12)");
        }
        if at(24) != 1 {
            return TestResult::Fail("frame counter wrong (offset 24)");
        }
        if at(32) != 1 {
            return TestResult::Fail("parity counter wrong (offset 32)");
        }
        if at(36) != 1 {
            return TestResult::Fail("brk counter wrong (offset 36)");
        }
        if at(0) != 0 || at(28) != 0 || at(40) != 0 {
            return TestResult::Fail("cts/overrun/buf_overrun must stay 0 here");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_serial_state_counters);

    /// Data path through the file + pump helpers: writes queue
    /// in the TX ring, the pump peek/skip drains them, received
    /// bytes read back, FIONREAD/TCFLSH/TCXONC behave.
    fn bridge_data_path_and_flush() -> TestResult {
        let (idx, _f, fd) = fresh_port();
        let ctx = FakeCtx::new();
        feed_rx(idx, b"hello");
        if ioctl(&fd, FIONREAD, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("FIONREAD failed");
        }
        let n = i32::from_le_bytes(ctx.read_bytes(0, 4).try_into().unwrap());
        if n != 5 {
            return TestResult::Fail("FIONREAD count wrong");
        }
        let mut buf = [0u8; 8];
        let got = narf_scheduler::block_on(fd.read(0, &mut buf));
        match got {
            Ok(5) if &buf[..5] == b"hello" => {}
            _ => return TestResult::Fail("read did not return the RX bytes"),
        }
        // Write queues; peek shows it; skip (post-send) drains.
        let wrote = narf_scheduler::block_on(fd.write(0, b"world"));
        if wrote != Ok(5) {
            return TestResult::Fail("write did not queue 5 bytes");
        }
        let mut chunk = [0u8; 8];
        if tx_peek(idx, &mut chunk) != 5 || &chunk[..5] != b"world" {
            return TestResult::Fail("TX peek wrong");
        }
        tx_skip(idx, 5);
        if tx_peek(idx, &mut chunk) != 0 {
            return TestResult::Fail("TX ring not drained after skip");
        }
        // TCXONC stop suppresses peek + POLL_OUT; start restores.
        if ioctl(&fd, TCXONC, 0, &ctx).is_err() {
            return TestResult::Fail("TCXONC stop failed");
        }
        if fd.poll_readiness() & POLL_OUT != 0 {
            return TestResult::Fail("stopped port must not poll writable");
        }
        if ioctl(&fd, TCXONC, 1, &ctx).is_err() {
            return TestResult::Fail("TCXONC start failed");
        }
        if fd.poll_readiness() & POLL_OUT == 0 {
            return TestResult::Fail("restarted port must poll writable");
        }
        // TCFLSH input flush empties RX.
        feed_rx(idx, b"xy");
        if ioctl(&fd, TCFLSH, 0, &ctx).is_err() {
            return TestResult::Fail("TCFLSH failed");
        }
        if ioctl(&fd, FIONREAD, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("FIONREAD after flush failed");
        }
        let n = i32::from_le_bytes(ctx.read_bytes(0, 4).try_into().unwrap());
        if n != 0 {
            return TestResult::Fail("flush did not empty RX");
        }
        if ioctl(&fd, TCFLSH, 9, &ctx).is_ok() {
            return TestResult::Fail("bad TCFLSH selector must error");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_data_path_and_flush);

    /// Winsize round-trip + unknown ioctls + bad user pointers.
    fn bridge_misc_ioctls() -> TestResult {
        let (_idx, _f, fd) = fresh_port();
        let ctx = FakeCtx::new();
        let ws: [u16; 4] = [24, 80, 0, 0];
        let mut raw = [0u8; 8];
        for (i, v) in ws.iter().enumerate() {
            raw[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        ctx.write_bytes(0, &raw);
        if ioctl(&fd, TIOCSWINSZ, FakeCtx::BASE, &ctx).is_err() {
            return TestResult::Fail("TIOCSWINSZ failed");
        }
        if ioctl(&fd, TIOCGWINSZ, FakeCtx::BASE + 16, &ctx).is_err() {
            return TestResult::Fail("TIOCGWINSZ failed");
        }
        if ctx.read_bytes(16, 8) != raw.to_vec() {
            return TestResult::Fail("winsize round-trip wrong");
        }
        match ioctl(&fd, 0x9999, FakeCtx::BASE, &ctx) {
            Err(FsError::Unsupported) => {}
            _ => return TestResult::Fail("unknown ioctl must be Unsupported"),
        }
        match ioctl(&fd, TCGETS, 0x10, &ctx) {
            Err(FsError::BadAddress) => {}
            _ => return TestResult::Fail("bad user pointer must fault"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm_bridge", bridge_misc_ioctls);
}
