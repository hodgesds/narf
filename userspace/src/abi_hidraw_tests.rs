//! `/dev/hidrawN` through the syscall boundary: open, read, write, ioctl,
//! ppoll and close as libfido2 drives a FIDO token, with a CTAPHID
//! authenticator (`narf_ctap2::fixture_token`) behind a scripted HID
//! transport. Errnos and their order are `drivers/hid/hidraw.c`'s; values
//! from `include/uapi/asm-generic/errno{-base,}.h`.
use crate::abi_test_support::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_input::hid_device::{self, HidDevice, HidInfo, HidIoError, HidTransport, ReportType};
use narf_lib::sync::IrqSafeSpinLock;

const BAD: u64 = 0x0000_8000_0000_0000;
const EIO: i64 = -5;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const ENOSYS: i64 = -38;
const ETIMEDOUT: i64 = -110;
const SIGPIPE: u32 = 13;

const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;

/// The CTAP-spec FIDO HID report descriptor: 64-byte IN and OUT reports
/// on usage page 0xF1D0, no report IDs.
const FIDO: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

const NAME: &str = "Yubico YubiKey OTP+FIDO+CCID";

const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | ((b'H' as u64) << 8) | nr
}
const HIDIOCGRDESCSIZE: u64 = ioc(2, 0x01, 4);
const HIDIOCGRDESC: u64 = ioc(2, 0x02, 4100);
const HIDIOCGRAWINFO: u64 = ioc(2, 0x03, 8);
const fn hidiocgrawname(len: u64) -> u64 {
    ioc(2, 0x04, len)
}
const fn hidiocsfeature(len: u64) -> u64 {
    ioc(3, 0x06, len)
}
const fn hidiocgfeature(len: u64) -> u64 {
    ioc(3, 0x07, len)
}
const HIDIOCREVOKE: u64 = ioc(1, 0x0d, 4);

// ── A FIDO token on a scripted transport ───────────────────────────────

/// The interrupt-OUT path hands each 64-byte CTAPHID packet to the
/// authenticator and feeds its answers back as input reports, as a
/// token's interrupt-IN endpoint would.
struct Token {
    token: IrqSafeSpinLock<narf_ctap2::fixture_token::FixtureToken>,
    dev: IrqSafeSpinLock<Option<Weak<HidDevice>>>,
    output_error: IrqSafeSpinLock<Option<HidIoError>>,
    raw_error: IrqSafeSpinLock<Option<HidIoError>>,
    sets: IrqSafeSpinLock<Vec<(u8, Vec<u8>, ReportType)>>,
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Token").finish_non_exhaustive()
    }
}

#[async_trait]
impl HidTransport for Token {
    async fn output_report(&self, data: &[u8]) -> Result<usize, HidIoError> {
        let scripted = *self.output_error.lock();
        if let Some(e) = scripted {
            return Err(e);
        }
        // Report ID 0 (the descriptor uses none), then one packet.
        if data.len() != 65 || data[0] != 0 {
            return Err(HidIoError::InvalidArgs);
        }
        let mut packet = [0u8; 64];
        packet.copy_from_slice(&data[1..]);
        let mut replies = Vec::new();
        {
            let mut token = self.token.lock();
            token.handle_report(&packet);
            let mut out = [0u8; 64];
            // A parked operation answers with keepalives forever; INIT and
            // PING never park, so a bound is only a guard.
            for _ in 0..16 {
                if token.next_report(&mut out).is_err() {
                    break;
                }
                replies.push(out);
            }
        }
        let dev = self.dev.lock().as_ref().and_then(Weak::upgrade);
        if let Some(dev) = dev {
            for reply in &replies {
                dev.report_in(reply);
            }
        }
        Ok(data.len())
    }

    async fn raw_request(
        &self,
        id: u8,
        buf: &mut [u8],
        kind: ReportType,
        set: bool,
    ) -> Result<usize, HidIoError> {
        let scripted = *self.raw_error.lock();
        if let Some(e) = scripted {
            return Err(e);
        }
        if set {
            self.sets.lock().push((id, buf.to_vec(), kind));
            return Ok(buf.len());
        }
        let reply = [id, 0x11, 0x22, 0x33];
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok(n)
    }
}

struct Fixture {
    dev: Arc<HidDevice>,
    token: Arc<Token>,
    minor: u32,
}

impl Fixture {
    fn plug() -> Result<Self, &'static str> {
        narf_filesystem::hidraw::populate_hidraw_class();
        let token = Arc::new(Token {
            token: IrqSafeSpinLock::new(narf_ctap2::fixture_token::FixtureToken::new([7; 32])),
            dev: IrqSafeSpinLock::new(None),
            output_error: IrqSafeSpinLock::new(None),
            raw_error: IrqSafeSpinLock::new(None),
            sets: IrqSafeSpinLock::new(Vec::new()),
        });
        let dev = hid_device::register(
            HidInfo {
                bus: narf_input::evdev::bus::USB,
                vendor: 0x1050,
                product: 0x0407,
                version: 0x0526,
                country: 0,
                name: String::from(NAME),
                phys: String::from("usb-0000:c6:00.4-1/input1"),
                uniq: String::new(),
                report_descriptor: FIDO.to_vec(),
                sysfs_parent: String::from(
                    "devices/pci0000:00/0000:00:08.3/0000:c6:00.4/usb7/7-1/7-1:1.1",
                ),
            },
            token.clone(),
        );
        *token.dev.lock() = Some(Arc::downgrade(&dev));
        let minor = match narf_filesystem::hidraw::node_of(&dev) {
            Some(node) => node.minor(),
            None => {
                hid_device::unregister(&dev);
                return Err("registered FIDO device has no hidraw node");
            }
        };
        Ok(Self { dev, token, minor })
    }

    fn path(&self) -> Vec<u8> {
        format!("/dev/hidraw{}\0", self.minor).into_bytes()
    }

    fn open(&self) -> Result<u32, &'static str> {
        let flags = (crate::fd::O_RDWR | crate::fd::O_NONBLOCK) as u64;
        match call_open(self.path().as_ptr() as u64, flags) {
            Some(fd) if fd >= 0 => Ok(fd as u32),
            _ => Err("open(/dev/hidrawN, O_RDWR|O_NONBLOCK) failed"),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        hid_device::unregister(&self.dev);
    }
}

fn read(fd: u32, buf: &mut [u8]) -> Option<i64> {
    call(
        Syscall::Read.raw(),
        a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
    )
}

fn write(fd: u32, buf: &[u8]) -> Option<i64> {
    call(
        Syscall::Write.raw(),
        a2(fd as u64, buf.as_ptr() as u64, buf.len() as u64),
    )
}

fn ioctl(fd: u32, cmd: u64, arg: u64) -> Option<i64> {
    call(Syscall::Ioctl.raw(), a2(fd as u64, cmd, arg))
}

fn close(fd: u32) {
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
}

/// `ppoll(fd, POLLIN|POLLOUT, timeout 0)`'s revents, limited to the bits
/// this file asserts on.
fn revents(fd: u32) -> Result<u16, &'static str> {
    let mut pollfd = [0u8; 8];
    pollfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pollfd[4..6].copy_from_slice(&(POLLIN | POLLOUT).to_ne_bytes());
    let timeout = [0u64; 2];
    match call(
        Syscall::Ppoll.raw(),
        a4(pollfd.as_mut_ptr() as u64, 1, timeout.as_ptr() as u64, 0, 8),
    ) {
        Some(n) if n >= 0 => {
            Ok(u16::from_ne_bytes([pollfd[6], pollfd[7]]) & (POLLIN | POLLOUT | POLLERR | POLLHUP))
        }
        _ => Err("ppoll failed"),
    }
}

/// Read a whole file through open/read/close.
fn slurp(path: &[u8]) -> Result<Vec<u8>, &'static str> {
    let fd = match call_open(path.as_ptr() as u64, 0) {
        Some(fd) if fd >= 0 => fd as u32,
        _ => return Err("sysfs open failed"),
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match read(fd, &mut buf) {
            Some(0) => break,
            Some(n) if n > 0 => out.extend_from_slice(&buf[..n as usize]),
            _ => {
                close(fd);
                return Err("sysfs read failed");
            }
        }
    }
    close(fd);
    Ok(out)
}

/// One CTAPHID initialization packet on `cid`, as a hidraw write: report
/// ID 0, then the 64-byte packet.
fn init_packet(cid: u32, cmd: u8, payload: &[u8]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[1..5].copy_from_slice(&cid.to_be_bytes());
    out[5] = 0x80 | cmd;
    out[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let n = payload.len().min(57);
    out[8..8 + n].copy_from_slice(&payload[..n]);
    out
}

fn cont_packet(cid: u32, seq: u8, payload: &[u8]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[1..5].copy_from_slice(&cid.to_be_bytes());
    out[5] = seq;
    out[6..6 + payload.len()].copy_from_slice(payload);
    out
}

// ── CTAPHID round trip ─────────────────────────────────────────────────

fn smoke_hidraw_ctaphid_init_and_ping_round_trip() -> TestResult {
    with_setup(|| {
        let fx = Fixture::plug()?;
        let fd = fx.open()?;
        // The node: S_IFCHR 0600, rdev 243:N (what libudev matches).
        let mut sb = [0u8; STAT_SIZE];
        if call_stat(fx.path().as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0)
            || stat_mode(&sb) != 0o020600
            || stat_rdev(&sb) != narf_filesystem::devfs::linux_makedev(243, fx.minor)
        {
            close(fd);
            return Err("stat(/dev/hidrawN) is not a 243:N 0600 char device");
        }
        let r = (|| {
            // What libfido2's fido_hid_open asks first.
            let mut size = 0i32;
            if ioctl(fd, HIDIOCGRDESCSIZE, &mut size as *mut i32 as u64) != Some(0)
                || size != FIDO.len() as i32
            {
                return Err("HIDIOCGRDESCSIZE");
            }
            let mut rdesc = [0u8; 4100];
            rdesc[..4].copy_from_slice(&(size as u32).to_ne_bytes());
            if ioctl(fd, HIDIOCGRDESC, rdesc.as_mut_ptr() as u64) != Some(0)
                || rdesc[4..4 + FIDO.len()] != *FIDO
            {
                return Err("HIDIOCGRDESC");
            }
            let mut info = [0u8; 8];
            if ioctl(fd, HIDIOCGRAWINFO, info.as_mut_ptr() as u64) != Some(0)
                || u32::from_ne_bytes(info[0..4].try_into().unwrap()) != 3
                || i16::from_ne_bytes([info[4], info[5]]) != 0x1050
                || i16::from_ne_bytes([info[6], info[7]]) != 0x0407
            {
                return Err("HIDIOCGRAWINFO");
            }
            let mut name = [0u8; 256];
            if ioctl(fd, hidiocgrawname(256), name.as_mut_ptr() as u64)
                != Some(NAME.len() as i64 + 1)
                || name[..NAME.len()] != *NAME.as_bytes()
            {
                return Err("HIDIOCGRAWNAME");
            }
            let mut buf = [0u8; 64];
            if read(fd, &mut buf) != Some(EAGAIN) {
                return Err("empty O_NONBLOCK read is not EAGAIN");
            }
            if revents(fd)? != POLLOUT {
                return Err("idle hidraw does not poll writable-only");
            }
            // CTAPHID_INIT on the broadcast channel.
            let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
            if write(fd, &init_packet(0xffff_ffff, 0x06, &nonce)) != Some(65) {
                return Err("CTAPHID_INIT write");
            }
            if revents(fd)? != POLLIN | POLLOUT {
                return Err("INIT response did not make the fd readable");
            }
            if read(fd, &mut buf) != Some(64) {
                return Err("INIT response read");
            }
            let cid = u32::from_be_bytes([buf[15], buf[16], buf[17], buf[18]]);
            if buf[0..4] != [0xff; 4]
                || buf[4] != 0x86
                || u16::from_be_bytes([buf[5], buf[6]]) != 17
                || buf[7..15] != nonce
                || cid == 0
                || cid == 0xffff_ffff
                || buf[19] != 2
            {
                return Err("INIT response malformed");
            }
            // CTAPHID_PING of 100 bytes: two packets out, two back.
            let payload: Vec<u8> = (0..100u8).collect();
            if write(fd, &init_packet(cid, 0x01, &payload)) != Some(65)
                || write(fd, &cont_packet(cid, 0, &payload[57..])) != Some(65)
            {
                return Err("PING writes");
            }
            let mut echoed = Vec::new();
            if read(fd, &mut buf) != Some(64)
                || buf[0..4] != cid.to_be_bytes()
                || buf[4] != 0x81
                || u16::from_be_bytes([buf[5], buf[6]]) != 100
            {
                return Err("PING init response");
            }
            echoed.extend_from_slice(&buf[7..64]);
            if read(fd, &mut buf) != Some(64) || buf[0..4] != cid.to_be_bytes() || buf[4] != 0 {
                return Err("PING continuation response");
            }
            echoed.extend_from_slice(&buf[5..5 + 43]);
            if echoed != payload {
                return Err("PING payload not echoed");
            }
            if read(fd, &mut buf) != Some(EAGAIN) {
                return Err("drained fd is not EAGAIN");
            }
            // fido_id's view: the parent's report_descriptor, reached
            // through the class and device links.
            let class = format!("/sys/class/hidraw/hidraw{}", fx.minor);
            if slurp(format!("{class}/device/report_descriptor\0").as_bytes())? != FIDO
                || !slurp(format!("{class}/device/uevent\0").as_bytes())?
                    .windows(30)
                    .any(|w| w == b"HID_ID=0003:00001050:00000407\n")
                || slurp(format!("/sys/dev/char/243:{}/uevent\0", fx.minor).as_bytes())?
                    != format!("MAJOR=243\nMINOR={0}\nDEVNAME=hidraw{0}\n", fx.minor).into_bytes()
            {
                return Err("sysfs links do not chase to the HID device");
            }
            Ok(())
        })();
        close(fd);
        r
    })
}
kernel_test_in!(
    "syscall_abi/hidraw",
    smoke_hidraw_ctaphid_init_and_ping_round_trip
);

// ── errnos ─────────────────────────────────────────────────────────────

fn smoke_hidraw_errno_through_syscalls() -> TestResult {
    with_setup(|| {
        let fx = Fixture::plug()?;
        let fd = fx.open()?;
        let r = (|| {
            let big = alloc::vec![0u8; 16385];
            if write(fd, &[0]) != Some(EINVAL) || write(fd, &big) != Some(EINVAL) {
                return Err("write size checks are not EINVAL");
            }
            for (cmd, arg, want) in [
                // A foreign type is EINVAL; an unknown number ENOTTY.
                (0x8004_4501, 0, EINVAL),
                (ioc(2, 0x0e, 4), 0, ENOTTY),
                (HIDIOCGRDESCSIZE, BAD, EFAULT),
                (HIDIOCREVOKE, 1, EINVAL),
                (hidiocgfeature(1), 0, EINVAL),
            ] {
                if ioctl(fd, cmd, arg) != Some(want) {
                    return Err("ioctl errno or precedence differs from hidraw_ioctl");
                }
            }
            let mut rdesc = [0u8; 4100];
            rdesc[..4].copy_from_slice(&4096u32.to_ne_bytes());
            if ioctl(fd, HIDIOCGRDESC, rdesc.as_mut_ptr() as u64) != Some(EINVAL) {
                return Err("HIDIOCGRDESC len 4096 is not EINVAL");
            }
            // Feature reports: GET returns the transfer length, SET the
            // count.
            let mut feature = [0x0du8, 0, 0, 0];
            if ioctl(fd, hidiocgfeature(4), feature.as_mut_ptr() as u64) != Some(4)
                || feature != [0x0d, 0x11, 0x22, 0x33]
            {
                return Err("HIDIOCGFEATURE");
            }
            let set = [5u8, 1, 2];
            if ioctl(fd, hidiocsfeature(3), set.as_ptr() as u64) != Some(3)
                || fx.token.sets.lock().last()
                    != Some(&(5, alloc::vec![5, 1, 2], ReportType::Feature))
            {
                return Err("HIDIOCSFEATURE");
            }
            // Transport errnos reach userspace unchanged; a stall is EPIPE
            // without SIGPIPE.
            let packet = init_packet(0xffff_ffff, 0x06, &[0; 8]);
            for (err, want) in [
                (HidIoError::Stall, EPIPE),
                (HidIoError::Timeout, ETIMEDOUT),
                (HidIoError::Io, EIO),
                (HidIoError::NoDevice, ENODEV),
                (HidIoError::InvalidArgs, EINVAL),
            ] {
                *fx.token.output_error.lock() = Some(err);
                if write(fd, &packet) != Some(want) {
                    return Err("output_report errno not passed through write");
                }
                *fx.token.raw_error.lock() = Some(err);
                if ioctl(fd, hidiocgfeature(4), feature.as_mut_ptr() as u64) != Some(want) {
                    return Err("raw_request errno not passed through the ioctl");
                }
            }
            if crate::handlers::signal_pending_of(FAKE_TASK) & crate::handlers::sig_bit(SIGPIPE)
                != 0
            {
                crate::handlers::clear_signal_pending(FAKE_TASK, SIGPIPE);
                return Err("a stalled hidraw write raised SIGPIPE");
            }
            // -ENOSYS from raw_request; from output_report it is the
            // SET_REPORT fallback instead.
            *fx.token.raw_error.lock() = Some(HidIoError::Unsupported);
            if ioctl(fd, hidiocgfeature(4), feature.as_mut_ptr() as u64) != Some(ENOSYS) {
                return Err("raw_request ENOSYS not passed through");
            }
            *fx.token.raw_error.lock() = None;
            *fx.token.output_error.lock() = Some(HidIoError::Unsupported);
            if write(fd, &packet) != Some(65)
                || fx.token.sets.lock().last().map(|s| (s.0, s.2)) != Some((0, ReportType::Output))
            {
                return Err("ENOSYS output did not fall back to SET_REPORT(Output)");
            }
            *fx.token.output_error.lock() = None;
            // HIDIOCREVOKE: this fd is dead, ENODEV everywhere.
            if ioctl(fd, HIDIOCREVOKE, 0) != Some(0) {
                return Err("HIDIOCREVOKE");
            }
            let mut buf = [0u8; 64];
            if read(fd, &mut buf) != Some(ENODEV)
                || write(fd, &packet) != Some(ENODEV)
                || ioctl(fd, HIDIOCGRDESCSIZE, buf.as_mut_ptr() as u64) != Some(ENODEV)
                || ioctl(fd, 0x8004_4501, 0) != Some(ENODEV)
            {
                return Err("revoked fd is not ENODEV");
            }
            if revents(fd)? & (POLLERR | POLLHUP) != POLLERR | POLLHUP {
                return Err("revoked fd does not poll POLLERR|POLLHUP");
            }
            Ok(())
        })();
        close(fd);
        r
    })
}
kernel_test_in!("syscall_abi/hidraw", smoke_hidraw_errno_through_syscalls);

fn smoke_hidraw_unplug_through_syscalls() -> TestResult {
    with_setup(|| {
        let fx = Fixture::plug()?;
        let fd = fx.open()?;
        fx.dev.report_in(&[0xab; 64]);
        hid_device::unregister(&fx.dev);
        let r = (|| {
            let mut buf = [0u8; 64];
            // The queued report survives the unplug; then EIO, not EAGAIN.
            if read(fd, &mut buf) != Some(64) || buf != [0xab; 64] {
                return Err("report queued before unplug lost");
            }
            if read(fd, &mut buf) != Some(EIO) {
                return Err("empty read after unplug is not EIO");
            }
            if revents(fd)? & (POLLERR | POLLHUP) != POLLERR | POLLHUP {
                return Err("unplugged fd does not poll POLLERR|POLLHUP");
            }
            if write(fd, &init_packet(0xffff_ffff, 0x06, &[0; 8])) != Some(ENODEV)
                || ioctl(fd, HIDIOCGRDESCSIZE, buf.as_mut_ptr() as u64) != Some(ENODEV)
            {
                return Err("write / ioctl after unplug is not ENODEV");
            }
            // devtmpfs dropped the node.
            if call_open(fx.path().as_ptr() as u64, 2) != Some(-2) {
                return Err("open of an unplugged hidraw node is not ENOENT");
            }
            Ok(())
        })();
        close(fd);
        r
    })
}
kernel_test_in!("syscall_abi/hidraw", smoke_hidraw_unplug_through_syscalls);
