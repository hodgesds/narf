//! `/dev/hidrawN` and the HID sysfs surface.
//!
//! Linux `drivers/hid/hidraw.c` for every device in the transport-neutral
//! registry [`narf_input::hid_device`], plus the parts of
//! `drivers/hid/hid-core.c` raw HID users read from sysfs:
//!
//! ```text
//! <parent>/BBBB:VVVV:PPPP.NNNN/        hid device (hid_add_device)
//!     uevent   HID_ID= HID_NAME= HID_PHYS= HID_UNIQ= MODALIAS=  (hid_uevent)
//!     modalias country report_descriptor
//!     subsystem -> bus/hid
//!     hidraw/hidrawN/                 class device (hidraw_connect)
//!         dev uevent(MAJOR= MINOR= DEVNAME=hidrawN)
//!         subsystem -> class/hidraw   device -> ../../../BBBB:VVVV:PPPP.NNNN
//! /sys/bus/hid/devices/BBBB:VVVV:PPPP.NNNN -> the hid device
//! /sys/class/hidraw/hidrawN, /sys/dev/char/243:N -> hidrawN
//! ```
//!
//! `<parent>` is the transport's [`HidInfo::sysfs_parent`] (the USB
//! interface, created by get-or-create), or `/sys/devices/platform/narf-hid`
//! — a platform device with a `subsystem` link and a `/sys/bus/platform`
//! entry, so udev's `path_id` can walk it — when the transport has none.
//! systemd's `fido_id` reads the parent's `report_descriptor`, Chromium
//! `HID_ID`/`HID_NAME`, libfido2 and Firefox `HIDIOCGRDESC`.
//!
//! The node is a clone-on-open device: devfs lookup returns a prototype on
//! the device's [`HidrawNode`] (stat, owner, mode and the uaccess ACL live
//! there, so udev's chown/chmod/setxattr persist across opens), and each
//! `open(2)` adds a [`HidrawList`] — the per-open report ring of
//! `HIDRAW_BUFFER_SIZE` slots — that the device's report sink fills.
//!
//! LINUX-GAPs, each small:
//! - `hidraw_read`'s empty-queue order is signal (`-ERESTARTSYS`), then
//!   `-EIO`, then `-EAGAIN`; the syscall layer checks the signal after the
//!   file op reports `WouldBlock`, so a signal pending on entry to a read
//!   of an empty, unplugged device gives `EIO`.
//! - `hidraw_read` keeps a report whose `copy_to_user` faults; here the
//!   syscall layer copies after the file op has consumed it.
//! - `hidraw_send_report` sizes the request before `memdup_user`; `write(2)`
//!   copies the buffer first, so an unreadable buffer with `count < 2` is
//!   `EFAULT`, not `EINVAL`. (The ioctls keep Linux's order.)
//! - `HIDIOCREVOKE` wakes this fd's pollers and parked readers; Linux's
//!   `hidraw_revoke` only sets the flag, and a reader already blocked on
//!   an empty ring stays blocked.
//! - The first open's `hid_hw_power(PM_HINT_FULLON)` / `hid_hw_open` and
//!   last close's `hid_hw_close` have no `HidTransport` counterpart.
//! - No `fasync` (`SIGIO`) and no `DRIVER=` / `driver` link: NARF binds no
//!   HID drivers to the bus.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_input::hid_device::{
    self, Change, HidDevice, HidIoError, ReportType, HID_MAX_BUFFER_SIZE, HID_MAX_DESCRIPTOR_SIZE,
};
use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

use crate::sysfs::{
    class_register, get_or_create_child, get_root, kobject_add_attr, kobject_add_bin_attr,
    kobject_add_uevent_attr, kobject_emit_uevent, Kobject,
};
use crate::uevent::UeventAction;
use crate::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN,
    POLL_OUT, POLL_RDNORM,
};

/// The hidraw character major. Linux takes a dynamic one
/// (`alloc_chrdev_region` in `hidraw_init`); 243 is what that allocation
/// lands on for the target laptops, and is free in NARF's static table
/// (`/proc/devices`).
pub const HIDRAW_MAJOR: u32 = 243;
/// `HIDRAW_MAX_DEVICES` (`include/uapi/linux/hidraw.h:54`).
pub const HIDRAW_MAX_DEVICES: usize = 64;
/// `HIDRAW_BUFFER_SIZE` (`include/uapi/linux/hidraw.h:56`): the per-open
/// ring. One slot always stays empty (`new_head == tail` is full), so an
/// open holds at most 63 reports.
pub const HIDRAW_BUFFER_SIZE: usize = 64;

/// `EPOLLWRNORM` (`include/uapi/linux/eventpoll.h`).
const POLL_WRNORM: u32 = 0x0100;

// ── ioctls (`include/uapi/linux/hidraw.h`) ─────────────────────────────

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
/// `IOCSIZE_MASK` (`include/uapi/asm-generic/ioctl.h`).
const IOCSIZE_MASK: u32 = 0x3fff << 16;

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((b'H' as u32) << 8) | nr
}

/// `HIDIOCGRDESCSIZE` — `_IOR('H', 0x01, int)`.
pub const HIDIOCGRDESCSIZE: u32 = ioc(IOC_READ, 0x01, 4);
/// `HIDIOCGRDESC` — `_IOR('H', 0x02, struct hidraw_report_descriptor)`.
pub const HIDIOCGRDESC: u32 = ioc(IOC_READ, 0x02, 4 + HID_MAX_DESCRIPTOR_SIZE as u32);
/// `HIDIOCGRAWINFO` — `_IOR('H', 0x03, struct hidraw_devinfo)`.
pub const HIDIOCGRAWINFO: u32 = ioc(IOC_READ, 0x03, 8);
/// `HIDIOCREVOKE` — `_IOW('H', 0x0D, int)`.
pub const HIDIOCREVOKE: u32 = ioc(IOC_WRITE, 0x0D, 4);
/// `HIDIOCTL_LAST` = `_IOC_NR(HIDIOCREVOKE)`.
const HIDIOCTL_LAST: u32 = 0x0D;

/// `HIDIOCGRAWNAME(len)`.
pub const fn hidiocgrawname(len: u32) -> u32 {
    ioc(IOC_READ, 0x04, len)
}
/// `HIDIOCGRAWPHYS(len)`.
pub const fn hidiocgrawphys(len: u32) -> u32 {
    ioc(IOC_READ, 0x05, len)
}
/// `HIDIOCSFEATURE(len)`.
pub const fn hidiocsfeature(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x06, len)
}
/// `HIDIOCGFEATURE(len)`.
pub const fn hidiocgfeature(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x07, len)
}
/// `HIDIOCGRAWUNIQ(len)`.
pub const fn hidiocgrawuniq(len: u32) -> u32 {
    ioc(IOC_READ, 0x08, len)
}
/// `HIDIOCSINPUT(len)`.
pub const fn hidiocsinput(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x09, len)
}
/// `HIDIOCGINPUT(len)`.
pub const fn hidiocginput(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x0A, len)
}
/// `HIDIOCSOUTPUT(len)`.
pub const fn hidiocsoutput(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x0B, len)
}
/// `HIDIOCGOUTPUT(len)`.
pub const fn hidiocgoutput(len: u32) -> u32 {
    ioc(IOC_WRITE | IOC_READ, 0x0C, len)
}

/// A transport failure as the errno Linux's transports return through
/// `hid_hw_*` — hidraw passes it to userspace unchanged.
fn hid_err(e: HidIoError) -> FsError {
    match e {
        HidIoError::NoDevice => FsError::NoDevice,
        HidIoError::Stall => FsError::Stalled,
        HidIoError::Timeout => FsError::TransferTimedOut,
        HidIoError::Unsupported => FsError::NotImplemented,
        HidIoError::InvalidArgs => FsError::InvalidData,
        HidIoError::Io => FsError::Io(narf_block::BlockError::IOError),
    }
}

/// `struct hid_device`'s `name[128]`, `phys[64]`, `uniq[64]`: transports
/// `strscpy` into them, so what hidraw and the uevent report is the
/// string up to its first NUL, cut to `cap - 1` bytes (on a character
/// boundary).
fn hid_field(s: &str, cap: usize) -> &str {
    let s = s.split('\0').next().unwrap_or("");
    if s.len() < cap {
        return s;
    }
    let mut end = cap - 1;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

const NAME_CAP: usize = 128;
const PHYS_CAP: usize = 64;
const UNIQ_CAP: usize = 64;

// ── Per-node state ─────────────────────────────────────────────────────

/// The one extended attribute a hidraw node stores: the POSIX access ACL
/// logind's udev `uaccess` builtin writes for a FIDO token
/// (`60-fido-id.rules` → `ID_FIDO_TOKEN` → `TAG+="uaccess"`).
const ACL_XATTR: &str = "system.posix_acl_access";

/// The node's inode state: owner, mode and ACL. Linux keeps it on the
/// devtmpfs inode, which lives exactly as long as the device; so does
/// this, on the [`HidrawNode`]. A replugged device gets a fresh node even
/// on a reused minor.
#[derive(Clone)]
struct NodeMeta {
    uid: u32,
    gid: u32,
    perms: u16,
    access_acl: Option<Vec<u8>>,
}

impl NodeMeta {
    /// `hidraw_class` has no `devnode` callback, so devtmpfs creates the
    /// node `root:root 0600` (`drivers/base/devtmpfs.c`).
    const DEFAULT: Self = Self {
        uid: 0,
        gid: 0,
        perms: 0o600,
        access_acl: None,
    };
}

/// One open of a hidraw node (`struct hidraw_list`).
struct HidrawList {
    reports: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    revoked: AtomicBool,
    /// Level: `POLLOUT | POLLWRNORM` always ("hidraw is always
    /// writable"), `POLLIN | POLLRDNORM` while a report is queued,
    /// `POLLERR | POLLHUP` once the device is gone or the fd revoked
    /// (`hidraw_poll`). Updated under `reports`, so level and queue never
    /// disagree.
    readiness: Readiness,
}

impl HidrawList {
    fn new() -> Self {
        Self {
            reports: IrqSafeSpinLock::new(VecDeque::new()),
            revoked: AtomicBool::new(false),
            readiness: Readiness::new(POLL_OUT | POLL_WRNORM),
        }
    }

    fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// One slot of `hidraw_report_event`'s loop: queue a copy unless the
    /// ring is full (the report is dropped), and wake. `Err` is the
    /// `kmemdup` failure that ends Linux's loop.
    fn queue(&self, data: &[u8]) -> Result<(), ()> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len()).map_err(|_| ())?;
        copy.extend_from_slice(data);
        let mut q = self.reports.lock();
        if q.len() >= HIDRAW_BUFFER_SIZE - 1 {
            return Ok(());
        }
        q.push_back(copy);
        // Linux wakes the wait queue on every report, so an
        // edge-triggered epoll sees each one, not only the first.
        self.readiness
            .set_event(POLL_IN | POLL_RDNORM, 0, POLL_IN | POLL_RDNORM);
        Ok(())
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let mut q = self.reports.lock();
        let r = q.pop_front();
        if q.is_empty() {
            self.readiness.set(0, POLL_IN | POLL_RDNORM);
        }
        r
    }
}

struct NodeState {
    /// `hidraw->exist`.
    exist: bool,
    /// `hidraw->open`.
    open: u32,
    lists: Vec<Arc<HidrawList>>,
}

/// One hidraw minor (`struct hidraw`).
pub struct HidrawNode {
    minor: u32,
    hid: Arc<HidDevice>,
    state: IrqSafeSpinLock<NodeState>,
    /// The report-sink subscription on `hid`.
    sink: AtomicU64,
    meta: IrqSafeSpinLock<NodeMeta>,
}

impl core::fmt::Debug for HidrawNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidrawNode")
            .field("minor", &self.minor)
            .field("hid", &self.hid.sysfs_name())
            .finish_non_exhaustive()
    }
}

/// `hidraw_table[HIDRAW_MAX_DEVICES]`. A slot is taken at connect and
/// freed only once the device is gone *and* its last open has closed
/// (`drop_ref`), so a minor is never reused under an open fd.
static TABLE: IrqSafeSpinLock<[Option<Arc<HidrawNode>>; HIDRAW_MAX_DEVICES]> =
    IrqSafeSpinLock::new([const { None }; HIDRAW_MAX_DEVICES]);

impl HidrawNode {
    /// The minor (`/dev/hidraw<minor>`).
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// The HID device behind the node.
    pub fn hid(&self) -> &Arc<HidDevice> {
        &self.hid
    }

    fn exist(&self) -> bool {
        self.state.lock().exist
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(HIDRAW_MAJOR, self.minor)
    }

    /// `hidraw_report_event`.
    fn report_event(&self, data: &[u8]) {
        let st = self.state.lock();
        for list in &st.lists {
            if list.is_revoked() {
                continue;
            }
            if list.queue(data).is_err() {
                break;
            }
        }
    }

    /// `hidraw_open`: `-ENODEV` once the device is gone.
    fn open_list(self: &Arc<Self>) -> Result<Arc<dyn FileOps>, FsError> {
        let list = Arc::new(HidrawList::new());
        {
            let mut st = self.state.lock();
            if !st.exist {
                return Err(FsError::NoDevice);
            }
            st.open += 1;
            st.lists.push(list.clone());
        }
        Ok(Arc::new(HidrawFile {
            node: self.clone(),
            list: Some(list),
        }))
    }

    /// `hidraw_release` + `drop_ref(hidraw, 0)`.
    fn release(&self, list: &Arc<HidrawList>) {
        let free = {
            let mut st = self.state.lock();
            st.lists.retain(|l| !Arc::ptr_eq(l, list));
            st.open = st.open.saturating_sub(1);
            st.open == 0 && !st.exist
        };
        list.reports.lock().clear();
        if free {
            self.free_minor();
        }
    }

    /// `hidraw_disconnect` → `drop_ref(hidraw, 1)`.
    fn disconnect(&self) {
        let free = {
            let mut st = self.state.lock();
            st.exist = false;
            // `wake_up_interruptible(&hidraw->wait)`: readers see -EIO,
            // pollers EPOLLERR | EPOLLHUP.
            for list in &st.lists {
                list.readiness.set(POLL_ERR | POLL_HUP, 0);
            }
            st.open == 0
        };
        self.hid.unsubscribe(self.sink.load(Ordering::Acquire));
        if free {
            self.free_minor();
        }
    }

    fn free_minor(&self) {
        let mut table = TABLE.lock();
        let slot = &mut table[self.minor as usize];
        if slot
            .as_ref()
            .is_some_and(|n| core::ptr::eq(Arc::as_ptr(n), self))
        {
            *slot = None;
        }
    }

    // ── report transfers ───────────────────────────────────────────────

    /// The size checks of `hidraw_send_report` / `hidraw_get_report`
    /// (`drivers/hid/hidraw.c:122-141` / `:201-225`), in their order.
    fn check_transfer(&self, count: usize) -> Result<(), FsError> {
        if !self.exist() {
            return Err(FsError::NoDevice);
        }
        // `!dev->ll_driver->raw_request` (get_report only): every
        // `HidTransport` implements it.
        if count > HID_MAX_BUFFER_SIZE {
            return Err(FsError::InvalidData);
        }
        if count < 2 {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    /// `hidraw_send_report` after `memdup_user`: an output report goes
    /// out on the interrupt path first, falling back to SET_REPORT only
    /// when the transport has none (`-ENOSYS`); everything else is
    /// SET_REPORT of `kind` for report `buf[0]`.
    async fn send(&self, mut buf: Vec<u8>, kind: ReportType) -> Result<usize, FsError> {
        let transport = self.hid.transport().clone();
        if kind == ReportType::Output {
            match transport.output_report(&buf).await {
                Err(HidIoError::Unsupported) => {}
                other => return other.map(|n| n.min(buf.len())).map_err(hid_err),
            }
        }
        let id = buf[0];
        let len = buf.len();
        transport
            .raw_request(id, &mut buf, kind, true)
            .await
            .map(|n| n.min(len))
            .map_err(hid_err)
    }
}

// ── The file ───────────────────────────────────────────────────────────

/// `/dev/hidrawN`. The devfs prototype has no list; every open gets its
/// own.
pub struct HidrawFile {
    node: Arc<HidrawNode>,
    list: Option<Arc<HidrawList>>,
}

impl core::fmt::Debug for HidrawFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidrawFile")
            .field("node", &self.node)
            .field("open", &self.list.is_some())
            .finish()
    }
}

impl Drop for HidrawFile {
    fn drop(&mut self) {
        if let Some(list) = self.list.take() {
            self.node.release(&list);
        }
    }
}

impl HidrawFile {
    fn list(&self) -> Result<&Arc<HidrawList>, FsError> {
        // Only an O_PATH descriptor has no list, and the syscall layer
        // refuses I/O on those first.
        self.list.as_ref().ok_or(FsError::BadFd)
    }

    /// `hidraw_get_report` from the size checks on.
    async fn get_report(
        &self,
        ctx: &dyn IoctlContext,
        arg: u64,
        count: usize,
        kind: ReportType,
    ) -> Result<u64, FsError> {
        self.node.check_transfer(count)?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(count)
            .map_err(|_| FsError::OutOfMemory)?;
        buf.resize(count, 0);
        // "Read the first byte from the user. This is the report number,
        // which is passed to hid_hw_raw_request()."
        let mut report_number = [0u8; 1];
        ctx.read(arg, &mut report_number)
            .map_err(|_| FsError::BadAddress)?;
        buf[0] = report_number[0];
        let transport = self.node.hid.transport().clone();
        let ret = transport
            .raw_request(report_number[0], &mut buf, kind, false)
            .await
            .map_err(hid_err)?;
        let len = ret.min(count);
        if len != 0 {
            ctx.write(arg, &buf[..len])
                .map_err(|_| FsError::BadAddress)?;
        }
        Ok(len as u64)
    }

    /// `hidraw_send_report` from an ioctl: size checks, then
    /// `memdup_user`, then the transfer.
    async fn send_report(
        &self,
        ctx: &dyn IoctlContext,
        arg: u64,
        count: usize,
        kind: ReportType,
    ) -> Result<u64, FsError> {
        self.node.check_transfer(count)?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(count)
            .map_err(|_| FsError::OutOfMemory)?;
        buf.resize(count, 0);
        ctx.read(arg, &mut buf).map_err(|_| FsError::BadAddress)?;
        self.node.send(buf, kind).await.map(|n| n as u64)
    }

    /// `hidraw_fixed_size_ioctl`; `None` is its `-EAGAIN` "not one of
    /// mine" marker.
    fn fixed_size_ioctl(
        &self,
        list: &HidrawList,
        cmd: u32,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        let info = self.node.hid.info();
        let rdesc = &info.report_descriptor;
        let fault = |_| FsError::BadAddress;
        Some(match cmd {
            HIDIOCGRDESCSIZE => ctx
                .write(arg, &(rdesc.len() as i32).to_ne_bytes())
                .map(|()| 0)
                .map_err(fault),
            HIDIOCGRDESC => (|| {
                let mut len = [0u8; 4];
                ctx.read(arg, &mut len).map_err(fault)?;
                let len = u32::from_ne_bytes(len) as usize;
                if len > HID_MAX_DESCRIPTOR_SIZE - 1 {
                    return Err(FsError::InvalidData);
                }
                let n = rdesc.len().min(len);
                if n != 0 {
                    // `arg + offsetof(struct hidraw_report_descriptor, value[0])`
                    ctx.write(arg + 4, &rdesc[..n]).map_err(fault)?;
                }
                Ok(0)
            })(),
            HIDIOCGRAWINFO => {
                // struct hidraw_devinfo { __u32 bustype; __s16 vendor;
                // __s16 product; } — vendor/product truncate to 16 bits.
                let mut dinfo = [0u8; 8];
                dinfo[0..4].copy_from_slice(&u32::from(info.bus).to_ne_bytes());
                dinfo[4..6].copy_from_slice(&(info.vendor as u16 as i16).to_ne_bytes());
                dinfo[6..8].copy_from_slice(&(info.product as u16 as i16).to_ne_bytes());
                ctx.write(arg, &dinfo).map(|()| 0).map_err(fault)
            }
            HIDIOCREVOKE => {
                if arg != 0 {
                    Err(FsError::InvalidData)
                } else {
                    // `hidraw_revoke`.
                    list.revoked.store(true, Ordering::Release);
                    list.readiness.set(POLL_ERR | POLL_HUP, 0);
                    Ok(0)
                }
            }
            _ => return None,
        })
    }

    /// `hidraw_ro_variable_size_ioctl`.
    fn ro_variable_size_ioctl(
        &self,
        cmd: u32,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, FsError> {
        let info = self.node.hid.info();
        let field = match cmd & !IOCSIZE_MASK {
            c if c == hidiocgrawname(0) => hid_field(&info.name, NAME_CAP),
            c if c == hidiocgrawphys(0) => hid_field(&info.phys, PHYS_CAP),
            c if c == hidiocgrawuniq(0) => hid_field(&info.uniq, UNIQ_CAP),
            _ => return Err(FsError::InvalidData),
        };
        // `field_len = strlen(...) + 1; if (len > field_len) len = field_len;`
        let mut bytes = Vec::with_capacity(field.len() + 1);
        bytes.extend_from_slice(field.as_bytes());
        bytes.push(0);
        let len = ((cmd & IOCSIZE_MASK) >> 16) as usize;
        let len = len.min(bytes.len());
        if len != 0 {
            ctx.write(arg, &bytes[..len])
                .map_err(|_| FsError::BadAddress)?;
        }
        Ok(len as u64)
    }

    /// `hidraw_ioctl`, in its check order.
    async fn ioctl_inner(
        &self,
        cmd: u32,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, FsError> {
        let list = self.list()?;
        if !self.node.exist() || list.is_revoked() {
            return Err(FsError::NoDevice);
        }
        if (cmd >> 8) & 0xff != u32::from(b'H') {
            return Err(FsError::InvalidData);
        }
        let nr = cmd & 0xff;
        if nr > HIDIOCTL_LAST || nr == 0 {
            // -ENOTTY. LINUX-GAP: the syscall layer's generic relay for an
            // unknown request first copies an `_IOW` argument, so a bad
            // pointer there reads as EFAULT.
            return Err(FsError::Unsupported);
        }
        if let Some(r) = self.fixed_size_ioctl(list, cmd, arg, ctx) {
            return r;
        }
        let len = ((cmd & IOCSIZE_MASK) >> 16) as usize;
        match cmd >> 30 {
            d if d == IOC_READ | IOC_WRITE => {
                // `hidraw_rw_variable_size_ioctl`.
                let base = cmd & !IOCSIZE_MASK;
                if base == hidiocsfeature(0) {
                    self.send_report(ctx, arg, len, ReportType::Feature).await
                } else if base == hidiocgfeature(0) {
                    self.get_report(ctx, arg, len, ReportType::Feature).await
                } else if base == hidiocsinput(0) {
                    self.send_report(ctx, arg, len, ReportType::Input).await
                } else if base == hidiocginput(0) {
                    self.get_report(ctx, arg, len, ReportType::Input).await
                } else if base == hidiocsoutput(0) {
                    self.send_report(ctx, arg, len, ReportType::Output).await
                } else if base == hidiocgoutput(0) {
                    self.get_report(ctx, arg, len, ReportType::Output).await
                } else {
                    Err(FsError::InvalidData)
                }
            }
            IOC_READ => self.ro_variable_size_ioctl(cmd, arg, ctx),
            // "Any other IOC_DIR is wrong"
            _ => Err(FsError::InvalidData),
        }
    }
}

impl FileOps for HidrawFile {
    /// `hidraw_read`: one report per call, cut to `count`. An empty ring
    /// is `-EIO` once the device is gone, else would-block (`-EAGAIN` for
    /// O_NONBLOCK; a blocking read parks on the ring's readiness).
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let r = (|| {
            let list = self.list()?;
            if list.is_revoked() {
                return Err(FsError::NoDevice);
            }
            loop {
                let Some(report) = list.pop() else {
                    return Err(if self.node.exist() {
                        FsError::WouldBlock
                    } else {
                        FsError::Io(narf_block::BlockError::IOError)
                    });
                };
                let len = report.len().min(buf.len());
                // `while (ret == 0)`: a zero-length copy consumes the
                // report and takes the next.
                if len != 0 {
                    buf[..len].copy_from_slice(&report[..len]);
                    return Ok(len);
                }
            }
        })();
        Box::pin(async move { r })
    }

    /// `hidraw_write`: an output report (`hidraw_send_report(...,
    /// HID_OUTPUT_REPORT)`), report ID first.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let list = self.list()?;
            if list.is_revoked() {
                return Err(FsError::NoDevice);
            }
            self.node.check_transfer(buf.len())?;
            let mut copy = Vec::new();
            copy.try_reserve_exact(buf.len())
                .map_err(|_| FsError::OutOfMemory)?;
            copy.extend_from_slice(buf);
            self.node.send(copy, ReportType::Output).await
        })
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(self.ioctl_inner(cmd, arg, context))
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: self.node.meta.lock().perms,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        self.node.rdev()
    }

    fn ino(&self) -> u64 {
        crate::devfs::char_device_inode(self.node.rdev())
    }

    fn owners(&self) -> (u32, u32) {
        let meta = self.node.meta.lock();
        (meta.uid, meta.gid)
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        {
            let mut meta = self.node.meta.lock();
            meta.uid = uid;
            meta.gid = gid;
        }
        Box::pin(async { Ok(()) })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.node.meta.lock().perms = perms & 0o7777;
        Box::pin(async { Ok(()) })
    }

    /// A missing ACL is ENODATA (`NotFound`), not "no xattr support":
    /// libacl synthesises a base ACL from the mode on ENODATA but gives
    /// up on EOPNOTSUPP.
    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        let r = if name == ACL_XATTR {
            self.node
                .meta
                .lock()
                .access_acl
                .clone()
                .ok_or(FsError::NotFound)
        } else {
            Err(FsError::NotFound)
        };
        Box::pin(async move { r })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], _flags: u32) -> FsFuture<'a, ()> {
        let r = if name == ACL_XATTR {
            self.node.meta.lock().access_acl = Some(value.to_vec());
            Ok(())
        } else {
            // devtmpfs answers EOPNOTSUPP for anything but the ACL.
            Err(FsError::Unsupported)
        };
        Box::pin(async move { r })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        let mut out = Vec::new();
        if self.node.meta.lock().access_acl.is_some() {
            out.extend_from_slice(ACL_XATTR.as_bytes());
            out.push(0);
        }
        Box::pin(async move { Ok(out) })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let r = if name == ACL_XATTR && self.node.meta.lock().access_acl.take().is_some() {
            Ok(())
        } else {
            Err(FsError::NotFound)
        };
        Box::pin(async move { r })
    }

    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        self.node.open_list().ok()
    }

    fn open_instance_checked(&self, _write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        self.node.open_list().map(Some)
    }

    fn readiness(&self) -> Option<&Readiness> {
        self.list.as_ref().map(|l| &l.readiness)
    }

    fn poll_readiness(&self) -> u32 {
        self.list.as_ref().map(|l| l.readiness.mask()).unwrap_or(0)
    }

    /// The read path answers at once — a report or would-block — so
    /// `sys_read` polls it once and parks on the readiness cell.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    /// A report stream: no file position (`noop_llseek`).
    fn is_stream(&self) -> bool {
        true
    }
}

// ── devfs ──────────────────────────────────────────────────────────────

fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let minor: usize = name.strip_prefix("hidraw")?.parse().ok()?;
    // Exactly `hidraw%d`: no `hidraw01` alias of `hidraw1`.
    if format!("hidraw{minor}") != name {
        return None;
    }
    let node = TABLE.lock().get(minor)?.clone()?;
    // `device_destroy` removed the devtmpfs node at disconnect.
    if !node.exist() {
        return None;
    }
    Some(Arc::new(HidrawFile { node, list: None }))
}

fn enumerate() -> Vec<(String, FileType)> {
    let nodes: Vec<Arc<HidrawNode>> = TABLE.lock().iter().flatten().cloned().collect();
    nodes
        .into_iter()
        .filter(|n| n.exist())
        .map(|n| (format!("hidraw{}", n.minor), FileType::Special))
        .collect()
}

/// The live hidraw node of `hid`, if it has one.
pub fn node_of(hid: &Arc<HidDevice>) -> Option<Arc<HidrawNode>> {
    let node = TABLE
        .lock()
        .iter()
        .flatten()
        .find(|n| Arc::ptr_eq(&n.hid, hid))
        .cloned()?;
    node.exist().then_some(node)
}

// ── sysfs + uevents ────────────────────────────────────────────────────

/// One published HID device.
struct Published {
    hid: Arc<HidDevice>,
    node: Option<Arc<HidrawNode>>,
    /// The `BBBB:VVVV:PPPP.NNNN` kobject and the parent it hangs off.
    kobj: Arc<Kobject>,
    parent: Arc<Kobject>,
}

static PUBLISHED: IrqSafeSpinLock<Vec<Published>> = IrqSafeSpinLock::new(Vec::new());
/// Serialises publication and removal, uevent order included.
static PUBLICATION: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// `kobj`'s path below `/sys`, e.g. `devices/platform/narf-hid/...`.
fn sys_rel(kobj: &Kobject) -> String {
    let path = kobj.path();
    String::from(path.strip_prefix("/sys/").unwrap_or(path.as_str()))
}

/// The `../` prefix that climbs from directory `kobj` to `/sys`.
fn to_sys_root(kobj: &Kobject) -> String {
    "../".repeat(sys_rel(kobj).split('/').count())
}

fn bus_hid_devices() -> Arc<Kobject> {
    let root = get_root();
    let bus = get_or_create_child(&root, "bus");
    let hid = get_or_create_child(&bus, "hid");
    get_or_create_child(&hid, "devices")
}

/// `/sys/devices/platform/narf-hid`, the parent of a device whose
/// transport has no sysfs node of its own: a platform device, so udev's
/// `path_id` finds a subsystem on the parent walk (see the `narf-input`
/// parent in `sysfs::publish_input_device`).
fn platform_parent() -> Arc<Kobject> {
    let root = get_root();
    let devices = get_or_create_child(&root, "devices");
    let platform = get_or_create_child(&devices, "platform");
    let parent = get_or_create_child(&platform, "narf-hid");
    if !parent.has_attr("uevent") {
        let bus = get_or_create_child(&root, "bus");
        let bus_platform = get_or_create_child(&bus, "platform");
        let bus_platform_devices = get_or_create_child(&bus_platform, "devices");
        parent.add_symlink("subsystem", "../../../bus/platform");
        bus_platform_devices.add_symlink("narf-hid", "../../../../devices/platform/narf-hid");
        kobject_add_uevent_attr(&parent, String::from("MODALIAS=platform:narf-hid\n"));
    }
    parent
}

/// The kobject at `path` below `/sys` (created as plain directories where
/// missing — the transport owns the real ones), or the platform fallback
/// when `path` is empty.
fn resolve_parent(path: &str) -> Arc<Kobject> {
    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("sys/").unwrap_or(path);
    if path.is_empty() {
        return platform_parent();
    }
    let mut k = get_root();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        k = get_or_create_child(&k, part);
    }
    k
}

/// `hidraw_connect`: the lowest free minor, or `None` when all
/// `HIDRAW_MAX_DEVICES` are taken (Linux's `-EINVAL`: the device keeps
/// working, without a hidraw node).
fn connect(hid: &Arc<HidDevice>) -> Option<Arc<HidrawNode>> {
    let node = {
        let mut table = TABLE.lock();
        let minor = table.iter().position(|s| s.is_none())?;
        let node = Arc::new(HidrawNode {
            minor: minor as u32,
            hid: hid.clone(),
            state: IrqSafeSpinLock::new(NodeState {
                exist: true,
                open: 0,
                lists: Vec::new(),
            }),
            sink: AtomicU64::new(0),
            meta: IrqSafeSpinLock::new(NodeMeta::DEFAULT),
        });
        table[minor] = Some(node.clone());
        node
    };
    let weak = Arc::downgrade(&node);
    let handle = hid.subscribe(Arc::new(move |data: &[u8]| {
        if let Some(node) = weak.upgrade() {
            node.report_event(data);
        }
    }));
    node.sink.store(handle, Ordering::Release);
    Some(node)
}

/// The sysfs objects one publication built.
struct Built {
    parent: Arc<Kobject>,
    kobj: Arc<Kobject>,
    raw: Option<Arc<Kobject>>,
}

/// Build the sysfs subtree of `hid` (and of `node`, its hidraw minor).
fn build_sysfs(hid: &Arc<HidDevice>, node: Option<&Arc<HidrawNode>>) -> Built {
    let info = hid.info();
    let name = hid.sysfs_name();
    let group =
        narf_input::hid_scan::scan_group(&info.report_descriptor, info.vendor, info.product);
    let modalias = format!(
        "hid:b{:04X}g{:04X}v{:08X}p{:08X}",
        info.bus, group, info.vendor, info.product
    );
    let parent = resolve_parent(&info.sysfs_parent);
    let kobj = get_or_create_child(&parent, &name);
    // `hid_uevent` (`drivers/hid/hid-core.c:2870`).
    kobject_add_uevent_attr(
        &kobj,
        format!(
            "HID_ID={:04X}:{:08X}:{:08X}\nHID_NAME={}\nHID_PHYS={}\nHID_UNIQ={}\nMODALIAS={}\n",
            info.bus,
            info.vendor,
            info.product,
            hid_field(&info.name, NAME_CAP),
            hid_field(&info.phys, PHYS_CAP),
            hid_field(&info.uniq, UNIQ_CAP),
            modalias
        ),
    );
    // `modalias_show` (`hid-core.c:2846`).
    {
        let modalias = format!("{modalias}\n");
        kobject_add_attr(&kobj, "modalias", move || modalias.clone());
    }
    // `country_show` (`hid-core.c:2224`), created by `hid_connect`.
    {
        let country = info.country;
        kobject_add_attr(&kobj, "country", move || format!("{country:02x}\n"));
    }
    // `report_descriptor_read` (`hid-core.c:2205`).
    {
        let rdesc: Arc<[u8]> = Arc::from(info.report_descriptor.as_slice());
        kobject_add_bin_attr(
            &kobj,
            "report_descriptor",
            Arc::new(move |off: usize, buf: &mut [u8]| {
                if off >= rdesc.len() {
                    return 0;
                }
                let n = buf.len().min(rdesc.len() - off);
                buf[..n].copy_from_slice(&rdesc[off..off + n]);
                n
            }),
        );
    }
    kobj.add_symlink("subsystem", format!("{}bus/hid", to_sys_root(&kobj)));
    bus_hid_devices().add_symlink(name.clone(), format!("../../../{}", sys_rel(&kobj)));

    let raw = node.map(|node| {
        let dev_name = format!("hidraw{}", node.minor);
        let glue = get_or_create_child(&kobj, "hidraw");
        let raw = Kobject::new_child(glue, dev_name.clone());
        {
            let dev = format!("{}:{}\n", HIDRAW_MAJOR, node.minor);
            kobject_add_attr(&raw, "dev", move || dev.clone());
        }
        kobject_add_uevent_attr(
            &raw,
            format!(
                "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
                HIDRAW_MAJOR, node.minor, dev_name
            ),
        );
        raw.add_symlink("subsystem", format!("{}class/hidraw", to_sys_root(&raw)));
        raw.add_symlink("device", format!("../../../{name}"));
        let target = format!("../../{}", sys_rel(&raw));
        class_register("hidraw").add_symlink(dev_name, target.clone());
        let root = get_root();
        let dev = get_or_create_child(&root, "dev");
        let chars = get_or_create_child(&dev, "char");
        let _block = get_or_create_child(&dev, "block");
        chars.add_symlink(format!("{}:{}", HIDRAW_MAJOR, node.minor), target);
        raw
    });
    Built { parent, kobj, raw }
}

/// `device_add(&hdev->dev)`, then the driver's `hid_connect` →
/// `device_create(&hidraw_class, ...)`: the hid device's ADD first.
fn emit_added(built: &Built) {
    kobject_emit_uevent(&built.kobj, UeventAction::Add);
    if let Some(raw) = &built.raw {
        kobject_emit_uevent(raw, UeventAction::Add);
    }
}

/// Remove a published device's subtree and every link to it, emitting
/// the removal uevents in Linux's order: `hidraw_disconnect`'s
/// `device_destroy` before `hid_destroy_device`'s `device_del`. They are
/// emitted even when the transport already took the parent down: a
/// detached kobject keeps its path.
fn remove_sysfs(entry: &Published) {
    let kobj = &entry.kobj;
    if let Some(node) = &entry.node {
        let dev_name = format!("hidraw{}", node.minor);
        if let Some(glue) = kobj.get_child("hidraw") {
            if let Some(raw) = glue.get_child(&dev_name) {
                kobject_emit_uevent(&raw, UeventAction::Remove);
            }
            glue.remove_child(&dev_name);
        }
        kobj.remove_child("hidraw");
        let root = get_root();
        if let Some(class) = root.get_child("class").and_then(|c| c.get_child("hidraw")) {
            class.remove_symlink(&dev_name);
        }
        if let Some(chars) = root.get_child("dev").and_then(|d| d.get_child("char")) {
            chars.remove_symlink(&format!("{}:{}", HIDRAW_MAJOR, node.minor));
        }
    }
    kobject_emit_uevent(kobj, UeventAction::Remove);
    let name = entry.hid.sysfs_name();
    bus_hid_devices().remove_symlink(&name);
    entry.parent.remove_child(&name);
}

/// `hid_add_device` + `hidraw_connect`, as the publisher sees them.
fn publish(hid: &Arc<HidDevice>) {
    let _publication = PUBLICATION.lock();
    // A device the registry dropped without a `Removed` (its test-only
    // reset) would otherwise hold its minor forever.
    let dead: Vec<Published> = {
        let mut published = PUBLISHED.lock();
        let (dead, live) = core::mem::take(&mut *published)
            .into_iter()
            .partition(|p| !p.hid.is_alive());
        *published = live;
        dead
    };
    for entry in &dead {
        retire(entry);
    }
    if !hid.is_alive() {
        return;
    }
    // The hook replays every live device when it is (re)installed.
    if PUBLISHED.lock().iter().any(|p| Arc::ptr_eq(&p.hid, hid)) {
        return;
    }
    let node = connect(hid);
    let built = build_sysfs(hid, node.as_ref());
    PUBLISHED.lock().push(Published {
        hid: hid.clone(),
        node,
        kobj: built.kobj.clone(),
        parent: built.parent.clone(),
    });
    emit_added(&built);
}

/// `hidraw_disconnect` + `hid_destroy_device`.
fn unpublish(hid: &Arc<HidDevice>) {
    let _publication = PUBLICATION.lock();
    let entry = {
        let mut published = PUBLISHED.lock();
        let Some(i) = published.iter().position(|p| Arc::ptr_eq(&p.hid, hid)) else {
            return;
        };
        published.swap_remove(i)
    };
    retire(&entry);
}

fn retire(entry: &Published) {
    if let Some(node) = &entry.node {
        node.disconnect();
    }
    remove_sysfs(entry);
}

fn hid_changed(hid: &Arc<HidDevice>, change: Change) {
    match change {
        Change::Added => publish(hid),
        Change::Removed => unpublish(hid),
    }
}

/// Install the hidraw publisher: the `hidraw` class, `/sys/bus/hid`, the
/// devfs provider and the [`hid_device`] change hook, which replays the
/// devices registered before it. Idempotent; a builtin sysfs provider.
pub fn populate_hidraw_class() {
    class_register("hidraw");
    let _ = bus_hid_devices();
    crate::devfs::register_provider(crate::devfs::DeviceProvider {
        name: "hidraw",
        lookup,
        lookup_dir: |_| None,
        enumerate,
    });
    hid_device::set_change_hook(hid_changed);
}

/// Forget every published device and minor, without uevents. Test-only:
/// fixtures that rebuild sysfs or the HID registry start clean.
#[doc(hidden)]
pub fn __reset_for_test() {
    let _publication = PUBLICATION.lock();
    let entries: Vec<Published> = core::mem::take(&mut *PUBLISHED.lock());
    for entry in &entries {
        if let Some(node) = &entry.node {
            node.disconnect();
        }
    }
    let mut table = TABLE.lock();
    for slot in table.iter_mut() {
        *slot = None;
    }
}
