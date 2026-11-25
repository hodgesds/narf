//! usbfs: `/dev/bus/usb/BBB/DDD`, a port of Linux `drivers/usb/core/devio.c`.
//!
//! Every addressed device and every root hub has a character node (major
//! 189, minor `(bus - 1) * 128 + dev - 1`). `read` returns the device
//! descriptor followed by every configuration descriptor; the `USBDEVFS_*`
//! ioctls claim interfaces and move control, bulk and interrupt data. This
//! is what libusb, and so pcscd, lsusb, fwupd and WebUSB, drive.
//!
//! Interfaces are claimed in the device registry ([`crate::usbdev`]) as
//! [`Owner::File`], so a kernel class driver and an open file can never
//! hold the same interface, and `GETDRIVER` reports `usbfs` for a claimed
//! one exactly as Linux does.
//!
//! Gaps against Linux (each `// LINUX-GAP` below):
//! - isochronous URBs are refused with `-EINVAL` after Linux's checks;
//! - `USBDEVFS_RESET` fails with `-EIO` on a non-root device;
//! - a control stage still times out after the controller's fixed 250 ms
//!   whatever the caller's timeout (`xhci::event_wait`);
//! - DISCSIGNAL is recorded and URB `signr` accepted, but neither signal
//!   is sent;
//! - a new configuration's interfaces are not offered to kernel drivers;
//! - DISCONNECT unbinds only the raw-HID binding; a device-wide kernel
//!   binding (boot keyboard, storage) reports `-EBUSY`.
//!
//! `GET_CAPABILITIES` advertises exactly what is implemented.

mod desc;
mod engine;
#[cfg(feature = "kernel-test")]
mod tests;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_ERR,
    POLL_HUP, POLL_OUT,
};
use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

use crate::usbdev::{self, Owner, RootHub, UsbDev};
use crate::xhci::PortSpeed;
use desc::{AltDesc, EpDesc};
use engine::{Engine, Stop, Submit, Urb};
pub use engine::{Pipe, Xfer, XhciPipe};
use engine::{
    EINVAL, ENODEV, ENOENT, URB_BULK_CONTINUATION, URB_ISO_ASAP, URB_NO_FSBR, URB_NO_INTERRUPT,
    URB_SHORT_NOT_OK, URB_ZERO_PACKET,
};

// ── UAPI (`include/uapi/linux/usbdevice_fs.h`, x86_64 / arm64 layouts) ──

pub const USBDEVFS_CONTROL: u32 = 0xc018_5500;
pub const USBDEVFS_BULK: u32 = 0xc018_5502;
pub const USBDEVFS_RESETEP: u32 = 0x8004_5503;
pub const USBDEVFS_SETINTERFACE: u32 = 0x8008_5504;
pub const USBDEVFS_SETCONFIGURATION: u32 = 0x8004_5505;
pub const USBDEVFS_GETDRIVER: u32 = 0x4104_5508;
pub const USBDEVFS_SUBMITURB: u32 = 0x8038_550a;
pub const USBDEVFS_DISCARDURB: u32 = 0x0000_550b;
pub const USBDEVFS_REAPURB: u32 = 0x4008_550c;
pub const USBDEVFS_REAPURBNDELAY: u32 = 0x4008_550d;
pub const USBDEVFS_DISCSIGNAL: u32 = 0x8010_550e;
pub const USBDEVFS_CLAIMINTERFACE: u32 = 0x8004_550f;
pub const USBDEVFS_RELEASEINTERFACE: u32 = 0x8004_5510;
pub const USBDEVFS_CONNECTINFO: u32 = 0x4008_5511;
pub const USBDEVFS_IOCTL: u32 = 0xc010_5512;
pub const USBDEVFS_HUB_PORTINFO: u32 = 0x8080_5513;
pub const USBDEVFS_RESET: u32 = 0x0000_5514;
pub const USBDEVFS_CLEAR_HALT: u32 = 0x8004_5515;
pub const USBDEVFS_DISCONNECT: u32 = 0x0000_5516;
pub const USBDEVFS_CONNECT: u32 = 0x0000_5517;
pub const USBDEVFS_CLAIM_PORT: u32 = 0x8004_5518;
pub const USBDEVFS_RELEASE_PORT: u32 = 0x8004_5519;
pub const USBDEVFS_GET_CAPABILITIES: u32 = 0x8004_551a;
pub const USBDEVFS_DISCONNECT_CLAIM: u32 = 0x8108_551b;
pub const USBDEVFS_ALLOC_STREAMS: u32 = 0x8008_551c;
pub const USBDEVFS_FREE_STREAMS: u32 = 0x8008_551d;
pub const USBDEVFS_DROP_PRIVILEGES: u32 = 0x4004_551e;
pub const USBDEVFS_GET_SPEED: u32 = 0x0000_551f;
/// `USBDEVFS_CONNINFO_EX(len)`: this with `len << 16`.
pub const USBDEVFS_CONNINFO_EX_0: u32 = 0x8000_5520;
pub const USBDEVFS_FORBID_SUSPEND: u32 = 0x0000_5521;
pub const USBDEVFS_ALLOW_SUSPEND: u32 = 0x0000_5522;
pub const USBDEVFS_WAIT_FOR_RESUME: u32 = 0x0000_5523;

const IOCSIZE_MASK: u32 = 0x3fff_0000;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

pub const CAP_ZERO_PACKET: u32 = 0x01;
pub const CAP_BULK_CONTINUATION: u32 = 0x02;
pub const CAP_NO_PACKET_SIZE_LIM: u32 = 0x04;
pub const CAP_BULK_SCATTER_GATHER: u32 = 0x08;
pub const CAP_REAP_AFTER_DISCONNECT: u32 = 0x10;
pub const CAP_MMAP: u32 = 0x20;
pub const CAP_DROP_PRIVILEGES: u32 = 0x40;
pub const CAP_CONNINFO_EX: u32 = 0x80;
pub const CAP_SUSPEND: u32 = 0x100;

pub const URB_TYPE_ISO: u8 = 0;
pub const URB_TYPE_INTERRUPT: u8 = 1;
pub const URB_TYPE_CONTROL: u8 = 2;
pub const URB_TYPE_BULK: u8 = 3;

const DISCONNECT_CLAIM_IF_DRIVER: u32 = 0x01;
const DISCONNECT_CLAIM_EXCEPT_DRIVER: u32 = 0x02;

/// `sizeof(struct usbdevfs_urb)` before `iso_frame_desc`.
const URB_SIZE: usize = 56;
/// `USBFS_XFER_MAX`.
const USBFS_XFER_MAX: u32 = u32::MAX / 2 - 1_000_000;
/// `USB_MAXENDPOINTS`.
const USB_MAXENDPOINTS: u32 = 30;
/// Per-URB kernel bookkeeping charged with its buffer (`struct async` +
/// `struct urb`, rounded).
const URB_OVERHEAD: usize = 256;
/// `usbfs_memory_mb`'s default.
const USBFS_MEMORY_LIMIT: usize = 16 << 20;

/// `EPOLLWRNORM`.
const POLL_WRNORM: u32 = 0x0100;

const EPERM: i32 = 1;
const EINTR: i32 = 4;
const EIO: i32 = 5;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const EBUSY: i32 = 16;
const EISDIR: i32 = 21;
const ENOTTY: i32 = 25;
const ESRCH: i32 = 3;
const ENOSYS: i32 = 38;
const ENODATA: i32 = 61;
const EHOSTUNREACH: i32 = 113;

/// `enum usb_device_speed`.
fn speed_code(speed: PortSpeed) -> u32 {
    match speed {
        PortSpeed::Low => 1,
        PortSpeed::Full => 2,
        PortSpeed::High => 3,
        PortSpeed::Super => 5,
        PortSpeed::SuperPlus => 6,
    }
}

/// A positive errno as the filesystem error the syscall layer turns back
/// into it.
fn fs_error(errno: i32) -> FsError {
    match errno {
        EPERM => FsError::OperationNotPermitted,
        ENOENT => FsError::NotFound,
        ESRCH => FsError::NoSuchProcess,
        EINTR => FsError::Interrupted,
        EAGAIN => FsError::WouldBlock,
        ENOMEM => FsError::OutOfMemory,
        EACCES => FsError::PermissionDenied,
        EFAULT => FsError::BadAddress,
        EBUSY => FsError::Busy,
        // ESHUTDOWN: a transfer the disconnect flushed.
        ENODEV | 108 => FsError::NoDevice,
        EISDIR => FsError::IsADirectory,
        EINVAL => FsError::InvalidData,
        ENOTTY => FsError::NotATty,
        // A STALL: EPIPE without the SIGPIPE a pipe write raises.
        32 => FsError::Stalled,
        ENOSYS => FsError::NotImplemented,
        ENODATA => FsError::NoData,
        71 => FsError::Protocol,
        75 => FsError::Overflow,
        110 => FsError::TransferTimedOut,
        EHOSTUNREACH => FsError::HostUnreachable,
        121 => FsError::RemoteIo,
        _ => FsError::Io(narf_block::BlockError::IOError),
    }
}

// ── The usbfs memory budget (`usbfs_increase_memory_usage`) ─────────────

static MEMORY_USED: AtomicUsize = AtomicUsize::new(0);

fn charge(bytes: usize) -> Result<(), i32> {
    let used = MEMORY_USED.fetch_add(bytes, Ordering::AcqRel) + bytes;
    if used > USBFS_MEMORY_LIMIT {
        MEMORY_USED.fetch_sub(bytes, Ordering::AcqRel);
        return Err(ENOMEM);
    }
    Ok(())
}

fn uncharge(bytes: usize) {
    MEMORY_USED.fetch_sub(bytes, Ordering::AcqRel);
}

// ── What a node names ───────────────────────────────────────────────────

/// A device node's target: a registered device or a root hub.
#[derive(Clone, Debug)]
pub enum Target {
    Device(Arc<UsbDev>),
    RootHub(RootHub),
}

/// Identity of a node across lookups.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum NodeKey {
    Device {
        controller: u8,
        slot: u8,
        generation: u64,
    },
    RootHub {
        busnum: u8,
    },
}

impl Target {
    fn key(&self) -> NodeKey {
        match self {
            Target::Device(d) => NodeKey::Device {
                controller: d.controller,
                slot: d.slot,
                generation: d.generation,
            },
            Target::RootHub(h) => NodeKey::RootHub { busnum: h.busnum },
        }
    }

    pub fn busnum(&self) -> u8 {
        match self {
            Target::Device(d) => d.busnum,
            Target::RootHub(h) => h.busnum,
        }
    }

    pub fn devnum(&self) -> u8 {
        match self {
            Target::Device(d) => d.devnum,
            Target::RootHub(_) => 1,
        }
    }

    /// `dev->state != USB_STATE_NOTATTACHED`.
    fn attached(&self) -> bool {
        match self {
            Target::Device(d) => d.attached(),
            Target::RootHub(h) => usbdev::root_hubs().iter().any(|r| r == h),
        }
    }

    fn descriptor(&self) -> [u8; 18] {
        match self {
            Target::Device(d) => d.descriptor,
            Target::RootHub(h) => {
                let all = usbdev::root_hub_descriptors(h);
                let mut out = [0u8; 18];
                out.copy_from_slice(&all[..18]);
                out
            }
        }
    }

    /// Every configuration descriptor (`dev->rawdescriptors`).
    fn configs(&self) -> Vec<Vec<u8>> {
        match self {
            Target::Device(d) => d.configs.clone(),
            Target::RootHub(h) => alloc::vec![usbdev::root_hub_descriptors(h)[18..].to_vec()],
        }
    }

    fn config_value(&self) -> u8 {
        match self {
            Target::Device(d) => d.config_value(),
            Target::RootHub(_) => 1,
        }
    }

    /// `dev->actconfig`.
    fn active_config(&self) -> Option<Vec<u8>> {
        match self {
            Target::Device(d) => d.active_config().map(<[u8]>::to_vec),
            Target::RootHub(h) => Some(usbdev::root_hub_descriptors(h)[18..].to_vec()),
        }
    }

    fn alt_setting(&self, iface: u8) -> u8 {
        match self {
            Target::Device(d) => d.alt_setting(iface),
            Target::RootHub(_) => 0,
        }
    }

    /// Who holds `iface`: the root hub's interface is the hub driver's.
    fn owner(&self, iface: u8) -> Option<Owner> {
        match self {
            Target::Device(d) => d.owner(iface),
            Target::RootHub(_) => (iface == 0).then_some(Owner::Driver("hub")),
        }
    }

    fn claim(&self, iface: u8, owner: Owner) -> Result<(), Owner> {
        match self {
            Target::Device(d) => d.claim(iface, owner),
            Target::RootHub(_) => Err(Owner::Driver("hub")),
        }
    }

    fn release(&self, iface: u8, owner: &Owner) -> bool {
        match self {
            Target::Device(d) => d.release(iface, owner),
            Target::RootHub(_) => false,
        }
    }

    fn speed(&self) -> u32 {
        match self {
            Target::Device(d) => speed_code(d.speed),
            Target::RootHub(h) if h.usb3 => 5,
            Target::RootHub(_) => 3,
        }
    }

    /// `hdev->maxchild`: 0 for anything but a hub.
    fn maxchild(&self) -> u8 {
        match self {
            Target::RootHub(h) => h.ports,
            Target::Device(d) => crate::attach::hub_num_ports(d.controller, d.slot).unwrap_or(0),
        }
    }

    /// The devnum of the child on hub port `port`, 0 when none.
    fn child_devnum(&self, port: u8) -> u8 {
        let path = match self {
            Target::RootHub(_) => alloc::format!("{port}"),
            Target::Device(d) => alloc::format!("{}.{port}", d.devpath),
        };
        usbdev::all()
            .iter()
            .find(|c| c.busnum == self.busnum() && c.devpath == path)
            .map_or(0, |c| c.devnum)
    }

    /// The hub ports from the root hub down to this device (`portnum` of
    /// every ancestor), root first.
    fn port_chain(&self) -> Vec<u8> {
        match self {
            Target::RootHub(_) => Vec::new(),
            Target::Device(d) => d
                .devpath
                .split('.')
                .filter_map(|p| p.parse::<u8>().ok())
                .collect(),
        }
    }
}

// ── Node metadata (mode, owner, uaccess ACL) ────────────────────────────

#[derive(Debug)]
struct Meta {
    uid: u32,
    gid: u32,
    perms: u16,
    access_acl: Option<Vec<u8>>,
}

type SharedMeta = Arc<IrqSafeSpinLock<Meta>>;

/// Node metadata by identity: udev's `chmod`/`chown`/`setfacl` on
/// `/dev/bus/usb/BBB/DDD` must outlive the lookup that served it. A new
/// device in the same bus and device numbers starts over at devtmpfs's
/// `0600 root:root`, as its node is created anew on Linux.
static NODES: IrqSafeSpinLock<Vec<(NodeKey, SharedMeta)>> = IrqSafeSpinLock::new(Vec::new());

fn meta_for(target: &Target) -> SharedMeta {
    let key = target.key();
    let mut nodes = NODES.lock();
    if let Some((_, m)) = nodes.iter().find(|(k, _)| *k == key) {
        return m.clone();
    }
    // Drop a stale entry for the same bus/devnum.
    nodes.retain(|(k, _)| match (k, key) {
        (
            NodeKey::Device {
                controller, slot, ..
            },
            NodeKey::Device {
                controller: c,
                slot: s,
                ..
            },
        ) => !(*controller == c && *slot == s),
        _ => true,
    });
    let m = Arc::new(IrqSafeSpinLock::new(Meta {
        uid: 0,
        gid: 0,
        perms: 0o600,
        access_acl: None,
    }));
    nodes.push((key, m.clone()));
    m
}

const ACL_XATTR: &str = "system.posix_acl_access";

// ── The devfs tree ──────────────────────────────────────────────────────

const INO_BUS: u64 = 0xd005_0000_0000_0001;
const INO_USB: u64 = 0xd005_0000_0000_0002;
const INO_BUS_N: u64 = 0xd005_0001_0000_0000;

fn three_digits(name: &str) -> Option<u8> {
    if name.len() != 3 || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse::<u8>().ok().filter(|&n| n != 0)
}

fn bus_exists(busnum: u8) -> bool {
    usbdev::root_hubs().iter().any(|h| h.busnum == busnum)
}

/// The node `/dev/bus/usb/<busnum>/<devnum>` names, if any.
pub fn lookup_node(busnum: u8, devnum: u8) -> Option<Arc<dyn FileOps>> {
    let target = if devnum == 1 {
        Target::RootHub(*usbdev::root_hubs().iter().find(|h| h.busnum == busnum)?)
    } else {
        Target::Device(usbdev::find_by_number(busnum, devnum)?)
    };
    let meta = meta_for(&target);
    Some(Arc::new(UsbfsNode { target, meta }))
}

macro_rules! sync_dir_async {
    () => {
        fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
            Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
        }

        fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
            Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
        }

        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }

        fn enumerate_async<'a>(
            &'a self,
            cursor: usize,
            max: usize,
        ) -> FsFuture<'a, Vec<(String, FileType)>> {
            Box::pin(async move { Ok(self.enumerate(cursor, max)) })
        }
    };
}

/// `/dev/bus`.
struct BusDir;

impl DirOps for BusDir {
    fn ino(&self) -> u64 {
        INO_BUS
    }

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        (name == "usb").then(|| Arc::new(UsbDir) as Arc<dyn DirOps>)
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        alloc::vec![(String::from("usb"), FileType::Dir)]
            .into_iter()
            .skip(cursor)
            .take(max)
            .collect()
    }

    sync_dir_async!();
}

/// `/dev/bus/usb`.
struct UsbDir;

impl DirOps for UsbDir {
    fn ino(&self) -> u64 {
        INO_USB
    }

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let busnum = three_digits(name)?;
        bus_exists(busnum).then(|| Arc::new(BusNumDir(busnum)) as Arc<dyn DirOps>)
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut buses: Vec<u8> = usbdev::root_hubs().iter().map(|h| h.busnum).collect();
        buses.sort_unstable();
        buses
            .into_iter()
            .map(|b| (alloc::format!("{b:03}"), FileType::Dir))
            .skip(cursor)
            .take(max)
            .collect()
    }

    sync_dir_async!();
}

/// `/dev/bus/usb/BBB`.
struct BusNumDir(u8);

impl DirOps for BusNumDir {
    fn ino(&self) -> u64 {
        INO_BUS_N | u64::from(self.0)
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        lookup_node(self.0, three_digits(name)?)
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut devs: Vec<u8> = usbdev::all()
            .iter()
            .filter(|d| d.busnum == self.0)
            .map(|d| d.devnum)
            .collect();
        if bus_exists(self.0) {
            devs.push(1);
        }
        devs.sort_unstable();
        devs.into_iter()
            .map(|d| (alloc::format!("{d:03}"), FileType::Special))
            .skip(cursor)
            .take(max)
            .collect()
    }

    sync_dir_async!();
}

fn provider_lookup(_name: &str) -> Option<Arc<dyn FileOps>> {
    None
}

fn provider_lookup_dir(name: &str) -> Option<Arc<dyn DirOps>> {
    (name == "bus" && !usbdev::root_hubs().is_empty()).then(|| Arc::new(BusDir) as Arc<dyn DirOps>)
}

fn provider_enumerate() -> Vec<(String, FileType)> {
    if usbdev::root_hubs().is_empty() {
        Vec::new()
    } else {
        alloc::vec![(String::from("bus"), FileType::Dir)]
    }
}

/// Publish `/dev/bus/usb` in devtmpfs.
pub fn register_devfs() {
    narf_filesystem::devfs::register_provider(narf_filesystem::devfs::DeviceProvider {
        name: "usbfs",
        lookup: provider_lookup,
        lookup_dir: provider_lookup_dir,
        enumerate: provider_enumerate,
    });
}

// ── The node ────────────────────────────────────────────────────────────

/// `/dev/bus/usb/BBB/DDD` before open: stat, ownership and ACL.
#[derive(Debug)]
pub struct UsbfsNode {
    target: Target,
    meta: SharedMeta,
}

impl UsbfsNode {
    fn rdev_of(target: &Target) -> u64 {
        narf_filesystem::devfs::linux_makedev(
            crate::usb_sysfs::USB_DEVICE_MAJOR,
            crate::usb_sysfs::minor(target.busnum(), target.devnum()),
        )
    }
}

/// The stat/ownership half every usbfs FileOps shares.
macro_rules! node_metadata {
    () => {
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: self.meta().lock().perms,
                },
                mtime_cycles: 0,
            }
        }

        fn rdev(&self) -> u64 {
            UsbfsNode::rdev_of(self.target())
        }

        fn ino(&self) -> u64 {
            narf_filesystem::devfs::char_device_inode(self.rdev())
        }

        fn owners(&self) -> (u32, u32) {
            let m = self.meta().lock();
            (m.uid, m.gid)
        }

        fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
            {
                let mut m = self.meta().lock();
                m.uid = uid;
                m.gid = gid;
            }
            Box::pin(async { Ok(()) })
        }

        fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
            self.meta().lock().perms = perms & 0o7777;
            Box::pin(async { Ok(()) })
        }

        fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
            // A missing ACL is ENODATA (NotFound here) so libacl derives one
            // from the mode, as on devtmpfs.
            let r = if name == ACL_XATTR {
                self.meta()
                    .lock()
                    .access_acl
                    .clone()
                    .ok_or(FsError::NotFound)
            } else {
                Err(FsError::NotFound)
            };
            Box::pin(async move { r })
        }

        fn set_xattr<'a>(
            &'a self,
            name: &'a str,
            value: &'a [u8],
            _flags: u32,
        ) -> FsFuture<'a, ()> {
            let r = if name == ACL_XATTR {
                self.meta().lock().access_acl = Some(value.to_vec());
                Ok(())
            } else {
                Err(FsError::Unsupported)
            };
            Box::pin(async move { r })
        }

        fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
            let mut out = Vec::new();
            if self.meta().lock().access_acl.is_some() {
                out.extend_from_slice(ACL_XATTR.as_bytes());
                out.push(0);
            }
            Box::pin(async move { Ok(out) })
        }

        fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
            let r = if name == ACL_XATTR && self.meta().lock().access_acl.take().is_some() {
                Ok(())
            } else {
                Err(FsError::NotFound)
            };
            Box::pin(async move { r })
        }
    };
}

impl UsbfsNode {
    fn meta(&self) -> &SharedMeta {
        &self.meta
    }

    fn target(&self) -> &Target {
        &self.target
    }
}

impl FileOps for UsbfsNode {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::BadFd) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::BadFd) })
    }

    /// `usbdev_open`: `-ENODEV` once the device is gone.
    fn open_instance_checked(&self, write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        UsbfsFile::open(self.target.clone(), self.meta.clone(), write, true)
            .map(|f| Some(f as Arc<dyn FileOps>))
    }

    node_metadata!();
}

// ── The open file ───────────────────────────────────────────────────────

/// Linux `struct usb_dev_state`.
struct FileState {
    engine: Engine,
    /// `ifclaimed`: one bit per interface number (an `unsigned long`).
    ifclaimed: u64,
    interface_allowed_mask: u32,
    privileges_dropped: bool,
    /// DISCSIGNAL's signal and context, and the opener's pid.
    discsignr: u32,
    disccontext: u64,
    disc_pid: u32,
    suspend_allowed: bool,
    not_yet_resumed: bool,
    /// `list_empty(&ps->list)`: `usbdev_remove` ran.
    removed: bool,
    pump_running: bool,
    /// Halted endpoints a recovery is running for.
    recovering: Vec<u8>,
    next_sync: u64,
}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shared")
            .field("target", &self.target)
            .field("id", &self.id)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

/// One open of a usbfs node.
pub struct Shared {
    target: Target,
    meta: SharedMeta,
    pipe: Option<Arc<dyn Pipe>>,
    id: u64,
    writable: bool,
    /// Spawn a completion pump while URBs are in flight (off in smokes,
    /// which drive the engine from the ioctls themselves).
    autopump: bool,
    state: IrqSafeSpinLock<FileState>,
    readiness: Readiness,
}

/// The file description: dropping it is `usbdev_release`.
#[derive(Debug)]
pub struct UsbfsFile(Arc<Shared>);

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
static OPEN: IrqSafeSpinLock<Vec<Weak<Shared>>> = IrqSafeSpinLock::new(Vec::new());

/// Port claims (`hub->ports[i]->port_owner`): hub, port, owning file.
static PORT_OWNERS: IrqSafeSpinLock<Vec<(NodeKey, u8, u64)>> = IrqSafeSpinLock::new(Vec::new());

fn open_files() -> Vec<Arc<Shared>> {
    let mut open = OPEN.lock();
    open.retain(|w| w.strong_count() > 0);
    open.iter().filter_map(Weak::upgrade).collect()
}

impl UsbfsFile {
    /// Open `target`. `pipe` is built from the controller for a device.
    fn open(
        target: Target,
        meta: SharedMeta,
        write: bool,
        autopump: bool,
    ) -> Result<Arc<Self>, FsError> {
        if !target.attached() {
            return Err(FsError::NoDevice);
        }
        let pipe: Option<Arc<dyn Pipe>> = match &target {
            Target::RootHub(_) => None,
            Target::Device(d) => {
                let c = crate::xhci::controller_by_id(d.controller).ok_or(FsError::NoDevice)?;
                let dev = crate::device::USBDevice::new(c, d.slot, d.root_port, d.speed);
                if dev.generation() != d.generation {
                    return Err(FsError::NoDevice);
                }
                Some(Arc::new(XhciPipe::new(dev)))
            }
        };
        Ok(Self::with_pipe(target, meta, pipe, write, autopump))
    }

    fn with_pipe(
        target: Target,
        meta: SharedMeta,
        pipe: Option<Arc<dyn Pipe>>,
        write: bool,
        autopump: bool,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            target,
            meta,
            pipe,
            id: NEXT_FILE.fetch_add(1, Ordering::Relaxed),
            writable: write,
            autopump,
            state: IrqSafeSpinLock::new(FileState {
                engine: Engine::default(),
                ifclaimed: 0,
                interface_allowed_mask: 0xffff_ffff,
                privileges_dropped: false,
                discsignr: 0,
                disccontext: 0,
                disc_pid: 0,
                suspend_allowed: false,
                not_yet_resumed: false,
                removed: false,
                pump_running: false,
                recovering: Vec::new(),
                next_sync: 1,
            }),
            readiness: Readiness::new(0),
        });
        OPEN.lock().push(Arc::downgrade(&shared));
        Arc::new(UsbfsFile(shared))
    }

    /// The per-open state (smokes inspect it).
    pub fn shared(&self) -> &Arc<Shared> {
        &self.0
    }

    fn meta(&self) -> &SharedMeta {
        &self.0.meta
    }

    fn target(&self) -> &Target {
        &self.0.target
    }
}

impl Drop for UsbfsFile {
    /// `usbdev_release`: release port claims and interfaces, kill every
    /// pending URB and drop what was never reaped.
    fn drop(&mut self) {
        let sh = self.0.clone();
        PORT_OWNERS.lock().retain(|(_, _, f)| *f != sh.id);
        let claimed = sh.state.lock().ifclaimed;
        for ifnum in 0..64u8 {
            if claimed & (1u64 << ifnum) != 0 {
                sh.target.release(ifnum, &Owner::File(sh.id));
            }
        }
        sh.state.lock().ifclaimed = 0;
        let stops = sh.kill_matching(|_| true);
        if stops.is_empty() {
            sh.free_all();
        } else if let Some(pipe) = sh.pipe.clone() {
            narf_scheduler::spawn(async move {
                for stop in stops {
                    let r = pipe.stop(stop.receipt).await;
                    sh.state.lock().engine.end_kill(&*pipe, stop, r);
                }
                sh.free_all();
            });
        }
    }
}

impl Shared {
    /// `connected(ps)`.
    fn connected(&self) -> bool {
        !self.state.lock().removed && self.target.attached()
    }

    fn refresh_readiness(&self) {
        let (completed, removed) = {
            let st = self.state.lock();
            (st.engine.has_completed(), st.removed)
        };
        let mut mask = 0;
        if self.writable && completed {
            mask |= POLL_OUT | POLL_WRNORM;
        }
        if removed || !self.target.attached() {
            mask |= POLL_HUP;
        }
        if removed {
            mask |= POLL_ERR;
        }
        self.readiness.set(mask, !mask);
    }

    /// Uncharge and drop everything the engine still holds.
    fn free_all(&self) {
        let mut st = self.state.lock();
        uncharge(st.engine.charged());
        st.engine = Engine::default();
    }

    /// Drive the engine once.
    fn pump(&self) {
        let Some(pipe) = self.pipe.as_deref() else {
            return;
        };
        let completed = self.state.lock().engine.pump(pipe);
        if completed {
            self.refresh_readiness();
        }
    }

    /// Recover the host side of endpoints a transfer error halted.
    async fn recover_halted(&self) {
        let Some(pipe) = self.pipe.as_deref() else {
            return;
        };
        let eps: Vec<u8> = {
            let mut st = self.state.lock();
            let mut eps = Vec::new();
            for ep in st.engine.take_halted() {
                if !st.recovering.contains(&ep) {
                    st.recovering.push(ep);
                    eps.push(ep);
                }
            }
            eps
        };
        for ep in eps {
            if pipe.halted(ep) {
                let _ = pipe.recover(ep).await;
            }
            self.state.lock().recovering.retain(|&e| e != ep);
        }
    }

    /// Keep a pump running while URBs are in flight.
    fn ensure_pump(self: &Arc<Self>) {
        if !self.autopump || self.pipe.is_none() {
            return;
        }
        {
            let mut st = self.state.lock();
            if st.pump_running || !st.engine.busy() {
                return;
            }
            st.pump_running = true;
        }
        let weak = Arc::downgrade(self);
        narf_scheduler::spawn(async move {
            loop {
                let Some(sh) = weak.upgrade() else {
                    return;
                };
                sh.pump();
                sh.recover_halted().await;
                {
                    let mut st = sh.state.lock();
                    if !st.engine.busy() {
                        st.pump_running = false;
                        return;
                    }
                }
                drop(sh);
                narf_time::sleep_ms(1).await;
            }
        });
    }

    /// Mark matching pending URBs killed; the posted ones come back for
    /// the caller to stop.
    fn kill_matching(&self, pred: impl Fn(&Urb) -> bool) -> Vec<Stop> {
        let mut st = self.state.lock();
        let mut stops = Vec::new();
        for i in st.engine.matching(&pred) {
            if let Some(stop) = st.engine.begin_kill(i) {
                stops.push(stop);
            }
        }
        stops
    }

    /// Kill matching URBs and wait for the stops (`destroy_async`).
    async fn destroy(&self, pred: impl Fn(&Urb) -> bool) {
        let stops = self.kill_matching(pred);
        if let Some(pipe) = self.pipe.as_deref() {
            for stop in stops {
                let r = pipe.stop(stop.receipt).await;
                self.state.lock().engine.end_kill(pipe, stop, r);
            }
        }
        self.refresh_readiness();
    }

    /// The device went away (`usbdev_remove`).
    fn removed(&self) {
        {
            let mut st = self.state.lock();
            if let Some(pipe) = self.pipe.as_deref() {
                st.engine.flush(pipe);
            }
            st.removed = true;
            st.not_yet_resumed = false;
        }
        // LINUX-GAP: kill_pid_usb_asyncio(discsignr, EPIPE, disccontext)
        // is not sent; DISCSIGNAL's settings are only recorded.
        self.refresh_readiness();
    }

    // ── Interface claims (`claimintf` / `releaseintf` / `checkintf`) ──

    async fn claimintf(&self, ifnum: u32) -> Result<(), i32> {
        if ifnum >= 64 {
            return Err(EINVAL);
        }
        let iface = ifnum as u8;
        {
            let st = self.state.lock();
            if st.ifclaimed & (1u64 << ifnum) != 0 {
                return Ok(());
            }
            if st.privileges_dropped
                && (ifnum >= 32 || st.interface_allowed_mask & (1u32 << ifnum) == 0)
            {
                return Err(EACCES);
            }
        }
        let config = self.target.active_config().ok_or(ENOENT)?;
        if !desc::has_interface(&config, iface) {
            return Err(ENOENT);
        }
        let owner = Owner::File(self.id);
        self.target.claim(iface, owner.clone()).map_err(|_| EBUSY)?;
        // Linux allocates every endpoint of the configuration at
        // SET_CONFIGURATION; NARF programs an interface's endpoints when
        // their first owner takes it.
        if let Err(e) = self.enable_interface(&config, iface).await {
            self.target.release(iface, &owner);
            return Err(e);
        }
        self.state.lock().ifclaimed |= 1u64 << ifnum;
        Ok(())
    }

    /// Program the endpoints of `iface`'s current setting that the
    /// controller does not have yet.
    async fn enable_interface(&self, config: &[u8], iface: u8) -> Result<(), i32> {
        let Some(pipe) = self.pipe.as_deref() else {
            return Ok(());
        };
        let Some(alt) = desc::find_alt(config, iface, self.target.alt_setting(iface)) else {
            return Ok(());
        };
        let eps: Vec<_> = alt
            .endpoints
            .iter()
            .filter(|e| !pipe.configured(e.addr))
            .filter_map(EpDesc::config)
            .collect();
        pipe.configure(&eps).await.map_err(engine::errno)
    }

    fn releaseintf(&self, ifnum: u32) -> Result<(), i32> {
        if ifnum >= 64 {
            return Err(EINVAL);
        }
        let config = self.target.active_config();
        if !config.is_some_and(|c| desc::has_interface(&c, ifnum as u8)) {
            return Err(ENOENT);
        }
        let mut st = self.state.lock();
        if st.ifclaimed & (1u64 << ifnum) == 0 {
            return Err(EINVAL);
        }
        st.ifclaimed &= !(1u64 << ifnum);
        drop(st);
        self.target.release(ifnum as u8, &Owner::File(self.id));
        Ok(())
    }

    async fn checkintf(&self, ifnum: u32) -> Result<(), i32> {
        if self.target.config_value() == 0 {
            return Err(EHOSTUNREACH);
        }
        if ifnum >= 64 {
            return Err(EINVAL);
        }
        if self.state.lock().ifclaimed & (1u64 << ifnum) != 0 {
            return Ok(());
        }
        // Linux warns "did not claim interface before use" and claims it.
        self.claimintf(ifnum).await
    }

    /// `findintfep`: the interface owning endpoint `ep`.
    fn findintfep(&self, ep: u32) -> Result<u32, i32> {
        if ep & !(0x80 | 0x0f) != 0 {
            return Err(EINVAL);
        }
        let config = self.target.active_config().ok_or(ESRCH)?;
        desc::interface_for_endpoint(&config, ep as u8)
            .map(u32::from)
            .ok_or(ENOENT)
    }

    /// `ep_to_host_endpoint`: the endpoint in its interface's current
    /// setting. EP0 is always there.
    fn host_endpoint(&self, ep: u8) -> Option<EpDesc> {
        if ep & 0x0f == 0 {
            return Some(EpDesc {
                addr: ep,
                attributes: desc::XFER_CONTROL,
                max_packet: u16::from(self.target.descriptor()[7]),
                interval: 0,
            });
        }
        let config = self.target.active_config()?;
        desc::alt_settings(&config)
            .into_iter()
            .filter(|a| a.alt == self.target.alt_setting(a.number))
            .flat_map(|a| a.endpoints)
            .find(|e| e.addr == ep)
    }

    /// `check_ctrlrecip`.
    async fn check_ctrlrecip(&self, requesttype: u8, request: u8, index: u16) -> Result<(), i32> {
        if requesttype & 0x60 == 0x40 {
            return Ok(()); // USB_TYPE_VENDOR
        }
        if requesttype == 0xa1 && request == 0 {
            let printer = self
                .target
                .active_config()
                .and_then(|c| desc::find_alt(&c, (index >> 8) as u8, (index & 0xff) as u8));
            if printer.is_some_and(|a: AltDesc| a.class == desc::CLASS_PRINTER) {
                return Ok(());
            }
        }
        let index = u32::from(index & 0xff);
        match requesttype & 0x1f {
            0x02 => {
                if index & !0x80 == 0 {
                    return Ok(());
                }
                let ifnum = match self.findintfep(index) {
                    Ok(i) => Ok(i),
                    Err(_) => self.findintfep(index ^ 0x80),
                }?;
                self.checkintf(ifnum).await
            }
            0x01 => self.checkintf(index).await,
            _ => Ok(()),
        }
    }

    // ── Transfers ──

    /// One control transfer, on the device or emulated for a root hub.
    async fn control(&self, setup: [u8; 8], data: &mut [u8]) -> Result<usize, i32> {
        match (&self.pipe, &self.target) {
            (Some(pipe), _) => pipe.control(setup, data).await.map_err(engine::errno),
            (None, Target::RootHub(hub)) => root_hub_control(hub, setup, data),
            (None, Target::Device(_)) => Err(ENODEV),
        }
    }

    /// Submit a URB the caller waits for (CONTROL/BULK ioctls), then wait
    /// up to `timeout_ms` (0 = forever) as `usbfs_start_wait_urb`.
    /// Returns `(status, urb)`; a URB the deadline killed is `-ETIMEDOUT`.
    async fn run_sync(self: &Arc<Self>, mut s: Submit, timeout_ms: u32) -> Result<(i32, Urb), i32> {
        let sync = {
            let mut st = self.state.lock();
            let sync = st.next_sync;
            st.next_sync += 1;
            s.sync = sync;
            st.engine.submit(s)?;
            sync
        };
        self.ensure_pump();
        let deadline = (timeout_ms != 0)
            .then(|| narf_time::monotonic_ns() + u64::from(timeout_ms) * 1_000_000);
        loop {
            self.pump();
            self.recover_halted().await;
            if let Some(urb) = self.state.lock().engine.take_sync(sync) {
                return Ok((urb.status, urb));
            }
            if deadline.is_some_and(|d| narf_time::monotonic_ns() >= d) {
                let stop = {
                    let mut st = self.state.lock();
                    st.engine
                        .index_of_sync(sync)
                        .and_then(|i| st.engine.begin_kill(i))
                };
                if let (Some(stop), Some(pipe)) = (stop, self.pipe.as_deref()) {
                    let r = pipe.stop(stop.receipt).await;
                    self.state.lock().engine.end_kill(pipe, stop, r);
                }
                let urb = self.state.lock().engine.take_sync(sync).ok_or(EIO)?;
                // Completed before it was killed: its own result stands.
                let status = if urb.status == -ENOENT {
                    -110
                } else {
                    urb.status
                };
                return Ok((status, urb));
            }
            narf_time::sleep_ms(1).await;
        }
    }
}

/// Emulated standard requests of a root hub (`rh_call_control`'s device
/// part). Hub-class requests are not emulated and stall.
fn root_hub_control(hub: &RootHub, setup: [u8; 8], data: &mut [u8]) -> Result<usize, i32> {
    let [rt, req, v0, v1, _, _, _, _] = setup;
    let value = u16::from_le_bytes([v0, v1]);
    let reply: Vec<u8> = match (rt, req) {
        (0x80, 0x00) => alloc::vec![0x01, 0x00], // GET_STATUS: self-powered
        (0x81, 0x00) | (0x82, 0x00) => alloc::vec![0, 0],
        (0x80, 0x08) => alloc::vec![1], // GET_CONFIGURATION
        (0x81, 0x0a) => alloc::vec![0], // GET_INTERFACE
        (0x80, 0x06) => {
            let all = usbdev::root_hub_descriptors(hub);
            match (value >> 8, value & 0xff) {
                (1, _) => all[..18].to_vec(),
                (2, 0) => all[18..].to_vec(),
                (3, 0) => alloc::vec![4, 3, 0x09, 0x04],
                (3, index @ 1..=3) => {
                    let text = match index {
                        // The controller's PCI name, as the sysfs `serial`.
                        1 => crate::xhci::controller_by_id(hub.controller)
                            .map(|c| crate::hid::raw::pci_slot_name(&c))
                            .unwrap_or_default(),
                        2 => String::from("xHCI Host Controller"),
                        _ => alloc::format!("Linux {} xhci-hcd", crate::usb_sysfs::KERNEL_RELEASE),
                    };
                    let mut out = alloc::vec![0u8, 3];
                    for unit in text.encode_utf16() {
                        out.extend_from_slice(&unit.to_le_bytes());
                    }
                    out[0] = out.len().min(255) as u8;
                    out
                }
                _ => return Err(32),
            }
        }
        // SET_CONFIGURATION, SET/CLEAR_FEATURE on the device: accepted.
        (0x00, 0x09) | (0x00, 0x03) | (0x00, 0x01) => return Ok(0),
        _ => return Err(32),
    };
    let n = reply.len().min(data.len());
    data[..n].copy_from_slice(&reply[..n]);
    Ok(n)
}

/// `usbdev_remove` for every open file of `dev`.
pub fn device_removed(dev: &Arc<UsbDev>) {
    for sh in open_files() {
        if let Target::Device(d) = &sh.target {
            if Arc::ptr_eq(d, dev) {
                sh.removed();
            }
        }
    }
    NODES.lock().retain(|(k, _)| {
        !matches!(k, NodeKey::Device { controller, slot, generation }
            if *controller == dev.controller && *slot == dev.slot && *generation == dev.generation)
    });
}

// ── User memory ─────────────────────────────────────────────────────────

fn get(ctx: &dyn IoctlContext, address: u64, out: &mut [u8]) -> Result<(), i32> {
    ctx.read(address, out).map_err(|_| EFAULT)
}

fn put(ctx: &dyn IoctlContext, address: u64, bytes: &[u8]) -> Result<(), i32> {
    ctx.write(address, bytes).map_err(|_| EFAULT)
}

fn get_u32(ctx: &dyn IoctlContext, address: u64) -> Result<u32, i32> {
    let mut b = [0u8; 4];
    get(ctx, address, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

/// The NUL-terminated bytes of a fixed `char[256]` field (`strncmp`).
fn c_name(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// The driver name Linux reports for an interface's owner.
fn driver_of(owner: &Owner) -> &'static str {
    match owner {
        Owner::Driver(name) => name,
        Owner::File(_) => "usbfs",
    }
}

// ── The ioctls (`usbdev_do_ioctl`) ──────────────────────────────────────

impl Shared {
    async fn ioctl(
        self: &Arc<Self>,
        cmd: u32,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, i32> {
        if !self.writable {
            return Err(EPERM);
        }
        // Reap operations are allowed even after disconnection.
        match cmd {
            USBDEVFS_REAPURB => return self.reapurb(arg, ctx, true).await,
            USBDEVFS_REAPURBNDELAY => return self.reapurb(arg, ctx, false).await,
            _ => {}
        }
        if !self.connected() {
            return Err(ENODEV);
        }
        let r = match cmd {
            USBDEVFS_CONTROL => self.proc_control(arg, ctx).await,
            USBDEVFS_BULK => self.proc_bulk(arg, ctx).await,
            USBDEVFS_RESETEP => self.proc_resetep(arg, ctx).await,
            USBDEVFS_RESET => self.proc_resetdevice(),
            USBDEVFS_CLEAR_HALT => self.proc_clearhalt(arg, ctx).await,
            USBDEVFS_GETDRIVER => self.proc_getdriver(arg, ctx),
            USBDEVFS_CONNECTINFO => self.proc_connectinfo(arg, ctx),
            USBDEVFS_SETINTERFACE => self.proc_setintf(arg, ctx).await,
            USBDEVFS_SETCONFIGURATION => self.proc_setconfig(arg, ctx).await,
            USBDEVFS_SUBMITURB => self.proc_submiturb(arg, ctx).await,
            USBDEVFS_DISCARDURB => self.proc_unlinkurb(arg).await,
            USBDEVFS_DISCSIGNAL => self.proc_disconnectsignal(arg, ctx),
            USBDEVFS_CLAIMINTERFACE => {
                let ifnum = get_u32(ctx, arg)?;
                self.claimintf(ifnum).await.map(|()| 0)
            }
            USBDEVFS_RELEASEINTERFACE => {
                let ifnum = get_u32(ctx, arg)?;
                self.releaseintf(ifnum)?;
                self.destroy(|u| u.ifnum == Some(ifnum as u8)).await;
                Ok(0)
            }
            USBDEVFS_IOCTL => self.proc_ioctl(arg, ctx).await,
            USBDEVFS_CLAIM_PORT => self.proc_claim_port(arg, ctx),
            USBDEVFS_RELEASE_PORT => self.proc_release_port(arg, ctx),
            USBDEVFS_GET_CAPABILITIES => {
                // No MMAP, no streams and no SUSPEND (this usbfs behaves as
                // a !CONFIG_PM kernel); no BULK_CONTINUATION, as on every
                // xHCI host (`no_stop_on_short`); no scatter-gather.
                let caps = CAP_ZERO_PACKET
                    | CAP_NO_PACKET_SIZE_LIM
                    | CAP_REAP_AFTER_DISCONNECT
                    | CAP_DROP_PRIVILEGES
                    | CAP_CONNINFO_EX;
                put(ctx, arg, &caps.to_le_bytes()).map(|()| 0)
            }
            USBDEVFS_DISCONNECT_CLAIM => self.proc_disconnect_claim(arg, ctx).await,
            USBDEVFS_ALLOC_STREAMS => self.proc_streams(arg, ctx, true).await,
            USBDEVFS_FREE_STREAMS => self.proc_streams(arg, ctx, false).await,
            USBDEVFS_DROP_PRIVILEGES => {
                let mask = get_u32(ctx, arg)?;
                let mut st = self.state.lock();
                st.interface_allowed_mask &= mask;
                st.privileges_dropped = true;
                Ok(0)
            }
            USBDEVFS_GET_SPEED => Ok(u64::from(self.target.speed())),
            USBDEVFS_FORBID_SUSPEND => {
                // `usb_autoresume_device` cannot fail without CONFIG_PM.
                self.state.lock().suspend_allowed = false;
                Ok(0)
            }
            USBDEVFS_ALLOW_SUSPEND => {
                let mut st = self.state.lock();
                st.not_yet_resumed = true;
                st.suspend_allowed = true;
                Ok(0)
            }
            USBDEVFS_WAIT_FOR_RESUME => self.proc_wait_for_resume().await,
            _ => Err(ENOTTY),
        };
        // Variable-length commands.
        if cmd & !IOCSIZE_MASK == USBDEVFS_CONNINFO_EX_0 {
            return self.proc_conninfo_ex(arg, ctx, ((cmd & IOCSIZE_MASK) >> 16) as usize);
        }
        r
    }

    async fn proc_control(self: &Arc<Self>, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut b = [0u8; 24];
        get(ctx, arg, &mut b)?;
        let (rt, req, value, index, length) = (b[0], b[1], le16(&b, 2), le16(&b, 4), le16(&b, 6));
        let data = le64(&b, 16);
        self.check_ctrlrecip(rt, req, index).await?;
        let w_length = usize::from(length);
        if w_length > 4096 {
            return Err(EINVAL);
        }
        let charge_bytes = 4096 + URB_OVERHEAD;
        charge(charge_bytes)?;
        let mut setup = [0u8; 8];
        setup[0] = rt;
        setup[1] = req;
        setup[2..4].copy_from_slice(&value.to_le_bytes());
        setup[4..6].copy_from_slice(&index.to_le_bytes());
        setup[6..8].copy_from_slice(&length.to_le_bytes());
        // LINUX-GAP: the caller's timeout (b[8..12]) is not honoured past
        // the controller's fixed per-stage bound.
        let mut tbuf = alloc::vec![0u8; w_length];
        let r = if rt & 0x80 != 0 && w_length != 0 {
            match self.control(setup, &mut tbuf).await {
                Ok(n) => {
                    if n != 0 {
                        if let Err(e) = put(ctx, data, &tbuf[..n]) {
                            uncharge(charge_bytes);
                            return Err(e);
                        }
                    }
                    Ok(n as u64)
                }
                Err(e) => Err(e),
            }
        } else {
            if w_length != 0 {
                if let Err(e) = get(ctx, data, &mut tbuf) {
                    uncharge(charge_bytes);
                    return Err(e);
                }
            }
            self.control(setup, &mut tbuf).await.map(|n| n as u64)
        };
        uncharge(charge_bytes);
        r
    }

    async fn proc_bulk(self: &Arc<Self>, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut b = [0u8; 24];
        get(ctx, arg, &mut b)?;
        let (ep, len, timeout, data) = (le32(&b, 0), le32(&b, 4), le32(&b, 8), le64(&b, 16));
        let ifnum = self.findintfep(ep)?;
        self.checkintf(ifnum).await?;
        if len >= (i32::MAX as u32) - URB_OVERHEAD as u32 {
            return Err(EINVAL);
        }
        let host = self.host_endpoint(ep as u8).ok_or(EINVAL)?;
        if host.maxp() == 0 {
            return Err(EINVAL);
        }
        // LINUX-GAP: a bulk ioctl on an isochronous endpoint is refused.
        let xfer = match host.xfer() {
            desc::XFER_INT => Xfer::Interrupt,
            desc::XFER_BULK => Xfer::Bulk,
            _ => return Err(EINVAL),
        };
        let len = len as usize;
        let charge_bytes = len + URB_OVERHEAD;
        charge(charge_bytes)?;
        let is_in = ep & 0x80 != 0;
        let mut out = Vec::new();
        if !is_in && len != 0 {
            out = alloc::vec![0u8; len];
            if let Err(e) = get(ctx, data, &mut out) {
                uncharge(charge_bytes);
                return Err(e);
            }
        }
        let submit = Submit {
            userurb: 0,
            ifnum: Some(ifnum as u8),
            ep: ep as u8,
            xfer,
            buffer: data,
            length: len,
            flags: 0,
            continuation: false,
            maxp: host.maxp(),
            charge: 0,
            sync: 0,
            out,
        };
        let r = self.run_sync(submit, timeout).await;
        uncharge(charge_bytes);
        let (status, urb) = r?;
        if status < 0 {
            return Err(-status);
        }
        if is_in && urb.actual != 0 {
            put(ctx, data, &urb.data[..urb.actual])?;
        }
        Ok(urb.actual as u64)
    }

    async fn proc_resetep(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let ep = get_u32(ctx, arg)?;
        let ifnum = self.findintfep(ep)?;
        self.checkintf(ifnum).await?;
        self.reset_endpoint(ep as u8).await;
        Ok(0)
    }

    /// `usb_reset_endpoint`: restart the host side of `ep` at DATA0. The
    /// xHCI driver refuses an endpoint with transfers queued, silently.
    async fn reset_endpoint(&self, ep: u8) {
        let Some(pipe) = self.pipe.as_deref() else {
            return;
        };
        if self.state.lock().engine.endpoint_busy(ep) || !pipe.configured(ep) {
            return;
        }
        let Some(cfg) = self.host_endpoint(ep).and_then(|e| e.config()) else {
            return;
        };
        if pipe.halted(ep) {
            let _ = pipe.recover(ep).await;
        }
        if pipe.deconfigure(&[ep]).await.is_ok() {
            let _ = pipe.configure(&[cfg]).await;
        }
    }

    fn proc_resetdevice(&self) -> Result<u64, i32> {
        let st = self.state.lock();
        if st.privileges_dropped {
            if let Some(config) = self.target.active_config() {
                for a in desc::alt_settings(&config).iter().filter(|a| a.alt == 0) {
                    let ours = st.ifclaimed & (1u64 << a.number.min(63)) != 0;
                    if self.target.owner(a.number).is_some() && !ours {
                        return Err(EACCES);
                    }
                }
            }
        }
        drop(st);
        match self.target {
            Target::RootHub(_) => Err(EISDIR),
            // LINUX-GAP: no port reset + re-address path yet.
            Target::Device(_) => Err(EIO),
        }
    }

    async fn proc_clearhalt(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let ep = get_u32(ctx, arg)?;
        let ifnum = self.findintfep(ep)?;
        self.checkintf(ifnum).await?;
        let ep = ep as u8;
        // `usb_clear_halt`: CLEAR_FEATURE(ENDPOINT_HALT) to the endpoint,
        // then the host-side reset (the xHCI driver already recovered a
        // halted endpoint when the transfer failed).
        if let Some(pipe) = self.pipe.as_deref() {
            if pipe.halted(ep) {
                let _ = pipe.recover(ep).await;
            }
        }
        // CLEAR_FEATURE(ENDPOINT_HALT), recipient endpoint.
        let setup = [0x02, 0x01, 0, 0, ep, 0, 0, 0];
        self.control(setup, &mut []).await?;
        self.reset_endpoint(ep).await;
        Ok(0)
    }

    fn proc_getdriver(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut gd = [0u8; 260];
        get(ctx, arg, &mut gd)?;
        let ifnum = le32(&gd, 0);
        let config = self.target.active_config();
        let iface_exists =
            ifnum < 256 && config.is_some_and(|c| desc::has_interface(&c, ifnum as u8));
        let owner = iface_exists
            .then(|| self.target.owner(ifnum as u8))
            .flatten()
            .ok_or(ENODATA)?;
        let name = driver_of(&owner).as_bytes();
        let n = name.len().min(255);
        gd[4..].fill(0);
        gd[4..4 + n].copy_from_slice(&name[..n]);
        put(ctx, arg, &gd).map(|()| 0)
    }

    fn proc_connectinfo(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut ci = [0u8; 8];
        ci[0..4].copy_from_slice(&u32::from(self.target.devnum()).to_le_bytes());
        ci[4] = u8::from(self.target.speed() == 1);
        put(ctx, arg, &ci).map(|()| 0)
    }

    fn proc_conninfo_ex(&self, arg: u64, ctx: &dyn IoctlContext, size: usize) -> Result<u64, i32> {
        if size < 4 {
            return Err(EINVAL);
        }
        let mut ci = [0u8; 24];
        ci[0..4].copy_from_slice(&24u32.to_le_bytes());
        ci[4..8].copy_from_slice(&u32::from(self.target.busnum()).to_le_bytes());
        ci[8..12].copy_from_slice(&u32::from(self.target.devnum()).to_le_bytes());
        ci[12..16].copy_from_slice(&self.target.speed().to_le_bytes());
        let chain = self.target.port_chain();
        ci[16] = chain.len().min(255) as u8;
        // The seven ports nearest the device, root first.
        let keep = &chain[chain.len().saturating_sub(7)..];
        ci[17..17 + keep.len()].copy_from_slice(keep);
        put(ctx, arg, &ci[..size.min(24)]).map(|()| 0)
    }

    async fn proc_setintf(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut b = [0u8; 8];
        get(ctx, arg, &mut b)?;
        let (ifnum, altsetting) = (le32(&b, 0), le32(&b, 4));
        self.checkintf(ifnum).await?;
        self.destroy(|u| u.ifnum == Some(ifnum as u8)).await;
        self.set_interface(ifnum, altsetting).await.map(|()| 0)
    }

    /// `usb_set_interface`.
    async fn set_interface(&self, ifnum: u32, altsetting: u32) -> Result<(), i32> {
        let config = self.target.active_config().ok_or(EINVAL)?;
        let iface = ifnum as u8;
        if ifnum > 255 || !desc::has_interface(&config, iface) {
            return Err(EINVAL);
        }
        let new = (altsetting <= 255)
            .then(|| desc::find_alt(&config, iface, altsetting as u8))
            .flatten()
            .ok_or(EINVAL)?;
        let old = desc::find_alt(&config, iface, self.target.alt_setting(iface));
        let Some(pipe) = self.pipe.as_deref() else {
            return Err(EINVAL);
        };
        // Bandwidth: drop the old setting's endpoints, add the new one's.
        let old_eps: Vec<EpDesc> = old.map(|a| a.endpoints).unwrap_or_default();
        let dropped: Vec<u8> = old_eps
            .iter()
            .map(|e| e.addr)
            .filter(|&ep| pipe.configured(ep))
            .collect();
        pipe.deconfigure(&dropped).await.map_err(engine::errno)?;
        let added: Vec<_> = new.endpoints.iter().filter_map(EpDesc::config).collect();
        let back: Vec<_> = old_eps
            .iter()
            .filter(|e| dropped.contains(&e.addr))
            .filter_map(EpDesc::config)
            .collect();
        if let Err(e) = pipe.configure(&added).await {
            let _ = pipe.configure(&back).await;
            return Err(engine::errno(e));
        }
        let setup = [0x01, 0x0b, altsetting as u8, 0, iface, 0, 0, 0];
        let mut manual = false;
        match pipe.control(setup, &mut []).await {
            Ok(_) => {}
            // USB 2.0 §9.4.10: a single-setting interface may STALL it.
            Err(crate::device::UsbError::Stall) if desc::num_altsettings(&config, iface) == 1 => {
                manual = true;
            }
            Err(e) => {
                let new_eps: Vec<u8> = new.endpoints.iter().map(|e| e.addr).collect();
                let _ = pipe.deconfigure(&new_eps).await;
                let _ = pipe.configure(&back).await;
                return Err(engine::errno(e));
            }
        }
        if let Target::Device(d) = &self.target {
            d.set_alt_setting(iface, altsetting as u8);
        }
        if manual {
            for e in &new.endpoints {
                let setup = [0x02, 0x01, 0, 0, e.addr, 0, 0, 0];
                let _ = pipe.control(setup, &mut []).await;
            }
        }
        Ok(())
    }

    async fn proc_setconfig(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let u = get_u32(ctx, arg)? as i32;
        if let Some(config) = self.target.active_config() {
            let busy = desc::alt_settings(&config)
                .iter()
                .any(|a| self.target.owner(a.number).is_some());
            if busy {
                return Err(EBUSY);
            }
        }
        let Target::Device(dev) = &self.target else {
            return Err(EBUSY);
        };
        let Some(pipe) = self.pipe.as_deref() else {
            return Err(ENODEV);
        };
        // `usb_set_configuration`: -1 unconfigures; an unknown nonzero
        // value is EINVAL; 0 names a config 0 if the device has one.
        let configuration = if u == -1 { 0 } else { u };
        let exists = dev
            .configs
            .iter()
            .any(|c| c.len() >= 9 && i32::from(c[5]) == configuration);
        if !exists && configuration != 0 {
            return Err(EINVAL);
        }
        // Drop every endpoint of the old configuration from the controller.
        if let Some(old) = dev.active_config() {
            let eps: Vec<u8> = desc::alt_settings(old)
                .iter()
                .flat_map(|a| a.endpoints.iter().map(|e| e.addr))
                .filter(|&ep| pipe.configured(ep))
                .fold(Vec::new(), |mut v, ep| {
                    if !v.contains(&ep) {
                        v.push(ep);
                    }
                    v
                });
            pipe.deconfigure(&eps).await.map_err(engine::errno)?;
        }
        let same = i32::from(dev.config_value()) == configuration && dev.config_value() != 0;
        let setup = [0x00, 0x09, configuration as u8, 0, 0, 0, 0, 0];
        match pipe.control(setup, &mut []).await {
            Ok(_) => {
                dev.set_config_value(if exists { configuration as u8 } else { 0 });
                crate::usb_sysfs::publish_interfaces(dev);
                // LINUX-GAP: kernel drivers are not probed against the new
                // configuration's interfaces.
                Ok(0)
            }
            Err(e) => {
                // `usb_set_configuration`: "All the old state is gone", the
                // device is unconfigured. `usb_reset_configuration` keeps
                // `actconfig` with its endpoints freed.
                if !same {
                    dev.set_config_value(0);
                }
                Err(engine::errno(e))
            }
        }
    }

    async fn proc_submiturb(
        self: &Arc<Self>,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, i32> {
        let mut u = [0u8; URB_SIZE];
        get(ctx, arg, &mut u)?;
        let kind = u[0];
        let mut endpoint = u[1];
        let flags = le32(&u, 8);
        let mut buffer = le64(&u, 16);
        let mut buffer_length = le32(&u, 24);
        let number_of_packets = le32(&u, 36) as i32;
        // `signr` (offset 44) is accepted; LINUX-GAP: no completion signal.

        let mut mask = URB_SHORT_NOT_OK
            | URB_BULK_CONTINUATION
            | URB_NO_FSBR
            | URB_ZERO_PACKET
            | URB_NO_INTERRUPT;
        if kind == URB_TYPE_ISO {
            mask |= URB_ISO_ASAP;
        }
        if flags & !mask != 0 {
            return Err(EINVAL);
        }
        if buffer_length >= USBFS_XFER_MAX {
            return Err(EINVAL);
        }
        if buffer_length > 0 && buffer == 0 {
            return Err(EINVAL);
        }
        let mut ifnum = None;
        if !(kind == URB_TYPE_CONTROL && endpoint & !0x80 == 0) {
            let i = self.findintfep(u32::from(endpoint))?;
            self.checkintf(i).await?;
            ifnum = Some(i as u8);
        }
        let ep = self.host_endpoint(endpoint).ok_or(ENOENT)?;
        let mut is_in = endpoint & 0x80 != 0;
        let allow_short;
        let mut allow_zero = false;
        let mut setup = None;
        let xfer = match kind {
            URB_TYPE_CONTROL => {
                if ep.xfer() != desc::XFER_CONTROL {
                    return Err(EINVAL);
                }
                if buffer_length < 8 {
                    return Err(EINVAL);
                }
                let mut dr = [0u8; 8];
                get(ctx, buffer, &mut dr)?;
                let w_length = u32::from(le16(&dr, 6));
                if buffer_length < w_length + 8 {
                    return Err(EINVAL);
                }
                self.check_ctrlrecip(dr[0], dr[1], le16(&dr, 4)).await?;
                buffer_length = w_length;
                buffer += 8;
                if dr[0] & 0x80 != 0 && buffer_length != 0 {
                    is_in = true;
                    endpoint |= 0x80;
                } else {
                    is_in = false;
                    endpoint &= !0x80;
                }
                allow_short = is_in;
                setup = Some(dr);
                None
            }
            URB_TYPE_BULK => match ep.xfer() {
                desc::XFER_CONTROL | desc::XFER_ISOC => return Err(EINVAL),
                desc::XFER_INT => {
                    allow_zero = !is_in;
                    allow_short = is_in;
                    Some(Xfer::Interrupt)
                }
                _ => {
                    allow_zero = !is_in;
                    allow_short = is_in;
                    Some(Xfer::Bulk)
                }
            },
            URB_TYPE_INTERRUPT => {
                if ep.xfer() != desc::XFER_INT {
                    return Err(EINVAL);
                }
                allow_zero = !is_in;
                allow_short = is_in;
                Some(Xfer::Interrupt)
            }
            URB_TYPE_ISO => {
                if !(1..=128).contains(&number_of_packets) {
                    return Err(EINVAL);
                }
                if ep.xfer() != desc::XFER_ISOC {
                    return Err(EINVAL);
                }
                // LINUX-GAP: isochronous URBs are not implemented.
                return Err(EINVAL);
            }
            _ => return Err(EINVAL),
        };
        let length = buffer_length as usize;
        let charge_bytes = URB_OVERHEAD + length;
        charge(charge_bytes)?;
        let mut out = Vec::new();
        if !is_in && length != 0 {
            out = alloc::vec![0u8; length];
            if let Err(e) = get(ctx, buffer, &mut out) {
                uncharge(charge_bytes);
                return Err(e);
            }
        }
        let mut urb_flags = 0;
        if allow_short && flags & URB_SHORT_NOT_OK != 0 {
            urb_flags |= URB_SHORT_NOT_OK;
        }
        if allow_zero && flags & URB_ZERO_PACKET != 0 {
            urb_flags |= URB_ZERO_PACKET;
        }
        let Some(xfer) = xfer else {
            // A control URB runs to completion here (EP0 is serialised by
            // the controller); it is reapable as soon as this returns.
            let dr = setup.unwrap_or_default();
            let mut data = if is_in { alloc::vec![0u8; length] } else { out };
            let r = self.control(dr, &mut data).await;
            let (status, actual) = match r {
                Ok(n) => {
                    let short = is_in && n < length && urb_flags & URB_SHORT_NOT_OK != 0;
                    (if short { -121 } else { 0 }, n)
                }
                Err(e) => (-e, 0),
            };
            data.truncate(if is_in { actual } else { 0 });
            let done = engine::completed_urb(
                arg,
                ifnum,
                endpoint,
                buffer,
                length,
                status,
                actual,
                data,
                charge_bytes,
            );
            self.state.lock().engine.push_completed(done);
            self.refresh_readiness();
            return Ok(0);
        };
        let submit = Submit {
            userurb: arg,
            ifnum,
            ep: endpoint,
            xfer,
            buffer,
            length,
            flags: urb_flags,
            continuation: flags & URB_BULK_CONTINUATION != 0,
            maxp: ep.maxp(),
            charge: charge_bytes,
            sync: 0,
            out,
        };
        if let Err(e) = self.state.lock().engine.submit(submit) {
            uncharge(charge_bytes);
            return Err(e);
        }
        self.pump();
        self.ensure_pump();
        Ok(0)
    }

    async fn proc_unlinkurb(&self, arg: u64) -> Result<u64, i32> {
        let stop = {
            let mut st = self.state.lock();
            let i = st.engine.index_of(arg).ok_or(EINVAL)?;
            st.engine.begin_kill(i)
        };
        if let (Some(stop), Some(pipe)) = (stop, self.pipe.as_deref()) {
            let r = pipe.stop(stop.receipt).await;
            self.state.lock().engine.end_kill(pipe, stop, r);
        }
        // `usb_kill_urb` returns once the URB is given back.
        while self.state.lock().engine.is_pending(arg) {
            narf_time::sleep_ms(1).await;
        }
        self.refresh_readiness();
        Ok(0)
    }

    /// `processcompl`: copy one completion out, then free it.
    fn processcompl(&self, urb: Urb, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        uncharge(urb.charge);
        if urb.ep & 0x80 != 0 && urb.actual != 0 {
            put(ctx, urb.buffer, &urb.data[..urb.actual.min(urb.data.len())])?;
        }
        put(ctx, urb.userurb + 4, &urb.status.to_le_bytes())?;
        put(ctx, urb.userurb + 28, &(urb.actual as i32).to_le_bytes())?;
        put(ctx, urb.userurb + 40, &0i32.to_le_bytes())?;
        put(ctx, arg, &urb.userurb.to_le_bytes())?;
        Ok(0)
    }

    async fn reapurb(&self, arg: u64, ctx: &dyn IoctlContext, block: bool) -> Result<u64, i32> {
        loop {
            self.pump();
            self.recover_halted().await;
            let urb = self.state.lock().engine.take_completed();
            self.refresh_readiness();
            if let Some(urb) = urb {
                return self.processcompl(urb, arg, ctx);
            }
            if !self.connected() {
                return Err(ENODEV);
            }
            if !block {
                return Err(EAGAIN);
            }
            narf_time::sleep_ms(1).await;
        }
    }

    fn proc_disconnectsignal(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut b = [0u8; 16];
        get(ctx, arg, &mut b)?;
        let mut st = self.state.lock();
        st.discsignr = le32(&b, 0);
        st.disccontext = le64(&b, 8);
        st.disc_pid = ctx.process_id();
        Ok(0)
    }

    /// `usb_driver_release_interface` for whoever holds `ifnum`.
    /// `Err(EBUSY)` when that binding cannot be torn down per interface.
    async fn unbind(&self, ifnum: u8, owner: &Owner) -> Result<(), i32> {
        match owner {
            Owner::File(id) if *id == self.id => {
                self.state.lock().ifclaimed &= !(1u64 << ifnum);
                self.destroy(|u| u.ifnum == Some(ifnum)).await;
                self.target.release(ifnum, owner);
                Ok(())
            }
            Owner::File(id) => {
                // `driver_disconnect`: the other file loses the interface
                // and its URBs on it.
                if let Some(other) = open_files().into_iter().find(|f| f.id == *id) {
                    other.state.lock().ifclaimed &= !(1u64 << ifnum);
                    other.destroy(|u| u.ifnum == Some(ifnum)).await;
                }
                self.target.release(ifnum, owner);
                Ok(())
            }
            Owner::Driver(_) => {
                let Target::Device(dev) = &self.target else {
                    return Err(EBUSY);
                };
                if !crate::hid::raw::unbind_interface(dev.controller, dev.slot, ifnum) {
                    // LINUX-GAP: device-wide kernel bindings cannot be
                    // released per interface.
                    return Err(EBUSY);
                }
                // Discard the armed interrupt TRB the binding left behind.
                if let (Some(pipe), Some(config)) = (self.pipe.as_deref(), dev.active_config()) {
                    if let Some(alt) = desc::find_alt(config, ifnum, dev.alt_setting(ifnum)) {
                        let eps: Vec<u8> = alt
                            .endpoints
                            .iter()
                            .map(|e| e.addr)
                            .filter(|&ep| pipe.configured(ep))
                            .collect();
                        let _ = pipe.deconfigure(&eps).await;
                    }
                }
                Ok(())
            }
        }
    }

    async fn proc_ioctl(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut b = [0u8; 16];
        get(ctx, arg, &mut b)?;
        let (ifno, code, data) = (le32(&b, 0) as i32, le32(&b, 4), le64(&b, 8));
        if self.state.lock().privileges_dropped {
            return Err(EACCES);
        }
        if !self.connected() {
            return Err(ENODEV);
        }
        let size = ((code & IOCSIZE_MASK) >> 16) as usize;
        let dir = code >> 30;
        let mut buf = alloc::vec![0u8; size];
        if size > 0 && dir & IOC_WRITE != 0 {
            get(ctx, data, &mut buf)?;
        }
        let config = self.target.active_config();
        let r: Result<u64, i32> = if self.target.config_value() == 0 {
            Err(EHOSTUNREACH)
        } else if !(0..=255).contains(&ifno)
            || !config.is_some_and(|c| desc::has_interface(&c, ifno as u8))
        {
            Err(EINVAL)
        } else {
            let iface = ifno as u8;
            let owner = self.target.owner(iface);
            match code {
                USBDEVFS_DISCONNECT => match owner {
                    Some(o) => self.unbind(iface, &o).await.map(|()| 0),
                    None => Err(ENODATA),
                },
                USBDEVFS_CONNECT => match owner {
                    None => Ok(u64::from(self.connect_driver(iface).await)),
                    Some(_) => Err(EBUSY),
                },
                _ => match owner {
                    Some(Owner::Driver("hub")) if code == USBDEVFS_HUB_PORTINFO => {
                        // `hub_ioctl`.
                        let nports = self.target.maxchild().min(127);
                        buf.resize(128, 0);
                        buf[0] = nports;
                        for p in 1..=nports {
                            buf[usize::from(p)] = self.target.child_devnum(p);
                        }
                        Ok(u64::from(nports) + 1)
                    }
                    Some(Owner::Driver("hub")) => Err(ENOSYS),
                    _ => Err(ENOTTY),
                },
            }
        };
        if r.is_ok() && dir & IOC_READ != 0 && size > 0 {
            put(ctx, data, &buf[..size])?;
        }
        r
    }

    /// `device_attach` for one interface: whether a kernel driver bound.
    async fn connect_driver(&self, iface: u8) -> bool {
        let Target::Device(dev) = &self.target else {
            return false;
        };
        let (Some(c), Some(config)) = (
            crate::xhci::controller_by_id(dev.controller),
            dev.active_config(),
        ) else {
            return false;
        };
        let Some(offset) = crate::hid::raw::hid_interface_offsets(config)
            .into_iter()
            .find(|&o| config.get(o + 2) == Some(&iface) && config.get(o + 3) == Some(&0))
        else {
            return false;
        };
        // The binding programs its own endpoints.
        if let Some(pipe) = self.pipe.as_deref() {
            if let Some(alt) = desc::find_alt(config, iface, 0) {
                let eps: Vec<u8> = alt
                    .endpoints
                    .iter()
                    .map(|e| e.addr)
                    .filter(|&ep| pipe.configured(ep))
                    .collect();
                if pipe.deconfigure(&eps).await.is_err() {
                    return false;
                }
            }
        }
        crate::hid::raw::bind_interface(&c, dev, config, offset)
            .await
            .is_ok()
    }

    fn proc_claim_port(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let port = get_u32(ctx, arg)?;
        if port == 0 || port > u32::from(self.target.maxchild()) {
            return Err(EINVAL);
        }
        let key = self.target.key();
        let mut owners = PORT_OWNERS.lock();
        if owners
            .iter()
            .any(|(k, p, _)| *k == key && u32::from(*p) == port)
        {
            return Err(EBUSY);
        }
        // LINUX-GAP: NARF's hub enumeration does not yet skip a claimed
        // port.
        owners.push((key, port as u8, self.id));
        Ok(0)
    }

    fn proc_release_port(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let port = get_u32(ctx, arg)?;
        if port == 0 || port > u32::from(self.target.maxchild()) {
            return Err(EINVAL);
        }
        let key = self.target.key();
        let mut owners = PORT_OWNERS.lock();
        let i = owners
            .iter()
            .position(|(k, p, f)| *k == key && u32::from(*p) == port && *f == self.id)
            .ok_or(ENOENT)?;
        owners.remove(i);
        Ok(0)
    }

    async fn proc_disconnect_claim(&self, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, i32> {
        let mut dc = [0u8; 264];
        get(ctx, arg, &mut dc)?;
        let (ifnum, flags) = (le32(&dc, 0), le32(&dc, 4));
        let config = self.target.active_config();
        if ifnum > 255 || !config.is_some_and(|c| desc::has_interface(&c, ifnum as u8)) {
            return Err(EINVAL);
        }
        if let Some(owner) = self.target.owner(ifnum as u8) {
            if self.state.lock().privileges_dropped {
                return Err(EACCES);
            }
            let wanted = c_name(&dc[8..264]);
            let name = driver_of(&owner).as_bytes();
            if flags & DISCONNECT_CLAIM_IF_DRIVER != 0 && wanted != name {
                return Err(EBUSY);
            }
            if flags & DISCONNECT_CLAIM_EXCEPT_DRIVER != 0 && wanted == name {
                return Err(EBUSY);
            }
            self.unbind(ifnum as u8, &owner).await?;
        }
        self.claimintf(ifnum).await.map(|()| 0)
    }

    /// `parse_usbdevfs_streams` and `usb_alloc_streams` / `usb_free_streams`
    /// on a host whose endpoints have no streams allocated.
    async fn proc_streams(
        &self,
        arg: u64,
        ctx: &dyn IoctlContext,
        alloc: bool,
    ) -> Result<u64, i32> {
        let num_streams = get_u32(ctx, arg)?;
        let num_eps = get_u32(ctx, arg + 4)?;
        if !(1..=USB_MAXENDPOINTS).contains(&num_eps) {
            return Err(EINVAL);
        }
        if alloc && !(2..=65536).contains(&num_streams) {
            return Err(EINVAL);
        }
        let mut eps = alloc::vec![0u8; num_eps as usize];
        get(ctx, arg + 8, &mut eps)?;
        let mut first = None;
        let mut descs = Vec::new();
        for &ep in &eps {
            let host = self.host_endpoint(ep).ok_or(EINVAL)?;
            let ifnum = self.findintfep(u32::from(ep))?;
            match first {
                None => {
                    self.checkintf(ifnum).await?;
                    first = Some(ifnum);
                }
                Some(i) if i != ifnum => return Err(EINVAL),
                Some(_) => {}
            }
            descs.push(host);
        }
        if let Some(i) = first {
            self.destroy(|u| u.ifnum == Some(i as u8)).await;
        }
        if self.target.speed() < 5 {
            return Err(EINVAL);
        }
        if self.target.config_value() == 0 {
            return Err(ENODEV);
        }
        // Streams apply to bulk endpoints only; none here has any allocated.
        // LINUX-GAP: a SuperSpeed bulk endpoint with MaxStreams cannot
        // allocate them yet.
        let _ = descs;
        Err(EINVAL)
    }

    async fn proc_wait_for_resume(&self) -> Result<u64, i32> {
        // Without CONFIG_PM nothing suspends: the wait ends on disconnect.
        while self.state.lock().not_yet_resumed {
            narf_time::sleep_ms(10).await;
        }
        self.state.lock().suspend_allowed = false;
        Ok(0)
    }

    /// `usbdev_read`: the device descriptor, then every configuration.
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> Result<usize, i32> {
        if !self.connected() {
            return Err(ENODEV);
        }
        let mut ppos = pos as usize;
        let mut done = 0usize;
        let device = self.target.descriptor();
        if ppos < device.len() {
            let n = (device.len() - ppos).min(buf.len());
            buf[..n].copy_from_slice(&device[ppos..ppos + n]);
            ppos += n;
            done += n;
        }
        let mut at = device.len();
        for config in self.target.configs() {
            if done >= buf.len() {
                break;
            }
            let length = if config.len() >= 4 {
                usize::from(le16(&config, 2))
            } else {
                config.len()
            };
            if ppos < at + length {
                let off = ppos - at;
                let n = (length - off).min(buf.len() - done);
                // A descriptor longer than what was read: the unallocated
                // tail is skipped over, not written.
                let have = config.len().saturating_sub(off).min(n);
                buf[done..done + have].copy_from_slice(&config[off..off + have]);
                ppos += n;
                done += n;
            }
            at += length;
        }
        Ok(done)
    }
}

impl FileOps for UsbfsFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let r = self.0.read_at(offset, buf).map_err(fs_error);
        Box::pin(async move { r })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // `usbdev_file_operations` has no write.
        Box::pin(async { Err(FsError::InvalidData) })
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move { self.0.ioctl(cmd, arg, ctx).await.map_err(fs_error) })
    }

    fn poll_readiness(&self) -> u32 {
        self.0.pump();
        self.0.refresh_readiness();
        self.0.readiness.mask()
    }

    fn readiness(&self) -> Option<&Readiness> {
        Some(&self.0.readiness)
    }

    node_metadata!();
}

#[doc(hidden)]
pub fn __reset_for_test() {
    NODES.lock().clear();
    PORT_OWNERS.lock().clear();
    OPEN.lock().clear();
}

/// Open `target` over a model pipe, no pump task (smokes).
#[doc(hidden)]
pub fn __open_for_test(target: Target, pipe: Option<Arc<dyn Pipe>>, write: bool) -> Arc<UsbfsFile> {
    let meta = meta_for(&target);
    UsbfsFile::with_pipe(target, meta, pipe, write, false)
}

/// Bytes currently charged to the usbfs memory budget.
#[doc(hidden)]
pub fn __memory_used_for_test() -> usize {
    MEMORY_USED.load(Ordering::Acquire)
}
