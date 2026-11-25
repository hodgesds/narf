//! `/dev/hidrawN` and the HID sysfs surface, driven through the
//! `hid_device` registry with a scripted transport.
//!
//! Every errno and its order is `drivers/hid/hidraw.c`'s; every sysfs
//! name, attribute and link is what Linux shows for the same device (the
//! values are a Yubico 1050:0407 FIDO interface and the SYNA8018
//! 06CB:CE67 touchpad as a P14s Gen 5 reports them).

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use async_trait::async_trait;
use narf_input::hid_device::{self, HidDevice, HidInfo, HidIoError, HidTransport, ReportType};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hidraw::{
    hidiocgfeature, hidiocginput, hidiocgoutput, hidiocgrawname, hidiocgrawphys, hidiocgrawuniq,
    hidiocsfeature, hidiocsinput, hidiocsoutput, node_of, populate_hidraw_class, HIDIOCGRAWINFO,
    HIDIOCGRDESC, HIDIOCGRDESCSIZE, HIDIOCREVOKE, HIDRAW_BUFFER_SIZE, HIDRAW_MAJOR,
};
use crate::sysfs::{get_root, Kobject};
use crate::uevent::{UeventAction, UeventEnv, UeventReader};
use crate::{FileOps, FileType, FsError, FsInstance, IoctlContext};

const POLL_IN: u32 = crate::POLL_IN;
const POLL_OUT: u32 = crate::POLL_OUT;
const POLL_ERR: u32 = crate::POLL_ERR;
const POLL_HUP: u32 = crate::POLL_HUP;
const POLL_RDNORM: u32 = crate::POLL_RDNORM;
const POLL_WRNORM: u32 = 0x0100;

/// The CTAP-spec FIDO HID report descriptor (64-byte IN/OUT reports).
const FIDO: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

/// A touchpad descriptor with a Contact ID input and the Win8 blob.
const PTP: &[u8] = &[
    0x05, 0x0d, 0x09, 0x05, 0xa1, 0x01, 0x85, 0x01, 0x09, 0x22, 0xa1, 0x02, 0x09, 0x51, 0x75, 0x08,
    0x95, 0x01, 0x81, 0x02, 0xc0, 0x06, 0x00, 0xff, 0x85, 0x05, 0x09, 0xc5, 0x15, 0x00, 0x26, 0xff,
    0x00, 0x75, 0x08, 0x96, 0x00, 0x01, 0xb1, 0x02, 0xc0,
];

const YUBIKEY_PARENT: &str = "devices/pci0000:00/0000:00:08.3/0000:c6:00.4/usb7/7-1/7-1:1.1";

// ── Scripted transport ─────────────────────────────────────────────────

/// One `raw_request`: report ID, buffer as passed, type, SET.
type Request = (u8, Vec<u8>, ReportType, bool);

#[derive(Debug)]
struct Fake {
    outputs: IrqSafeSpinLock<Vec<Vec<u8>>>,
    requests: IrqSafeSpinLock<Vec<Request>>,
    /// `None`: accept the whole report.
    output_result: IrqSafeSpinLock<Option<Result<usize, HidIoError>>>,
    /// `None`: accept a SET, answer a GET with `get_reply`.
    raw_result: IrqSafeSpinLock<Option<Result<usize, HidIoError>>>,
    get_reply: IrqSafeSpinLock<Vec<u8>>,
}

impl Default for Fake {
    fn default() -> Self {
        Self {
            outputs: IrqSafeSpinLock::new(Vec::new()),
            requests: IrqSafeSpinLock::new(Vec::new()),
            output_result: IrqSafeSpinLock::new(None),
            raw_result: IrqSafeSpinLock::new(None),
            get_reply: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

#[async_trait]
impl HidTransport for Fake {
    async fn output_report(&self, data: &[u8]) -> Result<usize, HidIoError> {
        self.outputs.lock().push(data.to_vec());
        let scripted = *self.output_result.lock();
        scripted.unwrap_or(Ok(data.len()))
    }

    async fn raw_request(
        &self,
        id: u8,
        buf: &mut [u8],
        kind: ReportType,
        set: bool,
    ) -> Result<usize, HidIoError> {
        self.requests.lock().push((id, buf.to_vec(), kind, set));
        let scripted = *self.raw_result.lock();
        if let Some(r) = scripted {
            return r;
        }
        if set {
            return Ok(buf.len());
        }
        let reply = self.get_reply.lock().clone();
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok(reply.len())
    }
}

fn yubikey_info() -> HidInfo {
    HidInfo {
        bus: narf_input::evdev::bus::USB,
        vendor: 0x1050,
        product: 0x0407,
        version: 0x0526,
        country: 0,
        name: String::from("Yubico YubiKey OTP+FIDO+CCID"),
        phys: String::from("usb-0000:c6:00.4-1/input1"),
        uniq: String::new(),
        report_descriptor: FIDO.to_vec(),
        sysfs_parent: String::from(YUBIKEY_PARENT),
    }
}

fn register(info: HidInfo) -> (Arc<HidDevice>, Arc<Fake>) {
    populate_hidraw_class();
    let fake = Arc::new(Fake::default());
    let dev = hid_device::register(info, fake.clone());
    (dev, fake)
}

// ── Fixture plumbing ───────────────────────────────────────────────────

/// Poll a future once: every fixture transfer completes synchronously.
fn now<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// A fake user address space: `[BASE, BASE + len)` is mapped.
struct User {
    bytes: IrqSafeSpinLock<Vec<u8>>,
}

const BASE: u64 = 0x10_0000;
const BAD: u64 = 0x10;

impl User {
    fn new(len: usize) -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(vec![0; len]),
        }
    }
    fn range(&self, address: u64, len: usize) -> Result<core::ops::Range<usize>, FsError> {
        let start = address.checked_sub(BASE).ok_or(FsError::BadAddress)? as usize;
        let end = start.checked_add(len).ok_or(FsError::BadAddress)?;
        if end > self.bytes.lock().len() {
            return Err(FsError::BadAddress);
        }
        Ok(start..end)
    }
    fn put(&self, at: usize, data: &[u8]) {
        self.bytes.lock()[at..at + data.len()].copy_from_slice(data);
    }
    fn get(&self, at: usize, len: usize) -> Vec<u8> {
        self.bytes.lock()[at..at + len].to_vec()
    }
}

impl IoctlContext for User {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        let r = self.range(address, destination.len())?;
        destination.copy_from_slice(&self.bytes.lock()[r]);
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        let r = self.range(address, source.len())?;
        self.bytes.lock()[r].copy_from_slice(source);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        true
    }
}

fn ioctl(f: &Arc<dyn FileOps>, cmd: u32, arg: u64, user: &User) -> Result<u64, FsError> {
    now(f.ioctl_user(cmd, arg, user)).unwrap_or(Err(FsError::WouldBlock))
}

fn read(f: &Arc<dyn FileOps>, len: usize) -> Result<Vec<u8>, FsError> {
    let mut buf = vec![0u8; len];
    let n = now(f.read(0, &mut buf)).unwrap_or(Err(FsError::WouldBlock))?;
    buf.truncate(n);
    Ok(buf)
}

fn write(f: &Arc<dyn FileOps>, data: &[u8]) -> Result<usize, FsError> {
    now(f.write(0, data)).unwrap_or(Err(FsError::WouldBlock))
}

fn lookup(minor: u32) -> Option<Arc<dyn FileOps>> {
    crate::devfs::DevFs::new()
        .root()
        .lookup(&format!("hidraw{minor}"))
}

fn open(minor: u32) -> Result<Arc<dyn FileOps>, &'static str> {
    lookup(minor)
        .ok_or("no /dev/hidrawN")?
        .open_instance_checked(true)
        .map_err(|_| "open failed")?
        .ok_or("open minted no instance")
}

fn minor_of(dev: &Arc<HidDevice>) -> Result<u32, &'static str> {
    Ok(node_of(dev).ok_or("device has no hidraw node")?.minor())
}

fn walk(path: &str) -> Option<Arc<Kobject>> {
    let mut k = get_root();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        k = k.get_child(part)?;
    }
    Some(k)
}

fn has_extra(env: &UeventEnv, key: &str, value: &str) -> bool {
    env.extras.iter().any(|(k, v)| k == key && v == value)
}

/// Run `body`, then unregister every device it registered.
fn with_devices(
    body: impl FnOnce(&mut Vec<Arc<HidDevice>>) -> Result<(), &'static str>,
) -> TestResult {
    let mut devs = Vec::new();
    let r = body(&mut devs);
    for dev in &devs {
        hid_device::unregister(dev);
    }
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

// ── sysfs + uevents ────────────────────────────────────────────────────

fn smoke_hidraw_sysfs_topology_and_uevents() -> TestResult {
    with_devices(|devs| {
        let mut reader = UeventReader::new();
        let (dev, _fake) = register(yubikey_info());
        devs.push(dev.clone());
        let n = minor_of(&dev)?;
        let name = dev.sysfs_name();
        if name != format!("0003:1050:0407.{:04X}", dev.id()) {
            return Err("sysfs name is not BBBB:VVVV:PPPP.NNNN");
        }
        let hid_path = format!("{YUBIKEY_PARENT}/{name}");
        let raw_path = format!("{hid_path}/hidraw/hidraw{n}");
        let hid = walk(&hid_path).ok_or("hid device kobject missing under its parent")?;
        // `hid_uevent` + `modalias_show` + `country_show`.
        if hid.attr_show("uevent").as_deref()
            != Some(
                "HID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\n\
                 HID_PHYS=usb-0000:c6:00.4-1/input1\nHID_UNIQ=\n\
                 MODALIAS=hid:b0003g0001v00001050p00000407\n",
            )
        {
            return Err("hid device uevent differs from hid_uevent");
        }
        if hid.attr_show("modalias").as_deref() != Some("hid:b0003g0001v00001050p00000407\n")
            || hid.attr_show("country").as_deref() != Some("00\n")
        {
            return Err("modalias / country attribute wrong");
        }
        // `report_descriptor_read`: offset reads, clamped at rsize.
        let mut buf = [0u8; 64];
        if hid.bin_attr_read("report_descriptor", 0, &mut buf) != Some(FIDO.len())
            || buf[..FIDO.len()] != *FIDO
            || hid.bin_attr_read("report_descriptor", 30, &mut buf) != Some(FIDO.len() - 30)
            || buf[..4] != FIDO[30..]
            || hid.bin_attr_read("report_descriptor", FIDO.len(), &mut buf) != Some(0)
        {
            return Err("report_descriptor bin attribute wrong");
        }
        if hid.get_symlink("subsystem").as_deref() != Some("../../../../../../../../bus/hid") {
            return Err("hid device subsystem link wrong");
        }
        if walk("bus/hid/devices")
            .and_then(|d| d.get_symlink(&name))
            .as_deref()
            != Some(format!("../../../{hid_path}").as_str())
        {
            return Err("/sys/bus/hid/devices link wrong");
        }
        let raw = walk(&raw_path).ok_or("hidraw class device missing")?;
        if raw.attr_show("dev") != Some(format!("{HIDRAW_MAJOR}:{n}\n"))
            || raw.attr_show("uevent")
                != Some(format!(
                    "MAJOR={HIDRAW_MAJOR}\nMINOR={n}\nDEVNAME=hidraw{n}\n"
                ))
        {
            return Err("hidrawN dev / uevent wrong");
        }
        if raw.get_symlink("subsystem").as_deref()
            != Some("../../../../../../../../../../class/hidraw")
            || raw.get_symlink("device") != Some(format!("../../../{name}"))
        {
            return Err("hidrawN subsystem / device link wrong");
        }
        let target = format!("../../{raw_path}");
        if walk("class/hidraw").and_then(|c| c.get_symlink(&format!("hidraw{n}")))
            != Some(target.clone())
            || walk("dev/char").and_then(|c| c.get_symlink(&format!("{HIDRAW_MAJOR}:{n}")))
                != Some(target)
        {
            return Err("/sys/class/hidraw or /sys/dev/char link wrong");
        }
        // add@hid device, then add@hidrawN (device_add before the driver's
        // hidraw_connect), each self-describing.
        let added: Vec<UeventEnv> = reader
            .drain(64)
            .into_iter()
            .filter(|e| e.devpath.starts_with(&format!("/{hid_path}")))
            .collect();
        if added.len() != 2
            || added[0].action != UeventAction::Add
            || added[0].devpath != format!("/{hid_path}")
            || added[0].subsystem != "hid"
            || !has_extra(&added[0], "HID_ID", "0003:00001050:00000407")
            || !has_extra(&added[0], "MODALIAS", "hid:b0003g0001v00001050p00000407")
            || added[1].action != UeventAction::Add
            || added[1].devpath != format!("/{raw_path}")
            || added[1].subsystem != "hidraw"
            || !has_extra(&added[1], "DEVNAME", &format!("hidraw{n}"))
            || !has_extra(&added[1], "MAJOR", "243")
        {
            return Err("ADD uevents missing, misordered or incomplete");
        }
        // The devtmpfs node: root:root 0600 character device 243:n.
        let proto = lookup(n).ok_or("devfs lookup of hidrawN failed")?;
        let st = proto.stat();
        if st.mode.file_type != FileType::Special
            || st.mode.perms != 0o600
            || proto.owners() != (0, 0)
            || proto.rdev() != crate::devfs::linux_makedev(HIDRAW_MAJOR, n)
            || proto.ino() != crate::devfs::char_device_inode(proto.rdev())
        {
            return Err("hidraw node stat differs from devtmpfs");
        }
        let listed = crate::devfs::DevFs::new().root().enumerate(0, 4096);
        if !listed.iter().any(|(name, _)| *name == format!("hidraw{n}")) {
            return Err("hidrawN missing from /dev readdir");
        }
        // A non-canonical name is not an alias.
        if crate::devfs::DevFs::new()
            .root()
            .lookup(&format!("hidraw0{n}"))
            .is_some()
        {
            return Err("hidraw0N resolved");
        }
        // Re-installing the hook replays the device without republishing.
        populate_hidraw_class();
        if !reader
            .drain(64)
            .iter()
            .all(|e| !e.devpath.starts_with(&format!("/{hid_path}")))
            || !walk(&hid_path).is_some_and(|k| Arc::ptr_eq(&k, &hid))
        {
            return Err("hook replay republished a published device");
        }
        // Unplug: remove@hidrawN, then remove@hid device; links gone.
        hid_device::unregister(&dev);
        let removed: Vec<UeventEnv> = reader
            .drain(64)
            .into_iter()
            .filter(|e| e.devpath.starts_with(&format!("/{hid_path}")))
            .collect();
        if removed.len() != 2
            || removed[0].action != UeventAction::Remove
            || removed[0].devpath != format!("/{raw_path}")
            || removed[1].action != UeventAction::Remove
            || removed[1].devpath != format!("/{hid_path}")
        {
            return Err("REMOVE uevents missing or misordered");
        }
        if walk(&hid_path).is_some()
            || walk("bus/hid/devices")
                .and_then(|d| d.get_symlink(&name))
                .is_some()
            || walk("class/hidraw")
                .and_then(|c| c.get_symlink(&format!("hidraw{n}")))
                .is_some()
            || walk("dev/char")
                .and_then(|c| c.get_symlink(&format!("{HIDRAW_MAJOR}:{n}")))
                .is_some()
            || lookup(n).is_some()
            || node_of(&dev).is_some()
        {
            return Err("unplug left sysfs links or the devfs node behind");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_sysfs_topology_and_uevents);

fn smoke_hidraw_platform_parent_and_identity_limits() -> TestResult {
    with_devices(|devs| {
        let long_name: String = core::iter::repeat_n('n', 140).collect();
        let long_phys: String = core::iter::repeat_n('p', 70).collect();
        let (dev, _fake) = register(HidInfo {
            bus: narf_input::evdev::bus::I2C,
            vendor: 0x06cb,
            product: 0xce67,
            version: 0x0100,
            country: 0x21,
            name: long_name.clone(),
            phys: long_phys.clone(),
            uniq: String::from("ab\0cd"),
            report_descriptor: PTP.to_vec(),
            sysfs_parent: String::new(),
        });
        devs.push(dev.clone());
        let name = dev.sysfs_name();
        if name != format!("0018:06CB:CE67.{:04X}", dev.id()) {
            return Err("I2C sysfs name wrong");
        }
        // No transport node: the platform parent, with a subsystem of its
        // own and a /sys/bus/platform entry, so path_id can walk it.
        let parent = walk("devices/platform/narf-hid").ok_or("platform parent missing")?;
        if parent.get_symlink("subsystem").as_deref() != Some("../../../bus/platform")
            || walk("bus/platform/devices")
                .and_then(|d| d.get_symlink("narf-hid"))
                .as_deref()
                != Some("../../../../devices/platform/narf-hid")
            || !parent.has_attr("uevent")
        {
            return Err("platform parent lacks its subsystem / bus entry / uevent");
        }
        let hid = parent
            .get_child(&name)
            .ok_or("hid device not under the platform parent")?;
        if hid.get_symlink("subsystem").as_deref() != Some("../../../../bus/hid") {
            return Err("hid subsystem link depth wrong under the platform parent");
        }
        // hid->name[128], phys[64], uniq[64] after strscpy: 127 / 63
        // bytes, uniq up to its NUL. Group 0004 = MULTITOUCH_WIN_8.
        let want = format!(
            "HID_ID=0018:000006CB:0000CE67\nHID_NAME={}\nHID_PHYS={}\nHID_UNIQ=ab\n\
             MODALIAS=hid:b0018g0004v000006CBp0000CE67\n",
            &long_name[..127],
            &long_phys[..63]
        );
        if hid.attr_show("uevent") != Some(want) {
            return Err("I2C hid uevent: truncation or group wrong");
        }
        if hid.attr_show("country").as_deref() != Some("21\n") {
            return Err("country not %02x");
        }
        // HIDIOCGRAWNAME / PHYS / UNIQ see the same truncated strings.
        let f = open(minor_of(&dev)?)?;
        let user = User::new(512);
        if ioctl(&f, hidiocgrawname(256), BASE, &user) != Ok(128)
            || user.get(0, 127) != long_name.as_bytes()[..127].to_vec()
            || user.get(127, 1) != [0]
            || ioctl(&f, hidiocgrawphys(256), BASE, &user) != Ok(64)
            || user.get(0, 63) != long_phys.as_bytes()[..63].to_vec()
            || ioctl(&f, hidiocgrawuniq(256), BASE, &user) != Ok(3)
            || user.get(0, 3) != b"ab\0".to_vec()
        {
            return Err("string ioctls did not truncate like hid_device's fields");
        }
        Ok(())
    })
}
kernel_test_in!(
    "filesystem/hidraw",
    smoke_hidraw_platform_parent_and_identity_limits
);

// ── read / poll ────────────────────────────────────────────────────────

fn smoke_hidraw_read_ring_semantics() -> TestResult {
    with_devices(|devs| {
        let (dev, _fake) = register(yubikey_info());
        devs.push(dev.clone());
        let n = minor_of(&dev)?;
        let a = open(n)?;
        let b = open(n)?;
        let idle = POLL_OUT | POLL_WRNORM;
        if a.poll_readiness() != idle || read(&a, 64) != Err(FsError::WouldBlock) {
            return Err("an idle open is not writable-only / would-block");
        }
        dev.report_in(&[1, 2, 3, 4]);
        if a.poll_readiness() != idle | POLL_IN | POLL_RDNORM
            || b.poll_readiness() != idle | POLL_IN | POLL_RDNORM
        {
            return Err("a report did not make every open readable");
        }
        // One report per read, cut to count, consumed whole.
        if read(&a, 2) != Ok(vec![1, 2]) || read(&a, 64) != Err(FsError::WouldBlock) {
            return Err("a short read did not consume the whole report");
        }
        if a.poll_readiness() != idle {
            return Err("draining the ring left POLLIN set");
        }
        if read(&b, 64) != Ok(vec![1, 2, 3, 4]) {
            return Err("second open missed the report");
        }
        // `while (ret == 0)`: an empty report is skipped.
        dev.report_in(&[]);
        dev.report_in(&[9]);
        if read(&a, 64) != Ok(vec![9]) {
            return Err("zero-length report was returned instead of skipped");
        }
        // HIDRAW_BUFFER_SIZE slots, one always empty: the newest overflow
        // is dropped, the oldest kept.
        let _ = read(&b, 64);
        let _ = read(&b, 64);
        for i in 0..(HIDRAW_BUFFER_SIZE as u8 + 6) {
            dev.report_in(&[i]);
        }
        for i in 0..(HIDRAW_BUFFER_SIZE as u8 - 1) {
            if read(&a, 1) != Ok(vec![i]) {
                return Err("ring did not keep the oldest 63 reports in order");
            }
        }
        if read(&a, 1) != Err(FsError::WouldBlock) {
            return Err("ring held more than HIDRAW_BUFFER_SIZE - 1 reports");
        }
        // A later open starts empty.
        let c = open(n)?;
        if read(&c, 64) != Err(FsError::WouldBlock) {
            return Err("a new open saw reports queued before it");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_read_ring_semantics);

fn smoke_hidraw_unplug_semantics() -> TestResult {
    with_devices(|devs| {
        let (dev, _fake) = register(yubikey_info());
        devs.push(dev.clone());
        let n = minor_of(&dev)?;
        let a = open(n)?;
        if now(a.set_perms(0o660)).is_none() {
            return Err("chmod did not complete");
        }
        dev.report_in(&[7, 7]);
        hid_device::unregister(&dev);
        // Queued data is still delivered; then -EIO, never EAGAIN.
        let st = a.poll_readiness();
        if st & (POLL_ERR | POLL_HUP) != POLL_ERR | POLL_HUP || st & POLL_IN == 0 {
            return Err("unplug did not raise POLLERR|POLLHUP");
        }
        if read(&a, 64) != Ok(vec![7, 7]) {
            return Err("queued report lost at unplug");
        }
        if read(&a, 64) != Err(FsError::Io(narf_block::BlockError::IOError)) {
            return Err("empty read after unplug is not EIO");
        }
        let user = User::new(16);
        if write(&a, &[0, 1]) != Err(FsError::NoDevice)
            || ioctl(&a, HIDIOCGRDESCSIZE, BASE, &user) != Err(FsError::NoDevice)
            || ioctl(&a, 0x8004_4501, BASE, &user) != Err(FsError::NoDevice)
        {
            return Err("write / ioctl after unplug is not ENODEV (checked first)");
        }
        if lookup(n).is_some() || a.open_instance_checked(true).err() != Some(FsError::NoDevice) {
            return Err("node still openable after unplug");
        }
        // The minor stays taken while an fd is open...
        let (dev2, _f2) = register(yubikey_info());
        devs.push(dev2.clone());
        if minor_of(&dev2)? == n {
            return Err("minor reused under an open fd");
        }
        // ...and is the lowest free one once it closes; the new device's
        // node starts from the devtmpfs defaults.
        drop(a);
        let (dev3, _f3) = register(yubikey_info());
        devs.push(dev3.clone());
        if minor_of(&dev3)? != n {
            return Err("closed minor not reused as the lowest free");
        }
        if lookup(n)
            .ok_or("no node for reused minor")?
            .stat()
            .mode
            .perms
            != 0o600
        {
            return Err("reused minor inherited the old node's mode");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_unplug_semantics);

// ── write and the report ioctls ────────────────────────────────────────

fn smoke_hidraw_write_and_report_transfers() -> TestResult {
    with_devices(|devs| {
        let (dev, fake) = register(yubikey_info());
        devs.push(dev.clone());
        let f = open(minor_of(&dev)?)?;
        // hidraw_send_report's size checks.
        if write(&f, &[0]) != Err(FsError::InvalidData)
            || write(&f, &vec![0; 16385]) != Err(FsError::InvalidData)
            || !fake.outputs.lock().is_empty()
        {
            return Err("write size checks wrong or reached the transport");
        }
        // Output reports go out on the interrupt path.
        if write(&f, &[0, 0xaa]) != Ok(2)
            || *fake.outputs.lock() != vec![vec![0, 0xaa]]
            || !fake.requests.lock().is_empty()
        {
            return Err("write did not use output_report");
        }
        // -ENOSYS (no interrupt OUT) falls back to SET_REPORT(Output, buf[0]).
        *fake.output_result.lock() = Some(Err(HidIoError::Unsupported));
        if write(&f, &[3, 1, 2]) != Ok(3)
            || *fake.requests.lock() != vec![(3, vec![3, 1, 2], ReportType::Output, true)]
        {
            return Err("ENOSYS output did not fall back to SET_REPORT");
        }
        // Any other failure is returned as is, without the fallback.
        fake.requests.lock().clear();
        for (err, want) in [
            (HidIoError::Stall, FsError::Stalled),
            (HidIoError::Timeout, FsError::TransferTimedOut),
            (HidIoError::NoDevice, FsError::NoDevice),
            (HidIoError::Io, FsError::Io(narf_block::BlockError::IOError)),
            (HidIoError::InvalidArgs, FsError::InvalidData),
        ] {
            *fake.output_result.lock() = Some(Err(err));
            if write(&f, &[0, 1]) != Err(want) {
                return Err("output_report error not mapped to the transport errno");
            }
        }
        if !fake.requests.lock().is_empty() {
            return Err("a non-ENOSYS output error fell back to SET_REPORT");
        }
        *fake.output_result.lock() = None;
        fake.outputs.lock().clear();

        let user = User::new(64);
        user.put(0, &[5, 1, 2]);
        // HIDIOCSFEATURE / SINPUT: SET_REPORT; HIDIOCSOUTPUT: the output path.
        if ioctl(&f, hidiocsfeature(3), BASE, &user) != Ok(3)
            || ioctl(&f, hidiocsinput(3), BASE, &user) != Ok(3)
            || *fake.requests.lock()
                != vec![
                    (5, vec![5, 1, 2], ReportType::Feature, true),
                    (5, vec![5, 1, 2], ReportType::Input, true),
                ]
            || !fake.outputs.lock().is_empty()
        {
            return Err("SFEATURE / SINPUT not a SET_REPORT of their type");
        }
        if ioctl(&f, hidiocsoutput(3), BASE, &user) != Ok(3)
            || *fake.outputs.lock() != vec![vec![5, 1, 2]]
        {
            return Err("SOUTPUT did not try the interrupt path first");
        }
        fake.requests.lock().clear();
        // HIDIOCGFEATURE: report number from the user, result cut to len.
        user.put(0, &[0x0d; 16]);
        *fake.get_reply.lock() = vec![0x0d, 0xa1, 0xa2, 0xa3];
        if ioctl(&f, hidiocgfeature(8), BASE, &user) != Ok(4)
            || user.get(0, 5) != vec![0x0d, 0xa1, 0xa2, 0xa3, 0x0d]
        {
            return Err("GFEATURE result or copy-out wrong");
        }
        let req = fake.requests.lock().last().cloned();
        if req.as_ref().map(|r| (r.0, r.1.len(), r.1[0], r.2, r.3))
            != Some((0x0d, 8, 0x0d, ReportType::Feature, false))
        {
            return Err("GFEATURE did not ask for report buf[0] with count bytes");
        }
        *fake.get_reply.lock() = (0..20).collect();
        user.put(0, &[0; 16]);
        if ioctl(&f, hidiocginput(8), BASE, &user) != Ok(8)
            || user.get(0, 9) != vec![0, 1, 2, 3, 4, 5, 6, 7, 0]
            || ioctl(&f, hidiocgoutput(8), BASE, &user) != Ok(8)
        {
            return Err("a longer GET reply was not cut to len");
        }
        let kinds: Vec<ReportType> = fake.requests.lock().iter().map(|r| r.2).collect();
        if kinds[kinds.len() - 2..] != [ReportType::Input, ReportType::Output] {
            return Err("GINPUT / GOUTPUT asked for the wrong report type");
        }
        // Size checks precede the user copy; EFAULT precedes the transport.
        // (`_IOC_SIZE` is 14 bits, so only write(2) can exceed
        // HID_MAX_BUFFER_SIZE; that case is covered above.)
        let before = fake.requests.lock().len();
        for (cmd, arg, want) in [
            (hidiocgfeature(1), BASE, FsError::InvalidData),
            (hidiocgfeature(0), BAD, FsError::InvalidData),
            (hidiocsfeature(1), BAD, FsError::InvalidData),
            (hidiocgfeature(8), BAD, FsError::BadAddress),
            (hidiocsfeature(8), BAD, FsError::BadAddress),
            // SFEATURE copies the whole buffer: 8 bytes do not fit at the end.
            (hidiocsfeature(8), BASE + 60, FsError::BadAddress),
        ] {
            if ioctl(&f, cmd, arg, &user) != Err(want) {
                return Err("report ioctl size / fault order differs from hidraw.c");
            }
        }
        if fake.requests.lock().len() != before {
            return Err("a rejected report ioctl reached the transport");
        }
        // GFEATURE reads one byte first; a fault on copy-out follows the
        // transfer.
        if ioctl(&f, hidiocgfeature(8), BASE + 63, &user) != Err(FsError::BadAddress)
            || fake.requests.lock().len() != before + 1
        {
            return Err("GFEATURE copy-out fault not after the transfer");
        }
        // Transport errnos pass through.
        *fake.raw_result.lock() = Some(Err(HidIoError::Unsupported));
        if ioctl(&f, hidiocgfeature(8), BASE, &user) != Err(FsError::NotImplemented) {
            return Err("raw_request ENOSYS not passed through");
        }
        *fake.raw_result.lock() = Some(Err(HidIoError::Stall));
        if ioctl(&f, hidiocsfeature(2), BASE, &user) != Err(FsError::Stalled) {
            return Err("raw_request EPIPE not passed through");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_write_and_report_transfers);

// ── ioctl decode ───────────────────────────────────────────────────────

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((b'H' as u32) << 8) | nr
}

fn smoke_hidraw_ioctl_decode_and_errno_order() -> TestResult {
    with_devices(|devs| {
        let mut info = yubikey_info();
        info.vendor = 0x8001_abcd;
        let (dev, fake) = register(info);
        devs.push(dev.clone());
        let f = open(minor_of(&dev)?)?;
        let user = User::new(8192);
        for (cmd, want) in [
            // _IOC_TYPE != 'H' → EINVAL (not ENOTTY).
            (0x8004_4501, FsError::InvalidData),
            // _IOC_NR == 0 or > HIDIOCTL_LAST → ENOTTY.
            (ioc(2, 0x00, 4), FsError::Unsupported),
            (ioc(2, 0x0e, 4), FsError::Unsupported),
            (ioc(3, 0xff, 4), FsError::Unsupported),
            // Fixed-size commands match only at their exact size.
            (ioc(2, 0x01, 8), FsError::InvalidData),
            (ioc(2, 0x03, 4), FsError::InvalidData),
            // Variable-size commands match only in their direction.
            (ioc(1, 0x06, 8), FsError::InvalidData),
            (ioc(2, 0x06, 8), FsError::InvalidData),
            (ioc(3, 0x04, 8), FsError::InvalidData),
            (ioc(0, 0x04, 0), FsError::InvalidData),
            (ioc(1, 0x0d, 8), FsError::InvalidData),
        ] {
            if ioctl(&f, cmd, BASE, &user) != Err(want) {
                return Err("ioctl decode errno differs from hidraw_ioctl");
            }
        }
        // HIDIOCGRDESCSIZE.
        if ioctl(&f, HIDIOCGRDESCSIZE, BASE, &user) != Ok(0)
            || user.get(0, 4) != (FIDO.len() as i32).to_ne_bytes()
            || ioctl(&f, HIDIOCGRDESCSIZE, BAD, &user) != Err(FsError::BadAddress)
        {
            return Err("HIDIOCGRDESCSIZE wrong");
        }
        // HIDIOCGRDESC: len from the user, capped at 4095, min(rsize, len)
        // bytes at value[0].
        user.put(0, &4096u32.to_ne_bytes());
        if ioctl(&f, HIDIOCGRDESC, BASE, &user) != Err(FsError::InvalidData) {
            return Err("HIDIOCGRDESC len 4096 not EINVAL");
        }
        user.put(0, &4095u32.to_ne_bytes());
        if ioctl(&f, HIDIOCGRDESC, BASE, &user) != Ok(0) || user.get(4, FIDO.len()) != FIDO.to_vec()
        {
            return Err("HIDIOCGRDESC full copy wrong");
        }
        user.put(0, &3u32.to_ne_bytes());
        user.put(4, &[0xee; 8]);
        if ioctl(&f, HIDIOCGRDESC, BASE, &user) != Ok(0)
            || user.get(4, 4) != vec![FIDO[0], FIDO[1], FIDO[2], 0xee]
        {
            return Err("HIDIOCGRDESC did not copy min(rsize, len)");
        }
        // len 0 copies nothing, so value[] need not be mapped.
        let end = BASE + 8192 - 4;
        user.put(8192 - 4, &0u32.to_ne_bytes());
        if ioctl(&f, HIDIOCGRDESC, end, &user) != Ok(0)
            || ioctl(&f, HIDIOCGRDESC, BAD, &user) != Err(FsError::BadAddress)
        {
            return Err("HIDIOCGRDESC zero-length or fault case wrong");
        }
        // HIDIOCGRAWINFO: u32 bustype, s16 vendor/product (truncated).
        if ioctl(&f, HIDIOCGRAWINFO, BASE, &user) != Ok(0) {
            return Err("HIDIOCGRAWINFO failed");
        }
        let mut want = Vec::new();
        want.extend_from_slice(&3u32.to_ne_bytes());
        want.extend_from_slice(&(0xabcdu16 as i16).to_ne_bytes());
        want.extend_from_slice(&0x0407i16.to_ne_bytes());
        if user.get(0, 8) != want {
            return Err("HIDIOCGRAWINFO layout or truncation wrong");
        }
        // HIDIOCGRAWNAME(len): min(len, strlen + 1) bytes; no NUL when cut.
        let name = b"Yubico YubiKey OTP+FIDO+CCID";
        user.put(0, &[0xee; 64]);
        if ioctl(&f, hidiocgrawname(0), BASE, &user) != Ok(0)
            || ioctl(&f, hidiocgrawname(5), BASE, &user) != Ok(5)
            || user.get(0, 6) != b"Yubic\xee".to_vec()
            || ioctl(&f, hidiocgrawname(256), BASE, &user) != Ok(name.len() as u64 + 1)
            || user.get(0, name.len() + 1)[..name.len()] != name[..]
            || user.get(name.len(), 1) != [0]
            || ioctl(&f, hidiocgrawname(16), BAD, &user) != Err(FsError::BadAddress)
        {
            return Err("HIDIOCGRAWNAME length rules wrong");
        }
        if ioctl(&f, hidiocgrawuniq(16), BASE, &user) != Ok(1)
            || user.get(0, 1) != [0]
            || ioctl(&f, hidiocgrawphys(4), BASE, &user) != Ok(4)
            || user.get(0, 4) != b"usb-".to_vec()
        {
            return Err("HIDIOCGRAWUNIQ / PHYS wrong");
        }
        // HIDIOCREVOKE with a non-NULL argument is EINVAL and revokes nothing.
        if ioctl(&f, HIDIOCREVOKE, 1, &user) != Err(FsError::InvalidData)
            || ioctl(&f, HIDIOCGRDESCSIZE, BASE, &user) != Ok(0)
        {
            return Err("HIDIOCREVOKE(arg) not EINVAL, or it revoked");
        }
        if !fake.requests.lock().is_empty() || !fake.outputs.lock().is_empty() {
            return Err("an identity ioctl reached the transport");
        }
        Ok(())
    })
}
kernel_test_in!(
    "filesystem/hidraw",
    smoke_hidraw_ioctl_decode_and_errno_order
);

fn smoke_hidraw_revoke_is_per_open() -> TestResult {
    with_devices(|devs| {
        let (dev, fake) = register(yubikey_info());
        devs.push(dev.clone());
        let n = minor_of(&dev)?;
        let a = open(n)?;
        let b = open(n)?;
        let user = User::new(16);
        if ioctl(&a, HIDIOCREVOKE, 0, &user) != Ok(0) {
            return Err("HIDIOCREVOKE failed");
        }
        if a.poll_readiness() & (POLL_ERR | POLL_HUP) != POLL_ERR | POLL_HUP {
            return Err("revoked fd does not poll POLLERR|POLLHUP");
        }
        dev.report_in(&[1, 2]);
        if read(&a, 64) != Err(FsError::NoDevice)
            || write(&a, &[0, 1]) != Err(FsError::NoDevice)
            || ioctl(&a, HIDIOCGRDESCSIZE, BASE, &user) != Err(FsError::NoDevice)
            || ioctl(&a, 0x8004_4501, BASE, &user) != Err(FsError::NoDevice)
        {
            return Err("revoked fd is not ENODEV everywhere");
        }
        if !fake.outputs.lock().is_empty() {
            return Err("revoked fd's write reached the transport");
        }
        if read(&b, 64) != Ok(vec![1, 2]) || b.poll_readiness() & POLL_ERR != 0 {
            return Err("revoke leaked to another open");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_revoke_is_per_open);

// ── owner / mode / ACL ─────────────────────────────────────────────────

fn smoke_hidraw_owner_mode_and_acl_persist() -> TestResult {
    use crate::{
        acl_of_file, posix_access_ok_with_acl, AccessRequest, Accessor, AclEntry, AclType,
        FileOwner, PosixAcl, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_READ, ACL_USER, ACL_USER_OBJ,
        ACL_WRITE,
    };
    with_devices(|devs| {
        let (dev, _fake) = register(yubikey_info());
        devs.push(dev.clone());
        let n = minor_of(&dev)?;
        // udev's chown/chmod through one open survive its close.
        {
            let f = open(n)?;
            if now(f.set_owners(0, 104)) != Some(Ok(())) || now(f.set_perms(0o660)) != Some(Ok(()))
            {
                return Err("chown / chmod failed");
            }
        }
        let proto = lookup(n).ok_or("node vanished")?;
        if proto.owners() != (0, 104) || proto.stat().mode.perms != 0o660 {
            return Err("owner / mode did not persist on the node");
        }
        // The uaccess ACL logind writes for the session user.
        const ACL: &str = "system.posix_acl_access";
        if now(proto.get_xattr(ACL)) != Some(Err(FsError::NotFound)) {
            return Err("missing ACL is not ENODATA");
        }
        let rw = ACL_READ | ACL_WRITE;
        let acl = PosixAcl::from_entries(vec![
            AclEntry::tagged(ACL_USER_OBJ, rw),
            AclEntry {
                tag: ACL_USER,
                perm: rw,
                id: 1000,
            },
            AclEntry::tagged(ACL_GROUP_OBJ, 0),
            AclEntry::tagged(ACL_MASK, rw),
            AclEntry::tagged(ACL_OTHER, 0),
        ]);
        let blob = acl.to_xattr();
        if now(proto.set_xattr(ACL, &blob, 0)) != Some(Ok(())) {
            return Err("ACL setxattr failed");
        }
        // Visible to the next open's permission check.
        let opened = open(n)?;
        let stored = now(acl_of_file(&*opened, AclType::Access))
            .and_then(|r| r.ok())
            .flatten()
            .ok_or("open-time ACL lookup found nothing")?;
        let owner = FileOwner {
            uid: 0,
            gid: 0,
            perms: 0o600,
            is_dir: false,
        };
        let want = AccessRequest {
            read: true,
            write: true,
            exec: false,
        };
        if !posix_access_ok_with_acl(owner, &Accessor::new(1000, 1000), want, Some(&stored))
            || posix_access_ok_with_acl(owner, &Accessor::new(1001, 1001), want, Some(&stored))
        {
            return Err("ACL does not grant exactly the session user");
        }
        let mut names = ACL.as_bytes().to_vec();
        names.push(0);
        if now(opened.list_xattr()) != Some(Ok(names))
            || now(opened.set_xattr("user.x", b"1", 0)) != Some(Err(FsError::Unsupported))
            || now(opened.get_xattr("user.x")) != Some(Err(FsError::NotFound))
            || now(opened.remove_xattr(ACL)) != Some(Ok(()))
            || now(proto.remove_xattr(ACL)) != Some(Err(FsError::NotFound))
            || now(proto.list_xattr()) != Some(Ok(Vec::new()))
        {
            return Err("xattr list / set / remove semantics wrong");
        }
        Ok(())
    })
}
kernel_test_in!("filesystem/hidraw", smoke_hidraw_owner_mode_and_acl_persist);

fn smoke_hidraw_minors_exhaust_at_max_devices() -> TestResult {
    with_devices(|devs| {
        // Fill every free minor; the first device past the table still
        // gets its HID device in sysfs, without a hidraw node.
        let mut spare = None;
        for _ in 0..=crate::hidraw::HIDRAW_MAX_DEVICES {
            let (dev, _fake) = register(yubikey_info());
            devs.push(dev.clone());
            if node_of(&dev).is_none() {
                spare = Some(dev);
                break;
            }
        }
        let spare = spare.ok_or("more than HIDRAW_MAX_DEVICES minors handed out")?;
        let hid = walk(&format!("{YUBIKEY_PARENT}/{}", spare.sysfs_name()))
            .ok_or("minor-less device missing from sysfs")?;
        if hid.get_child("hidraw").is_some() || !hid.has_attr("uevent") {
            return Err("minor-less device published a hidraw child");
        }
        let with_minor = devs.iter().filter(|d| node_of(d).is_some()).count();
        if with_minor > crate::hidraw::HIDRAW_MAX_DEVICES {
            return Err("minor table overflowed");
        }
        // Releasing one makes room again.
        let first = devs.remove(0);
        hid_device::unregister(&first);
        let (dev, _fake) = register(yubikey_info());
        devs.push(dev.clone());
        if node_of(&dev).is_none() {
            return Err("freed minor not reusable");
        }
        Ok(())
    })
}
kernel_test_in!(
    "filesystem/hidraw",
    smoke_hidraw_minors_exhaust_at_max_devices
);
