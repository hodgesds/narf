//! usbfs smokes: every ioctl through `FileOps::ioctl_user`, over a modelled
//! controller pipe and a modelled user address space. Errnos and their
//! check order follow `drivers/usb/core/devio.c`.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;

use narf_filesystem::{FileOps, FsError, IoctlContext, POLL_ERR, POLL_HUP};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::*;
use crate::device::UsbError;
use crate::usbdev::{self, Owner, UsbDevSpec};
use crate::xhci::{EndpointConfig, PortSpeed};

// ── The modelled controller ─────────────────────────────────────────────

#[derive(Default)]
struct Model {
    configured: Vec<u8>,
    deconfigured: Vec<u8>,
    controls: Vec<[u8; 8]>,
    /// `(endpoint, payload)` of every OUT TD.
    outs: Vec<(u8, Vec<u8>)>,
    /// Device responses per IN endpoint, one transfer each.
    responses: Vec<(u8, VecDeque<Vec<u8>>)>,
    /// `(receipt, endpoint, len, payload)` of every posted TD.
    posted: Vec<(u64, u8, usize, Vec<u8>)>,
    next: u64,
    stall_next: Vec<u8>,
    halted: Vec<u8>,
    recovered: Vec<u8>,
    control_reply: Vec<u8>,
    control_stall: bool,
}

struct FakePipe(IrqSafeSpinLock<Model>);

impl FakePipe {
    fn new() -> Arc<Self> {
        Arc::new(Self(IrqSafeSpinLock::new(Model::default())))
    }

    fn respond(&self, ep: u8, bytes: &[u8]) {
        let mut m = self.0.lock();
        if let Some((_, q)) = m.responses.iter_mut().find(|(e, _)| *e == ep) {
            q.push_back(bytes.to_vec());
        } else {
            let mut q = VecDeque::new();
            q.push_back(bytes.to_vec());
            m.responses.push((ep, q));
        }
    }
}

#[async_trait]
impl Pipe for FakePipe {
    fn begin(&self, ep: u8, _xfer: Xfer, len: usize, data: &[u8]) -> Result<u64, UsbError> {
        let mut m = self.0.lock();
        m.next += 1;
        let id = m.next;
        m.posted.push((id, ep, len, data.to_vec()));
        Ok(id)
    }

    fn poll(&self, receipt: u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let mut m = self.0.lock();
        let (_, ep, len, payload) = m
            .posted
            .iter()
            .find(|p| p.0 == receipt)
            .cloned()
            .ok_or(UsbError::StaleSlot)?;
        if let Some(i) = m.stall_next.iter().position(|&e| e == ep) {
            m.stall_next.remove(i);
            m.halted.push(ep);
            return Err(UsbError::Stall);
        }
        if ep & 0x80 == 0 {
            m.outs.push((ep, payload));
            return Ok(Some(len));
        }
        let Some((_, q)) = m.responses.iter_mut().find(|(e, _)| *e == ep) else {
            return Ok(None);
        };
        let Some(front) = q.front_mut() else {
            return Ok(None);
        };
        let n = front.len().min(len);
        out[..n].copy_from_slice(&front[..n]);
        if front.len() > len {
            front.drain(..len);
        } else {
            q.pop_front();
        }
        Ok(Some(n))
    }

    async fn stop(&self, receipt: u64) -> Result<(), UsbError> {
        self.0.lock().posted.retain(|p| p.0 != receipt);
        Ok(())
    }

    fn forget(&self, receipt: u64) {
        self.0.lock().posted.retain(|p| p.0 != receipt);
    }

    async fn control(&self, setup: [u8; 8], data: &mut [u8]) -> Result<usize, UsbError> {
        let mut m = self.0.lock();
        m.controls.push(setup);
        if m.control_stall {
            return Err(UsbError::Stall);
        }
        if setup[0] & 0x80 != 0 {
            let n = m.control_reply.len().min(data.len());
            data[..n].copy_from_slice(&m.control_reply[..n]);
            Ok(n)
        } else {
            Ok(data.len())
        }
    }

    fn configured(&self, ep: u8) -> bool {
        self.0.lock().configured.contains(&ep)
    }

    async fn configure(&self, eps: &[EndpointConfig]) -> Result<(), UsbError> {
        let mut m = self.0.lock();
        if eps.iter().any(|e| m.configured.contains(&e.ep_addr)) {
            return Err(UsbError::HardwareError(0xFE));
        }
        m.configured.extend(eps.iter().map(|e| e.ep_addr));
        Ok(())
    }

    async fn deconfigure(&self, eps: &[u8]) -> Result<(), UsbError> {
        let mut m = self.0.lock();
        m.configured.retain(|e| !eps.contains(e));
        m.deconfigured.extend_from_slice(eps);
        Ok(())
    }

    fn halted(&self, ep: u8) -> bool {
        self.0.lock().halted.contains(&ep)
    }

    async fn recover(&self, ep: u8) -> Result<(), UsbError> {
        let mut m = self.0.lock();
        m.halted.retain(|&e| e != ep);
        m.recovered.push(ep);
        Ok(())
    }
}

// ── The modelled user address space ─────────────────────────────────────

const BASE: u64 = 0x10_0000;

struct Mem(IrqSafeSpinLock<Vec<u8>>);

impl Mem {
    fn new() -> Self {
        Self(IrqSafeSpinLock::new(alloc::vec![0u8; 0x4000]))
    }

    fn poke(&self, at: u64, bytes: &[u8]) {
        let o = (at - BASE) as usize;
        self.0.lock()[o..o + bytes.len()].copy_from_slice(bytes);
    }

    fn peek(&self, at: u64, len: usize) -> Vec<u8> {
        let o = (at - BASE) as usize;
        self.0.lock()[o..o + len].to_vec()
    }

    fn u32_at(&self, at: u64) -> u32 {
        let b = self.peek(at, 4);
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn i32_at(&self, at: u64) -> i32 {
        self.u32_at(at) as i32
    }
}

impl IoctlContext for Mem {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        let m = self.0.lock();
        let o = address.checked_sub(BASE).ok_or(FsError::BadAddress)? as usize;
        let src = m.get(o..o + destination.len()).ok_or(FsError::BadAddress)?;
        destination.copy_from_slice(src);
        Ok(())
    }

    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        let mut m = self.0.lock();
        let o = address.checked_sub(BASE).ok_or(FsError::BadAddress)? as usize;
        let dst = m.get_mut(o..o + source.len()).ok_or(FsError::BadAddress)?;
        dst.copy_from_slice(source);
        Ok(())
    }

    fn nonblocking(&self) -> bool {
        false
    }
}

// ── Fixture ─────────────────────────────────────────────────────────────

/// A composite device: HID keyboard (iface 0, held by usbhid), a vendor
/// interface with two settings (iface 1) and a CCID reader (iface 2).
fn config() -> Vec<u8> {
    let mut c = alloc::vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
    c.extend_from_slice(&[9, 4, 0, 0, 1, 3, 1, 1, 0]);
    c.extend_from_slice(&[7, 5, 0x81, 3, 8, 0, 10]);
    c.extend_from_slice(&[9, 4, 1, 0, 2, 0xff, 0, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x82, 2, 64, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x02, 2, 64, 0, 0]);
    c.extend_from_slice(&[9, 4, 1, 1, 1, 0xff, 0, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x83, 3, 16, 0, 4]);
    c.extend_from_slice(&[9, 4, 2, 0, 3, 0x0b, 0, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x84, 2, 64, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x04, 2, 64, 0, 0]);
    c.extend_from_slice(&[7, 5, 0x85, 3, 8, 0, 16]);
    let total = c.len() as u16;
    c[2..4].copy_from_slice(&total.to_le_bytes());
    c
}

fn device() -> Arc<UsbDev> {
    let mut d = [0u8; 18];
    d[0] = 18;
    d[1] = 1;
    d[2..4].copy_from_slice(&0x0200u16.to_le_bytes());
    d[7] = 64;
    d[8..10].copy_from_slice(&0x1050u16.to_le_bytes());
    d[10..12].copy_from_slice(&0x0407u16.to_le_bytes());
    d[17] = 1;
    let dev = usbdev::__insert_for_test(UsbDevSpec {
        controller: 6,
        slot: 4,
        busnum: 3,
        devnum: 5,
        root_port: 1,
        route: 0x3,
        devpath: String::from("1.3"),
        speed: PortSpeed::High,
        descriptor: d,
        configs: alloc::vec![config()],
        config: 1,
    });
    let _ = dev.claim(0, Owner::Driver("usbhid"));
    dev
}

struct Fx {
    dev: Arc<UsbDev>,
    pipe: Arc<FakePipe>,
    file: Arc<UsbfsFile>,
    mem: Mem,
}

fn reset() {
    usbdev::__reset_for_test();
    __reset_for_test();
}

fn fixture() -> Fx {
    reset();
    let dev = device();
    let pipe = FakePipe::new();
    let file = __open_for_test(
        Target::Device(dev.clone()),
        Some(pipe.clone() as Arc<dyn Pipe>),
        true,
    );
    Fx {
        dev,
        pipe,
        file,
        mem: Mem::new(),
    }
}

/// Drive an ioctl or read to completion. `block_on_spin`, not `block_on`:
/// the synchronous transfers (CONTROL/BULK) poll their URB between
/// `sleep_ms(1)` waits until their timeout, and under kernel-test the BSP
/// keeps its timer masked, so a `block_on` waiting for the timer IRQ never
/// returns. `block_on_spin` runs the hrtimer softirq itself (as
/// `hub_tests.rs` does for the same reason).
fn run<F: core::future::Future>(f: F) -> F::Output {
    narf_scheduler::block_on_spin(f)
}

impl Fx {
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64, FsError> {
        run(self.file.ioctl_user(cmd, arg, &self.mem))
    }

    fn ioctl_on(&self, file: &Arc<UsbfsFile>, cmd: u32, arg: u64) -> Result<u64, FsError> {
        run(file.ioctl_user(cmd, arg, &self.mem))
    }

    /// An ioctl taking an `unsigned int` argument.
    fn ioctl_u32(&self, cmd: u32, value: u32) -> Result<u64, FsError> {
        self.mem.poke(BASE, &value.to_le_bytes());
        self.ioctl(cmd, BASE)
    }

    fn open_another(&self) -> Arc<UsbfsFile> {
        __open_for_test(
            Target::Device(self.dev.clone()),
            Some(self.pipe.clone() as Arc<dyn Pipe>),
            true,
        )
    }
}

const ARG: u64 = BASE;
const URB: u64 = BASE + 0x100;
const DATA: u64 = BASE + 0x1000;
const OUT_PTR: u64 = BASE + 0x80;

/// Write a `struct usbdevfs_urb` at [`URB`].
fn urb(fx: &Fx, kind: u8, ep: u8, flags: u32, buffer: u64, len: u32) {
    let mut u = [0u8; 56];
    u[0] = kind;
    u[1] = ep;
    u[8..12].copy_from_slice(&flags.to_le_bytes());
    u[16..24].copy_from_slice(&buffer.to_le_bytes());
    u[24..28].copy_from_slice(&len.to_le_bytes());
    u[36..40].copy_from_slice(&1u32.to_le_bytes());
    fx.mem.poke(URB, &u);
}

/// Reap one URB without blocking: `(status, actual)`.
fn reap(fx: &Fx) -> Result<(i32, i32), FsError> {
    fx.ioctl(USBDEVFS_REAPURBNDELAY, OUT_PTR)?;
    let addr = fx.mem.peek(OUT_PTR, 8);
    if u64::from_le_bytes(addr.try_into().unwrap_or([0; 8])) != URB {
        return Err(FsError::InvalidData);
    }
    Ok((fx.mem.i32_at(URB + 4), fx.mem.i32_at(URB + 28)))
}

fn bulk(fx: &Fx, ep: u32, len: u32, timeout: u32) -> Result<u64, FsError> {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&ep.to_le_bytes());
    b[4..8].copy_from_slice(&len.to_le_bytes());
    b[8..12].copy_from_slice(&timeout.to_le_bytes());
    b[16..24].copy_from_slice(&DATA.to_le_bytes());
    fx.mem.poke(ARG, &b);
    fx.ioctl(USBDEVFS_BULK, ARG)
}

fn control(fx: &Fx, rt: u8, req: u8, value: u16, index: u16, len: u16) -> Result<u64, FsError> {
    let mut b = [0u8; 24];
    b[0] = rt;
    b[1] = req;
    b[2..4].copy_from_slice(&value.to_le_bytes());
    b[4..6].copy_from_slice(&index.to_le_bytes());
    b[6..8].copy_from_slice(&len.to_le_bytes());
    b[8..12].copy_from_slice(&1000u32.to_le_bytes());
    b[16..24].copy_from_slice(&DATA.to_le_bytes());
    fx.mem.poke(ARG, &b);
    fx.ioctl(USBDEVFS_CONTROL, ARG)
}

/// A `struct usbdevfs_ioctl` at [`ARG`].
fn sub_ioctl(fx: &Fx, file: &Arc<UsbfsFile>, ifno: i32, code: u32) -> Result<u64, FsError> {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&ifno.to_le_bytes());
    b[4..8].copy_from_slice(&code.to_le_bytes());
    b[8..16].copy_from_slice(&DATA.to_le_bytes());
    fx.mem.poke(ARG, &b);
    fx.ioctl_on(file, USBDEVFS_IOCTL, ARG)
}

fn verdict(r: Result<(), &'static str>) -> TestResult {
    reset();
    match r {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}

// ── read ────────────────────────────────────────────────────────────────

fn smoke_usbfs_read_descriptors() -> TestResult {
    let fx = fixture();
    let r = (|| {
        let mut buf = [0u8; 256];
        let n = run(fx.file.read(0, &mut buf)).map_err(|_| "read")?;
        let cfg = config();
        if n != 18 + cfg.len() || buf[..18] != fx.dev.descriptor || buf[18..n] != cfg[..] {
            return Err("read is the device descriptor, then every configuration");
        }
        let mut tail = [0u8; 4];
        let n = run(fx.file.read(20, &mut tail)).map_err(|_| "read")?;
        if n != 4 || tail[..] != cfg[2..6] {
            return Err("a read at an offset continues inside the configuration");
        }
        let n = run(fx.file.read(18 + cfg.len() as u64, &mut tail))
            .map_err(|_| "read")?;
        if n != 0 {
            return Err("a read past the last configuration is EOF");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_read_descriptors);

// ── claims ──────────────────────────────────────────────────────────────

fn smoke_usbfs_claim_release_getdriver() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 2)
            .map_err(|_| "claim a free interface")?;
        if !fx.pipe.configured(0x84) || !fx.pipe.configured(0x04) || !fx.pipe.configured(0x85) {
            return Err("claiming programs the interface's endpoints");
        }
        if fx.dev.owner(2) != Some(Owner::File(fx.file.shared().id)) {
            return Err("the registry records the file as owner");
        }
        if !matches!(fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 0), Err(FsError::Busy)) {
            return Err("a driver-held interface is EBUSY");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 9),
            Err(FsError::NotFound)
        ) {
            return Err("a missing interface is ENOENT");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 64),
            Err(FsError::InvalidData)
        ) {
            return Err("ifnum >= 8 * sizeof(unsigned long) is EINVAL");
        }
        let getdriver = |ifnum: u32| {
            let mut gd = [0u8; 260];
            gd[0..4].copy_from_slice(&ifnum.to_le_bytes());
            fx.mem.poke(ARG, &gd);
            fx.ioctl(USBDEVFS_GETDRIVER, ARG)
                .map(|_| String::from_utf8_lossy(c_name(&fx.mem.peek(ARG + 4, 256))).into_owned())
        };
        if getdriver(2).as_deref() != Ok("usbfs") || getdriver(0).as_deref() != Ok("usbhid") {
            return Err("GETDRIVER names usbfs for a file's claim, the driver otherwise");
        }
        if !matches!(getdriver(1), Err(FsError::NoData)) {
            return Err("GETDRIVER on an unbound interface is ENODATA");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_RELEASEINTERFACE, 1),
            Err(FsError::InvalidData)
        ) {
            return Err("releasing an unclaimed interface is EINVAL");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_RELEASEINTERFACE, 9),
            Err(FsError::NotFound)
        ) {
            return Err("releasing a missing interface is ENOENT");
        }
        fx.ioctl_u32(USBDEVFS_RELEASEINTERFACE, 2)
            .map_err(|_| "release")?;
        if fx.dev.owner(2).is_some() {
            return Err("release clears the registry claim");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_claim_release_getdriver);

fn smoke_usbfs_readonly_is_eperm() -> TestResult {
    reset();
    let dev = device();
    let ro = __open_for_test(
        Target::Device(dev),
        Some(FakePipe::new() as Arc<dyn Pipe>),
        false,
    );
    let mem = Mem::new();
    mem.poke(BASE, &2u32.to_le_bytes());
    let r = (|| {
        for cmd in [
            USBDEVFS_CLAIMINTERFACE,
            USBDEVFS_REAPURBNDELAY,
            USBDEVFS_GET_CAPABILITIES,
        ] {
            let got = run(ro.ioctl_user(cmd, BASE, &mem));
            if !matches!(got, Err(FsError::OperationNotPermitted)) {
                return Err("an fd without FMODE_WRITE gets EPERM before anything else");
            }
        }
        Ok(())
    })();
    drop(ro);
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_readonly_is_eperm);

// ── bulk and control ────────────────────────────────────────────────────

fn smoke_usbfs_bulk_split_short_and_errors() -> TestResult {
    let fx = fixture();
    let r = (|| {
        let response: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        fx.pipe.respond(0x84, &response);
        let n = bulk(&fx, 0x84, 8192, 0).map_err(|_| "bulk IN")?;
        if n != 5000 || fx.mem.peek(DATA, 5000) != response {
            return Err("a 5000-byte transfer arrives across page TDs, ended by the short one");
        }
        let payload: Vec<u8> = (0..4100u32).map(|i| (i * 7) as u8).collect();
        fx.mem.poke(DATA, &payload);
        if bulk(&fx, 0x04, 4100, 0) != Ok(4100) {
            return Err("bulk OUT returns the bytes sent");
        }
        let outs = fx.pipe.0.lock().outs.clone();
        if outs.len() != 2 || outs[0].1.len() != 4096 || outs[1].1 != payload[4096..] {
            return Err("an OUT transfer is split into page TDs, in order");
        }
        if !matches!(bulk(&fx, 0x06, 8, 0), Err(FsError::NotFound)) {
            return Err("an endpoint no interface has is ENOENT");
        }
        if !matches!(bulk(&fx, 0x10, 8, 0), Err(FsError::InvalidData)) {
            return Err("endpoint bits outside 0x8f are EINVAL");
        }
        if !matches!(bulk(&fx, 0x81, 8, 0), Err(FsError::Busy)) {
            return Err("an endpoint of a driver-held interface is EBUSY");
        }
        if !matches!(bulk(&fx, 0x83, 8, 0), Err(FsError::InvalidData)) {
            return Err("an endpoint not in the current setting is EINVAL");
        }
        if bulk(&fx, 0x84, 64, 5) != Err(FsError::TransferTimedOut) {
            return Err("a bulk that sees no data within its timeout is ETIMEDOUT");
        }
        if !fx.pipe.0.lock().posted.is_empty() {
            return Err("the timed-out TD is stopped");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_bulk_split_short_and_errors);

fn smoke_usbfs_control() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.pipe.0.lock().control_reply = alloc::vec![0xde, 0xad, 0xbe, 0xef, 0x55];
        if control(&fx, 0xc0, 0x01, 0, 0, 4) != Ok(4)
            || fx.mem.peek(DATA, 4) != [0xde, 0xad, 0xbe, 0xef]
        {
            return Err("a vendor IN request returns its data");
        }
        if fx.pipe.0.lock().controls.last() != Some(&[0xc0, 0x01, 0, 0, 0, 0, 4, 0]) {
            return Err("the setup packet goes out as given");
        }
        if !matches!(
            control(&fx, 0xc0, 0x01, 0, 0, 4097),
            Err(FsError::InvalidData)
        ) {
            return Err("wLength > PAGE_SIZE is EINVAL");
        }
        if !matches!(control(&fx, 0x81, 0x00, 0, 0, 2), Err(FsError::Busy)) {
            return Err("an interface-recipient request to a driver's interface is EBUSY");
        }
        if !matches!(control(&fx, 0x82, 0x00, 0, 0x81, 2), Err(FsError::Busy)) {
            return Err("an endpoint-recipient request checks the endpoint's interface");
        }
        if control(&fx, 0x82, 0x00, 0, 0x00, 2).is_err() {
            return Err("EP0 as recipient needs no claim");
        }
        fx.pipe.0.lock().control_stall = true;
        if !matches!(
            control(&fx, 0x80, 0x06, 0x0100, 0, 18),
            Err(FsError::Stalled)
        ) {
            return Err("a stalled request is EPIPE");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_control);

// ── URBs ────────────────────────────────────────────────────────────────

fn smoke_usbfs_submit_reap_discard() -> TestResult {
    let fx = fixture();
    let baseline = __memory_used_for_test();
    let r = (|| {
        urb(&fx, URB_TYPE_BULK, 0x84, 0, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        if !matches!(reap(&fx), Err(FsError::WouldBlock)) {
            return Err("REAPURBNDELAY with nothing complete is EAGAIN");
        }
        fx.pipe.respond(0x84, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        if reap(&fx) != Ok((0, 10)) || fx.mem.peek(DATA, 10) != [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
            return Err("a reaped URB reports status, length and its data");
        }
        urb(&fx, URB_TYPE_BULK, 0x84, URB_SHORT_NOT_OK, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        fx.pipe.respond(0x84, &[7; 10]);
        if reap(&fx) != Ok((-121, 10)) {
            return Err("a short IN URB with SHORT_NOT_OK completes -EREMOTEIO");
        }
        urb(&fx, URB_TYPE_BULK, 0x84, 0, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        fx.ioctl(USBDEVFS_DISCARDURB, URB).map_err(|_| "discard")?;
        if reap(&fx).map(|r| r.0) != Ok(-2) {
            return Err("a discarded URB is reaped with -ENOENT");
        }
        if !matches!(
            fx.ioctl(USBDEVFS_DISCARDURB, URB),
            Err(FsError::InvalidData)
        ) {
            return Err("discarding a URB that is not pending is EINVAL");
        }
        urb(&fx, URB_TYPE_BULK, 0x84, 0x08, DATA, 64);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::InvalidData)) {
            return Err("an unknown flag is EINVAL");
        }
        urb(&fx, URB_TYPE_BULK, 0x84, 0, 0, 64);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::InvalidData)) {
            return Err("a NULL buffer with a length is EINVAL");
        }
        urb(&fx, URB_TYPE_INTERRUPT, 0x84, 0, DATA, 64);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::InvalidData)) {
            return Err("an INTERRUPT URB on a bulk endpoint is EINVAL");
        }
        urb(&fx, URB_TYPE_ISO, 0x84, 0, DATA, 64);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::InvalidData)) {
            return Err("an ISO URB on a bulk endpoint is EINVAL");
        }
        urb(&fx, URB_TYPE_CONTROL, 0, 0, DATA, 4);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::InvalidData)) {
            return Err("a control URB shorter than its setup packet is EINVAL");
        }
        urb(&fx, URB_TYPE_BULK, 0x86, 0, DATA, 64);
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::NotFound)) {
            return Err("an endpoint no interface has is ENOENT");
        }
        // A control URB: setup packet, then the data stage.
        fx.pipe.0.lock().control_reply = alloc::vec![9, 8, 7];
        fx.mem.poke(DATA, &[0xc0, 0x02, 0, 0, 0, 0, 3, 0]);
        urb(&fx, URB_TYPE_CONTROL, 0, 0, DATA, 11);
        fx.ioctl(USBDEVFS_SUBMITURB, URB)
            .map_err(|_| "control submit")?;
        if reap(&fx) != Ok((0, 3)) || fx.mem.peek(DATA + 8, 3) != [9, 8, 7] {
            return Err("a control URB's data lands after its setup packet");
        }
        if __memory_used_for_test() != baseline {
            return Err("reaped URBs return their charge to the usbfs budget");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_submit_reap_discard);

fn smoke_usbfs_stall_recovers_host_side() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.pipe.0.lock().stall_next.push(0x84);
        urb(&fx, URB_TYPE_BULK, 0x84, 0, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        if reap(&fx).map(|r| r.0) != Ok(-32) {
            return Err("a stalled URB completes -EPIPE");
        }
        if fx.pipe.0.lock().recovered != [0x84] {
            return Err("the halted endpoint's host side is recovered");
        }
        fx.ioctl_u32(USBDEVFS_CLEAR_HALT, 0x84)
            .map_err(|_| "clear halt")?;
        if fx.pipe.0.lock().controls.last() != Some(&[0x02, 0x01, 0, 0, 0x84, 0, 0, 0]) {
            return Err("CLEAR_HALT sends CLEAR_FEATURE(ENDPOINT_HALT) to the endpoint");
        }
        if !fx.pipe.configured(0x84) {
            return Err("the endpoint is reprogrammed at DATA0 after CLEAR_HALT");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLEAR_HALT, 0x06),
            Err(FsError::NotFound)
        ) {
            return Err("CLEAR_HALT on a missing endpoint is ENOENT");
        }
        fx.ioctl_u32(USBDEVFS_RESETEP, 0x04)
            .map_err(|_| "resetep")?;
        if !matches!(fx.ioctl_u32(USBDEVFS_RESETEP, 0x81), Err(FsError::Busy)) {
            return Err("RESETEP on a driver's endpoint is EBUSY");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_stall_recovers_host_side);

fn smoke_usbfs_zero_packet_and_continuation() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.mem.poke(DATA, &[0x5a; 64]);
        urb(&fx, URB_TYPE_BULK, 0x04, URB_ZERO_PACKET, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        if reap(&fx) != Ok((0, 64)) {
            return Err("a ZERO_PACKET OUT URB completes with its length");
        }
        let lens: Vec<usize> = fx.pipe.0.lock().outs.iter().map(|o| o.1.len()).collect();
        if lens != [64, 0] {
            return Err("ZERO_PACKET adds a zero-length packet after a full one");
        }
        // A failed bulk transfer unlinks the continuation URBs queued
        // behind it and refuses more until a new transfer starts.
        fx.pipe.0.lock().stall_next.push(0x04);
        urb(&fx, URB_TYPE_BULK, 0x04, 0, DATA, 8);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "first")?;
        let first = reap(&fx).map(|r| r.0);
        urb(&fx, URB_TYPE_BULK, 0x04, URB_BULK_CONTINUATION, DATA, 8);
        if first != Ok(-32) {
            return Err("the failing transfer completes -EPIPE");
        }
        if !matches!(fx.ioctl(USBDEVFS_SUBMITURB, URB), Err(FsError::RemoteIo)) {
            return Err("a continuation URB after a failed transfer is EREMOTEIO");
        }
        urb(&fx, URB_TYPE_BULK, 0x04, 0, DATA, 8);
        fx.ioctl(USBDEVFS_SUBMITURB, URB)
            .map_err(|_| "a new transfer re-enables")?;
        if reap(&fx) != Ok((0, 8)) {
            return Err("a new transfer moves data again");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!(
    "drivers/usb/usbfs",
    smoke_usbfs_zero_packet_and_continuation
);

// ── device information ──────────────────────────────────────────────────

fn smoke_usbfs_capabilities_speed_conninfo() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.ioctl(USBDEVFS_GET_CAPABILITIES, ARG)
            .map_err(|_| "caps")?;
        if fx.mem.u32_at(ARG)
            != CAP_ZERO_PACKET
                | CAP_NO_PACKET_SIZE_LIM
                | CAP_REAP_AFTER_DISCONNECT
                | CAP_DROP_PRIVILEGES
                | CAP_CONNINFO_EX
        {
            return Err("GET_CAPABILITIES advertises what is implemented, no MMAP or SUSPEND");
        }
        if fx.ioctl(USBDEVFS_GET_SPEED, 0) != Ok(3) {
            return Err("GET_SPEED returns USB_SPEED_HIGH for a high-speed device");
        }
        fx.ioctl(USBDEVFS_CONNECTINFO, ARG)
            .map_err(|_| "connectinfo")?;
        if fx.mem.peek(ARG, 8) != [5, 0, 0, 0, 0, 0, 0, 0] {
            return Err("CONNECTINFO is devnum and the low-speed flag");
        }
        fx.mem.poke(ARG, &[0xee; 24]);
        fx.ioctl(USBDEVFS_CONNINFO_EX_0 | (24 << 16), ARG)
            .map_err(|_| "conninfo_ex")?;
        let ci = fx.mem.peek(ARG, 24);
        if ci[0..16] != [24, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0]
            || ci[16] != 2
            || ci[17..19] != [1, 3]
        {
            return Err("CONNINFO_EX: size, bus, devnum, speed and the root-first port chain");
        }
        fx.mem.poke(ARG, &[0xee; 24]);
        fx.ioctl(USBDEVFS_CONNINFO_EX_0 | (4 << 16), ARG)
            .map_err(|_| "short conninfo_ex")?;
        if fx.mem.peek(ARG, 8) != [24, 0, 0, 0, 0xee, 0xee, 0xee, 0xee] {
            return Err("CONNINFO_EX copies min(sizeof, size) bytes");
        }
        if !matches!(
            fx.ioctl(USBDEVFS_CONNINFO_EX_0 | (2 << 16), ARG),
            Err(FsError::InvalidData)
        ) {
            return Err("CONNINFO_EX smaller than its size field is EINVAL");
        }
        if !matches!(fx.ioctl(0x0000_5599, ARG), Err(FsError::NotATty)) {
            return Err("an unknown usbfs ioctl is ENOTTY");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_capabilities_speed_conninfo);

// ── settings ────────────────────────────────────────────────────────────

fn smoke_usbfs_setinterface() -> TestResult {
    let fx = fixture();
    let r = (|| {
        let set = |iface: u32, alt: u32| {
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&iface.to_le_bytes());
            b[4..8].copy_from_slice(&alt.to_le_bytes());
            fx.mem.poke(ARG, &b);
            fx.ioctl(USBDEVFS_SETINTERFACE, ARG)
        };
        set(1, 1).map_err(|_| "set alt 1")?;
        {
            let m = fx.pipe.0.lock();
            if !m.deconfigured.contains(&0x82) || !m.deconfigured.contains(&0x02) {
                return Err("SETINTERFACE drops the old setting's endpoints");
            }
            if !m.configured.contains(&0x83) || m.configured.contains(&0x82) {
                return Err("SETINTERFACE programs the new setting's endpoints");
            }
            if m.controls.last() != Some(&[0x01, 0x0b, 1, 0, 1, 0, 0, 0]) {
                return Err("SET_INTERFACE(alt 1, iface 1) is sent");
            }
        }
        if fx.dev.alt_setting(1) != 1 {
            return Err("the registry records the current setting");
        }
        if !matches!(set(1, 7), Err(FsError::InvalidData)) {
            return Err("a missing alternate setting is EINVAL");
        }
        if !matches!(set(9, 0), Err(FsError::NotFound)) {
            return Err("SETINTERFACE claims first: a missing interface is ENOENT");
        }
        if !matches!(set(0, 0), Err(FsError::Busy)) {
            return Err("SETINTERFACE on a driver's interface is EBUSY");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_setinterface);

fn smoke_usbfs_setconfiguration() -> TestResult {
    let fx = fixture();
    let r = (|| {
        if !matches!(
            fx.ioctl_u32(USBDEVFS_SETCONFIGURATION, 1),
            Err(FsError::Busy)
        ) {
            return Err("SETCONFIGURATION while a driver holds an interface is EBUSY");
        }
        fx.dev.release(0, &Owner::Driver("usbhid"));
        if !matches!(
            fx.ioctl_u32(USBDEVFS_SETCONFIGURATION, 5),
            Err(FsError::InvalidData)
        ) {
            return Err("an unknown configuration value is EINVAL");
        }
        fx.ioctl_u32(USBDEVFS_SETCONFIGURATION, 1)
            .map_err(|_| "set config 1")?;
        if fx.pipe.0.lock().controls.last() != Some(&[0x00, 0x09, 1, 0, 0, 0, 0, 0]) {
            return Err("SET_CONFIGURATION(1) is sent");
        }
        fx.ioctl_u32(USBDEVFS_SETCONFIGURATION, u32::MAX)
            .map_err(|_| "unconfigure")?;
        if fx.dev.config_value() != 0 {
            return Err("-1 unconfigures the device");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 2),
            Err(FsError::NotFound)
        ) {
            return Err("an unconfigured device has no interfaces to claim");
        }
        if !matches!(bulk(&fx, 0x84, 8, 0), Err(FsError::NoSuchProcess)) {
            return Err("findintfep without a configuration is ESRCH");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_setconfiguration);

// ── privileges, driver detach ───────────────────────────────────────────

fn smoke_usbfs_drop_privileges() -> TestResult {
    let fx = fixture();
    let r = (|| {
        fx.ioctl_u32(USBDEVFS_DROP_PRIVILEGES, 1 << 2)
            .map_err(|_| "drop")?;
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 1),
            Err(FsError::PermissionDenied)
        ) {
            return Err("after DROP_PRIVILEGES an interface outside the mask is EACCES");
        }
        fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 2)
            .map_err(|_| "allowed claim")?;
        if !matches!(
            sub_ioctl(&fx, &fx.file, 1, USBDEVFS_DISCONNECT),
            Err(FsError::PermissionDenied)
        ) {
            return Err("USBDEVFS_IOCTL after DROP_PRIVILEGES is EACCES");
        }
        let mut dc = [0u8; 264];
        dc[0] = 0; // the usbhid interface
        fx.mem.poke(ARG, &dc);
        if !matches!(
            fx.ioctl(USBDEVFS_DISCONNECT_CLAIM, ARG),
            Err(FsError::PermissionDenied)
        ) {
            return Err("DISCONNECT_CLAIM of a driver after DROP_PRIVILEGES is EACCES");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_drop_privileges);

fn smoke_usbfs_disconnect_connect_and_claim() -> TestResult {
    let fx = fixture();
    let other = fx.open_another();
    let r = (|| {
        fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 2)
            .map_err(|_| "claim")?;
        sub_ioctl(&fx, &other, 2, USBDEVFS_DISCONNECT).map_err(|_| "disconnect another file")?;
        if fx.dev.owner(2).is_some() || fx.file.shared().state.lock().ifclaimed != 0 {
            return Err("DISCONNECT of usbfs takes the interface from the other file");
        }
        if !matches!(
            sub_ioctl(&fx, &other, 1, USBDEVFS_DISCONNECT),
            Err(FsError::NoData)
        ) {
            return Err("DISCONNECT with no driver bound is ENODATA");
        }
        if !matches!(
            sub_ioctl(&fx, &other, 0, USBDEVFS_CONNECT),
            Err(FsError::Busy)
        ) {
            return Err("CONNECT with a driver bound is EBUSY");
        }
        if !matches!(
            sub_ioctl(&fx, &other, 0, 0x4004_4801),
            Err(FsError::NotATty)
        ) {
            return Err("a driver ioctl to usbhid, which has none, is ENOTTY");
        }
        if !matches!(
            sub_ioctl(&fx, &other, 9, USBDEVFS_DISCONNECT),
            Err(FsError::InvalidData)
        ) {
            return Err("USBDEVFS_IOCTL on a missing interface is EINVAL");
        }
        // LINUX-GAP: usbhid's device-wide keyboard binding cannot be
        // released per interface yet, so DISCONNECT reports EBUSY.
        if !matches!(
            sub_ioctl(&fx, &other, 0, USBDEVFS_DISCONNECT),
            Err(FsError::Busy)
        ) {
            return Err("a device-wide kernel binding is EBUSY (documented gap)");
        }
        let claim = |iface: u32, flags: u32, driver: &[u8]| {
            let mut dc = [0u8; 264];
            dc[0..4].copy_from_slice(&iface.to_le_bytes());
            dc[4..8].copy_from_slice(&flags.to_le_bytes());
            dc[8..8 + driver.len()].copy_from_slice(driver);
            fx.mem.poke(ARG, &dc);
            fx.ioctl(USBDEVFS_DISCONNECT_CLAIM, ARG)
        };
        if !matches!(claim(0, 0x01, b"foo"), Err(FsError::Busy)) {
            return Err("DISCONNECT_CLAIM_IF_DRIVER with another driver is EBUSY");
        }
        if !matches!(claim(0, 0x02, b"usbhid"), Err(FsError::Busy)) {
            return Err("DISCONNECT_CLAIM_EXCEPT_DRIVER naming the driver is EBUSY");
        }
        if !matches!(claim(9, 0, b""), Err(FsError::InvalidData)) {
            return Err("DISCONNECT_CLAIM on a missing interface is EINVAL");
        }
        claim(2, 0, b"").map_err(|_| "claim a free interface")?;
        if fx.dev.owner(2) != Some(Owner::File(fx.file.shared().id)) {
            return Err("DISCONNECT_CLAIM ends with the interface claimed");
        }
        Ok(())
    })();
    drop(other);
    verdict(r)
}
kernel_test_in!(
    "drivers/usb/usbfs",
    smoke_usbfs_disconnect_connect_and_claim
);

// ── disconnect ──────────────────────────────────────────────────────────

fn smoke_usbfs_device_removal() -> TestResult {
    let fx = fixture();
    let r = (|| {
        urb(&fx, URB_TYPE_BULK, 0x84, 0, DATA, 64);
        fx.ioctl(USBDEVFS_SUBMITURB, URB).map_err(|_| "submit")?;
        usbdev::remove(fx.dev.controller, fx.dev.slot);
        let mask = fx.file.poll_readiness();
        if mask & (POLL_HUP | POLL_ERR) != POLL_HUP | POLL_ERR || mask & POLL_WRNORM == 0 {
            return Err("after removal poll is HUP|ERR, with the flushed URB reapable");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIMINTERFACE, 2),
            Err(FsError::NoDevice)
        ) {
            return Err("ioctls on a removed device are ENODEV");
        }
        if reap(&fx).map(|r| r.0) != Ok(-108) {
            return Err("a URB in flight at removal is reaped with -ESHUTDOWN");
        }
        if !matches!(reap(&fx), Err(FsError::NoDevice)) {
            return Err("REAPURBNDELAY with nothing left on a removed device is ENODEV");
        }
        let mut buf = [0u8; 18];
        if !matches!(
            run(fx.file.read(0, &mut buf)),
            Err(FsError::NoDevice)
        ) {
            return Err("read of a removed device is ENODEV");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_device_removal);

// ── streams, reset ──────────────────────────────────────────────────────

fn smoke_usbfs_streams_and_reset() -> TestResult {
    let fx = fixture();
    let r = (|| {
        let streams = |cmd: u32, num_streams: u32, eps: &[u8]| {
            let mut b = alloc::vec![0u8; 8 + eps.len()];
            b[0..4].copy_from_slice(&num_streams.to_le_bytes());
            b[4..8].copy_from_slice(&(eps.len() as u32).to_le_bytes());
            b[8..].copy_from_slice(eps);
            fx.mem.poke(ARG, &b);
            fx.ioctl(cmd, ARG)
        };
        if !matches!(
            streams(USBDEVFS_ALLOC_STREAMS, 4, &[]),
            Err(FsError::InvalidData)
        ) {
            return Err("num_eps 0 is EINVAL");
        }
        if !matches!(
            streams(USBDEVFS_ALLOC_STREAMS, 1, &[0x84]),
            Err(FsError::InvalidData)
        ) {
            return Err("fewer than two streams is EINVAL");
        }
        if !matches!(
            streams(USBDEVFS_ALLOC_STREAMS, 4, &[0x86]),
            Err(FsError::InvalidData)
        ) {
            return Err("an endpoint not in the current setting is EINVAL");
        }
        if !matches!(
            streams(USBDEVFS_ALLOC_STREAMS, 4, &[0x84, 0x82]),
            Err(FsError::InvalidData)
        ) {
            return Err("endpoints of two interfaces are EINVAL");
        }
        if !matches!(
            streams(USBDEVFS_ALLOC_STREAMS, 4, &[0x84]),
            Err(FsError::InvalidData)
        ) {
            return Err("streams below SuperSpeed are EINVAL");
        }
        if !matches!(
            streams(USBDEVFS_FREE_STREAMS, 0, &[0x84]),
            Err(FsError::InvalidData)
        ) {
            return Err("freeing streams never allocated is EINVAL");
        }
        // LINUX-GAP: no port reset + re-address path, so a device reset is
        // EIO rather than usb_reset_device's result.
        if !matches!(fx.ioctl(USBDEVFS_RESET, 0), Err(FsError::Io(_))) {
            return Err("RESET of a device reports the documented EIO gap");
        }
        if !matches!(
            fx.ioctl_u32(USBDEVFS_CLAIM_PORT, 1),
            Err(FsError::InvalidData)
        ) {
            return Err("CLAIM_PORT on a device that is not a hub is EINVAL");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_streams_and_reset);

// ── the devfs tree and node metadata ────────────────────────────────────

fn smoke_usbfs_node_names_and_metadata() -> TestResult {
    reset();
    let dev = device();
    let r = (|| {
        if three_digits("007") != Some(7)
            || three_digits("7").is_some()
            || three_digits("000").is_some()
        {
            return Err("node names are exactly three digits, never 000");
        }
        let node = lookup_node(3, 5).ok_or("device node")?;
        if node.rdev() != narf_filesystem::devfs::linux_makedev(189, 2 * 128 + 4) {
            return Err("rdev is 189:(bus-1)*128+dev-1");
        }
        if node.stat().mode.perms != 0o600 || node.owners() != (0, 0) {
            return Err("a node starts at devtmpfs's 0600 root:root");
        }
        run(node.set_perms(0o664)).map_err(|_| "chmod")?;
        run(node.set_owners(0, 85)).map_err(|_| "chown")?;
        let again = lookup_node(3, 5).ok_or("relookup")?;
        if again.stat().mode.perms != 0o664 || again.owners() != (0, 85) {
            return Err("udev's chmod/chown survive a new lookup");
        }
        run(again.set_xattr(ACL_XATTR, &[2, 0, 0, 0], 0))
            .map_err(|_| "acl")?;
        if run(lookup_node(3, 5).ok_or("acl node")?.get_xattr(ACL_XATTR)).ok()
            != Some(alloc::vec![2, 0, 0, 0])
        {
            return Err("the uaccess ACL persists");
        }
        if lookup_node(3, 9).is_some() {
            return Err("an unused device number has no node");
        }
        usbdev::remove(dev.controller, dev.slot);
        if lookup_node(3, 5).is_some() {
            return Err("a removed device's node is gone");
        }
        Ok(())
    })();
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_node_names_and_metadata);

// ── root hubs (need a probed controller) ────────────────────────────────

fn smoke_usbfs_root_hub() -> TestResult {
    reset();
    let Some(hub) = usbdev::root_hubs().first().copied() else {
        return TestResult::Skip("no xHCI root hub");
    };
    let file = __open_for_test(Target::RootHub(hub), None, true);
    let other = __open_for_test(Target::RootHub(hub), None, true);
    let mem = Mem::new();
    let io = |f: &Arc<UsbfsFile>, cmd: u32, arg: u64| {
        run(f.ioctl_user(cmd, arg, &mem))
    };
    let r = (|| {
        let mut buf = [0u8; 18];
        run(file.read(0, &mut buf)).map_err(|_| "read")?;
        if buf[..] != usbdev::root_hub_descriptors(&hub)[..18] {
            return Err("a root hub reads as its hcd.c descriptors");
        }
        if !matches!(io(&file, USBDEVFS_RESET, 0), Err(FsError::IsADirectory)) {
            return Err("RESET of a root hub is EISDIR");
        }
        mem.poke(BASE, &0u32.to_le_bytes());
        if !matches!(io(&file, USBDEVFS_CLAIMINTERFACE, BASE), Err(FsError::Busy)) {
            return Err("the hub driver holds a root hub's interface");
        }
        let mut b = [0u8; 16];
        b[4..8].copy_from_slice(&USBDEVFS_HUB_PORTINFO.to_le_bytes());
        b[8..16].copy_from_slice(&(BASE + 0x100).to_le_bytes());
        mem.poke(BASE, &b);
        let n = io(&file, USBDEVFS_IOCTL, BASE).map_err(|_| "portinfo")?;
        if n != u64::from(hub.ports) + 1 || mem.peek(BASE + 0x100, 1)[0] != hub.ports {
            return Err("HUB_PORTINFO returns nports + 1 and the port count");
        }
        // GET_DESCRIPTOR(STRING 2): the product string.
        let mut c = [0u8; 24];
        c[0] = 0x80;
        c[1] = 0x06;
        c[2..4].copy_from_slice(&0x0302u16.to_le_bytes());
        c[6..8].copy_from_slice(&64u16.to_le_bytes());
        c[16..24].copy_from_slice(&(BASE + 0x200).to_le_bytes());
        mem.poke(BASE, &c);
        let n = io(&file, USBDEVFS_CONTROL, BASE).map_err(|_| "string")? as usize;
        let s = mem.peek(BASE + 0x200, n);
        let text: String =
            char::decode_utf16(s[2..].chunks(2).map(|w| u16::from_le_bytes([w[0], w[1]])))
                .map(|c| c.unwrap_or('?'))
                .collect();
        if text != "xHCI Host Controller" {
            return Err("the root hub's product string is hcd.c's");
        }
        if hub.ports >= 1 {
            mem.poke(BASE, &1u32.to_le_bytes());
            io(&file, USBDEVFS_CLAIM_PORT, BASE).map_err(|_| "claim port")?;
            if !matches!(io(&other, USBDEVFS_CLAIM_PORT, BASE), Err(FsError::Busy)) {
                return Err("a claimed port is EBUSY to another file");
            }
            if !matches!(
                io(&other, USBDEVFS_RELEASE_PORT, BASE),
                Err(FsError::NotFound)
            ) {
                return Err("releasing a port another file owns is ENOENT");
            }
            io(&file, USBDEVFS_RELEASE_PORT, BASE).map_err(|_| "release port")?;
        }
        mem.poke(BASE, &0u32.to_le_bytes());
        if !matches!(
            io(&file, USBDEVFS_CLAIM_PORT, BASE),
            Err(FsError::InvalidData)
        ) {
            return Err("port 0 is EINVAL");
        }
        Ok(())
    })();
    drop(file);
    drop(other);
    verdict(r)
}
kernel_test_in!("drivers/usb/usbfs", smoke_usbfs_root_hub);
