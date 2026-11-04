//! Loadable MT76 frontend. Native MCU/WFDMA code stays in the permanent host;
//! this image owns its probe, opaque service/operation handles and poller.
use crate::module_protocol as protocol;
use core::sync::atomic::{AtomicU64, Ordering};

static DEVICE: AtomicU64 = AtomicU64::new(0);
static SESSION: AtomicU64 = AtomicU64::new(0);
static INITIALIZATION: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
    fn narf_wireless_open(dev: u64, family: u32, version: u32, session: *mut u64) -> i32;
    fn narf_wireless_submit(
        dev: u64,
        session: u64,
        opcode: u32,
        request: *const u8,
        len: usize,
        operation: *mut u64,
    ) -> i32;
    fn narf_wireless_poll(
        dev: u64,
        session: u64,
        operation: u64,
        reply: *mut u8,
        len: usize,
        written: *mut usize,
    ) -> i32;
    fn narf_wireless_close(dev: u64, session: u64) -> i32;
    fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
}

extern "C" fn poll(dev: u64) -> i32 {
    let session = SESSION.load(Ordering::Acquire);
    if session == 0 || DEVICE.load(Ordering::Acquire) != dev {
        return -19;
    }
    let operation = INITIALIZATION.load(Ordering::Acquire);
    if operation == 0 {
        return 0;
    }
    let mut reply = [0; 128];
    let mut len = 0;
    // SAFETY: ids belong to this probe; outputs are borrowed only for this
    // bounded call. The permanent host retains every native future.
    let status = unsafe {
        narf_wireless_poll(
            dev,
            session,
            operation,
            reply.as_mut_ptr(),
            reply.len(),
            &mut len,
        )
    };
    if status == -11 {
        return 0;
    }
    if status == 0 && len <= reply.len() && protocol::initialized(&reply[..len]) {
        INITIALIZATION.store(0, Ordering::Release);
        return 0;
    }
    exit();
    if status == 0 {
        -5
    } else {
        status
    }
}

extern "C" fn probe_c(dev: u64, reserved: u64) -> i32 {
    if reserved != 0 || SESSION.load(Ordering::Acquire) != 0 {
        return -16;
    }
    let mut session = 0;
    // SAFETY: aligned scalar output; opening is tied to this exact probe
    // context by the kernel's current module identity, never by `dev` alone.
    let status =
        unsafe { narf_wireless_open(dev, protocol::FAMILY, protocol::VERSION, &mut session) };
    if status != 0 {
        return status;
    }
    DEVICE.store(dev, Ordering::Release);
    SESSION.store(session, Ordering::Release);
    let mut operation = 0;
    // SAFETY: INITIALIZE has an empty request. Firmware/identity gate actual
    // netdev publication; this return reports only accepted work.
    let status = unsafe {
        narf_wireless_submit(
            dev,
            session,
            protocol::INITIALIZE,
            core::ptr::null(),
            0,
            &mut operation,
        )
    };
    if status != 0 {
        exit();
        return status;
    }
    INITIALIZATION.store(operation, Ordering::Release);
    // SAFETY: valid C callback, pinned by the module gate for each invocation.
    let status = unsafe { narf_spawn_poller(dev, poll as usize, dev) };
    if status != 0 {
        exit();
    }
    status
}

pub fn exit() {
    let session = SESSION.swap(0, Ordering::AcqRel);
    INITIALIZATION.store(0, Ordering::Release);
    if session != 0 {
        // SAFETY: close conveys only cleanup for this exact owner-scoped id.
        unsafe { narf_wireless_close(DEVICE.load(Ordering::Acquire), session) };
    }
}

pub fn register() {
    const NAME: &[u8] = b"mt76-module";
    for &(vendor, device) in &[
        (0x14c3, 0x0608),
        (0x14c3, 0x0616),
        (0x14c3, 0x7920),
        (0x14c3, 0x7922),
        (0x14c3, 0x7961),
        (0x0e8d, 0x7922),
    ] {
        // SAFETY: static name and C thunk; the loader unregisters every match
        // before unmapping this image. Each CONNAC2 PCI alias is supported.
        unsafe {
            narf_register_pci_driver(NAME.as_ptr(), NAME.len(), vendor, device, probe_c as usize)
        };
    }
}
