//! Exercise the actual bus/context boundary with a permanent in-tree host.
//! This fixture models service bytes, not MediaTek firmware or RF success.
use super::*;
use crate::module_wireless as service;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

const OWNER: u64 = 0xffff_ffff_7301;
const TOKEN: u64 = 0xffff_ffff_7302;
const FAMILY: u32 = 0xff76_0001;
static OPENS: AtomicUsize = AtomicUsize::new(0);
static CLOSES: AtomicUsize = AtomicUsize::new(0);
static CLOSES_LIVE: AtomicUsize = AtomicUsize::new(0);
static REVOKE_IN_POLL: AtomicBool = AtomicBool::new(false);
static CLOSE_IN_POLL: AtomicBool = AtomicBool::new(false);
static CAP: IrqSafeSpinLock<Option<Cap<BusDeviceCap, Write>>> = IrqSafeSpinLock::new(None);
static HOST: service::Host = service::Host {
    family: FAMILY,
    version: 1,
    open: host_open,
    submit: host_submit,
    poll: host_poll,
    cancel: host_cancel,
    close: host_close,
};
fn host_open(
    owner: u64,
    token: u64,
    _: u64,
    _: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), i32> {
    if owner != OWNER || token != TOKEN {
        return Err(-22);
    }
    cap.invoke(DeviceOp(|| ())).map_err(|_| -19)?;
    OPENS.fetch_add(1, Ordering::AcqRel);
    *CAP.lock() = Some(cap);
    Ok(())
}
fn host_submit(_: u64, opcode: u32, bytes: &[u8]) -> Result<u64, i32> {
    if opcode == 7 && bytes == [3, 4, 5] {
        Ok(42)
    } else {
        Err(-22)
    }
}
fn host_poll(
    id: u64,
    operation: u64,
    capacity: usize,
    publish: &mut service::Publish<'_>,
) -> (i32, usize) {
    if operation != 42 {
        return (-22, 0);
    }
    if capacity < 2 {
        return (-105, 2);
    }
    if REVOKE_IN_POLL.load(Ordering::Acquire) {
        if let Some(cap) = *CAP.lock() {
            cap.revoke();
        }
    }
    if CLOSE_IN_POLL.load(Ordering::Acquire) {
        service::close(OWNER, TOKEN, id);
    }
    match publish(&[0xde, 0xad]) {
        Ok(()) => (0, 2),
        Err(error) => (error, 0),
    }
}
fn host_cancel(_: u64, operation: u64) -> i32 {
    if operation == 42 {
        0
    } else {
        -22
    }
}
fn host_close(_: u64) {
    CLOSES.fetch_add(1, Ordering::AcqRel);
    if CAP
        .lock()
        .is_some_and(|cap| cap.invoke(DeviceOp(|| ())).is_ok())
    {
        CLOSES_LIVE.fetch_add(1, Ordering::AcqRel);
    }
}
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        remove_device_ctx(TOKEN);
        *CAP.lock() = None;
        REVOKE_IN_POLL.store(false, Ordering::Release);
        CLOSE_IN_POLL.store(false, Ordering::Release);
    }
}
fn install() -> (Cleanup, Cap<BusDeviceCap, Write>) {
    remove_device_ctx(TOKEN);
    OPENS.store(0, Ordering::Release);
    CLOSES.store(0, Ordering::Release);
    CLOSES_LIVE.store(0, Ordering::Release);
    REVOKE_IN_POLL.store(false, Ordering::Release);
    CLOSE_IN_POLL.store(false, Ordering::Release);
    let device = BusDevice {
        addr: crate::BusAddr::Mmio(narf_memory::PhysAddr::new(TOKEN)),
        id: crate::DeviceId {
            vendor: 0x14c3,
            device: 0x7922,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::VirtioMmio {
            base: narf_memory::PhysAddr::new(TOKEN),
            len: 4096,
            device_id: 1,
        },
    };
    let cap = Cap::bootstrap();
    install_device_ctx(OWNER, TOKEN, device, cap);
    let _ = service::register(&HOST);
    (Cleanup, cap)
}
fn smoke_bus_wireless_service_exact_owner_device_version_and_retained_reply() -> TestResult {
    let (_cleanup, _) = install();
    if service::open(OWNER + 1, TOKEN, FAMILY, 1) != Err(-19)
        || service::open(OWNER, TOKEN + 1, FAMILY, 1) != Err(-19)
        || service::open(OWNER, TOKEN, FAMILY, 2) != Err(-93)
        || OPENS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail(
            "wireless service opened without exact probe owner/device/version",
        );
    }
    let Ok(id) = service::open(OWNER, TOKEN, FAMILY, 1) else {
        return TestResult::Fail("wireless service could not open exact probe grant");
    };
    if service::open(OWNER, TOKEN, FAMILY, 1) != Err(-16)
        || service::submit(OWNER + 1, TOKEN, id, 7, &[3, 4, 5]) != Err(-19)
        || service::submit(OWNER, TOKEN + 1, id, 7, &[3, 4, 5]) != Err(-19)
        || service::submit(OWNER, TOKEN, id + 1, 7, &[3, 4, 5]) != Err(-19)
        || service::submit(OWNER, TOKEN, id, 7, &[3, 4, 5]) != Ok(42)
    {
        return TestResult::Fail(
            "wireless operation aliased another owner/device/session or lost payload",
        );
    }
    let mut small = [0x77];
    let mut full = [0x77; 4];
    if service::poll(OWNER, TOKEN, id, 42, &mut small) != (-105, 2)
        || small != [0x77]
        || service::poll(OWNER, TOKEN, id, 42, &mut full) != (0, 2)
        || full != [0xde, 0xad, 0x77, 0x77]
    {
        return TestResult::Fail("wireless reply sizing consumed or corrupted copied bytes");
    }
    if service::close(OWNER + 1, TOKEN, id) != -19
        || service::close(OWNER, TOKEN, id) != 0
        || service::submit(OWNER, TOKEN, id, 7, &[3, 4, 5]) != Err(-19)
    {
        return TestResult::Fail(
            "closed wireless service remained usable or foreign close succeeded",
        );
    }
    let Ok(next) = service::open(OWNER, TOKEN, FAMILY, 1) else {
        return TestResult::Fail("wireless fixture reopen failed");
    };
    if next == id || service::cancel(OWNER, TOKEN, id, 42) != -19 {
        return TestResult::Fail("wireless session id reused after close");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/module-wireless",
    smoke_bus_wireless_service_exact_owner_device_version_and_retained_reply
);

fn smoke_bus_wireless_service_revocation_suppresses_bytes_and_teardown_precedes_cap_revoke(
) -> TestResult {
    let (_cleanup, cap) = install();
    let Ok(id) = service::open(OWNER, TOKEN, FAMILY, 1) else {
        return TestResult::Fail("wireless teardown fixture open");
    };
    remove_device_ctx(TOKEN);
    if CLOSES.load(Ordering::Acquire) != 1
        || CLOSES_LIVE.load(Ordering::Acquire) != 1
        || cap.check_live().is_ok()
        || service::cancel(OWNER, TOKEN, id, 42) != -19
    {
        return TestResult::Fail(
            "wireless device teardown revoked before host cleanup or retained stale session",
        );
    }
    let (_second_cleanup, _) = install();
    let Ok(next) = service::open(OWNER, TOKEN, FAMILY, 1) else {
        return TestResult::Fail("wireless revocation fixture reopen");
    };
    REVOKE_IN_POLL.store(true, Ordering::Release);
    let mut bytes = [0x66; 4];
    if service::poll(OWNER, TOKEN, next, 42, &mut bytes) != (-19, 0)
        || bytes != [0x66; 4]
        || service::submit(OWNER, TOKEN, next, 7, &[3, 4, 5]) != Err(-19)
        || service::close(OWNER, TOKEN, next) != 0
    {
        return TestResult::Fail("wireless native completion published bytes after current grant was revoked or cleanup became unreachable");
    }
    let (_third_cleanup, cap) = install();
    let Ok(closing) = service::open(OWNER, TOKEN, FAMILY, 1) else {
        return TestResult::Fail("wireless close-at-publication fixture open");
    };
    CLOSE_IN_POLL.store(true, Ordering::Release);
    if service::poll(OWNER, TOKEN, closing, 42, &mut bytes) != (-19, 0)
        || bytes != [0x66; 4]
        || cap.check_live().is_err()
        || CLOSES.load(Ordering::Acquire) != 1
    {
        return TestResult::Fail(
            "wireless completion copied after exact service close while probe cap stayed live",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/module-wireless",
    smoke_bus_wireless_service_revocation_suppresses_bytes_and_teardown_precedes_cap_revoke
);
