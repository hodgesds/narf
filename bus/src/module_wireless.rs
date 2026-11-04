//! Versioned copy-mode wireless services for loadable modules.
//!
//! Bus knows neither firmware objects nor wireless Rust traits. A permanent
//! family adapter registers these hooks; the module sees only owner-scoped,
//! never-reused session/operation integers and copied protocol bytes.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{BusDevice, BusDeviceCap};

/// Maximum request bytes accepted before a host adapter is entered.
pub const MAX_REQUEST: usize = 4096;
/// Maximum copied reply. Larger firmware images are read in bounded chunks.
pub const MAX_REPLY: usize = 65_536;

/// Kernel-only final copy gate. Its implementation performs no host/module
/// callback, allocation or await while holding service/device presence.
pub type Publish<'a> = dyn FnMut(&[u8]) -> Result<(), i32> + 'a;

pub type HostOpen = fn(u64, u64, u64, BusDevice, Cap<BusDeviceCap, Write>) -> Result<(), i32>;

/// Permanent, kernel-resident hooks. No hook may point into unloadable text.
/// `poll` returns `(status, required_bytes)`; `-EAGAIN` retains an operation,
/// `-ENOBUFS` retains its terminal reply, and a successful copy consumes it.
/// `cancel` requests cancellation; it must never free hardware-owned memory.
/// `close` withdraws publication and retains uncertain native work/resources
/// until its own terminal cleanup, independently of module text.
#[derive(Debug)]
pub struct Host {
    pub family: u32,
    pub version: u32,
    pub open: HostOpen,
    pub submit: fn(u64, u32, &[u8]) -> Result<u64, i32>,
    pub poll: fn(u64, u64, usize, &mut Publish<'_>) -> (i32, usize),
    pub cancel: fn(u64, u64) -> i32,
    pub close: fn(u64),
}

#[derive(Clone, Copy)]
struct Binding {
    owner: u64,
    token: u64,
    session: u64,
    cap: Cap<BusDeviceCap, Write>,
    host: &'static Host,
}

static HOSTS: IrqSafeSpinLock<Vec<&'static Host>> = IrqSafeSpinLock::new(Vec::new());
static BINDINGS: IrqSafeSpinLock<Vec<Binding>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Register one permanent host per family. A replacement cannot silently
/// change the implementation or protocol underneath existing sessions.
pub fn register(host: &'static Host) -> Result<(), i32> {
    let mut hosts = HOSTS.lock();
    if let Some(old) = hosts.iter().find(|old| old.family == host.family) {
        return if core::ptr::eq(*old, host) {
            Ok(())
        } else {
            Err(-16)
        };
    }
    hosts.push(host);
    Ok(())
}

struct Current<F>(F);
impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Current<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

fn current(binding: Binding) -> Result<(), i32> {
    binding.cap.invoke(Current(|| ())).map_err(|_| -19)?;
    let (_, cap) = crate::driver_match::module_device_authority(binding.owner, binding.token)?;
    if cap.slot() != binding.cap.slot() {
        return Err(-19);
    }
    if !BINDINGS.lock().iter().any(|entry| {
        entry.session == binding.session
            && entry.owner == binding.owner
            && entry.token == binding.token
    }) {
        return Err(-19);
    }
    Ok(())
}

fn binding(owner: u64, token: u64, session: u64) -> Result<Binding, i32> {
    let binding = BINDINGS
        .lock()
        .iter()
        .copied()
        .find(|b| b.owner == owner && b.token == token && b.session == session)
        .ok_or(-19)?;
    current(binding)?;
    Ok(binding)
}

/// Open a service only on the exact device already granted to this module's
/// probe. Unknown families/versions fail before the host performs device I/O.
pub fn open(owner: u64, token: u64, family: u32, version: u32) -> Result<u64, i32> {
    let host = HOSTS
        .lock()
        .iter()
        .copied()
        .find(|host| host.family == family)
        .ok_or(-95)?;
    if host.version != version {
        return Err(-93);
    }
    let (device, cap) = crate::driver_match::module_device_authority(owner, token)?;
    let session = NEXT_SESSION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| -75)?;
    let entry = Binding {
        owner,
        token,
        session,
        cap,
        host,
    };
    {
        let mut bindings = BINDINGS.lock();
        if bindings
            .iter()
            .any(|b| b.owner == owner && b.token == token)
        {
            return Err(-16);
        }
        // Reserve before opening; device teardown can find even an opening
        // service, and a concurrent second open cannot duplicate native ownership.
        bindings.push(entry);
    }
    if let Err(error) = (host.open)(owner, token, session, device, cap) {
        close(owner, token, session);
        return Err(error);
    }
    if binding(owner, token, session).is_err() {
        (host.close)(session);
        return Err(-19);
    }
    Ok(session)
}

pub fn submit(
    owner: u64,
    token: u64,
    session: u64,
    opcode: u32,
    request: &[u8],
) -> Result<u64, i32> {
    if request.len() > MAX_REQUEST {
        return Err(-90);
    }
    let binding = binding(owner, token, session)?;
    let operation = (binding.host.submit)(session, opcode, request)?;
    if current(binding).is_err() {
        (binding.host.cancel)(session, operation);
        return Err(-19);
    }
    Ok(operation)
}

pub fn poll(
    owner: u64,
    token: u64,
    session: u64,
    operation: u64,
    reply: &mut [u8],
) -> (i32, usize) {
    if reply.len() > MAX_REPLY {
        return (-90, 0);
    }
    let binding = match binding(owner, token, session) {
        Ok(b) => b,
        Err(e) => return (e, 0),
    };
    let capacity = reply.len();
    let mut publish = |bytes: &[u8]| {
        if bytes.len() > capacity {
            return Err(-105);
        }
        let bindings = BINDINGS.lock();
        if !bindings.iter().any(|entry| {
            entry.owner == owner
                && entry.token == token
                && entry.session == session
                && entry.cap.slot() == binding.cap.slot()
        }) {
            return Err(-19);
        }
        // Only the bounded memory copy runs under these locks. In particular
        // no permanent host hook or unloadable callback is invoked here.
        crate::driver_match::module_device_publish(owner, token, binding.cap, || {
            reply[..bytes.len()].copy_from_slice(bytes)
        })
    };
    // Invoke the permanent host without registry locks. It can hold its
    // native receive epoch through this final non-reentrant copy gate.
    (binding.host.poll)(session, operation, capacity, &mut publish)
}

pub fn cancel(owner: u64, token: u64, session: u64, operation: u64) -> i32 {
    match binding(owner, token, session) {
        Ok(binding) => (binding.host.cancel)(session, operation),
        Err(error) => error,
    }
}

/// Closing is permitted even after revocation: it conveys no new I/O rights
/// and must still request cleanup of this exact old session.
pub fn close(owner: u64, token: u64, session: u64) -> i32 {
    let removed = {
        let mut bindings = BINDINGS.lock();
        bindings
            .iter()
            .position(|b| b.owner == owner && b.token == token && b.session == session)
            .map(|index| bindings.remove(index))
    };
    match removed {
        Some(binding) => {
            (binding.host.close)(session);
            0
        }
        None => -19,
    }
}

pub(crate) fn retire_device(owner: u64, token: u64) {
    loop {
        let removed = {
            let mut bindings = BINDINGS.lock();
            bindings
                .iter()
                .position(|b| b.owner == owner && b.token == token)
                .map(|index| bindings.remove(index))
        };
        let Some(binding) = removed else {
            return;
        };
        (binding.host.close)(binding.session);
    }
}
