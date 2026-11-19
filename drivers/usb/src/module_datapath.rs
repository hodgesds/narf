//! USB transfer datapath for loadable modules.
//!
//! The registration half (`narf_register_usb_driver`, in
//! [`crate::class_registry`]) offers a module a device no built-in driver
//! claimed. This file is what lets that module *drive* the device. It is the
//! USB-stack implementation of [`narf_bus::module_usb::Datapath`], reached
//! from the `narf_usb_*` kernel-ABI exports.
//!
//! ## Model
//!
//! * **Context.** [`open`] mints one context per `(module, device token)`
//!   immediately before the module's probe runs, holding the
//!   `Arc<USBDevice>` and the configuration descriptor the device was
//!   matched with. The module only ever holds the opaque token; every hook
//!   finds the context by `(owner, token)`, so one module can never reach a
//!   device it was not probed for. A declined probe, a detach, or module
//!   unload retires the context.
//! * **Requests ("URBs").** Control, endpoint-configuration, bulk and
//!   interrupt requests are kernel-owned. Each gets a never-reused id. All
//!   data moves by copy: OUT payloads are copied in at submit, IN payloads
//!   are copied out at poll. Transfer buffers are xHCI endpoint pages, so
//!   module memory is never a DMA target and unload never races hardware
//!   writes into module data.
//! * **Completion.** Futures (control, configure, bulk stop) run in in-tree
//!   tasks; bulk and interrupt completions are found by a per-context pump
//!   task polling the xHCI event queue every millisecond while anything is
//!   pending. A terminal request optionally fires the module's completion
//!   callback, always outside every lock here and always through the
//!   module callback gate (`narf_bus::module_usb::call_module_usb_callback`),
//!   which refuses once the module is no longer Live.
//! * **Serial node.** A module USB-serial driver can publish a
//!   `/dev/ttyUSB<N>` node backed by its device: writers' bytes queue in the
//!   node's TX ring and kick the module; the module moves them with
//!   `serial_tx` and delivers received bytes with `serial_rx`.
//!
//! Lock order: `CONTEXTS` → xHCI-internal locks. No lock is held across an
//! `.await` or a module callback.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_bus::module_usb::{self, Completion, Datapath};
use narf_lib::sync::IrqSafeSpinLock;

use crate::device::{BulkToken, USBDevice, UsbError};
use crate::serial::devfs_bridge;
use crate::serial::ChipFamily;
use crate::xhci::{EndpointConfig, EndpointKind};

/// Most simultaneously live module USB contexts (all modules together).
const MAX_CONTEXTS: usize = 32;
/// Most unconsumed requests one context may hold.
pub const MAX_URBS: usize = 32;

const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EAGAIN: i32 = -11;
const ENOSPC: i32 = -28;
const ENOBUFS: i32 = -105;
const EOPNOTSUPP: i32 = -95;
const ECANCELED: i32 = -125;
const EPIPE: i32 = -32;
const EPROTO: i32 = -71;
const EOVERFLOW: i32 = -75;
const ETIMEDOUT: i32 = -110;
const EIO: i32 = -5;

/// Standard `SET_ADDRESS`: the xHCI controller owns device addressing, so a
/// module may not issue it on EP0.
const STD_REQ_SET_ADDRESS: u8 = 0x05;

/// Linux-style URB status for a USB-layer failure.
fn errno(error: UsbError) -> i32 {
    match error {
        UsbError::Stall => EPIPE,
        UsbError::TransactionError => EPROTO,
        UsbError::Babble | UsbError::BufferTooSmall => EOVERFLOW,
        UsbError::Timeout => ETIMEDOUT,
        UsbError::StaleSlot => ENODEV,
        UsbError::NotConfigured => EINVAL,
        // `XhciError::NotReady`: the endpoint already owns a TD.
        UsbError::HardwareError(0xFE) => EBUSY,
        UsbError::HardwareError(_) => EIO,
    }
}

enum Pending {
    /// A control or configure future runs in its own task.
    Future,
    /// A posted bulk TD; the pump polls its receipt.
    Bulk {
        receipt: BulkToken,
        is_in: bool,
        len: usize,
    },
    /// An armed interrupt-IN endpoint; the pump polls it.
    InterruptIn { dci: u8, len: usize },
    /// A staged interrupt-OUT TRB; the pump polls its completion.
    InterruptOut { dci: u8, len: usize },
    /// A bulk TD whose stop is in flight in a kernel task.
    Stopping,
}

enum State {
    Pending(Pending),
    Done {
        status: i32,
        actual: usize,
        data: Vec<u8>,
    },
}

struct Urb {
    id: u64,
    state: State,
    done: Completion,
}

struct Context {
    owner: u64,
    token: u64,
    device: Arc<USBDevice>,
    config: Vec<u8>,
    /// Endpoints a completed `configure` request enabled.
    configured: Vec<EndpointConfig>,
    /// Interrupt-IN endpoints already armed, with the armed length: the
    /// xHCI poll re-arms after every report, so later requests only wait.
    armed: Vec<(u8, usize)>,
    urbs: Vec<Urb>,
    pump_running: bool,
    serial: Option<u32>,
}

struct ModulePort {
    index: u32,
    owner: u64,
    token: u64,
    kick: Completion,
}

static CONTEXTS: IrqSafeSpinLock<Vec<Context>> = IrqSafeSpinLock::new(Vec::new());
static PORTS: IrqSafeSpinLock<Vec<ModulePort>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_URB: AtomicU64 = AtomicU64::new(1);

fn next_urb_id() -> Result<u64, i32> {
    NEXT_URB
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| EOVERFLOW)
}

fn find(contexts: &mut [Context], owner: u64, token: u64) -> Result<&mut Context, i32> {
    contexts
        .iter_mut()
        .find(|c| c.owner == owner && c.token == token)
        .ok_or(ENODEV)
}

fn fire(owner: u64, done: Completion) {
    if let Some(callback) = done.callback {
        let _ = module_usb::call_module_usb_callback(owner, callback, done.cookie);
    }
}

// ── Context lifetime ────────────────────────────────────────────────

/// Mint the context a module's probe will drive. Called by the class
/// registry immediately before it invokes the module's probe; an existing
/// context for the same token (a stale one from a previous attach of the
/// slot) is retired first. `false` when the device cannot be offered.
pub(crate) fn open(owner: u64, token: u64, device: Arc<USBDevice>, config: &[u8]) -> bool {
    if config.len() > module_usb::MAX_CONFIG_DESCRIPTOR {
        return false;
    }
    retire_token(token);
    let mut contexts = CONTEXTS.lock();
    if contexts.len() >= MAX_CONTEXTS {
        return false;
    }
    contexts.push(Context {
        owner,
        token,
        device,
        config: config.to_vec(),
        configured: Vec::new(),
        armed: Vec::new(),
        urbs: Vec::new(),
        pump_running: false,
        serial: None,
    });
    true
}

/// Retire the context for one device token (declined probe, detach).
pub(crate) fn retire_token(token: u64) {
    let removed: Vec<Context> = {
        let mut contexts = CONTEXTS.lock();
        let (gone, kept): (Vec<Context>, Vec<Context>) = core::mem::take(&mut *contexts)
            .into_iter()
            .partition(|c| c.token == token);
        *contexts = kept;
        gone
    };
    removed.into_iter().for_each(teardown);
}

/// Retire every context one module owns. The loader calls this (through
/// the registration host's `unregister`) after the module's exit hook and
/// before its text is unmapped.
pub(crate) fn retire_owner(owner: u64) {
    let removed: Vec<Context> = {
        let mut contexts = CONTEXTS.lock();
        let (gone, kept): (Vec<Context>, Vec<Context>) = core::mem::take(&mut *contexts)
            .into_iter()
            .partition(|c| c.owner == owner);
        *contexts = kept;
        gone
    };
    removed.into_iter().for_each(teardown);
}

/// Release a retired context's resources. No module callback runs from
/// here: pending requests are simply dropped, and a posted bulk TD is
/// stopped by a kernel task that never calls module text.
fn teardown(ctx: Context) {
    // Sinks outside the USB stack (a module's block disk) go first: a
    // request still running waits on this context's transfers.
    narf_bus::module_context_retired(ctx.owner, ctx.token);
    if let Some(index) = ctx.serial {
        PORTS
            .lock()
            .retain(|p| !(p.owner == ctx.owner && p.token == ctx.token));
        devfs_bridge::unregister_tty_usb(index as usize);
    }
    for urb in ctx.urbs {
        if let State::Pending(Pending::Bulk { receipt, .. }) = urb.state {
            let device = Arc::clone(&ctx.device);
            narf_scheduler::spawn(async move {
                // An error leaves the endpoint terminally busy, which is the
                // xHCI layer's own fail-closed rule; nothing else to do.
                let _ = device.stop_bulk(&receipt).await;
            });
        }
    }
}

// ── Datapath hooks ──────────────────────────────────────────────────

fn config_descriptor(owner: u64, token: u64, out: &mut [u8]) -> (i32, usize) {
    let mut contexts = CONTEXTS.lock();
    let ctx = match find(&mut contexts, owner, token) {
        Ok(ctx) => ctx,
        Err(e) => return (e, 0),
    };
    let len = ctx.config.len();
    if out.len() < len {
        return (ENOBUFS, len);
    }
    out[..len].copy_from_slice(&ctx.config);
    (0, len)
}

/// Find endpoint `address` in a configuration descriptor and derive its
/// xHCI configuration from the descriptor's own attributes.
pub(crate) fn endpoint_from_config(config: &[u8], address: u8) -> Result<EndpointConfig, i32> {
    let mut offset = 0usize;
    while offset + 2 <= config.len() {
        let len = config[offset] as usize;
        if len < 2 || offset + len > config.len() {
            break;
        }
        let d = &config[offset..offset + len];
        if d[1] == 0x05 && len >= 7 && d[2] == address {
            let is_in = address & 0x80 != 0;
            let kind = match (d[3] & 0x03, is_in) {
                (2, true) => EndpointKind::BulkIn,
                (2, false) => EndpointKind::BulkOut,
                (3, true) => EndpointKind::InterruptIn,
                (3, false) => EndpointKind::InterruptOut,
                _ => return Err(EOPNOTSUPP),
            };
            return Ok(EndpointConfig {
                ep_addr: address,
                max_packet: u16::from_le_bytes([d[4], d[5]]) & 0x07ff,
                kind,
                interval: match kind {
                    EndpointKind::BulkIn | EndpointKind::BulkOut => 0,
                    _ => d[6],
                },
            });
        }
        offset += len;
    }
    Err(EINVAL)
}

fn configure(owner: u64, token: u64, endpoints: &[u8], done: Completion) -> Result<u64, i32> {
    let (id, device, eps) = {
        let mut contexts = CONTEXTS.lock();
        let ctx = find(&mut contexts, owner, token)?;
        if ctx.urbs.len() >= MAX_URBS {
            return Err(ENOSPC);
        }
        let mut eps = Vec::with_capacity(endpoints.len());
        for (i, &address) in endpoints.iter().enumerate() {
            if address & 0x0f == 0 || endpoints[..i].contains(&address) {
                return Err(EINVAL);
            }
            eps.push(endpoint_from_config(&ctx.config, address)?);
        }
        let id = next_urb_id()?;
        ctx.urbs.push(Urb {
            id,
            state: State::Pending(Pending::Future),
            done,
        });
        (id, Arc::clone(&ctx.device), eps)
    };
    narf_scheduler::spawn(async move {
        let status = match device.configure_endpoints(&eps).await {
            Ok(()) => {
                if let Ok(ctx) = find(&mut CONTEXTS.lock(), owner, token) {
                    for ep in &eps {
                        ctx.configured.retain(|c| c.ep_addr != ep.ep_addr);
                        ctx.armed
                            .retain(|&(dci, _)| dci != crate::bulk::dci_for(ep.ep_addr));
                        ctx.configured.push(*ep);
                    }
                }
                0
            }
            Err(e) => errno(e),
        };
        finish(owner, token, id, status, 0, Vec::new());
    });
    Ok(id)
}

fn control(
    owner: u64,
    token: u64,
    setup: [u8; 8],
    data: &[u8],
    done: Completion,
) -> Result<u64, i32> {
    let [bm_request_type, b_request, v0, v1, i0, i1, l0, l1] = setup;
    let w_length = usize::from(u16::from_le_bytes([l0, l1]));
    let is_in = bm_request_type & 0x80 != 0;
    if w_length > module_usb::MAX_TRANSFER
        || (is_in && !data.is_empty())
        || (!is_in && data.len() != w_length)
    {
        return Err(EINVAL);
    }
    // Standard, device-recipient SET_ADDRESS would desynchronise the
    // controller's slot state from the device.
    if bm_request_type & 0x7f == 0 && b_request == STD_REQ_SET_ADDRESS {
        return Err(EINVAL);
    }
    let w_value = u16::from_le_bytes([v0, v1]);
    let w_index = u16::from_le_bytes([i0, i1]);
    let (id, device) = {
        let mut contexts = CONTEXTS.lock();
        let ctx = find(&mut contexts, owner, token)?;
        if ctx.urbs.len() >= MAX_URBS {
            return Err(ENOSPC);
        }
        let id = next_urb_id()?;
        ctx.urbs.push(Urb {
            id,
            state: State::Pending(Pending::Future),
            done,
        });
        (id, Arc::clone(&ctx.device))
    };
    let out = data.to_vec();
    narf_scheduler::spawn(async move {
        if is_in {
            let mut buf = vec![0u8; w_length];
            match device
                .control_in(bm_request_type, b_request, w_value, w_index, &mut buf)
                .await
            {
                Ok(n) => {
                    buf.truncate(n.min(w_length));
                    let actual = buf.len();
                    finish(owner, token, id, 0, actual, buf);
                }
                Err(e) => finish(owner, token, id, errno(e), 0, Vec::new()),
            }
        } else {
            match device
                .control_out(bm_request_type, b_request, w_value, w_index, &out)
                .await
            {
                Ok(n) => finish(owner, token, id, 0, n, Vec::new()),
                Err(e) => finish(owner, token, id, errno(e), 0, Vec::new()),
            }
        }
    });
    Ok(id)
}

fn transfer(
    owner: u64,
    token: u64,
    endpoint: u8,
    data: &[u8],
    len: usize,
    done: Completion,
) -> Result<u64, i32> {
    let is_in = endpoint & 0x80 != 0;
    if (is_in && !data.is_empty()) || (!is_in && data.len() != len) {
        return Err(EINVAL);
    }
    let (id, start_pump) = {
        let mut contexts = CONTEXTS.lock();
        let ctx = find(&mut contexts, owner, token)?;
        if ctx.urbs.len() >= MAX_URBS {
            return Err(ENOSPC);
        }
        let ep = *ctx
            .configured
            .iter()
            .find(|c| c.ep_addr == endpoint)
            .ok_or(EINVAL)?;
        let dci = crate::bulk::dci_for(endpoint);
        // Allocate the id before posting anything, so no failure can leave a
        // TD posted without a request that owns it.
        let id = next_urb_id()?;
        let pending = match ep.kind {
            EndpointKind::BulkIn => Pending::Bulk {
                receipt: ctx.device.begin_bulk_in(dci, len).map_err(errno)?,
                is_in: true,
                len,
            },
            EndpointKind::BulkOut => Pending::Bulk {
                receipt: ctx.device.begin_bulk_out(dci, data).map_err(errno)?,
                is_in: false,
                len,
            },
            EndpointKind::InterruptIn => {
                let busy = ctx.urbs.iter().any(|u| {
                matches!(u.state, State::Pending(Pending::InterruptIn { dci: d, .. }) if d == dci)
            });
                if busy {
                    return Err(EBUSY);
                }
                match ctx.armed.iter().find(|&&(d, _)| d == dci) {
                    Some(&(_, armed)) if armed != len => return Err(EINVAL),
                    Some(_) => {}
                    None => {
                        ctx.device
                            .arm_interrupt_in(dci, len as u32)
                            .map_err(errno)?;
                        ctx.armed.push((dci, len));
                    }
                }
                Pending::InterruptIn { dci, len }
            }
            EndpointKind::InterruptOut => {
                let busy = ctx.urbs.iter().any(|u| {
                matches!(u.state, State::Pending(Pending::InterruptOut { dci: d, .. }) if d == dci)
            });
                if busy {
                    return Err(EBUSY);
                }
                ctx.device
                    .controller()
                    .arm_interrupt_out(ctx.device.slot_id(), dci, data)
                    .map_err(|e| errno(UsbError::from_xhci(e)))?;
                Pending::InterruptOut { dci, len }
            }
            EndpointKind::IsochIn | EndpointKind::IsochOut => return Err(EOPNOTSUPP),
        };
        ctx.urbs.push(Urb {
            id,
            state: State::Pending(pending),
            done,
        });
        let start_pump = !ctx.pump_running;
        ctx.pump_running = true;
        (id, start_pump)
    };
    // Spawn outside the IRQ-safe context lock.
    if start_pump {
        narf_scheduler::spawn(pump(owner, token));
    }
    Ok(id)
}

/// Record a future's terminal result and fire its completion callback.
fn finish(owner: u64, token: u64, id: u64, status: i32, actual: usize, data: Vec<u8>) {
    let done = {
        let mut contexts = CONTEXTS.lock();
        let Ok(ctx) = find(&mut contexts, owner, token) else {
            return; // Retired while in flight: nobody left to tell.
        };
        let Some(urb) = ctx.urbs.iter_mut().find(|u| u.id == id) else {
            return;
        };
        urb.state = State::Done {
            status,
            actual,
            data,
        };
        urb.done
    };
    fire(owner, done);
}

/// Poll one pending bulk/interrupt request once. `Some((status, actual,
/// data))` once it is terminal. Futures and stopping receipts are driven
/// elsewhere and report `None` here.
fn poll_pending(device: &USBDevice, pending: &Pending) -> Option<(i32, usize, Vec<u8>)> {
    match pending {
        Pending::Bulk {
            receipt,
            is_in,
            len,
        } => {
            if *is_in {
                let mut buf = vec![0u8; *len];
                match device.poll_bulk_in(receipt, &mut buf) {
                    Ok(Some(n)) => {
                        buf.truncate(n);
                        Some((0, n, buf))
                    }
                    Ok(None) => None,
                    Err(e) => Some((errno(e), 0, Vec::new())),
                }
            } else {
                match device.poll_bulk_out(receipt) {
                    Ok(Some(n)) => Some((0, n, Vec::new())),
                    Ok(None) => None,
                    Err(e) => Some((errno(e), 0, Vec::new())),
                }
            }
        }
        Pending::InterruptIn { dci, len } => {
            let mut buf = vec![0u8; *len];
            match device.poll_interrupt_in(*dci, &mut buf) {
                Ok(Some(n)) => {
                    buf.truncate(n.min(*len));
                    Some((0, n, buf))
                }
                Ok(None) => None,
                Err(e) => Some((errno(e), 0, Vec::new())),
            }
        }
        Pending::InterruptOut { dci, len } => {
            match device
                .controller()
                .poll_interrupt_out(device.slot_id(), *dci, *len as u32)
            {
                Ok(Some(n)) => Some((0, n, Vec::new())),
                Ok(None) => None,
                Err(e) => Some((errno(UsbError::from_xhci(e)), 0, Vec::new())),
            }
        }
        Pending::Future | Pending::Stopping => None,
    }
}

/// Poll one context's bulk/interrupt requests once. Returns the completions
/// to fire and whether anything is still pending.
fn pump_once(owner: u64, token: u64) -> Option<(Vec<Completion>, bool)> {
    let mut contexts = CONTEXTS.lock();
    let ctx = find(&mut contexts, owner, token).ok()?;
    let mut fired = Vec::new();
    let mut still_pending = false;
    let device = Arc::clone(&ctx.device);
    for urb in ctx.urbs.iter_mut() {
        let State::Pending(pending) = &urb.state else {
            continue;
        };
        let result = match pending {
            Pending::Future | Pending::Stopping => continue,
            pending => poll_pending(&device, pending),
        };
        match result {
            Some((status, actual, data)) => {
                urb.state = State::Done {
                    status,
                    actual,
                    data,
                };
                fired.push(urb.done);
            }
            None => still_pending = true,
        }
    }
    if !still_pending {
        ctx.pump_running = false;
    }
    Some((fired, still_pending))
}

/// Per-context completion pump. Runs while bulk/interrupt requests are
/// pending and exits when none are (the next submit restarts it) or when
/// the context is retired.
async fn pump(owner: u64, token: u64) {
    loop {
        let Some((fired, still_pending)) = pump_once(owner, token) else {
            return;
        };
        for done in fired {
            fire(owner, done);
        }
        if !still_pending {
            return;
        }
        narf_time::sleep_cycles(narf_time::ns_to_cycles(1_000_000)).await;
    }
}

fn poll(owner: u64, token: u64, id: u64, out: &mut [u8]) -> (i32, usize) {
    let mut contexts = CONTEXTS.lock();
    let ctx = match find(&mut contexts, owner, token) {
        Ok(ctx) => ctx,
        Err(e) => return (e, 0),
    };
    let Some(index) = ctx.urbs.iter().position(|u| u.id == id) else {
        return (EINVAL, 0);
    };
    let State::Done {
        status,
        actual,
        data,
    } = &ctx.urbs[index].state
    else {
        return (EAGAIN, 0);
    };
    if data.len() > out.len() {
        return (ENOBUFS, data.len());
    }
    out[..data.len()].copy_from_slice(data);
    let (status, actual) = (*status, *actual);
    ctx.urbs.remove(index);
    (status, actual)
}

fn cancel(owner: u64, token: u64, id: u64) -> i32 {
    let (fire_now, stop) = {
        let mut contexts = CONTEXTS.lock();
        let ctx = match find(&mut contexts, owner, token) {
            Ok(ctx) => ctx,
            Err(e) => return e,
        };
        let device = Arc::clone(&ctx.device);
        let Some(urb) = ctx.urbs.iter_mut().find(|u| u.id == id) else {
            return EINVAL;
        };
        match &urb.state {
            State::Done { .. } | State::Pending(Pending::Stopping) => return 0,
            // A control/configure transfer and a staged interrupt-OUT TRB
            // run to their real completion; the module keeps polling.
            State::Pending(Pending::Future) | State::Pending(Pending::InterruptOut { .. }) => {
                return EBUSY;
            }
            State::Pending(Pending::InterruptIn { .. }) => {
                // The armed TRB stays posted (a kernel page); the next
                // request on this endpoint waits on it again.
                urb.state = State::Done {
                    status: ECANCELED,
                    actual: 0,
                    data: Vec::new(),
                };
                (Some(urb.done), None)
            }
            State::Pending(Pending::Bulk { .. }) => {
                let State::Pending(Pending::Bulk { receipt, .. }) =
                    core::mem::replace(&mut urb.state, State::Pending(Pending::Stopping))
                else {
                    unreachable!("matched Bulk above");
                };
                (None, Some((device, receipt)))
            }
        }
    };
    if let Some(done) = fire_now {
        fire(owner, done);
    }
    if let Some((device, receipt)) = stop {
        narf_scheduler::spawn(async move {
            // A successful stop proves the TD retired without completing;
            // an OUT transfer may still have reached the device first.
            let status = match device.stop_bulk(&receipt).await {
                Ok(()) => ECANCELED,
                Err(e) => errno(e),
            };
            finish(owner, token, id, status, 0, Vec::new());
        });
    }
    0
}

// ── Module-backed serial node ───────────────────────────────────────

fn family(code: u32) -> Option<ChipFamily> {
    match code {
        0 => Some(ChipFamily::Ch341),
        1 => Some(ChipFamily::Ftdi),
        2 => Some(ChipFamily::Pl2303),
        3 => Some(ChipFamily::Cp210x),
        _ => None,
    }
}

fn serial_register(owner: u64, token: u64, code: u32, kick: Completion) -> Result<u32, i32> {
    let chip = family(code).ok_or(EINVAL)?;
    {
        let mut contexts = CONTEXTS.lock();
        let ctx = find(&mut contexts, owner, token)?;
        if ctx.serial.is_some() {
            return Err(EBUSY);
        }
    }
    // Publish outside the context lock (the devfs registry has its own).
    let index = devfs_bridge::register_tty_usb(chip);
    let Ok(index32) = u32::try_from(index) else {
        devfs_bridge::unregister_tty_usb(index);
        return Err(ENOSPC);
    };
    let claimed = {
        let mut contexts = CONTEXTS.lock();
        match find(&mut contexts, owner, token) {
            Ok(ctx) if ctx.serial.is_none() => {
                ctx.serial = Some(index32);
                PORTS.lock().push(ModulePort {
                    index: index32,
                    owner,
                    token,
                    kick,
                });
                Ok(index32)
            }
            Ok(_) => Err(EBUSY),
            Err(e) => Err(e),
        }
    };
    if claimed.is_err() {
        // Retired or raced while publishing: withdraw the node again.
        devfs_bridge::unregister_tty_usb(index);
    }
    claimed
}

fn owned_port(owner: u64, token: u64, port: u32) -> Result<(), i32> {
    let mut contexts = CONTEXTS.lock();
    let ctx = find(&mut contexts, owner, token)?;
    if ctx.serial != Some(port) {
        return Err(EINVAL);
    }
    Ok(())
}

fn serial_tx(owner: u64, token: u64, port: u32, out: &mut [u8]) -> Result<usize, i32> {
    owned_port(owner, token, port)?;
    let node = devfs_bridge::get_port(port as usize).ok_or(ENODEV)?;
    let mut node = node.lock();
    if node.tx_stopped {
        return Ok(0);
    }
    Ok(node.tx.pop(out))
}

fn serial_rx(owner: u64, token: u64, port: u32, data: &[u8]) -> Result<usize, i32> {
    owned_port(owner, token, port)?;
    let node = devfs_bridge::get_port(port as usize).ok_or(ENODEV)?;
    let pushed = node.lock().rx.push(data);
    Ok(pushed)
}

/// A writer queued bytes on `/dev/ttyUSB<index>`. If a module owns that
/// node, run its kick callback (task context, module gate). Called by the
/// devfs node after it released its own lock.
pub(crate) fn serial_kick(index: usize) {
    let kick = PORTS
        .lock()
        .iter()
        .find(|p| p.index as usize == index)
        .map(|p| (p.owner, p.kick));
    if let Some((owner, kick)) = kick {
        fire(owner, kick);
    }
}

/// One step of [`wait`]: `Some(rc)` once the request is terminal (0) or
/// can no longer be waited on, `None` while it is pending.
fn wait_step(owner: u64, token: u64, id: u64) -> Option<i32> {
    let mut contexts = CONTEXTS.lock();
    let ctx = match find(&mut contexts, owner, token) {
        Ok(ctx) => ctx,
        Err(e) => return Some(e),
    };
    let device = Arc::clone(&ctx.device);
    let Some(urb) = ctx.urbs.iter_mut().find(|u| u.id == id) else {
        return Some(EINVAL);
    };
    let State::Pending(pending) = &urb.state else {
        return Some(0);
    };
    let (status, actual, data) = poll_pending(&device, pending)?;
    urb.state = State::Done {
        status,
        actual,
        data,
    };
    Some(0)
}

fn wait(owner: u64, token: u64, id: u64, timeout_ns: u64) -> i32 {
    {
        let mut contexts = CONTEXTS.lock();
        let ctx = match find(&mut contexts, owner, token) {
            Ok(ctx) => ctx,
            Err(e) => return e,
        };
        let Some(urb) = ctx.urbs.iter().find(|u| u.id == id) else {
            return EINVAL;
        };
        // A request with a callback is reported through it; waiting here
        // would swallow that or re-enter the module.
        if urb.done.callback.is_some() {
            return EINVAL;
        }
        match urb.state {
            State::Done { .. } => return 0,
            // Control/configure futures and bulk stops run in kernel tasks;
            // an inline wait cannot drive them.
            State::Pending(Pending::Future) => return EOPNOTSUPP,
            State::Pending(Pending::Stopping) => return EBUSY,
            State::Pending(_) => {}
        }
    }
    let mut rc = ETIMEDOUT;
    let finished = narf_scheduler::responsive_spin_until(
        || match wait_step(owner, token, id) {
            Some(result) => {
                rc = result;
                true
            }
            None => false,
        },
        narf_time::Deadline::after_ns(timeout_ns),
    );
    if finished {
        rc
    } else {
        ETIMEDOUT
    }
}

fn context_live(owner: u64, token: u64) -> bool {
    CONTEXTS
        .lock()
        .iter()
        .any(|c| c.owner == owner && c.token == token)
}

static DATAPATH: Datapath = Datapath {
    config_descriptor,
    configure,
    control,
    transfer,
    poll,
    cancel,
    serial_register,
    serial_tx,
    serial_rx,
    wait,
    context_live,
};

/// Install the datapath hooks behind the `narf_usb_*` exports. Idempotent;
/// called with the registration host at boot.
pub fn install() {
    let _ = module_usb::register_datapath(&DATAPATH);
}

// ── Test introspection ──────────────────────────────────────────────

#[doc(hidden)]
/// Number of live module USB contexts owned by `owner`.
pub fn __context_count_for_test(owner: u64) -> usize {
    CONTEXTS.lock().iter().filter(|c| c.owner == owner).count()
}

#[doc(hidden)]
/// Mint a context outside the probe path, for smokes that exercise the
/// datapath against a real attached device without loading module text.
pub fn __open_for_test(owner: u64, token: u64, device: Arc<USBDevice>, config: &[u8]) -> bool {
    open(owner, token, device, config)
}

#[doc(hidden)]
/// Retire one test context.
pub fn __retire_for_test(token: u64) {
    retire_token(token);
}

#[doc(hidden)]
/// Number of unconsumed requests in one context.
pub fn __urb_count_for_test(owner: u64, token: u64) -> usize {
    find(&mut CONTEXTS.lock(), owner, token).map_or(0, |c| c.urbs.len())
}

#[cfg(feature = "kernel-test")]
#[path = "module_datapath_tests.rs"]
mod tests;
