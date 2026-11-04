//! Permanent native host for the loadable MT76 copy-mode frontend.
//!
//! The kernel owns async futures, verified firmware, native ring/token/PID
//! joins and actual wiphy/netdev publication. The separately linked image
//! owns only probe/service/operation ids and drives bounded service polls.
use crate::{iface, module_protocol as wire, mt7921};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::Interface;
use narf_wireless::{WirelessError, WirelessNetIface};
use zeroize::Zeroizing;

type NativeWork = Pin<Box<dyn Future<Output = Result<Reply, i32>> + Send>>;
struct Reply {
    bytes: Vec<u8>,
    receive_epoch: Option<u64>,
}
impl Reply {
    fn plain(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            receive_epoch: None,
        }
    }
}
struct Operation {
    id: u64,
    started: bool,
    cancelled: bool,
    future: Option<NativeWork>,
    result: Option<Result<Reply, i32>>,
}
impl Operation {
    fn advance(&mut self, cx: &mut Context<'_>) {
        if let Some(future) = self.future.as_mut() {
            self.started = true;
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                self.future = None;
                self.result = Some(if self.cancelled && result.is_ok() {
                    Err(-114)
                } else {
                    result
                });
            }
        }
    }
    fn request_cancel(&mut self) {
        self.cancelled = true;
        if !self.started {
            self.future = None;
            self.result = Some(Err(-125));
        }
    }
}
struct Received {
    bytes: Vec<u8>,
    epoch: u64,
}
struct Session {
    id: u64,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    generation: AtomicU64,
    closed: AtomicBool,
    operation: Mutex<Option<Operation>>,
    received: IrqSafeSpinLock<VecDeque<Received>>,
}
static SESSIONS: IrqSafeSpinLock<Vec<Arc<Session>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);
const RX_LIMIT: usize = 64;
static HOST: narf_bus::module_wireless::Host = narf_bus::module_wireless::Host {
    family: wire::FAMILY,
    version: wire::VERSION,
    open,
    submit,
    poll,
    cancel,
    close,
};

#[path = "module_tests.rs"]
mod tests;

pub(crate) fn register() {
    let _ = narf_bus::module_wireless::register(&HOST);
}

/// Ordinary boot/reprobe workers must not take over a module's discovery;
/// only its retained INITIALIZE operation drives native firmware startup.
pub(crate) fn owns_discovery() -> bool {
    SESSIONS
        .lock()
        .iter()
        .any(|session| !session.closed.load(Ordering::Acquire))
}
struct Current;
impl CapOp<BusDeviceCap, Write> for Current {
    type Output = ();
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<(), CapError> {
        Ok(())
    }
}
impl Session {
    fn current(&self) -> Result<(), i32> {
        if self.closed.load(Ordering::Acquire)
            || !mt7921::pci::module_generation_current(self.generation.load(Ordering::Acquire))
        {
            return Err(-19);
        }
        self.cap.invoke(Current).map_err(|_| -19)
    }
    fn iface(&self) -> Result<Arc<iface::Mt76Iface>, i32> {
        self.current()?;
        iface::module_active().ok_or(-19)
    }
}
fn session(id: u64) -> Result<Arc<Session>, i32> {
    SESSIONS
        .lock()
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or(-19)
}
fn error(error: WirelessError) -> i32 {
    match error {
        WirelessError::NotSupported => -95,
        WirelessError::Busy => -16,
        WirelessError::Timeout => -110,
        WirelessError::InvalidArgs => -22,
        WirelessError::HardwareError => -5,
        WirelessError::Denied => -13,
    }
}
fn native_error(error: mt7921::firmware_transport::Error) -> i32 {
    use mt7921::firmware_transport::Error;
    match error {
        Error::Busy => -16,
        Error::Authority => -13,
        Error::Bounds => -22,
        Error::DeviceGone => -19,
        Error::Timeout => -110,
        _ => -5,
    }
}
fn open(
    _owner: u64,
    _token: u64,
    id: u64,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), i32> {
    if !((device.id.vendor == mt7921::MTK_VENDOR
        && mt7921::ALL_DEV_IDS.contains(&device.id.device))
        || (device.id.vendor == mt7921::ITTIM_VENDOR && device.id.device == mt7921::MTK_DEV_MT7922))
    {
        return Err(-19);
    }
    cap.invoke(Current).map_err(|_| -19)?;
    let entry = Arc::new(Session {
        id,
        device,
        cap,
        generation: AtomicU64::new(0),
        closed: AtomicBool::new(false),
        operation: Mutex::new(None),
        received: IrqSafeSpinLock::new(VecDeque::new()),
    });
    {
        let mut sessions = SESSIONS.lock();
        if !sessions.is_empty() {
            return Err(-16);
        }
        // Publish the opening lease so a concurrent device teardown can close
        // it. closed is checked again after discovery, before any operation.
        sessions.push(entry.clone());
    }
    let generation = mt7921::pci::module_discover(device, cap)?;
    entry.generation.store(generation, Ordering::Release);
    if entry.closed.load(Ordering::Acquire) {
        mt7921::pci::module_remove(device, cap, generation);
        cap.revoke();
        return Err(-19);
    }
    entry.current()
}

fn submit(id: u64, opcode: u32, request: &[u8]) -> Result<u64, i32> {
    // Malformed/unsupported requests cause no future allocation, native I/O,
    // queue mutation or operation-id publication.
    wire::validate(opcode, request)?;
    let session = session(id)?;
    session.current()?;
    let mut slot = session.operation.try_lock().ok_or(-16)?;
    if slot.is_some() {
        return Err(-16);
    }
    let operation = NEXT_OPERATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| -75)?;
    let bytes = Zeroizing::new(request.to_vec());
    let owner = session.clone();
    let future = Box::pin(async move {
        owner.current()?;
        let reply = execute(&owner, opcode, &bytes).await?;
        owner.current()?;
        Ok(reply)
    });
    *slot = Some(Operation {
        id: operation,
        started: false,
        cancelled: false,
        future: Some(future),
        result: None,
    });
    Ok(operation)
}

fn poll(
    id: u64,
    operation: u64,
    capacity: usize,
    publish: &mut narf_bus::module_wireless::Publish<'_>,
) -> (i32, usize) {
    let session = match session(id) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    if let Err(error) = session.current() {
        return (error, 0);
    }
    let Some(mut slot) = session.operation.try_lock() else {
        return (-11, 0);
    };
    let Some(work) = slot.as_mut().filter(|work| work.id == operation) else {
        return (-22, 0);
    };
    // The module's domain-gated periodic poller drives progress even when
    // the native future's IRQ/timer waker fires between these calls.
    work.advance(&mut Context::from_waker(Waker::noop()));
    if session.current().is_err() {
        return (-19, 0);
    }
    let Some(result) = work.result.as_ref() else {
        return (-11, 0);
    };
    let result = match result {
        Err(error) => (*error, 0),
        Ok(reply) => {
            if capacity < reply.bytes.len() {
                return (-105, reply.bytes.len());
            }
            match reply.receive_epoch {
                Some(epoch) => {
                    publish_received(&reply.bytes, epoch, capacity, publish, |epoch, copy| {
                        mt7921::firmware_transport::boot_receive_publish(epoch, copy)
                    })
                }
                None => match publish(&reply.bytes) {
                    Ok(()) => (0, reply.bytes.len()),
                    Err(error) => (error, 0),
                },
            }
        }
    };
    *slot = None;
    result
}

/// Same final gate for the live boot owner and actual native Session fixtures.
/// The epoch owner encloses the *actual* module-byte copy, not an earlier
/// staging copy or stale scalar observation. The callback only copies bytes.
pub(crate) fn publish_received(
    bytes: &[u8],
    epoch: u64,
    capacity: usize,
    publish: &mut narf_bus::module_wireless::Publish<'_>,
    gate: impl FnOnce(u64, &mut dyn FnMut()) -> Result<bool, mt7921::firmware_transport::Error>,
) -> (i32, usize) {
    if capacity < bytes.len() {
        return (-105, bytes.len());
    }
    let mut result = Err(-19);
    let mut copy = || {
        result = publish(bytes);
    };
    match gate(epoch, &mut copy) {
        Ok(true) => match result {
            Ok(()) => (0, bytes.len()),
            Err(error) => (error, 0),
        },
        Ok(false) => (-19, 0),
        Err(error) => (native_error(error), 0),
    }
}
fn cancel(id: u64, operation: u64) -> i32 {
    let session = match session(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if let Err(error) = session.current() {
        return error;
    }
    let Some(mut slot) = session.operation.try_lock() else {
        return -16;
    };
    let Some(work) = slot.as_mut().filter(|work| work.id == operation) else {
        return -22;
    };
    work.request_cancel();
    // Started native work is never dropped. It reaches its actual terminal
    // result; successful effects are reported EALREADY, never fake Cancelled.
    0
}
fn close(id: u64) {
    let removed = {
        let mut sessions = SESSIONS.lock();
        sessions
            .iter()
            .position(|s| s.id == id)
            .map(|index| sessions.remove(index))
    };
    let Some(session) = removed else {
        return;
    };
    session.closed.store(true, Ordering::Release);
    session.received.lock().clear();
    mt7921::pci::module_remove(
        session.device,
        session.cap,
        session.generation.load(Ordering::Acquire),
    );
    // Stop every subsequent native invocation, including a borrowed future
    // which currently holds BOOT_OWNER. Removal has already parked mastering;
    // uncertain DMA remains retained rather than being freed on revocation.
    session.cap.revoke();
    narf_scheduler::spawn(async move {
        let mut slot = session.operation.lock().await;
        if let Some(work) = slot.as_mut() {
            if work.started {
                if let Some(future) = work.future.take() {
                    let _ = future.await;
                }
            }
        }
        *slot = None;
    });
}

pub(crate) fn capture_receive(name: &str, bytes: &[u8], epoch: u64) {
    let owner = SESSIONS.lock().first().cloned();
    let Some(owner) = owner else {
        return;
    };
    if owner.current().is_err() || bytes.len() > wire::MAX_FRAME {
        return;
    }
    let Ok(iface) = owner.iface() else {
        return;
    };
    if iface.name() != name || !iface::is_active(&iface) {
        return;
    }
    let mut received = owner.received.lock();
    // Bounded independent copy queue; saturation drops this copy only. The
    // normal stack/IPC receive path and its ownership remain unaffected.
    if received.len() < RX_LIMIT {
        received.push_back(Received {
            bytes: bytes.to_vec(),
            epoch,
        });
    }
}

async fn execute(owner: &Arc<Session>, opcode: u32, request: &[u8]) -> Result<Reply, i32> {
    if opcode == wire::INITIALIZE {
        use mt7921::firmware_transport::{boot_status, BootStatus, State};
        let mut attempts = 0;
        let info = loop {
            owner.current()?;
            let result = mt7921::firmware_transport::provision_module_radio_once().await;
            // Check between terminal preflight attempts, never by dropping a
            // native future which has already published hardware ownership.
            owner.current()?;
            attempts += 1;
            match result {
                Ok(info) => break info,
                Err(_)
                    if attempts < 120
                        && matches!(
                            boot_status(),
                            BootStatus::Absent | BootStatus::Retained(State::RadioReady(_))
                        ) =>
                {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
                }
                Err(error) => return Err(native_error(error)),
            }
        };
        owner.current()?;
        let iface = owner.iface()?;
        let name = iface.name().as_bytes();
        let index = narf_net::iface::ifindex_of(iface.name()).ok_or(-19)?;
        if name.is_empty() || name.len() > 70 || !iface::is_active(&iface) {
            return Err(-19);
        }
        let mut bytes = Vec::with_capacity(wire::INIT_FIXED + name.len());
        bytes.extend_from_slice(&wire::VERSION.to_le_bytes());
        bytes.extend_from_slice(&wire::FAMILY.to_le_bytes());
        bytes.extend_from_slice(&info.chip_id.to_le_bytes());
        bytes.push(info.capabilities.phy.bands);
        bytes.push(info.hardware_type);
        bytes.extend_from_slice(&info.capabilities.mac);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&iface.wiphy_id().to_le_bytes());
        bytes.extend_from_slice(&info.firmware.version);
        bytes.extend_from_slice(&info.firmware.build_date);
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(name);
        return Ok(Reply::plain(bytes));
    }
    let iface = owner.iface()?;
    if !iface::is_active(&iface) {
        return Err(-19);
    }
    let reply = match opcode {
        wire::SCAN => {
            let count = usize::from(request[1]);
            let frequencies = (0..count)
                .map(|i| wire::read_u32(request, 8 + i * 4))
                .collect::<Result<Vec<_>, _>>()?;
            let mut cursor = 8 + count * 4;
            let mut ssids = Vec::new();
            for _ in 0..request[2] {
                let len = usize::from(request[cursor]);
                cursor += 1;
                ssids.push(request[cursor..cursor + len].to_vec());
                cursor += len;
            }
            let results = iface
                .scan(narf_wireless::ScanRequest {
                    ssids,
                    frequencies_mhz: frequencies,
                    channels: Vec::new(),
                    active: request[0] != 0,
                    random_mac: None,
                    colocated_6ghz: false,
                    duration_tu: None,
                    duration_mandatory: false,
                    extra_ies: request[cursor..].to_vec(),
                })
                .await
                .map_err(error)?;
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(results.len() as u32).to_le_bytes());
            for result in results {
                if result.ssid.len() > 32 {
                    return Err(-5);
                }
                bytes.extend_from_slice(&result.bssid);
                bytes.push(result.rssi as u8);
                bytes.push(result.ssid.len() as u8);
                bytes.extend_from_slice(&result.frequency_mhz.to_le_bytes());
                bytes.extend_from_slice(&result.channel.to_le_bytes());
                bytes.push(match result.security {
                    narf_wireless::scan::BssSecurity::Open => 0,
                    narf_wireless::scan::BssSecurity::Wep => 1,
                    narf_wireless::scan::BssSecurity::Wpa => 2,
                    narf_wireless::scan::BssSecurity::Wpa2 => 3,
                    narf_wireless::scan::BssSecurity::Wpa3 => 4,
                });
                bytes.extend_from_slice(&result.ssid);
            }
            if bytes.len() > narf_bus::module_wireless::MAX_REPLY {
                return Err(-90);
            }
            Reply::plain(bytes)
        }
        wire::ASSOCIATE => {
            let ssid_len = usize::from(wire::read_u16(request, 12)?);
            let ie_len = usize::from(wire::read_u16(request, 14)?);
            let secret = &request[20 + ssid_len + ie_len..];
            let security = match request[7] {
                0 => narf_wireless::SecurityConfig::Open,
                1 => narf_wireless::SecurityConfig::Wpa2 {
                    psk: secret.try_into().map_err(|_| -22)?,
                },
                2 => narf_wireless::SecurityConfig::Wpa3 {
                    password: secret.to_vec(),
                },
                _ => return Err(-22),
            };
            iface
                .associate(narf_wireless::AssociateRequest {
                    bssid: request[..6].try_into().map_err(|_| -22)?,
                    ssid: request[20..20 + ssid_len].to_vec(),
                    frequency_mhz: wire::read_u32(request, 8)?,
                    channel: u32::from(request[6]),
                    security,
                    ie: request[20 + ssid_len..20 + ssid_len + ie_len].to_vec(),
                })
                .await
                .map_err(error)?;
            Reply::plain(Vec::new())
        }
        wire::DISASSOCIATE => {
            iface.disassociate().await.map_err(error)?;
            Reply::plain(Vec::new())
        }
        wire::TRANSMIT => {
            iface.transmit_frame(request).await.map_err(error)?;
            Reply::plain(Vec::new())
        }
        wire::RECEIVE => {
            let received = owner.received.lock().pop_front();
            match received {
                Some(received) => Reply {
                    bytes: received.bytes,
                    receive_epoch: Some(received.epoch),
                },
                None => Reply::plain(Vec::new()),
            }
        }
        wire::FIRMWARE_CHUNK => Reply::plain(
            mt7921::firmware_transport::module_firmware_chunk(
                request[0],
                wire::read_u32(request, 4)? as usize,
                usize::from(wire::read_u16(request, 2)?),
            )
            .map_err(native_error)?,
        ),
        _ => return Err(-95),
    };
    if !iface::is_active(&iface) {
        return Err(-19);
    }
    Ok(reply)
}
