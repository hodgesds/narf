//! Controller bring-up state machine.
//!
//! Vol 4 Part E §3 prescribes the post-Reset informational sequence
//! every Host runs to learn the controller's capabilities. We model
//! it as an explicit phase enum so the state machine is auditable
//! and resumable on transient transport errors.

use alloc::sync::Arc;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use narf_capabilities::{Cap, CapError, Grant, NoopOp};

use crate::event::CommandComplete;
use crate::hci::{Command, Event};
use crate::opcode;
use crate::transport::{HciTransport, TransportError};
use crate::Bluetooth;

/// Default Event Mask per §7.3.1: 0x0000_1FFF_FFFF_FFFF — every event the
/// host is interested in for a generic bring-up. Shared by bring-up
/// and mgmt power-on (issue #815) so the two cannot drift apart.
pub const DEFAULT_EVENT_MASK: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00, 0x00];

/// Phases a controller passes through during bring-up.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringupPhase {
    Reset = 0,
    ReadLocalVersion = 1,
    ReadBdAddr = 2,
    ReadBufferSize = 3,
    SetEventMask = 4,
    /// HCI_Read_Local_Name (§7.4.14) — the name mgmt READ_INFO
    /// reports (issue #815). Informational, after the mandatory
    /// sequence; a controller that cannot answer it fails bring-up
    /// rather than reporting a zeroed name.
    ReadLocalName = 5,
    /// HCI_Read_Class_Of_Device (§7.4.23) — the class mgmt READ_INFO
    /// reports (issue #815). Same discipline as the local name.
    ReadClassOfDevice = 6,
    Ready = 7,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringupError {
    AuthorityRevoked,
    Transport(TransportError),
    /// Controller's Command Complete carried a non-zero HCI Status.
    BadStatus {
        phase: BringupPhase,
        status: u8,
    },
    /// Controller responded with an unexpected event during a phase.
    UnexpectedEvent {
        phase: BringupPhase,
        code: u8,
    },
    /// Got Command Complete for an opcode we didn't issue.
    OpcodeMismatch {
        phase: BringupPhase,
        got: u16,
    },
}

impl From<CapError> for BringupError {
    fn from(_: CapError) -> Self {
        BringupError::AuthorityRevoked
    }
}

impl From<TransportError> for BringupError {
    fn from(e: TransportError) -> Self {
        BringupError::Transport(e)
    }
}

/// Controller-supplied capabilities collected during bring-up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ControllerInfo {
    /// 6-byte BD_ADDR (LE on the wire). All-zero until ReadBdAddr completes.
    pub bd_addr: [u8; 6],
    /// HCI version byte from §7.4.1.
    pub hci_version: u8,
    /// 16-bit HCI revision (LE).
    pub hci_revision: u16,
    /// LMP version byte.
    pub lmp_version: u8,
    /// Manufacturer ID (LE).
    pub manufacturer: u16,
    /// LMP subversion (LE).
    pub lmp_subversion: u16,
    /// HC ACL data MTU. From §7.4.5; 0 until ReadBufferSize completes.
    pub acl_data_mtu: u16,
    /// HC SCO data MTU.
    pub sco_data_mtu: u8,
    /// Number of HC ACL data buffers.
    pub acl_total_num: u16,
    /// Number of HC SCO data buffers.
    pub sco_total_num: u16,
    /// 3-byte Class of Device (§7.4.23). All-zero until
    /// ReadClassOfDevice completes; mgmt READ_INFO reports this
    /// verbatim, so a zero here means "not yet read", never a
    /// fabricated class (issue #815).
    pub dev_class: [u8; 3],
    /// 248-byte local name (§7.4.14, NUL-padded). All-zero until
    /// ReadLocalName completes; mgmt READ_INFO reports this verbatim
    /// (issue #815).
    pub local_name: [u8; 248],
    /// 10-byte short name (the first 10 bytes of the mgmt short
    /// name, without its NUL). The controller has no short-name
    /// concept: this stays zero until userspace sets one via mgmt
    /// SET_LOCAL_NAME, matching Linux (an unset short name reads
    /// back empty). mgmt READ_INFO reports this verbatim.
    pub short_name: [u8; 10],
}

// NOTE: no #[derive(Default)] — the pinned toolchain caps array
// `Default` at 32 elements and `local_name` is [u8; 248] (see
// AGENTS.md). Keep this in sync with the struct fields above.
impl Default for ControllerInfo {
    fn default() -> Self {
        Self {
            bd_addr: [0; 6],
            hci_version: 0,
            hci_revision: 0,
            lmp_version: 0,
            manufacturer: 0,
            lmp_subversion: 0,
            acl_data_mtu: 0,
            sco_data_mtu: 0,
            acl_total_num: 0,
            sco_total_num: 0,
            dev_class: [0; 3],
            local_name: [0; 248],
            short_name: [0; 10],
        }
    }
}

#[derive(Debug)]
pub struct Controller {
    transport: Arc<dyn HciTransport>,
    phase: AtomicU8,
    info: narf_lib::sync::IrqSafeSpinLock<ControllerInfo>,
    /// Set by [`unregister_controller`] before anything else is torn
    /// down. The registry slot stays in place (HCI ordinals are
    /// index-stable — see `CONTROLLERS`) so a detached controller
    /// never shifts a live controller's index; the flag is what
    /// makes the slot dead. A later registration reuses the slot.
    detached: AtomicBool,
}

impl Controller {
    pub fn new(transport: Arc<dyn HciTransport>) -> Self {
        Self {
            transport,
            phase: AtomicU8::new(BringupPhase::Reset as u8),
            info: narf_lib::sync::IrqSafeSpinLock::new(ControllerInfo::default()),
            detached: AtomicBool::new(false),
        }
    }

    /// Whether [`unregister_controller`] has detached this controller.
    /// A detached controller's pump is gone, its transport is
    /// unregistered, and its sysfs node is removed; only the
    /// registry slot (and this flag) survives, until a later
    /// registration reuses the index.
    pub fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }

    pub fn phase(&self) -> BringupPhase {
        let v = self.phase.load(Ordering::Acquire);
        // SAFETY: `BringupPhase` is `#[repr(u8)]` and `self.phase` is only
        // ever stored as one of its discriminants (0..=7), so `v` is a valid
        // bit pattern for the enum.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::mem::transmute(v) }
    }

    pub fn info(&self) -> ControllerInfo {
        *self.info.lock()
    }

    /// The controller's HCI transport — used by raw/user HCI sockets to send
    /// commands and drain events directly.
    pub fn transport(&self) -> Arc<dyn HciTransport> {
        self.transport.clone()
    }

    /// Drive the bring-up sequence to completion. Each step issues a
    /// Mandatory command, waits for `HCI_Command_Complete`, and
    /// records the controller's response.
    pub fn bring_up(&self, cap: &Cap<Bluetooth, Grant>) -> Result<ControllerInfo, BringupError> {
        cap.invoke(NoopOp)?;

        self.run_phase(BringupPhase::Reset, opcode::HCI_RESET, &[], |_, _| Ok(()))?;

        self.run_phase(
            BringupPhase::ReadLocalVersion,
            opcode::HCI_READ_LOCAL_VERSION,
            &[],
            |info, ret| {
                // Status (1) + HCI_Version (1) + HCI_Revision (2) +
                // LMP_Version (1) + Manufacturer (2) + LMP_Subversion (2)
                if ret.len() < 9 {
                    return Err(BringupError::UnexpectedEvent {
                        phase: BringupPhase::ReadLocalVersion,
                        code: 0,
                    });
                }
                info.hci_version = ret[1];
                info.hci_revision = u16::from_le_bytes([ret[2], ret[3]]);
                info.lmp_version = ret[4];
                info.manufacturer = u16::from_le_bytes([ret[5], ret[6]]);
                info.lmp_subversion = u16::from_le_bytes([ret[7], ret[8]]);
                Ok(())
            },
        )?;

        self.run_phase(
            BringupPhase::ReadBdAddr,
            opcode::HCI_READ_BD_ADDR,
            &[],
            |info, ret| {
                // Status (1) + BD_ADDR (6).
                if ret.len() < 7 {
                    return Err(BringupError::UnexpectedEvent {
                        phase: BringupPhase::ReadBdAddr,
                        code: 0,
                    });
                }
                info.bd_addr.copy_from_slice(&ret[1..7]);
                Ok(())
            },
        )?;

        self.run_phase(
            BringupPhase::ReadBufferSize,
            opcode::HCI_READ_BUFFER_SIZE,
            &[],
            |info, ret| {
                // Status (1) + ACL_MTU (2) + SCO_MTU (1) + ACL_count (2) + SCO_count (2).
                if ret.len() < 8 {
                    return Err(BringupError::UnexpectedEvent {
                        phase: BringupPhase::ReadBufferSize,
                        code: 0,
                    });
                }
                info.acl_data_mtu = u16::from_le_bytes([ret[1], ret[2]]);
                info.sco_data_mtu = ret[3];
                info.acl_total_num = u16::from_le_bytes([ret[4], ret[5]]);
                info.sco_total_num = u16::from_le_bytes([ret[6], ret[7]]);
                Ok(())
            },
        )?;

        self.run_phase(
            BringupPhase::SetEventMask,
            opcode::HCI_SET_EVENT_MASK,
            &DEFAULT_EVENT_MASK,
            |_, _| Ok(()),
        )?;

        // Local name + Class of Device (§7.4.14/§7.4.23): the
        // identity mgmt READ_INFO reports. Informational, not part
        // of the §3 mandatory sequence, but read here so the
        // registry never advertises a zeroed name/class for a
        // controller that knows its own (issue #815).
        self.run_phase(
            BringupPhase::ReadLocalName,
            opcode::HCI_READ_LOCAL_NAME,
            &[],
            |info, ret| {
                // Status (1) + Local_Name (248).
                if ret.len() < 249 {
                    return Err(BringupError::UnexpectedEvent {
                        phase: BringupPhase::ReadLocalName,
                        code: 0,
                    });
                }
                info.local_name.copy_from_slice(&ret[1..249]);
                Ok(())
            },
        )?;

        self.run_phase(
            BringupPhase::ReadClassOfDevice,
            opcode::HCI_READ_CLASS_OF_DEVICE,
            &[],
            |info, ret| {
                // Status (1) + Class_Of_Device (3).
                if ret.len() < 4 {
                    return Err(BringupError::UnexpectedEvent {
                        phase: BringupPhase::ReadClassOfDevice,
                        code: 0,
                    });
                }
                info.dev_class.copy_from_slice(&ret[1..4]);
                Ok(())
            },
        )?;

        self.phase
            .store(BringupPhase::Ready as u8, Ordering::Release);
        Ok(*self.info.lock())
    }

    /// Issue one HCI command and wait for its Command Complete,
    /// returning the return parameters (status byte first).
    ///
    /// The synchronous issuance path mgmt uses (issue #815): the
    /// same send + polled-wait discipline as bring-up. Callers must
    /// hold no `IrqSafeSpinLock` across this call — the wait halts
    /// on IRQs (see the `block_on` lock rule in the repo AGENTS.md).
    ///
    /// Known limit, not a silent assumption: while the pump task is
    /// draining this transport's events, the completion can be
    /// consumed by the pump instead of this waiter (and vice versa
    /// for pump events). The waiter then times out after the
    /// bring-up budget and reports failure even though the command
    /// was issued. A single command path (pump/CmdQueue) is the
    /// follow-up; mgmt fixtures run pump-less, where the wait is
    /// exact.
    pub fn issue_command(
        &self,
        opcode: u16,
        params: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, BringupError> {
        let cmd = Command::with_params(opcode, params);
        self.transport.send_command(&cmd)?;
        let event = self.wait_for_event()?;
        let cc = CommandComplete::parse(&event).ok_or(BringupError::UnexpectedEvent {
            phase: self.phase(),
            code: event.code,
        })?;
        if cc.opcode != opcode {
            return Err(BringupError::OpcodeMismatch {
                phase: self.phase(),
                got: cc.opcode,
            });
        }
        let status = cc.status().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(BringupError::BadStatus {
                phase: self.phase(),
                status,
            });
        }
        Ok(cc.return_params.to_vec())
    }

    /// Record a Class of Device written via mgmt SET_DEV_CLASS
    /// (issue #815): the stored copy is what READ_INFO reports and
    /// what power-on re-applies.
    pub fn set_dev_class(&self, class: [u8; 3]) {
        self.info.lock().dev_class = class;
    }

    /// Record a local name written via mgmt SET_LOCAL_NAME (issue
    /// #815): the stored copies are what READ_INFO reports and what
    /// power-on re-applies.
    pub fn set_local_name(&self, name: [u8; 248], short_name: [u8; 10]) {
        let mut info = self.info.lock();
        info.local_name = name;
        info.short_name = short_name;
    }

    fn run_phase<F>(
        &self,
        phase: BringupPhase,
        op: u16,
        params: &[u8],
        mut on_complete: F,
    ) -> Result<(), BringupError>
    where
        F: FnMut(&mut ControllerInfo, &[u8]) -> Result<(), BringupError>,
    {
        self.phase.store(phase as u8, Ordering::Release);
        let ret = self.issue_command(op, params)?;
        let mut info = self.info.lock();
        on_complete(&mut info, &ret)?;
        Ok(())
    }

    fn wait_for_event(&self) -> Result<Event, BringupError> {
        // Polled wait. Real transports park the executor; the
        // loopback transport returns immediately. The controller's
        // bring-up budget is generous (per Vol 4 Part E §6 the
        // command-complete timeout is ≥ 5 s on a real controller).
        // responsive_spin_until ticks sleep_pumps so cursor/FB/serial
        // stay alive across the multi-second budget. 5 s spec
        // upper bound (Vol 4 Part E §6) + a small overhead margin.
        let mut got: Option<Event> = None;
        let mut transport_err: Option<TransportError> = None;
        let _ = narf_scheduler::responsive_spin_until(
            || match self.transport.recv_event() {
                Ok(Some(e)) => {
                    got = Some(e);
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    transport_err = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_ms(5_500),
        );
        if let Some(e) = transport_err {
            return Err(BringupError::Transport(e));
        }
        got.ok_or(BringupError::Transport(TransportError::Timeout))
    }
}

// ── Brought-up controller registry ──────────────────────────────────

/// Controllers that have completed [`Controller::bring_up`].
///
/// Index-stable by position: the HCI ordinal is the slot position,
/// and detaching a controller tombstones its slot (see
/// [`Controller::is_detached`]) instead of removing it, so a
/// detach never shifts a live controller's ordinal. A later
/// registration reuses the first tombstoned slot, so the vector is
/// bounded by the peak number of simultaneously-live controllers.
/// [`controllers`] returns every slot including tombstoned ones;
/// use [`get_live`] / [`live_indices`] when only live controllers
/// may be observed.
static CONTROLLERS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<Arc<Controller>>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Every controller brought up so far, by HCI ordinal — including
/// detached (tombstoned) slots. Index-stable: `controllers()[i]`
/// is always the controller for ordinal `i`, live or detached.
pub fn controllers() -> alloc::vec::Vec<Arc<Controller>> {
    CONTROLLERS.lock().clone()
}

/// The live controller at ordinal `index`, or `None` when the slot
/// is out of range or its controller has been detached.
pub fn get_live(index: usize) -> Option<Arc<Controller>> {
    let controllers = CONTROLLERS.lock();
    let controller = controllers.get(index)?;
    if controller.is_detached() {
        return None;
    }
    Some(controller.clone())
}

/// Whether ordinal `index` currently names a live controller.
pub fn is_live(index: usize) -> bool {
    get_live(index).is_some()
}

/// Ordinals of the live controllers, in order. This is what mgmt
/// `READ_INDEX_LIST` reports: a detached ordinal disappears from
/// the list instead of shifting the ordinals after it.
pub fn live_indices() -> alloc::vec::Vec<usize> {
    CONTROLLERS
        .lock()
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.is_detached())
        .map(|(i, _)| i)
        .collect()
}

/// Number of live (not detached) controllers.
pub fn controller_count() -> usize {
    CONTROLLERS
        .lock()
        .iter()
        .filter(|c| !c.is_detached())
        .count()
}

/// Adopt a transport whose driver already completed the mandatory HCI
/// bring-up asynchronously.
///
/// USB devices are discovered by the Stage::Late supervisor after the
/// synchronous `bluetooth-bringup` initcall has run. Re-running
/// [`Controller::bring_up`] through the synchronous transport trait from that
/// executor task would trip `block_on`'s re-entrancy guard, so the USB driver
/// performs the same command sequence on its native async transfer path and
/// registers the resulting ready controller here.
///
/// Idempotent by transport pointer identity among LIVE controllers.
/// Returns the stable HCI ordinal. A detached slot is reused for a
/// fresh registration (same ordinal, fresh controller) — a
/// re-registration of a detached transport is a new bind, never a
/// resurrection of the detached controller's state.
pub fn register_ready_transport(transport: Arc<dyn HciTransport>, info: ControllerInfo) -> usize {
    let mut controllers = CONTROLLERS.lock();
    if let Some(index) = controllers.iter().position(|controller| {
        !controller.is_detached() && Arc::ptr_eq(&controller.transport, &transport)
    }) {
        return index;
    }

    let controller = Arc::new(Controller::new(transport));
    *controller.info.lock() = info;
    controller
        .phase
        .store(BringupPhase::Ready as u8, Ordering::Release);
    let index = match controllers.iter().position(|c| c.is_detached()) {
        Some(slot) => {
            controllers[slot] = controller;
            slot
        }
        None => {
            controllers.push(controller);
            controllers.len() - 1
        }
    };
    drop(controllers);
    // Publish /sys/class/bluetooth/hci<index> (Linux hci_register_dev also
    // creates the sysfs device on registration).
    let _ = crate::sysfs_bridge::register_hci_controller(index, info, &[]);
    // Tell any open mgmt socket a controller appeared (MGMT_EV_INDEX_ADDED).
    narf_filesystem::bluetooth::publish_mgmt_event(&crate::mgmt::index_added(index as u16));
    // Start the HCI event/ACL pump for this controller (task spawn
    // happens only once the Stage::Late bluetooth-pump initcall has
    // enabled it; before that the pump is registered for fixtures).
    crate::pump::notify_controller_ready(index);
    index
}

/// Whether `transport` already backs a brought-up controller.
///
/// Compared by `Arc` pointer identity rather than by name: two
/// controllers of the same kind share a transport name, and bringing
/// the second one up is not a duplicate.
fn already_brought_up(transport: &Arc<dyn HciTransport>) -> bool {
    CONTROLLERS
        .lock()
        .iter()
        .any(|c| Arc::ptr_eq(&c.transport, transport))
}

/// Outcome of one controller's bring-up, for the boot transcript.
#[derive(Debug)]
pub struct BringupOutcome {
    /// The transport's name.
    pub transport: &'static str,
    /// What the bring-up sequence returned.
    pub result: Result<ControllerInfo, BringupError>,
}

/// Run [`Controller::bring_up`] against every registered transport
/// that does not already back a controller.
///
/// Idempotent: a transport that has already been brought up is
/// skipped, so running this twice — or running it after a driver has
/// brought up its own controller — does not reset a working adapter.
///
/// A failure on one transport does not stop the others: a dongle that
/// does not answer should not keep an onboard controller offline.
pub fn bring_up_all(cap: &Cap<Bluetooth, Grant>) -> alloc::vec::Vec<BringupOutcome> {
    let mut out = alloc::vec::Vec::new();
    for t in crate::transport::transports() {
        if already_brought_up(&t) {
            continue;
        }
        let name = t.name();
        let controller = Arc::new(Controller::new(t));
        let result = controller.bring_up(cap);
        if let Ok(info) = &result {
            let info = *info;
            let mut controllers = CONTROLLERS.lock();
            // Reuse a tombstoned slot when one exists, so the
            // vector stays bounded and the ordinal is stable.
            let index = match controllers.iter().position(|c| c.is_detached()) {
                Some(slot) => {
                    controllers[slot] = controller;
                    slot
                }
                None => {
                    controllers.push(controller);
                    controllers.len() - 1
                }
            };
            drop(controllers);
            // Mirror the controller into /sys/class/bluetooth/hci<index>.
            let _ = crate::sysfs_bridge::register_hci_controller(index, info, &[]);
            narf_filesystem::bluetooth::publish_mgmt_event(&crate::mgmt::index_added(index as u16));
            crate::pump::notify_controller_ready(index);
        }
        out.push(BringupOutcome {
            transport: name,
            result,
        });
    }
    out
}

/// Detach composition (issue #890): tear a controller down in full
/// when its USB device is unbound.
///
/// Order is load-bearing and fail-closed:
///
/// 1. Tombstone the registry slot FIRST (the linearization point).
///    From here on the controller is invisible to every live-only
///    lookup (`get_live`, `is_live`, `live_indices`,
///    `controller_count`, mgmt, hci_sock, the pump), so an event
///    arriving mid-teardown — a Disconnection Complete, a
///    re-registration of the same transport — cannot resurrect
///    it: the pump core is dropped with its connection table, and
///    a re-registration lands as a FRESH controller reusing the
///    slot, never as the detached one's state coming back.
/// 2. Stop + remove the pump: the task observes the missing slot
///    (`stop_requested` is true when no slot exists) and exits at
///    its next iteration boundary; a step already in flight
///    finishes against the detached core and then drops it when
///    the slot is gone, so the transport is quiescent afterwards.
/// 3. Unregister the transport, so a later [`bring_up_all`] pass
///    cannot re-bring-up the dead transport.
/// 4. Remove the sysfs node, then forget the mgmt settings.
/// 5. Publish mgmt `INDEX_REMOVED` LAST, so a userspace observer
///    that sees the event already finds everything gone.
///
/// Idempotent: detaching an unknown or already-detached ordinal
/// returns `false` and changes nothing. Returns `true` when this
/// call performed the detach.
///
/// This removes the controller from the Bluetooth side only. The
/// USB-side registry entry (`BTUSB_DEVICES`) is removed by the
/// btusb detach hook, which calls this after dropping its entry.
pub fn unregister_controller(index: usize) -> bool {
    // 1. Tombstone first.
    let transport = {
        let controllers = CONTROLLERS.lock();
        let Some(controller) = controllers.get(index) else {
            return false;
        };
        if controller.detached.swap(true, Ordering::AcqRel) {
            return false;
        }
        controller.transport.clone()
    };
    // 2. Pump teardown (quiesce + drop the core).
    crate::pump::stop_pump(index);
    let _ = crate::pump::remove_pump(index);
    // 3. Transport unregistration.
    let _ = crate::transport::unregister(&transport);
    // 4. Sysfs node + mgmt settings.
    let _ = crate::sysfs_bridge::unregister_hci_controller(index);
    crate::mgmt::forget_settings(index as u16);
    // 5. INDEX_REMOVED, last.
    narf_filesystem::bluetooth::publish_mgmt_event(&crate::mgmt::index_removed(index as u16));
    true
}

#[doc(hidden)]
/// Test-only: drain the brought-up registry.
pub fn __test_reset_controllers() {
    CONTROLLERS.lock().clear();
}
