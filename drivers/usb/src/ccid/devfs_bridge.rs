//! `/dev/ccid<N>` devfs bridge for USB CCID smart-card readers.
//!
//! The CCID class driver ([`crate::ccid`]) binds readers and models
//! the wire protocol (T=0 / T=1, ATR, APDU exchange), but until this
//! bridge nothing in the tree could *reach* a bound reader:
//! `attach.rs` documents a PC/SC consumer attaching via
//! `/dev/ccid0`, yet no such node existed and `power_on` /
//! `send_apdu` had no production caller. This module is that
//! surface:
//!
//! - Each bound reader is published as `/dev/ccid<N>` (node index
//!   = `CCID_READERS` index) through the filesystem's
//!   dynamic-provider hooks (`install_ccid_hooks`, wired by the
//!   `usb-ccid-devfs` Stage::Subsys initcall), mirroring the USB
//!   serial bridge in this crate. A matching
//!   `/sys/class/ccid/ccid<N>/` entry carries `dev` and `slots`.
//! - The node is clone-on-open: every open gets a fresh per-fd
//!   state (current slot, one in-flight response). `write` submits
//!   one raw APDU to the fd's slot via `CcidReader::send_apdu` and
//!   queues the response for `read`; a second `write` while a
//!   response is unread fails `Busy` — the TPM devfs bridge's
//!   one-command-in-flight discipline.
//! - Card power and status go through async ioctls (the `ioctl_user`
//!   override, because power operations await USB transfers). The
//!   command set is NARF-local — Linux has no `/dev/ccid` chardev
//!   (its CCID readers sit behind PC/SC middleware on libusb) —
//!   using `_IOC` type `'C'`:
//!     - `CCID_IOC_POWER_ON` (nr 0): power the fd's slot; the ATR
//!       becomes the pending read data.
//!     - `CCID_IOC_POWER_OFF` (nr 1): power the fd's slot off and
//!       drop any unread response.
//!     - `CCID_IOC_SLOT_STATUS` (nr 2): live `GetSlotStatus` query;
//!       returns bit 0 = card present, bit 1 = card powered,
//!       bit 2 = presence changed since this fd's last
//!       SLOT_STATUS, bits [15:8] = the node's change generation.
//!     - `CCID_IOC_SET_SLOT` (nr 3): `arg` selects the fd's slot
//!       (validated against the reader's slot count).
//! - Slot presence is tracked per node from
//!   `RDR_to_PC_NotifySlotChange` reports. The
//!   `usb-ccid-supervisor` Stage::Late pump
//!   (`spawn_slot_change_pump`) arms each reader's Interrupt-IN
//!   endpoint and feeds reports into `handle_notify_report`;
//!   readers without an interrupt endpoint are polled via
//!   `GetSlotStatus` on a slow divider (`refresh_slot_presence`).
//!   Presence transitions bump the node's change generation, which
//!   surfaces as `POLL_IN` readiness and the SLOT_STATUS changed
//!   bit — no event is discovered-and-dropped.
//!
//! The bridge talks to the class driver through the narrow
//! [`CcidTransport`] seam. Production implements it over the bound
//! `CcidReader` + the global xHCI controller; fixtures register a
//! modelled card and drive the *published surface* (lookup → open →
//! ioctls / read / write) end to end.
//!
//! Deferred (unchanged from the class driver's own list): CCID
//! transport-level chaining (`wLevelParameter`) for APDUs beyond the
//! single-block XfrBlock path, PPS / T=15 negotiation, and
//! `PC_to_RDR_Secure` PIN entry (threat-model review). APDUs and
//! responses within the class driver's 4 KiB cap — including T=0
//! short APDUs and the GET_RESPONSE / T=1 block handling inside
//! `send_apdu_t0` / `send_apdu_t1` — work through the raw surface.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use narf_block::BlockError;
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_IN, POLL_OUT,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::ccid::{self, CcidError, SlotStatus};
use crate::xhci::Xhci;

/// Linux misc major. CCID has no assigned minor; 240+ is the
/// experimental/local range of the misc space (the TPM bridge's
/// tpmrm0 uses 225 in the same major).
pub const CCID_MAJOR: u32 = 10;
/// First misc minor handed out: node `ccid<N>` uses `240 + N`.
pub const CCID_MINOR_BASE: u32 = 240;

// ── ioctls (NARF-local, Linux `_IOC` encoding, type 'C') ────────

const fn ioc(dir: u32, ty: u32, nr: u32) -> u32 {
    (dir << 30) | (ty << 8) | nr
}

/// Power the fd's slot on; the ATR queues as the next `read`.
pub const CCID_IOC_POWER_ON: u32 = ioc(0, 0x43, 0);
/// Power the fd's slot off; drops any unread response.
pub const CCID_IOC_POWER_OFF: u32 = ioc(0, 0x43, 1);
/// Live slot-status query; see the packed return in the module doc.
pub const CCID_IOC_SLOT_STATUS: u32 = ioc(0, 0x43, 2);
/// Select the fd's slot (`arg` = slot index).
pub const CCID_IOC_SET_SLOT: u32 = ioc(0, 0x43, 3);

fn fs_err(_e: CcidError) -> FsError {
    FsError::Io(BlockError::IOError)
}

// ── Transport seam ───────────────────────────────────────────────

/// Boxed future returned by [`CcidTransport`] methods.
pub type CcidFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CcidError>> + Send + 'a>>;

/// The card-side operations the bridge needs from a reader. The
/// production implementation is `XhciTransport` (bound class-driver
/// reader over the global xHCI controller); fixtures implement the
/// same seam with a modelled card so the published surface is
/// exercised without silicon.
pub trait CcidTransport: Send + Sync {
    /// Number of ICC slots on this reader (≥ 1).
    fn num_slots(&self) -> u8;
    /// Power `slot` on; returns the ATR bytes.
    fn power_on<'a>(&'a self, slot: u8) -> CcidFuture<'a, Vec<u8>>;
    /// Power `slot` off.
    fn power_off<'a>(&'a self, slot: u8) -> CcidFuture<'a, ()>;
    /// Exchange one raw APDU with the powered card in `slot`;
    /// returns the raw response (data + SW1SW2).
    fn send_apdu<'a>(&'a self, slot: u8, apdu: &'a [u8]) -> CcidFuture<'a, Vec<u8>>;
    /// Query `slot`'s presence / power state.
    fn slot_status<'a>(&'a self, slot: u8) -> CcidFuture<'a, SlotStatus>;
}

/// Production transport: reader `reader_index` in
/// `ccid::CCID_READERS`, driven over `xhci::controller()`.
#[derive(Debug)]
struct XhciTransport {
    reader_index: usize,
}

impl XhciTransport {
    fn resolve(&self) -> Result<(Arc<ccid::CcidReader>, Arc<Xhci>), CcidError> {
        let reader = ccid::CCID_READERS
            .lock()
            .get(self.reader_index)
            .cloned()
            .ok_or(CcidError::Transfer)?;
        let xhci = crate::xhci::controller().ok_or(CcidError::Transfer)?;
        Ok((reader, xhci))
    }
}

impl CcidTransport for XhciTransport {
    fn num_slots(&self) -> u8 {
        ccid::CCID_READERS
            .lock()
            .get(self.reader_index)
            .map(|r| r.num_slots)
            .unwrap_or(0)
    }

    fn power_on<'a>(&'a self, slot: u8) -> CcidFuture<'a, Vec<u8>> {
        let resolved = self.resolve();
        Box::pin(async move {
            let (reader, xhci) = resolved?;
            reader.power_on(&xhci, slot).await.map(|atr| atr.bytes)
        })
    }

    fn power_off<'a>(&'a self, slot: u8) -> CcidFuture<'a, ()> {
        let resolved = self.resolve();
        Box::pin(async move {
            let (reader, xhci) = resolved?;
            reader.power_off(&xhci, slot).await
        })
    }

    fn send_apdu<'a>(&'a self, slot: u8, apdu: &'a [u8]) -> CcidFuture<'a, Vec<u8>> {
        let resolved = self.resolve();
        let apdu: Vec<u8> = apdu.to_vec();
        Box::pin(async move {
            let (reader, xhci) = resolved?;
            reader.send_apdu(&xhci, slot, &apdu).await
        })
    }

    fn slot_status<'a>(&'a self, slot: u8) -> CcidFuture<'a, SlotStatus> {
        let resolved = self.resolve();
        Box::pin(async move {
            let (reader, xhci) = resolved?;
            reader.get_slot_status(&xhci, slot).await
        })
    }
}

// ── Node registry + presence state ───────────────────────────────

/// Per-node slot-presence state, fed by NotifySlotChange reports
/// and GetSlotStatus refreshes. `change_gen` bumps on every
/// observed presence transition; fds compare it against the
/// generation they last acknowledged.
#[derive(Debug)]
struct CcidShared {
    /// Last known presence per slot (`None` = not yet observed).
    /// Slot indices are masked to 16 — the CCID report format
    /// covers at most 16 slots in practice and the class driver
    /// binds single-interface readers.
    present: [Option<bool>; 16],
    change_gen: u64,
}

impl CcidShared {
    const fn new() -> Self {
        Self {
            present: [None; 16],
            change_gen: 0,
        }
    }

    /// Record `slot`'s presence; returns true when it transitioned.
    fn note_presence(&mut self, slot: u8, present: bool) -> bool {
        let idx = (slot as usize) & 15;
        if self.present[idx] != Some(present) {
            self.present[idx] = Some(present);
            self.change_gen = self.change_gen.wrapping_add(1);
            true
        } else {
            false
        }
    }
}

/// One published reader: its transport plus shared presence state.
pub struct CcidNode {
    transport: Arc<dyn CcidTransport>,
    shared: IrqSafeSpinLock<CcidShared>,
}

impl core::fmt::Debug for CcidNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CcidNode")
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

static CCID_NODES: IrqSafeSpinLock<Vec<Arc<CcidNode>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a transport as the next `/dev/ccid<N>` node and create
/// its sysfs entry. Returns the node index. This is the general
/// registration; production goes through [`register_reader`],
/// fixtures register modelled transports directly.
pub fn register_ccid_transport(transport: Arc<dyn CcidTransport>) -> usize {
    let num_slots = transport.num_slots();
    let node = Arc::new(CcidNode {
        transport,
        shared: IrqSafeSpinLock::new(CcidShared::new()),
    });
    let idx = {
        let mut g = CCID_NODES.lock();
        let idx = g.len();
        g.push(node);
        idx
    };
    register_sysfs(idx, num_slots);
    idx
}

/// Production registration: publish the class-driver reader at
/// `CCID_READERS[reader_index]` as `/dev/ccid<reader_index>`.
/// Called from the bind path, so node index == reader index by
/// construction.
pub fn register_reader(reader_index: usize) -> usize {
    register_ccid_transport(Arc::new(XhciTransport { reader_index }))
}

/// Number of published CCID nodes.
pub fn node_count() -> usize {
    CCID_NODES.lock().len()
}

fn get_node(index: usize) -> Option<Arc<CcidNode>> {
    CCID_NODES.lock().get(index).cloned()
}

/// Last known presence of `slot` on node `index`
/// (`None` = node or observation absent).
pub fn slot_present(index: usize, slot: u8) -> Option<bool> {
    let node = get_node(index)?;
    let sh = node.shared.lock();
    sh.present.get((slot as usize) & 15).copied().flatten()
}

/// Feed a raw `RDR_to_PC_NotifySlotChange` report into node
/// `index`'s presence state. Returns the number of presence
/// transitions applied. This is the production apply path — the
/// supervisor pump calls it for every interrupt-IN report, and the
/// fixtures call it to simulate insert/remove.
pub fn handle_notify_report(index: usize, bytes: &[u8]) -> usize {
    let Some(changes) = ccid::decode_notify_slot_change(bytes) else {
        return 0;
    };
    let Some(node) = get_node(index) else {
        return 0;
    };
    let mut sh = node.shared.lock();
    let mut applied = 0;
    for change in changes {
        if sh.note_presence(change.slot, change.present) {
            applied += 1;
        }
    }
    applied
}

/// One GetSlotStatus presence refresh for node `index`, slot
/// `slot`: queries the transport and folds the result into the
/// shared presence state. This is the pump's fallback path for
/// readers without an interrupt endpoint.
pub async fn refresh_slot_presence(index: usize, slot: u8) -> Result<SlotStatus, CcidError> {
    let node = get_node(index).ok_or(CcidError::Transfer)?;
    let status = node.transport.slot_status(slot).await?;
    node.shared.lock().note_presence(slot, status.present());
    Ok(status)
}

/// Remove every registered node. Test-only: kernel fixtures reset
/// the registry between runs (sysfs state is reset separately via
/// `narf_filesystem::sysfs::__reset_for_test()`).
#[doc(hidden)]
pub fn __reset_for_test() {
    CCID_NODES.lock().clear();
}

// ── sysfs ────────────────────────────────────────────────────────

fn register_sysfs(idx: usize, num_slots: u8) {
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};
    let class = class_register("ccid");
    let name = format!("ccid{}", idx);
    let kobj = class_device_register(class, &name);
    let dev_str = format!("{}:{}\n", CCID_MAJOR, CCID_MINOR_BASE + idx as u32);
    kobject_add_attr(&kobj, "dev", move || dev_str.clone());
    kobject_add_attr(&kobj, "slots", move || format!("{}\n", num_slots));
}

// ── FileOps node ─────────────────────────────────────────────────

/// Per-open state: the fd's selected slot, its one in-flight
/// response, and the change generation it last acknowledged.
#[derive(Debug)]
struct FdState {
    slot: u8,
    response: Vec<u8>,
    response_pending: bool,
    seen_gen: u64,
}

/// `/dev/ccid<N>` file operations. The prototype returned by
/// [`lookup_ccid`] is never used for I/O directly — `open_instance`
/// mints a fresh per-fd instance sharing the node.
#[derive(Debug)]
pub struct CcidFile {
    node: Arc<CcidNode>,
    index: usize,
    state: IrqSafeSpinLock<FdState>,
}

impl CcidFile {
    fn new(node: Arc<CcidNode>, index: usize) -> Self {
        let seen_gen = node.shared.lock().change_gen;
        Self {
            node,
            index,
            state: IrqSafeSpinLock::new(FdState {
                slot: 0,
                response: Vec::new(),
                response_pending: false,
                seen_gen,
            }),
        }
    }
}

impl FileOps for CcidFile {
    fn ino(&self) -> u64 {
        narf_filesystem::devfs::char_device_inode(self.rdev())
    }

    /// Mint a fresh per-open instance so concurrent consumers
    /// never share an in-flight response or slot selection.
    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        Some(Arc::new(CcidFile::new(self.node.clone(), self.index)))
    }

    /// Drain the pending response (APDU response or ATR) into
    /// `buf`. Offset-based, like the TPM bridge: sequential reads
    /// continue where the previous one stopped, and consuming the
    /// last byte clears the pending flag so the next `write` is
    /// accepted.
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = {
            let mut st = self.state.lock();
            if !st.response_pending {
                0
            } else {
                let off = offset as usize;
                if off >= st.response.len() {
                    // Fully consumed on a previous read whose offset
                    // ran past the end: release the slot.
                    st.response_pending = false;
                    st.response.clear();
                    0
                } else {
                    let n = (st.response.len() - off).min(buf.len());
                    buf[..n].copy_from_slice(&st.response[off..off + n]);
                    if off + n >= st.response.len() {
                        st.response_pending = false;
                        st.response.clear();
                    }
                    n
                }
            }
        };
        Box::pin(async move { Ok(n) })
    }

    /// Submit one raw APDU to the fd's slot and queue the response
    /// for `read`. Fails `Busy` while a previous response (or ATR)
    /// is unread — one command in flight per fd.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let (slot, transport) = {
            let st = self.state.lock();
            if st.response_pending {
                return Box::pin(async move { Err(FsError::Busy) });
            }
            (st.slot, self.node.transport.clone())
        };
        let apdu: Vec<u8> = buf.to_vec();
        let len = apdu.len();
        Box::pin(async move {
            let response = transport.send_apdu(slot, &apdu).await.map_err(fs_err)?;
            let mut st = self.state.lock();
            st.response = response;
            st.response_pending = true;
            Ok(len)
        })
    }

    /// Async ioctl surface: POWER_ON / POWER_OFF / SLOT_STATUS /
    /// SET_SLOT (module doc has the contract). The synchronous
    /// `ioctl` keeps the trait default (`Unsupported`): power
    /// operations await USB transfers and cannot run synchronously.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        _ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        let transport = self.node.transport.clone();
        Box::pin(async move {
            match cmd {
                CCID_IOC_POWER_ON => {
                    let slot = self.state.lock().slot;
                    if self.state.lock().response_pending {
                        return Err(FsError::Busy);
                    }
                    let atr = transport.power_on(slot).await.map_err(fs_err)?;
                    let mut st = self.state.lock();
                    st.response = atr;
                    st.response_pending = true;
                    Ok(0)
                }
                CCID_IOC_POWER_OFF => {
                    let slot = self.state.lock().slot;
                    transport.power_off(slot).await.map_err(fs_err)?;
                    let mut st = self.state.lock();
                    st.response.clear();
                    st.response_pending = false;
                    Ok(0)
                }
                CCID_IOC_SLOT_STATUS => {
                    let slot = self.state.lock().slot;
                    let status = transport.slot_status(slot).await.map_err(fs_err)?;
                    let gen = self.node.shared.lock().change_gen;
                    let changed = {
                        let mut st = self.state.lock();
                        let changed = st.seen_gen != gen;
                        st.seen_gen = gen;
                        changed
                    };
                    let mut packed: u64 = 0;
                    if status.present() {
                        packed |= 1 << 0;
                    }
                    if status.powered() {
                        packed |= 1 << 1;
                    }
                    if changed {
                        packed |= 1 << 2;
                    }
                    packed |= (gen & 0xFF) << 8;
                    Ok(packed)
                }
                CCID_IOC_SET_SLOT => {
                    let slot = arg as u8;
                    if slot >= transport.num_slots() {
                        return Err(FsError::NoDevice);
                    }
                    self.state.lock().slot = slot;
                    Ok(0)
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// `st_rdev` = misc major(10) : (240 + node index).
    fn rdev(&self) -> u64 {
        ((CCID_MAJOR as u64) << 8) | (CCID_MINOR_BASE as u64 + self.index as u64)
    }

    /// `POLL_IN` when a response is pending or an unacknowledged
    /// presence change exists; `POLL_OUT` when the fd accepts a
    /// new command.
    fn poll_readiness(&self) -> u32 {
        let st = self.state.lock();
        let gen = self.node.shared.lock().change_gen;
        let mut readiness = 0;
        if st.response_pending || st.seen_gen != gen {
            readiness |= POLL_IN;
        }
        if !st.response_pending {
            readiness |= POLL_OUT;
        }
        readiness
    }
}

// ── Provider lookup / enumerate ──────────────────────────────────

/// Resolve `ccid<N>` to its (prototype) file operations.
pub fn lookup_ccid(name: &str) -> Option<Arc<dyn FileOps>> {
    let idx: usize = name.strip_prefix("ccid")?.parse().ok()?;
    let node = get_node(idx)?;
    Some(Arc::new(CcidFile::new(node, idx)) as Arc<dyn FileOps>)
}

/// Enumerate published nodes for the devfs provider directory.
pub fn enumerate_ccid() -> Vec<(String, FileType)> {
    (0..node_count())
        .map(|i| (format!("ccid{}", i), FileType::Special))
        .collect()
}

// ── Slot-change supervisor pump ──────────────────────────────────

/// Pump cadence, in cycles — the same order as the HID
/// supervisor's poll loop; slot changes are human-speed events.
const PUMP_CYCLES: u64 = 16_000_000;
/// GetSlotStatus fallback runs every Nth pump cycle for readers
/// without an interrupt endpoint.
const STATUS_POLL_DIVIDER: u32 = 32;

/// Spawn the slot-change pump: arms each bound reader's
/// Interrupt-IN endpoint and feeds NotifySlotChange reports into
/// the bridge presence state; readers without the endpoint get a
/// periodic GetSlotStatus refresh. Spawned by the
/// `usb-ccid-supervisor` Stage::Late initcall once xHCI is probed.
pub fn spawn_slot_change_pump() {
    narf_scheduler::spawn_stackful(async {
        let mut armed: Vec<bool> = Vec::new();
        let mut cycle: u32 = 0;
        let mut buf = [0u8; 64];
        loop {
            if let Some(xhci) = crate::xhci::controller() {
                // Clone the Arc list under a short lock; never hold
                // the registry lock across the polls below.
                let readers = ccid::CCID_READERS.lock().clone();
                if armed.len() < readers.len() {
                    armed.resize(readers.len(), false);
                }
                for (i, reader) in readers.iter().enumerate() {
                    let Some(intr) = reader.intr_in_ep else {
                        continue;
                    };
                    if !armed[i] {
                        if reader.arm_slot_change(&xhci).is_ok() {
                            armed[i] = true;
                        }
                        continue;
                    }
                    let mps = (intr.max_packet as usize).clamp(2, buf.len());
                    match reader.poll_slot_change(&xhci, &mut buf[..mps]) {
                        Ok(Some(n)) => {
                            let bytes: Vec<u8> = buf[..n].to_vec();
                            handle_notify_report(i, &bytes);
                        }
                        Ok(None) => {}
                        // A failed drain drops the staged TRB;
                        // re-arm on the next cycle.
                        Err(_) => armed[i] = false,
                    }
                }
                cycle = cycle.wrapping_add(1);
                if cycle % STATUS_POLL_DIVIDER == 0 {
                    for (i, reader) in readers.iter().enumerate() {
                        if reader.intr_in_ep.is_none() {
                            for slot in 0..reader.num_slots {
                                let _ = refresh_slot_presence(i, slot).await;
                            }
                        }
                    }
                }
            }
            narf_time::sleep_cycles(PUMP_CYCLES).await;
        }
    });
}

// ── Kernel-test fixtures ─────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Modelled card side: two slots, scripted ATR + APDU replies.
    /// The conversation fixtures drive this *through the bridge* —
    /// the fake only ever sees transport calls.
    #[derive(Debug)]
    struct FakeCard {
        present: [bool; 2],
        powered: [bool; 2],
    }

    #[derive(Debug)]
    struct FakeTransport {
        card: IrqSafeSpinLock<FakeCard>,
    }

    /// The fake's ATR: TS=0x3B (direct convention), T0 + history.
    const FAKE_ATR: &[u8] = &[0x3B, 0x90, 0x11, 0x00];

    impl FakeTransport {
        fn new(present: bool) -> Arc<Self> {
            Arc::new(Self {
                card: IrqSafeSpinLock::new(FakeCard {
                    present: [present, false],
                    powered: [false, false],
                }),
            })
        }

        fn set_present(&self, slot: u8, present: bool) {
            let mut card = self.card.lock();
            card.present[slot as usize] = present;
            if !present {
                card.powered[slot as usize] = false;
            }
        }
    }

    impl CcidTransport for FakeTransport {
        fn num_slots(&self) -> u8 {
            2
        }

        fn power_on<'a>(&'a self, slot: u8) -> CcidFuture<'a, Vec<u8>> {
            Box::pin(async move {
                let mut card = self.card.lock();
                if !card.present[slot as usize] {
                    // bError 0xFE: ICC mute / not present (§6.2.6).
                    return Err(CcidError::CommandError(0xFE));
                }
                card.powered[slot as usize] = true;
                Ok(FAKE_ATR.to_vec())
            })
        }

        fn power_off<'a>(&'a self, slot: u8) -> CcidFuture<'a, ()> {
            Box::pin(async move {
                self.card.lock().powered[slot as usize] = false;
                Ok(())
            })
        }

        fn send_apdu<'a>(&'a self, slot: u8, apdu: &'a [u8]) -> CcidFuture<'a, Vec<u8>> {
            let apdu: Vec<u8> = apdu.to_vec();
            Box::pin(async move {
                let card = self.card.lock();
                if !card.present[slot as usize] {
                    return Err(CcidError::CommandError(0xFE));
                }
                if !card.powered[slot as usize] {
                    // bError 0xFB: ICC not powered.
                    return Err(CcidError::CommandError(0xFB));
                }
                // Scripted card: SELECT → 9000; READ BINARY →
                // 3 data bytes + 9000; anything else → 6D00.
                let response: &[u8] = match apdu.get(1) {
                    Some(0xA4) => &[0x90, 0x00],
                    Some(0xB0) => &[0x01, 0x02, 0x03, 0x90, 0x00],
                    _ => &[0x6D, 0x00],
                };
                Ok(response.to_vec())
            })
        }

        fn slot_status<'a>(&'a self, slot: u8) -> CcidFuture<'a, SlotStatus> {
            Box::pin(async move {
                let card = self.card.lock();
                let icc_status = if !card.present[slot as usize] {
                    2
                } else if card.powered[slot as usize] {
                    0
                } else {
                    1
                };
                Ok(SlotStatus {
                    icc_status,
                    error: 0,
                    clock_status: 0,
                })
            })
        }
    }

    /// Ioctl context for fixtures: the bridge's ioctls use value
    /// semantics only, so user-memory access is never exercised.
    struct NullCtx;

    impl IoctlContext for NullCtx {
        fn read(&self, _address: u64, _dest: &mut [u8]) -> Result<(), FsError> {
            Err(FsError::BadAddress)
        }
        fn write(&self, _address: u64, _src: &[u8]) -> Result<(), FsError> {
            Err(FsError::BadAddress)
        }
        fn nonblocking(&self) -> bool {
            true
        }
    }

    fn reset() {
        __reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
    }

    fn open(name: &str) -> Arc<dyn FileOps> {
        let proto = lookup_ccid(name).expect("node published");
        proto.open_instance().expect("clone-on-open")
    }

    fn ioctl(fd: &Arc<dyn FileOps>, cmd: u32, arg: u64) -> Result<u64, FsError> {
        narf_scheduler::block_on(fd.ioctl_user(cmd, arg, &NullCtx))
    }

    fn write_apdu(fd: &Arc<dyn FileOps>, apdu: &[u8]) -> Result<usize, FsError> {
        narf_scheduler::block_on(fd.write(0, apdu))
    }

    fn read_all(fd: &Arc<dyn FileOps>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let mut buf = [0u8; 64];
            let n = narf_scheduler::block_on(fd.read(offset, &mut buf)).expect("read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }
        out
    }

    const SELECT_APDU: &[u8] = &[0x00, 0xA4, 0x04, 0x00];
    const READ_APDU: &[u8] = &[0x00, 0xB0, 0x00, 0x00, 0x03];

    /// Registration publishes ccid0; enumeration and lookup agree.
    fn smoke_ccid_bridge_lookup_enumerate() -> TestResult {
        reset();
        if !enumerate_ccid().is_empty() {
            return TestResult::Fail("enumeration should start empty");
        }
        if lookup_ccid("ccid0").is_some() {
            return TestResult::Fail("ccid0 should not resolve before registration");
        }
        let idx = register_ccid_transport(FakeTransport::new(true));
        if idx != 0 || node_count() != 1 {
            return TestResult::Fail("first registration should be node 0");
        }
        let names = enumerate_ccid();
        if names.len() != 1 || names[0].0 != "ccid0" {
            return TestResult::Fail("enumeration should list exactly ccid0");
        }
        if lookup_ccid("ccid0").is_none() {
            return TestResult::Fail("ccid0 should resolve after registration");
        }
        if lookup_ccid("ccid1").is_some() || lookup_ccid("ttyUSB0").is_some() {
            return TestResult::Fail("unregistered names must not resolve");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_lookup_enumerate
    );

    /// The full conversation through the published surface:
    /// open → POWER_ON → ATR → APDU round-trips → Busy discipline
    /// → POWER_OFF → APDU to the unpowered slot fails.
    fn smoke_ccid_bridge_power_apdu_conversation() -> TestResult {
        reset();
        register_ccid_transport(FakeTransport::new(true));
        let fd = open("ccid0");

        if ioctl(&fd, CCID_IOC_POWER_ON, 0) != Ok(0) {
            return TestResult::Fail("POWER_ON should succeed with a card present");
        }
        if read_all(&fd) != FAKE_ATR {
            return TestResult::Fail("first read after POWER_ON should be the ATR");
        }
        if write_apdu(&fd, SELECT_APDU) != Ok(SELECT_APDU.len()) {
            return TestResult::Fail("SELECT write should be accepted");
        }
        if read_all(&fd) != [0x90, 0x00] {
            return TestResult::Fail("SELECT should answer 9000");
        }
        if write_apdu(&fd, READ_APDU) != Ok(READ_APDU.len()) {
            return TestResult::Fail("READ BINARY write should be accepted");
        }
        if read_all(&fd) != [0x01, 0x02, 0x03, 0x90, 0x00] {
            return TestResult::Fail("READ BINARY should answer data + 9000");
        }
        // One command in flight per fd.
        if write_apdu(&fd, SELECT_APDU) != Ok(SELECT_APDU.len()) {
            return TestResult::Fail("write after drain should be accepted");
        }
        if write_apdu(&fd, SELECT_APDU) != Err(FsError::Busy) {
            return TestResult::Fail("second write with unread response should be Busy");
        }
        let _ = read_all(&fd);
        if ioctl(&fd, CCID_IOC_POWER_OFF, 0) != Ok(0) {
            return TestResult::Fail("POWER_OFF should succeed");
        }
        if write_apdu(&fd, SELECT_APDU).is_ok() {
            return TestResult::Fail("APDU to an unpowered slot must fail");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_power_apdu_conversation
    );

    /// Negative paths: power-on and APDU against an empty slot
    /// fail; SLOT_STATUS reports the slot empty.
    fn smoke_ccid_bridge_absent_card() -> TestResult {
        reset();
        register_ccid_transport(FakeTransport::new(false));
        let fd = open("ccid0");

        if ioctl(&fd, CCID_IOC_POWER_ON, 0).is_ok() {
            return TestResult::Fail("POWER_ON against an empty slot must fail");
        }
        if write_apdu(&fd, SELECT_APDU).is_ok() {
            return TestResult::Fail("APDU against an empty slot must fail");
        }
        match ioctl(&fd, CCID_IOC_SLOT_STATUS, 0) {
            Ok(packed) if packed & 0b011 == 0 => {}
            other => {
                return TestResult::Fail(match other {
                    Ok(_) => "SLOT_STATUS should report no card present/powered",
                    Err(_) => "SLOT_STATUS should succeed against an empty slot",
                })
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_absent_card
    );

    /// Slot-change servicing: a NotifySlotChange report fed
    /// through the production apply path updates presence, wakes
    /// pollers (POLL_IN), and the changed bit acknowledges on the
    /// first SLOT_STATUS. Removal is symmetric.
    fn smoke_ccid_bridge_slot_change_events() -> TestResult {
        reset();
        let fake = FakeTransport::new(false);
        let idx = register_ccid_transport(fake.clone());
        let fd = open("ccid0");

        // Insert: slot 0 byte = changed(1) | present(1) = 0b11.
        fake.set_present(0, true);
        if handle_notify_report(idx, &[ccid::RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x03]) != 1 {
            return TestResult::Fail("insert report should apply one transition");
        }
        if slot_present(idx, 0) != Some(true) {
            return TestResult::Fail("presence should record the inserted card");
        }
        if fd.poll_readiness() & POLL_IN == 0 {
            return TestResult::Fail("unacked change should read as POLL_IN");
        }
        match ioctl(&fd, CCID_IOC_SLOT_STATUS, 0) {
            Ok(packed) if packed & (1 << 0) != 0 && packed & (1 << 2) != 0 => {}
            _ => return TestResult::Fail("first SLOT_STATUS: present + changed bits"),
        }
        match ioctl(&fd, CCID_IOC_SLOT_STATUS, 0) {
            Ok(packed) if packed & (1 << 2) == 0 => {}
            _ => return TestResult::Fail("second SLOT_STATUS: changed bit acked"),
        }

        // Removal: slot 0 byte = changed(1) | present(0) = 0b10.
        fake.set_present(0, false);
        if handle_notify_report(idx, &[ccid::RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x02]) != 1 {
            return TestResult::Fail("removal report should apply one transition");
        }
        if slot_present(idx, 0) != Some(false) {
            return TestResult::Fail("presence should record the removal");
        }
        match ioctl(&fd, CCID_IOC_SLOT_STATUS, 0) {
            Ok(packed) if packed & (1 << 0) == 0 && packed & (1 << 2) != 0 => {}
            _ => return TestResult::Fail("SLOT_STATUS after removal: absent + changed"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_slot_change_events
    );

    /// Per-fd isolation: pending responses and slot selection are
    /// per-open state; the card itself is shared.
    fn smoke_ccid_bridge_per_fd_isolation() -> TestResult {
        reset();
        register_ccid_transport(FakeTransport::new(true));
        let fd_a = open("ccid0");
        let fd_b = open("ccid0");

        if ioctl(&fd_a, CCID_IOC_POWER_ON, 0) != Ok(0) {
            return TestResult::Fail("fd_a POWER_ON should succeed");
        }
        let mut buf = [0u8; 8];
        if narf_scheduler::block_on(fd_b.read(0, &mut buf)) != Ok(0) {
            return TestResult::Fail("fd_b must not see fd_a's pending ATR");
        }
        if read_all(&fd_a) != FAKE_ATR {
            return TestResult::Fail("fd_a should drain its own ATR");
        }
        if ioctl(&fd_a, CCID_IOC_SET_SLOT, 1) != Ok(0) {
            return TestResult::Fail("SET_SLOT 1 should succeed (2-slot reader)");
        }
        if write_apdu(&fd_a, SELECT_APDU).is_ok() {
            return TestResult::Fail("fd_a APDU to empty slot 1 must fail");
        }
        if write_apdu(&fd_b, SELECT_APDU) != Ok(SELECT_APDU.len()) {
            return TestResult::Fail("fd_b APDU on slot 0 should still work");
        }
        if ioctl(&fd_b, CCID_IOC_SET_SLOT, 7) != Err(FsError::NoDevice) {
            return TestResult::Fail("SET_SLOT beyond the reader must be NoDevice");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_per_fd_isolation
    );

    /// A second registered reader publishes ccid1 and converses
    /// independently.
    fn smoke_ccid_bridge_second_reader() -> TestResult {
        reset();
        register_ccid_transport(FakeTransport::new(true));
        register_ccid_transport(FakeTransport::new(false));
        if enumerate_ccid().len() != 2 {
            return TestResult::Fail("two registrations should enumerate two nodes");
        }
        let fd0 = open("ccid0");
        let fd1 = open("ccid1");
        if ioctl(&fd0, CCID_IOC_POWER_ON, 0) != Ok(0) {
            return TestResult::Fail("ccid0 POWER_ON should succeed");
        }
        if ioctl(&fd1, CCID_IOC_POWER_ON, 0).is_ok() {
            return TestResult::Fail("ccid1 (empty) POWER_ON must fail");
        }
        if read_all(&fd0) != FAKE_ATR {
            return TestResult::Fail("ccid0 should return its ATR");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_second_reader
    );

    /// The pump's GetSlotStatus fallback path: refresh_slot_presence
    /// folds live status into the shared presence state.
    fn smoke_ccid_bridge_status_poll_refresh() -> TestResult {
        reset();
        let fake = FakeTransport::new(true);
        let idx = register_ccid_transport(fake.clone());
        if slot_present(idx, 0).is_some() {
            return TestResult::Fail("presence should start unobserved");
        }
        match narf_scheduler::block_on(refresh_slot_presence(idx, 0)) {
            Ok(status) if status.present() => {}
            _ => return TestResult::Fail("refresh should report the present card"),
        }
        if slot_present(idx, 0) != Some(true) {
            return TestResult::Fail("refresh should record presence");
        }
        fake.set_present(0, false);
        match narf_scheduler::block_on(refresh_slot_presence(idx, 0)) {
            Ok(status) if !status.present() => {}
            _ => return TestResult::Fail("refresh should report the removal"),
        }
        if slot_present(idx, 0) != Some(false) {
            return TestResult::Fail("refresh should record the removal");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ccid/devfs_bridge",
        smoke_ccid_bridge_status_poll_refresh
    );
}
