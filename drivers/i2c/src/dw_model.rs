//! Behavioural DesignWare APB I2C model for the fixture lane
//! (#1029) — the register-level fake both DW drivers' transfer
//! state machines run against in smokes.
//!
//! Before this model, the i2c fixtures backed MMIO with a flat
//! `[u32; 64]` array: `IC_DATA_CMD` writes overwrote each other,
//! `IC_STATUS` never evolved, `IC_TX_ABRT_SOURCE` never raised, and
//! neither wrapper's transfer loop had ever executed end-to-end.
//! This model is the swtpm/keystone pattern applied to DW I2C: a
//! register file whose *behaviour* follows the DW_apb_i2c databook
//! semantics the production code assumes, plus a virtual target
//! device on the other end of the bus.
//!
//! Fidelity choices (and their limits):
//! - TX / RX FIFOs are [`FIFO_DEPTH`] entries, matching the depth
//!   the FCH driver documents for its silicon. Writes to
//!   `IC_DATA_CMD` push `{read, stop, data}` commands; reads pop
//!   the RX FIFO. `IC_STATUS` / `IC_TXFLR` / `IC_RXFLR` are computed
//!   from FIFO state on every read, never stored.
//! - The wire engine advances on register *reads*. Every wait in
//!   both drivers is a poll loop over status registers, so reads
//!   are the model's clock: on each read the engine processes
//!   queued commands (address phase, byte delivery, STOP) until it
//!   stalls. A read command stalls while the RX FIFO is full —
//!   that stall is what forces the driver's issue/drain interleave
//!   across FIFO-depth boundaries, exactly as wire timing does on
//!   silicon. Writes never advance the engine: the wire is slower
//!   than register writes, which is why a fast producer can fill
//!   the TX FIFO (see the cadence knob below).
//! - Address phase: the first command of a phase (bus idle, or the
//!   direction changed since the current phase) looks the target
//!   up by `IC_TAR`. Absent or NAK-ing target → `ABRT_7B_ADDR_NOACK`
//!   abort. Direction change mid-transfer → repeated START (the
//!   event log records `Restart`); same-direction commands after a
//!   FIFO drain simply continue the phase — one of the two bus
//!   conversations silicon can produce, chosen deterministically.
//! - Data NAK from the target → `ABRT_TXDATA_NOACK`. Any abort
//!   latches `IC_RAW_INTR_STAT.TX_ABRT` + `IC_TX_ABRT_SOURCE`,
//!   flushes the TX FIFO, and issues STOP, per the databook; the
//!   latch clears when the driver reads `IC_CLR_TX_ABRT` (which is
//!   exactly the production `check_abort` path).
//! - Fault knobs for the drivers' error paths: `set_stretch`
//!   freezes the engine for N read accesses (a target holding SCL
//!   low); `set_pump` rate-limits the engine (a slow wire, so the
//!   TX FIFO genuinely fills and the driver's TFNF wait engages);
//!   `inject_abort` raises a caller-chosen `IC_TX_ABRT_SOURCE` at
//!   the next address phase (arbitration loss and the generic
//!   `I2cError::Abort` path cannot be produced by a well-behaved
//!   single target, so they are injected, not simulated).
//! - Not modelled: `IC_COMP_PARAM_1` (no production path reads it),
//!   the config-register write lock while enabled (no production
//!   path relies on it; config writes are accepted leniently),
//!   10-bit addressing (neither driver programs it), and
//!   interrupt-line signalling (both drivers poll).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::dw::DwRegs;

// ── Register offsets (mirror the drivers' maps) ──────────────────
const IC_TAR: u64 = 0x04;
const IC_DATA_CMD: u64 = 0x10;
const IC_INTR_STAT: u64 = 0x2c;
const IC_INTR_MASK: u64 = 0x30;
const IC_RAW_INTR_STAT: u64 = 0x34;
const IC_RX_TL: u64 = 0x38;
const IC_CLR_INTR: u64 = 0x40;
const IC_CLR_TX_ABRT: u64 = 0x54;
const IC_ENABLE: u64 = 0x6c;
const IC_STATUS: u64 = 0x70;
const IC_TXFLR: u64 = 0x74;
const IC_RXFLR: u64 = 0x78;
const IC_TX_ABRT_SOURCE: u64 = 0x80;
const IC_ENABLE_STATUS: u64 = 0x9c;
const IC_COMP_TYPE: u64 = 0xfc;

const DATA_CMD_READ: u32 = 1 << 8;
const DATA_CMD_STOP: u32 = 1 << 9;

const DW_COMP_TYPE_MAGIC: u32 = 0x4457_0140;

/// FIFO depth of the modelled core — the depth the AMD FCH driver
/// documents for its silicon ("the DW core's RX FIFO is 16-deep on
/// the AMD FCH").
pub const FIFO_DEPTH: usize = 16;

// ── IC_TX_ABRT_SOURCE bits the engine raises itself ──────────────
const ABRT_7B_ADDR_NOACK: u32 = 1 << 0;
const ABRT_TXDATA_NOACK: u32 = 1 << 3;

/// One observed bus event at a virtual target, in wire order.
/// Fixtures assert on this log to prove the conversation the
/// production driver actually held (START/STOP envelope, repeated
/// START on direction change, which bytes moved which way).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BusEvent {
    /// Address phase ACKed, bus was idle: a fresh START.
    Start { read: bool },
    /// Address phase ACKed while the bus was already held: a
    /// repeated START (direction change inside one transfer).
    Restart { read: bool },
    /// A byte the master wrote and the target ACKed (register
    /// pointer bytes included — they are bus bytes).
    WriteByte(u8),
    /// A byte the target returned for a read command.
    ReadByte(u8),
    /// The target NAKed its address phase.
    AddrNak,
    /// The target NAKed this data byte; the controller aborted.
    DataNak(u8),
    /// STOP issued (end of transfer, or the post-abort STOP).
    Stop,
}

/// A virtual I2C target device with register-file semantics, like
/// the sensor / HID parts these buses exist to serve: the first
/// `reg_addr_bytes` bytes of a write phase set the register
/// pointer (little-endian), subsequent bytes store at `ptr++`,
/// and reads return `regs[ptr++]`.
#[derive(Debug)]
pub struct VirtualTarget {
    addr: u8,
    reg_addr_bytes: usize,
    regs: BTreeMap<u16, u8>,
    ptr: u16,
    ptr_bytes_seen: usize,
    data_bytes_seen: usize,
    nak_address: bool,
    nak_data_after: Option<usize>,
    events: Vec<BusEvent>,
}

impl VirtualTarget {
    pub fn new(addr: u8, reg_addr_bytes: usize) -> Self {
        Self {
            addr,
            reg_addr_bytes,
            regs: BTreeMap::new(),
            ptr: 0,
            ptr_bytes_seen: 0,
            data_bytes_seen: 0,
            nak_address: false,
            nak_data_after: None,
            events: Vec::new(),
        }
    }

    /// Plant register contents (e.g. a HID descriptor) before the
    /// target is attached to the model.
    pub fn load(&mut self, start: u16, bytes: &[u8]) -> &mut Self {
        for (i, &b) in bytes.iter().enumerate() {
            self.regs.insert(start.wrapping_add(i as u16), b);
        }
        self
    }

    /// Make the target NAK its address phase (a device that is
    /// held in reset / powered down but still on the bus).
    pub fn set_nak_address(&mut self, nak: bool) -> &mut Self {
        self.nak_address = nak;
        self
    }

    /// NAK the data byte with this 0-based index within each write
    /// phase's data portion (after the register-pointer bytes).
    pub fn set_nak_data_after(&mut self, index: Option<usize>) -> &mut Self {
        self.nak_data_after = index;
        self
    }

    pub fn reg(&self, at: u16) -> u8 {
        self.regs.get(&at).copied().unwrap_or(0)
    }

    fn begin_write_phase(&mut self) {
        self.ptr_bytes_seen = 0;
        self.data_bytes_seen = 0;
    }

    /// Deliver one master→target byte. Returns false when the
    /// target NAKs it (the controller then aborts the transfer).
    fn write_byte(&mut self, b: u8) -> bool {
        self.events.push(BusEvent::WriteByte(b));
        if self.ptr_bytes_seen < self.reg_addr_bytes {
            let shift = 8 * self.ptr_bytes_seen;
            self.ptr = (self.ptr & !(0xffu16 << shift)) | ((b as u16) << shift);
            self.ptr_bytes_seen += 1;
            return true;
        }
        if self.nak_data_after == Some(self.data_bytes_seen) {
            // Replace the optimistic WriteByte record: the byte was
            // clocked out but NAKed, which is a different event.
            self.events.pop();
            self.events.push(BusEvent::DataNak(b));
            return false;
        }
        self.regs.insert(self.ptr, b);
        self.ptr = self.ptr.wrapping_add(1);
        self.data_bytes_seen += 1;
        true
    }

    fn read_byte(&mut self) -> u8 {
        let v = self.regs.get(&self.ptr).copied().unwrap_or(0);
        self.ptr = self.ptr.wrapping_add(1);
        self.events.push(BusEvent::ReadByte(v));
        v
    }
}

#[derive(Copy, Clone, Debug)]
struct TxEntry {
    data: u8,
    read: bool,
    stop: bool,
}

#[derive(Debug)]
struct ModelState {
    /// Plain stored registers (IC_CON, IC_TAR, timing constants,
    /// thresholds, interrupt mask, the LPSS private window, …).
    /// Computed registers are never read back from here.
    stored: BTreeMap<u64, u32>,
    enabled: bool,
    tx_fifo: VecDeque<TxEntry>,
    rx_fifo: VecDeque<u8>,
    /// START issued and no STOP since.
    bus_held: bool,
    /// Direction of the current address phase.
    phase_read: bool,
    /// IC_TAR of the current phase's target.
    current_addr: u8,
    abrt_source: u32,
    tx_abrt: bool,
    stop_det: bool,
    targets: Vec<VirtualTarget>,
    /// Engine freezes for this many read accesses (SCL stretch).
    stretch: u32,
    /// Engine processes commands only every `pump_period`-th read,
    /// at most `pump_budget` commands per window (slow-wire knob).
    pump_period: u64,
    pump_budget: usize,
    reads: u64,
    injected_abort: Option<u32>,
    max_tx_level: usize,
    max_rx_level: usize,
    rx_pop_count: usize,
}

/// Behavioural DW I2C register file. Cheap handle around shared
/// state: clone it to give one copy to the driver under test and
/// keep one for fixture setup/inspection.
#[derive(Clone)]
pub struct DwModel {
    state: Arc<IrqSafeSpinLock<ModelState>>,
}

impl core::fmt::Debug for DwModel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DwModel").finish_non_exhaustive()
    }
}

impl Default for DwModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DwModel {
    pub fn new() -> Self {
        Self {
            state: Arc::new(IrqSafeSpinLock::new(ModelState {
                stored: BTreeMap::new(),
                enabled: false,
                tx_fifo: VecDeque::new(),
                rx_fifo: VecDeque::new(),
                bus_held: false,
                phase_read: false,
                current_addr: 0,
                abrt_source: 0,
                tx_abrt: false,
                stop_det: false,
                targets: Vec::new(),
                stretch: 0,
                pump_period: 1,
                pump_budget: usize::MAX,
                reads: 0,
                injected_abort: None,
                max_tx_level: 0,
                max_rx_level: 0,
                rx_pop_count: 0,
            })),
        }
    }

    /// Attach a virtual target device to the bus.
    pub fn attach(&self, target: VirtualTarget) {
        self.state.lock().targets.push(target);
    }

    /// Freeze the wire engine for the next `reads` read accesses
    /// (a target stretching SCL). `u32::MAX` is effectively forever
    /// next to the drivers' 100 000-poll timeout budget.
    pub fn set_stretch(&self, reads: u32) {
        self.state.lock().stretch = reads;
    }

    /// Rate-limit the wire engine: it processes at most `budget`
    /// queued commands per `period` read accesses. The default
    /// (period 1, unbounded budget) is "as fast as the driver
    /// polls"; a larger period + budget 1 models a wire slow
    /// enough that the TX FIFO fills.
    pub fn set_pump(&self, period: u64, budget: usize) {
        let mut s = self.state.lock();
        s.pump_period = period.max(1);
        s.pump_budget = budget;
    }

    /// Raise TX_ABRT with `source` at the next address phase
    /// instead of ACKing a target (fault injection for the abort
    /// reasons a single well-behaved target cannot produce).
    pub fn inject_abort(&self, source: u32) {
        self.state.lock().injected_abort = Some(source);
    }

    /// The bus-event log recorded at the target on `addr`
    /// (empty when no such target is attached).
    pub fn events(&self, addr: u8) -> Vec<BusEvent> {
        let s = self.state.lock();
        s.targets
            .iter()
            .find(|t| t.addr == addr)
            .map(|t| t.events.clone())
            .unwrap_or_default()
    }

    /// Current register contents of the target on `addr`.
    pub fn target_reg(&self, addr: u8, at: u16) -> u8 {
        let s = self.state.lock();
        s.targets
            .iter()
            .find(|t| t.addr == addr)
            .map(|t| t.reg(at))
            .unwrap_or(0)
    }

    /// Whether a TX_ABRT is still latched (the production
    /// `check_abort` path clears it by reading IC_CLR_TX_ABRT).
    pub fn tx_abrt_latched(&self) -> bool {
        self.state.lock().tx_abrt
    }

    /// Deepest TX / RX FIFO levels the engine observed.
    pub fn max_tx_level(&self) -> usize {
        self.state.lock().max_tx_level
    }
    pub fn max_rx_level(&self) -> usize {
        self.state.lock().max_rx_level
    }
    /// How many RX bytes the driver has popped via IC_DATA_CMD
    /// reads (drain-interleave evidence on long reads).
    pub fn rx_pop_count(&self) -> usize {
        self.state.lock().rx_pop_count
    }
    /// Current value of a plain stored register (e.g. the LPSS
    /// private window after the ungate sequence).
    pub fn stored_reg(&self, off: u64) -> u32 {
        self.state.lock().stored.get(&off).copied().unwrap_or(0)
    }
}

// ── Wire engine ──────────────────────────────────────────────────

fn target_idx(s: &ModelState, addr: u8) -> Option<usize> {
    s.targets.iter().position(|t| t.addr == addr)
}

fn raise_abort(s: &mut ModelState, source: u32) {
    if s.bus_held {
        if let Some(i) = target_idx(s, s.current_addr) {
            s.targets[i].events.push(BusEvent::Stop);
        }
    }
    s.abrt_source = source;
    s.tx_abrt = true;
    // Databook: on TX_ABRT the TX FIFO is flushed and a STOP is
    // generated; the controller then sits idle until the abort is
    // cleared by reading IC_CLR_TX_ABRT.
    s.tx_fifo.clear();
    s.bus_held = false;
}

fn issue_stop(s: &mut ModelState) {
    s.bus_held = false;
    s.stop_det = true;
    if let Some(i) = target_idx(s, s.current_addr) {
        s.targets[i].events.push(BusEvent::Stop);
    }
}

/// Run the address phase for a new phase of direction `read`.
/// Returns false when the phase aborts (abort latched here).
fn start_phase(s: &mut ModelState, read: bool) -> bool {
    let tar = (s.stored.get(&IC_TAR).copied().unwrap_or(0) & 0x7f) as u8;
    if let Some(source) = s.injected_abort.take() {
        raise_abort(s, source);
        return false;
    }
    let Some(i) = target_idx(s, tar) else {
        raise_abort(s, ABRT_7B_ADDR_NOACK);
        return false;
    };
    if s.targets[i].nak_address {
        s.targets[i].events.push(BusEvent::AddrNak);
        raise_abort(s, ABRT_7B_ADDR_NOACK);
        return false;
    }
    let held = s.bus_held;
    s.targets[i].events.push(if held {
        BusEvent::Restart { read }
    } else {
        BusEvent::Start { read }
    });
    if !read {
        s.targets[i].begin_write_phase();
    }
    s.bus_held = true;
    s.phase_read = read;
    s.current_addr = tar;
    true
}

/// Advance the wire engine as far as it can go right now. Called
/// on register reads only (see the module docs for why reads are
/// the model's clock).
fn pump(s: &mut ModelState) {
    if !s.enabled || s.tx_abrt {
        return;
    }
    if s.stretch > 0 {
        s.stretch -= 1;
        return;
    }
    if s.reads % s.pump_period != 0 {
        return;
    }
    let mut budget = s.pump_budget;
    while budget > 0 {
        let Some(front) = s.tx_fifo.front().copied() else {
            return;
        };
        if !s.bus_held || s.phase_read != front.read {
            if !start_phase(s, front.read) {
                return;
            }
            continue;
        }
        if front.read {
            if s.rx_fifo.len() >= FIFO_DEPTH {
                // The target's byte has nowhere to go; the engine
                // holds SCL until the driver drains the RX FIFO.
                return;
            }
            s.tx_fifo.pop_front();
            let Some(i) = target_idx(s, s.current_addr) else {
                return;
            };
            let b = s.targets[i].read_byte();
            s.rx_fifo.push_back(b);
            s.max_rx_level = s.max_rx_level.max(s.rx_fifo.len());
            if front.stop {
                issue_stop(s);
            }
        } else {
            s.tx_fifo.pop_front();
            let Some(i) = target_idx(s, s.current_addr) else {
                return;
            };
            if !s.targets[i].write_byte(front.data) {
                raise_abort(s, ABRT_TXDATA_NOACK);
                return;
            }
            if front.stop {
                issue_stop(s);
            }
        }
        budget -= 1;
    }
}

fn status_bits(s: &ModelState) -> u32 {
    let mut v = 0u32;
    if s.bus_held || !s.tx_fifo.is_empty() {
        v |= 1 << 0; // ACTIVITY
    }
    if s.tx_fifo.len() < FIFO_DEPTH {
        v |= 1 << 1; // TFNF
    }
    if s.tx_fifo.is_empty() {
        v |= 1 << 2; // TFE
    }
    if !s.rx_fifo.is_empty() {
        v |= 1 << 3; // RFNE
    }
    if s.rx_fifo.len() >= FIFO_DEPTH {
        v |= 1 << 4; // RFF
    }
    if s.bus_held {
        v |= 1 << 5; // MST_ACTIVITY
    }
    v
}

fn raw_intr_bits(s: &ModelState) -> u32 {
    let rx_tl = s.stored.get(&IC_RX_TL).copied().unwrap_or(0) as usize;
    let mut v = 0u32;
    if s.rx_fifo.len() > rx_tl {
        v |= 1 << 2; // RX_FULL (level above IC_RX_TL)
    }
    if s.tx_fifo.is_empty() {
        v |= 1 << 4; // TX_EMPTY
    }
    if s.tx_abrt {
        v |= 1 << 6; // TX_ABRT
    }
    if s.bus_held || !s.tx_fifo.is_empty() {
        v |= 1 << 8; // ACTIVITY
    }
    if s.stop_det {
        v |= 1 << 9; // STOP_DET
    }
    v
}

impl DwRegs for DwModel {
    unsafe fn read32(&self, off: u64) -> u32 {
        let mut s = self.state.lock();
        s.reads += 1;
        if off == IC_DATA_CMD {
            // Pop first: freeing an RX slot is what lets a stalled
            // engine advance during this same access.
            let had_byte = !s.rx_fifo.is_empty();
            let v = s.rx_fifo.pop_front().map(u32::from).unwrap_or(0);
            if had_byte {
                s.rx_pop_count += 1;
            }
            pump(&mut s);
            return v;
        }
        // Read-to-clear registers: apply the clear, then let the
        // engine advance, then report (these read back as 0).
        if off == IC_CLR_TX_ABRT {
            s.tx_abrt = false;
            s.abrt_source = 0;
            pump(&mut s);
            return 0;
        }
        if off == IC_CLR_INTR {
            s.stop_det = false;
            pump(&mut s);
            return 0;
        }
        pump(&mut s);
        match off {
            IC_STATUS => status_bits(&s),
            IC_RAW_INTR_STAT => raw_intr_bits(&s),
            IC_INTR_STAT => raw_intr_bits(&s) & s.stored.get(&IC_INTR_MASK).copied().unwrap_or(0),
            IC_TXFLR => s.tx_fifo.len() as u32,
            IC_RXFLR => s.rx_fifo.len() as u32,
            IC_TX_ABRT_SOURCE => s.abrt_source,
            IC_ENABLE_STATUS => u32::from(s.enabled),
            IC_COMP_TYPE => DW_COMP_TYPE_MAGIC,
            _ => s.stored.get(&off).copied().unwrap_or(0),
        }
    }

    unsafe fn write32(&self, off: u64, val: u32) {
        let mut s = self.state.lock();
        match off {
            IC_ENABLE => {
                s.enabled = val & 1 != 0;
                if !s.enabled {
                    // Databook: disabling the core flushes both
                    // FIFOs and drops any in-flight phase.
                    s.tx_fifo.clear();
                    s.rx_fifo.clear();
                    s.bus_held = false;
                }
                s.stored.insert(off, val);
            }
            IC_DATA_CMD => {
                // Push only — writes never advance the wire (see
                // the module docs). Pushes while disabled or with
                // an abort latched are dropped, as on silicon.
                if s.enabled && !s.tx_abrt {
                    s.tx_fifo.push_back(TxEntry {
                        data: val as u8,
                        read: val & DATA_CMD_READ != 0,
                        stop: val & DATA_CMD_STOP != 0,
                    });
                    s.max_tx_level = s.max_tx_level.max(s.tx_fifo.len());
                }
            }
            // Computed / read-only registers ignore writes.
            IC_STATUS | IC_RAW_INTR_STAT | IC_INTR_STAT | IC_TXFLR | IC_RXFLR
            | IC_TX_ABRT_SOURCE | IC_ENABLE_STATUS | IC_COMP_TYPE => {}
            _ => {
                s.stored.insert(off, val);
            }
        }
    }
}
