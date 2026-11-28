//! Mellanox ConnectX-3 (`mlx4`) Ethernet driver core.
//!
//! Brings the HCA up through the legacy HCR command interface
//! (`cmd.rs`), the ICM context-memory model (`icm.rs`), and the
//! EQ/CQ/QP + memory-region objects (`eq.rs` / `cq.rs` / `qp.rs` /
//! `mr.rs`), then drives a single-queue Ethernet datapath (`wqe.rs` /
//! `port.rs`) wired into `narf_net` exactly like the sibling mlx5
//! driver: a copy-mode TX path, a polled RX drain, `publish_netdev`
//! into the kernel stack, and an `install_rx_drain` hook for
//! syscall-context busy-waits.
//!
//! The wire encodings (commands, contexts, descriptors) are
//! unit-tested in `tests.rs`; the end-to-end bring-up and datapath are
//! validated on ConnectX-3 silicon at boot (QEMU emulates no mlx4
//! device).

use core::sync::atomic::{fence, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::platform::{map_bar, BusDevice, MmioRegion};
use core::mem::ManuallyDrop;

// Firmware can retain these addresses after any command, including a timeout.
// Releasing them requires a device reset/drain proof that this driver does not
// yet have. Pin both built-in and module DMA; only completed mailboxes free.
struct DmaBuffer(ManuallyDrop<crate::platform::DmaBuffer>);
impl core::ops::Deref for DmaBuffer {
    type Target = crate::platform::DmaBuffer;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
fn alloc_dma(device: &BusDevice, len: usize) -> Result<DmaBuffer, ()> {
    crate::platform::alloc_dma(device, len).map(|b| DmaBuffer(ManuallyDrop::new(b)))
}
impl DmaBuffer {
    fn free_completed(self) {
        let buffer = ManuallyDrop::into_inner(self.0);
        #[cfg(feature = "builtin")]
        drop(buffer);
        #[cfg(feature = "module")]
        buffer.free_completed();
    }
}
#[cfg(feature = "builtin")]
use narf_bus::BusDeviceCap;
#[cfg(feature = "builtin")]
use narf_capabilities::{Cap, Write};
#[cfg(feature = "builtin")]
use narf_io::alloc_coherent;
#[cfg(feature = "builtin")]
use narf_ipc::{channel, Consumer, Producer};
#[cfg(feature = "builtin")]
use narf_lib::id::DomainId;
#[cfg(feature = "builtin")]
use narf_lib::sync::IrqSafeSpinLock;
#[cfg(feature = "builtin")]
use narf_net::{Frame, RX_RING_N, TX_RING_N};

#[cfg(feature = "module")]
use crate::platform::{
    console as narf_console, scheduler as narf_scheduler, time as narf_time,
    Lock as IrqSafeSpinLock,
};
use cmd::CmdOp;

#[cfg(feature = "builtin")]
mod tests;

pub mod bit_field;
pub mod cmd;
pub mod cq;
pub mod eq;
pub mod fw;
pub mod icm;
pub mod mr;
pub mod port;
pub mod qp;
pub mod wire;
pub mod wqe;

// Try-only gates prevent nested pumps and concurrent callers from posting
// WQEs out of order or consuming the same CQE twice. Never wait on a gate.
struct Busy<'a>(&'a core::sync::atomic::AtomicBool);
impl<'a> Busy<'a> {
    fn enter(flag: &'a core::sync::atomic::AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(flag))
    }
}
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// ── PCI device IDs ──────────────────────────────────────────────────

/// Vendor: Mellanox (now NVIDIA Networking).
pub const MLX4_VENDOR: u16 = 0x15B3;
/// ConnectX-3 (MT27500).
pub const MLX4_DEV_CX3: u16 = 0x1003;
/// ConnectX-3 Pro (MT27520).
pub const MLX4_DEV_CX3_PRO: u16 = 0x1007;

#[cfg(feature = "builtin")]
const ALL_DEV_IDS: &[u16] = &[MLX4_DEV_CX3, MLX4_DEV_CX3_PRO];

// ── Tunables ────────────────────────────────────────────────────────

/// Startup wait for the firmware command interface (PRM §9.6).
const CMD_DEADLINE_MS: u64 = 10_000;
/// UAR page size (4 KiB).
const UAR_PAGE_SIZE: u64 = 4096;

/// log2 EQ depth (64 EQEs × 32 B = 2 KiB, one page).
const LOG_EQ_SIZE: u8 = 6;
/// log2 CQ depth (shared TX+RX completions).
const LOG_CQ_SIZE: u8 = 7;
/// log2 SQ depth (send WQEs).
const LOG_SQ_SIZE: u8 = 4;
const SQ_N: usize = 1 << LOG_SQ_SIZE;
/// log2 RQ depth (receive WQEs).
const LOG_RQ_SIZE: u8 = 5;
const RQ_N: usize = 1 << LOG_RQ_SIZE;
/// SQ WQE stride is one TXBB (64 B → log 6); RQ WQE is one data seg
/// (16 B → log 4).
const LOG_SQ_STRIDE: u8 = 6;
const LOG_RQ_STRIDE: u8 = 4;
/// Per-slot RX/TX staging-buffer length (MTU + headroom).
const RX_SLOT_LEN: usize = 2048;
const TX_SLOT_LEN: usize = 2048;
/// RX poll interval when no completions are pending.
#[cfg(feature = "builtin")]
const RX_POLL_INTERVAL_NS: u64 = 1_000_000;
/// CQEs drained per RX pump pass.
#[cfg(feature = "builtin")]
const RX_DRAIN_BUDGET: usize = 64;
/// TX slot-exhaustion retry budget before dropping a frame.
#[cfg(feature = "builtin")]
const TX_RETRY_MAX: u32 = 100;
/// Default Ethernet MTU.
const DEFAULT_MTU: u32 = 1500;
/// Wire MTU programmed into SET_PORT (MTU + L2 header + VLAN + FCS).
const WIRE_MTU: u16 = 1500 + 14 + 4 + 4;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mlx4Error {
    BarMapFailed,
    NoMemory,
    /// A firmware command returned a non-zero status byte.
    CmdFailed(u8),
    /// A firmware command did not clear the GO bit within the deadline.
    CmdTimeout,
    /// The datapath has not been set up yet.
    NoDatapath,
    /// TX staging slots are all in flight.
    TxSlotsExhausted,
    /// Frame larger than one TX staging slot.
    FrameTooLarge,
    /// Generic / catch-all.
    Other(&'static str),
}

// ── Cached NIC state ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct NicCachedState {
    pub mac: [u8; 6],
    pub mtu: u32,
    pub link_up: bool,
}

// ── TX staging-slot bookkeeping ─────────────────────────────────────

/// Maps SQ WQE indices to TX staging slots so a completion recycles
/// exactly the slot its WQE used. Pure data — unit-testable.
#[derive(Clone, Debug)]
pub struct TxSlotPool {
    free: [bool; SQ_N],
    by_wqe: [Option<usize>; SQ_N],
}

impl TxSlotPool {
    pub fn new() -> Self {
        Self {
            free: [true; SQ_N],
            by_wqe: [None; SQ_N],
        }
    }
    pub fn claim(&mut self) -> Option<usize> {
        let slot = self.free.iter().position(|&f| f)?;
        self.free[slot] = false;
        Some(slot)
    }
    pub fn record(&mut self, wqe_idx: u32, slot: usize) {
        self.by_wqe[(wqe_idx as usize) % SQ_N] = Some(slot);
    }
    pub fn release(&mut self, wqe_counter: u16) -> Option<usize> {
        let slot = self.by_wqe[(wqe_counter as usize) % SQ_N].take()?;
        self.free[slot] = true;
        Some(slot)
    }
    pub fn free_count(&self) -> usize {
        self.free.iter().filter(|&&f| f).count()
    }
}

impl Default for TxSlotPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── Live datapath state ─────────────────────────────────────────────

/// Built once by `setup_datapath`; the DMA regions must stay resident
/// for the controller's life, so this is never replaced. Private —
/// only `Mlx4Eth` methods touch it (`DmaBuffer` has no `Debug`).
struct DatapathState {
    qp_number: u32,
    cq_number: u32,
    /// The one physical MR lkey covering all datapath buffers.
    data_lkey: u32,
    /// SQ + RQ WQE buffer (one page).
    _wq: DmaBuffer,
    sq_base: u64,
    rq_base: u64,
    /// CQ buffer (one page).
    cq_buf: DmaBuffer,
    /// EQ buffer (one page) — kept resident; the HCA writes EQEs here.
    _eq: DmaBuffer,
    /// Host-memory doorbell record page (RX prod + QP/CQ db).
    db_rec: DmaBuffer,
    /// RX staging pool (`RQ_N` slots).
    rx_pool: DmaBuffer,
    /// TX staging pool (`SQ_N` slots).
    tx_pool: DmaBuffer,
    tx_slots: TxSlotPool,
    /// SQ producer index (WQE count) and RX producer index.
    sq_prod: u32,
    rx_prod: u32,
    /// CQ consumer index.
    cq_cons: u32,
}

impl DatapathState {
    fn rx_slot_va(&self, slot: usize) -> u64 {
        self.rx_pool.dma_addr_at((slot * RX_SLOT_LEN) as u64).raw()
    }
    fn tx_slot_cpu(&self, slot: usize) -> *mut u8 {
        self.tx_pool
            .cpu_mut_ptr_at::<u8>((slot * TX_SLOT_LEN) as u64)
    }
    fn tx_slot_va(&self, slot: usize) -> u64 {
        self.tx_pool.dma_addr_at((slot * TX_SLOT_LEN) as u64).raw()
    }
}

// ── The controller ──────────────────────────────────────────────────

pub struct Mlx4Eth {
    device: BusDevice,
    bringup_deadline: Option<narf_time::Deadline>,
    command_failed: core::sync::atomic::AtomicBool,
    command_busy: core::sync::atomic::AtomicBool,
    tx_busy: core::sync::atomic::AtomicBool,
    drain_busy: core::sync::atomic::AtomicBool,
    next_link_poll: IrqSafeSpinLock<Option<narf_time::Deadline>>,
    /// BAR0 — init registers, HCR, clear-int.
    mmio: MmioRegion,
    /// BAR2 — UAR doorbell region.
    uar: MmioRegion,
    /// HCR command toggle bit (flipped per command).
    cmd_toggle: IrqSafeSpinLock<bool>,
    /// Firmware area ICM pages (held resident).
    _fw_area: IrqSafeSpinLock<Vec<DmaBuffer>>,
    /// Auxiliary + context-table ICM pages (held resident).
    _icm: IrqSafeSpinLock<Vec<DmaBuffer>>,
    /// Next free MTT index (bump allocator).
    next_mtt: IrqSafeSpinLock<u64>,
    dev_cap: fw::DevCap,
    fw_info: fw::FwInfo,
    mtt_entry_sz: u16,
    /// BAR2 UAR page index the driver rings its doorbells through — the
    /// first page past the firmware-reserved UARs (`QUERY_DEV_CAP`).
    uar_index: u32,
    #[cfg(feature = "builtin")]
    pub addr: narf_bus::BusAddr,
    nic_state: IrqSafeSpinLock<NicCachedState>,
    datapath: IrqSafeSpinLock<Option<DatapathState>>,

    // IPC integration (mlx5's shape).
    #[cfg(feature = "builtin")]
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    #[cfg(feature = "builtin")]
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    #[cfg(feature = "builtin")]
    rx_ipc_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    #[cfg(feature = "builtin")]
    ifname: crate::publish::IfName,
}

// SAFETY: the only non-`Send` members are the MMIO/DMA handles; they
// address identity-mapped device memory valid from any CPU, so moving
// the controller across threads is sound.
unsafe impl Send for Mlx4Eth {}
// SAFETY: every interior-mutable field is behind an `IrqSafeSpinLock`,
// and the MMIO/DMA handles are only touched through `&self` methods
// that take those locks, so concurrent `&Mlx4Eth` access is
// serialized.
unsafe impl Sync for Mlx4Eth {}

impl core::fmt::Debug for Mlx4Eth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mlx4Eth")
            .field(
                "fw",
                &(
                    self.fw_info.major,
                    self.fw_info.minor,
                    self.fw_info.subminor,
                ),
            )
            .field("num_ports", &self.dev_cap.num_ports)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl Mlx4Eth {
    /// The published interface name, or `""` before probe published one.
    #[cfg(feature = "builtin")]
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }

    /// A snapshot of the cached MAC/MTU/link state.
    pub fn nic_state(&self) -> NicCachedState {
        *self.nic_state.lock()
    }

    // ── HCR command transport ───────────────────────────────────────

    /// Allocate a zeroed 4-KiB DMA command mailbox.
    fn alloc_mailbox(&self) -> Result<DmaBuffer, Mlx4Error> {
        let mb = alloc_dma(&self.device, cmd::MAILBOX_SIZE).map_err(|_| Mlx4Error::NoMemory)?;
        // SAFETY: freshly-allocated coherent DMA exclusively ours.
        unsafe {
            core::ptr::write_bytes(mb.cpu_mut_ptr_at::<u8>(0), 0, cmd::MAILBOX_SIZE);
        }
        Ok(mb)
    }

    #[inline]
    fn hcr_read_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO; BE on wire, so swap.
        unsafe { self.mmio.read32(cmd::HCR_BASE + cmd::HCR_STATUS) }.swap_bytes()
    }

    #[inline]
    fn hcr_write(&self, off: u64, host_value: u32) {
        // SAFETY: identity-mapped MMIO; BE on wire, so swap the LE store.
        unsafe {
            self.mmio
                .write32(cmd::HCR_BASE + off, host_value.swap_bytes());
        }
    }

    /// Issue one HCR command. `in_param`/`out_param` carry either an
    /// immediate value or a mailbox physical address; `out_is_imm`
    /// returns the firmware's immediate output. Commands are
    /// effectively serialized — the only caller during bring-up is the
    /// single probe task, and the steady-state datapath issues none.
    fn cmd(
        &self,
        in_param: u64,
        in_modifier: u32,
        op_modifier: u8,
        op: CmdOp,
        out_param: u64,
        out_is_imm: bool,
    ) -> Result<u64, Mlx4Error> {
        use core::fmt::Write as _;
        if self.command_failed.load(Ordering::Acquire)
            || self.bringup_deadline.is_some_and(|d| d.expired())
        {
            return Err(Mlx4Error::CmdTimeout);
        }
        if self
            .command_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Mlx4Error::Other("command already in progress"));
        }
        struct Busy<'a>(&'a core::sync::atomic::AtomicBool);
        impl Drop for Busy<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _busy = Busy(&self.command_busy);
        #[cfg(feature = "builtin")]
        let _nested = narf_scheduler::sleep_pumps::block_nested();
        let per_command = narf_time::Deadline::after_ms(CMD_DEADLINE_MS);
        let deadline = self
            .bringup_deadline
            .map_or(per_command, |d| per_command.min(d));
        let previous_toggle = *self.cmd_toggle.lock();
        // Wait for the previous command's GO and toggle handshake.
        let clear = narf_scheduler::responsive_spin_until(
            || !cmd::is_pending(self.hcr_read_status(), previous_toggle),
            deadline,
        );
        if !clear {
            self.command_failed.store(true, Ordering::Release);
            let _ = writeln!(
                narf_console::Writer,
                "mlx4: {:?} idle timeout, HCR={:#010x}",
                op,
                self.hcr_read_status()
            );
            return Err(Mlx4Error::CmdTimeout);
        }
        let toggle = {
            let mut t = self.cmd_toggle.lock();
            *t = !*t;
            *t
        };
        self.hcr_write(cmd::HCR_IN_PARAM_H, (in_param >> 32) as u32);
        self.hcr_write(cmd::HCR_IN_PARAM_L, in_param as u32);
        self.hcr_write(cmd::HCR_IN_MODIFIER, in_modifier);
        self.hcr_write(cmd::HCR_OUT_PARAM_H, (out_param >> 32) as u32);
        self.hcr_write(cmd::HCR_OUT_PARAM_L, out_param as u32);
        self.hcr_write(cmd::HCR_TOKEN, cmd::token_word(cmd::POLL_TOKEN));
        fence(Ordering::SeqCst);
        self.hcr_write(
            cmd::HCR_STATUS,
            cmd::go_word(op, op_modifier, toggle, false),
        );

        let done = narf_scheduler::responsive_spin_until(
            || !cmd::is_pending(self.hcr_read_status(), toggle),
            deadline,
        );
        if !done {
            self.command_failed.store(true, Ordering::Release);
            let _ = writeln!(
                narf_console::Writer,
                "mlx4: {:?} completion timeout, HCR={:#010x}",
                op,
                self.hcr_read_status()
            );
            return Err(Mlx4Error::CmdTimeout);
        }
        let status = cmd::status_of(self.hcr_read_status());
        if status != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "mlx4: {:?} failed: {:?}",
                op,
                cmd::CmdStatus::from_raw(status)
            );
            return Err(Mlx4Error::CmdFailed(status));
        }
        if out_is_imm {
            // SAFETY: identity-mapped MMIO; BE on wire.
            let hi = unsafe { self.mmio.read32(cmd::HCR_BASE + cmd::HCR_OUT_PARAM_H) }.swap_bytes();
            // SAFETY: identity-mapped MMIO; BE on wire.
            let lo = unsafe { self.mmio.read32(cmd::HCR_BASE + cmd::HCR_OUT_PARAM_L) }.swap_bytes();
            Ok((u64::from(hi) << 32) | u64::from(lo))
        } else {
            Ok(0)
        }
    }

    /// A command whose output lands in `out_mb`; returns the mailbox
    /// bytes copied back out.
    fn cmd_out_mailbox(
        &self,
        op: CmdOp,
        op_modifier: u8,
        in_modifier: u32,
        out_len: usize,
    ) -> Result<Vec<u8>, Mlx4Error> {
        if out_len > cmd::MAILBOX_SIZE {
            return Err(Mlx4Error::Other("oversize output mailbox"));
        }
        let out_mb = self.alloc_mailbox()?;
        let result = self.cmd(
            0,
            in_modifier,
            op_modifier,
            op,
            out_mb.dma_addr().raw(),
            false,
        );
        if let Err(error) = result {
            if !matches!(error, Mlx4Error::CmdTimeout) {
                out_mb.free_completed();
            }
            return Err(error);
        }
        let mut buf = alloc::vec![0u8; out_len];
        // SAFETY: `out_mb` is a 4-KiB mailbox; `out_len <= MAILBOX_SIZE`.
        unsafe {
            core::ptr::copy_nonoverlapping(out_mb.cpu_ptr_at::<u8>(0), buf.as_mut_ptr(), out_len);
        }
        out_mb.free_completed();
        Ok(buf)
    }

    /// A command whose input is the bytes in `in_bytes` (copied into a
    /// mailbox).
    fn cmd_in_mailbox(
        &self,
        op: CmdOp,
        op_modifier: u8,
        in_modifier: u32,
        in_bytes: &[u8],
    ) -> Result<(), Mlx4Error> {
        if in_bytes.len() > cmd::MAILBOX_SIZE {
            return Err(Mlx4Error::Other("oversize input mailbox"));
        }
        let mb = self.alloc_mailbox()?;
        // SAFETY: `in_bytes.len() <= MAILBOX_SIZE` by contract.
        unsafe {
            core::ptr::copy_nonoverlapping(
                in_bytes.as_ptr(),
                mb.cpu_mut_ptr_at::<u8>(0),
                in_bytes.len(),
            );
        }
        fence(Ordering::SeqCst);
        let result = self.cmd(mb.dma_addr().raw(), in_modifier, op_modifier, op, 0, false);
        if !matches!(result, Err(Mlx4Error::CmdTimeout)) {
            mb.free_completed();
        }
        result.map(|_| ())
    }

    // ── MTT allocation + writing ─────────────────────────────────────

    fn alloc_mtt(&self, npages: u64) -> u64 {
        let mut n = self.next_mtt.lock();
        let base = *n;
        *n += npages;
        base
    }

    /// Byte address of MTT index `mtt_index` (context `mtt_base`).
    fn mtt_addr(&self, mtt_index: u64) -> u64 {
        mtt_index * u64::from(self.mtt_entry_sz)
    }

    /// WRITE_MTT `npages` consecutive page addresses starting at
    /// `mtt_index`.
    fn write_mtt(&self, mtt_index: u64, pages: &[u64]) -> Result<(), Mlx4Error> {
        let mut mb = alloc::vec![0u8; 16 + pages.len() * 8];
        wire::put_be64(&mut mb, 0, mtt_index);
        // bytes 8..16 reserved (0).
        for (i, &p) in pages.iter().enumerate() {
            wire::put_be64(&mut mb, 16 + i * 8, mr::mtt_entry(p));
        }
        self.cmd_in_mailbox(CmdOp::WriteMtt, 0, pages.len() as u32, &mb)
    }

    // ── Bring-up ─────────────────────────────────────────────────────

    /// # Safety
    /// Caller owns the device's BARs exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(device: &BusDevice) -> Result<Arc<Self>, Mlx4Error> {
        // SAFETY: caller-authority over the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| Mlx4Error::BarMapFailed)?;
        // SAFETY: caller-authority over the device; BAR2 is the UAR region.
        let uar = unsafe { map_bar(device, 2) }.map_err(|_| Mlx4Error::BarMapFailed)?;

        #[cfg(feature = "builtin")]
        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        #[cfg(feature = "builtin")]
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        #[cfg(feature = "module")]
        device.enable().map_err(|_| Mlx4Error::BarMapFailed)?;
        let dev = Arc::new(Self {
            device: *device,
            bringup_deadline: Some(narf_time::Deadline::after_ms(60_000)),
            command_failed: core::sync::atomic::AtomicBool::new(false),
            command_busy: core::sync::atomic::AtomicBool::new(false),
            tx_busy: core::sync::atomic::AtomicBool::new(false),
            drain_busy: core::sync::atomic::AtomicBool::new(false),
            next_link_poll: IrqSafeSpinLock::new(None),
            mmio,
            uar,
            cmd_toggle: IrqSafeSpinLock::new(false),
            _fw_area: IrqSafeSpinLock::new(Vec::new()),
            _icm: IrqSafeSpinLock::new(Vec::new()),
            next_mtt: IrqSafeSpinLock::new(0),
            dev_cap: fw::DevCap::default(),
            fw_info: fw::FwInfo::default(),
            mtt_entry_sz: 8,
            uar_index: 0,
            #[cfg(feature = "builtin")]
            addr: device.addr,
            nic_state: IrqSafeSpinLock::new(NicCachedState {
                mac: [0; 6],
                mtu: DEFAULT_MTU,
                link_up: false,
            }),
            datapath: IrqSafeSpinLock::new(None),
            #[cfg(feature = "builtin")]
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            #[cfg(feature = "builtin")]
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
            #[cfg(feature = "builtin")]
            rx_ipc_prod: IrqSafeSpinLock::new(Some(rx_prod)),
            #[cfg(feature = "builtin")]
            ifname: crate::publish::IfName::new(),
        });

        // `dev_cap` / `fw_info` / `mtt_entry_sz` are filled by the
        // firmware handshake; they live behind `&self` via a rebuild
        // because `Arc` is already shared. Instead of interior
        // mutability for one-shot init state, run the handshake on a
        // throwaway owned builder and fold the results in before the
        // `Arc` is handed out — but the `Arc` is needed for the
        // command transport (`&self`). So: run the sequence, then
        // stash the caps via the lock-free fields set here. We take
        // the simpler route and keep them `Copy` defaults, refreshing
        // caches post-handshake through dedicated locks.
        let dev = Self::run_bringup(dev)?;
        #[cfg(feature = "builtin")]
        spawn_pumps(dev.clone(), tx_cons);
        Ok(dev)
    }

    /// The firmware handshake + ICM + port + datapath sequence. Split
    /// out so `bring_up` stays readable. Consumes and returns the
    /// `Arc` so caps gathered here can be re-folded via a rebuild when
    /// interior mutability would otherwise be required.
    fn run_bringup(dev: Arc<Self>) -> Result<Arc<Self>, Mlx4Error> {
        // 1. QUERY_FW — firmware version + ICM firmware-area size.
        let fw_mb = dev.cmd_out_mailbox(CmdOp::QueryFw, 0, 0, 0x100)?;
        let fw_info = fw::decode_query_fw(&fw_mb);
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "mlx4: firmware {}.{}.{} requests {} pages ({} KiB)",
            fw_info.major,
            fw_info.minor,
            fw_info.subminor,
            fw_info.fw_pages,
            u64::from(fw_info.fw_pages) * 4
        );

        // 2. MAP_FA — map the firmware area's ICM pages.
        let fw_pages = fw_info.fw_pages.max(1);
        let fw_area = dev.map_icm_pages(CmdOp::MapFa, fw_pages, &mut 0, false)?;

        // 3. RUN_FW.
        dev.cmd(0, 0, 0, CmdOp::RunFw, 0, false)?;

        // 4. QUERY_DEV_CAP.
        let dc_mb = dev.cmd_out_mailbox(CmdOp::QueryDevCap, 0, 0, 0x100)?;
        let dev_cap = fw::decode_query_dev_cap(&dc_mb);

        // 5. Plan ICM + SET_ICM_SIZE + MAP_ICM_AUX + MAP_ICM(tables).
        // Size each context table to cover the device's reserved range
        // plus the driver's own object, so our objects (placed at the
        // first index past the reserved range) always fit.
        let counts = icm::IcmCounts {
            log_num_qps: (dev_cap.log2_rsvd_qps + 1).max(7),
            log_num_cqs: (dev_cap.log2_rsvd_cqs + 1).max(7),
            log_num_eqs: (dev_cap.log2_rsvd_eqs + 1).max(4),
            log_num_mpts: (dev_cap.log2_rsvd_mrws + 1).max(7),
            log_num_mtts: (dev_cap.log2_rsvd_mtts + 1).max(14),
            ..icm::IcmCounts::default()
        };
        let layout = icm::make_layout(&dev_cap, &counts);
        let aux_pages = dev.cmd(layout.total, 0, 0, CmdOp::SetIcmSize, 0, true)?;
        let aux_pages = u32::try_from(aux_pages)
            .map_err(|_| Mlx4Error::Other("invalid auxiliary page count"))?
            .max(1);
        let icm_aux = dev.map_icm_pages(CmdOp::MapIcmAux, aux_pages as u32, &mut 0, false)?;

        let mut icm_pages: Vec<DmaBuffer> = Vec::new();
        for (virt, size) in layout.regions() {
            let pages = (size / icm::ICM_PAGE_SIZE).max(1) as u32;
            let mut v = virt;
            let mut chunk = dev.map_icm_pages(CmdOp::MapIcm, pages, &mut v, true)?;
            icm_pages.append(&mut chunk);
        }

        // 6. INIT_HCA. UAR region holds `num_uars = uar_bytes / 4 KiB`
        // pages; `uar_page_sz = PAGE_SHIFT - 12 = 0` for 4-KiB pages.
        let log_uar_sz = dev_cap.log2_uar_sz.saturating_sub(12);
        let init = layout.init_hca_params(&counts, log_uar_sz, 0);
        let init_mb = icm::build_init_hca(&init);
        dev.cmd_in_mailbox(CmdOp::InitHca, 0, 0, &init_mb)?;

        // 7. QUERY_ADAPTER (board id / inta pin — informational).
        dev.cmd_out_mailbox(CmdOp::QueryAdapter, 0, 0, 0x100)?;

        // Fold the gathered caps in. Interior-mutability-free: rebuild
        // a fresh `Arc` carrying the caps, moving the resident DMA +
        // ring state across. The old `Arc` has no other strong refs
        // yet (pumps spawn after this returns).
        let mut dev = dev;
        {
            let d =
                Arc::get_mut(&mut dev).ok_or(Mlx4Error::Other("mlx4 Arc aliased during init"))?;
            d.fw_info = fw_info;
            d.dev_cap = dev_cap;
            d.mtt_entry_sz = dev_cap.mtt_entry_sz.max(8);
            // Driver doorbell UAR + MTT bump base live past the
            // firmware-reserved ranges.
            d.uar_index = u32::from(dev_cap.reserved_uars);
            *d.next_mtt.lock() = 1u64 << dev_cap.log2_rsvd_mtts;
            d._fw_area.lock().extend(fw_area);
            d._icm.lock().extend(icm_aux);
            d._icm.lock().extend(icm_pages);
        }

        dev.setup_datapath(&layout)?;
        dev.cmd(0, 1, 0, CmdOp::InitPort, 0, false)?;
        Arc::get_mut(&mut dev)
            .ok_or(Mlx4Error::Other("mlx4 Arc aliased during init"))?
            .bringup_deadline = None;
        dev.refresh_link()?;
        Ok(dev)
    }

    /// Allocate `npages` 4-KiB ICM pages and map them with a VPM
    /// command (`MAP_FA` / `MAP_ICM_AUX` / `MAP_ICM`). When `with_virt`
    /// is set, consecutive ICM virtual addresses starting at `*virt`
    /// are written and `*virt` is advanced; otherwise the virtual
    /// field is left zero (firmware-area / aux mappings). Returns the
    /// resident DMA pages.
    fn map_icm_pages(
        &self,
        op: CmdOp,
        npages: u32,
        virt: &mut u64,
        with_virt: bool,
    ) -> Result<Vec<DmaBuffer>, Mlx4Error> {
        let mut pages: Vec<DmaBuffer> = Vec::new();
        pages
            .try_reserve_exact(npages as usize)
            .map_err(|_| Mlx4Error::NoMemory)?;
        let mut entries: Vec<icm::VpmEntry> = Vec::new();
        entries
            .try_reserve_exact(icm::VPM_ENTRIES_PER_MAILBOX)
            .map_err(|_| Mlx4Error::NoMemory)?;
        for _ in 0..npages {
            if self.command_failed.load(Ordering::Acquire)
                || self.bringup_deadline.is_some_and(|d| d.expired())
            {
                return Err(Mlx4Error::CmdTimeout);
            }
            let page = alloc_dma(&self.device, icm::ICM_PAGE_SIZE as usize)
                .map_err(|_| Mlx4Error::NoMemory)?;
            let phys = page.dma_addr().raw();
            entries.push(icm::VpmEntry {
                virt: if with_virt { *virt } else { 0 },
                phys,
            });
            if with_virt {
                *virt += icm::ICM_PAGE_SIZE;
            }
            pages.push(page);
            if entries.len() == icm::VPM_ENTRIES_PER_MAILBOX {
                let mb = icm::build_vpm_mailbox(&entries);
                self.cmd_in_mailbox(op, 0, entries.len() as u32, &mb)?;
                entries.clear();
            }
        }
        if !entries.is_empty() {
            let mb = icm::build_vpm_mailbox(&entries);
            self.cmd_in_mailbox(op, 0, entries.len() as u32, &mb)?;
        }
        Ok(pages)
    }

    // ── Datapath setup ──────────────────────────────────────────────

    /// Create the single Ethernet EQ/CQ/QP, a physical MR covering the
    /// datapath buffers, program the MAC + MTU, and post the initial
    /// receive ring. Runs in `bring_up` before the pumps spawn.
    fn setup_datapath(&self, _layout: &icm::IcmLayout) -> Result<(), Mlx4Error> {
        // One page backs the SQ+RQ, one the CQ, one the doorbell record.
        let wq = alloc_dma(&self.device, 4096).map_err(|_| Mlx4Error::NoMemory)?;
        let cq_buf = alloc_dma(&self.device, 4096).map_err(|_| Mlx4Error::NoMemory)?;
        let db_rec = alloc_dma(&self.device, 4096).map_err(|_| Mlx4Error::NoMemory)?;
        let rx_pool =
            alloc_dma(&self.device, RQ_N * RX_SLOT_LEN).map_err(|_| Mlx4Error::NoMemory)?;
        let tx_pool =
            alloc_dma(&self.device, SQ_N * TX_SLOT_LEN).map_err(|_| Mlx4Error::NoMemory)?;

        // Our object numbers sit at the first index past each resource's
        // firmware-reserved range (`QUERY_DEV_CAP`); the ICM tables were
        // sized in bring-up to cover reserved + these.
        let dc = self.dev_cap;
        let uar_index = self.uar_index;
        let eq_number = 1u32 << dc.log2_rsvd_eqs;
        let cq_number = 1u32 << dc.log2_rsvd_cqs;
        let qp_number = 1u32 << dc.log2_rsvd_qps;

        // One physical MR covering the whole address space — the
        // mlx4_en idiom. Data segments then carry device physical
        // addresses directly with this lkey.
        let data_lkey = self.create_physical_mr()?;

        // EQ: its own single page, one MTT entry.
        let eq_buf = alloc_dma(&self.device, 4096).map_err(|_| Mlx4Error::NoMemory)?;
        // Empty completion/event entries start hardware-owned (phase 1).
        // SAFETY: fresh DMA pages, initialized before SW2HW commands.
        unsafe {
            for i in 0..(1 << LOG_CQ_SIZE) {
                cq_buf
                    .cpu_mut_ptr_at::<u8>((i * cq::CQE_SIZE + 31) as u64)
                    .write(0x80);
            }
            for i in 0..(1 << LOG_EQ_SIZE) {
                eq_buf
                    .cpu_mut_ptr_at::<u8>((i * eq::EQE_SIZE + 31) as u64)
                    .write(0x80);
            }
        }
        let eq_mtt = self.alloc_mtt(1);
        self.write_mtt(eq_mtt, &[eq_buf.dma_addr().raw()])?;
        let eq_ctx = eq::build_eq_context(&eq::EqParams {
            log_eq_size: LOG_EQ_SIZE,
            intr: 0,
            mtt_base: self.mtt_addr(eq_mtt),
            log_page_size: 0,
        });
        self.cmd_in_mailbox(CmdOp::Sw2hwEq, 0, eq_number, &eq_ctx)?;
        // Completion polling does not arm EQ interrupts. Link uses QUERY_PORT.

        // CQ.
        let cq_mtt = self.alloc_mtt(1);
        self.write_mtt(cq_mtt, &[cq_buf.dma_addr().raw()])?;
        let cq_ctx = cq::build_cq_context(&cq::CqParams {
            log_cq_size: LOG_CQ_SIZE,
            uar_index,
            mtt_base: self.mtt_addr(cq_mtt),
            log_page_size: 0,
            comp_eqn: eq_number as u8,
            db_rec_addr: db_rec.dma_addr_at(0).raw(),
        });
        self.cmd_in_mailbox(CmdOp::Sw2hwCq, 0, cq_number, &cq_ctx)?;

        // QP (SQ+RQ in one page).
        let qp_mtt = self.alloc_mtt(1);
        self.write_mtt(qp_mtt, &[wq.dma_addr().raw()])?;
        let mut qp_ctx = qp::build_qp_context(&qp::QpEthParams {
            pd: 0,
            uar_index,
            cqn_send: cq_number,
            cqn_recv: cq_number,
            mtt_base: self.mtt_addr(qp_mtt),
            log_page_size: 0,
            log_rq_size: LOG_RQ_SIZE,
            log_rq_stride: LOG_RQ_STRIDE,
            log_sq_size: LOG_SQ_SIZE,
            log_sq_stride: LOG_SQ_STRIDE,
            port: 1,
            db_rec_addr: db_rec.dma_addr_at(8).raw(),
        });
        wire::put_be32(&mut qp_ctx, 0x10, qp_number);
        self.qp_to_ready(qp_number, &qp_ctx)?;

        // Program MTU + unicast MAC on the port.
        let gen = port::build_set_port_general(WIRE_MTU);
        self.cmd_in_mailbox(
            CmdOp::SetPort,
            port::SET_PORT_ETH_OPCODE,
            (u32::from(port::SET_PORT_GENERAL) << 8) | 1,
            &gen,
        )?;
        let mac = self.query_port()?.mac;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Mlx4Error::Other("invalid port MAC"));
        }
        let mac_mb = port::build_mac_table(&[mac], 1);
        self.cmd_in_mailbox(
            CmdOp::SetPort,
            port::SET_PORT_ETH_OPCODE,
            (u32::from(port::SET_PORT_MAC_TABLE) << 8) | 1,
            &mac_mb,
        )?;
        // INIT_HCA selects legacy (A0) steering. One receive QP accepts
        // our MAC and multicast/broadcast (ARP, DHCP, IPv6 discovery).
        let steering = port::build_rqp_calc(qp_number);
        self.cmd_in_mailbox(
            CmdOp::SetPort,
            port::SET_PORT_ETH_OPCODE,
            (u32::from(port::SET_PORT_RQP_CALC) << 8) | 1,
            &steering,
        )?;

        // Larger-stride queue comes first (Linux mlx4_ib set_kernel_sq_size).
        let sq_base = wq.cpu_ptr_at::<u8>(0) as u64;
        let rq_base = wq.cpu_ptr_at::<u8>((SQ_N * (1 << LOG_SQ_STRIDE)) as u64) as u64;

        {
            let mut nic = self.nic_state.lock();
            nic.mac = mac;
            nic.mtu = DEFAULT_MTU;
            nic.link_up = false;
        }

        *self.datapath.lock() = Some(DatapathState {
            qp_number,
            cq_number,
            data_lkey,
            _wq: wq,
            sq_base,
            rq_base,
            cq_buf,
            _eq: eq_buf,
            db_rec,
            rx_pool,
            tx_pool,
            tx_slots: TxSlotPool::new(),
            sq_prod: 0,
            rx_prod: 0,
            cq_cons: 0,
        });

        for slot in 0..RQ_N {
            self.post_recv_slot(slot)?;
        }
        Ok(())
    }

    /// Create one physical (no-MTT) memory region spanning the whole
    /// device address space; its lkey tags every datapath data
    /// segment (the mlx4_en idiom).
    fn create_physical_mr(&self) -> Result<u32, Mlx4Error> {
        let mpt_index = 1u32 << self.dev_cap.log2_rsvd_mrws; // first free MPT.
        let key = mr::hw_index_to_key(mpt_index);
        let mpt = mr::build_mpt(&mr::MptParams {
            pd: 0,
            access: mr::MLX4_PERM_LOCAL_READ | mr::MLX4_PERM_LOCAL_WRITE,
            key,
            start: 0,
            length: u64::MAX,
            mtt_addr: 0,
            page_shift: 12,
            physical: true,
        });
        self.cmd_in_mailbox(CmdOp::Sw2hwMpt, 0, mpt_index, &mpt)?;
        Ok(key)
    }

    /// Run a QP through RST→INIT→RTR→RTS with the same base context.
    fn qp_to_ready(&self, qp_number: u32, ctx: &[u8; qp::QP_CONTEXT_LEN]) -> Result<(), Mlx4Error> {
        for (trans, op) in [
            (qp::QpTransition::RstToInit, CmdOp::Rst2initQp),
            (qp::QpTransition::InitToRtr, CmdOp::Init2rtrQp),
            (qp::QpTransition::RtrToRts, CmdOp::Rtr2rtsQp),
        ] {
            let mb = qp::build_modify_mailbox(ctx, trans, 0);
            self.cmd_in_mailbox(op, 0, qp_number, &mb)?;
        }
        Ok(())
    }

    /// Read the port's default MAC via QUERY_PORT.
    fn query_port(&self) -> Result<port::PortInfo, Mlx4Error> {
        let mb = self.cmd_out_mailbox(CmdOp::QueryPort, 0, 1, 0x40)?;
        Ok(port::decode_query_port(&mb))
    }
    fn refresh_link(&self) -> Result<(), Mlx4Error> {
        match self.query_port() {
            Ok(info) => {
                self.nic_state.lock().link_up = info.link_up;
                Ok(())
            }
            Err(error) => {
                self.nic_state.lock().link_up = false;
                Err(error)
            }
        }
    }
    /// At most one bounded link query per second; permanently stop after HCR timeout.
    pub fn poll_link(&self) {
        {
            let mut next = self.next_link_poll.lock();
            if next.is_some_and(|d| !d.expired()) {
                return;
            }
            *next = Some(narf_time::Deadline::after_ms(1000));
        }
        let _ = self.refresh_link();
    }

    // ── Datapath: TX ─────────────────────────────────────────────────

    /// Transmit one frame: copy into a staging slot, post a send WQE,
    /// ring the send doorbell.
    pub fn transmit(&self, frame: &[u8]) -> Result<(), Mlx4Error> {
        let _busy = Busy::enter(&self.tx_busy).ok_or(Mlx4Error::TxSlotsExhausted)?;
        if frame.len() > TX_SLOT_LEN {
            return Err(Mlx4Error::FrameTooLarge);
        }
        let (slot, slot_cpu, slot_va, sq_slot, wqe_idx, own, qpn, sq_addr) = {
            let mut dp = self.datapath.lock();
            let dp = dp.as_mut().ok_or(Mlx4Error::NoDatapath)?;
            let slot = dp.tx_slots.claim().ok_or(Mlx4Error::TxSlotsExhausted)?;
            let slot_cpu = dp.tx_slot_cpu(slot);
            let slot_va = dp.tx_slot_va(slot);
            let wqe_idx = dp.sq_prod;
            let sq_slot = (wqe_idx as usize) % SQ_N;
            let own = (wqe_idx & (1 << LOG_SQ_SIZE)) != 0;
            let sq_addr = dp.sq_base + (sq_slot * (1 << LOG_SQ_STRIDE)) as u64;
            dp.sq_prod = dp.sq_prod.wrapping_add(1);
            dp.tx_slots.record(wqe_idx, slot);
            (
                slot,
                slot_cpu,
                slot_va,
                sq_slot,
                wqe_idx,
                own,
                dp.qp_number,
                sq_addr,
            )
        };
        let _ = (slot, sq_slot);
        // Copy the frame into its staging slot.
        // SAFETY: the slot is claimed (exclusively ours) and names
        // `TX_SLOT_LEN` coherent bytes; `frame.len() <= TX_SLOT_LEN`.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), slot_cpu, frame.len());
        }
        let data_lkey = {
            let dp = self.datapath.lock();
            dp.as_ref().ok_or(Mlx4Error::NoDatapath)?.data_lkey
        };
        let wqe = wqe::build_tx_wqe(own, false, slot_va, data_lkey, frame.len() as u32);
        // Write the WQE into the SQ slot.
        // SAFETY: `sq_addr` is the identity-mapped SQ-slot DMA address.
        unsafe {
            let dst = sq_addr as *mut u8;
            core::ptr::copy_nonoverlapping(wqe.as_ptr().add(4), dst.add(4), wqe.len() - 4);
            core::sync::atomic::fence(Ordering::Release);
            core::ptr::write_volatile(
                dst.cast::<u32>(),
                core::ptr::read_unaligned(wqe.as_ptr().cast::<u32>()),
            );
        }
        fence(Ordering::SeqCst);
        // Ring the send doorbell (BAR2 UAR).
        self.uar_write(
            self.uar_index,
            wqe::SEND_DOORBELL_UAR_OFFSET,
            wqe::tx_doorbell_word(qpn),
        );
        let _ = wqe_idx;
        Ok(())
    }

    /// Write a big-endian doorbell word into a UAR page in BAR2.
    fn uar_write(&self, uar_index: u32, byte_off: u64, host_value: u32) {
        let abs = u64::from(uar_index) * UAR_PAGE_SIZE + byte_off;
        // SAFETY: identity-mapped MMIO; BE on wire, so swap.
        unsafe {
            self.uar.write32(abs, host_value.swap_bytes());
        }
    }

    // ── Datapath: RX / completion drain ──────────────────────────────

    /// Post a receive WQE for RX pool slot `slot`.
    fn post_recv_slot(&self, slot: usize) -> Result<(), Mlx4Error> {
        let (rq_addr, va, lkey, prod) = {
            let mut dp = self.datapath.lock();
            let dp = dp.as_mut().ok_or(Mlx4Error::NoDatapath)?;
            let rq_slot = slot % RQ_N;
            let rq_addr = dp.rq_base + (rq_slot * (1 << LOG_RQ_STRIDE)) as u64;
            let va = dp.rx_slot_va(slot);
            let lkey = dp.data_lkey;
            dp.rx_prod = dp.rx_prod.wrapping_add(1);
            (rq_addr, va, lkey, dp.rx_prod)
        };
        let wqe = wqe::build_rx_wqe(va, lkey, RX_SLOT_LEN as u32);
        // SAFETY: `rq_addr` is the identity-mapped RQ-slot DMA address.
        unsafe {
            let dst = rq_addr as *mut u8;
            core::ptr::copy_nonoverlapping(wqe.as_ptr(), dst, wqe.len());
        }
        fence(Ordering::SeqCst);
        // Bump the RX producer doorbell record (host memory).
        self.write_rx_prod_db(prod);
        Ok(())
    }

    fn write_rx_prod_db(&self, prod: u32) {
        let dp = self.datapath.lock();
        if let Some(dp) = dp.as_ref() {
            let w = wqe::rx_prod_doorbell_word(prod).swap_bytes();
            // SAFETY: the doorbell record is the driver's resident DMA page.
            unsafe {
                core::ptr::write_volatile(dp.db_rec.cpu_mut_ptr_at::<u32>(8), w);
            }
        }
    }

    /// Drain up to `budget` CQEs. TX completions free their staging
    /// slot; RX completions deliver the frame and repost the slot.
    pub fn drain_datapath(&self, budget: usize) -> usize {
        let Some(_busy) = Busy::enter(&self.drain_busy) else {
            return 0;
        };
        let (cq_base_cpu, cq_number) = {
            let dp = self.datapath.lock();
            match dp.as_ref() {
                Some(dp) => (dp.cq_buf.cpu_ptr::<u8>() as usize, dp.cq_number),
                None => return 0,
            }
        };
        let _ = cq_number;
        let cq_cap: u32 = 1 << LOG_CQ_SIZE;
        let mut handled = 0usize;
        while handled < budget {
            let cons = {
                let dp = self.datapath.lock();
                match dp.as_ref() {
                    Some(dp) => dp.cq_cons,
                    None => return handled,
                }
            };
            let idx = (cons % cq_cap) as usize;
            let cqe_ptr = (cq_base_cpu + idx * cq::CQE_SIZE) as *const u8;
            // Read ownership first, then acquire the device-written payload.
            // SAFETY: ownership byte lies within this CQ entry.
            let owner = unsafe { core::ptr::read_volatile(cqe_ptr.add(31)) };
            if !cq::cqe_is_sw_owned(owner, cons, cq_cap) {
                break;
            }
            core::sync::atomic::fence(Ordering::Acquire);
            let mut raw = [0u8; cq::CQE_SIZE];
            // SAFETY: `cqe_ptr` is within the resident CQ buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(cqe_ptr, raw.as_mut_ptr(), cq::CQE_SIZE);
            }

            let cqe = cq::decode_cqe(&raw);
            {
                let mut dp = self.datapath.lock();
                if let Some(dp) = dp.as_mut() {
                    dp.cq_cons = dp.cq_cons.wrapping_add(1);
                }
            }
            if cqe.is_send {
                let mut dp = self.datapath.lock();
                if let Some(dp) = dp.as_mut() {
                    dp.tx_slots.release(cqe.wqe_index);
                }
            } else {
                self.rx_complete(&cqe);
            }
            // Update the CQ consumer doorbell.
            self.write_cq_ci();
            handled += 1;
        }
        handled
    }

    fn write_cq_ci(&self) {
        let (cons, cqn) = {
            let dp = self.datapath.lock();
            match dp.as_ref() {
                Some(dp) => (dp.cq_cons, dp.cq_number),
                None => return,
            }
        };
        let _ = cqn;
        // Polled CQ: advance the host-memory set_ci record; do not arm an
        // interrupt vector that the module has not installed.
        let dp = self.datapath.lock();
        if let Some(dp) = dp.as_ref() {
            core::sync::atomic::fence(Ordering::Release);
            // SAFETY: first dword of the resident CQ doorbell record.
            unsafe {
                core::ptr::write_volatile(
                    dp.db_rec.cpu_mut_ptr_at::<u32>(0),
                    (cons & 0xffffff).to_be(),
                );
            }
        }
    }

    /// Write a 64-bit (two big-endian words) CQ doorbell into a UAR page.
    #[allow(dead_code)]
    fn uar_write64(&self, uar_index: u32, byte_off: u64, words: [u32; 2]) {
        let abs = u64::from(uar_index) * UAR_PAGE_SIZE + byte_off;
        // SAFETY: identity-mapped MMIO; BE on wire.
        unsafe {
            self.uar.write32(abs, words[0].swap_bytes());
            self.uar.write32(abs + 4, words[1].swap_bytes());
        }
    }

    fn rx_complete(&self, cqe: &cq::CqeView) {
        if cqe.bad_fcs() || cqe.is_error() || !(14..=RX_SLOT_LEN as u32).contains(&cqe.byte_cnt) {
            let slot = (cqe.wqe_index as usize) % RQ_N;
            let _ = self.post_recv_slot(slot);
            return;
        }
        let slot = (cqe.wqe_index as usize) % RQ_N;
        let len = (cqe.byte_cnt as usize).min(RX_SLOT_LEN);
        let (slot_ptr, l4_ok, ip_ok) = {
            let dp = self.datapath.lock();
            match dp.as_ref() {
                Some(dp) => (
                    dp.rx_pool.cpu_ptr_at::<u8>((slot * RX_SLOT_LEN) as u64),
                    cqe.l4_csum_ok(),
                    cqe.ip_csum_ok(),
                ),
                None => return,
            }
        };
        #[cfg(feature = "module")]
        let _ = (l4_ok, ip_ok);
        if len > 0 {
            #[cfg(feature = "builtin")]
            if let Ok(buf) = alloc_coherent(len, DomainId::DRIVER_0) {
                // SAFETY: `slot_ptr` names `RX_SLOT_LEN` resident bytes
                // the HCA just filled; `len` is clamped to the slot.
                unsafe {
                    core::ptr::copy_nonoverlapping(slot_ptr, buf.cpu_mut_ptr_at::<u8>(0), len);
                }
                let mut f = Frame::new(buf, len as u32);
                f.set_rx_meta(narf_net::RxMeta {
                    csum_l3: ip_ok,
                    csum_l4: l4_ok,
                    ..Default::default()
                });
                if let Some(prod) = self.rx_ipc_prod.lock().as_mut() {
                    let _ = prod.try_send(f);
                }
            }
            // SAFETY: same resident slot bounds; `deliver_rx` returns
            // before the slot is reposted below.
            let bytes = unsafe { core::slice::from_raw_parts_mut(slot_ptr as *mut u8, len) };
            #[cfg(feature = "builtin")]
            crate::publish::deliver_rx(self.ifname(), bytes);
            #[cfg(feature = "module")]
            crate::module_probe::deliver(self.device.token, bytes);
        }
        let _ = self.post_recv_slot(slot);
    }
}

// ── narf_net integration ────────────────────────────────────────────

#[cfg(feature = "builtin")]
impl narf_net::Interface for Mlx4Eth {
    fn name(&self) -> &str {
        self.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic_state().mac
    }
    fn mtu(&self) -> u32 {
        let m = self.nic_state().mtu;
        if m == 0 {
            DEFAULT_MTU
        } else {
            m
        }
    }
    fn link_up(&self) -> bool {
        self.nic_state().link_up
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

#[cfg(feature = "builtin")]
impl crate::HwNic for Mlx4Eth {
    fn name(&self) -> &'static str {
        "mlx4"
    }
    fn mac(&self) -> [u8; 6] {
        self.nic_state().mac
    }
    fn mtu(&self) -> u32 {
        let m = self.nic_state().mtu;
        if m == 0 {
            DEFAULT_MTU
        } else {
            m
        }
    }
    fn link_up(&self) -> bool {
        self.nic_state().link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::MellanoxMlx4
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::RX_CSUM
    }
    fn ring_capacity(&self) -> usize {
        RQ_N
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

// ── Probe / registration ────────────────────────────────────────────

#[cfg(feature = "builtin")]
static CONTROLLERS: IrqSafeSpinLock<Vec<Arc<Mlx4Eth>>> = IrqSafeSpinLock::new(Vec::new());

/// The probed controller at `index`.
#[cfg(feature = "builtin")]
pub fn controller(index: usize) -> Option<Arc<Mlx4Eth>> {
    CONTROLLERS.lock().get(index).cloned()
}

/// Number of probed controllers.
#[cfg(feature = "builtin")]
pub fn instance_count() -> usize {
    CONTROLLERS.lock().len()
}

/// `true` once at least one ConnectX-3 has been probed.
#[cfg(feature = "builtin")]
pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

#[cfg(feature = "builtin")]
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLERS.lock().iter().any(|c| c.addr == device.addr) {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: probe holds exclusive authority over `device` + its cfg
    // `cap` across `bring_up`.
    let dev = match unsafe { Mlx4Eth::bring_up(&device) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("mlx4"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    let state = dev.nic_state();
    let name = crate::publish::publish_netdev_with_context(
        state.mac,
        index as u64,
        mlx4_send_frame,
        crate::publish::LinkSample::carrier_only(state.link_up),
    );
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "mlx4", None, bus_info);
    dev.ifname.set(name.clone());
    narf_net::iface::install_rx_drain(mlx4_rx_pump_step);
    let _ = narf_net::iface::set_software_gro(&name, true);

    let auth = narf_net::trusted_net_authority().and_then(|a| a.derive().ok());
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Mlx4NetIface { nic: dev.clone() });
    }
    Ok(())
}

/// Lightweight registry adapter — owns its instance's `Arc` so each
/// port gets its own rings (the `Rtl8125Nic` / `Mlx5NetIface` pattern).
#[derive(Debug)]
#[cfg(feature = "builtin")]
pub struct Mlx4NetIface {
    nic: Arc<Mlx4Eth>,
}

#[cfg(feature = "builtin")]
impl narf_net::Interface for Mlx4NetIface {
    fn name(&self) -> &str {
        self.nic.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.nic_state().mac
    }
    fn mtu(&self) -> u32 {
        let m = self.nic.nic_state().mtu;
        if m == 0 {
            DEFAULT_MTU
        } else {
            m
        }
    }
    fn link_up(&self) -> bool {
        self.nic.nic_state().link_up
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

#[cfg(feature = "builtin")]
fn spawn_pumps(device: Arc<Mlx4Eth>, tx_cons: Consumer<Frame, TX_RING_N>) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        mlx4_rx_pump(d1).await;
    });
    narf_scheduler::spawn(async move {
        mlx4_tx_pump(device, tx_cons).await;
    });
}

#[cfg(feature = "builtin")]
async fn mlx4_rx_pump(device: Arc<Mlx4Eth>) {
    let poll_cycles = narf_time::ns_to_cycles(RX_POLL_INTERVAL_NS);
    loop {
        device.poll_link();
        let _ = narf_net::iface::set_link_metadata(
            device.ifname(),
            device.nic_state().link_up,
            None,
            None,
        );
        if device.drain_datapath(RX_DRAIN_BUDGET) != 0 {
            continue;
        }
        narf_time::sleep_cycles(poll_cycles).await;
    }
}

#[cfg(feature = "builtin")]
async fn mlx4_tx_pump(device: Arc<Mlx4Eth>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        if frame.len() as usize > TX_SLOT_LEN {
            continue;
        }
        let mut tries = 0u32;
        loop {
            match device.transmit(frame.payload()) {
                Ok(()) => break,
                Err(Mlx4Error::TxSlotsExhausted) if tries < TX_RETRY_MAX => {
                    tries += 1;
                    narf_time::sleep_cycles(narf_time::ns_to_cycles(RX_POLL_INTERVAL_NS)).await;
                }
                Err(_) => break,
            }
        }
    }
}

/// Synchronous CQ drain over every probed controller — for
/// syscall-context busy-waits (ARP / TCP handshake).
#[cfg(feature = "builtin")]
pub fn mlx4_rx_pump_step() -> bool {
    let controllers = CONTROLLERS.lock().clone();
    let mut any = false;
    for c in controllers {
        any |= c.drain_datapath(RX_DRAIN_BUDGET) != 0;
    }
    any
}

/// Stack `SendCtxFn`: transmit through the cookie's controller.
#[cfg(feature = "builtin")]
fn mlx4_send_frame(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = controller(usize::try_from(cookie).map_err(|_| ())?).ok_or(())?;
    ctrl.transmit(frame).map_err(|_| ())
}

/// Register the driver against the ConnectX-3 device ids.
#[cfg(feature = "builtin")]
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MLX4_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

#[cfg(feature = "builtin")]
fn name_for(did: u16) -> &'static str {
    match did {
        MLX4_DEV_CX3 => "mlx4-connectx3",
        MLX4_DEV_CX3_PRO => "mlx4-connectx3-pro",
        _ => "mlx4",
    }
}

#[cfg(feature = "module")]
impl Mlx4Eth {
    pub(crate) fn module_access_failed(&self) -> bool {
        self.mmio.failed() || self.uar.failed() || self.command_failed.load(Ordering::Acquire)
    }
}
