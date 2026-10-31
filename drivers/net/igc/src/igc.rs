//! Intel I225/I226 native Ethernet driver.
//! Protocol reference: ~/git/linux ecd997b0189a, drivers/net/ethernet/intel/igc.
//! Advanced queues, checked offloads and DMA ownership through completion/reset.

pub const IGC_VENDOR: u16 = 0x8086;

/// I225-LM (LAN-on-motherboard variant).
pub const IGC_I225_LM: u16 = 0x15F2;
/// I225-V (consumer variant).
pub const IGC_I225_V: u16 = 0x15F3;
/// I225-IT (industrial-temp).
pub const IGC_I225_IT: u16 = 0x0D9F;
/// I225-I (server / iLM).
pub const IGC_I225_I: u16 = 0x15F8;
/// I220-V (1 GbE Foxville-Lite).
pub const IGC_I220_V: u16 = 0x15F7;
/// I225-K — NUC / embedded.
pub const IGC_I225_K: u16 = 0x3100;
/// I225-K2 — NUC stepping.
pub const IGC_I225_K2: u16 = 0x3101;
/// I225-LMVP — vPro stepping.
pub const IGC_I225_LMVP: u16 = 0x5502;
/// I225 blank NVM — boot fallback.
pub const IGC_I225_BLANK_NVM: u16 = 0x15FD;
/// I226-LM (LAN-on-motherboard).
pub const IGC_I226_LM: u16 = 0x125B;
/// I226-V.
pub const IGC_I226_V: u16 = 0x125C;
/// I226-IT.
pub const IGC_I226_IT: u16 = 0x125D;
/// I226-K — NUC / embedded.
pub const IGC_I226_K: u16 = 0x3102;
/// I226-LMVP — vPro stepping.
pub const IGC_I226_LMVP: u16 = 0x5503;
/// I226 blank NVM — boot fallback.
pub const IGC_I226_BLANK_NVM: u16 = 0x125F;
/// I221-V (1 GbE).
pub const IGC_I221_V: u16 = 0x125E;

pub const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
pub const IMS_TXDW: u32 = 1 << 0;
pub const IMS_LSC: u32 = 1 << 2;
pub const IMS_RXO: u32 = 1 << 6;
pub const IMS_RXDMT0: u32 = 1 << 4;
pub const IMS_RXT0: u32 = 1 << 7;
pub const IMS_DEFAULT: u32 = IMS_TXDW | IMS_LSC | IMS_RXO | IMS_RXDMT0 | IMS_RXT0;
pub const GPIE_NSICR: u32 = 1 << 0;
pub const GPIE_MULTIPLE_MSIX: u32 = 1 << 4;
pub const GPIE_EIAME: u32 = 1 << 30;
pub const GPIE_PBA: u32 = 1 << 31;
pub const IGC_ADVTXD_DTYP_DATA: u32 = 0x0030_0000;
/// Advanced TX context descriptor type (bits[21:20] = 0b10).
pub const IGC_ADVTXD_DTYP_CTXT: u32 = 0x0020_0000;
pub const IGC_ADVTXD_DCMD_DEXT: u32 = 1 << 29;
pub const IGC_ADVTXD_DCMD_RS: u32 = 1 << 27;
pub const IGC_ADVTXD_DCMD_IFCS: u32 = 1 << 25;
pub const IGC_ADVTXD_DCMD_EOP: u32 = 1 << 24;
/// TSE — TCP Segmentation Enable (bit 31 of cmd_type_len).
pub const IGC_ADVTXD_DCMD_TSE: u32 = 1 << 31;
/// PAYLEN shift — payload length sits at bits[31:14] of olinfo_status.
pub const IGC_ADVTXD_PAYLEN_SHIFT: u32 = 14;
/// Insert IP checksum (bit 8 of olinfo_status POPTS field).
pub const IGC_TXD_POPTS_IXSM: u32 = 0x0100;
/// Insert TCP/UDP checksum (bit 9 of olinfo_status POPTS field).
pub const IGC_TXD_POPTS_TXSM: u32 = 0x0200;
/// MAC length shift in vlan_macip_lens (bits[18:9]).
pub const IGC_ADVTXD_MACLEN_SHIFT: u32 = 9;
/// TUCMD: IPv4 packet.
pub const IGC_ADVTXD_TUCMD_IPV4: u32 = 0x400;
/// TUCMD: L4 type = TCP.
pub const IGC_ADVTXD_TUCMD_L4T_TCP: u32 = 0x800;
/// L4 length shift in mss_l4len_idx (bits[15:8]).
pub const IGC_ADVTXD_L4LEN_SHIFT: u32 = 8;
/// MSS shift in mss_l4len_idx (bits[31:16]).
pub const IGC_ADVTXD_MSS_SHIFT: u32 = 16;

/// Advanced TX context descriptor. Precedes the data descriptor for
/// TSO; carries MSS / L4len / TUCMD. Layout mirrors igc_base.h.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxCtxtDesc {
    pub vlan_macip_lens: u32,
    pub launch_time: u32,
    pub type_tucmd_mlhl: u32,
    pub mss_l4len_idx: u32,
}

/// Advanced TX data descriptor. Replaces the legacy 8-byte descriptor
/// on igc hardware when DEXT is set. Used for both plain sends and TSO.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxDataDesc {
    pub buffer_addr: u64,
    pub cmd_type_len: u32,
    pub olinfo_status: u32,
}

// ── Descriptor offload impl blocks ──────────────────────────────────

impl AdvTxCtxtDesc {
    /// Build a TSO context descriptor for an IPv4/TCP frame.
    pub fn new_tso_v4(mac_len: u8, ip_len: u8, l4_len: u8, mss: u16) -> Self {
        let vlan_macip_lens = (ip_len as u32) | ((mac_len as u32) << IGC_ADVTXD_MACLEN_SHIFT);
        let type_tucmd_mlhl = IGC_ADVTXD_DCMD_DEXT
            | IGC_ADVTXD_DTYP_CTXT
            | IGC_ADVTXD_TUCMD_IPV4
            | IGC_ADVTXD_TUCMD_L4T_TCP;
        let mss_l4len_idx =
            ((l4_len as u32) << IGC_ADVTXD_L4LEN_SHIFT) | ((mss as u32) << IGC_ADVTXD_MSS_SHIFT);
        AdvTxCtxtDesc {
            vlan_macip_lens,
            launch_time: 0,
            type_tucmd_mlhl,
            mss_l4len_idx,
        }
    }
}

impl AdvTxDataDesc {
    /// Build a data descriptor with IP + TCP/UDP checksum offload.
    pub fn with_csum(addr: u64, len: u16) -> Self {
        let cmd_type_len = (len as u32)
            | IGC_ADVTXD_DTYP_DATA
            | IGC_ADVTXD_DCMD_DEXT
            | IGC_ADVTXD_DCMD_RS
            | IGC_ADVTXD_DCMD_IFCS
            | IGC_ADVTXD_DCMD_EOP;
        let olinfo_status =
            ((len as u32) << IGC_ADVTXD_PAYLEN_SHIFT) | IGC_TXD_POPTS_IXSM | IGC_TXD_POPTS_TXSM;
        AdvTxDataDesc {
            buffer_addr: addr,
            cmd_type_len,
            olinfo_status,
        }
    }

    /// Build a data descriptor with TSO enabled. The hardware segments
    /// using the MSS from the preceding context descriptor.
    pub fn with_tso(addr: u64, len: u16, _mss: u16) -> Self {
        let cmd_type_len = (len as u32)
            | IGC_ADVTXD_DTYP_DATA
            | IGC_ADVTXD_DCMD_DEXT
            | IGC_ADVTXD_DCMD_RS
            | IGC_ADVTXD_DCMD_IFCS
            | IGC_ADVTXD_DCMD_EOP
            | IGC_ADVTXD_DCMD_TSE;
        let olinfo_status =
            ((len as u32) << IGC_ADVTXD_PAYLEN_SHIFT) | IGC_TXD_POPTS_IXSM | IGC_TXD_POPTS_TXSM;
        AdvTxDataDesc {
            buffer_addr: addr,
            cmd_type_len,
            olinfo_status,
        }
    }
}

use crate::{
    hardware::{self, Registers},
    packet::{MAX_MTU, MAX_TSO},
    queue::{Queue, COUNT},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_io::alloc_coherent;
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};
use narf_net::{Frame, OffloadCapabilities, TxMeta, RX_RING_N, TX_RING_N};

const STOPPED: u8 = 0;
const RUNNING: u8 = 1;
const CHANGING: u8 = 2;
const SUSPENDED: u8 = 3;
const FAILED: u8 = 4;
const ADMIN_DOWN: u8 = 5;
const REMOVED: u8 = 6;
#[path = "control.rs"]
mod control;
const OFFLOADS: OffloadCapabilities = OffloadCapabilities {
    tx_checksum: true,
    rx_checksum: true,
    max_tso_bytes: MAX_TSO as u32,
    vlan_insert: true,
};

pub use crate::protocol::IgcError;

struct Check;
impl CapOp<BusDeviceCap, Write> for Check {
    type Output = ();
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<(), CapError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Hardware {
    mmio: MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
}
struct RegisterAccess<'a> {
    hw: &'a Hardware,
    reg: u64,
    value: Option<u32>,
}
impl CapOp<BusDeviceCap, Write> for RegisterAccess<'_> {
    type Output = u32;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<u32, CapError> {
        assert!(self.reg % 4 == 0 && self.reg + 4 <= self.hw.mmio.len);
        // SAFETY: live exclusive device capability is checked by invoke;
        // alignment and mapped bounds are checked above.
        unsafe {
            if let Some(value) = self.value {
                self.hw.mmio.write32(self.reg, value);
                Ok(0)
            } else {
                Ok(self.hw.mmio.read32(self.reg))
            }
        }
    }
}
impl Registers for Hardware {
    fn read(&self, reg: u64) -> u32 {
        self.cap
            .invoke(RegisterAccess {
                hw: self,
                reg,
                value: None,
            })
            .unwrap_or(u32::MAX)
    }
    fn write(&self, reg: u64, value: u32) {
        let _ = self.cap.invoke(RegisterAccess {
            hw: self,
            reg,
            value: Some(value),
        });
    }
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool {
        hardware::wait_until(us, ready)
    }
    fn delay(&self, us: u64) {
        let deadline = narf_time::Deadline::after_us(us);
        narf_scheduler::responsive_spin_until(|| deadline.expired(), deadline);
    }
}

/// Cumulative diagnostics. Hardware counters are clear-on-read and sampled
/// only by the maintenance worker, so snapshots never clear another reader.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IgcStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub crc_errors: u64,
    pub missed_packets: u64,
    pub rx_drops: u64,
    pub tx_rejected: u64,
    pub resets: u64,
}

#[derive(Clone, Debug)]
struct Config {
    mac: [u8; 6],
    mtu: u32,
    promiscuous: bool,
    all_multicast: bool,
    multicast: Vec<[u8; 6]>,
    unicast: Vec<[u8; 6]>,
}

#[derive(Debug)]
pub struct Igc {
    hw: Hardware,
    device: BusDevice,
    config: IrqSafeSpinLock<Config>,
    mtu: AtomicU32,
    queues: IrqSafeSpinLock<Arc<Vec<Arc<Queue>>>>,
    ptp: IrqSafeSpinLock<crate::ptp::ClockState>,
    phc_index: core::sync::atomic::AtomicI32,
    counters: IrqSafeSpinLock<crate::counters::Counters>,
    queue_history: IrqSafeSpinLock<[[u64; 8]; 4]>,
    schedule: IrqSafeSpinLock<crate::traffic::Schedule>,
    flows: IrqSafeSpinLock<Vec<narf_net::nic::FlowRule>>,
    merge: IrqSafeSpinLock<crate::merge::Merge>,
    quarantine: IrqSafeSpinLock<Vec<Arc<Vec<Arc<Queue>>>>>,
    settings: IrqSafeSpinLock<narf_net::nic::Settings>,
    ifname: crate::publish::IfName,
    cookie: u64,
    removed: AtomicBool,
    admin_up: AtomicBool,
    recovery_requested: AtomicBool,
    pub(crate) irq_routes: Vec<IrqRoute>,
    state: AtomicU8,
    active: AtomicUsize,
    control_busy: AtomicBool,
    stats: IrqSafeSpinLock<IgcStats>,
    msix: IrqSafeSpinLock<Option<MsixTable>>,
    saved_pci: narf_bus::pci::SavedPciConfig,
    /// Administrative vector; queue completions use `irq_routes` when available.
    pub irq_vector: Option<u8>,
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

struct Operation<'a>(&'a AtomicUsize);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct ControlLease<'a>(&'a AtomicBool);
impl Drop for ControlLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// Failed initialization retains all DMA and BAR ownership. A failed reset
// cannot prove that the controller has stopped touching its old rings.
static RETAINED: IrqSafeSpinLock<Vec<Arc<Igc>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_COOKIE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
#[derive(Clone, Copy, Debug)]
pub(crate) struct IrqRoute {
    vector: u8,
    #[cfg(target_arch = "x86_64")]
    cpu: u32,
    index: u8,
}
static ISR_HW: [IrqSafeSpinLock<Option<Hardware>>; 256] =
    [const { IrqSafeSpinLock::new(None) }; 256];
fn igc_isr(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    let hw = *ISR_HW[cookie as usize & 255].lock();
    if let Some(hw) = hw {
        let _ = hw.read(0x1500);
    }
    narf_interrupts::dispatch::IrqStatus::Handled
}
fn queue_cpu(queue: usize) -> u32 {
    let bits = narf_scheduler::online_cpu_set().bits();
    (0..64)
        .filter(|i| bits & (1u64 << i) != 0)
        .nth(queue % bits.count_ones().max(1) as usize)
        .unwrap_or(0)
}

impl Igc {
    /// Initialize a single exclusively owned PCI function.
    ///
    /// # Safety
    /// Caller owns BAR0 and the PCI function exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Arc<Self>, IgcError> {
        // SAFETY: caller's exclusive ownership contract.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IgcError::BarMapFailed)?;
        if mmio.len < 0x20000 {
            return Err(IgcError::BarMapFailed);
        }
        let hw = Hardware { mmio, cap: *cap };
        hardware::reset(&hw, 4)?;
        let mac = hardware::read_mac(&hw)?;
        let mut queues = Vec::new();
        let count = narf_scheduler::online_cpu_set().len().clamp(1, 4) as usize;
        for _ in 0..count {
            queues.push(Arc::new(Queue::new()?));
        }
        let (msix, irq_routes) = Self::try_enable_msix(cap, device).unwrap_or((None, Vec::new()));
        let irq_vector = irq_routes.first().map(|r| r.vector);
        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
        let controller = Arc::new(Self {
            hw,
            device: *device,
            config: IrqSafeSpinLock::new(Config {
                mac,
                mtu: 1500,
                promiscuous: false,
                all_multicast: true,
                multicast: Vec::new(),
                unicast: Vec::new(),
            }),
            mtu: AtomicU32::new(1500),
            queues: IrqSafeSpinLock::new(Arc::new(queues)),
            ptp: IrqSafeSpinLock::new(crate::ptp::ClockState::new()),
            phc_index: core::sync::atomic::AtomicI32::new(-1),
            counters: IrqSafeSpinLock::new(crate::counters::Counters::new()),
            queue_history: IrqSafeSpinLock::new([[0; 8]; 4]),
            schedule: IrqSafeSpinLock::new(
                crate::traffic::Schedule::validate(Default::default(), count, 0).unwrap(),
            ),
            flows: IrqSafeSpinLock::new(Vec::new()),
            merge: IrqSafeSpinLock::new(crate::merge::Merge::new()),
            quarantine: IrqSafeSpinLock::new(Vec::new()),
            settings: IrqSafeSpinLock::new(narf_net::nic::Settings {
                rx_entries: COUNT as u32,
                tx_entries: COUNT as u32,
                channels: count as u16,
                coalesce_us: 166,
                rss: narf_net::rss::RssConfig::standard(count, 128),
                link: narf_net::nic::LinkSettings {
                    advertised: if matches!(device.id.device, IGC_I220_V | IGC_I221_V) {
                        0x1f
                    } else {
                        0x3f
                    },
                    ..Default::default()
                },
                pause: Default::default(),
                eee: false,
                wake: 0,
            }),
            ifname: crate::publish::IfName::new(),
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            removed: AtomicBool::new(false),
            admin_up: AtomicBool::new(true),
            recovery_requested: AtomicBool::new(false),
            irq_routes,
            state: AtomicU8::new(STOPPED),
            active: AtomicUsize::new(0),
            control_busy: AtomicBool::new(false),
            stats: IrqSafeSpinLock::new(IgcStats::default()),
            saved_pci: narf_bus::pci::save_config(cap, device)
                .map_err(|_| IgcError::BarMapFailed)?,
            msix: IrqSafeSpinLock::new(msix),
            irq_vector,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });
        // Retain before any ring DMA address reaches the device.
        RETAINED.lock().push(controller.clone());
        for route in &controller.irq_routes {
            *ISR_HW[route.vector as usize].lock() = Some(controller.hw);
            narf_interrupts::dispatch::install_handler_named(
                route.vector,
                "igc",
                u64::from(route.vector),
                igc_isr,
            );
        }
        if let Err(error) = controller.start() {
            controller.state.store(FAILED, Ordering::Release);
            let _ = hardware::quiesce(&controller.hw, count);
            return Err(error);
        }
        spawn_pumps(controller.clone(), rx_prod, tx_cons);
        Ok(controller)
    }

    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(Option<MsixTable>, Vec<IrqRoute>), IgcError> {
        let mut table = enable_msix(cap, device).map_err(|_| IgcError::BarMapFailed)?;
        let mut routes = Vec::new();
        for i in 0..table.size().min(5) {
            table.alloc_vector().ok_or(IgcError::BarMapFailed)?;
            let vector = match narf_interrupts::vector::alloc() {
                Ok(v) => v,
                Err(_) => {
                    for r in &routes {
                        let r: &IrqRoute = r;
                        let _ = narf_interrupts::vector::free(r.vector);
                    }
                    return Err(IgcError::BarMapFailed);
                }
            };
            routes.push(IrqRoute {
                vector,
                #[cfg(target_arch = "x86_64")]
                cpu: queue_cpu(i.saturating_sub(1) as usize),
                index: i as u8,
            });
        }
        if routes.is_empty() {
            return Err(IgcError::BarMapFailed);
        }
        Ok((Some(table), routes))
    }
    fn name(&self) -> &'static str {
        self.ifname.get()
    }
    fn queues(&self) -> Arc<Vec<Arc<Queue>>> {
        self.queues.lock().clone()
    }
    fn route(&self, q: usize) -> Option<IrqRoute> {
        if self.irq_routes.is_empty() {
            None
        } else {
            self.irq_routes
                .get(if self.irq_routes.len() == 1 {
                    0
                } else {
                    1 + q % (self.irq_routes.len() - 1)
                })
                .copied()
        }
    }
    fn operation(&self) -> Result<Operation<'_>, IgcError> {
        // SeqCst orders the two-atomic stop/entry handshake on both arches.
        // Stop cannot observe zero while an entrant still observes RUNNING.
        self.active.fetch_add(1, Ordering::SeqCst);
        let guard = Operation(&self.active);
        if self.removed.load(Ordering::Acquire)
            || self.state.load(Ordering::SeqCst) != RUNNING
            || self.hw.cap.invoke(Check).is_err()
        {
            return Err(IgcError::Other("controller unavailable"));
        }
        if self.hw.read(8) == u32::MAX {
            self.state.store(FAILED, Ordering::Release);
            return Err(IgcError::Other("PCI function unavailable"));
        }
        Ok(guard)
    }

    fn control(&self) -> Result<ControlLease<'_>, IgcError> {
        if self.control_busy.swap(true, Ordering::Acquire) {
            return Err(IgcError::Other("hardware control busy"));
        }
        Ok(ControlLease(&self.control_busy))
    }

    // Lifecycle methods execute without queue/config/global spinlock guards.
    fn stop(&self) -> Result<(), IgcError> {
        self.state
            .compare_exchange(RUNNING, CHANGING, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| IgcError::Other("controller busy"))?;
        if !self
            .hw
            .wait(100_000, || self.active.load(Ordering::SeqCst) == 0)
        {
            self.state.store(RUNNING, Ordering::Release);
            return Err(IgcError::Other("active packet operation"));
        }
        if let Err(error) = hardware::quiesce(&self.hw, self.queues().len()) {
            self.state.store(FAILED, Ordering::Release);
            return Err(error);
        }
        for q in self.queues().iter() {
            q.reclaim();
        }
        self.sample_counters();
        self.save_clock();
        self.merge.lock().reset();
        crate::publish::publish_link(self.name(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    fn start(&self) -> Result<(), IgcError> {
        self.apply_pci_quirks()?;
        if self.removed.load(Ordering::Acquire) {
            return Err(IgcError::Other("device removed"));
        }
        if let Some(table) = self.msix.lock().as_mut() {
            for route in &self.irq_routes {
                #[cfg(target_arch = "x86_64")]
                let target = narf_interrupts::apic_id_at(route.cpu as usize)
                    .ok_or(IgcError::BarMapFailed)?;
                #[cfg(target_arch = "aarch64")]
                let target = 0;
                // SAFETY: device and allocated MSI-X entries are exclusively owned.
                unsafe { table.program_vector(u16::from(route.index), target, route.vector) }
                    .map_err(|_| IgcError::BarMapFailed)?;
                *ISR_HW[route.vector as usize].lock() = Some(self.hw);
            }
            // SAFETY: all reserved entries have valid routes.
            unsafe { table.enable() }.map_err(|_| IgcError::BarMapFailed)?;
        }
        let settings = self.settings.lock().clone();
        hardware::setup_phy_policy(
            &self.hw,
            matches!(self.device.id.device, IGC_I220_V | IGC_I221_V),
            &settings.link,
            settings.pause,
            settings.eee,
        )?;
        self.counters
            .lock()
            .sample(&self.hw, self.num_queues(), true);
        let (mac, mtu) = {
            let c = self.config.lock();
            (c.mac, c.mtu)
        };
        // Packet-buffer allocation/filter/RSS configuration precedes queue
        // enable; global RX/TX stays disabled until every queue acknowledges.
        hardware::configure(&self.hw, mac, mtu, &self.settings.lock().rss);
        self.apply_filters();
        // Prepare every ring before globally enabling receive/transmit.
        for (q, queue) in self.queues().iter().enumerate() {
            hardware::queue_sized(
                &self.hw,
                q,
                queue.tx_ring.dma_addr().raw(),
                queue.rx_ring.dma_addr().raw(),
                queue.counts().0,
                queue.counts().1,
            )?;
        }
        self.restore_clock()?;
        let now = crate::ptp::read(&self.hw)?;
        let mut schedule = self.schedule.lock();
        *schedule =
            crate::traffic::Schedule::validate(schedule.config.clone(), self.num_queues(), now)
                .map_err(|_| IgcError::Other("invalid schedule"))?;
        let mut effective = schedule.clone();
        if self.merge.lock().config.enabled && !effective.active() {
            effective.config.preemptible_queues = 1;
        }
        effective.apply(
            &self.hw,
            self.num_queues(),
            matches!(
                self.device.id.device,
                IGC_I226_LM
                    | IGC_I226_V
                    | IGC_I226_IT
                    | IGC_I226_K
                    | IGC_I226_LMVP
                    | IGC_I226_BLANK_NVM
            ),
        );
        for (q, queue) in self.queues().iter().enumerate() {
            // Reject permanently closed queues during the configuration
            // transition too; never post DMA that cannot finish in any cycle.
            queue.set_gate_closed(
                !effective.config.gates.is_empty()
                    && effective.windows[q].0 == effective.windows[q].1,
            );
        }
        drop(schedule);
        self.configure_interrupts();
        if self.removed.load(Ordering::Acquire) {
            return Err(IgcError::Other("device removed"));
        }
        hardware::enable_data(&self.hw)?;
        self.mtu.store(mtu, Ordering::Release);
        self.state.store(RUNNING, Ordering::Release);
        Ok(())
    }

    fn configure_interrupts(&self) {
        if self.irq_routes.is_empty() {
            return;
        }
        self.hw.write(
            0x1514,
            GPIE_NSICR | GPIE_MULTIPLE_MSIX | GPIE_EIAME | GPIE_PBA,
        );
        for i in 0..2 {
            let mut ivar = 0u32;
            for side in 0..2 {
                let q = i * 2 + side;
                if q < self.queues().len() {
                    let route = self.route(q).unwrap();
                    let byte = u32::from(route.index) | 0x80;
                    ivar |= (byte | (byte << 8)) << (side * 16);
                }
            }
            self.hw.write(0x1700 + i as u64 * 4, ivar);
        }
        self.hw.write(0x1740, 0x8000);
        let ticks = (self.settings.lock().coalesce_us * 1000 / 256) & 0x7ffc;
        for r in &self.irq_routes {
            self.hw
                .write(0x1680 + u64::from(r.index) * 4, ticks | (1 << 31));
        }
        let mask = (1u32 << self.irq_routes.len()) - 1;
        self.hw.write(0x152c, mask);
        self.hw.write(0x1530, mask);
        self.hw.write(0x1524, mask);
        self.hw.write(0x1508, IMS_DEFAULT);
    }
    pub fn mac(&self) -> [u8; 6] {
        self.config.lock().mac
    }
    pub fn mtu(&self) -> u32 {
        self.mtu.load(Ordering::Acquire)
    }
    pub fn ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNNING
    }
    pub fn link_sample(&self) -> crate::publish::LinkSample {
        if !self.ready() {
            return crate::publish::LinkSample::DOWN;
        }
        decode_link(self.hw.read(8))
    }
    pub fn link_up(&self) -> bool {
        self.link_sample().carrier
    }
    pub fn stats(&self) -> IgcStats {
        *self.stats.lock()
    }
    pub fn num_queues(&self) -> usize {
        self.queues().len()
    }

    pub fn tx(&self, bytes: &[u8], meta: &TxMeta) -> Result<(), IgcError> {
        if bytes.len() < 14 || bytes.len() > MAX_TSO {
            return Err(IgcError::QueueTooSmall);
        }
        let mut buffer = alloc_coherent(bytes.len(), DomainId::DRIVER_0)
            .map_err(|_| IgcError::Other("TX allocation failed"))?;
        buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        self.submit_frame(Frame::new(buffer, bytes.len() as u32), *meta)
    }
    /// Borrowed frames are copied; only submit_frame transfers DMA ownership.
    pub fn tx_frame(&self, frame: &Frame) -> Result<(), IgcError> {
        let mut buffer = alloc_coherent(frame.len() as usize, DomainId::DRIVER_0)
            .map_err(|_| IgcError::QueueTooSmall)?;
        buffer.as_mut_slice()[..frame.len() as usize].copy_from_slice(frame.payload());
        let mut owned = Frame::new(buffer, frame.len());
        owned.set_tx_timing(frame.tx_timing());
        self.submit_frame(owned, frame.tx_meta())
    }
    pub fn submit_frame(&self, frame: Frame, meta: TxMeta) -> Result<(), IgcError> {
        let _operation = self.operation()?;
        let timing = frame.tx_timing();
        let q = timing.queue.map_or_else(
            || self.settings.lock().rss.rx_queue(frame.payload()),
            usize::from,
        );
        if q >= self.num_queues() {
            return Err(IgcError::QueueTooSmall);
        }
        let mut options = crate::queue::TxOptions::default();
        if let Some(time) = timing.launch_time_ns {
            let now = {
                let _clock = self.ptp.lock();
                crate::ptp::read(&self.hw)?
            };
            options.launch = Some(self.schedule.lock().launch(q, time, now)?);
        }
        if let Some(cookie) = timing.timestamp_cookie {
            options.command = self
                .ptp
                .lock()
                .reserve(q, cookie, narf_time::monotonic_ns())?;
        }
        let result = self.queues()[q].post_options(&self.hw, q, frame, meta, self.mtu(), options);
        if result.is_err() && timing.timestamp_cookie.is_some() {
            self.ptp.lock().pending[q] = None;
        }
        if result.is_err() {
            self.stats.lock().tx_rejected += 1;
        }
        result
    }
    pub fn rx_drain_frames(&self, budget: usize) -> Vec<Frame> {
        let Ok(_operation) = self.operation() else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        for (q, queue) in self.queues().iter().enumerate() {
            let (mut batch, drops) = queue.receive(&self.hw, q, self.mtu(), budget);
            self.stats.lock().rx_drops += drops;
            narf_net::iface::note_rx_drop(self.name(), drops);
            frames.append(&mut batch);
        }
        frames
    }
    pub fn rx_recv_frame(&self) -> Option<Frame> {
        let _operation = self.operation().ok()?;
        for (q, queue) in self.queues().iter().enumerate() {
            let (frames, drops) = queue.receive(&self.hw, q, self.mtu(), 1);
            self.stats.lock().rx_drops += drops;
            if let Some(frame) = frames.into_iter().next() {
                return Some(frame);
            }
        }
        None
    }
    pub fn rx(&self, output: &mut [u8]) -> usize {
        let Some(frame) = self.rx_recv_frame() else {
            return 0;
        };
        if output.len() < frame.len() as usize {
            return 0;
        }
        let n = frame.len() as usize;
        output[..n].copy_from_slice(frame.payload());
        n
    }
    /// Explicit reset; callers may retry after errors, but failed DMA fences
    /// retain all storage and keep the interface down.
    pub fn recover(&self) -> Result<(), IgcError> {
        let _control = self.control()?;
        if self
            .state
            .compare_exchange(FAILED, CHANGING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.stop()?;
        }
        if !self
            .hw
            .wait(100_000, || self.active.load(Ordering::SeqCst) == 0)
        {
            self.state.store(FAILED, Ordering::Release);
            return Err(IgcError::Other("packet operation did not stop"));
        }
        self.reset_and_start()
    }
    fn reset_and_start(&self) -> Result<(), IgcError> {
        self.cancel_timestamps(125);
        let result = (|| {
            narf_bus::pci::restore_config(&self.hw.cap, &self.device, &self.saved_pci)
                .map_err(|_| IgcError::BarMapFailed)?;
            // Restore PCI memory/master decoding after system sleep.
            narf_bus::pci::set_command(
                &self.hw.cap,
                &self.device,
                narf_bus::pci::cmd::MEM_SPACE
                    | narf_bus::pci::cmd::BUS_MASTER
                    | narf_bus::pci::cmd::INTX_DISABLE,
            )
            .map_err(|_| IgcError::BarMapFailed)?;
            let closed = self
                .queues()
                .iter()
                .enumerate()
                .filter(|(_, q)| q.xsk().is_some_and(|s| s.is_closed()))
                .map(|(q, _)| q)
                .collect::<Vec<_>>();
            hardware::reset_queues(&self.hw, self.queues().as_slice())?;
            for q in closed {
                narf_net::bypass::classifier::release_native(self.name(), q as u32);
            }
            self.stats.lock().resets += 1;
            self.start()
        })();
        if result.is_err() {
            let _ = hardware::quiesce(&self.hw, self.queues().len());
            self.state.store(FAILED, Ordering::Release);
        }
        result
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<(), IgcError> {
        let _control = self.control()?;
        self.change_mtu(mtu)
    }
    fn change_mtu(&self, mtu: u32) -> Result<(), IgcError> {
        let tsn = self.schedule.lock().active();
        let preemption = self.merge.lock().config.enabled;
        if mtu > 1500 && (tsn || preemption || self.queues().iter().any(|q| q.xsk().is_some())) {
            return Err(IgcError::Other(
                "MTU incompatible with active queue offload",
            ));
        }
        if !(68..=MAX_MTU).contains(&mtu) {
            return Err(IgcError::Other("MTU outside 68..9216"));
        }
        self.stop()?;
        let old = self.config.lock().mtu;
        self.config.lock().mtu = mtu;
        if let Err(error) = self.reset_and_start() {
            // A later recovery must restore the configuration the registry
            // still reports, rather than completing a rejected transaction.
            self.config.lock().mtu = old;
            return Err(error);
        }
        Ok(())
    }
    pub fn set_mac(&self, mac: [u8; 6]) -> Result<(), IgcError> {
        let _control = self.control()?;
        self.change_mac(mac)
    }
    fn change_mac(&self, mac: [u8; 6]) -> Result<(), IgcError> {
        if !hardware::valid_mac(mac) {
            return Err(IgcError::Other("invalid unicast address"));
        }
        let _operation = self.operation()?;
        let mut config = self.config.lock();
        config.mac = mac;
        hardware::write_mac(&self.hw, mac);
        self.hw.flush();
        Ok(())
    }
    pub fn set_receive_mode(
        &self,
        promiscuous: bool,
        all_multicast: bool,
        multicast: &[[u8; 6]],
    ) -> Result<(), IgcError> {
        let _control = self.control()?;
        if multicast.iter().any(|a| a[0] & 1 == 0) {
            return Err(IgcError::Other("non-multicast filter address"));
        }
        let _operation = self.operation()?;
        let mut c = self.config.lock();
        c.promiscuous = promiscuous;
        c.all_multicast = all_multicast;
        c.multicast.clear();
        c.multicast.extend_from_slice(multicast);
        drop(c);
        self.apply_filters();
        Ok(())
    }
    fn apply_filters(&self) {
        let c = self.config.lock();
        let mut table = [0u32; 128];
        for addr in &c.multicast {
            let hash = (u16::from(addr[4]) >> 4) | (u16::from(addr[5]) << 4);
            table[usize::from(hash >> 5)] |= 1 << (hash & 31);
        }
        for (i, word) in table.iter().enumerate() {
            self.hw.write(0x5200 + i as u64 * 4, *word);
        }
        let mut rctl = self.hw.read(0x100) & !0x18;
        for slot in 1..16 {
            let addr = c.unicast.get(slot - 1).copied().unwrap_or([0; 6]);
            self.hw.write(
                0x5400 + slot as u64 * 8,
                u32::from_le_bytes([addr[0], addr[1], addr[2], addr[3]]),
            );
            self.hw.write(
                0x5404 + slot as u64 * 8,
                u32::from_le_bytes([addr[4], addr[5], 0, if addr == [0; 6] { 0 } else { 0x80 }]),
            );
        }
        if c.promiscuous {
            rctl |= 0x18;
        }
        if c.unicast.len() > 15 {
            rctl |= 8;
        }
        if c.all_multicast {
            rctl |= 0x10;
        }
        crate::traffic::flows(&self.hw, &self.flows.lock(), c.unicast.len() + 1);
        if self.merge.lock().config.enabled {
            self.hw.write(0x5478, 0);
            self.hw.write(0x547c, 0x90000000);
        }
        self.hw.write(0x100, rctl);
        self.hw.flush();
    }

    fn maintain(&self) {
        let Ok(_operation) = self.operation() else {
            return;
        };
        for (q, queue) in self.queues().iter().enumerate() {
            queue.flush(&self.hw, q);
            queue.reclaim();
        }
        self.sample_counters();
        {
            let mut clock = self.ptp.lock();
            clock.collect(&self.hw, narf_time::monotonic_ns());
        }
        self.deliver_timestamps();
        let events = self.queues().iter().fold(0, |e, q| e | q.merge_events());
        let (verify, response) = {
            let mut m = self.merge.lock();
            let result = m.tick(narf_time::monotonic_ns(), self.link_up(), events);
            m.apply(
                &self.hw,
                self.num_queues(),
                self.schedule.lock().config.preemptible_queues,
            );
            result
        };
        for kind in [if verify { 1 } else { 0 }, if response { 2 } else { 0 }] {
            if kind != 0 {
                let _ = self.queues()[0].post_smd(&self.hw, kind);
            }
        }
    }

    fn sample_counters(&self) {
        if self.hw.read(8) == u32::MAX {
            return;
        }
        let mut counters = self.counters.lock();
        let (crc, missed, fifo) = counters.sample(&self.hw, self.num_queues(), false);
        narf_net::iface::note_rx_crc_error(self.name(), crc);
        narf_net::iface::note_rx_overrun(self.name(), missed + fifo);
        let mut stats = self.stats.lock();
        stats.crc_errors += crc;
        stats.missed_packets += missed + fifo;
        stats.rx_packets = counters.value(0x4074);
        stats.tx_packets = counters.value(0x4080);
        stats.rx_bytes = counters.value(0x4088);
        stats.tx_bytes = counters.value(0x4090);
    }

    fn set_pme(&self, enabled: bool) -> Result<(), IgcError> {
        self.hw
            .cap
            .invoke(Check)
            .map_err(|_| IgcError::BarMapFailed)?;
        // SAFETY: this driver exclusively owns this live PCI function.
        if let Some(off) = unsafe { narf_bus::pci_cap::find_cap(&self.device, 1) }
            .map_err(|_| IgcError::BarMapFailed)?
        {
            let at = (off + 4) as u16;
            let v = narf_bus::pci::read_config32(&self.hw.cap, &self.device, at)
                .map_err(|_| IgcError::BarMapFailed)?;
            // PME_Status is W1C; clear the old event while changing PME_Enable.
            narf_bus::pci::write_config32(
                &self.hw.cap,
                &self.device,
                at,
                (v & !0x8100) | 0x8000 | if enabled { 0x100 } else { 0 },
            )
            .map_err(|_| IgcError::BarMapFailed)?;
        } else if enabled {
            return Err(IgcError::Other("PCI wake capability absent"));
        }
        Ok(())
    }
    fn apply_pci_quirks(&self) -> Result<(), IgcError> {
        self.set_pme(false)?;
        if matches!(
            self.device.id.device,
            IGC_I226_LM
                | IGC_I226_V
                | IGC_I226_IT
                | IGC_I226_K
                | IGC_I226_LMVP
                | IGC_I226_BLANK_NVM
        ) {
            // Linux igc_probe disables ASPM L1.2 on I226 to avoid packet
            // loss. Clear both PCI-PM and ASPM L1.2 enable at the endpoint;
            // the link cannot enter L1.2 when either endpoint disables it.
            let read_cap = self.hw.cap.derive().map_err(|_| IgcError::BarMapFailed)?;
            if let Some(cap) = narf_bus::pci_cap_ext::find_cap(&read_cap, &self.device, 0x1e)
                .map_err(|_| IgcError::BarMapFailed)?
            {
                let offset = (cap.offset + 8) as u16;
                let ctl = narf_bus::pci::read_config32(&self.hw.cap, &self.device, offset)
                    .map_err(|_| IgcError::BarMapFailed)?;
                narf_bus::pci::write_config32(&self.hw.cap, &self.device, offset, ctl & !5)
                    .map_err(|_| IgcError::BarMapFailed)?;
            }
        }
        self.hw.write(0x5800, 0);
        self.hw.write(0x5808, 0); // WoL disabled
        Ok(())
    }
}

impl narf_net::iface::DeviceControl for Igc {
    fn nic(&self) -> Option<&dyn narf_net::nic::NicControl> {
        Some(self)
    }
    fn configure(&self, desired: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        if !(68..=MAX_MTU).contains(&desired.mtu)
            || !hardware::valid_mac(desired.mac)
            || desired
                .addresses
                .iter()
                .any(|a| a.unicast == (a.addr[0] & 1 != 0))
        {
            return Err(22);
        }
        let unicast = desired.addresses.iter().filter(|a| a.unicast).count();
        crate::traffic::validate_flows(&self.flows.lock(), self.num_queues(), unicast)?;
        if self.merge.lock().config.enabled
            && unicast
                + self
                    .flows
                    .lock()
                    .iter()
                    .filter(|f| f.destination_mac.is_some())
                    .count()
                > 14
        {
            return Err(28);
        }
        let tsn = self.schedule.lock().active();
        let preemption = self.merge.lock().config.enabled;
        if desired.mtu > 1500
            && (tsn || preemption || self.queues().iter().any(|q| q.xsk().is_some()))
        {
            return Err(22);
        }
        let old = self.config.lock().clone();
        let next = Config {
            mac: desired.mac,
            mtu: desired.mtu,
            promiscuous: desired.promiscuous,
            all_multicast: desired.all_multicast,
            multicast: desired
                .addresses
                .iter()
                .filter(|a| !a.unicast)
                .map(|a| a.addr)
                .collect(),
            unicast: desired
                .addresses
                .iter()
                .filter(|a| a.unicast)
                .map(|a| a.addr)
                .collect(),
        };
        let running = self.ready();
        if !running && self.state.load(Ordering::Acquire) != ADMIN_DOWN {
            return Err(16);
        }
        if old.mtu != next.mtu {
            if running {
                self.stop().map_err(|_| 5)?;
            }
            *self.config.lock() = next;
            if self.reset_and_start().is_err() {
                *self.config.lock() = old;
                return Err(5);
            }
            if !running {
                self.stop().map_err(|_| 5)?;
                self.state.store(ADMIN_DOWN, Ordering::Release);
            }
        } else {
            let _operation = self.clock_operation().map_err(|_| 19)?;
            *self.config.lock() = next;
            hardware::write_mac(&self.hw, desired.mac);
            self.apply_filters();
            if self.hw.cap.invoke(Check).is_err() || self.hw.read(8) == u32::MAX {
                *self.config.lock() = old;
                self.state.store(FAILED, Ordering::Release);
                return Err(19);
            }
        }

        Ok(())
    }
}

impl narf_power::device_pm::DevicePmOps for Igc {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        let _control = self
            .control()
            .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
        if self.ready() {
            self.stop()
                .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
        } else if self.state.load(Ordering::Acquire) != ADMIN_DOWN {
            return Err(narf_power::device_pm::DevicePmError::Busy);
        }
        let flags = self.settings.lock().wake;
        let result = hardware::wake(&self.hw, flags).and_then(|wake| self.set_pme(wake));
        if result.is_err() {
            let _ = self.reset_and_start();
            return Err(narf_power::device_pm::DevicePmError::DriverError);
        }
        self.state.store(SUSPENDED, Ordering::Release);
        self.hw.write(0x18, self.hw.read(0x18) & !0x10000000);
        Ok(())
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        let _control = self
            .control()
            .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
        self.state
            .compare_exchange(SUSPENDED, CHANGING, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
        if narf_bus::pci::set_power_state(
            &self.hw.cap,
            &self.device,
            narf_bus::pci::PciPowerState::D0,
        )
        .is_err()
        {
            self.state.store(FAILED, Ordering::Release);
            return Err(narf_power::device_pm::DevicePmError::DriverError);
        }
        self.hw.delay(10_000);
        self.reset_and_start()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)?;
        if !self.admin_up.load(Ordering::Acquire) {
            self.stop()
                .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)?;
            self.state.store(ADMIN_DOWN, Ordering::Release);
        }
        Ok(())
    }
}

pub(crate) fn decode_link(status: u32) -> crate::publish::LinkSample {
    use narf_net::iface::LinkDuplex;
    if status == u32::MAX || status & 2 == 0 {
        return crate::publish::LinkSample::DOWN;
    }
    let speed = if status & 0x80 != 0 {
        if status & 0x400000 != 0 {
            2500
        } else {
            1000
        }
    } else if status & 0x40 != 0 {
        100
    } else {
        10
    };
    crate::publish::LinkSample::up(
        Some(speed),
        Some(if status & 1 != 0 {
            LinkDuplex::Full
        } else {
            LinkDuplex::Half
        }),
    )
}

pub fn igc_ifname() -> &'static str {
    with_controller(|c| c.name()).unwrap_or("")
}
pub fn is_probed() -> bool {
    with_controller(Igc::ready).unwrap_or(false)
}
pub fn with_controller<R>(f: impl FnOnce(&Igc) -> R) -> Option<R> {
    let c = RETAINED
        .lock()
        .iter()
        .find(|c| !c.removed.load(Ordering::Acquire) && !c.name().is_empty())
        .cloned();
    c.map(|c| f(&c))
}
fn by_cookie(cookie: u64) -> Option<Arc<Igc>> {
    RETAINED
        .lock()
        .iter()
        .find(|c| c.cookie == cookie && !c.removed.load(Ordering::Acquire))
        .cloned()
}
fn send_copy(cookie: u64, frame: &[u8], meta: TxMeta) -> Result<(), ()> {
    by_cookie(cookie)
        .ok_or(())?
        .tx(frame, &meta)
        .map_err(|_| ())
}
fn send_owned(cookie: u64, frame: Frame, meta: TxMeta) -> Result<(), ()> {
    by_cookie(cookie)
        .ok_or(())?
        .submit_frame(frame, meta)
        .map_err(|_| ())
}
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // One controller is supported; never report a second function as bound.
    if RETAINED
        .lock()
        .iter()
        .any(|c| c.device.addr == device.addr && !c.removed.load(Ordering::Acquire))
    {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: PCI match framework grants exclusive function ownership.
    let controller = match unsafe { Igc::bring_up(&device, &cap) } {
        Ok(controller) => controller,
        Err(error) => {
            let _ = core::fmt::write(
                &mut narf_console::Writer,
                format_args!(
                    "[igc] {:04x}:{:04x} probe failed: {:?}\n",
                    device.id.vendor, device.id.device, error
                ),
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    let name = crate::publish::publish_netdev_with_context(
        controller.mac(),
        controller.cookie,
        send_copy,
        controller.link_sample(),
    );
    narf_net::iface::set_offloads(&name, OFFLOADS);
    let mut pools = Vec::new();
    for _ in 0..controller.num_queues() {
        let pool = Arc::new(narf_io::pool::DmaPool::new(MAX_TSO, DomainId::DRIVER_0, 8));
        let _ = pool.prefill(8);
        pools.push(pool);
    }
    narf_net::iface::enable_zero_copy_tx_context(
        &name,
        controller.cookie,
        send_owned,
        pools,
        0,
        true,
    );
    controller.ifname.set(name);
    let clock = narf_time::phc::register(Arc::new(control::PhcDevice(Arc::downgrade(&controller))));
    controller.phc_index.store(clock as i32, Ordering::Release);
    narf_filesystem::devfs_ptp::register();
    for q in controller.queues().iter() {
        q.set_owner(controller.name());
    }
    let _ = core::fmt::write(
        &mut narf_console::Writer,
        format_args!(
            "[igc] {} MAC {:02x?}, {} queues, IRQ {:?}\n",
            controller.name(),
            controller.mac(),
            controller.num_queues(),
            controller.irq_vector
        ),
    );
    narf_net::iface::set_device_control(controller.name(), controller.clone());
    if let Some(iface) = narf_net::iface::lookup(controller.name()) {
        // The stack does not yet maintain a complete IPv6 multicast join
        // list. Make the initial all-multicast policy explicit in IFF_ALLMULTI;
        // an administrator can subsequently install a selective group list.
        let _ = narf_net::iface::dev_set_allmulti(0, iface.ifindex, 1);
    }
    narf_power::device_pm::register_device_pm_ops(controller.name(), controller.clone());
    narf_bus::pcie_recovery::register_error_callback(controller.device.addr, controller.clone());
    narf_net::iface::set_open_stop(controller.name(), admin_hook);
    narf_net::iface::set_driver_info(
        controller.name(),
        "igc",
        Some("0.1.0"),
        alloc::format!("{:?}", device.addr),
    );
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    if let Some(auth) = narf_net::trusted_net_authority().and_then(|a| a.derive().ok()) {
        let _ = narf_net::registry().register(&auth, IgcInterface(controller.clone()));
    }
    Ok(())
}

#[derive(Debug)]
pub struct IgcNic;
impl narf_net::Interface for IgcNic {
    fn name(&self) -> &'static str {
        let name = igc_ifname();
        if name.is_empty() {
            "igc"
        } else {
            name
        }
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(Igc::mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        with_controller(Igc::mtu).unwrap_or(1500)
    }
    fn link_up(&self) -> bool {
        with_controller(Igc::link_up).unwrap_or(false)
    }
    fn offloads(&self) -> OffloadCapabilities {
        OFFLOADS
    }
    fn num_rx_queues(&self) -> u16 {
        with_controller(Igc::num_queues).unwrap_or(1) as u16
    }
    fn num_tx_queues(&self) -> u16 {
        <Self as narf_net::Interface>::num_rx_queues(self)
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        with_controller(|c| c.settings.lock().rss.clone())
    }
    fn queue_affinity(&self, _: u16) -> narf_net::rss::QueueAffinity {
        narf_net::rss::QueueAffinity {
            core: 0,
            irq: with_controller(|c| c.irq_vector).flatten(),
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut ring = RING.lock();
            if ring.is_none() {
                *ring = c.rx_ipc_ring.lock().take();
                if ring.is_some() {
                    crate::publish::note_rx_mirror_attached(igc_ifname());
                }
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut ring = RING.lock();
            if ring.is_none() {
                *ring = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}
impl crate::HwNic for IgcNic {
    fn name(&self) -> &'static str {
        let name = igc_ifname();
        if name.is_empty() {
            "igc"
        } else {
            name
        }
    }
    fn mac(&self) -> [u8; 6] {
        <Self as narf_net::Interface>::mac(self)
    }
    fn mtu(&self) -> u32 {
        <Self as narf_net::Interface>::mtu(self)
    }
    fn link_up(&self) -> bool {
        <Self as narf_net::Interface>::link_up(self)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIgc
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::TX_CSUM
            | crate::NicCaps::RX_CSUM
            | crate::NicCaps::TSO
            | crate::NicCaps::RSS
            | crate::NicCaps::VLAN_TAGGING
            | crate::NicCaps::MULTICAST_HASH
            | crate::NicCaps::PROMISC
    }
    fn ring_capacity(&self) -> usize {
        COUNT - 1
    }
    fn num_rx_queues(&self) -> u16 {
        <Self as narf_net::Interface>::num_rx_queues(self)
    }
    fn num_tx_queues(&self) -> u16 {
        <Self as narf_net::Interface>::num_tx_queues(self)
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        <Self as narf_net::Interface>::rss(self)
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        <Self as narf_net::Interface>::queue_affinity(self, q)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

#[derive(Debug)]
struct IgcInterface(Arc<Igc>);
impl narf_net::Interface for IgcInterface {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        self.0.mtu()
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn offloads(&self) -> OffloadCapabilities {
        OFFLOADS
    }
    fn num_rx_queues(&self) -> u16 {
        self.0.num_queues() as u16
    }
    fn num_tx_queues(&self) -> u16 {
        self.0.num_queues() as u16
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        Some(self.0.settings.lock().rss.clone())
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        narf_net::rss::QueueAffinity {
            core: queue_cpu(q as usize),
            irq: self.0.route(q as usize).map(|r| r.vector),
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        crate::publish::note_rx_mirror_attached(self.0.name());
        &self.0.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx_ipc_ring
    }
}
fn admin_hook(name: &str, up: bool) {
    let c = RETAINED
        .lock()
        .iter()
        .find(|c| c.name() == name && !c.removed.load(Ordering::Acquire))
        .cloned();
    if let Some(c) = c {
        c.request_admin(up);
    }
}
fn remove(device: BusDevice, _: Cap<BusDeviceCap, Write>) {
    let c = RETAINED
        .lock()
        .iter()
        .find(|c| c.device.addr == device.addr && !c.removed.load(Ordering::Acquire))
        .cloned();
    if let Some(c) = c {
        c.remove();
    }
}
fn spawn_pumps(
    device: Arc<Igc>,
    rx_prod: Producer<Frame, RX_RING_N>,
    mut tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let producer = Arc::new(IrqSafeSpinLock::new(rx_prod));
    for q in 0..4 {
        let rx = device.clone();
        let producer = producer.clone();
        let mut spec = narf_scheduler::TaskSpec::unthrottled();
        spec.affinity = narf_scheduler::affinity::Affinity::pinned(
            narf_scheduler::affinity::CpuId(queue_cpu(q)),
        );
        narf_scheduler::spawn_with_spec(
            async move {
                while !rx.removed.load(Ordering::Acquire) {
                    let route = rx.route(q);
                    let waiter = route.map(|r| {
                        narf_interrupts::wait_for_irq_until(
                            r.vector,
                            narf_time::Deadline::after_ms(10),
                        )
                    });
                    let frames = if let Ok(_op) = rx.operation() {
                        let queues = rx.queues();
                        if let Some(queue) = queues.get(q) {
                            queue.poll_xsk(&rx.hw, q, rx.mtu());
                            let (f, drops) = queue.receive(&rx.hw, q, rx.mtu(), 64);
                            rx.stats.lock().rx_drops += drops;
                            narf_net::iface::note_rx_drop(rx.name(), drops);
                            f
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    };
                    for mut frame in frames {
                        let name = rx.name();
                        crate::publish::mirror_rx(
                            &frame,
                            crate::publish::rx_mirror_attached(name),
                            |f| {
                                let _ = producer.lock().try_send(f);
                            },
                        );
                        let (action, len) =
                            narf_net::bypass::classifier::run_xdp(name, frame.payload_mut());
                        frame.truncate(len as u32);
                        if action == narf_net::bypass::classifier::XdpAction::Tx {
                            if rx.submit_frame(frame, TxMeta::plain()).is_err() {
                                narf_net::bypass::classifier::count_xdp_tx_drop();
                            }
                        } else {
                            let timestamp = frame.rx_meta().timestamp_ns;
                            native_redirect(name, frame.payload_mut(), action, timestamp);
                        }
                    }
                    let pending = if let Ok(_op) = rx.operation() {
                        if let Some(r) = route {
                            rx.hw.write(0x1524, 1u32 << r.index);
                        }
                        rx.queues().get(q).is_some_and(|queue| queue.pending_rx())
                    } else {
                        false
                    };
                    if pending {
                        narf_scheduler::yield_now().await;
                        continue;
                    }
                    match waiter {
                        Some(w) => {
                            let _ = w.await;
                        }
                        None => narf_time::sleep_cycles(narf_time::ns_to_cycles(1_000_000)).await,
                    }
                }
            },
            spec,
        );
    }
    let tx = device.clone();
    narf_scheduler::spawn(async move {
        while !tx.removed.load(Ordering::Acquire) {
            let result = {
                use core::future::Future;
                let receive = tx_cons.recv();
                let timer = narf_time::sleep_cycles(narf_time::ns_to_cycles(10_000_000));
                let mut receive = core::pin::pin!(receive);
                let mut timer = core::pin::pin!(timer);
                core::future::poll_fn(|cx| {
                    if let core::task::Poll::Ready(v) = receive.as_mut().poll(cx) {
                        return core::task::Poll::Ready(Some(v));
                    }
                    if timer.as_mut().poll(cx).is_ready() {
                        return core::task::Poll::Ready(None);
                    }
                    core::task::Poll::Pending
                })
                .await
            };
            match result {
                Some(Ok(frame)) => {
                    if !tx.removed.load(Ordering::Acquire) {
                        let meta = frame.tx_meta();
                        let _ = tx.submit_frame(frame, meta);
                    }
                }
                Some(Err(_)) => break,
                None => {}
            }
        }
    });
    narf_scheduler::spawn(async move {
        let mut last = crate::publish::LinkSample::DOWN;
        while !device.removed.load(Ordering::Acquire) {
            device.maintain_admin();
            if device.recovery_requested.swap(false, Ordering::AcqRel) {
                let _ = device.recover();
            }
            device.maintain();
            let link = device.link_sample();
            if link != last {
                if let Ok(_control) = device.control() {
                    if let Ok(_op) = device.operation() {
                        let pause = device.settings.lock().pause;
                        let _ = hardware::update_pause(&device.hw, pause, device.mtu());
                        if device.schedule.lock().active() || device.merge.lock().config.enabled {
                            crate::traffic::adjust_offset(&device.hw);
                        }
                    }
                }
                crate::publish::publish_link(device.name(), link);
                last = link;
            }
            let timeout = narf_time::ns_to_cycles(5_000_000_000);
            if link.carrier
                && device
                    .queues()
                    .iter()
                    .any(|q| q.stalled(narf_time::now_cycles(), timeout))
            {
                let _ = device.recover();
            }
            narf_time::sleep_cycles(narf_time::ns_to_cycles(10_000_000)).await;
        }
    });
}

/// Every Intel device id this driver claims. Kept as a single
/// `const` so the `register_pci_driver` loop and the match-table
/// smoke test see the same list (no drift between code + test).
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    IGC_I225_LM,
    IGC_I225_V,
    IGC_I225_IT,
    IGC_I225_I,
    IGC_I220_V,
    IGC_I225_K,
    IGC_I225_K2,
    IGC_I225_LMVP,
    IGC_I225_BLANK_NVM,
    IGC_I226_LM,
    IGC_I226_V,
    IGC_I226_IT,
    IGC_I226_K,
    IGC_I226_LMVP,
    IGC_I226_BLANK_NVM,
    IGC_I221_V,
];

pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::driver_match::register_remove(name_for(did), remove);
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IGC_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        IGC_I225_LM => "igc-i225-lm",
        IGC_I225_V => "igc-i225-v",
        IGC_I225_IT => "igc-i225-it",
        IGC_I225_I => "igc-i225-i",
        IGC_I220_V => "igc-i220-v",
        IGC_I225_K => "igc-i225-k",
        IGC_I225_K2 => "igc-i225-k2",
        IGC_I225_LMVP => "igc-i225-lmvp",
        IGC_I225_BLANK_NVM => "igc-i225-blank-nvm",
        IGC_I226_LM => "igc-i226-lm",
        IGC_I226_V => "igc-i226-v",
        IGC_I226_IT => "igc-i226-it",
        IGC_I226_K => "igc-i226-k",
        IGC_I226_LMVP => "igc-i226-lmvp",
        IGC_I226_BLANK_NVM => "igc-i226-blank-nvm",
        IGC_I221_V => "igc-i221-v",
        _ => "igc",
    }
}

/// Finish a native XDP action only after packet/queue locks have released.
pub(crate) fn native_redirect(
    name: &str,
    bytes: &mut [u8],
    action: narf_net::bypass::classifier::XdpAction,
    timestamp: Option<u64>,
) {
    use narf_net::bypass::classifier::{self, XdpAction};
    match action {
        XdpAction::Pass | XdpAction::RedirectCpu { .. } => {
            narf_net::iface::on_native_rx_timestamped(name, bytes, timestamp)
        }
        XdpAction::Tx => {
            if narf_net::iface::send_on(name, bytes).is_err() {
                classifier::count_xdp_tx_drop();
            }
        }
        XdpAction::Redirect { ifindex } => {
            if narf_net::iface::send_on_ifindex(ifindex, bytes).is_err() {
                classifier::count_xdp_tx_drop();
            }
        }
        XdpAction::Broadcast => {
            let mut ports = [0u32; classifier::MAX_XDP_BROADCAST_PORTS];
            let (n, exclude) = classifier::take_xdp_broadcast(&mut ports);
            let ingress = if exclude {
                narf_net::iface::ifindex_of(name)
            } else {
                None
            };
            for &port in &ports[..n] {
                if Some(port) != ingress && narf_net::iface::send_on_ifindex(port, bytes).is_err() {
                    classifier::count_xdp_tx_drop();
                }
            }
        }
        XdpAction::Drop | XdpAction::Aborted => {}
    }
}
