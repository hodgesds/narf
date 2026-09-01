//! virtio-mem over modern virtio-PCI (VirtIO 1.2 §5.14).
//!
//! Queue 0 carries PLUG/UNPLUG/STATE requests. Host acknowledgements are
//! committed to the frame allocator transactionally: plug is rolled back at
//! the device if allocator admission fails, while unplug first proves the
//! complete block free and re-onlines it if the device rejects the request.

extern crate alloc;

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{MemoryHotplugError, PhysAddr};

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_CONFIG_GENERATION,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE,
    CC_DRIVER_FEATURE_SELECT, CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE,
    CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::req_gate::ReqGate;
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_MEM_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_MEM_PCI_DEVICE: u16 = 0x1058;

const CFG_BLOCK_SIZE: u64 = 0;
const CFG_NODE_ID: u64 = 8;
const CFG_ADDR: u64 = 16;
const CFG_REGION_SIZE: u64 = 24;
const CFG_USABLE_REGION_SIZE: u64 = 32;
const CFG_PLUGGED_SIZE: u64 = 40;
const CFG_REQUESTED_SIZE: u64 = 48;

const REQ_PLUG: u16 = 0;
const REQ_UNPLUG: u16 = 1;
const REQ_STATE: u16 = 3;
const RESP_ACK: u16 = 0;
const STATE_PLUGGED: u16 = 0;
const STATE_UNPLUGGED: u16 = 1;
const VIRTIO_MEM_F_ACPI_PXM: u64 = 1 << 0;
const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u64 = 1 << 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VirtioMemConfig {
    pub addr: u64,
    pub region_size: u64,
    pub usable_region_size: u64,
    pub plugged_size: u64,
    pub block_size: u64,
    pub node_id: u16,
    pub requested_size: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VirtioMemError {
    Transport(VirtioPciError),
    InvalidConfig,
    DeviceRejected,
    Allocator(MemoryHotplugError),
}

impl From<VirtioPciError> for VirtioMemError {
    fn from(error: VirtioPciError) -> Self {
        Self::Transport(error)
    }
}

impl From<MemoryHotplugError> for VirtioMemError {
    fn from(error: MemoryHotplugError) -> Self {
        Self::Allocator(error)
    }
}

pub struct VirtioMemPci {
    common: VirtioRegion,
    device_cfg: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    queue: IrqSafeSpinLock<Option<Virtqueue>>,
    _queue_dma: DmaBuffer,
    request_dma: DmaBuffer,
    queue_notify_off: u16,
    online_blocks: IrqSafeSpinLock<Vec<u64>>,
    /// Cached device config. Interior-mutable so `reconcile` can run on
    /// `&self`; taken only for a copy in/out, never across a round-trip.
    config: IrqSafeSpinLock<VirtioMemConfig>,
    /// Serialises `reconcile` (and with it the shared `request_dma`
    /// scratch) WITHOUT masking interrupts while waiting — see
    /// [`crate::req_gate`].
    req_gate: AtomicBool,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioMemPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let config = *self.config.lock();
        f.debug_struct("VirtioMemPci")
            .field("config", &config)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioMemPci {
    /// # Safety
    /// Caller owns the PCI function exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioMemError> {
        // SAFETY: bounded capability walk of the caller-owned function.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller owns all mapped BAR windows.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let device_cap = caps
            .device_cfg
            .as_ref()
            .ok_or(VirtioMemError::InvalidConfig)?;
        // SAFETY: same.
        let device_cfg = unsafe { map_cap(device, device_cap) }?;
        if device_cfg.length < 56 {
            return Err(VirtioMemError::InvalidConfig);
        }

        // SAFETY: common config offsets are fixed by VirtIO 1.2.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }
        // SAFETY: fixed common-config fields.
        let features = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            let low = common.read32(CC_DEVICE_FEATURE) as u64;
            common.write32(CC_DEVICE_FEATURE_SELECT, 1);
            low | ((common.read32(CC_DEVICE_FEATURE) as u64) << 32)
        };
        if features & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioMemError::Transport(
                VirtioPciError::DeviceRejectedFeatures,
            ));
        }
        // SAFETY: accept the two virtio-mem semantics we implement plus the
        // mandatory modern-transport bit. QEMU requires acknowledgement of
        // UNPLUGGED_INACCESSIBLE when that backend mode is enabled.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(
                CC_DRIVER_FEATURE,
                (features & (VIRTIO_MEM_F_ACPI_PXM | VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE)) as u32,
            );
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, 1u32 << (VIRTIO_F_VERSION_1 - 32));
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: fixed common status byte.
        if unsafe { common.read8(CC_DEVICE_STATUS) } & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioMemError::Transport(
                VirtioPciError::DeviceRejectedFeatures,
            ));
        }

        // SAFETY: queue 0 is mandatory for virtio-mem.
        let qmax = unsafe {
            common.write16(CC_QUEUE_SELECT, 0);
            common.read16(CC_QUEUE_SIZE)
        };
        if qmax < 2 {
            return Err(VirtioMemError::Transport(VirtioPciError::QueueTooSmall));
        }
        // Keep the largest advertised power-of-two depth that fits in the
        // queue page; there is no benefit to constraining this single-flight
        // control queue to an artificially tiny ring.
        let mut qsize = 128u16.min(qmax);
        while !qsize.is_power_of_two() {
            qsize -= 1;
        }
        let queue_dma =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let layout = VirtqueueLayout::new(qsize.max(2), queue_dma.dma_addr().raw())
            .ok_or(VirtioPciError::QueueTooSmall)?;
        // SAFETY: fixed queue fields for selected queue 0.
        unsafe {
            common.write16(CC_QUEUE_SIZE, qsize.max(2));
            common.write64_split(CC_QUEUE_DESC, layout.desc_table);
            common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
            common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
            common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
        }
        // SAFETY: queue 0 remains selected.
        let queue_notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
        // SAFETY: queue layout is fully published.
        unsafe { common.write16(CC_QUEUE_ENABLE, 1) };
        let request_dma =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        let config = Self::read_config_stable(&common, &device_cfg)?;
        Self::validate_config(config)?;
        // SAFETY: device accepted features and queue 0 is ready.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }
        // SAFETY: coherent queue page is exclusively owned and initialized.
        let queue = unsafe { Virtqueue::new(layout) };
        Ok(Self {
            common,
            device_cfg,
            notify,
            notify_off_multiplier: caps.notify.notify_off_multiplier,
            queue: IrqSafeSpinLock::new(Some(queue)),
            _queue_dma: queue_dma,
            request_dma,
            queue_notify_off,
            online_blocks: IrqSafeSpinLock::new(Vec::new()),
            config: IrqSafeSpinLock::new(config),
            req_gate: AtomicBool::new(false),
            ready: true,
        })
    }

    fn read64(region: &VirtioRegion, offset: u64) -> u64 {
        // SAFETY: caller validated the complete device-config length.
        unsafe { region.read32(offset) as u64 | ((region.read32(offset + 4) as u64) << 32) }
    }

    fn read_config_stable(
        common: &VirtioRegion,
        device: &VirtioRegion,
    ) -> Result<VirtioMemConfig, VirtioMemError> {
        for _ in 0..8 {
            // SAFETY: fixed common/device config offsets.
            let before = unsafe { common.read8(CC_CONFIG_GENERATION) };
            let config = VirtioMemConfig {
                addr: Self::read64(device, CFG_ADDR),
                region_size: Self::read64(device, CFG_REGION_SIZE),
                usable_region_size: Self::read64(device, CFG_USABLE_REGION_SIZE),
                plugged_size: Self::read64(device, CFG_PLUGGED_SIZE),
                block_size: Self::read64(device, CFG_BLOCK_SIZE),
                // SAFETY: device config is at least 56 bytes.
                node_id: unsafe { device.read16(CFG_NODE_ID) },
                requested_size: Self::read64(device, CFG_REQUESTED_SIZE),
            };
            compiler_fence(Ordering::Acquire);
            // SAFETY: fixed generation byte.
            if before == unsafe { common.read8(CC_CONFIG_GENERATION) } {
                return Ok(config);
            }
        }
        Err(VirtioMemError::InvalidConfig)
    }

    fn validate_config(config: VirtioMemConfig) -> Result<(), VirtioMemError> {
        if config.block_size < 4096
            || !config.block_size.is_power_of_two()
            || config.addr & (config.block_size - 1) != 0
            || config.region_size == 0
            || config.region_size % config.block_size != 0
            || config.usable_region_size > config.region_size
            || config.usable_region_size % config.block_size != 0
            || config.plugged_size > config.usable_region_size
            || config.requested_size > config.usable_region_size
            || config.node_id as usize >= narf_memory::FRAME_MAX_NUMA_NODES
            || !narf_memory::kernel_ram_range_mapped(
                PhysAddr::new(config.addr),
                config.usable_region_size,
            )
        {
            return Err(VirtioMemError::InvalidConfig);
        }
        Ok(())
    }

    fn request(&self, request_type: u16, addr: u64) -> Result<u16, VirtioMemError> {
        let phys = self.request_dma.dma_addr().raw();
        let ptr = self.request_dma.as_mut_ptr();
        // Request at +0 (24 bytes), response at +64 (8 bytes).
        // SAFETY: page-sized coherent scratch is single-flight under the
        // request gate held by `reconcile`.
        unsafe {
            core::ptr::write_bytes(ptr, 0, 72);
            core::ptr::write_volatile(ptr.cast::<u16>(), request_type.to_le());
            core::ptr::write_volatile(ptr.add(8).cast::<u64>(), addr.to_le());
            core::ptr::write_volatile(ptr.add(16).cast::<u16>(), 1u16.to_le());
        }
        let descriptors = [
            VirtqDesc {
                addr: phys,
                len: 24,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            VirtqDesc {
                addr: phys + 64,
                len: 10,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut queue = self.queue.lock();
            let virtqueue = queue.as_mut().ok_or(VirtioPciError::NoQueues)?;
            virtqueue
                .add_buffer(&descriptors)
                .ok_or(VirtioPciError::AddBufferFailed)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: notify window and queue offset came from the device caps.
        unsafe {
            self.notify.write16(
                self.queue_notify_off as u64 * self.notify_off_multiplier as u64,
                0,
            );
        }
        // Re-take the queue lock per completion poll instead of holding
        // it across the whole round-trip: `queue` is an IrqSafeSpinLock,
        // so a long hold would keep this CPU interrupts-masked for up to
        // the full deadline — the exact livelock class the request gate
        // exists to avoid (see blk_pci / crate::req_gate).
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut queue = self.queue.lock();
                    match queue.as_mut() {
                        Some(virtqueue) => virtqueue.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues.into());
        }
        {
            let mut queue = self.queue.lock();
            if let Some(virtqueue) = queue.as_mut() {
                virtqueue.free_chain(head);
            }
        }
        if !done {
            return Err(VirtioPciError::CompletionTimeout.into());
        }
        compiler_fence(Ordering::Acquire);
        // SAFETY: device completed the writable response descriptor.
        let response = unsafe { core::ptr::read_volatile(ptr.add(64).cast::<u16>()) };
        if u16::from_le(response) != RESP_ACK {
            return Err(VirtioMemError::DeviceRejected);
        }
        if request_type == REQ_STATE {
            // SAFETY: response has type + three le16 padding words before
            // the state union (Linux `struct virtio_mem_resp`).
            let state = unsafe { core::ptr::read_volatile(ptr.add(72).cast::<u16>()) };
            Ok(u16::from_le(state))
        } else {
            Ok(RESP_ACK)
        }
    }

    fn online_block(&self, addr: u64) -> Result<(), VirtioMemError> {
        self.request(REQ_PLUG, addr)?;
        let config = *self.config.lock();
        let node = config.node_id as usize;
        // SAFETY: virtio-mem's device-owned region is guest RAM mapped by the
        // platform and the host ACK proves this block is plugged.
        if let Err(error) = unsafe {
            narf_memory::online_memory_range(PhysAddr::new(addr), config.block_size, node)
        } {
            let _ = self.request(REQ_UNPLUG, addr);
            return Err(error.into());
        }
        self.online_blocks.lock().push(addr);
        Ok(())
    }

    fn offline_block(&self, addr: u64) -> Result<(), VirtioMemError> {
        let config = *self.config.lock();
        let node = narf_memory::offline_memory_range(PhysAddr::new(addr), config.block_size)?;
        if let Err(error) = self.request(REQ_UNPLUG, addr) {
            // SAFETY: this exact block was managed immediately above and the
            // device rejected unplug, so it remains real mapped RAM.
            let _ = unsafe {
                narf_memory::online_memory_range(PhysAddr::new(addr), config.block_size, node)
            };
            return Err(error);
        }
        let mut online = self.online_blocks.lock();
        if let Some(index) = online.iter().position(|candidate| *candidate == addr) {
            online.swap_remove(index);
        }
        Ok(())
    }

    /// Reconcile device state and the host's requested size.
    ///
    /// Serialised by the device's request gate (which also covers the
    /// shared request scratch), NOT by the global `CONTROLLER` lock —
    /// each not-yet-online block costs a device round-trip, so a
    /// reconcile can wait on the device for a long time and must do so
    /// with interrupts enabled.
    pub fn reconcile(&self) -> Result<(), VirtioMemError> {
        let _gate = ReqGate::acquire(&self.req_gate);
        let current = Self::read_config_stable(&self.common, &self.device_cfg)?;
        Self::validate_config(current)?;
        *self.config.lock() = current;
        let node = current.node_id as usize;

        // Recover already-plugged blocks (e.g. kexec/device reset) into the
        // allocator before honoring a new target.
        let blocks = current.usable_region_size / current.block_size;
        for index in 0..blocks {
            let addr = current.addr + index * current.block_size;
            if self.online_blocks.lock().contains(&addr) {
                continue;
            }
            if self.request(REQ_STATE, addr)? == STATE_PLUGGED {
                // SAFETY: STATE_PLUGGED proves host-backed guest RAM.
                unsafe {
                    narf_memory::online_memory_range(PhysAddr::new(addr), current.block_size, node)
                }?;
                self.online_blocks.lock().push(addr);
            }
        }

        let target_blocks = current.requested_size / current.block_size;
        while self.online_blocks.lock().len() < target_blocks as usize {
            let mut candidate = None;
            for index in 0..blocks {
                let addr = current.addr + index * current.block_size;
                if !self.online_blocks.lock().contains(&addr)
                    && self.request(REQ_STATE, addr)? == STATE_UNPLUGGED
                {
                    candidate = Some(addr);
                    break;
                }
            }
            self.online_block(candidate.ok_or(VirtioMemError::InvalidConfig)?)?;
        }
        while self.online_blocks.lock().len() > target_blocks as usize {
            let candidates = self.online_blocks.lock().clone();
            let mut removed = false;
            for addr in candidates.into_iter().rev() {
                match self.offline_block(addr) {
                    Ok(()) => {
                        removed = true;
                        break;
                    }
                    Err(VirtioMemError::Allocator(MemoryHotplugError::Busy)) => {}
                    Err(error) => return Err(error),
                }
            }
            if !removed {
                return Err(MemoryHotplugError::Busy.into());
            }
        }
        Ok(())
    }
}

/// The probed controller, behind an `Arc` so `poll_config` can snapshot
/// the handle under a brief lock hold and release `CONTROLLER` BEFORE
/// `reconcile`'s device round-trips (the same clone-and-release pattern
/// as the mount registry and virtio-net). Serialisation of the actual
/// work is the device's own `req_gate`.
static CONTROLLER: IrqSafeSpinLock<Option<Arc<VirtioMemPci>>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
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
    // SAFETY: the bus gives this probe exclusive authority over the function.
    let controller = unsafe { VirtioMemPci::bring_up(&device, &cap) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    controller
        .reconcile()
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    *CONTROLLER.lock() = Some(Arc::new(controller));
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vmem0"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(VIRTIO_MEM_PCI_VENDOR),
        pci_did: Some(VIRTIO_MEM_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-mem-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_MEM_PCI_VENDOR,
            device: VIRTIO_MEM_PCI_DEVICE,
        },
        probe,
    });
}

pub fn poll_config() -> Result<(), VirtioMemError> {
    // Snapshot + release: `reconcile` issues a device round-trip per
    // not-yet-online block, and `CONTROLLER` is an IRQ-masking lock, so
    // it must not be held across that. The device's request gate keeps
    // reconciles mutually exclusive.
    let controller = CONTROLLER.lock().clone();
    controller.ok_or(VirtioMemError::InvalidConfig)?.reconcile()
}

/// Reconcile live host resize requests on a bounded cadence.
///
/// Stable generation reads make polling equivalent to consuming a config
/// interrupt, and the periodic fallback cannot lose an edge.
pub fn spawn_config_pump() {
    const POLL_CYCLES: u64 = 330_000_000;
    narf_scheduler::spawn_stackful(async move {
        loop {
            narf_time::sleep_cycles(POLL_CYCLES).await;
            let _ = poll_config();
        }
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}
