//! narf-drivers-virtio — virtio-mmio transport probe + skeleton driver.

#![no_std]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;
extern crate narf_io;

pub mod balloon_pci;
pub mod blk;
pub mod blk_pci;
pub mod console_pci;
pub mod fs_pci;
pub mod gpu_pci;
pub mod input_pci;
pub mod iommu_pci;
pub mod net_pci;
pub mod p9_pci;
pub mod pci;
pub mod queue;
pub mod rng_pci;
pub mod scsi_pci;
pub mod snd_pci;
pub mod vsock_pci;
pub mod class_blk;

mod tests;

/// Stage::Subsys initcalls — register every virtio-PCI driver with
/// the bus match table. Each call is idempotent on its own; the
/// `register` function only adds entries.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "virtio-blk-pci",     || {
        blk_pci::register_pci_driver();     InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-net-pci",     || {
        net_pci::register_pci_driver();     InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-rng-pci",     || {
        rng_pci::register_pci_driver();     InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-balloon-pci", || {
        balloon_pci::register_pci_driver(); InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-input-pci",   || {
        input_pci::register_pci_driver();   InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-gpu-pci",     || {
        gpu_pci::register_pci_driver();     InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-snd-pci",     || {
        snd_pci::register_pci_driver();     InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-iommu-pci",   || {
        iommu_pci::register_pci_driver();   InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-scsi-pci",    || {
        scsi_pci::register_pci_driver();    InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-9p-pci",      || {
        p9_pci::register_pci_driver();      InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-fs-pci",      || {
        fs_pci::register_pci_driver();      InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-vsock-pci",   || {
        vsock_pci::register_pci_driver();   InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "virtio-console-pci", || {
        console_pci::register_pci_driver(); InitResult::Ok
    });
}

use alloc::boxed::Box;
use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

use narf_bus::{BusDevice, BusKind};
use narf_memory::PhysAddr;
use narf_drivers::{Driver, DriverEnv, DriverFuture};

// ── VirtioMmioDevice ────────────────────────────────────────────────

/// A probed virtio-mmio transport.
#[derive(Debug)]
pub struct VirtioMmioDevice {
    base: PhysAddr,
    device_id: u32,
    vendor_id: u32,
    version: u32,
}

impl VirtioMmioDevice {
    pub const MAGIC: u32 = 0x7472_6976; // "virt"

    // Registers offsets (VirtIO 1.2 §4.2.2)
    pub const REG_MAGIC:          u64 = 0x000;
    pub const REG_VERSION:        u64 = 0x004;
    pub const REG_DEVICE_ID:      u64 = 0x008;
    pub const REG_VENDOR_ID:      u64 = 0x00c;
    pub const REG_DEVICE_FEATURES: u64 = 0x010;
    pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const REG_DRIVER_FEATURES: u64 = 0x020;
    pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const REG_QUEUE_SEL:      u64 = 0x030;
    pub const REG_QUEUE_NUM_MAX:  u64 = 0x034;
    pub const REG_QUEUE_NUM:      u64 = 0x038;
    pub const REG_QUEUE_READY:    u64 = 0x044;
    pub const REG_QUEUE_NOTIFY:   u64 = 0x050;
    pub const REG_INTERRUPT_STATUS: u64 = 0x060;
    pub const REG_INTERRUPT_ACK:  u64 = 0x064;
    pub const REG_STATUS:         u64 = 0x070;
    pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
    pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
    pub const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const REG_QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const REG_QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const REG_CONFIG_GENERATION: u64 = 0x0fc;
    pub const REG_CONFIG:         u64 = 0x100;

    pub unsafe fn probe(d: &BusDevice) -> Result<Self, ProbeError> {
        let BusKind::VirtioMmio { base, .. } = d.kind else {
            return Err(ProbeError::NotVirtioMmio);
        };
        unsafe { Self::probe_raw(base.raw()) }
    }

    pub unsafe fn probe_raw(base_raw: u64) -> Result<Self, ProbeError> {
        unsafe {
            let magic = core::ptr::read_volatile(base_raw as *const u32);
            if magic != Self::MAGIC { return Err(ProbeError::WrongMagic); }

            let version = core::ptr::read_volatile((base_raw + Self::REG_VERSION) as *const u32);
            if version != 2 { return Err(ProbeError::UnsupportedVersion); }

            let device_id = core::ptr::read_volatile((base_raw + Self::REG_DEVICE_ID) as *const u32);
            if device_id == 0 { return Err(ProbeError::EmptySlot); }

            let vendor_id = core::ptr::read_volatile((base_raw + Self::REG_VENDOR_ID) as *const u32);

            Ok(Self {
                base: PhysAddr::new(base_raw),
                device_id,
                vendor_id,
                version,
            })
        }
    }

    pub fn device_id(&self) -> u32 { self.device_id }
    pub fn vendor_id(&self) -> u32 { self.vendor_id }
    pub fn version(&self) -> u32 { self.version }
    pub fn mmio_base(&self) -> PhysAddr { self.base }

    #[inline]
    pub fn read_u32(&self, offset: u64) -> u32 {
        compiler_fence(Ordering::SeqCst);
        let val = unsafe { core::ptr::read_volatile((self.base.raw() + offset) as *const u32) };
        compiler_fence(Ordering::SeqCst);
        val
    }

    #[inline]
    pub fn write_u32(&self, offset: u64, val: u32) {
        compiler_fence(Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((self.base.raw() + offset) as *mut u32, val); }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    NotVirtioMmio,
    WrongMagic,
    UnsupportedVersion,
    EmptySlot,
}

// ── Status and Features ─────────────────────────────────────────────

pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
pub const VIRTIO_STATUS_DRIVER:      u32 = 2;
pub const VIRTIO_STATUS_DRIVER_OK:   u32 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
pub const VIRTIO_STATUS_FAILED:      u32 = 128;

pub const VIRTIO_F_VERSION_1: u64 = 32;

// ── VirtioSkeletonDriver ────────────────────────────────────────────

#[derive(Debug)]
pub struct VirtioSkeletonDriver {
    probed: AtomicU32,
}

impl VirtioSkeletonDriver {
    pub const fn new() -> Self {
        Self { probed: AtomicU32::new(0) }
    }
    pub fn probed_count(&self) -> u32 {
        self.probed.load(Ordering::Relaxed)
    }
    fn probe_registry(&self) {
        for d in narf_bus::devices() {
            if let Ok(_v) = unsafe { VirtioMmioDevice::probe(&d) } {
                self.probed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Driver for VirtioSkeletonDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            self.probe_registry();
        })
    }
    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move { })
    }
}
