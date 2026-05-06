//! BootInfo types. Post-validation, callers treat these as trusted.

use narf_memory::{PhysAddr, VirtAddr};

/// A single region in the firmware memory map.
#[derive(Copy, Clone, Debug)]
pub struct MemRegion {
    pub start: PhysAddr,
    pub len: u64,
    pub kind: MemRegionKind,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MemRegionKind {
    /// Free RAM usable by the kernel.
    Usable,
    /// Reserved by firmware / ACPI / bootloader — do not touch.
    Reserved,
    /// ACPI reclaimable.
    AcpiReclaimable,
    /// ACPI NVS.
    AcpiNvs,
    /// Kernel / bootloader modules — treat as reserved for Stage 1.
    Kernel,
}

/// Untrusted raw handoff — whatever the bootloader gave us. Opaque;
/// the per-arch backend reads this and produces a `BootInfo`.
///
/// `#[repr(C)]` is load-bearing: the arch boot stubs construct this from
/// machine registers (RDI, RSI on SysV AMD64 / X0, X1 on AAPCS64) and
/// pass it by value to `_start_rust`. The ABI requires a known, stable
/// field layout.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawBootInfo {
    /// Magic number the bootloader placed in a register (multiboot2:
    /// `0x36d76289`; FDT: magic of the DTB header).
    pub magic: u64,
    /// Pointer to the boot-information structure (multiboot2 info) or to
    /// the DTB (aarch64 U-Boot).
    pub payload: PhysAddr,
}

/// Validated boot info. Held by `frame/init_bsp` for the duration of boot.
#[derive(Debug, Clone)]
pub struct BootInfo {
    pub memory_map: &'static [MemRegion],
    pub cmdline: &'static str,
    /// Physical base of the UART. On x86_64 this is an I/O port number
    /// (0x3F8 by default); on aarch64 it's an MMIO address.
    pub uart_phys: PhysAddr,
    /// Virtual base to be programmed by `memory/` into `console::remap_to_virtual`.
    /// Stage 1 mirrors it from `uart_phys` (kernel is identity-mapped for the
    /// UART pre-MMU); Wave 2's MMU bring-up replaces this with the real
    /// kernel-virtual mapping.
    pub uart_virt: VirtAddr,
    /// Physical address of the device tree blob (aarch64) or 0 on
    /// x86_64. Subsystems that need DTB-described topology (PCIe host
    /// bridge, etc.) walk this directly.
    pub dtb_phys: Option<PhysAddr>,
    /// Physical address of the ACPI RSDP, when the bootloader supplied
    /// one (PVH `hvm_start_info.rsdp_paddr`, multiboot2 ACPI tag, or a
    /// legacy EBDA scan). `None` on aarch64 / non-ACPI platforms.
    pub acpi_rsdp_phys: Option<PhysAddr>,
    /// Physical region carrying the bootloader-supplied initramfs
    /// (CPIO newc archive). On multiboot2 this is the first
    /// `MULTIBOOT2_TAG_TYPE_MODULE` whose cmdline equals
    /// `"initramfs"`; on PVH the equivalent `hvm_modlist_entry`;
    /// on FDT the `chosen` node's `linux,initrd-{start,end}` pair.
    /// `None` when the bootloader supplied no initramfs (raw
    /// `-kernel` boot, smoke-test images).
    ///
    /// `narf-initramfs` consumes this region during `Stage::Early`
    /// to populate its staging static; subsequent consumers
    /// `narf-firmware`'s scan, the userspace init-binary loader,
    /// …) borrow `&'static Initramfs` from `narf_initramfs::staged()`.
    pub initramfs: Option<MemRegion>,
    /// Optional framebuffer parameters provided by the bootloader.
    pub framebuffer: Option<FramebufferInfo>,
    }

    #[derive(Copy, Clone, Debug)]
    pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    }


/// Errors from `validate_boot_info`. Stage 1 raises `BadMagic` and
/// `NoUsableRam`; the rest are scaffolding for later checks.
#[derive(Copy, Clone, Debug)]
pub enum BootError {
    BadMagic,
    NoUsableRam,
    OverlappingRegions,
    BadDtbMagic,
    MisalignedRegion,
    KernelOverlapsUsable,
}
