//! Per-device DMA configuration from firmware: Linux `of_dma_configure`
//! (coherence) plus `of_reserved_mem_device_init` (a `shared-dma-pool`).
//!
//! Spec: `bus/specification/spec.md` §3 ("DMA configuration").
//!
//! * x86_64 is always coherent (Linux x86 selects no
//!   `ARCH_HAS_SYNC_DMA_*`, so `dev_is_dma_coherent` is constant true) and
//!   carries no Devicetree pools: [`configure`] is [`DmaDevice::coherent`].
//! * aarch64 PCI functions take the host bridge node's `of_dma_is_coherent`
//!   (`pci_dma_configure` → `of_dma_configure(bridge->parent->of_node)`),
//!   defaulting to non-coherent like arm64's `dma_default_coherent`. A
//!   `dma-mem` interconnect DMA parent is not followed and counts as
//!   non-coherent.
//! * The function node's `memory-region[0]` `shared-dma-pool` becomes the
//!   device pool. Linux leaves that call to drivers; NARF makes it here
//!   because it cannot remap System RAM non-cacheable (`DMA_DIRECT_REMAP`),
//!   so a reserved pool is the only non-coherent backing. A non-coherent
//!   device without one falls back to the `linux,dma-default` pool
//!   (`DMA_GLOBAL_POOL`), else allocation fails closed.
//! * A DTB-less aarch64 boot is NARF's QEMU `virt` fallback, whose PCIe and
//!   virtio are coherent; it keeps the coherent configuration. aarch64 boots
//!   never carry ACPI (`acpi_rsdp_phys = None`), so `_CCA` has no source.

use narf_io::{CoherentPool, DmaCoherence, DmaDevice, IoError};

use crate::BusDevice;

/// Linux `of_dma_configure` + `of_reserved_mem_device_init` for `device`.
///
/// Errors: a non-PCI device on a Devicetree boot (`NotMapped`: platform
/// device ↔ node association is not implemented for DMA), or a described
/// pool that cannot be mapped (`PoolRejected` / `NotMapped`).
pub fn configure(device: &BusDevice) -> Result<DmaDevice, IoError> {
    #[cfg(target_arch = "aarch64")]
    {
        const MAX_DTB_SIZE: usize = 2 * 1024 * 1024;
        let Some(phys) = crate::boot_dtb() else {
            return Ok(DmaDevice::coherent());
        };
        // SAFETY: the boot path reserved the firmware DTB in RAM covered by
        // the kernel direct map; `discover` bounds every slice by the blob's
        // own `totalsize` (capped here).
        let Some(blob) =
            (unsafe { narf_firmware_fdt::discover(phys.raw() as usize, MAX_DTB_SIZE) })
        else {
            return Ok(DmaDevice::coherent());
        };
        let crate::BusKind::Pcie { addr, .. } = device.kind else {
            return Err(IoError::NotMapped);
        };
        let devfns = crate::pci::devfn_path(device);
        // SAFETY: boot subtracted every enabled static `/reserved-memory`
        // range from the RAM map, and `pci_from_dt` maps only `no-map`
        // `shared-dma-pool` ranges, which nothing else in the kernel uses.
        unsafe { pci_from_dt(blob, addr.segment, devfns.as_deref(), false) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = device;
        Ok(DmaDevice::coherent())
    }
}

/// Devicetree half of [`configure`] for a PCI function of `domain` reached
/// through `devfns` (root hop first; `None` = no node association, so no
/// device pool). `default_coherent` is the arch `dma_default_coherent`.
///
/// # Safety
/// Every `no-map` `shared-dma-pool` in `blob` must be reserved memory that
/// nothing but the resulting [`CoherentPool`]s uses.
pub unsafe fn pci_from_dt(
    blob: &[u8],
    domain: u16,
    devfns: Option<&[u8]>,
    default_coherent: bool,
) -> Result<DmaDevice, IoError> {
    use narf_firmware_fdt::DmaCoherenceProp as P;
    let coherent = match narf_firmware_fdt::pci_host_bridge_dma_coherence(blob, domain) {
        Some(P::Coherent) => true,
        Some(P::NonCoherent | P::Unresolved) => false,
        Some(P::Default) | None => default_coherent,
    };
    let coherence = if coherent {
        DmaCoherence::Coherent
    } else {
        DmaCoherence::NonCoherent
    };
    let map = |pool: narf_firmware_fdt::SharedDmaPool| {
        // SAFETY: caller contract.
        unsafe { CoherentPool::reserved(pool.addr, pool.size) }
    };
    let device_pool = devfns
        .and_then(|devfns| narf_firmware_fdt::pci_function_dma_pool(blob, domain, devfns))
        .map(map)
        .transpose()?;
    let default_pool = if device_pool.is_none() && !coherent {
        narf_firmware_fdt::default_shared_dma_pool(blob)
            .map(map)
            .transpose()?
    } else {
        None
    };
    Ok(DmaDevice::new(coherence, device_pool, default_pool))
}

#[path = "dma_tests.rs"]
mod tests;
