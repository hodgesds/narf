//! Private retained RTL8188EE LLT/descriptor continuation, with PCI BME off.
use super::{
    firmware_native::PciIo,
    firmware_transport::{Owner, PacketIo},
    prepare::{Error, Memory, Prepared},
};
use alloc::sync::Arc;
use narf_io::DmaBuffer;

#[derive(Debug)]
pub(super) struct Coherent(DmaBuffer);
fn device_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: device ownership crosses the outer-shareable domain on ARM.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
// SAFETY: each private coherent allocation has a distinct device extent and
// CPU mapping. The generic outer owner retains published buffers on all error
// and Drop paths; sync performs cache maintenance plus device ordering.
unsafe impl Memory for Coherent {
    fn address(&self) -> u64 {
        self.0.dma_addr().raw()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len()) {
            return Err(Error::Address);
        }
        // SAFETY: exclusively owned coherent CPU mapping; complete aligned
        // dword extent validated above. Device addresses are never CPU pointers.
        unsafe {
            self.0
                .cpu_mut_ptr_at::<u32>(offset as u64)
                .write_volatile(value.to_le());
        }
        Ok(())
    }
    fn sync(&self) {
        self.0.sync(0, self.0.len());
        device_barrier();
    }
}
pub(super) type NativePrepared = Prepared<PacketIo<PciIo>, Coherent>;

/// Consume the sole successful firmware owner's native continuation claim
/// before allocation. DMA addresses are allocated under that same live PCI
/// authority; no independently reconstructed BAR or device can be substituted.
/// Dropping/failing this call never makes the claim available to another owner.
pub(super) fn allocate(owner: Arc<Owner<PciIo>>, depth: usize) -> Result<NativePrepared, Error> {
    let port = owner.claim_packet_io()?;
    let mut blocks = alloc::vec::Vec::new();
    // Collect the exact allocation shape before moving the unique port into
    // Prepared. The shared builder validates addresses/extents/overlap anew.
    if !(4..=256).contains(&depth) || !depth.is_power_of_two() {
        return Err(Error::Geometry);
    }
    blocks
        .try_reserve_exact(depth + 8)
        .map_err(|_| Error::Memory)?;
    for bytes in core::iter::repeat_n(depth * 64, 7)
        .chain(core::iter::once(depth * 32))
        .chain(core::iter::repeat_n(4096, depth))
    {
        blocks.push(Coherent(port.with_io(|io| io.allocate_dma(bytes))?));
    }
    let mut blocks = blocks.into_iter();
    Prepared::allocate(port, depth, |_| blocks.next().ok_or(Error::Memory))
}

pub(super) type Retained = narf_lib::mutex::Mutex<Option<NativePrepared>>;

/// The controller and diagnostic interface share this storage before the
/// worker starts. Place all resources there before the first BAR publication;
/// cancellation releases the async guard while retaining the terminal owner.
pub(super) use super::prepare::retain_and_prepare as prepare_retained;

pub(super) async fn initialize_registered(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
) -> Result<(), Error> {
    let profile = super::radio::Profile::from_factory(&factory).map_err(Error::Radio)?;
    firmware.initialize_registered().await?;
    let prepared = allocate(firmware, 128)?;
    prepare_retained(&retained, prepared).await?;
    let mut storage = retained.lock().await;
    storage
        .as_mut()
        .ok_or(Error::State)?
        .configure_radio(profile)
        .await
}
