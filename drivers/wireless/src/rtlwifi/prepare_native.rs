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
    fn read32(&self, offset: usize) -> Result<u32, Error> {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len()) {
            return Err(Error::Address);
        }
        // SAFETY: complete aligned extent in this retained coherent CPU map.
        Ok(u32::from_le(unsafe {
            self.0.cpu_ptr_at::<u32>(offset as u64).read_volatile()
        }))
    }
    fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.0.len())
        {
            return Err(Error::Address);
        }
        for (index, value) in bytes.iter().copied().enumerate() {
            // SAFETY: bounded exclusively owned CPU mapping; no DMA address cast.
            unsafe {
                self.0
                    .cpu_mut_ptr_at::<u8>((offset + index) as u64)
                    .write_volatile(value)
            };
        }
        Ok(())
    }
    fn read_bytes(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.0.len())
        {
            return Err(Error::Address);
        }
        for (index, value) in bytes.iter_mut().enumerate() {
            // SAFETY: bounded retained CPU mapping, after native device barrier.
            *value = unsafe {
                self.0
                    .cpu_ptr_at::<u8>((offset + index) as u64)
                    .read_volatile()
            };
        }
        Ok(())
    }
    fn sync(&self) {
        self.0.sync(0, self.0.len());
        device_barrier();
    }
}
pub(super) type NativePrepared = Prepared<PacketIo<PciIo>, Coherent>;

impl super::prepare::packet::Port for PacketIo<PciIo> {
    fn publication(&self) -> Result<super::prepare::packet::Publication, Error> {
        self.with_io(|io| Ok(io.publication()))
            .map_err(Error::Access)
    }
    type Buffer = Coherent;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.with_io(|io| io.packet_authority(active, operation))?
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Coherent, Error> {
        Ok(Coherent(self.with_io(|io| io.allocate_dma(bytes))?))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.with_io(|io| io.packet_master(enabled))?;
        Ok(())
    }
    fn kick(&self, queue_bit: u16) -> Result<(), Error> {
        self.with_io(|io| io.packet_kick(queue_bit))?;
        Ok(())
    }
}

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
    if firmware.status().stage == super::firmware_transport::Stage::Detected {
        firmware.initialize_registered().await?;
        let prepared = allocate(firmware, 128)?;
        prepare_retained(&retained, prepared).await?;
        let mut storage = retained.lock().await;
        storage
            .as_mut()
            .ok_or(Error::State)?
            .configure_radio(profile)
            .await?;
    } else if firmware.status().stage != super::firmware_transport::Stage::Ready {
        return Err(Error::State);
    }
    let mut storage = retained.lock().await;
    let prepared = storage.as_mut().ok_or(Error::State)?;
    if prepared.phase() == super::prepare::Phase::MacConfigured && prepared.station_transmit_ready()
    {
        return Ok(());
    }
    let calibration =
        super::channel_power::Calibration::load_registered(&factory).map_err(Error::Power)?;
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
    let permission = calibration.permission(&domain, 1).map_err(Error::Power)?;
    if prepared.phase() == super::prepare::Phase::RadioConfigured {
        prepared.configure_channel(permission).await?;
    }
    if prepared.phase() == super::prepare::Phase::ChannelConfigured {
        prepared.configure_mac(&factory)?;
    }
    if prepared.phase() != super::prepare::Phase::MacConfigured {
        return Err(Error::State);
    }
    // Preserve the exact signed board envelope with this same native owner;
    // station progress recomputes permission against current host policy.
    prepared
        .stage_station_calibration(calibration, &domain)
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))
}
