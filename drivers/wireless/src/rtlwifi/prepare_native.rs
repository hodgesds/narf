//! Private retained RTL8188EE/RTL8821AE/RTL8192EE/RTL8192CE LLT/descriptor
//! continuation, with PCI BME off.
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
    let chip = super::prepare::Chip::from_device(owner.device_id()).ok_or(Error::State)?;
    if chip == super::prepare::Chip::Rtl8192ee {
        return allocate_rtl8192ee(owner);
    }
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
        // Each RX slot must hold Linux's 9100-byte rxbuffersize; the shared
        // builder rejects a shorter block (`prepare::RX_BUFFER`).
        .chain(core::iter::repeat_n(super::prepare::RX_BUFFER, depth))
    {
        blocks.push(Coherent(port.with_io(|io| io.allocate_dma(bytes))?));
    }
    let mut blocks = blocks.into_iter();
    Prepared::allocate_for(chip, port, depth, |_| blocks.next().ok_or(Error::Memory))
}

/// RTL8192EE two-ring shape (`prepare::packet::ee92::blocks`): Linux's
/// fixed `TX_DESC_NUM_92E`/`RTL_PCI_MAX_RX_COUNT` counts, which `init_mac`
/// programs, replace the caller's linked-ring depth.
fn allocate_rtl8192ee(owner: Arc<Owner<PciIo>>) -> Result<NativePrepared, Error> {
    use super::prepare::packet::ee92;
    let port = owner.claim_packet_io()?;
    let mut blocks = alloc::vec::Vec::new();
    blocks
        .try_reserve_exact(ee92::DEPTH + 15)
        .map_err(|_| Error::Memory)?;
    for bytes in ee92::blocks() {
        blocks.push(Coherent(port.with_io(|io| io.allocate_dma(bytes))?));
    }
    let mut blocks = blocks.into_iter();
    Prepared::allocate_rtl8192ee(port, |_| blocks.next().ok_or(Error::Memory))
}

pub(super) type Retained = narf_lib::mutex::Mutex<Option<NativePrepared>>;

/// The controller and diagnostic interface share this storage before the
/// worker starts. Place all resources there before the first BAR publication;
/// cancellation releases the async guard while retaining the terminal owner.
pub(super) use super::prepare::retain_and_prepare as prepare_retained;

/// RTL8821AE retained continuation to an admitted 2.4 GHz station owner:
/// registry firmware (`rtl8821aefw_29.bin`, then `rtl8821aefw.bin`), the
/// one-shot packet claim, DMA32 rings, the exact 8821AE LLT, the parked
/// MAC/BB/RF hardware init, then the channel from the signed per-board
/// `NAPC` envelope under current host policy, the operational MAC (boards
/// with the BT function strapped on are refused) and the staged envelope
/// the station re-proves at every publication. Packet DMA, CR gates and
/// IRQs stay closed until the station service starts.
pub(super) async fn prepare_rtl8821ae(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
    channel: u8,
) -> Result<(), Error> {
    if !super::rtl8821ae::envelope::station_channel(channel)
        || firmware.device_id() != super::regs::RTL_DEV_8821AE
    {
        return Err(Error::State);
    }
    if firmware.status().stage == super::firmware_transport::Stage::Detected {
        firmware.initialize_registered().await?;
        let prepared = allocate(firmware, 128)?;
        prepare_retained(&retained, prepared).await?;
        let mut storage = retained.lock().await;
        storage
            .as_mut()
            .ok_or(Error::State)?
            .configure_rtl8821ae(&factory)
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
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
    admit_rtl8821ae(prepared, &factory, &domain, channel).await
}

/// RadioConfigured/ChannelConfigured → MacConfigured with a staged `NAPC`
/// envelope; a MacConfigured owner without one only stages it. Shared by
/// native provisioning and the interface's readiness path.
pub(super) async fn admit_rtl8821ae<I: super::firmware_transport::Io, M: Memory>(
    prepared: &mut Prepared<I, M>,
    factory: &super::efuse::Factory,
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
) -> Result<(), Error> {
    use super::prepare::Phase;
    let calibration =
        super::rtl8821ae::envelope::Calibration::load_registered(factory).map_err(Error::Power)?;
    if matches!(
        prepared.phase(),
        Phase::RadioConfigured | Phase::ChannelConfigured
    ) {
        let permission = calibration
            .permission(domain, channel)
            .map_err(Error::Power)?;
        prepared.configure_rtl8821ae_channel(permission).await?;
        prepared.configure_rtl8821ae_mac(factory)?;
    }
    if prepared.phase() != Phase::MacConfigured {
        return Err(Error::State);
    }
    if prepared.station_calibration_present() {
        return Ok(());
    }
    prepared
        .stage_rtl8821ae_calibration(calibration, domain)
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))
}
/// RTL8192EE retained continuation to an admitted 2.4 GHz station owner,
/// as [`prepare_rtl8821ae`]: registry firmware (`rtl8192eefw.bin`), the
/// one-shot packet claim, the 8192EE BD/descriptor rings with
/// `_rtl92ee_init_mac` (DMA-hang check, LLT, ring bases), the parked
/// `rtl92ee_hw_init` radio (`configure_rtl8192ee`: BT-coexist boards and
/// maps without TX power refused before any table write), then the channel
/// from the signed per-board `N92E` envelope under current host policy,
/// the operational MAC and the staged envelope the station re-proves at
/// every publication. Packet DMA, CR gates and IRQs stay closed until the
/// station service starts.
pub(super) async fn prepare_rtl8192ee(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
    channel: u8,
) -> Result<(), Error> {
    if !(1..=11).contains(&channel) || firmware.device_id() != super::regs::RTL_DEV_8192EE {
        return Err(Error::State);
    }
    if firmware.status().stage == super::firmware_transport::Stage::Detected {
        firmware.initialize_registered().await?;
        let prepared = allocate(firmware, 128)?;
        prepare_retained(&retained, prepared).await?;
        let mut storage = retained.lock().await;
        storage
            .as_mut()
            .ok_or(Error::State)?
            .configure_rtl8192ee(&factory)
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
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
    admit_rtl8192ee(prepared, &factory, &domain, channel).await
}

/// RTL8192CE / RTL8188CE retained continuation to an admitted 2.4 GHz
/// station owner, as [`prepare_rtl8192ee`]: registry firmware (the image
/// `rtl92c_init_sw_vars` selects for the measured version), the one-shot
/// packet claim, the 92C linked rings with `_rtl92ce_llt_table_init` and
/// the remaining `_rtl92ce_init_mac` (`prepare`), the parked
/// `rtl92ce_hw_init` radio (`configure_rtl8192ce`: test chips, 1T2R
/// bondings, unprovisioned maps, BT-coexist boards and a MAC other than the
/// factory identity refused before any table write), then the channel from
/// the signed per-board `N92C` envelope (probed device + measured RF type)
/// under current host policy, the operational MAC and the staged envelope
/// the station re-proves at every publication. Packet DMA, CR gates and
/// IRQs stay closed until the station service starts.
pub(super) async fn prepare_rtl8192ce(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
    channel: u8,
) -> Result<(), Error> {
    let device = firmware.device_id();
    if !(1..=11).contains(&channel) || !super::rtl8192ce::is_8192ce(device) {
        return Err(Error::State);
    }
    if firmware.status().stage == super::firmware_transport::Stage::Detected {
        firmware.initialize_registered().await?;
        let prepared = allocate(firmware, 128)?;
        prepare_retained(&retained, prepared).await?;
        let mut storage = retained.lock().await;
        storage
            .as_mut()
            .ok_or(Error::State)?
            .configure_rtl8192ce(&factory, device)
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
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
    admit_rtl8192ce(prepared, &factory, &domain, channel).await
}

/// RadioConfigured/ChannelConfigured → MacConfigured with a staged `N92C`
/// envelope (20 MHz permission on `channel`) for the owner's probed device
/// and measured RF type; a MacConfigured owner without one only stages it.
/// Shared by native provisioning and the interface's readiness path.
pub(super) async fn admit_rtl8192ce<I: super::firmware_transport::Io, M: Memory>(
    prepared: &mut Prepared<I, M>,
    factory: &super::efuse::Factory,
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
) -> Result<(), Error> {
    use super::prepare::Phase;
    let (device, rf) = prepared.rtl8192ce_binding().ok_or(Error::State)?;
    let calibration = super::rtl8192ce::envelope::Calibration::load_registered(factory, device, rf)
        .map_err(Error::Power)?;
    if matches!(
        prepared.phase(),
        Phase::RadioConfigured | Phase::ChannelConfigured
    ) {
        let permission = calibration
            .permission(domain, channel)
            .map_err(Error::Power)?;
        prepared.configure_rtl8192ce_channel(permission).await?;
        prepared.configure_rtl8192ce_mac(factory)?;
    }
    if prepared.phase() != Phase::MacConfigured {
        return Err(Error::State);
    }
    if prepared.station_calibration_present() {
        return Ok(());
    }
    prepared
        .stage_rtl8192ce_calibration(calibration, domain)
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))
}

/// RadioConfigured/ChannelConfigured → MacConfigured with a staged `N92E`
/// envelope (20 MHz permission on `channel`); a MacConfigured owner
/// without one only stages it. Shared by native provisioning and the
/// interface's readiness path.
pub(super) async fn admit_rtl8192ee<I: super::firmware_transport::Io, M: Memory>(
    prepared: &mut Prepared<I, M>,
    factory: &super::efuse::Factory,
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
) -> Result<(), Error> {
    use super::prepare::Phase;
    let calibration =
        super::rtl8192ee::envelope::Calibration::load_registered(factory).map_err(Error::Power)?;
    if matches!(
        prepared.phase(),
        Phase::RadioConfigured | Phase::ChannelConfigured
    ) {
        let permission = calibration
            .permission(domain, channel)
            .map_err(Error::Power)?;
        prepared.configure_rtl8192ee_channel(permission).await?;
        prepared.configure_rtl8192ee_mac(factory)?;
    }
    if prepared.phase() != Phase::MacConfigured {
        return Err(Error::State);
    }
    if prepared.station_calibration_present() {
        return Ok(());
    }
    prepared
        .stage_rtl8192ee_calibration(calibration, domain)
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))
}

/// RTL8192DE retained continuation to an admitted 2.4 GHz station owner:
/// registry firmware (`rtl8192defw.bin`), the one-shot packet claim,
/// DMA32 rings, the mode-dependent LLT (the mode is bound from the PROM
/// before the prepare runs), the `rtl92de_hw_init` tail, then the channel
/// from the signed per-board `N92D` envelope under current host policy,
/// the operational MAC and the staged envelope the station re-proves at
/// every publication. Packet DMA, CR gates and IRQs stay closed until
/// the station service starts. The channel gate is the function's own
/// bandset (`rtl8192de::native_channel` over the PROM mode and the PCI
/// function): a dual-dual MAC0 function (5 GHz bandset) admits the
/// 5 GHz station plan, MAC1 2.4 GHz channels 1-11, single and
/// dual-single functions both bands.
pub(super) async fn prepare_rtl8192de(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
    channel: u8,
) -> Result<(), Error> {
    if firmware.device_id() != super::regs::RTL_DEV_8192DE {
        return Err(Error::State);
    }
    let interface_index = firmware.native().function().ok_or(Error::State)?;
    let mode = super::rtl8192de::mode_from_prom(super::rtl8192de::Interface::Pci, &factory.logical)
        .ok_or(Error::State)?;
    if !super::rtl8192de::native_channel(channel, mode, interface_index) {
        return Err(Error::State);
    }
    if firmware.status().stage == super::firmware_transport::Stage::Detected {
        firmware.initialize_registered().await?;
        let mut prepared = allocate(firmware, 128)?;
        prepared.bind_rtl8192de_mode(mode)?;
        prepare_retained(&retained, prepared).await?;
        let mut storage = retained.lock().await;
        storage
            .as_mut()
            .ok_or(Error::State)?
            .configure_rtl8192de(&factory, interface_index)
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
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
    admit_rtl8192de(prepared, &factory, &domain, channel).await
}

/// RadioConfigured/ChannelConfigured → MacConfigured with a staged `N92D`
/// envelope (20 MHz permission on `channel`) for the owner's probed device
/// and measured RF type; a MacConfigured owner without one only stages it.
/// Shared by native provisioning and the interface's readiness path.
pub(super) async fn admit_rtl8192de<I: super::firmware_transport::Io, M: Memory>(
    prepared: &mut Prepared<I, M>,
    factory: &super::efuse::Factory,
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
) -> Result<(), Error> {
    use super::prepare::Phase;
    prepared.rtl8192de_binding().ok_or(Error::State)?;
    let calibration =
        super::rtl8192de::envelope::Calibration::load_registered(factory).map_err(Error::Power)?;
    if matches!(
        prepared.phase(),
        Phase::RadioConfigured | Phase::ChannelConfigured
    ) {
        let permission = calibration
            .permission(domain, channel)
            .map_err(Error::Power)?;
        prepared.configure_rtl8192de_channel(permission).await?;
        prepared.configure_rtl8192de_mac(factory)?;
    }
    if prepared.phase() != Phase::MacConfigured {
        return Err(Error::State);
    }
    if prepared.station_calibration_present() {
        return Ok(());
    }
    prepared
        .stage_rtl8192de_calibration(calibration, domain)
        .map_err(|_| Error::Power(super::channel_power::Error::Policy))
}
pub(super) async fn initialize_registered(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
) -> Result<(), Error> {
    initialize_registered_on_channel(firmware, retained, factory, 1).await
}
pub(super) async fn initialize_registered_on_channel(
    firmware: Arc<Owner<PciIo>>,
    retained: Arc<Retained>,
    factory: Arc<super::efuse::Factory>,
    channel: u8,
) -> Result<(), Error> {
    // RTL8821AE and RTL8192DE are dual-band (their own gates admit the
    // 5 GHz plan, 92DE per function bandset); every other profile stays on
    // 2.4 GHz channels 1-11.
    if firmware.device_id() == super::regs::RTL_DEV_8821AE {
        return prepare_rtl8821ae(firmware, retained, factory, channel).await;
    }
    if firmware.device_id() == super::regs::RTL_DEV_8192DE {
        return prepare_rtl8192de(firmware, retained, factory, channel).await;
    }
    if !(1..=11).contains(&channel) {
        return Err(Error::State);
    }
    if firmware.device_id() == super::regs::RTL_DEV_8192EE {
        return prepare_rtl8192ee(firmware, retained, factory, channel).await;
    }
    if super::rtl8192ce::is_8192ce(firmware.device_id()) {
        return prepare_rtl8192ce(firmware, retained, factory, channel).await;
    }
    if firmware.device_id() != super::regs::RTL_DEV_8188EE {
        return Err(Error::State);
    }
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
    let permission = calibration
        .permission(&domain, channel)
        .map_err(Error::Power)?;
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
