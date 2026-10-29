//! Live RX 6000 / RX 9000 INFO queries. References: gfx_v10_0_get_gpu_clock_counter,
//! amdgpu_info_ioctl, sienna_cichlid_ppt.c and smu_v14_0_2_ppt.c in Linux.
//! The platform owner serializes these reads with reset and the SMU mailbox.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank, amdgpu_smu_navi22 as smu,
    amdgpu_uapi as u,
};
use alloc::vec::Vec;
use core::future::Future;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_filesystem::FsError;

// smuio_11_0_0_offset.h, BASE_IDX 1 (discrete GC 10.3's default branch).
const UPPER: u32 = 0x102; // linux: mmGOLDEN_TSC_COUNT_UPPER
const LOWER: u32 = 0x103; // linux: mmGOLDEN_TSC_COUNT_LOWER
                          // hdp_5_0_0_offset.h, BASE_IDX 0; all counter bits remain valid data.
const HDP_LIVE: u32 = 0xd1; // linux: mmHDP_READ_CACHE_INVALIDATE

#[derive(Clone, Copy, Debug)]
struct ClockLayout {
    upper: u64,
    lower: u64,
    live: u64,
}
impl ClockLayout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, FsError> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(FsError::InvalidData)?;
        bank(gpu, ip::HW_ID_GC, &[profile.gc_version], 0, 0).map_err(|_| FsError::InvalidData)?;
        let smuio = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_SMUIO, 0)
            .filter(|b| b.major == 11 && b.minor == 0)
            .ok_or(FsError::InvalidData)?;
        let base = bank(
            gpu,
            ip::HW_ID_SMUIO,
            &[(smuio.major, smuio.minor, smuio.revision)],
            1,
            LOWER,
        )
        .map_err(|_| FsError::InvalidData)?;
        let hdp = bank(
            gpu,
            ip::HW_ID_HDP,
            &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
            0,
            HDP_LIVE,
        )
        .map_err(|_| FsError::InvalidData)?;
        Ok(Self {
            upper: base + u64::from(UPPER) * 4,
            lower: base + u64::from(LOWER) * 4,
            live: hdp + u64::from(HDP_LIVE) * 4,
        })
    }
}

trait Io {
    fn read(&mut self, at: u64) -> u32;
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: ClockLayout bounds all three registers in the owner's
        // permanent BAR mapping; the caller holds live PCI authority.
        unsafe { self.0.read32(at) }
    }
}
fn sample(io: &mut impl Io, layout: ClockLayout) -> Result<u64, FsError> {
    if io.read(layout.live) == u32::MAX {
        return Err(FsError::NoDevice);
    }
    let before = io.read(layout.upper);
    let mut lower = io.read(layout.lower);
    let after = io.read(layout.upper);
    if before != after {
        lower = io.read(layout.lower);
    }
    if io.read(layout.live) == u32::MAX {
        return Err(FsError::NoDevice);
    }
    Ok(u64::from(after) << 32 | u64::from(lower))
}

/// Caller holds the retained boot owner, excluding reset/BAR teardown.
pub(crate) fn timestamp_rdna2(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<u64, FsError> {
    let layout = ClockLayout::resolve(gpu)?;
    struct Read(MmioRegion, ClockLayout);
    impl CapOp<BusDeviceCap, Write> for Read {
        type Output = Result<u64, FsError>;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
            // Linux disables preemption around the split counter. This short
            // read sequence cannot await, block, or span another low-word wrap.
            Ok(narf_lib::sync::without_interrupts(|| {
                sample(&mut Mmio(self.0), self.1)
            }))
        }
    }
    authority
        .invoke(Read(gpu.regs, layout))
        .map_err(|_| FsError::NoDevice)?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sensor {
    Sclk,
    Mclk,
    Temperature,
    Load,
    Power,
    Voltage,
    SocVoltage,
    InputPower,
    StableSclk,
    StableMclk,
    PeakSclk,
    PeakMclk,
}
impl Sensor {
    fn parse(which: u32) -> Result<Self, FsError> {
        match which {
            u::AMDGPU_INFO_SENSOR_GFX_SCLK => Ok(Self::Sclk),
            u::AMDGPU_INFO_SENSOR_GFX_MCLK => Ok(Self::Mclk),
            u::AMDGPU_INFO_SENSOR_GPU_TEMP => Ok(Self::Temperature),
            u::AMDGPU_INFO_SENSOR_GPU_LOAD => Ok(Self::Load),
            u::AMDGPU_INFO_SENSOR_GPU_AVG_POWER => Ok(Self::Power),
            u::AMDGPU_INFO_SENSOR_VDDGFX => Ok(Self::Voltage),
            u::AMDGPU_INFO_SENSOR_VDDNB => Ok(Self::SocVoltage),
            u::AMDGPU_INFO_SENSOR_GPU_INPUT_POWER => Ok(Self::InputPower),
            u::AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_SCLK => Ok(Self::StableSclk),
            u::AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_MCLK => Ok(Self::StableMclk),
            u::AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_SCLK => Ok(Self::PeakSclk),
            u::AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_MCLK => Ok(Self::PeakMclk),
            _ => Err(FsError::InvalidData),
        }
    }
    fn value(self, t: &Sensors) -> Result<u32, FsError> {
        Ok(match self {
            Self::Sclk => t.gfx_mhz,
            Self::Mclk => t.memory_mhz,
            Self::Temperature => t.temperature_milli,
            Self::Load => t.load,
            Self::Power => t.power_w,
            Self::Voltage => t.voltage_mv,
            Self::SocVoltage => t.soc_voltage_mv.ok_or(FsError::InvalidData)?,
            Self::InputPower => t.input_power_w.ok_or(FsError::InvalidData)?,
            _ => unreachable!("P-state queries use the DPM table"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pstates {
    pub gfx_standard: u32,
    pub memory_standard: u32,
    pub gfx_peak: u32,
    pub memory_peak: u32,
}
/// GetDpmFreqByIndex(0xff) includes an unrelated bit-31 DPM-mode flag.
/// Index 0xff is reserved for the count, so no last level may alias it.
pub(crate) fn last_dpm_index(raw: u32) -> Option<u32> {
    let count = raw & 0x7fff_ffff;
    (1..=0xff).contains(&count).then(|| count - 1)
}
pub(crate) fn dpm_mhz(raw: u32) -> Option<u32> {
    let mhz = raw & 0x7fff_ffff;
    (1..=u32::from(u16::MAX)).contains(&mhz).then_some(mhz)
}

pub(crate) struct Sensors {
    pub gfx_mhz: u32,
    pub memory_mhz: u32,
    pub temperature_milli: u32,
    pub load: u32,
    pub power_w: u32,
    pub voltage_mv: u32,
    pub soc_voltage_mv: Option<u32>,
    /// Latest SMU socket-power sample, in watts. Firmware averages over its
    /// sampling interval; this is not a separate instantaneous measurement.
    pub input_power_w: Option<u32>,
}
pub(crate) fn latest_power_w(socket_power_w: u16) -> Option<u32> {
    (socket_power_w != u16::MAX).then_some(u32::from(socket_power_w))
}
pub(crate) trait Backend {
    fn timestamp(&mut self) -> Result<u64, FsError>;
    fn dpm_enabled(&self) -> Result<bool, FsError>;
    fn telemetry(&mut self) -> impl Future<Output = Result<Sensors, FsError>> + Send;
    fn pstates(&mut self) -> impl Future<Output = Result<Pstates, FsError>> + Send;
}

pub(crate) fn smu_error(error: smu::Error) -> FsError {
    match error {
        smu::Error::Revoked | smu::Error::DeviceGone => FsError::NoDevice,
        _ => FsError::InvalidData,
    }
}
impl Backend for crate::amdgpu_navi22_boot::ColdBoot {
    fn timestamp(&mut self) -> Result<u64, FsError> {
        self.read_timestamp()
    }
    fn dpm_enabled(&self) -> Result<bool, FsError> {
        self.sensor_dpm_enabled()
    }
    async fn telemetry(&mut self) -> Result<Sensors, FsError> {
        let t = self
            .power_sample()
            .await
            .map_err(|error| match error {
                crate::amdgpu_navi22_boot::Error::Smu(error) => smu_error(error),
                _ => FsError::NoDevice,
            })?
            .telemetry
            .map_err(smu_error)?;
        Ok(Sensors {
            gfx_mhz: u32::from(t.metrics.gfx_mhz),
            memory_mhz: t.metrics.uclk_mhz,
            temperature_milli: t.metrics.edge_milli as u32,
            load: u32::from(t.metrics.gfx_activity),
            power_w: u32::from(t.metrics.socket_power_w),
            voltage_mv: u32::from(t.vddgfx_mv),
            soc_voltage_mv: t.metrics.vddsoc_mv.map(u32::from),
            input_power_w: latest_power_w(t.metrics.socket_power_w),
        })
    }
    async fn pstates(&mut self) -> Result<Pstates, FsError> {
        self.sensor_pstates().await
    }
}
impl Backend for crate::amdgpu_navi48_boot::ColdBoot {
    fn timestamp(&mut self) -> Result<u64, FsError> {
        self.read_timestamp()
    }
    fn dpm_enabled(&self) -> Result<bool, FsError> {
        self.sensor_dpm_enabled()
    }
    async fn telemetry(&mut self) -> Result<Sensors, FsError> {
        let t = self
            .power_sample()
            .await
            .map_err(|_| FsError::NoDevice)?
            .telemetry
            .map_err(smu14_error)?;
        Ok(Sensors {
            gfx_mhz: u32::from(t.metrics.gfx_mhz),
            memory_mhz: t.metrics.uclk_mhz,
            temperature_milli: t.metrics.edge_milli as u32,
            load: u32::from(t.metrics.gfx_activity),
            power_w: u32::from(t.metrics.socket_power_w),
            voltage_mv: u32::from(t.metrics.vddgfx_mv),
            soc_voltage_mv: t.metrics.vddsoc_mv.map(u32::from),
            input_power_w: latest_power_w(t.metrics.socket_power_w),
        })
    }
    async fn pstates(&mut self) -> Result<Pstates, FsError> {
        self.sensor_pstates().await
    }
}
pub(crate) fn smu14_error(error: crate::amdgpu_smu_navi48::Error) -> FsError {
    use crate::amdgpu_smu_navi48::Error;
    match error {
        Error::Revoked | Error::DeviceGone => FsError::NoDevice,
        _ => FsError::InvalidData,
    }
}

/// Reply to a copied drm_amdgpu_info while the caller retains the platform
/// owner. Both primary and render nodes enter here through dispatch_live.
pub(crate) async fn dispatch(bytes: &[u8], backend: &mut impl Backend) -> Result<u64, FsError> {
    if bytes.len() != 32 {
        return Err(FsError::InvalidData);
    }
    let pointer = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if pointer == 0 || size == 0 {
        return Err(FsError::InvalidData);
    }
    let which = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let reply: Vec<u8> = match which {
        u::AMDGPU_INFO_TIMESTAMP => backend.timestamp()?.to_le_bytes().to_vec(),
        u::AMDGPU_INFO_SENSOR => {
            // Linux checks dpm_enabled before even validating the sensor ID.
            if !backend.dpm_enabled()? {
                return Err(FsError::NotFound);
            }
            let sensor = Sensor::parse(u32::from_le_bytes(bytes[16..20].try_into().unwrap()))?;
            let value = match sensor {
                Sensor::StableSclk | Sensor::StableMclk | Sensor::PeakSclk | Sensor::PeakMclk => {
                    let p = backend.pstates().await?;
                    match sensor {
                        Sensor::StableSclk => p.gfx_standard,
                        Sensor::StableMclk => p.memory_standard,
                        Sensor::PeakSclk => p.gfx_peak,
                        _ => p.memory_peak,
                    }
                }
                _ => sensor.value(&backend.telemetry().await?)?,
            };
            value.to_le_bytes().to_vec()
        }
        _ => return Err(FsError::InvalidData),
    };
    // SAFETY: the caller's nonzero return_pointer; copy_out checks access_ok
    // and faults, writing at most min(return_size, sizeof(the reply)).
    unsafe {
        crate::drm_ioctl_bridge::copy_out(pointer as usize, &reply[..reply.len().min(size)])?
    };
    Ok(0)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_info_stats_tests.rs"]
mod tests;
