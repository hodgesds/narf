//! Native Rust register and ioctl cases; expected wire values are literal
//! Linux units, independent of the production sensor selector.
use super::*;
use alloc::{boxed::Box, vec};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Script(Vec<(u64, u32)>);
impl Io for Script {
    fn read(&mut self, at: u64) -> u32 {
        let (expected, value) = self.0.remove(0);
        assert_eq!(at, expected);
        value
    }
}
fn stats_clock_carry_all_ones_and_loss() -> TestResult {
    let layout = ClockLayout {
        upper: 0x118,
        lower: 0x11c,
        live: 0x80,
    };
    for (script, expected) in [
        (
            vec![(0x80, 0), (0x118, 2), (0x11c, 16), (0x118, 2), (0x80, 0)],
            Ok(0x2_0000_0010),
        ),
        (
            vec![
                (0x80, 0),
                (0x118, 2),
                (0x11c, u32::MAX),
                (0x118, 3),
                (0x11c, 4),
                (0x80, 0),
            ],
            Ok(0x3_0000_0004),
        ),
        (
            vec![
                (0x80, 0),
                (0x118, u32::MAX),
                (0x11c, u32::MAX),
                (0x118, u32::MAX),
                (0x80, 0),
            ],
            Ok(u64::MAX),
        ),
        (vec![(0x80, u32::MAX)], Err(FsError::NoDevice)),
        (
            vec![
                (0x80, 0),
                (0x118, 2),
                (0x11c, 16),
                (0x118, 2),
                (0x80, u32::MAX),
            ],
            Err(FsError::NoDevice),
        ),
    ] {
        let mut io = Script(script);
        assert_eq!(sample(&mut io, layout), expected);
        assert!(io.0.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_clock_carry_all_ones_and_loss
);

fn stats_rdna2_clock_uses_discovery_and_current_authority() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        for &did in profile.pci_ids {
            let mut gpu = crate::amdgpu_cp_navi22::tests::rdna2_gpu(profile, did);
            let mut memory = vec![0u32; 0x20000];
            gpu.regs.virt = memory.as_mut_ptr() as u64;
            gpu.regs.len = memory.len() as u64 * 4;
            let mut block = gpu.ip_blocks[0];
            block.hw_id = ip::HW_ID_SMUIO;
            (block.major, block.minor, block.revision) = (11, 0, 2);
            block.num_bases = 2;
            block.base_addrs[0] = 0x200; // Deliberately different from BASE_IDX 1.
            block.base_addrs[1] = 0x500;
            gpu.ip_blocks.push(block);
            memory[0x500 + 0x102] = 0x1234_5678;
            memory[0x500 + 0x103] = 0x9abc_def0;
            let cap = Cap::bootstrap();
            assert_eq!(timestamp_rdna2(&gpu, &cap), Ok(0x1234_5678_9abc_def0));
            memory[0xf20 + 0xd1] = u32::MAX;
            assert_eq!(timestamp_rdna2(&gpu, &cap), Err(FsError::NoDevice));
            memory[0xf20 + 0xd1] = 0;
            for bad in 0..4 {
                let original = gpu.ip_blocks.last().copied().unwrap();
                match bad {
                    0 => gpu.ip_blocks.last_mut().unwrap().major = 14,
                    1 => gpu.ip_blocks.last_mut().unwrap().num_bases = 1,
                    2 => gpu.ip_blocks.push(original),
                    _ => gpu.regs.len = (0x500 + 0x103) * 4,
                }
                assert_eq!(timestamp_rdna2(&gpu, &cap), Err(FsError::InvalidData));
                if bad == 2 {
                    gpu.ip_blocks.pop();
                }
                *gpu.ip_blocks.last_mut().unwrap() = original;
                gpu.regs.len = memory.len() as u64 * 4;
            }
            cap.revoke();
            gpu.regs.virt = 0; // A bypass of invoke would fault, not read a fixture.
            assert_eq!(timestamp_rdna2(&gpu, &cap), Err(FsError::NoDevice));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_rdna2_clock_uses_discovery_and_current_authority
);

fn stats_rdna4_clock_uses_smuio14_and_current_authority() -> TestResult {
    for profile in crate::amdgpu_rdna4::tests::Profile::ALL {
        let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
        profile.apply(&mut gpu);
        let mut memory = vec![0u32; 0x20000];
        gpu.regs.virt = memory.as_mut_ptr() as u64;
        gpu.regs.len = memory.len() as u64 * 4;
        gpu.ip_blocks
            .retain(|b| !matches!(b.hw_id, ip::HW_ID_SMUIO | ip::HW_ID_HDP));
        let mut block = gpu.ip_blocks[0];
        block.hw_id = ip::HW_ID_SMUIO;
        (block.major, block.minor, block.revision) = (14, 0, 2);
        block.num_bases = 2;
        block.base_addrs[0] = 0x200;
        block.base_addrs[1] = 0x500;
        gpu.ip_blocks.push(block);
        block.hw_id = ip::HW_ID_HDP;
        (block.major, block.minor, block.revision) = (6, 1, 0);
        block.base_addrs[0] = 0x800;
        gpu.ip_blocks.push(block);
        // HDP6 has no HDP5 invalidate register at 0xd1. Poison it so the
        // real reader must use the documented HOST_PATH_CNTL at 0xcc.
        memory[0x800 + 0xd1] = u32::MAX;
        for version in [(6, 0, 0), (6, 0, 1), (6, 1, 0), (6, 1, 1), (6, 4, 0)] {
            let hdp = gpu.ip_blocks.last_mut().unwrap();
            (hdp.major, hdp.minor, hdp.revision) = version;
            memory[0x500 + 0x2d] = 1;
            memory[0x500 + 0x2e] = u32::MAX;
            let cap = Cap::bootstrap();
            let reader = crate::amdgpu_smuio14::ClockReader::new(&gpu, cap).unwrap();
            assert_eq!(reader.read(), Some(0x1_ffff_ffff));
            memory[0x500 + 0x2d] = u32::MAX;
            assert_eq!(reader.read(), Some(u64::MAX));
            memory[0x800 + 0xcc] = u32::MAX;
            assert_eq!(reader.read(), None);
            memory[0x800 + 0xcc] = 0;
            cap.revoke();
            assert_eq!(reader.read(), None);
        }
        let hdp = gpu.ip_blocks.last_mut().unwrap();
        hdp.major = 5;
        assert!(crate::amdgpu_smuio14::ClockReader::new(&gpu, Cap::bootstrap()).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_rdna4_clock_uses_smuio14_and_current_authority
);

struct Fake {
    enabled: bool,
    gone: bool,
    pending: bool,
    error: Option<smu::Error>,
    clocks: usize,
    samples: usize,
    states: usize,
    gfx: u32,
    soc_voltage: Option<u32>,
    input_power: Option<u32>,
}
impl Fake {
    fn new() -> Self {
        Self {
            enabled: true,
            gone: false,
            pending: false,
            error: None,
            clocks: 0,
            samples: 0,
            states: 0,
            gfx: 2554,
            soc_voltage: Some(950),
            input_power: Some(171),
        }
    }
}
impl Backend for Fake {
    fn timestamp(&mut self) -> Result<u64, FsError> {
        self.clocks += 1;
        if self.gone {
            Err(FsError::NoDevice)
        } else {
            Ok(0x0123_4567_89ab_cdef)
        }
    }
    fn dpm_enabled(&self) -> Result<bool, FsError> {
        if self.gone {
            Err(FsError::NoDevice)
        } else {
            Ok(self.enabled)
        }
    }
    async fn telemetry(&mut self) -> Result<Sensors, FsError> {
        self.samples += 1;
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(error) = self.error {
            return Err(smu_error(error));
        }
        Ok(Sensors {
            gfx_mhz: self.gfx,
            memory_mhz: 1000,
            temperature_milli: 52000,
            load: 81,
            power_w: 171,
            voltage_mv: 1150,
            soc_voltage_mv: self.soc_voltage,
            input_power_w: self.input_power,
        })
    }
    async fn pstates(&mut self) -> Result<Pstates, FsError> {
        self.states += 1;
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(error) = self.error {
            return Err(smu_error(error));
        }
        Ok(Pstates {
            gfx_standard: 1825,
            memory_standard: 1000,
            gfx_peak: 2600,
            memory_peak: 1125,
        })
    }
}
fn request(out: &mut [u8], which: u32, sensor: u32, size: u32) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    bytes[8..12].copy_from_slice(&size.to_le_bytes());
    bytes[12..16].copy_from_slice(&which.to_le_bytes());
    bytes[16..20].copy_from_slice(&sensor.to_le_bytes());
    bytes
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn stats_ioctl_units_pstates_and_short_replies() -> TestResult {
    let mut backend = Fake::new();
    // amdgpu_info_ioctl: MHz, mC, percent, watts, mV, then UMD clocks in MHz.
    for (sensor, expected) in [
        (1, 2554u32),
        (2, 1000),
        (3, 52000),
        (4, 81),
        (5, 171),
        (6, 950),
        (7, 1150),
        (8, 1825),
        (9, 1000),
        (10, 2600),
        (11, 1125),
        (12, 171),
    ] {
        for size in [1, 3, 4, 16] {
            let mut out = [0xa5u8; 16];
            let req = request(&mut out, u::AMDGPU_INFO_SENSOR, sensor, size);
            assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
            let n = (size as usize).min(4);
            assert_eq!(&out[..n], &expected.to_le_bytes()[..n]);
            assert!(out[n..].iter().all(|&b| b == 0xa5));
        }
    }
    assert_eq!((backend.samples, backend.states), (32, 16));
    for size in [3, 8, 16] {
        let mut out = [0xa5u8; 16];
        let req = request(&mut out, u::AMDGPU_INFO_TIMESTAMP, 0, size);
        backend.enabled = false; // The always-on timestamp is independent of DPM.
        assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
        let n = (size as usize).min(8);
        assert_eq!(&out[..n], &0x0123_4567_89ab_cdefu64.to_le_bytes()[..n]);
        assert!(out[n..].iter().all(|&b| b == 0xa5));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_ioctl_units_pstates_and_short_replies
);

fn stats_ioctl_refuses_unavailable_data_and_bad_copies() -> TestResult {
    let mut backend = Fake::new();
    for sensor in [0, 13, u32::MAX] {
        let mut out = [0xa5u8; 16];
        let req = request(&mut out, u::AMDGPU_INFO_SENSOR, sensor, 16);
        backend.enabled = true;
        assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::InvalidData));
        backend.enabled = false;
        assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::NotFound));
        assert_eq!(out, [0xa5; 16]);
    }
    assert_eq!((backend.samples, backend.states), (0, 0));
    backend.enabled = true;
    for (error, expected) in [
        (smu::Error::Rejected(0xfd), FsError::InvalidData),
        (smu::Error::Timeout, FsError::InvalidData),
        (smu::Error::Revoked, FsError::NoDevice),
        (smu::Error::DeviceGone, FsError::NoDevice),
    ] {
        for sensor in [1, 6, 8, 12] {
            backend.error = Some(error);
            let mut out = [0xa5u8; 16];
            let req = request(&mut out, u::AMDGPU_INFO_SENSOR, sensor, 16);
            assert_eq!(run(dispatch(&req, &mut backend)), Err(expected));
            assert_eq!(out, [0xa5; 16]);
        }
    }
    backend.error = None;
    let mut out = [0xa5u8; 16];
    let mut req = request(&mut out, u::AMDGPU_INFO_TIMESTAMP, 0, 0);
    assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::InvalidData));
    assert_eq!(backend.clocks, 0);
    req[8..12].copy_from_slice(&16u32.to_le_bytes());
    {
        let _strict = crate::drm_ioctl_bridge::kernel_test_buffers::StrictUserCopies::new();
        assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::BadAddress));
    }
    assert_eq!(out, [0xa5; 16]);
    backend.gone = true;
    assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::NoDevice));
    assert_eq!(out, [0xa5; 16]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_ioctl_refuses_unavailable_data_and_bad_copies
);

fn stats_pending_queries_do_not_publish_and_samples_are_fresh() -> TestResult {
    for sensor in [1, 6, 8, 12] {
        let mut backend = Fake::new();
        backend.pending = true;
        let mut out = [0xa5u8; 16];
        let req = request(&mut out, u::AMDGPU_INFO_SENSOR, sensor, 16);
        let mut future = Box::pin(dispatch(&req, &mut backend));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        drop(future);
        assert_eq!(out, [0xa5; 16]);
        assert_eq!(backend.samples + backend.states, 1);
    }
    let mut backend = Fake::new();
    let mut out = [0xa5u8; 16];
    let req = request(&mut out, u::AMDGPU_INFO_SENSOR, 1, 4);
    assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
    assert_eq!(&out[..4], &2554u32.to_le_bytes());
    backend.gfx = 1900;
    assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
    assert_eq!(&out[..4], &1900u32.to_le_bytes());
    assert_eq!(backend.samples, 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_pending_queries_do_not_publish_and_samples_are_fresh
);

fn stats_soc_voltage_and_input_power_are_fresh_and_optional() -> TestResult {
    let mut backend = Fake::new();
    for (sensor, first, next) in [(6, 950u32, 1000u32), (12, 171, 203)] {
        let mut out = [0xa5u8; 16];
        let req = request(&mut out, u::AMDGPU_INFO_SENSOR, sensor, 4);
        assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
        assert_eq!(&out[..4], &first.to_le_bytes());
        if sensor == 6 {
            backend.soc_voltage = Some(next);
        } else {
            backend.input_power = Some(next);
        }
        assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
        assert_eq!(&out[..4], &next.to_le_bytes());
        if sensor == 6 {
            backend.soc_voltage = None;
        } else {
            backend.input_power = None;
        }
        out.fill(0xa5);
        assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::InvalidData));
        assert_eq!(out, [0xa5; 16]);
        backend.enabled = false;
        let samples = backend.samples;
        assert_eq!(run(dispatch(&req, &mut backend)), Err(FsError::NotFound));
        assert_eq!(backend.samples, samples);
        backend.enabled = true;
        // A reported off/idle zero is a value; missing data stays an error.
        if sensor == 6 {
            backend.soc_voltage = Some(0);
        } else {
            backend.input_power = Some(0);
        }
        assert_eq!(run(dispatch(&req, &mut backend)), Ok(0));
        assert_eq!(&out[..4], &[0; 4]);
        assert_eq!(&out[4..], &[0xa5; 12]);
    }
    assert_eq!(latest_power_w(0), Some(0));
    assert_eq!(latest_power_w(287), Some(287));
    assert_eq!(latest_power_w(u16::MAX), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/stats",
    stats_soc_voltage_and_input_power_are_fresh_and_optional
);
