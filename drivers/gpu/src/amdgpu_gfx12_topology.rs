//! Read GC12 harvesting under exclusive GRBM index ownership, and the
//! address configuration userspace asks for (`GB_ADDR_CONFIG`).
//! Source: Linux gfx_v12_0_get_cu_info, gfx_v12_0_setup_rb,
//! gfx_v12_0_gpu_early_init and GC12 headers.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    Readback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topology {
    pub active_cus: u32,
    /// Linux DRM layout: SE0..3 occupy columns 0/1, SE4..7 columns 2/3.
    pub cu_bitmap: [[u32; 4]; 4],
    pub active_arrays: u16,
    pub enabled_rb_mask: u32,
    /// `GB_ADDR_CONFIG` as gfx_v12_0_gpu_early_init reads it, which
    /// `AMDGPU_INFO_READ_MMR_REG` hands Mesa.
    pub gb_addr_config: u32,
}
#[derive(Clone, Copy)]
struct Limits {
    engines: u32,
    arrays: u32,
    cus: u32,
    rbs_per_array: u32,
}
impl Limits {
    fn from_gc(gc: ip::GcInfo) -> Result<Self, Error> {
        if !(1..=8).contains(&gc.num_se)
            || !(1..=2).contains(&gc.num_sa_per_se)
            || !(2..=32).contains(&gc.num_cu_per_sa)
            || gc.num_cu_per_sa % 2 != 0
            || gc.num_rb_per_se == 0
            || gc.num_rb_per_se > 32 / gc.num_se
            || gc.num_rb_per_se % gc.num_sa_per_se != 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            engines: gc.num_se,
            arrays: gc.num_sa_per_se,
            cus: gc.num_cu_per_sa,
            rbs_per_array: gc.num_rb_per_se / gc.num_sa_per_se,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
}
struct Mmio(narf_bus::MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: the constructor bounds both GC banks and invokes live authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: sole GRBM owner; only the bounded index register is written.
        unsafe { self.0.write32(address, value) };
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
fn sample(io: &mut impl Io, bases: [u64; 2], limits: Limits) -> Result<Topology, Error> {
    let [gc, hyp] = bases;
    let index = hyp + 0x2200 * 4;
    let prior = checked(io.read(index))?;
    let gb_addr_config = checked(io.read(gc + 0x13de * 4))?;
    let result = (|| {
        let disabled =
            (checked(io.read(gc + 0xfe9 * 4))? | checked(io.read(hyp + 0x5b92 * 4))?) >> 8 & 0xffff;
        let arrays = ((1u32 << (limits.engines * limits.arrays)) - 1) & !disabled;
        let disabled_rbs =
            (checked(io.read(gc + 0x13dd * 4))? | checked(io.read(hyp + 0x5b94 * 4))?) >> 4 & 0xf;
        let mut enabled_rb_mask = 0;
        let rb_mask_per_array = u32::MAX >> (32 - limits.rbs_per_array);
        for array in 0..limits.engines * limits.arrays {
            if arrays & (1 << array) != 0 {
                enabled_rb_mask |= rb_mask_per_array << (array * limits.rbs_per_array);
            }
        }
        enabled_rb_mask &= !disabled_rbs;
        let mut topology = Topology {
            active_cus: 0,
            cu_bitmap: [[0; 4]; 4],
            active_arrays: arrays as u16,
            enabled_rb_mask,
            gb_addr_config,
        };
        for se in 0..limits.engines {
            for sa in 0..limits.arrays {
                if arrays & (1 << (se * limits.arrays + sa)) == 0 {
                    continue;
                }
                let selector = (1 << 30) | (se << 16) | (sa << 8);
                io.write(index, selector);
                if checked(io.read(index))? != selector {
                    return Err(Error::Readback);
                }
                let inactive = (checked(io.read(gc + 0x100f * 4))?
                    | checked(io.read(hyp + 0x5b90 * 4))?)
                    >> 16;
                let mut bitmap = 0;
                for wgp in 0..limits.cus / 2 {
                    if inactive & (1 << wgp) == 0 {
                        bitmap |= 3 << (wgp * 2);
                    }
                }
                topology.cu_bitmap[(se % 4) as usize][(sa + (se / 4) * 2) as usize] = bitmap;
                topology.active_cus += bitmap.count_ones();
            }
        }
        if topology.active_cus == 0 {
            Err(Error::Invalid)
        } else {
            Ok(topology)
        }
    })();
    // No await/early return may leave the shared selector changed. Restore
    // even on a failed fuse read while this one capability operation owns it.
    io.write(index, prior);
    let restored = checked(io.read(index))?;
    if restored != prior {
        return Err(Error::Readback);
    }
    result
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
/// # Safety
/// Physical Navi48's firmware and protected boot power must be ready. Caller
/// owns GRBM indexing, GC and permanent register mappings exclusively, with
/// no concurrent queue setup, reset, harvesting override or power transition.
/// Reads both fused and inherited software disable masks; never changes them.
pub unsafe fn read(gpu: &AmdGpu, authority: &Cap<BusDeviceCap, Write>) -> Result<Topology, Error> {
    let (limits, bases) = layout(gpu)?;
    authority
        .invoke(Op(|| sample(&mut Mmio(gpu.regs), bases, limits)))
        .map_err(|_| Error::Revoked)?
}
pub(crate) fn validate(gpu: &AmdGpu) -> Result<(), Error> {
    layout(gpu).map(|_| ())
}
fn layout(gpu: &AmdGpu) -> Result<(Limits, [u64; 2]), Error> {
    if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI48 {
        return Err(Error::Unsupported);
    }
    let limits = Limits::from_gc(gpu.gc_info.ok_or(Error::Invalid)?)?;
    let bases = [
        bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x13de),
        bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 1, 0x5b94),
    ]
    .map(|b| b.map_err(|_| Error::Unsupported));
    let bases = [bases[0]?, bases[1]?];
    Ok((limits, bases))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Fake {
        index: u32,
        writes: Vec<(u64, u32)>,
        fail: bool,
        arrays: [u32; 2],
        wgps: [[u32; 2]; 16],
        rbs: [u32; 2],
    }
    impl Io for Fake {
        fn read(&mut self, a: u64) -> u32 {
            match a {
                0x18800 => self.index,
                0x13fa4 => self.arrays[0],
                0x26e48 => self.arrays[1],
                0x14f74 => self.rbs[0],
                0x14f78 => 0x2644_2043,
                0x26e50 => self.rbs[1],
                0x1403c | 0x26e40 => {
                    if self.fail {
                        return u32::MAX;
                    }
                    let i = ((self.index >> 16) & 0xf) * 2 + ((self.index >> 8) & 3);
                    self.wgps[i as usize][usize::from(a == 0x26e40)]
                }
                _ => panic!("GC12 topology used incorrect bank/register"),
            }
        }
        fn write(&mut self, a: u64, v: u32) {
            assert_eq!(a, 0x18800);
            self.writes.push((a, v));
            self.index = v;
        }
    }
    fn fake() -> Fake {
        Fake {
            index: 0xe0000000,
            writes: Vec::new(),
            fail: false,
            arrays: [0; 2],
            wgps: [[0; 2]; 16],
            rbs: [0; 2],
        }
    }
    fn gfx12_topology_counts_fused_and_user_harvesting() -> TestResult {
        let mut f = fake();
        f.arrays = [1 << 8, 1 << 9];
        f.wgps[11] = [1 << 16, 1 << 17];
        f.wgps[15] = [1 << 17, 0];
        f.rbs = [1 << 6, 1 << 7];
        let t = sample(
            &mut f,
            [0x10000, 0x10000],
            Limits {
                engines: 8,
                arrays: 2,
                cus: 8,
                rbs_per_array: 1,
            },
        )
        .unwrap();
        if t.active_cus != 106
            || t.gb_addr_config != 0x2644_2043
            || t.active_arrays != 0xfffc
            || t.enabled_rb_mask != 0xfff0
            || t.cu_bitmap[0][0] != 0
            || t.cu_bitmap[1][3] != 0xf0
            || t.cu_bitmap[3][3] != 0xf3
            || f.index != 0xe0000000
            || f.writes.len() != 15
        {
            return TestResult::Fail(
                "GC12 fuse/user masks, DRM bitmap packing or selector restoration",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        gfx12_topology_counts_fused_and_user_harvesting
    );
    fn gfx12_topology_errors_restore_selector_and_validate_dimensions() -> TestResult {
        let limits = Limits {
            engines: 4,
            arrays: 2,
            cus: 8,
            rbs_per_array: 2,
        };
        let mut f = fake();
        f.fail = true;
        if sample(&mut f, [0x10000, 0x10000], limits) != Err(Error::DeviceGone)
            || f.index != 0xe0000000
        {
            return TestResult::Fail("failed harvesting left selector changed");
        }
        let mut f = fake();
        f.arrays[0] = 0xff00;
        if sample(&mut f, [0x10000, 0x10000], limits) != Err(Error::Invalid) || f.writes.len() != 1
        {
            return TestResult::Fail("disabled arrays read or all-disabled GPU accepted");
        }
        for (engines, arrays, cus) in [
            (0, 2, 8),
            (9, 2, 8),
            (4, 0, 8),
            (4, 3, 8),
            (4, 2, 0),
            (4, 2, 7),
            (4, 2, 34),
        ] {
            if Limits::from_gc(ip::GcInfo {
                num_se: engines,
                num_sa_per_se: arrays,
                num_cu_per_sa: cus,
                num_rb_per_se: 4,
                ..Default::default()
            })
            .is_ok()
            {
                return TestResult::Fail("unsupported topology dimensions accepted");
            }
        }
        let mut g = crate::amdgpu_navi48_firmware::tests::gpu();
        g.ip_blocks[0].num_bases = 2;
        g.regs.len = 0x20000;
        g.gc_info = Some(ip::GcInfo {
            num_se: 4,
            num_sa_per_se: 2,
            num_cu_per_sa: 8,
            num_rb_per_se: 4,
            ..Default::default()
        });
        let cap = Cap::bootstrap();
        cap.revoke();
        // SAFETY: revoked authority must refuse before dereferencing null MMIO.
        if unsafe { read(&g, &cap) } != Err(Error::Revoked) {
            return TestResult::Fail("revoked topology sampled MMIO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        gfx12_topology_errors_restore_selector_and_validate_dimensions
    );
}
