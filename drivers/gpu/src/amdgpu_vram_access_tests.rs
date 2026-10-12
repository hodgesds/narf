use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Device {
    aperture: u64,
    registers: u64,
    index: u32,
    high: u32,
    reads: Vec<u64>,
    writes: Vec<(u64, u32)>,
    direct: usize,
    register_reads: usize,
    image: Option<(u64, Vec<u8>)>,
}

impl Device {
    fn new(aperture: u64) -> Self {
        Self {
            aperture,
            registers: 0x100,
            index: 0x1234,
            high: 0xdead_beef,
            reads: Vec::new(),
            writes: Vec::new(),
            direct: 0,
            register_reads: 0,
            image: None,
        }
    }
    fn word(&mut self, offset: u64) -> u32 {
        self.reads.push(offset);
        if let Some((base, image)) = &self.image {
            let start = offset
                .checked_sub(*base)
                .expect("read below discovery image") as usize;
            return image
                .get(start..start + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
        }
        offset as u32 ^ (offset >> 32) as u32
    }
}

impl ReadIo for Device {
    fn aperture_len(&self) -> u64 {
        self.aperture
    }
    fn registers_len(&self) -> u64 {
        self.registers
    }
    fn read_aperture(&mut self, offset: u64) -> u32 {
        assert!(offset + 4 <= self.aperture);
        self.direct += 1;
        self.word(offset)
    }
    fn read_register(&mut self, offset: u64) -> u32 {
        assert!(offset + 4 <= self.registers);
        self.register_reads += 1;
        match offset {
            0 => self.index,
            0x18 => self.high,
            4 => {
                assert_ne!(self.index & 0x8000_0000, 0, "VRAM selector missing");
                // Hardware model: 31 low address bits plus the high latch.
                let pos = u64::from(self.index & 0x7fff_ffff) | (u64::from(self.high) << 31);
                self.word(pos)
            }
            _ => panic!("wrong register port"),
        }
    }
    fn write_register(&mut self, offset: u64, value: u32) {
        assert!(offset + 4 <= self.registers);
        self.writes.push((offset, value));
        match offset {
            0 => self.index = value,
            0x18 => self.high = value,
            _ => panic!("reader must never write the data port"),
        }
    }
}

fn vram_read_handles_aperture_edge() -> TestResult {
    let mut io = Device::new(8);
    let mut out = [0; 12];
    if read(&mut io, 32, 4, &mut out).is_err()
        || out != [4, 0, 0, 0, 8, 0, 0, 0, 12, 0, 0, 0]
        || io.reads != [4, 8, 12]
        || io.direct != 1
        || io.writes
            != [
                (0, 0x8000_0008),
                (0x18, 0),
                (0, 0x8000_000c),
                (0x18, 0xdead_beef),
                (0, 0x1234),
            ]
    {
        return TestResult::Fail("aperture boundary, indexed sequence, or latch restoration");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/pcie", vram_read_handles_aperture_edge);

fn vram_read_handles_high_address_carry() -> TestResult {
    for boundary in [1u64 << 31, 1u64 << 32, 12u64 << 30] {
        let mut io = Device::new(256 << 20);
        let mut out = [0; 8];
        let start = boundary - 4;
        if read(&mut io, boundary + 4, start, &mut out).is_err()
            || io.reads != [start, boundary]
            || io.direct != 0
            || io.high != 0xdead_beef
            || io.index != 0x1234
        {
            return TestResult::Fail("VRAM high address carry truncated or stale latch");
        }
        for (chunk, pos) in out.chunks_exact(4).zip([start, boundary]) {
            if u32::from_le_bytes(chunk.try_into().unwrap()) != pos as u32 ^ (pos >> 32) as u32 {
                return TestResult::Fail("high-address read returned the wrong data");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pcie",
    vram_read_handles_high_address_carry
);

fn vram_read_rebar_never_touches_index() -> TestResult {
    // Power-of-two BAR can be larger than the fitted 12 GiB of memory.
    let mut io = Device::new(16 << 30);
    io.registers = 0;
    let pos = (12 << 30) - 4;
    let mut out = [0; 4];
    if read(&mut io, 12 << 30, pos, &mut out).is_err()
        || io.reads != [pos]
        || io.direct != 1
        || !io.writes.is_empty()
        || io.register_reads != 0
    {
        return TestResult::Fail("fully mapped VRAM must use BAR0 only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pcie",
    vram_read_rebar_never_touches_index
);

fn vram_read_rejects_before_io() -> TestResult {
    for (size, offset, len, expected) in [
        (16, 2, 4, Error::Unaligned),
        (16, 0, 3, Error::Unaligned),
        (16, 12, 8, Error::OutOfRange),
        (0, 0, 4, Error::OutOfRange),
        (u64::MAX, u64::MAX - 3, 8, Error::OutOfRange),
        (u64::MAX, 1 << 63, 4, Error::OutOfRange),
    ] {
        let mut io = Device::new(16);
        let mut out = vec![0xaa; len];
        if read(&mut io, size, offset, &mut out) != Err(expected)
            || out.iter().any(|b| *b != 0xaa)
            || !io.reads.is_empty()
            || !io.writes.is_empty()
            || io.register_reads != 0
        {
            return TestResult::Fail("invalid read had side effects");
        }
    }
    // A partially direct read must also be rejected before its first byte
    // if the indexed tail cannot be read safely.
    let mut io = Device::new(4);
    io.registers = 0x18;
    let mut out = [0xaa; 8];
    if read(&mut io, 8, 0, &mut out) != Err(Error::RegisterWindowTooSmall)
        || out != [0xaa; 8]
        || !io.reads.is_empty()
        || io.register_reads != 0
    {
        return TestResult::Fail("short BAR5 allowed a partial read");
    }
    if read(&mut io, 0, 0, &mut []).is_err() || io.register_reads != 0 {
        return TestResult::Fail("empty read accessed the device");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/pcie", vram_read_rejects_before_io);

#[cfg(target_arch = "x86_64")]
fn pcie_discovery_reaches_vram_tail() -> TestResult {
    use crate::amdgpu_discovery as d;
    let (blob, mp0, gc) = crate::tests::build_synthetic_discovery_blob();
    let size = 12u64 << 30;
    for aperture in [256 << 20, 16 << 30] {
        let mut io = Device::new(aperture);
        io.image = Some((size - 65536, blob.clone()));
        let (blocks, _) = crate::amdgpu::read_discovery(&mut io, size);
        if d::find_ip(&blocks, d::HW_ID_GC, 0).map(|b| b.base_addrs[0]) != Some(gc)
            || d::find_ip(&blocks, d::HW_ID_MP0, 0).map(|b| b.base_addrs[0]) != Some(mp0)
            || io.reads.len() != 10240 / 4
            || io.reads[0] != size - 65536
            || (io.direct != 0) != (aperture >= size)
        {
            return TestResult::Fail("discovery did not parse the physical VRAM tail");
        }
        io.image.as_mut().unwrap().1[0] ^= 1;
        if !crate::amdgpu::read_discovery(&mut io, size).0.is_empty() {
            return TestResult::Fail("corrupt indexed discovery was accepted");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers/gpu/amdgpu/pcie", pcie_discovery_reaches_vram_tail);

fn pcie_probe_reports_memory_and_identity() -> TestResult {
    use crate::amdgpu::{self, AmdGpu, AMD_VENDOR, NAVI22};
    use crate::amdgpu_discovery::{GcInfo, IpBlock, HW_ID_GC, MAX_BASE_ADDRS};
    use crate::amdgpu_info::{query_against, Snapshot};
    use crate::amdgpu_uapi as u;
    use narf_bus::BarKind;
    use narf_memory::PhysAddr;

    // Ordinary RAM models the direct register window. Put decoys at MM_DATA
    // and at the unscaled register ID to catch either wrong access method.
    let mut words = vec![0u32; 0x4000 / 4];
    words[1] = 1;
    words[0x0de3] = 12288;
    let regs = MmioRegion {
        phys: PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x4000,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    for aperture in [256u64 << 20, 12 << 30, 16 << 30] {
        // BAR0 need not be backed: sizing must never dereference it.
        let fb_bar = MmioRegion {
            phys: PhysAddr::new(0x8000_0000),
            virt: 0,
            len: aperture,
            kind: BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: the register mapping is backed by words for this call;
        // sizing only reads BAR5 and uses BAR0's address and length as data.
        let vram = unsafe { amdgpu::read_vram_info(&regs, &fb_bar) };
        if vram.size != 12 << 30
            || vram.visible_size != aperture.min(12 << 30)
            || vram.base != 0x8000_0000
        {
            return TestResult::Fail(
                "VRAM sizing did not respect the direct register or BAR limit",
            );
        }
        let mut gpu = AmdGpu {
            regs,
            fb_bar,
            vram,
            chip: amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, NAVI22).unwrap(),
            mode: None,
            fw_loaded: false,
            vbios: None,
            gc_info: Some(GcInfo {
                num_se: 2,
                num_sa_per_se: 2,
                num_cu_per_sa: 10,
                wave_size: 32,
                ..GcInfo::default()
            }),
            ip_blocks: vec![IpBlock {
                hw_id: HW_ID_GC,
                instance: 0,
                major: 10,
                minor: 3,
                revision: 2,
                sub_revision: 0,
                variant: 0,
                base_addrs: [0; MAX_BASE_ADDRS],
                num_bases: 1,
            }],
        };
        let snap = Snapshot::from_gpu(&gpu);
        if snap.is_apu || snap.visible_vram_size != aperture.min(12 << 30) {
            return TestResult::Fail("ReBAR changed discrete identity or visible VRAM");
        }
        let reply = query_against(&snap, u::AMDGPU_INFO_DEV_INFO, [0; 4]).unwrap();
        // SAFETY: a complete repr(C) POD reply, copied without alignment assumptions.
        let dev =
            unsafe { core::ptr::read_unaligned(reply.as_ptr().cast::<u::DrmAmdgpuInfoDevice>()) };
        if dev.family != u::AMDGPU_FAMILY_NV
            || dev.ids_flags != 0
            || dev.device_id != 0x73df
            || dev.num_hw_gfx_contexts != 8
        {
            return TestResult::Fail("Navi 22 DEV_INFO family or FUSION flag");
        }
        gpu.ip_blocks[0].revision = 6; // Rembrandt cannot use Navi 22's UAPI family.
        if query_against(&Snapshot::from_gpu(&gpu), u::AMDGPU_INFO_DEV_INFO, [0; 4]).is_ok() {
            return TestResult::Fail("unsupported GC version got Navi 22 DEV_INFO");
        }
        gpu.ip_blocks.clear();
        if gpu.is_apu() || Snapshot::from_gpu(&gpu).is_apu {
            return TestResult::Fail("missing discovery made a discrete card an APU");
        }
        if query_against(&Snapshot::from_gpu(&gpu), u::AMDGPU_INFO_DEV_INFO, [0; 4]).is_ok() {
            return TestResult::Fail("missing discovery claimed Navi 22 DEV_INFO");
        }
        for did in [
            amdgpu::PHOENIX1,
            amdgpu::RENOIR,
            amdgpu::REMBRANDT,
            amdgpu::RAPHAEL,
        ] {
            gpu.chip = amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, did).unwrap();
            if !Snapshot::from_gpu(&gpu).is_apu {
                return TestResult::Fail("small BAR lost the APU identity fallback");
            }
        }
    }
    // Missing devices cannot acquire a visible heap from an allocated BAR.
    for value in [0, u32::MAX] {
        words[0x0de3] = value;
        // SAFETY: both references point to the owned register buffer; only
        // BAR5 is read and BAR0's fields are inspected.
        let vram = unsafe { amdgpu::read_vram_info(&regs, &regs) };
        if vram.size != 0 || vram.visible_size != 0 || vram.fully_visible() {
            return TestResult::Fail("missing VRAM was reported as visible");
        }
    }
    let short = MmioRegion {
        len: 0x0de3 * 4,
        ..regs
    };
    // SAFETY: short is a prefix of the same owned buffer.
    if unsafe { amdgpu::read_vram_info(&short, &regs) }.size != 0 {
        return TestResult::Fail("short register BAR was accepted for sizing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/pcie",
    pcie_probe_reports_memory_and_identity
);
