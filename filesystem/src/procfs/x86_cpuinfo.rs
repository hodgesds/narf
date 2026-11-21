//! CPU-local CPUID state for Linux /proc/cpuinfo consumers.

use alloc::string::String;
use core::fmt::Write;
use narf_arch::x86_64::{cpuid::cpuid, ident, xsave::read_xcr0};
use narf_lib::{percpu, sync::IrqSafeSpinLock};

#[derive(Clone, Copy)]
pub(super) struct CpuInfo {
    pub(super) id: ident::CpuId,
    max_basic: u32,
    leaf1_edx: u32,
    leaf1_ecx: u32,
    leaf7_ebx: u32,
    ext_edx: u32,
    ext_ecx: u32,
    address_sizes: u32,
    clflush_bytes: u32,
    avx_usable: bool,
}

static INFO: [IrqSafeSpinLock<Option<CpuInfo>>; percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; percpu::MAX_CPUS];

/// Called by the pinned CPU telemetry worker, including on CPUs without
/// frequency counters. The slot lock keeps all reads on the same CPU.
pub fn record_current_cpu_info() {
    narf_lib::sync::without_interrupts(|| {
        let Some(slot) = INFO.get(percpu::current_cpu()) else {
            return;
        };
        let mut slot = slot.lock();
        if slot.is_some() {
            return;
        }
        // SAFETY: x86-64 provides leaf 1; optional leaves are bounded by
        // their respective maxima. XGETBV additionally requires OSXSAVE.
        let sample = unsafe {
            let max_basic = cpuid(0, 0).0;
            let (_, ebx, ecx, edx) = cpuid(1, 0);
            let max_ext = cpuid(0x8000_0000, 0).0;
            let (_, _, ext_ecx, ext_edx) = if max_ext >= 0x8000_0001 {
                cpuid(0x8000_0001, 0)
            } else {
                (0, 0, 0, 0)
            };
            CpuInfo {
                id: ident::read(),
                max_basic,
                leaf1_edx: edx,
                leaf1_ecx: ecx,
                leaf7_ebx: if max_basic >= 7 { cpuid(7, 0).1 } else { 0 },
                ext_edx,
                ext_ecx,
                address_sizes: if max_ext >= 0x8000_0008 {
                    cpuid(0x8000_0008, 0).0
                } else {
                    0
                },
                clflush_bytes: if edx & (1 << 19) != 0 {
                    ((ebx >> 8) & 255) * 8
                } else {
                    0
                },
                avx_usable: ecx & (1 << 28) != 0 && ecx & (1 << 27) != 0 && read_xcr0() & 6 == 6,
            }
        };
        *slot = Some(sample);
    });
}

pub(super) fn get(cpu: u32) -> Option<CpuInfo> {
    *INFO.get(cpu as usize)?.lock()
}

impl CpuInfo {
    pub(super) fn write_fields(&self, out: &mut String) {
        let _ = writeln!(out, "cpuid level\t: {}", self.max_basic);
        let phys = self.address_sizes & 255;
        let virt = (self.address_sizes >> 8) & 255;
        if phys != 0 && virt != 0 {
            let _ = writeln!(
                out,
                "address sizes\t: {phys} bits physical, {virt} bits virtual"
            );
        }
        if self.clflush_bytes != 0 {
            let _ = writeln!(out, "clflush size\t: {}", self.clflush_bytes);
        }
        // Linux arch/x86/include/asm/cpufeatures.h spellings. Flags that
        // depend on YMM state also require the OS to save and restore it.
        out.push_str("flags\t\t:");
        let mut flags = |bits: u32, names: &[(u8, &str)]| {
            for &(bit, name) in names {
                if bits & (1 << bit) != 0 {
                    out.push(' ');
                    out.push_str(name);
                }
            }
        };
        flags(
            self.leaf1_edx,
            &[
                (0, "fpu"),
                (3, "pse"),
                (4, "tsc"),
                (5, "msr"),
                (6, "pae"),
                (8, "cx8"),
                (9, "apic"),
                (13, "pge"),
                (15, "cmov"),
                (19, "clflush"),
                (23, "mmx"),
                (24, "fxsr"),
                (25, "sse"),
                (26, "sse2"),
                (28, "ht"),
            ],
        );
        flags(self.ext_edx, &[(20, "nx"), (27, "rdtscp"), (29, "lm")]);
        flags(
            self.leaf1_ecx,
            &[
                (0, "pni"),
                (1, "pclmulqdq"),
                (5, "vmx"),
                (9, "ssse3"),
                (13, "cx16"),
                (19, "sse4_1"),
                (20, "sse4_2"),
                (22, "movbe"),
                (23, "popcnt"),
                (25, "aes"),
                (30, "rdrand"),
                (31, "hypervisor"),
            ],
        );
        flags(self.ext_ecx, &[(0, "lahf_lm"), (2, "svm")]);
        flags(
            self.leaf7_ebx,
            &[
                (3, "bmi1"),
                (8, "bmi2"),
                (9, "erms"),
                (18, "rdseed"),
                (19, "adx"),
                (29, "sha_ni"),
            ],
        );
        if self.avx_usable {
            flags(self.leaf1_ecx, &[(12, "fma"), (28, "avx"), (29, "f16c")]);
            flags(self.leaf7_ebx, &[(5, "avx2")]);
        }
        out.push('\n');
    }
}

fn smoke_lscpu_cpuid_fields() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let mut sample = CpuInfo {
        id: ident::read(),
        max_basic: 31,
        leaf1_edx: 1 << 26,
        leaf1_ecx: (1 << 5) | (1 << 28),
        leaf7_ebx: 1 << 5,
        ext_edx: 1 << 29,
        ext_ecx: 0,
        address_sizes: (48 << 8) | 39,
        clflush_bytes: 64,
        avx_usable: false,
    };
    let mut out = String::new();
    sample.write_fields(&mut out);
    if !out.contains("address sizes\t: 39 bits physical, 48 bits virtual\n")
        || !out.contains("flags\t\t: sse2 lm vmx\n")
        || !out.contains("clflush size\t: 64\n")
    {
        return TestResult::Fail("lscpu CPUID feature or address-size decoding is wrong");
    }
    sample.avx_usable = true;
    sample.address_sizes = 0;
    out.clear();
    sample.write_fields(&mut out);
    if out.contains("address sizes") || !out.contains(" avx avx2\n") {
        return TestResult::Fail(
            "extended flags or missing address-width leaf handled incorrectly",
        );
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("filesystem/procfs/lscpu", smoke_lscpu_cpuid_fields);
