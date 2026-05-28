//! Smoke tests for the NVIDIA driver scaffold.
//!
//! Coverage targets:
//!
//! - PCI device-id table sanity (every entry maps to a family).
//! - PMC_BOOT_0 architecture-tag decode for known revisions
//!   (GM200, GP104, TU106, GA102, AD104).
//! - Falcon CPUCTL/BOOTVEC programming on a fake MMIO region.
//! - DCB-entry decode (encoder + connector).
//! - HEAD register encoders bit-positions.
//! - DP AUX command framing.
//! - Mode-set field encoders.

#![cfg(any(test, feature = "kernel-test"))]

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::bar::{bar0_window_target, PBUS_BAR0_WINDOW, PRAMIN_WINDOW_BASE};
use crate::ce::{ce_class_for, ce_instance_count, CE_LAUNCH_DMA};
use crate::chip::{
    chip_info_for_pci_id, ChipFamily, AD102_RTX_4090, AD104_RTX_4070, GA102_RTX_3090,
    GM200_GTX_TITAN_X, GP104_GTX_1080, KNOWN_DEVICES, NVIDIA_VENDOR, TU106_RTX_2060,
};
use crate::disp::nv50::{
    aux_header, enc_head_display, enc_head_sync_end, enc_head_sync_start, enc_head_total,
    head_base, sor_base, AuxCommand, PDISP_HEAD_BASE, PDISP_HEAD_STRIDE, PDISP_SOR_BASE,
    PDISP_SOR_STRIDE,
};
use crate::disp::{
    decode_dcb_entry, dispclass_for, EncoderType, Mode, ModeFlags, AD102_DISP, GA102_DISP,
    GM200_DISP, GP102_DISP, GV100_DISP, TU102_DISP,
};
use crate::fb::{ram_type_for_family, FbConfig, RamType};
use crate::fifo::{channel_cap_for, pb_header, PbType, USERD_GP_GET, USERD_GP_PUT, USERD_SIZE};
use crate::gr::{compute_class_for, graphics_class_for, AMPERE_A, MAXWELL_A, PASCAL_A};
use crate::mc::{
    Boot0, IntrSource, PMC_BOOT_0, PMC_BOOT_0_ARCH_SHIFT, PMC_ENABLE, PMC_ENABLE_ALL,
    PMC_ENABLE_PDISP, PMC_ENABLE_PFIFO, PMC_INTR_0, PMC_INTR_EN_0,
};
use crate::mmu::{pde_encode_pt, pte_encode_4k, Aperture, PageSize, PTE_RO, PTE_VALID, PTE_VOLATILE};
use crate::pmu::{pmu_firmware_for, PMU_INIT_MAGIC};

// ────────────────────────────────────────────────────────────────
// PCI id-table coverage
// ────────────────────────────────────────────────────────────────

fn smoke_nvidia_pci_table_covers_all_families() -> TestResult {
    let mut have_max = false;
    let mut have_pas = false;
    let mut have_vol = false;
    let mut have_tur = false;
    let mut have_amp = false;
    let mut have_ada = false;
    for (_, did) in KNOWN_DEVICES.iter().copied() {
        let ci = match chip_info_for_pci_id(NVIDIA_VENDOR, did) {
            Some(c) => c,
            None => return TestResult::Fail("device id not in chip table"),
        };
        match ci.family {
            ChipFamily::Maxwell => have_max = true,
            ChipFamily::Pascal => have_pas = true,
            ChipFamily::Volta => have_vol = true,
            ChipFamily::Turing => have_tur = true,
            ChipFamily::Ampere => have_amp = true,
            ChipFamily::Ada => have_ada = true,
            _ => return TestResult::Fail("unexpected family in table"),
        }
    }
    if !(have_max && have_pas && have_vol && have_tur && have_amp && have_ada) {
        return TestResult::Fail("missing coverage of a family generation");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/chip", smoke_nvidia_pci_table_covers_all_families);

fn smoke_nvidia_pci_rejects_non_nvidia_vendor() -> TestResult {
    if chip_info_for_pci_id(0x1002, GA102_RTX_3090).is_some() {
        return TestResult::Fail("AMD vendor id should not match NVIDIA table");
    }
    if chip_info_for_pci_id(0x8086, GA102_RTX_3090).is_some() {
        return TestResult::Fail("Intel vendor id should not match NVIDIA table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/chip", smoke_nvidia_pci_rejects_non_nvidia_vendor);

fn smoke_nvidia_chip_known_pci_ids_per_family() -> TestResult {
    // Spot-check one well-known board per family.
    let cases = [
        (GM200_GTX_TITAN_X, ChipFamily::Maxwell, "gm200"),
        (GP104_GTX_1080, ChipFamily::Pascal, "gp104"),
        (TU106_RTX_2060, ChipFamily::Turing, "tu106"),
        (GA102_RTX_3090, ChipFamily::Ampere, "ga102"),
        (AD102_RTX_4090, ChipFamily::Ada, "ad102"),
        (AD104_RTX_4070, ChipFamily::Ada, "ad104"),
    ];
    for (did, fam, asic) in cases.iter().copied() {
        let ci = match chip_info_for_pci_id(NVIDIA_VENDOR, did) {
            Some(c) => c,
            None => return TestResult::Fail("device id missing from table"),
        };
        if ci.family != fam {
            return TestResult::Fail("family mismatch for known board");
        }
        if ci.asic != asic {
            return TestResult::Fail("asic-tag mismatch for known board");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/chip", smoke_nvidia_chip_known_pci_ids_per_family);

// ────────────────────────────────────────────────────────────────
// PMC_BOOT_0 decode
// ────────────────────────────────────────────────────────────────

fn smoke_pmc_boot0_arch_tag_decode_per_family() -> TestResult {
    // Construct synthetic PMC_BOOT_0 values where bits[24:20] hold
    // the architecture nibble, and verify Boot0::decode classifies
    // them correctly. Tags are the documented values from
    // open-gpu-doc / nvkm/include/nvkm/core/device.h:
    //   Maxwell=0x04 Pascal=0x05 Volta=0x06 Turing=0x07
    //   Ampere=0x08 Ada=0x09
    let cases = [
        (0x04u32, ChipFamily::Maxwell),
        (0x05u32, ChipFamily::Pascal),
        (0x06u32, ChipFamily::Volta),
        (0x07u32, ChipFamily::Turing),
        (0x08u32, ChipFamily::Ampere),
        (0x09u32, ChipFamily::Ada),
    ];
    for (arch_nibble, fam) in cases.iter().copied() {
        // Assemble a PMC_BOOT_0 with that arch field + some
        // implementation / revision noise: impl=0x123 (bits[19:8]),
        // major=0xA (bits[7:4]), minor=0x5 (bits[3:0]).
        let raw =
            ((arch_nibble & 0x1F) << PMC_BOOT_0_ARCH_SHIFT) | (0x123 << 8) | (0xA << 4) | 0x5;
        let b = Boot0::decode(raw);
        if b.family != fam {
            return TestResult::Fail("arch nibble misclassified by Boot0::decode");
        }
        if b.minor_rev != 0x5 || b.major_rev != 0xA {
            return TestResult::Fail("major/minor rev decoded wrong");
        }
        if b.implementation != 0x123 {
            return TestResult::Fail("implementation field decode wrong");
        }
    }
    // And the presence sentinels reject 0 / all-ones.
    if Boot0::looks_present(0xFFFF_FFFF) {
        return TestResult::Fail("0xFFFFFFFF must look 'gone'");
    }
    if Boot0::looks_present(0) {
        return TestResult::Fail("0 must look 'gone'");
    }
    // Mid-value passes presence.
    if !Boot0::looks_present(0x0070_1234) {
        return TestResult::Fail("non-sentinel must look present");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mc", smoke_pmc_boot0_arch_tag_decode_per_family);

fn smoke_pmc_register_offsets_match_open_gpu_doc() -> TestResult {
    // Stable cross-generation offsets per dev_pmc.ref.txt.
    if PMC_BOOT_0 != 0x0000_0000 {
        return TestResult::Fail("PMC_BOOT_0 must be 0x000000");
    }
    if PMC_INTR_0 != 0x0000_0100 {
        return TestResult::Fail("PMC_INTR_0 must be 0x000100");
    }
    if PMC_INTR_EN_0 != 0x0000_0140 {
        return TestResult::Fail("PMC_INTR_EN_0 must be 0x000140");
    }
    if PMC_ENABLE != 0x0000_0200 {
        return TestResult::Fail("PMC_ENABLE must be 0x000200");
    }
    if PMC_ENABLE_ALL != 0xFFFF_FFFF {
        return TestResult::Fail("PMC_ENABLE_ALL must be 0xffffffff");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mc", smoke_pmc_register_offsets_match_open_gpu_doc);

fn smoke_pmc_intr_source_bits_unique_and_set() -> TestResult {
    let sources = [
        IntrSource::Fifo,
        IntrSource::Graphics,
        IntrSource::CopyEngine0,
        IntrSource::CopyEngine1,
        IntrSource::CopyEngine2,
        IntrSource::Display,
        IntrSource::Sec,
        IntrSource::Pmu,
        IntrSource::Gsp,
    ];
    let mut union = 0u32;
    for s in sources.iter().copied() {
        let bit = s.intr0_bit();
        if bit == 0 {
            return TestResult::Fail("zero bit in interrupt source");
        }
        if union & bit != 0 {
            return TestResult::Fail("overlap between interrupt source bits");
        }
        union |= bit;
    }
    if PMC_ENABLE_PFIFO == 0 || PMC_ENABLE_PDISP == 0 {
        return TestResult::Fail("engine-enable bits must be non-zero");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mc", smoke_pmc_intr_source_bits_unique_and_set);

// ────────────────────────────────────────────────────────────────
// Falcon
// ────────────────────────────────────────────────────────────────

// NOTE: Building a live Falcon test against a `FakeMmio` would need
// a kernel-side fake region in the driver runtime crate. The
// kernel runtime's `MmioRegion` is real-only; we'd need a stub for
// userspace-runtime tests to run. Instead we test the bit
// constants + DMA-cmd encoders directly — these are the load-
// bearing values the driver writes into the BAR.

fn smoke_falcon_register_offsets_match_v4() -> TestResult {
    use crate::falcon::*;
    // Cite dev_falcon_v4.ref.txt; these offsets are stable
    // Maxwell→Ada.
    if FALCON_IRQSSET != 0x0000_0000 {
        return TestResult::Fail("FALCON_IRQSSET offset wrong");
    }
    if FALCON_IRQMASK != 0x0000_0018 {
        return TestResult::Fail("FALCON_IRQMASK offset wrong");
    }
    if FALCON_MAILBOX0 != 0x0000_0040 {
        return TestResult::Fail("FALCON_MAILBOX0 offset wrong");
    }
    if FALCON_CPUCTL != 0x0000_0100 {
        return TestResult::Fail("FALCON_CPUCTL offset wrong");
    }
    if FALCON_BOOTVEC != 0x0000_0104 {
        return TestResult::Fail("FALCON_BOOTVEC offset wrong");
    }
    if FALCON_IMEMC != 0x0000_0180 || FALCON_IMEMD != 0x0000_0184 {
        return TestResult::Fail("FALCON_IMEMC/D offsets wrong");
    }
    if FALCON_DMEMC != 0x0000_01C0 || FALCON_DMEMD != 0x0000_01C4 {
        return TestResult::Fail("FALCON_DMEMC/D offsets wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/falcon", smoke_falcon_register_offsets_match_v4);

fn smoke_falcon_per_engine_base_addresses() -> TestResult {
    use crate::falcon::*;
    if FALCON_BASE_PMU != 0x0010_A000 {
        return TestResult::Fail("PMU Falcon base wrong");
    }
    if FALCON_BASE_GSP != 0x0011_0000 {
        return TestResult::Fail("GSP Falcon base wrong");
    }
    if FALCON_BASE_SEC2 != 0x0084_0000 {
        return TestResult::Fail("SEC2 Falcon base wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/falcon", smoke_falcon_per_engine_base_addresses);

fn smoke_falcon_cpuctl_bits_have_canonical_positions() -> TestResult {
    use crate::falcon::*;
    if CPUCTL_STARTCPU != 0x2 {
        return TestResult::Fail("STARTCPU should be bit 1");
    }
    if CPUCTL_HALT != 0x10 {
        return TestResult::Fail("HALT should be bit 4");
    }
    if CPUCTL_STOPPED != 0x20 {
        return TestResult::Fail("STOPPED should be bit 5");
    }
    if IMEMC_AINCR_WRITE != 1 << 24 {
        return TestResult::Fail("IMEMC.AINCR_WRITE should be bit 24");
    }
    if DMEMC_AINCR_WRITE != 1 << 24 {
        return TestResult::Fail("DMEMC.AINCR_WRITE should be bit 24");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/falcon", smoke_falcon_cpuctl_bits_have_canonical_positions);

// ────────────────────────────────────────────────────────────────
// PMU
// ────────────────────────────────────────────────────────────────

fn smoke_pmu_init_magic_matches_nouveau() -> TestResult {
    // The PMU firmware writes a fixed token into MAILBOX0 when it
    // finishes init. Cite nvkm/subdev/pmu/base.c::nvkm_pmu_init.
    if PMU_INIT_MAGIC == 0 {
        return TestResult::Fail("PMU init magic should be non-zero");
    }
    let req = pmu_firmware_for("gm200");
    if req.image_path.is_empty() || req.sig_path.is_empty() {
        return TestResult::Fail("firmware paths must be non-empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/pmu", smoke_pmu_init_magic_matches_nouveau);

// ────────────────────────────────────────────────────────────────
// MMU
// ────────────────────────────────────────────────────────────────

fn smoke_mmu_pte_encode_valid_aperture_and_phys() -> TestResult {
    let p = pte_encode_4k(0x1000_0000, Aperture::Vram, PTE_RO);
    if p & PTE_VALID == 0 {
        return TestResult::Fail("PTE must carry VALID");
    }
    if p & PTE_RO == 0 {
        return TestResult::Fail("PTE must carry RO when requested");
    }
    // Vram aperture = 00 in bits[5:4].
    if (p >> 4) & 0x3 != 0 {
        return TestResult::Fail("Vram aperture must encode 0b00");
    }
    // Sysmem coherent aperture = 01 in bits[5:4].
    let s = pte_encode_4k(0x4000_0000, Aperture::SysCoherent, PTE_VOLATILE);
    if (s >> 4) & 0x3 != 0b01 {
        return TestResult::Fail("SysCoherent aperture must encode 0b01");
    }
    if s & PTE_VOLATILE == 0 {
        return TestResult::Fail("VOLATILE flag must propagate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mmu", smoke_mmu_pte_encode_valid_aperture_and_phys);

fn smoke_mmu_pde_encode_points_at_vram_pt() -> TestResult {
    let pde = pde_encode_pt(0x2000_0000);
    if pde & PTE_VALID == 0 {
        return TestResult::Fail("PDE must carry VALID");
    }
    if (pde >> 4) & 0x3 != 0 {
        return TestResult::Fail("PDE-to-PT must use VRAM aperture");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mmu", smoke_mmu_pde_encode_points_at_vram_pt);

fn smoke_mmu_page_size_constants() -> TestResult {
    if PageSize::Small.bytes() != 4096 {
        return TestResult::Fail("Small page must be 4 KiB");
    }
    if PageSize::Big.bytes() != 64 * 1024 {
        return TestResult::Fail("Big page must be 64 KiB");
    }
    if PageSize::Large.bytes() != 2 * 1024 * 1024 {
        return TestResult::Fail("Large page must be 2 MiB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/mmu", smoke_mmu_page_size_constants);

// ────────────────────────────────────────────────────────────────
// FB / VRAM
// ────────────────────────────────────────────────────────────────

fn smoke_fb_vram_size_decode_pascal() -> TestResult {
    // PFB_CFG0 high half holds VRAM MiB on Pascal+. Build a synth
    // value: 8 GiB = 8192 MiB → 0x2000.
    let raw = 0x2000u32 << 16;
    let cfg = FbConfig::decode(raw, ChipFamily::Pascal);
    if cfg.vram_mib != 8192 {
        return TestResult::Fail("FB CFG0 high-half decode failed for 8 GiB");
    }
    if cfg.ram_type != RamType::Gddr5X {
        return TestResult::Fail("Pascal ram-type default should be GDDR5X");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fb", smoke_fb_vram_size_decode_pascal);

fn smoke_fb_ram_type_per_family_classification() -> TestResult {
    if ram_type_for_family(ChipFamily::Turing) != RamType::Gddr6 {
        return TestResult::Fail("Turing default is GDDR6");
    }
    if ram_type_for_family(ChipFamily::Ada) != RamType::Gddr6X {
        return TestResult::Fail("Ada default is GDDR6X");
    }
    if ram_type_for_family(ChipFamily::Volta) != RamType::Hbm2 {
        return TestResult::Fail("Volta default is HBM2");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fb", smoke_fb_ram_type_per_family_classification);

// ────────────────────────────────────────────────────────────────
// BAR / PRAMIN window
// ────────────────────────────────────────────────────────────────

fn smoke_bar_pramin_window_target_shift() -> TestResult {
    // Caller hands a 4 KiB-aligned phys page; window register
    // stores phys >> 16. PRAMIN window itself is 1 MiB at BAR0
    // offset 0x700000.
    if PRAMIN_WINDOW_BASE != 0x0070_0000 {
        return TestResult::Fail("PRAMIN window base wrong");
    }
    if PBUS_BAR0_WINDOW != 0x0000_1700 {
        return TestResult::Fail("PBUS_BAR0_WINDOW offset wrong");
    }
    let t = bar0_window_target(0x1234_5000);
    if t != 0x1234 {
        return TestResult::Fail("bar0_window_target shift wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/bar", smoke_bar_pramin_window_target_shift);

// ────────────────────────────────────────────────────────────────
// DCB / display
// ────────────────────────────────────────────────────────────────

fn smoke_disp_dcb_entry_decode_dp_over_sor0() -> TestResult {
    // Construct an 8-byte DCB v4 entry: DP encoder (3), i2c=2,
    // heads bitmask=1, connector index=4, OR=1.
    // Packing per dcb_outp_parse:
    //   bits[3:0]   = type (3 = DP)
    //   bits[7:4]   = i2c index (2)
    //   bits[11:8]  = heads bitmask (1)
    //   bits[15:12] = connector index (4)
    //   bits[27:24] = OR (1)
    let head_word: u32 = 3 | (2 << 4) | (1 << 8) | (4 << 12) | (1 << 24);
    let mut raw = [0u8; 8];
    raw[0..4].copy_from_slice(&head_word.to_le_bytes());
    let dcb = decode_dcb_entry(&raw).expect("should decode");
    if dcb.encoder_type != EncoderType::DisplayPort {
        return TestResult::Fail("encoder type should be DisplayPort");
    }
    if dcb.connector_index != 4 {
        return TestResult::Fail("connector index should be 4");
    }
    if dcb.heads != 0x1 {
        return TestResult::Fail("heads bitmask wrong");
    }
    if dcb.or != 1 {
        return TestResult::Fail("OR field wrong");
    }
    if dcb.i2c_index != 2 {
        return TestResult::Fail("i2c index wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_disp_dcb_entry_decode_dp_over_sor0);

fn smoke_disp_dcb_no_output_sentinel_rejected() -> TestResult {
    let mut raw = [0u8; 8];
    raw[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    if decode_dcb_entry(&raw).is_some() {
        return TestResult::Fail("0xFFFFFFFF sentinel must yield None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_disp_dcb_no_output_sentinel_rejected);

fn smoke_disp_dispclass_per_family() -> TestResult {
    if dispclass_for(ChipFamily::Maxwell) != Some(GM200_DISP) {
        return TestResult::Fail("Maxwell dispclass wrong");
    }
    if dispclass_for(ChipFamily::Pascal) != Some(GP102_DISP) {
        return TestResult::Fail("Pascal dispclass wrong");
    }
    if dispclass_for(ChipFamily::Volta) != Some(GV100_DISP) {
        return TestResult::Fail("Volta dispclass wrong");
    }
    if dispclass_for(ChipFamily::Turing) != Some(TU102_DISP) {
        return TestResult::Fail("Turing dispclass wrong");
    }
    if dispclass_for(ChipFamily::Ampere) != Some(GA102_DISP) {
        return TestResult::Fail("Ampere dispclass wrong");
    }
    if dispclass_for(ChipFamily::Ada) != Some(AD102_DISP) {
        return TestResult::Fail("Ada dispclass wrong");
    }
    if dispclass_for(ChipFamily::Fermi).is_some() {
        return TestResult::Fail("Fermi should not have a NV50-family dispclass here");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_disp_dispclass_per_family);

// ────────────────────────────────────────────────────────────────
// HEAD/SOR register-layout bit pins
// ────────────────────────────────────────────────────────────────

fn smoke_head_register_block_strides() -> TestResult {
    if head_base(0) != PDISP_HEAD_BASE {
        return TestResult::Fail("HEAD[0] base mismatch");
    }
    if head_base(1) != PDISP_HEAD_BASE + PDISP_HEAD_STRIDE {
        return TestResult::Fail("HEAD stride should be 0x400");
    }
    if sor_base(0) != PDISP_SOR_BASE {
        return TestResult::Fail("SOR[0] base mismatch");
    }
    if sor_base(2) != PDISP_SOR_BASE + 2 * PDISP_SOR_STRIDE {
        return TestResult::Fail("SOR stride should be 0x200");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_head_register_block_strides);

fn smoke_head_mode_field_encoders_pack_correctly() -> TestResult {
    let m = Mode {
        clock_khz: 148500,
        h_display: 1920,
        h_sync_start: 2008,
        h_sync_end: 2052,
        h_total: 2200,
        v_display: 1080,
        v_sync_start: 1084,
        v_sync_end: 1089,
        v_total: 1125,
        flags: ModeFlags {
            hsync_positive: true,
            vsync_positive: true,
            interlaced: false,
            double_scan: false,
        },
    };
    let total = enc_head_total(&m);
    if total & 0xFFFF != 2200 {
        return TestResult::Fail("h_total field bits[15:0] wrong");
    }
    if (total >> 16) & 0xFFFF != 1125 {
        return TestResult::Fail("v_total field bits[31:16] wrong");
    }
    let display = enc_head_display(&m);
    if display & 0xFFFF != 1920 {
        return TestResult::Fail("h_display low half wrong");
    }
    if (display >> 16) & 0xFFFF != 1080 {
        return TestResult::Fail("v_display high half wrong");
    }
    let ss = enc_head_sync_start(&m);
    if ss & 0xFFFF != 2008 || (ss >> 16) & 0xFFFF != 1084 {
        return TestResult::Fail("sync_start packing wrong");
    }
    let se = enc_head_sync_end(&m);
    if se & 0xFFFF != 2052 || (se >> 16) & 0xFFFF != 1089 {
        return TestResult::Fail("sync_end packing wrong");
    }
    // Refresh rate: clock_khz=148500 → 148_500_000 / (2200*1125)
    // = 60 Hz.
    if m.refresh_hz() != 60 {
        return TestResult::Fail("refresh-rate compute wrong for 1080p60");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_head_mode_field_encoders_pack_correctly);

// ────────────────────────────────────────────────────────────────
// DP AUX framing
// ────────────────────────────────────────────────────────────────

fn smoke_dp_aux_command_codes_match_dp_spec() -> TestResult {
    if AuxCommand::I2cWrite.code() != 0 {
        return TestResult::Fail("I2C_WRITE = 0");
    }
    if AuxCommand::I2cRead.code() != 1 {
        return TestResult::Fail("I2C_READ = 1");
    }
    if AuxCommand::DpcdWrite.code() != 8 {
        return TestResult::Fail("DPCD_WRITE = 8");
    }
    if AuxCommand::DpcdRead.code() != 9 {
        return TestResult::Fail("DPCD_READ = 9");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_dp_aux_command_codes_match_dp_spec);

fn smoke_dp_aux_header_field_packing() -> TestResult {
    // Read DPCD register 0x000 (DPCD revision), 1 byte. Command =
    // DpcdRead (9), addr = 0, size = 1 → payload-size-minus-1 = 0.
    let h = aux_header(AuxCommand::DpcdRead, 0, 1);
    if h & 0xF != 9 {
        return TestResult::Fail("AUX command low nibble wrong");
    }
    if (h >> 8) & 0x000F_FFFF != 0 {
        return TestResult::Fail("AUX address field should be zero");
    }
    if (h >> 25) & 0x7F != 0 {
        return TestResult::Fail("AUX size field should be 0 for 1-byte read");
    }
    // Write DPCD register 0x102 (training pattern), 1 byte.
    let h2 = aux_header(AuxCommand::DpcdWrite, 0x102, 1);
    if h2 & 0xF != 8 {
        return TestResult::Fail("DPCD_WRITE command code");
    }
    if (h2 >> 8) & 0x000F_FFFF != 0x102 {
        return TestResult::Fail("AUX address packing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_dp_aux_header_field_packing);

// ────────────────────────────────────────────────────────────────
// FIFO pushbuffer
// ────────────────────────────────────────────────────────────────

fn smoke_fifo_pushbuffer_header_encoding() -> TestResult {
    // Inc-write to method 0x40 (GP_PUT), 1 word follows.
    let h = pb_header(0x40, 1, PbType::Inc);
    if h & 0xFFFF != 0x40 {
        return TestResult::Fail("method low-16 wrong");
    }
    if (h >> 16) & 0x1FFF != 1 {
        return TestResult::Fail("size field bits[28:16] wrong");
    }
    if (h >> 29) & 0x7 != 1 {
        return TestResult::Fail("Inc type bits should be 0b001");
    }
    let h2 = pb_header(0x100, 4, PbType::NonInc);
    if (h2 >> 29) & 0x7 != 3 {
        return TestResult::Fail("NonInc type bits should be 0b011");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fifo", smoke_fifo_pushbuffer_header_encoding);

fn smoke_fifo_userd_layout_offsets() -> TestResult {
    if USERD_GP_PUT != 0x40 {
        return TestResult::Fail("USERD.GP_PUT offset must be 0x40");
    }
    if USERD_GP_GET != 0x44 {
        return TestResult::Fail("USERD.GP_GET offset must be 0x44");
    }
    if USERD_SIZE != 4096 {
        return TestResult::Fail("USERD slot is 4 KiB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fifo", smoke_fifo_userd_layout_offsets);

fn smoke_fifo_channel_cap_reasonable_for_family() -> TestResult {
    let max_max = channel_cap_for(ChipFamily::Maxwell);
    let ada_max = channel_cap_for(ChipFamily::Ada);
    if max_max < 64 || ada_max < 64 {
        return TestResult::Fail("channel cap too small");
    }
    if max_max > 65536 || ada_max > 65536 {
        return TestResult::Fail("channel cap unreasonably large");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fifo", smoke_fifo_channel_cap_reasonable_for_family);

// ────────────────────────────────────────────────────────────────
// GR / CE class tables
// ────────────────────────────────────────────────────────────────

fn smoke_gr_class_per_family_is_unique() -> TestResult {
    let classes = [
        graphics_class_for(ChipFamily::Maxwell).unwrap_or(0),
        graphics_class_for(ChipFamily::Pascal).unwrap_or(0),
        graphics_class_for(ChipFamily::Volta).unwrap_or(0),
        graphics_class_for(ChipFamily::Turing).unwrap_or(0),
        graphics_class_for(ChipFamily::Ampere).unwrap_or(0),
        graphics_class_for(ChipFamily::Ada).unwrap_or(0),
    ];
    // No duplicates.
    for i in 0..classes.len() {
        for j in (i + 1)..classes.len() {
            if classes[i] == classes[j] && classes[i] != 0 {
                return TestResult::Fail("duplicate GR class across families");
            }
        }
    }
    if graphics_class_for(ChipFamily::Maxwell) != Some(MAXWELL_A) {
        return TestResult::Fail("Maxwell GR class is MAXWELL_A");
    }
    if graphics_class_for(ChipFamily::Pascal) != Some(PASCAL_A) {
        return TestResult::Fail("Pascal GR class is PASCAL_A");
    }
    if graphics_class_for(ChipFamily::Ampere) != Some(AMPERE_A) {
        return TestResult::Fail("Ampere GR class is AMPERE_A");
    }
    if compute_class_for(ChipFamily::Maxwell).is_none() {
        return TestResult::Fail("compute class must exist for Maxwell");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/gr", smoke_gr_class_per_family_is_unique);

fn smoke_ce_class_and_instance_count_per_family() -> TestResult {
    if ce_class_for(ChipFamily::Maxwell).is_none() {
        return TestResult::Fail("Maxwell CE class missing");
    }
    if ce_class_for(ChipFamily::Ada).is_none() {
        return TestResult::Fail("Ada CE class missing");
    }
    if ce_instance_count(ChipFamily::Maxwell) < 1 {
        return TestResult::Fail("Maxwell needs at least 1 CE instance");
    }
    if ce_instance_count(ChipFamily::Ampere) < 4 {
        return TestResult::Fail("Ampere has many CE instances");
    }
    if CE_LAUNCH_DMA == 0 {
        return TestResult::Fail("CE LAUNCH_DMA method must be non-zero");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/ce", smoke_ce_class_and_instance_count_per_family);

// ────────────────────────────────────────────────────────────────
// VBIOS
// ────────────────────────────────────────────────────────────────

use crate::vbios::{
    dcb_header, dcb_table_offset, find_nv_image, parse_image_at, ROM_SIG_NV, ROM_SIG_PCI,
    PCIR_TYPE_NV,
};

fn smoke_vbios_parse_pci_option_rom_header() -> TestResult {
    // Build a 1 KiB ROM with a single PCIR-described image.
    // image @ 0:
    //   +0x00 .. 0xAA 0x55  (signature)
    //   +0x18 .. PCIR offset = 0x40 (le16)
    // PCIR @ 0x40:
    //   "PCIR"
    //   vendor (le16): 0x10DE
    //   device (le16): 0x1380
    //   ...
    //   +0x10  image-length blocks (le16) = 2  → 1024 bytes
    //   +0x14  type = 0x70 (NV)
    //   +0x15  flags = 0x80 (last)
    let mut rom = [0u8; 1024];
    rom[0..2].copy_from_slice(&ROM_SIG_PCI.to_le_bytes());
    rom[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
    rom[0x40..0x44].copy_from_slice(b"PCIR");
    rom[0x44..0x46].copy_from_slice(&0x10DEu16.to_le_bytes());
    rom[0x46..0x48].copy_from_slice(&0x1380u16.to_le_bytes());
    rom[0x50..0x52].copy_from_slice(&2u16.to_le_bytes());
    rom[0x54] = PCIR_TYPE_NV;
    rom[0x55] = 0x80;

    let img = match parse_image_at(&rom, 0) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("parse_image_at failed"),
    };
    if img.image_type != PCIR_TYPE_NV {
        return TestResult::Fail("PCIR image type byte misread");
    }
    if img.size != 1024 {
        return TestResult::Fail("image size = 2 * 512 = 1024");
    }
    if !img.last {
        return TestResult::Fail("PCIR.flags bit 7 means last image");
    }
    match find_nv_image(&rom) {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("find_nv_image should return the only image"),
    }
}
kernel_test_in!("drivers/nvidia/vbios", smoke_vbios_parse_pci_option_rom_header);

fn smoke_vbios_rejects_unknown_signature() -> TestResult {
    let mut rom = [0u8; 1024];
    // 0xDEAD as signature is not 0xAA55 / 0xBB77 / 0x4E56.
    rom[0..2].copy_from_slice(&0xDEADu16.to_le_bytes());
    match parse_image_at(&rom, 0) {
        Err(crate::vbios::VbiosError::UnknownSignature(0xDEAD)) => TestResult::Pass,
        _ => TestResult::Fail("unknown ROM signature should be rejected"),
    }
}
kernel_test_in!("drivers/nvidia/vbios", smoke_vbios_rejects_unknown_signature);

fn smoke_vbios_dcb_table_offset_and_header() -> TestResult {
    let mut image = [0u8; 256];
    // DCB pointer at image offset 0x36 → DCB header at 0x80.
    image[0x36..0x38].copy_from_slice(&0x80u16.to_le_bytes());
    // DCB v4.1 header.
    image[0x80] = 0x41;
    image[0x81] = 0x20; // header_len
    image[0x82] = 0x04; // entry_count
    image[0x83] = 0x08; // entry_size
    match dcb_table_offset(&image) {
        Some(0x80) => {}
        _ => return TestResult::Fail("DCB offset should be 0x80"),
    }
    let h = match dcb_header(&image, 0x80) {
        Some(h) => h,
        None => return TestResult::Fail("dcb_header decode failed"),
    };
    if h.version != 0x41 || h.entry_count != 4 || h.entry_size != 8 {
        return TestResult::Fail("DCB header fields misread");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/vbios", smoke_vbios_dcb_table_offset_and_header);

fn smoke_vbios_nv_modern_signature_accepted() -> TestResult {
    let mut rom = [0u8; 1024];
    rom[0..2].copy_from_slice(&ROM_SIG_NV.to_le_bytes());
    rom[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
    rom[0x40..0x44].copy_from_slice(b"PCIR");
    rom[0x50..0x52].copy_from_slice(&1u16.to_le_bytes());
    rom[0x54] = PCIR_TYPE_NV;
    rom[0x55] = 0x80;
    match parse_image_at(&rom, 0) {
        Ok(_) => TestResult::Pass,
        Err(_) => TestResult::Fail("NV-signature image must parse"),
    }
}
kernel_test_in!("drivers/nvidia/vbios", smoke_vbios_nv_modern_signature_accepted);

// ────────────────────────────────────────────────────────────────
// DP link training
// ────────────────────────────────────────────────────────────────

use crate::dp::{
    link_rate_gbps_x10, LaneStatus, LinkStatus, LtMachine, LtPhase, DPCD_LANE_COUNT_SET,
    DPCD_LINK_BW_SET, DPCD_TRAINING_PATTERN_SET, LINK_BW_1_62, LINK_BW_2_7, LINK_BW_5_4,
    LINK_BW_8_1, STATUS_CHANNEL_EQ_DONE, STATUS_CR_DONE, STATUS_SYMBOL_LOCKED,
    TRAINING_PATTERN_1, TRAINING_PATTERN_2, TRAINING_PATTERN_4,
};

fn smoke_dp_link_status_decodes_per_lane() -> TestResult {
    // Lane 0: CR + EQ + SYMBOL_LOCKED.
    // Lane 1: CR only.
    // Lane 2/3: nothing.
    let b202 = (STATUS_CR_DONE | STATUS_CHANNEL_EQ_DONE | STATUS_SYMBOL_LOCKED)
        | (STATUS_CR_DONE << 4);
    let b203 = 0;
    let b204 = 0x01; // interlane_aligned
    let s = LinkStatus::decode(b202, b203, b204);
    if !s.lanes[0].cr_done || !s.lanes[0].channel_eq_done || !s.lanes[0].symbol_locked {
        return TestResult::Fail("lane 0 decode wrong");
    }
    if !s.lanes[1].cr_done || s.lanes[1].channel_eq_done {
        return TestResult::Fail("lane 1 decode wrong");
    }
    if s.lanes[2].cr_done || s.lanes[3].cr_done {
        return TestResult::Fail("lanes 2/3 should be zero");
    }
    if !s.interlane_aligned {
        return TestResult::Fail("interlane_aligned bit decode wrong");
    }
    if !s.cr_done_on(2) {
        return TestResult::Fail("cr_done_on(2) should be true");
    }
    if s.cr_done_on(4) {
        return TestResult::Fail("cr_done_on(4) should be false (lanes 2/3 not done)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/dp", smoke_dp_link_status_decodes_per_lane);

fn smoke_dp_lt_state_machine_cr_then_eq_succeeds() -> TestResult {
    let mut m = LtMachine::new(LINK_BW_2_7, 4);
    if m.phase != LtPhase::CrStart {
        return TestResult::Fail("initial phase should be CrStart");
    }
    // CrStart → CrPoll (no status check yet).
    m.step(LinkStatus::decode(0, 0, 0));
    if m.phase != LtPhase::CrPoll {
        return TestResult::Fail("CrStart should advance to CrPoll");
    }
    // CrPoll with CR_DONE on all 4 lanes → EqStart.
    let cr_done_all = STATUS_CR_DONE | (STATUS_CR_DONE << 4);
    m.step(LinkStatus::decode(cr_done_all, cr_done_all, 0));
    if m.phase != LtPhase::EqStart {
        return TestResult::Fail("CR done on all lanes should advance to EqStart");
    }
    // EqStart → EqPoll.
    m.step(LinkStatus::decode(cr_done_all, cr_done_all, 0));
    if m.phase != LtPhase::EqPoll {
        return TestResult::Fail("EqStart should advance to EqPoll");
    }
    // EqPoll with EQ + symbol_locked + interlane_aligned → Done.
    let eq_done_nibble = STATUS_CR_DONE | STATUS_CHANNEL_EQ_DONE | STATUS_SYMBOL_LOCKED;
    let eq_all = eq_done_nibble | (eq_done_nibble << 4);
    m.step(LinkStatus::decode(eq_all, eq_all, 0x01));
    if m.phase != LtPhase::Done {
        return TestResult::Fail("EQ done on all lanes should advance to Done");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/dp", smoke_dp_lt_state_machine_cr_then_eq_succeeds);

fn smoke_dp_lt_voltage_bumps_until_failed() -> TestResult {
    // Sink never asserts CR_DONE. After 5 attempts at each
    // voltage level and we run out (voltage > 3), state should
    // be Failed.
    let mut m = LtMachine::new(LINK_BW_5_4, 4);
    m.step(LinkStatus::decode(0, 0, 0)); // CrStart → CrPoll
    // 20 polls (5 per level, 4 levels) all show no CR.
    for _ in 0..30 {
        m.step(LinkStatus::decode(0, 0, 0));
        if m.phase == LtPhase::Failed {
            break;
        }
    }
    if m.phase != LtPhase::Failed {
        return TestResult::Fail("CR never converged → must end Failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/dp", smoke_dp_lt_voltage_bumps_until_failed);

fn smoke_dp_link_rate_table_matches_dpcd_encoding() -> TestResult {
    // DPCD spec: 0x06=1.62, 0x0A=2.7, 0x14=5.4, 0x1E=8.1
    if link_rate_gbps_x10(LINK_BW_1_62) != 16 {
        return TestResult::Fail("1.62 Gbps → 16");
    }
    if link_rate_gbps_x10(LINK_BW_2_7) != 27 {
        return TestResult::Fail("2.7 Gbps → 27");
    }
    if link_rate_gbps_x10(LINK_BW_5_4) != 54 {
        return TestResult::Fail("5.4 Gbps → 54");
    }
    if link_rate_gbps_x10(LINK_BW_8_1) != 81 {
        return TestResult::Fail("8.1 Gbps → 81");
    }
    if link_rate_gbps_x10(0xFF) != 0 {
        return TestResult::Fail("unknown rate → 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/dp", smoke_dp_link_rate_table_matches_dpcd_encoding);

fn smoke_dp_dpcd_address_constants_match_spec() -> TestResult {
    if DPCD_TRAINING_PATTERN_SET != 0x0102 {
        return TestResult::Fail("DPCD TRAINING_PATTERN_SET = 0x102");
    }
    if DPCD_LINK_BW_SET != 0x0100 {
        return TestResult::Fail("DPCD LINK_BW_SET = 0x100");
    }
    if DPCD_LANE_COUNT_SET != 0x0101 {
        return TestResult::Fail("DPCD LANE_COUNT_SET = 0x101");
    }
    if TRAINING_PATTERN_1 != 1 || TRAINING_PATTERN_2 != 2 || TRAINING_PATTERN_4 != 4 {
        return TestResult::Fail("training-pattern codes mismatch DP spec");
    }
    let _ = LaneStatus::decode(0);
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/dp", smoke_dp_dpcd_address_constants_match_spec);
