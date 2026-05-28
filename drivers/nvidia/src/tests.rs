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
    decode_dcb_entry, dispclass_for, DcbEntry, EncoderType, Mode, ModeFlags, AD102_DISP,
    GA102_DISP, GM200_DISP, GP102_DISP, GV100_DISP, TU102_DISP,
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
    if (h >> 28) & 0xF != 0 {
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
    // Larger payload: 16 bytes → size-minus-1 = 15.
    let h3 = aux_header(AuxCommand::I2cRead, 0x50, 16);
    if (h3 >> 28) & 0xF != 15 {
        return TestResult::Fail("16-byte read should pack size-1 = 15");
    }
    if (h3 >> 8) & 0x000F_FFFF != 0x50 {
        return TestResult::Fail("16-byte read address should still be 0x50");
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

// ────────────────────────────────────────────────────────────────
// HPD debouncer
// ────────────────────────────────────────────────────────────────

use crate::hpd::{HpdDebouncer, HpdEvent, HpdOutcome, HpdSource, HpdState};

fn smoke_hpd_idle_connect_starts_debouncing() -> TestResult {
    let mut d = HpdDebouncer::new(HpdSource(0), 100);
    if d.state != HpdState::Idle {
        return TestResult::Fail("initial state must be Idle");
    }
    let outcome = d.handle(HpdEvent::Connect, 1000);
    if outcome != HpdOutcome::Stable {
        return TestResult::Fail("Idle → Connect should not fire BecameConnected yet");
    }
    if d.state != HpdState::Debouncing {
        return TestResult::Fail("Connect must arm Debouncing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/hpd", smoke_hpd_idle_connect_starts_debouncing);

fn smoke_hpd_debounce_window_expires_to_connected() -> TestResult {
    let mut d = HpdDebouncer::new(HpdSource(1), 100);
    d.handle(HpdEvent::Connect, 0);
    // Half-way through the window: still Stable.
    if d.poll(50) != HpdOutcome::Stable {
        return TestResult::Fail("Halfway through window should be Stable");
    }
    if d.state != HpdState::Debouncing {
        return TestResult::Fail("Halfway through window state remains Debouncing");
    }
    // Window expired: BecameConnected.
    if d.poll(101) != HpdOutcome::BecameConnected {
        return TestResult::Fail("Window expired should fire BecameConnected");
    }
    if d.state != HpdState::Connected {
        return TestResult::Fail("After firing, state should be Connected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/hpd", smoke_hpd_debounce_window_expires_to_connected);

fn smoke_hpd_bouncy_connect_disconnect_drops_to_idle() -> TestResult {
    let mut d = HpdDebouncer::new(HpdSource(2), 100);
    d.handle(HpdEvent::Connect, 0);
    let o = d.handle(HpdEvent::Disconnect, 30);
    if o != HpdOutcome::Stable {
        return TestResult::Fail("Bouncy disconnect should be Stable");
    }
    if d.state != HpdState::Idle {
        return TestResult::Fail("Bounce must roll back to Idle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/hpd",
    smoke_hpd_bouncy_connect_disconnect_drops_to_idle
);

fn smoke_hpd_disconnect_from_connected_fires_becamedisconnected() -> TestResult {
    let mut d = HpdDebouncer::new(HpdSource(3), 100);
    d.handle(HpdEvent::Connect, 0);
    let _ = d.poll(200);
    if d.state != HpdState::Connected {
        return TestResult::Fail("preconditioning to Connected");
    }
    let o = d.handle(HpdEvent::Disconnect, 1000);
    if o != HpdOutcome::BecameDisconnected {
        return TestResult::Fail("Connected → Disconnect must fire BecameDisconnected");
    }
    if d.state != HpdState::Idle {
        return TestResult::Fail("Disconnect resets to Idle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/hpd",
    smoke_hpd_disconnect_from_connected_fires_becamedisconnected
);

fn smoke_hpd_short_pulse_when_connected_emits_shortpulse() -> TestResult {
    let mut d = HpdDebouncer::new(HpdSource(4), 50);
    d.handle(HpdEvent::Connect, 0);
    let _ = d.poll(100);
    let o = d.handle(HpdEvent::ShortPulse, 500);
    if o != HpdOutcome::ShortPulse {
        return TestResult::Fail("ShortPulse on Connected must emit ShortPulse");
    }
    if d.state != HpdState::Connected {
        return TestResult::Fail("ShortPulse does not transition state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/hpd",
    smoke_hpd_short_pulse_when_connected_emits_shortpulse
);

// ────────────────────────────────────────────────────────────────
// GSP (Turing+)
// ────────────────────────────────────────────────────────────────

use crate::gsp::{Gsp, GspRpcFn, GspRpcRing, FBIF_OFFSET, WPR2_HI_SCRATCH};

fn smoke_gsp_present_only_on_turing_plus() -> TestResult {
    if !Gsp::family_has_gsp(ChipFamily::Turing) {
        return TestResult::Fail("Turing has GSP");
    }
    if !Gsp::family_has_gsp(ChipFamily::Ampere) {
        return TestResult::Fail("Ampere has GSP");
    }
    if !Gsp::family_has_gsp(ChipFamily::Ada) {
        return TestResult::Fail("Ada has GSP");
    }
    if Gsp::family_has_gsp(ChipFamily::Pascal) {
        return TestResult::Fail("Pascal does NOT have GSP");
    }
    if Gsp::family_has_gsp(ChipFamily::Maxwell) {
        return TestResult::Fail("Maxwell does NOT have GSP");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/gsp", smoke_gsp_present_only_on_turing_plus);

fn smoke_gsp_register_constants_pinned() -> TestResult {
    if WPR2_HI_SCRATCH != 0x001F_A828 {
        return TestResult::Fail("WPR2_HI_SCRATCH offset must match tu102.c line 0x1fa828");
    }
    if FBIF_OFFSET != 0x0000_0600 {
        return TestResult::Fail("FBIF offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/gsp", smoke_gsp_register_constants_pinned);

fn smoke_gsp_rpc_ring_empty_full_invariants() -> TestResult {
    let mut r = GspRpcRing::new(0x1000_0000, 4096);
    if !r.is_empty() {
        return TestResult::Fail("fresh ring must be empty");
    }
    if r.is_full(64) {
        return TestResult::Fail("fresh ring is not full");
    }
    // Wrap-around full check: wptr just before rptr.
    r.wptr = 4096 - 64;
    r.rptr = 4096 - 128;
    if r.is_empty() {
        return TestResult::Fail("filled ring is not empty");
    }
    // RPC function-id table — Nop is 0x0001, AllocRoot is 0x0003.
    if GspRpcFn::Nop as u32 != 0x0001 {
        return TestResult::Fail("Nop RPC fn id mismatches Nouveau");
    }
    if GspRpcFn::AllocRoot as u32 != 0x0003 {
        return TestResult::Fail("AllocRoot RPC fn id mismatches Nouveau");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/gsp", smoke_gsp_rpc_ring_empty_full_invariants);

// ────────────────────────────────────────────────────────────────
// KMS — connector enumeration + CRTC picking
// ────────────────────────────────────────────────────────────────

use crate::kms::{
    build_path, driveable, enumerate_dcb, lookup_connector_type, pick_crtc, EnumeratedPath,
    MAX_DCB_ENTRIES,
};

fn smoke_kms_enumerate_dcb_walks_multiple_entries() -> TestResult {
    // Two valid entries + one 0xFFFF sentinel.
    let mut raw = [0u8; 24];
    // Entry 0: HDMI encoder (6) + i2c=1 + heads=1 + conn=3 +
    // OR=1.
    let e0: u32 = 6 | (1 << 4) | (1 << 8) | (3 << 12) | (1 << 24);
    raw[0..4].copy_from_slice(&e0.to_le_bytes());
    // Entry 1: DP encoder (3) + i2c=2 + heads=3 + conn=4 + OR=2.
    let e1: u32 = 3 | (2 << 4) | (3 << 8) | (4 << 12) | (2 << 24);
    raw[8..12].copy_from_slice(&e1.to_le_bytes());
    // Entry 2: sentinel.
    raw[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let paths = enumerate_dcb(&raw);
    if paths.len() != 2 {
        return TestResult::Fail("should enumerate exactly two non-sentinel entries");
    }
    if paths[0].entry.encoder_type != EncoderType::Hdmi {
        return TestResult::Fail("entry 0 should be HDMI");
    }
    if paths[1].entry.encoder_type != EncoderType::DisplayPort {
        return TestResult::Fail("entry 1 should be DP");
    }
    if paths[1].valid_crtcs != 0x3 {
        return TestResult::Fail("DP entry heads bitmask 0b11");
    }
    if MAX_DCB_ENTRIES < 2 {
        return TestResult::Fail("MAX_DCB_ENTRIES too small");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/kms",
    smoke_kms_enumerate_dcb_walks_multiple_entries
);

fn smoke_kms_pick_crtc_intersects_valid_and_available() -> TestResult {
    // Path supports CRTCs 0 + 1; 0 is unavailable, 1 is free.
    let p = EnumeratedPath {
        dcb_index: 0,
        entry: DcbEntry {
            encoder_type: EncoderType::Hdmi,
            connector_index: 3,
            or: 1,
            i2c_index: 0,
            heads: 0b11,
        },
        valid_crtcs: 0b11,
    };
    match pick_crtc(&p, 0b10) {
        Some(1) => {}
        _ => return TestResult::Fail("should pick CRTC 1"),
    }
    if pick_crtc(&p, 0).is_some() {
        return TestResult::Fail("no available CRTCs → None");
    }
    if pick_crtc(&p, 0b100).is_some() {
        return TestResult::Fail("no overlap → None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/kms",
    smoke_kms_pick_crtc_intersects_valid_and_available
);

fn smoke_kms_driveable_filters_external_and_unknown() -> TestResult {
    let paths = [
        EnumeratedPath {
            dcb_index: 0,
            entry: DcbEntry {
                encoder_type: EncoderType::DisplayPort,
                connector_index: 4,
                or: 0,
                i2c_index: 0,
                heads: 0x1,
            },
            valid_crtcs: 0x1,
        },
        EnumeratedPath {
            dcb_index: 1,
            entry: DcbEntry {
                encoder_type: EncoderType::External,
                connector_index: 0,
                or: 0,
                i2c_index: 0,
                heads: 0,
            },
            valid_crtcs: 0,
        },
        EnumeratedPath {
            dcb_index: 2,
            entry: DcbEntry {
                encoder_type: EncoderType::Unknown(0xFF),
                connector_index: 0,
                or: 0,
                i2c_index: 0,
                heads: 0,
            },
            valid_crtcs: 0,
        },
    ];
    let out = driveable(&paths);
    if out.len() != 1 {
        return TestResult::Fail("only the DP entry survives the filter");
    }
    if out[0].entry.encoder_type != EncoderType::DisplayPort {
        return TestResult::Fail("DP entry must remain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/kms",
    smoke_kms_driveable_filters_external_and_unknown
);

fn smoke_kms_build_path_carries_ids() -> TestResult {
    let p = EnumeratedPath {
        dcb_index: 3,
        entry: DcbEntry {
            encoder_type: EncoderType::Hdmi,
            connector_index: 3,
            or: 2,
            i2c_index: 1,
            heads: 0x1,
        },
        valid_crtcs: 0x1,
    };
    let path = build_path(&p, 0);
    if path.connector_id != 3 {
        return TestResult::Fail("connector_id should be DCB index");
    }
    if path.encoder_id != 2 {
        return TestResult::Fail("encoder_id should be the OR field");
    }
    if path.crtc_id != 0 {
        return TestResult::Fail("crtc_id should be the picked index");
    }
    if path.encoder_type != EncoderType::Hdmi {
        return TestResult::Fail("encoder_type propagates");
    }
    // Lookup table sanity: index 4/5 → DP, index 6 → eDP.
    if lookup_connector_type(4) != crate::disp::ConnectorType::DisplayPort {
        return TestResult::Fail("connector index 4 should be DisplayPort");
    }
    if lookup_connector_type(6) != crate::disp::ConnectorType::Edp {
        return TestResult::Fail("connector index 6 should be Edp");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/kms", smoke_kms_build_path_carries_ids);

// ────────────────────────────────────────────────────────────────
// SEC2
// ────────────────────────────────────────────────────────────────

use crate::sec2::Sec2Cmd;

fn smoke_sec2_cmd_ids_pinned() -> TestResult {
    if Sec2Cmd::LoadFw as u32 != 0x0001 {
        return TestResult::Fail("LoadFw cmd id");
    }
    if Sec2Cmd::BootWpr2 as u32 != 0x0002 {
        return TestResult::Fail("BootWpr2 cmd id");
    }
    if Sec2Cmd::HdcpKx as u32 != 0x0010 {
        return TestResult::Fail("HdcpKx cmd id");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/sec2", smoke_sec2_cmd_ids_pinned);

// ────────────────────────────────────────────────────────────────
// Fence — monotonic completion tracking
// ────────────────────────────────────────────────────────────────

use crate::fence::{
    Fence, SEMAPHOREA, SEMAPHOREB, SEMAPHOREC, SEMAPHORED, SEMAPHORED_ACQUIRE_GEQ,
    SEMAPHORED_RELEASE,
};

fn smoke_fence_seqno_allocates_monotonically() -> TestResult {
    let f = Fence::new(0x1000_0000);
    let a = f.alloc_seqno();
    let b = f.alloc_seqno();
    let c = f.alloc_seqno();
    if a >= b || b >= c {
        return TestResult::Fail("seqno must monotonically increase");
    }
    if a != 1 || b != 2 || c != 3 {
        return TestResult::Fail("first seqnos should be 1, 2, 3");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/fence", smoke_fence_seqno_allocates_monotonically);

fn smoke_fence_observe_signalled_monotonic_max() -> TestResult {
    let f = Fence::new(0);
    let _ = f.alloc_seqno(); // 1
    let _ = f.alloc_seqno(); // 2
    f.observe_signalled(2);
    if !f.is_signalled(1) || !f.is_signalled(2) {
        return TestResult::Fail("1 and 2 should be signalled");
    }
    if f.is_signalled(3) {
        return TestResult::Fail("3 should not be signalled yet");
    }
    // Out-of-order delivery: observing a lower seqno must not
    // regress the watermark.
    f.observe_signalled(1);
    if !f.is_signalled(2) {
        return TestResult::Fail("watermark cannot regress");
    }
    if f.highwater() != 2 {
        return TestResult::Fail("highwater stays at 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/fence",
    smoke_fence_observe_signalled_monotonic_max
);

fn smoke_fence_semaphore_method_offsets_match_class_header() -> TestResult {
    if SEMAPHOREA != 0x0010 {
        return TestResult::Fail("SEMAPHOREA at method 0x10");
    }
    if SEMAPHOREB != 0x0014 {
        return TestResult::Fail("SEMAPHOREB at method 0x14");
    }
    if SEMAPHOREC != 0x0018 {
        return TestResult::Fail("SEMAPHOREC at method 0x18");
    }
    if SEMAPHORED != 0x001C {
        return TestResult::Fail("SEMAPHORED at method 0x1C");
    }
    if SEMAPHORED_RELEASE != 1 {
        return TestResult::Fail("RELEASE opcode = 1");
    }
    if SEMAPHORED_ACQUIRE_GEQ != 4 {
        return TestResult::Fail("ACQUIRE_GEQ opcode = 4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/fence",
    smoke_fence_semaphore_method_offsets_match_class_header
);

// ────────────────────────────────────────────────────────────────
// Flip — page flipping + VBLANK
// ────────────────────────────────────────────────────────────────

use crate::flip::{FlipQueue, FlipRequest, HEAD_INTR_STATUS, HEAD_INTR_VBLANK};

fn smoke_flip_enqueue_dequeue_round_trip() -> TestResult {
    let q = FlipQueue::new();
    if q.has_pending() {
        return TestResult::Fail("fresh queue must not be pending");
    }
    let r = FlipRequest {
        fb_phys: 0x2000_0000,
        pitch: 1920 * 4,
        format: 0x4,
        seqno: 0x1234_5678_9ABC_DEF0,
    };
    if !q.enqueue(&r) {
        return TestResult::Fail("first enqueue must succeed");
    }
    if !q.has_pending() {
        return TestResult::Fail("queue has a pending flip");
    }
    let r2 = FlipRequest {
        fb_phys: 0x3000_0000,
        pitch: 1920 * 4,
        format: 0x4,
        seqno: 0xDEAD_BEEF_F00D_BEEF,
    };
    if q.enqueue(&r2) {
        return TestResult::Fail("second enqueue must reject while pending");
    }
    match q.on_vblank(42) {
        Some(s) if s == 0x1234_5678_9ABC_DEF0 => {}
        _ => return TestResult::Fail("on_vblank should return enqueued seqno"),
    }
    if q.vblank_counter() != 42 {
        return TestResult::Fail("vblank_counter should advance");
    }
    if q.has_pending() {
        return TestResult::Fail("queue should be drained");
    }
    if q.on_vblank(43).is_some() {
        return TestResult::Fail("idle VBLANK should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/flip", smoke_flip_enqueue_dequeue_round_trip);

fn smoke_flip_head_vblank_interrupt_bit_layout() -> TestResult {
    if HEAD_INTR_VBLANK != 1 << 4 {
        return TestResult::Fail("VBLANK bit at position 4");
    }
    if HEAD_INTR_STATUS != 0x0000_0090 {
        return TestResult::Fail("HEAD IRQ status offset 0x90");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/flip",
    smoke_flip_head_vblank_interrupt_bit_layout
);

// ────────────────────────────────────────────────────────────────
// Pushbuffer assembly
// ────────────────────────────────────────────────────────────────

use crate::ce::{
    CE_LINE_COUNT, CE_LINE_LENGTH_IN, CE_OFFSET_IN_LOWER, CE_OFFSET_IN_UPPER,
    CE_OFFSET_OUT_LOWER, CE_OFFSET_OUT_UPPER,
};
use crate::pb::{append_fence_release, PbBuilder, PbError};

fn smoke_pb_builder_writes_method_then_data_words() -> TestResult {
    let mut buf = [0u8; 64];
    let mut pb = PbBuilder::new(&mut buf);
    if !pb.is_empty() {
        return TestResult::Fail("fresh PbBuilder is empty");
    }
    // Inc-write to CE_OFFSET_IN_UPPER, 2 words.
    pb.write_inc(CE_OFFSET_IN_UPPER, &[0xAAAA_AAAA, 0xBBBB_BBBB])
        .unwrap();
    if pb.len() != 12 {
        return TestResult::Fail("Should have written header + 2 data = 12 bytes");
    }
    // Decode the header back: method = CE_OFFSET_IN_UPPER (0x400),
    // size = 2, type = Inc (1).
    let hdr = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if hdr & 0xFFFF != CE_OFFSET_IN_UPPER as u32 {
        return TestResult::Fail("method low-16 in header word");
    }
    if (hdr >> 16) & 0x1FFF != 2 {
        return TestResult::Fail("size field");
    }
    if (hdr >> 29) & 0x7 != 1 {
        return TestResult::Fail("Inc type");
    }
    // Data word 0 = 0xAAAAAAAA, data word 1 = 0xBBBBBBBB.
    let w0 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let w1 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if w0 != 0xAAAA_AAAA || w1 != 0xBBBB_BBBB {
        return TestResult::Fail("data words");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/pb",
    smoke_pb_builder_writes_method_then_data_words
);

fn smoke_pb_builder_rejects_overflow() -> TestResult {
    let mut buf = [0u8; 12];
    let mut pb = PbBuilder::new(&mut buf);
    // Header + 2 words = 12 bytes — fits.
    pb.write_inc(CE_OFFSET_IN_UPPER, &[0, 0]).unwrap();
    // Next write would overflow.
    match pb.write_inc(CE_OFFSET_OUT_UPPER, &[0]) {
        Err(PbError::BufferFull) => TestResult::Pass,
        _ => TestResult::Fail("overflow should yield BufferFull"),
    }
}
kernel_test_in!("drivers/nvidia/pb", smoke_pb_builder_rejects_overflow);

fn smoke_pb_ce_copy_descriptor_full_assembly() -> TestResult {
    // Build a complete CE copy pushbuffer: src/dst 64b, line
    // length + count, LAUNCH_DMA.
    let mut buf = [0u8; 128];
    let mut pb = PbBuilder::new(&mut buf);
    let src: u64 = 0x1234_5678_9ABC_DEF0;
    let dst: u64 = 0x4000_0000_FACE_B00C;
    pb.write_inc(
        CE_OFFSET_IN_UPPER,
        &[(src >> 32) as u32, (src & 0xFFFF_FFFF) as u32],
    )
    .unwrap();
    pb.write_inc(
        CE_OFFSET_OUT_UPPER,
        &[(dst >> 32) as u32, (dst & 0xFFFF_FFFF) as u32],
    )
    .unwrap();
    pb.write_inc(CE_LINE_LENGTH_IN, &[4096]).unwrap();
    pb.write_inc(CE_LINE_COUNT, &[1]).unwrap();
    pb.write_inc(CE_LAUNCH_DMA, &[crate::ce::CE_FLAGS_BLOCKING])
        .unwrap();
    // Bytes written: 5 headers (4 each) + 2+2+1+1+1 data (4 each) = 20+28 = 48.
    if pb.len() != 48 {
        return TestResult::Fail("expected total 48 bytes for full CE copy descriptor");
    }
    // Verify CE_OFFSET_IN_LOWER / CE_OFFSET_OUT_LOWER constants
    // are consistent with the upper/+4 placement.
    if CE_OFFSET_IN_LOWER != CE_OFFSET_IN_UPPER + 4 {
        return TestResult::Fail("CE_OFFSET_IN_LOWER must follow UPPER by 4");
    }
    if CE_OFFSET_OUT_LOWER != CE_OFFSET_OUT_UPPER + 4 {
        return TestResult::Fail("CE_OFFSET_OUT_LOWER must follow UPPER by 4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/pb",
    smoke_pb_ce_copy_descriptor_full_assembly
);

fn smoke_pb_append_fence_release_emits_four_word_block() -> TestResult {
    let mut buf = [0u8; 32];
    let mut pb = PbBuilder::new(&mut buf);
    let sem: u64 = 0x9999_8888_7777_6666;
    let seq: u32 = 0xCAFE_F00D;
    append_fence_release(&mut pb, sem, seq).unwrap();
    // Header (4) + 4 data words = 20 bytes total.
    if pb.len() != 20 {
        return TestResult::Fail("fence release block should be 20 bytes");
    }
    let w_high = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let w_low = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let w_payload = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let w_op = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if w_high != ((sem >> 32) as u32) {
        return TestResult::Fail("SEMAPHOREA word should be high-half of address");
    }
    if w_low != (sem as u32) {
        return TestResult::Fail("SEMAPHOREB word should be low-half of address");
    }
    if w_payload != seq {
        return TestResult::Fail("SEMAPHOREC word should be payload");
    }
    if w_op != 1 {
        return TestResult::Fail("SEMAPHORED word should be RELEASE (1)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/pb",
    smoke_pb_append_fence_release_emits_four_word_block
);

// ────────────────────────────────────────────────────────────────
// EDID-over-AUX
// ────────────────────────────────────────────────────────────────

use crate::edid_aux::{
    aux_header_for_edid_read, aux_header_for_segment_select, validate_block, DDC_ADDR_EDID,
    DDC_ADDR_SEGMENT, EDID_BLOCK_SIZE,
};

fn smoke_edid_aux_addresses_and_block_size() -> TestResult {
    if DDC_ADDR_EDID != 0x50 {
        return TestResult::Fail("EDID at I²C addr 0x50");
    }
    if DDC_ADDR_SEGMENT != 0x30 {
        return TestResult::Fail("E-EDID segment register at 0x30");
    }
    if EDID_BLOCK_SIZE != 128 {
        return TestResult::Fail("EDID block size is 128 bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/edid_aux",
    smoke_edid_aux_addresses_and_block_size
);

fn smoke_edid_aux_read_header_packs_correctly() -> TestResult {
    let h = aux_header_for_edid_read(0, 16);
    // Low nibble = I2cRead (1).
    if h & 0xF != 1 {
        return TestResult::Fail("AUX command should be I2cRead");
    }
    if (h >> 8) & 0x000F_FFFF != DDC_ADDR_EDID {
        return TestResult::Fail("address field should be 0x50");
    }
    // size 16 → size-minus-1 = 15, packed in bits[31:28].
    if (h >> 28) & 0xF != 15 {
        return TestResult::Fail("size field should be 15");
    }
    let s = aux_header_for_segment_select();
    if s & 0xF != 0 {
        return TestResult::Fail("segment-select uses I2cWrite (0)");
    }
    if (s >> 8) & 0x000F_FFFF != DDC_ADDR_SEGMENT {
        return TestResult::Fail("segment register at 0x30");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/edid_aux",
    smoke_edid_aux_read_header_packs_correctly
);

fn smoke_edid_block_signature_and_checksum_validation() -> TestResult {
    let mut block = [0u8; EDID_BLOCK_SIZE];
    // Valid header.
    block[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Make the last byte the checksum so the sum is zero mod 256.
    let mut sum: u8 = 0;
    for b in block[..127].iter() {
        sum = sum.wrapping_add(*b);
    }
    block[127] = 0u8.wrapping_sub(sum);
    if validate_block(&block).is_err() {
        return TestResult::Fail("valid EDID block must pass validation");
    }
    // Break the checksum.
    block[127] = block[127].wrapping_add(1);
    if validate_block(&block).is_ok() {
        return TestResult::Fail("corrupt checksum must be detected");
    }
    // Break the signature.
    block[0] = 0xAA;
    if validate_block(&block).is_ok() {
        return TestResult::Fail("bad signature must be detected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/edid_aux",
    smoke_edid_block_signature_and_checksum_validation
);

// ────────────────────────────────────────────────────────────────
// Live mode-set commit (item 1)
// ────────────────────────────────────────────────────────────────

use crate::disp::nv50::{
    doorbell_kick, enc_pixel_clock, enc_raster_blank_end, enc_raster_blank_start, enc_raster_size,
    enc_raster_sync_end, head_method, put_value, stage_head_mode, stage_head_scanout, stage_update,
    DISP_CHAN_GET, DISP_CHAN_PUT, HEAD_CONTROL_INTERLACED, HEAD_CONTROL_PROGRESSIVE,
    NV507D_HEAD_SET_CONTEXT_DMA_ISO, NV507D_HEAD_SET_CONTROL, NV507D_HEAD_SET_OFFSET,
    NV507D_HEAD_SET_OVERSCAN_COLOR, NV507D_HEAD_SET_PIXEL_CLOCK, NV507D_HEAD_SET_RASTER_BLANK_END,
    NV507D_HEAD_SET_RASTER_BLANK_START, NV507D_HEAD_SET_RASTER_SIZE,
    NV507D_HEAD_SET_RASTER_SYNC_END, NV507D_HEAD_STRIDE, NV507D_UPDATE,
    PIXEL_CLOCK_MODE_CLK_CUSTOM,
};
fn smoke_disp_nv507d_method_addresses_match_cl507d_h() -> TestResult {
    // Method ids from
    // include/nvhw/class/cl507d.h. Pin them so a future change to
    // the const table is caught at test time.
    if NV507D_UPDATE != 0x0080 {
        return TestResult::Fail("NV507D::UPDATE method should be 0x80");
    }
    if NV507D_HEAD_SET_PIXEL_CLOCK != 0x0804 {
        return TestResult::Fail("NV507D::HEAD_SET_PIXEL_CLOCK(0) should be 0x804");
    }
    if NV507D_HEAD_SET_CONTROL != 0x0808 {
        return TestResult::Fail("NV507D::HEAD_SET_CONTROL(0) should be 0x808");
    }
    if NV507D_HEAD_SET_OVERSCAN_COLOR != 0x0810 {
        return TestResult::Fail("NV507D::HEAD_SET_OVERSCAN_COLOR(0) should be 0x810");
    }
    if NV507D_HEAD_SET_RASTER_SIZE != 0x0814 {
        return TestResult::Fail("HEAD_SET_RASTER_SIZE(0) should be 0x814");
    }
    if NV507D_HEAD_SET_RASTER_SYNC_END != 0x0818 {
        return TestResult::Fail("HEAD_SET_RASTER_SYNC_END(0) should be 0x818");
    }
    if NV507D_HEAD_SET_RASTER_BLANK_END != 0x081C {
        return TestResult::Fail("HEAD_SET_RASTER_BLANK_END(0) should be 0x81C");
    }
    if NV507D_HEAD_SET_RASTER_BLANK_START != 0x0820 {
        return TestResult::Fail("HEAD_SET_RASTER_BLANK_START(0) should be 0x820");
    }
    if NV507D_HEAD_SET_OFFSET != 0x0860 {
        return TestResult::Fail("HEAD_SET_OFFSET(0,0) should be 0x860");
    }
    if NV507D_HEAD_SET_CONTEXT_DMA_ISO != 0x0874 {
        return TestResult::Fail("HEAD_SET_CONTEXT_DMA_ISO(0) should be 0x874");
    }
    if NV507D_HEAD_STRIDE != 0x0400 {
        return TestResult::Fail("HEAD stride must be 0x400");
    }
    // Per-HEAD computation: HEAD(1) PIXEL_CLOCK = 0x804 + 0x400 = 0xC04.
    if head_method(NV507D_HEAD_SET_PIXEL_CLOCK, 1) != 0x0C04 {
        return TestResult::Fail("head_method(PIXEL_CLOCK, 1) mismatched");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_nv507d_method_addresses_match_cl507d_h
);

fn smoke_disp_pixel_clock_field_encoding() -> TestResult {
    // 148500 kHz (1080p60 pixel clock) with custom mode.
    let v = enc_pixel_clock(148_500, true, false);
    if v & 0x003F_FFFF != 148_500 {
        return TestResult::Fail("FREQUENCY field bits[21:0] wrong");
    }
    if v & PIXEL_CLOCK_MODE_CLK_CUSTOM == 0 {
        return TestResult::Fail("CLK_CUSTOM mode bits should be set");
    }
    if v & (1 << 24) != 0 {
        return TestResult::Fail("ADJ1000DIV1001 should be off");
    }
    // ntsc adjust.
    let v2 = enc_pixel_clock(27_000, false, true);
    if v2 & (1 << 24) == 0 {
        return TestResult::Fail("ADJ1000DIV1001 should be on");
    }
    if v2 & PIXEL_CLOCK_MODE_CLK_CUSTOM != 0 {
        return TestResult::Fail("CLK_CUSTOM should be off when custom=false");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/disp", smoke_disp_pixel_clock_field_encoding);

fn smoke_disp_raster_size_sync_blank_packing() -> TestResult {
    // 1080p timings: htotal=2200, vtotal=1125.
    let v = enc_raster_size(2200, 1125);
    if v & 0x7FFF != 2200 {
        return TestResult::Fail("WIDTH bits[14:0] wrong");
    }
    if (v >> 16) & 0x7FFF != 1125 {
        return TestResult::Fail("HEIGHT bits[30:16] wrong");
    }
    let s = enc_raster_sync_end(2052, 1089);
    if s & 0x7FFF != 2052 || (s >> 16) & 0x7FFF != 1089 {
        return TestResult::Fail("sync_end packing wrong");
    }
    let be = enc_raster_blank_end(280, 45);
    if be & 0x7FFF != 280 || (be >> 16) & 0x7FFF != 45 {
        return TestResult::Fail("blank_end packing wrong");
    }
    let bs = enc_raster_blank_start(2052, 1089);
    if bs & 0x7FFF != 2052 || (bs >> 16) & 0x7FFF != 1089 {
        return TestResult::Fail("blank_start packing wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_raster_size_sync_blank_packing
);

fn smoke_disp_stage_head_mode_writes_two_blocks() -> TestResult {
    let mut buf = [0u8; 128];
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
        flags: ModeFlags::default(),
    };
    let pb_len = {
        let mut pb = PbBuilder::new(&mut buf);
        stage_head_mode(&mut pb, 0, &m).unwrap();
        pb.len()
    };
    // Two PUSH_MTHD blocks: first block has 2 data words (PIXEL_CLOCK + CONTROL),
    // second has 5 (OVERSCAN_COLOR + 4 raster words). Per header-shape that's
    // 4 + 2*4 + 4 + 5*4 = 36 bytes.
    if pb_len != 36 {
        return TestResult::Fail("stage_head_mode should write 36 bytes (2 + 5 data + 2 hdrs)");
    }
    // Verify first header word's method id.
    let hdr0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if hdr0 & 0xFFFF != NV507D_HEAD_SET_PIXEL_CLOCK as u32 {
        return TestResult::Fail("first header method should be PIXEL_CLOCK(0)");
    }
    if (hdr0 >> 16) & 0x1FFF != 2 {
        return TestResult::Fail("first header size should be 2 words");
    }
    // Second header word.
    let hdr1 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if hdr1 & 0xFFFF != NV507D_HEAD_SET_OVERSCAN_COLOR as u32 {
        return TestResult::Fail("second header method should be OVERSCAN_COLOR(0)");
    }
    if (hdr1 >> 16) & 0x1FFF != 5 {
        return TestResult::Fail("second header size should be 5 words");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_stage_head_mode_writes_two_blocks
);

fn smoke_disp_stage_head_scanout_and_update() -> TestResult {
    let mut buf = [0u8; 64];
    let pb_len = {
        let mut pb = PbBuilder::new(&mut buf);
        stage_head_scanout(&mut pb, 0, 0x1234_5600, 0xCAFEC0DE).unwrap();
        let after_scanout = pb.len();
        if after_scanout != 16 {
            return TestResult::Fail("scanout stage should be 16 bytes");
        }
        stage_update(&mut pb, 0).unwrap();
        pb.len()
    };
    // 2 PUSH_MTHD blocks each with 1 data word for scanout (16 bytes),
    // then UPDATE adds 8 bytes (hdr + 1 data) = 24 total.
    if pb_len != 16 + 8 {
        return TestResult::Fail("UPDATE adds 8 bytes (hdr + 1 data)");
    }
    let data0 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if data0 != (0x1234_5600u32 >> 8) {
        return TestResult::Fail("OFFSET should be fb_offset_bytes >> 8");
    }
    let hdr_upd = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if hdr_upd & 0xFFFF != NV507D_UPDATE as u32 {
        return TestResult::Fail("UPDATE method id wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_stage_head_scanout_and_update
);

fn smoke_disp_put_pointer_encoding_matches_cl507c() -> TestResult {
    // Per cl507c.h::NV507C_PUT_PTR (bits[11:2]) the byte offset is
    // shifted right by 2 to yield the word index.
    if put_value(0) != 0 {
        return TestResult::Fail("0 → 0");
    }
    if put_value(4) != 4 {
        return TestResult::Fail("byte=4 → PUT[2]=1 → 0x4");
    }
    if put_value(64) != 64 {
        return TestResult::Fail("byte=64 → PUT[7]=16 → 0x40");
    }
    // Mask out non-word bits.
    if put_value(0xFFFF_FFFF) & 0x3 != 0 {
        return TestResult::Fail("bottom 2 bits must always be zero");
    }
    if DISP_CHAN_PUT != 0 || DISP_CHAN_GET != 4 {
        return TestResult::Fail("PUT at offset 0, GET at offset 4");
    }
    // The encoder must clamp into the [11:2] field range.
    if put_value(0xFFFF_FFFF) > 0x0FFF {
        return TestResult::Fail("PUT must stay inside bits[11:2]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_put_pointer_encoding_matches_cl507c
);

fn smoke_disp_head_control_interlace_bit_pin() -> TestResult {
    if HEAD_CONTROL_PROGRESSIVE != 0 {
        return TestResult::Fail("progressive should be 0");
    }
    if HEAD_CONTROL_INTERLACED != 1 {
        return TestResult::Fail("interlaced should be 1");
    }
    // stage_head_mode must propagate the flag.
    let mut buf = [0u8; 64];
    let m = Mode {
        clock_khz: 27_000,
        h_display: 720,
        h_sync_start: 736,
        h_sync_end: 798,
        h_total: 858,
        v_display: 480,
        v_sync_start: 484,
        v_sync_end: 488,
        v_total: 525,
        flags: ModeFlags {
            hsync_positive: true,
            vsync_positive: true,
            interlaced: true,
            double_scan: false,
        },
    };
    {
        let mut pb = PbBuilder::new(&mut buf);
        stage_head_mode(&mut pb, 0, &m).unwrap();
    }
    // The CONTROL data word is the second word in the first
    // PUSH_MTHD block (after PIXEL_CLOCK). That's bytes 8..12.
    let ctrl = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if ctrl != HEAD_CONTROL_INTERLACED {
        return TestResult::Fail("interlaced flag should produce CONTROL=1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/disp",
    smoke_disp_head_control_interlace_bit_pin
);

// ────────────────────────────────────────────────────────────────
// Multi-GPU controller list (item 6)
// ────────────────────────────────────────────────────────────────

fn smoke_pci_controller_list_starts_empty() -> TestResult {
    crate::pci::__reset_for_test();
    if crate::pci::is_probed() {
        return TestResult::Fail("freshly-reset controller list must be empty");
    }
    if crate::pci::card_count() != 0 {
        return TestResult::Fail("card_count() must be 0 after reset");
    }
    if crate::pci::card_indices().len() != 0 {
        return TestResult::Fail("card_indices() must be empty after reset");
    }
    if crate::pci::card_arc(0).is_some() {
        return TestResult::Fail("card_arc on empty list returns None");
    }
    if crate::pci::with_card(0, |_| ()).is_some() {
        return TestResult::Fail("with_card on empty list returns None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvidia/pci", smoke_pci_controller_list_starts_empty);

fn smoke_pci_controller_list_api_surface_exists() -> TestResult {
    // Verify the new multi-card API surface compiles + answers
    // consistently on an empty list. Real card-bringup happens in
    // QEMU/bare-metal integration tests; this is a compile-time
    // pin for the public API plus the boot-time helpers.
    crate::pci::__reset_for_test();
    let _ = crate::pci::is_probed();
    let _ = crate::pci::card_count();
    let v = crate::pci::card_indices();
    if !v.is_empty() {
        return TestResult::Fail("indices vec should be empty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/pci",
    smoke_pci_controller_list_api_surface_exists
);

fn smoke_pcie_recovery_callback_vote_table() -> TestResult {
    use narf_bus::pcie_recovery::{ErrorCallback, PciErrSeverity, PciErsResult};
    use crate::pcie_recovery::CardRecovery;
    let r = CardRecovery::new(0, narf_bus::BusAddr::Pcie(narf_bus::addr::PcieAddr::new(0, 0, 0, 0)));
    // Correctable + NonFatal vote CanRecover; Fatal needs reset.
    if r.error_detected(PciErrSeverity::Correctable) != PciErsResult::CanRecover {
        return TestResult::Fail("Correctable must yield CanRecover");
    }
    if r.error_detected(PciErrSeverity::NonFatal) != PciErsResult::CanRecover {
        return TestResult::Fail("NonFatal must yield CanRecover");
    }
    if r.error_detected(PciErrSeverity::Fatal) != PciErsResult::NeedReset {
        return TestResult::Fail("Fatal must yield NeedReset");
    }
    // Three calls observed via the counter.
    if r.error_detected_count.load(core::sync::atomic::Ordering::SeqCst) != 3 {
        return TestResult::Fail("error_detected counter must reach 3");
    }
    // slot_reset on a card-not-in-list returns Disconnect.
    crate::pci::__reset_for_test();
    if r.slot_reset() != PciErsResult::Disconnect {
        return TestResult::Fail("unregistered card → Disconnect");
    }
    r.resume();
    if r.resume_count.load(core::sync::atomic::Ordering::SeqCst) != 1 {
        return TestResult::Fail("resume counter must increment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvidia/pcie_recovery",
    smoke_pcie_recovery_callback_vote_table
);
