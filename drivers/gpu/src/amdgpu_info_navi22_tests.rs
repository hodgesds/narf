//! Each reply against the value Linux `amdgpu_kms.c` derives for a full
//! Navi 22 (RX 6750 XT, 12 GiB, ReBAR on), worked by hand from the cited
//! Linux functions.
use super::*;
use crate::amdgpu::Family;
use crate::amdgpu_discovery::{
    GcInfo, HW_ID_GC, HW_ID_NBIF, HW_ID_SDMA0, HW_ID_SDMA1, HW_ID_VCN, MAX_BASE_ADDRS,
};
use crate::amdgpu_gfx10_topology::{derive, Limits, Sample};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ip(hw_id: u16, v: (u8, u8, u8), base0: u32) -> IpBlock {
    let mut base_addrs = [0; MAX_BASE_ADDRS];
    base_addrs[0] = base0;
    IpBlock {
        hw_id,
        instance: 0,
        major: v.0,
        minor: v.1,
        revision: v.2,
        sub_revision: 0,
        variant: 0,
        base_addrs,
        num_bases: 1,
    }
}
fn gc_table() -> GcInfo {
    crate::amdgpu_gfx10_topology::tests::navi22_gc()
}
const GB_ADDR: u32 = crate::amdgpu_gfx10_topology::tests::GB_ADDR;
const VRAM: u64 = 12 << 30;

/// Version words planted in synthetic headers: ucode_version at +16 and the
/// feature word at +32 (+ RLC v2.1/v2.3 extras).
fn file(ver: u32, feature: u32, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len.max(36)];
    b[16..20].copy_from_slice(&ver.to_le_bytes());
    b[32..36].copy_from_slice(&feature.to_le_bytes());
    b
}
fn firmware() -> Firmware {
    let mut rlc = file(0x60, 0x1, 204);
    rlc[8..12].copy_from_slice(&[2, 0, 2, 0]); // header v2.2
    for (at, v) in [
        (108, 0x11u32),
        (112, 0x12),
        (124, 0x21),
        (128, 0x22),
        (140, 0x31),
        (144, 0x32),
    ] {
        rlc[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    // v2.3 words present in the buffer but not reported by a v2.2 header.
    rlc[172..176].copy_from_slice(&0xdead_u32.to_le_bytes());
    let (me, pfp, ce, mec) = (
        file(64, 35, 44),
        file(98, 35, 44),
        file(37, 35, 44),
        file(104, 35, 44),
    );
    let (sdma, sos, vcn, dmcub) = (
        file(80, 60, 48),
        file(0x0021_0e64, 0x0021_0e64, 44),
        file(0x0310_e002, 7, 32),
        file(0x0101_1900, 9, 40),
    );
    Firmware::parse(&Files {
        me: &me,
        pfp: &pfp,
        ce: &ce,
        mec: &mec,
        mec2: None,
        rlc: &rlc,
        sdma: &sdma,
        sos: &sos,
        vcn: &vcn,
        dmcub: &dmcub,
    })
    .unwrap()
}
fn snap(published: Published) -> Snapshot {
    Snapshot {
        did: 0x73df,
        family: Family::Navi2,
        vram_size: VRAM,
        visible_vram_size: VRAM,
        is_apu: false,
        gc: Some(gc_table()),
        ip_blocks: vec![
            ip(HW_ID_GC, (10, 3, 2), 0x1260),
            ip(HW_ID_SDMA0, (5, 2, 2), 0x1260),
            ip(HW_ID_SDMA1, (5, 2, 2), 0x1260),
            ip(HW_ID_VCN, (3, 0, 0), 0x7800),
            ip(HW_ID_NBIF, (3, 3, 1), 0),
        ],
        navi22: published,
    }
}
fn booted(queues_verified: bool) -> Published {
    let topology = derive(
        Limits::from_gc(&gc_table()).unwrap(),
        &Sample {
            gb_addr_config: GB_ADDR,
            ..Sample::default()
        },
    )
    .unwrap();
    Published {
        topology: Some(topology),
        pci_revision: Some(0xc0),
        boot: Some(Boot {
            firmware: firmware(),
            smc: 0x003a_5a00,
            gfx_mhz: Some((500, 2600)),
            queues_verified,
        }),
        vcn_harvest: Some(2),
        media_rings: 0,
    }
}
fn ask(s: &Snapshot, sub: Submission, q: u32, p: [u32; 4]) -> Result<Vec<u8>, FsError> {
    query_with(s, sub, q, p).expect("Navi22 query routed elsewhere")
}
fn decode<T: Copy + Default>(bytes: &[u8]) -> T {
    assert_eq!(bytes.len(), core::mem::size_of::<T>());
    // SAFETY: exact-sized POD reply; the vector need not be aligned.
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}

fn navi22_dev_info_matches_linux() -> TestResult {
    let s = snap(booted(true));
    let d: uapi::DrmAmdgpuInfoDevice =
        decode(&ask(&s, Submission::NotWired, uapi::AMDGPU_INFO_DEV_INFO, [0; 4]).unwrap());
    let sa = [0x3ff, 0x3ff, 0, 0];
    // Identity: rev_id 0 → external 0x32 (Mesa NAVI22 range 0x32..0x3c);
    // pci_rev 0xc0 = "AMD Radeon RX 6750 XT" in amdgpu.ids.
    let identity = d.device_id == 0x73df
        && d.chip_rev == 0
        && d.external_rev == 0x32
        && d.pci_rev == 0xc0
        && d.family == uapi::AMDGPU_FAMILY_NV;
    // gfx_v10_0_get_cu_info / setup_rb on an unharvested part.
    let topology = d.num_shader_engines == 2
        && d.num_shader_arrays_per_engine == 2
        && d.num_cu_per_sh == 10
        && d.cu_active_number == 40
        && d.cu_bitmap == [sa, sa, [0; 4], [0; 4]]
        && d.cu_ao_bitmap == d.cu_bitmap
        && d.cu_ao_mask == 0xffff_ffff
        && d.enabled_rb_pipes_mask == 0xff
        && d.num_rb_pipes == 8
        && d.num_tcc_blocks == 12
        && d.tcc_disabled_mask == 0
        && d.pa_sc_tile_steering_override == 0;
    // gfx_v10_0_gpu_early_init / sw_init and the GC table.
    let config = d.num_hw_gfx_contexts == 8
        && d.ce_ram_size == 65536
        && d.wave_front_size == 32
        && d.num_shader_visible_vgprs == 1024
        && d.gs_vgt_table_depth == 32
        && d.gs_prim_buffer_depth == 1792
        && d.max_gs_waves_per_vgt == 32
        && d.gc_double_offchip_lds_buf == 1;
    // amdgpu_vm_adjust_size(256K, 9, 3, 48): max_pfn 2^36, RESERVED_TOP
    // 64K + 2M + 2M, RESERVED_BOTTOM 64K, 48-bit hole.
    let va = d.virtual_address_offset == 0x1_0000
        && d.virtual_address_max == 0x8000_0000_0000
        && d.high_va_offset == 0xffff_8000_0000_0000
        && d.high_va_max == 0xffff_ffff_ffbf_0000
        && d.virtual_address_alignment == 4096
        && d.gart_page_size == 4096
        && d.pte_fragment_size == 2 << 20;
    // DPM GFXCLK range in kHz; no flags until submissions run (not FUSION,
    // MCBP/TMZ off by default on 10.3.2, GANG_SUBMIT gated).
    let rest = d.max_engine_clock == 2_600_000
        && d.min_engine_clock == 500_000
        && d.ids_flags == 0
        && d.userq_ip_mask == 0
        && d.shadow_size == 0;
    if !(identity && topology && config && va && rest) {
        return TestResult::Fail("Navi22 DEV_INFO differs from the Linux derivation");
    }
    // Before the cold boot publishes anything: the unknown-harvest zeros,
    // so Mesa rejects the chip instead of compiling for 0 CUs.
    let early: uapi::DrmAmdgpuInfoDevice = decode(
        &ask(
            &snap(Published::default()),
            Submission::NotWired,
            uapi::AMDGPU_INFO_DEV_INFO,
            [0; 4],
        )
        .unwrap(),
    );
    if early.external_rev != 0 || early.cu_active_number != 0 || early.cu_bitmap != [[0; 4]; 4] {
        return TestResult::Fail("unpublished topology reported as known");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/navi22", navi22_dev_info_matches_linux);

fn navi22_hw_ip_and_submission_switch() -> TestResult {
    let s = snap(booted(true));
    let hw = |sub, ip, inst| ask(&s, sub, uapi::AMDGPU_INFO_HW_IP_INFO, [ip, inst, 0, 0]);
    let info = |sub, ip| -> uapi::DrmAmdgpuInfoHwIp { decode(&hw(sub, ip, 0).unwrap()) };
    let gfx = info(Submission::NotWired, uapi::AMDGPU_HW_IP_GFX);
    let dma = info(Submission::NotWired, uapi::AMDGPU_HW_IP_DMA);
    let dec = info(Submission::NotWired, uapi::AMDGPU_HW_IP_VCN_DEC);
    let uvd = info(Submission::NotWired, uapi::AMDGPU_HW_IP_UVD);
    // gfx_v10_0_ip_block 10.0 with discovery 10.3.2; sdma_v5_2 5.2 at
    // 256/4; vcn_v3_0 3.0 at 256/64; absent UVD is an all-zero success.
    if (
        gfx.hw_ip_version_major,
        gfx.hw_ip_version_minor,
        gfx.ip_discovery_version,
    ) != (10, 0, 0x0a0302)
        || (gfx.ib_start_alignment, gfx.ib_size_alignment) != (32, 32)
        || (
            dma.hw_ip_version_major,
            dma.hw_ip_version_minor,
            dma.ip_discovery_version,
        ) != (5, 2, 0x050202)
        || (dma.ib_start_alignment, dma.ib_size_alignment) != (256, 4)
        || (
            dec.hw_ip_version_major,
            dec.ib_start_alignment,
            dec.ib_size_alignment,
        ) != (3, 256, 64)
        || uvd.hw_ip_version_major != 0
        || uvd.ib_start_alignment != 0
    {
        return TestResult::Fail("HW_IP_INFO versions or alignments differ from Linux");
    }
    if hw(Submission::NotWired, uapi::AMDGPU_HW_IP_NUM, 0) != Err(FsError::InvalidData)
        || hw(Submission::NotWired, uapi::AMDGPU_HW_IP_GFX, 1) != Err(FsError::InvalidData)
        || ask(
            &s,
            Submission::NotWired,
            uapi::AMDGPU_INFO_HW_IP_COUNT,
            [uapi::AMDGPU_HW_IP_UVD, 0, 0, 0],
        ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("invalid IP type/instance or absent block accepted");
    }
    let count = |sub, ip| {
        u32_at(
            &ask(&s, sub, uapi::AMDGPU_INFO_HW_IP_COUNT, [ip, 0, 0, 0]).unwrap(),
            0,
        )
    };
    let accel = |sub, p: &Snapshot| {
        u32_at(
            &ask(p, sub, uapi::AMDGPU_INFO_ACCEL_WORKING, [0; 4]).unwrap(),
            0,
        )
    };
    // The production switch: nothing is advertised.
    let n = Submission::NotWired;
    let closed = accel(n, &s) == 0
        && [
            uapi::AMDGPU_HW_IP_GFX,
            uapi::AMDGPU_HW_IP_COMPUTE,
            uapi::AMDGPU_HW_IP_DMA,
        ]
        .iter()
        .all(|&ip| info(n, ip).available_rings == 0 && count(n, ip) == 0);
    // Wired with verified queues: Linux's masks min(entities, rings).
    let w = Submission::Wired;
    let d: uapi::DrmAmdgpuInfoDevice =
        decode(&ask(&s, w, uapi::AMDGPU_INFO_DEV_INFO, [0; 4]).unwrap());
    let open = accel(w, &s) == 1
        && info(w, uapi::AMDGPU_HW_IP_GFX).available_rings == 0x1
        && info(w, uapi::AMDGPU_HW_IP_COMPUTE).available_rings == 0xf
        && info(w, uapi::AMDGPU_HW_IP_DMA).available_rings == 0x3
        && info(w, uapi::AMDGPU_HW_IP_VCN_DEC).available_rings == 0
        && count(w, uapi::AMDGPU_HW_IP_GFX) == 1
        && count(w, uapi::AMDGPU_HW_IP_DMA) == 2
        && d.ids_flags == u64::from(uapi::AMDGPU_IDS_FLAGS_GANG_SUBMIT);
    // Wired but the ring/IB tests failed: still closed.
    let failed = snap(booted(false));
    if !closed || !open || accel(w, &failed) != 0 {
        return TestResult::Fail("ring/ACCEL advertisement does not follow the single switch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_hw_ip_and_submission_switch
);

fn navi22_fw_version_reports_the_loaded_set() -> TestResult {
    let s = snap(booted(true));
    let fw = |t, inst, idx| {
        ask(
            &s,
            SUBMISSION,
            uapi::AMDGPU_INFO_FW_VERSION,
            [t, inst, idx, 0],
        )
    };
    let v = |t, idx| -> (u32, u32) {
        let b = fw(t, 0, idx).unwrap();
        (u32_at(&b, 0), u32_at(&b, 1))
    };
    let ok = v(uapi::AMDGPU_INFO_FW_GFX_ME, 0) == (64, 35)
        && v(uapi::AMDGPU_INFO_FW_GFX_PFP, 0) == (98, 35)
        && v(uapi::AMDGPU_INFO_FW_GFX_CE, 0) == (37, 35)
        && v(uapi::AMDGPU_INFO_FW_GFX_MEC, 0) == (104, 35)
        // Absent MEC2: Linux's zero-initialised mec2 version.
        && v(uapi::AMDGPU_INFO_FW_GFX_MEC, 1) == (0, 0)
        && v(uapi::AMDGPU_INFO_FW_GFX_RLC, 0) == (0x60, 1)
        && v(uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_CNTL, 0) == (0x11, 0x12)
        && v(uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_GPM_MEM, 0) == (0x21, 0x22)
        && v(uapi::AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_SRM_MEM, 0) == (0x31, 0x32)
        // RLCP is a v2.3 field; this header is v2.2.
        && v(uapi::AMDGPU_INFO_FW_GFX_RLCP, 0) == (0, 0)
        && v(uapi::AMDGPU_INFO_FW_SDMA, 0) == (80, 60)
        && v(uapi::AMDGPU_INFO_FW_SDMA, 1) == (80, 60)
        && v(uapi::AMDGPU_INFO_FW_SOS, 0) == (0x0021_0e64, 0x0021_0e64)
        && v(uapi::AMDGPU_INFO_FW_SMC, 0) == (0x003a_5a00, 0)
        && v(uapi::AMDGPU_INFO_FW_VCN, 0) == (0x0310_e002, 0)
        && v(uapi::AMDGPU_INFO_FW_DMCUB, 0) == (0x0101_1900, 0)
        && v(uapi::AMDGPU_INFO_FW_VCE, 0) == (0, 0)
        && v(uapi::AMDGPU_INFO_FW_ASD, 0) == (0, 0)
        && v(uapi::AMDGPU_INFO_FW_MES, 0) == (0, 0);
    let refused = fw(uapi::AMDGPU_INFO_FW_GFX_MEC, 0, 2) == Err(FsError::InvalidData)
        && fw(uapi::AMDGPU_INFO_FW_SDMA, 0, 2) == Err(FsError::InvalidData)
        && fw(uapi::AMDGPU_INFO_FW_GFX_ME, 1, 0) == Err(FsError::InvalidData)
        && fw(uapi::AMDGPU_INFO_FW_TA, 0, 0) == Err(FsError::InvalidData)
        && ask(
            &snap(Published::default()),
            SUBMISSION,
            uapi::AMDGPU_INFO_FW_VERSION,
            [uapi::AMDGPU_INFO_FW_GFX_ME, 0, 0, 0],
        ) == Err(FsError::InvalidData);
    if !ok || !refused {
        return TestResult::Fail("FW_VERSION differs from the Linux header fields");
    }
    if Firmware::parse(&Files {
        me: &[0; 20],
        pfp: &[],
        ce: &[],
        mec: &[],
        mec2: None,
        rlc: &[0; 12],
        sdma: &[],
        sos: &[],
        vcn: &[],
        dmcub: &[],
    })
    .is_ok()
    {
        return TestResult::Fail("truncated firmware header produced versions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_fw_version_reports_the_loaded_set
);

fn navi22_read_mmr_reg_serves_gb_addr_config() -> TestResult {
    let s = snap(booted(true));
    let mmr = |s: &Snapshot, off, count, inst| {
        ask(
            s,
            SUBMISSION,
            uapi::AMDGPU_INFO_READ_MMR_REG,
            [off, count, inst, 0],
        )
    };
    // Mesa's ac_drm_query_gpu_info: 0x263e, 1, 0xffffffff.
    let ok = mmr(&s, 0x263e, 1, 0xffff_ffff) == Ok(GB_ADDR.to_le_bytes().to_vec())
        && mmr(&s, 0x263e, 0, 0) == Ok(Vec::new())
        // GB_ADDR_CONFIG is not GRBM-indexed; a valid SE/SH select is fine.
        && mmr(&s, 0x263e, 1, 1 | (1 << 8)) == Ok(GB_ADDR.to_le_bytes().to_vec());
    let refused = mmr(&s, 0x263e, 2, 0xffff_ffff) == Err(FsError::BadAddress)
        && mmr(&s, 0x2004, 1, 0xffff_ffff) == Err(FsError::BadAddress)
        && mmr(&s, 0x263e, 1, 4) == Err(FsError::InvalidData)
        && mmr(&s, 0x263e, 1, 2 << 8) == Err(FsError::InvalidData)
        && mmr(&s, 0x263e, 129, 0xffff_ffff) == Err(FsError::InvalidData)
        && mmr(&snap(Published::default()), 0x263e, 1, 0xffff_ffff) == Err(FsError::InvalidData);
    if !ok || !refused {
        return TestResult::Fail("READ_MMR_REG differs from nv_read_register");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_read_mmr_reg_serves_gb_addr_config
);

fn navi22_memory_matches_linux_heaps() -> TestResult {
    let usable = VRAM - (8 << 20);
    let check = |visible: u64| -> bool {
        let s = Snapshot {
            visible_vram_size: visible,
            ..snap(booted(true))
        };
        let m: uapi::DrmAmdgpuMemoryInfo =
            decode(&ask(&s, SUBMISSION, uapi::AMDGPU_INFO_MEMORY, [0; 4]).unwrap());
        let g: uapi::DrmAmdgpuInfoVramGtt =
            decode(&ask(&s, SUBMISSION, uapi::AMDGPU_INFO_VRAM_GTT, [0; 4]).unwrap());
        let cpu = visible.min(usable);
        m.vram.total_heap_size == VRAM
            && m.vram.usable_heap_size == usable
            && m.vram.max_allocation == usable * 3 / 4
            && m.cpu_accessible_vram.total_heap_size == visible
            && m.cpu_accessible_vram.usable_heap_size == cpu
            && m.cpu_accessible_vram.max_allocation == cpu * 3 / 4
            && m.gtt.total_heap_size == 0
            && (g.vram_size, g.vram_cpu_accessible_size, g.gtt_size) == (usable, cpu, 0)
    };
    // ReBAR (all 12 GiB visible) and the 256 MiB fallback aperture.
    if !check(VRAM) || !check(256 << 20) {
        return TestResult::Fail("MEMORY/VRAM_GTT differ from amdgpu_info_ioctl");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_memory_matches_linux_heaps
);

fn info_navi22_acceleration_is_opt_in_per_boot() -> TestResult {
    set_accel(false);
    let off = submission() == Submission::NotWired && drm_version() == (3, 0, 0);
    set_accel(true);
    let on = submission() == SUBMISSION && drm_version() == (3, 64, 0);
    set_accel(false);
    if !off || !on {
        return TestResult::Fail("native submission advertised without amdgpu.navi22_accel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    info_navi22_acceleration_is_opt_in_per_boot
);

/// The RX 6750 XT's media answers: discovery lists VCN 3.0.0 and 3.0.1, the
/// harvest table removes VCN1. HW_IP_COUNT is `num_vcn_inst` (2, harvested
/// included), the rings follow the verified client media rings and the
/// switch, and VIDEO_CAPS reports the VCN0 tables (AV1 decode present).
fn navi22_media_hw_ip_and_video_caps_follow_linux() -> TestResult {
    let mut published = booted(true);
    published.media_rings = 0b1011; // dec, enc0, JPEG
    let mut s = snap(published);
    let mut vcn1 = ip(HW_ID_VCN, (3, 0, 1), 0x7b00);
    vcn1.instance = 1;
    s.ip_blocks.push(vcn1);
    let info = |s: &Snapshot, sub, ip| -> uapi::DrmAmdgpuInfoHwIp {
        decode(&ask(s, sub, uapi::AMDGPU_INFO_HW_IP_INFO, [ip, 0, 0, 0]).unwrap())
    };
    let count = |s: &Snapshot, sub, ip| {
        u32_at(
            &ask(s, sub, uapi::AMDGPU_INFO_HW_IP_COUNT, [ip, 0, 0, 0]).unwrap(),
            0,
        )
    };
    let (w, n) = (Submission::Wired, Submission::NotWired);
    let dec = info(&s, w, uapi::AMDGPU_HW_IP_VCN_DEC);
    let enc = info(&s, w, uapi::AMDGPU_HW_IP_VCN_ENC);
    let jpeg = info(&s, w, uapi::AMDGPU_HW_IP_VCN_JPEG);
    let wired = dec.available_rings == 1
        && enc.available_rings == 1
        && jpeg.available_rings == 1
        && (dec.ib_start_alignment, dec.ib_size_alignment) == (256, 64)
        && (enc.ib_start_alignment, enc.ib_size_alignment) == (256, 4)
        && (jpeg.ib_start_alignment, jpeg.ib_size_alignment) == (256, 64)
        && dec.ip_discovery_version == 0x030000
        && count(&s, w, uapi::AMDGPU_HW_IP_VCN_DEC) == 2
        && count(&s, w, uapi::AMDGPU_HW_IP_VCN_ENC) == 2
        && count(&s, w, uapi::AMDGPU_HW_IP_VCN_JPEG) == 1;
    // Without amdgpu.navi22_accel (NotWired) nothing media is offered.
    let closed = [
        uapi::AMDGPU_HW_IP_VCN_DEC,
        uapi::AMDGPU_HW_IP_VCN_ENC,
        uapi::AMDGPU_HW_IP_VCN_JPEG,
    ]
    .iter()
    .all(|&ip| info(&s, n, ip).available_rings == 0 && count(&s, n, ip) == 0);
    // Rings that did not pass their tests are not advertised.
    let mut partial = s.clone();
    partial.navi22.media_rings = 0b0001;
    let partial_ok = info(&partial, w, uapi::AMDGPU_HW_IP_VCN_ENC).available_rings == 0
        && info(&partial, w, uapi::AMDGPU_HW_IP_VCN_JPEG).available_rings == 0
        && info(&partial, w, uapi::AMDGPU_HW_IP_VCN_DEC).available_rings == 1;
    if !wired || !closed || !partial_ok {
        return TestResult::Fail("media HW_IP_INFO/COUNT differ from amdgpu_hw_ip_info");
    }
    let caps = |s: &Snapshot, kind| -> uapi::DrmAmdgpuInfoVideoCaps {
        decode(&ask(s, n, uapi::AMDGPU_INFO_VIDEO_CAPS, [kind, 0, 0, 0]).unwrap())
    };
    let av1 = uapi::AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1 as usize;
    let decode_caps = caps(&s, uapi::AMDGPU_INFO_VIDEO_CAPS_DECODE);
    let encode_caps = caps(&s, uapi::AMDGPU_INFO_VIDEO_CAPS_ENCODE);
    let mut vcn0_gone = s.clone();
    vcn0_gone.navi22.vcn_harvest = Some(1);
    let mut both = s.clone();
    both.navi22.vcn_harvest = Some(3);
    if decode_caps.codec_info[av1].valid != 1
        || decode_caps
            .codec_info
            .iter()
            .filter(|c| c.valid == 1)
            .count()
            != 8
        || encode_caps
            .codec_info
            .iter()
            .filter(|c| c.valid == 1)
            .count()
            != 2
        || caps(&vcn0_gone, uapi::AMDGPU_INFO_VIDEO_CAPS_DECODE).codec_info[av1].valid != 0
        || ask(
            &both,
            n,
            uapi::AMDGPU_INFO_VIDEO_CAPS,
            [uapi::AMDGPU_INFO_VIDEO_CAPS_DECODE, 0, 0, 0],
        ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("VIDEO_CAPS ignores the published VCN harvest");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_media_hw_ip_and_video_caps_follow_linux
);
