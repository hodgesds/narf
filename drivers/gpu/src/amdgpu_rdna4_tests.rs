//! RDNA4 identity, per-die policy and the shared test profiles.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A synthetic board the register-model tests run against. Each turns a
/// Navi48 descriptor into the named board by changing only what discovery,
/// the PCI header and harvesting would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// RX 9070 XT: GC 12.0.1, MP 14.0.3, SDMA 7.0.1, full 4 SE × 2 SA × 8 CU.
    Navi48,
    /// RX 9070 GRE-like: Navi48 with a quarter of the arrays fused off and
    /// a 192-bit (12-channel) memory bus.
    Navi48Gre,
    /// RX 9060 XT: GC 12.0.0, MP 14.0.2, SDMA 7.0.0, 2 SE, 128-bit bus.
    Navi44,
}
impl Profile {
    pub(crate) const ALL: [Self; 3] = [Self::Navi48, Self::Navi48Gre, Self::Navi44];
    pub(crate) fn chip(self) -> Rdna4Chip {
        match self {
            Self::Navi48 | Self::Navi48Gre => Rdna4Chip::Navi48,
            Self::Navi44 => Rdna4Chip::Navi44,
        }
    }
    pub(crate) fn did(self) -> u16 {
        match self {
            Self::Navi48 | Self::Navi48Gre => 0x7550,
            Self::Navi44 => 0x7590,
        }
    }
    /// DALSMC `GetNumUmcChannels` for the board's bus (16-bit channels).
    pub(crate) fn umc_channels(self) -> u32 {
        match self {
            Self::Navi48 => 16,
            Self::Navi48Gre => 12,
            Self::Navi44 => 8,
        }
    }
    pub(crate) fn vram_bytes(self) -> u64 {
        match self {
            Self::Navi48 | Self::Navi44 => 16 << 30,
            Self::Navi48Gre => 12 << 30,
        }
    }
    /// Discovery's GC table maxima: shader engines (2 SAs × 8 CUs each).
    pub(crate) fn shader_engines(self) -> u32 {
        match self {
            Self::Navi48 | Self::Navi48Gre => 4,
            Self::Navi44 => 2,
        }
    }
    /// Rewrite a Navi48 descriptor into this board: PCI id, every discovered
    /// GC/MP0/MP1/SDMA0 version, and the GC table's maxima. Blocks the
    /// descriptor lacks are left absent.
    pub(crate) fn apply(self, gpu: &mut AmdGpu) {
        gpu.chip.did = self.did();
        let (gc, mp, sdma) = match self.chip() {
            Rdna4Chip::Navi48 => (1, 3, 1),
            Rdna4Chip::Navi44 => (0, 2, 0),
        };
        for b in &mut gpu.ip_blocks {
            match b.hw_id {
                ip::HW_ID_GC if (b.major, b.minor) == (12, 0) => b.revision = gc,
                ip::HW_ID_MP0 | ip::HW_ID_MP1 if (b.major, b.minor) == (14, 0) => b.revision = mp,
                ip::HW_ID_SDMA0 if (b.major, b.minor) == (7, 0) => b.revision = sdma,
                _ => {}
            }
        }
        if let Some(gc) = gpu.gc_info.as_mut() {
            gc.num_se = self.shader_engines();
            gc.num_sa_per_se = 2;
            gc.num_cu_per_sa = 8;
        }
    }
}

fn rdna4_identity_follows_discovered_gc_not_pci_id() -> TestResult {
    let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    for profile in Profile::ALL {
        let mut g = crate::amdgpu_navi48_firmware::tests::gpu();
        profile.apply(&mut g);
        if Rdna4Chip::of(&g) != Some(profile.chip()) {
            return TestResult::Fail("profile die not identified from GC");
        }
    }
    // An unlisted board id (RX 9060, OEM) with Navi44 discovery is Navi44.
    gpu.chip.did = 0x7599;
    gpu.ip_blocks[0].revision = 0;
    if Rdna4Chip::of(&gpu) != Some(Rdna4Chip::Navi44) {
        return TestResult::Fail("unlisted RDNA4 id refused");
    }
    for (case, refuse) in [
        (0, "GC 12.0.2 accepted"),
        (1, "duplicate GC accepted"),
        (2, "non-RDNA4 family accepted"),
        (3, "foreign vendor accepted"),
    ] {
        let mut g = crate::amdgpu_navi48_firmware::tests::gpu();
        match case {
            0 => g.ip_blocks[0].revision = 2,
            1 => g.ip_blocks.push(g.ip_blocks[0]),
            2 => g.chip.family = Family::Navi3,
            _ => g.chip.vid = 0x10de,
        }
        if Rdna4Chip::of(&g).is_some() {
            return TestResult::Fail(refuse);
        }
    }
    for d in KNOWN_DEVICES {
        if known_device(d.did) != Some(d)
            || crate::amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, d.did)
                .is_none_or(|c| c.family != Family::Navi4 || c.asic != d.chip.asic())
        {
            return TestResult::Fail("known RDNA4 id not in the probe table");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4",
    rdna4_identity_follows_discovered_gc_not_pci_id
);

fn rdna4_per_die_policy_matches_linux() -> TestResult {
    use Rdna4Chip::*;
    // soc24_common_early_init / dal_asic_id.h.
    if Navi48.external_rev(0) != 0x50
        || Navi44.external_rev(1) != 0x41
        || Navi48.gfx_target_version() != 120001
        || Navi44.gfx_target_version() != 120000
        || !Navi48.jpeg_dpg()
        || Navi44.jpeg_dpg()
    {
        return TestResult::Fail("soc24 per-GC identity");
    }
    // dcn401_resource.c / dcn401_clk_mgr.c.
    if Navi48.dcc_plane_width_limit() != 0
        || Navi44.dcc_plane_width_limit() != 7680
        || Navi48.idle_dpm_min_smu() != 0x681800
        || Navi44.idle_dpm_min_smu() != 0x661300
        || Navi48.df_throttle_min_smu().is_some()
        || Navi44.df_throttle_min_smu() != Some(0x663500)
    {
        return TestResult::Fail("DCN401 per-ASIC caps");
    }
    let mib = |m: u64| m << 20;
    if mall_bytes(Navi48, 16) != mib(64)
        || mall_bytes(Navi48, 12) != mib(32)
        || mall_bytes(Navi48, 32) != mib(64)
        || mall_bytes(Navi44, 8) != mib(32)
        || mall_bytes(Navi44, 16) != mib(32)
        || mall_bytes(Navi44, 1) != 0
    {
        return TestResult::Fail("MALL channel arithmetic");
    }
    // Bits above DCN401's four are ignored, as read_pipe_fuses masks them
    // (DC_FULL_DIS included: Linux's check of it after the mask never fires).
    if PipePool::from_fuses(0x1_1100) != PipePool::FULL
        || PipePool::from_fuses(0x12) != PipePool::from_fuses(2)
    {
        return TestResult::Fail("CC_DC_PIPE_DIS bits above the four pipes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/rdna4", rdna4_per_die_policy_matches_linux);

fn umc(instance: u8) -> IpBlock {
    IpBlock {
        hw_id: ip::HW_ID_UMC,
        instance,
        major: 8,
        minor: 14,
        revision: 0,
        sub_revision: 0,
        variant: 0,
        base_addrs: [0; ip::MAX_BASE_ADDRS],
        num_bases: 1,
    }
}
/// A discovery blob carrying a harvest table (listing `harvested` UMC
/// instances) and a MALL_INFO table of `version` with `words` after its
/// header.
fn mall_blob(version: u16, words: &[u32], harvested: &[u8]) -> alloc::vec::Vec<u8> {
    let mut blob = alloc::vec![0u8; 1024];
    blob[..4].copy_from_slice(&ip::BINARY_SIGNATURE.to_le_bytes());
    let harvest = 512usize;
    blob[harvest..harvest + 4].copy_from_slice(&ip::HARVEST_TABLE_SIGNATURE.to_le_bytes());
    for (k, &instance) in harvested.iter().enumerate() {
        let at = harvest + 8 + k * 4;
        blob[at..at + 2].copy_from_slice(&ip::HW_ID_UMC.to_le_bytes());
        blob[at + 2] = instance;
    }
    let sum = blob[harvest..harvest + 136]
        .iter()
        .fold(0u16, |s, &b| s.wrapping_add(u16::from(b)));
    let entry = 12 + ip::TABLE_HARVEST_INFO * 8;
    blob[entry..entry + 2].copy_from_slice(&(harvest as u16).to_le_bytes());
    blob[entry + 2..entry + 4].copy_from_slice(&sum.to_le_bytes());
    let mall = 768usize;
    let entry = 12 + ip::TABLE_MALL_INFO * 8;
    blob[entry..entry + 2].copy_from_slice(&(mall as u16).to_le_bytes());
    blob[mall..mall + 4].copy_from_slice(&0x4C4C_414Du32.to_le_bytes());
    blob[mall + 4..mall + 6].copy_from_slice(&version.to_le_bytes());
    for (k, w) in words.iter().enumerate() {
        let at = mall + 12 + k * 4;
        blob[at..at + 4].copy_from_slice(&w.to_le_bytes());
    }
    blob
}
/// `nbif_v6_3_1_get_rev_id` / `nbio_v7_7_get_rev_id` and
/// `amdgpu_discovery_get_mall_info`: DEV_INFO's `chip_rev` comes from the
/// NBIO strap, never the PCI revision, and `mall_size` from discovery.
fn rdna4_rev_id_strap_and_mall_info_match_linux() -> TestResult {
    let gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    let mut blocks = gpu.ip_blocks.clone();
    let mut nbio = umc(0);
    (nbio.hw_id, nbio.major, nbio.minor, nbio.revision) = (ip::HW_ID_NBIF, 6, 3, 1);
    nbio.base_addrs = [0, 0x14, 0xd20, 0, 0];
    nbio.num_bases = 3;
    blocks.push(nbio);
    for (version, reg) in [
        ((6, 3, 1), 0x1c),
        ((7, 11, 4), 0x21),
        ((7, 11, 5), 0x21),
        ((7, 7, 0), 0x15),
        ((7, 7, 1), 0x15),
    ] {
        let last = blocks.last_mut().unwrap();
        (last.major, last.minor, last.revision) = version;
        if rev_id_strap(&blocks) != Some((0xd20 + reg) * 4) {
            return TestResult::Fail("RCC_DEV0_EPF0_STRAP0 per NBIO version");
        }
    }
    let last = blocks.last_mut().unwrap();
    (last.major, last.minor, last.revision) = (4, 3, 0);
    if rev_id_strap(&blocks).is_some() {
        return TestResult::Fail("strap read on an NBIO without nbif_v6_3_1/nbio_v7_7");
    }
    let last = blocks.last_mut().unwrap();
    (last.major, last.minor, last.revision, last.num_bases) = (6, 3, 1, 2);
    if rev_id_strap(&blocks).is_some() {
        return TestResult::Fail("strap read without BASE_IDX 2");
    }
    // Bits 27:24 only: a 0xc8 PCI revision can never be the strap value.
    if rev_id(0x0300_0000) != 3 || rev_id(0xF1FF_FFFF) != 1 || rev_id(0x00c8) != 0 {
        return TestResult::Fail("STRAP_ATI_REV_ID field");
    }

    let umcs: alloc::vec::Vec<_> = (0..16).map(umc).collect();
    let mib = |m: u64| m << 20;
    // v2: mall_size_per_umc * num_umc, with harvested UMCs removed.
    if ip::mall_size(&mall_blob(2, &[4 << 20], &[]), &umcs) != mib(64)
        || ip::mall_size(&mall_blob(2, &[4 << 20], &[12, 13, 14, 15]), &umcs) != mib(48)
        // A harvest count not below num_umc leaves num_umc alone.
        || ip::mall_size(&mall_blob(2, &[4 << 20], &[0, 1]), &umcs[..2]) != mib(8)
        // Instances >= 32 are "bogus" and not counted.
        || ip::mall_size(&mall_blob(2, &[4 << 20], &[40]), &umcs) != mib(64)
    {
        return TestResult::Fail("MALL_INFO v2 size");
    }
    // v1: per-UMC, doubled where m_s_present, halved where m_half_use.
    if ip::mall_size(&mall_blob(1, &[4 << 20, 0b01, 0b10], &[]), &umcs[..4])
        != mib(4 * 2 + 2 + 4 + 4)
    {
        return TestResult::Fail("MALL_INFO v1 size");
    }
    // Unhandled major version, no table, no blob: 0.
    let mut absent = mall_blob(2, &[4 << 20], &[]);
    let entry = 12 + ip::TABLE_MALL_INFO * 8;
    absent[entry..entry + 2].copy_from_slice(&0u16.to_le_bytes());
    if ip::mall_size(&mall_blob(3, &[4 << 20], &[]), &umcs) != 0
        || ip::mall_size(&absent, &umcs) != 0
        || ip::mall_size(&[0; 64], &umcs) != 0
    {
        return TestResult::Fail("MALL_INFO absent or unhandled");
    }
    // A corrupt harvest table fails discovery in Linux: no size.
    let mut corrupt = mall_blob(2, &[4 << 20], &[]);
    corrupt[512 + 8] ^= 1;
    if ip::mall_size(&corrupt, &umcs) != 0 {
        return TestResult::Fail("MALL size from a blob that fails discovery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4",
    rdna4_rev_id_strap_and_mall_info_match_linux
);

fn rdna4_firmware_table_selects_by_discovery_and_kicker() -> TestResult {
    let n48 = FirmwareSet::select((12, 0, 1), 3, 1, false).unwrap();
    let n44 = FirmwareSet::select((12, 0, 0), 2, 0, false).unwrap();
    if n48.gc.pfp != "amdgpu/gc_12_0_1_pfp.bin"
        || n44.gc.pfp != "amdgpu/gc_12_0_0_pfp.bin"
        || n44.gc.uni_mes != "amdgpu/gc_12_0_0_uni_mes.bin"
        || n44.rlc() != "amdgpu/gc_12_0_0_rlc.bin"
        || n44.imu() != "amdgpu/gc_12_0_0_imu.bin"
        || n44.sos() != "amdgpu/psp_14_0_2_sos.bin"
        || n44.smu() != "amdgpu/smu_14_0_2.bin"
        || n44.sdma != "amdgpu/sdma_7_0_0.bin"
        || n48.sos() != "amdgpu/psp_14_0_3_sos.bin"
        || n48.smu() != "amdgpu/smu_14_0_3.bin"
        || n48.sdma != "amdgpu/sdma_7_0_1.bin"
    {
        return TestResult::Fail("per-die firmware names");
    }
    if !is_kicker(0x7551, 0xc8) || is_kicker(0x7551, 0xc0) || is_kicker(0x7550, 0xc8) {
        return TestResult::Fail("kicker device list");
    }
    let k = FirmwareSet::select((12, 0, 1), 3, 1, true).unwrap();
    if k.rlc() != "amdgpu/gc_12_0_1_rlc_kicker.bin"
        || k.imu() != "amdgpu/gc_12_0_1_imu_kicker.bin"
        || k.sos() != "amdgpu/psp_14_0_3_sos_kicker.bin"
        || k.smu() != "amdgpu/smu_14_0_3_kicker.bin"
        // Kicker builds replace only those four.
        || k.gc.pfp != n48.gc.pfp
        || k.sdma != n48.sdma
    {
        return TestResult::Fail("kicker firmware names");
    }
    // No kicker image exists for GC 12.0.0 / MP 14.0.2.
    if FirmwareSet::select((12, 0, 0), 2, 0, true).is_some()
        || FirmwareSet::select((12, 0, 2), 3, 1, false).is_some()
        || FirmwareSet::select((12, 0, 1), 4, 1, false).is_some()
        || FirmwareSet::select((12, 0, 1), 3, 2, false).is_some()
    {
        return TestResult::Fail("unloadable firmware set selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4",
    rdna4_firmware_table_selects_by_discovery_and_kicker
);

/// Shared with tests/rdna4_family/check.sh, which regenerates both from the
/// Linux tree.
const POLICY: &str = include_str!("../tests/rdna4_family/policy.txt");
const FIRMWARE: &str = include_str!("../tests/rdna4_family/firmware.txt");
/// Linux's resource pool per CC_DC_PIPE_DIS value (pipe_pool.c).
const PIPE_POOL: &str = include_str!("../tests/rdna4_family/pipe_pool.txt");

/// The pool line pipe_pool.c prints for `fuses`.
fn pool_line(fuses: u32) -> alloc::string::String {
    use alloc::{format, string::String, vec::Vec};
    let pool = PipePool::from_fuses(fuses);
    let list = |f: &dyn Fn(u8) -> u8| {
        pool.pipes()
            .map(|p| format!("{}", f(p)))
            .collect::<Vec<String>>()
            .join(",")
    };
    let hw = list(&|p| pool.hw(p));
    let fuses = if fuses == 0 {
        String::from("0")
    } else {
        format!("{fuses:#x}")
    };
    format!(
        "{fuses} pipes={n} mpccs={mpccs} streams={n} hubp={hw} dpp={hw} opp={hw} tg={hw} abm={hw} \
         mpcc={hw} dsc={dsc}",
        n = pool.count(),
        mpccs = DCN401_PIPES,
        dsc = list(&|p| pool.dsc(p)),
    )
}

fn rdna4_pipe_pool_matches_linux_harvesting() -> TestResult {
    let lines: alloc::vec::Vec<&str> = PIPE_POOL
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    if lines.len() != 16 {
        return TestResult::Fail("pipe_pool.txt lists every CC_DC_PIPE_DIS value");
    }
    for (fuses, line) in (0..16u32).zip(lines) {
        if pool_line(fuses) != line {
            return TestResult::Fail("PipePool differs from Linux's resource pool");
        }
        // The inverse map: every surviving instance names its pipe index,
        // and no fused one does.
        let pool = PipePool::from_fuses(fuses);
        for inst in 0..4u8 {
            let fused = fuses & 1 << inst != 0;
            match pool.pipe(inst) {
                Some(p) if !fused && pool.hw(p) == inst => {}
                None if fused => {}
                _ => return TestResult::Fail("PipePool::pipe is not hw's inverse"),
            }
        }
        if pool.hw_mask(pool.all()) != 0xf & !(fuses as u8)
            || pool.pipe_mask(0xf) != pool.all()
            || pool.pipe_mask(fuses as u8) != 0
        {
            return TestResult::Fail("PipePool masks");
        }
        // Pipe indices past the pool continue over the fused instances.
        let mut seen = 0u8;
        for p in 0..4u8 {
            seen |= 1 << pool.hw(p);
        }
        if seen != 0xf {
            return TestResult::Fail("PipePool::hw is not a permutation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4",
    rdna4_pipe_pool_matches_linux_harvesting
);

fn rdna4_tables_match_linux_policy_and_firmware() -> TestResult {
    use alloc::{format, string::String, vec::Vec};
    let gc = |die: Rdna4Chip| {
        let (a, b, c) = die.gc_version();
        format!("{a}.{b}.{c}")
    };
    let mut expected: Vec<String> = Vec::new();
    for die in Rdna4Chip::ALL {
        let v = gc(die);
        expected.push(format!(
            "external_rev_offset.{v}={:#x}",
            die.external_rev(0)
        ));
        expected.push(format!("jpeg_dpg.{v}={}", u8::from(die.jpeg_dpg())));
        if die.dcc_plane_width_limit() != 0 {
            expected.push(format!(
                "dcc_plane_width_limit.{v}={}",
                die.dcc_plane_width_limit()
            ));
        }
        if let Some(smu) = die.df_throttle_min_smu() {
            expected.push(format!("df_throttle_min_smu.{v}={smu:#x}"));
        }
        expected.push(format!(
            "idle_dpm_min_smu.{v}={:#x}",
            die.idle_dpm_min_smu()
        ));
        expected.push(format!(
            "mall_channel_limit.{v}={}",
            die.mall_channel_limit()
        ));
        expected.push(format!(
            "gfx_target_version.{v}={}",
            die.gfx_target_version()
        ));
    }
    for &(did, rev) in KICKER_DEVICES {
        expected.push(format!("kicker={did:#06x},{rev:#04x}"));
    }
    for (table, rows) in [
        ("gc_12_0", &crate::amdgpu_gfx12_setup::GOLDEN[..]),
        ("gc_12_0_rev0", &crate::amdgpu_gfx12_setup::GOLDEN_REV0[..]),
    ] {
        for &(index, reg, mask, value) in rows {
            expected.push(format!("{table}.{index}.{reg:#x}={mask:#x},{value:#x}"));
        }
    }
    expected.push(format!(
        "smu_driver_if={:#x}",
        crate::amdgpu_smu_navi48::DRIVER_INTERFACE
    ));
    let mut linux: Vec<String> = POLICY
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    linux.sort();
    expected.sort();
    if linux != expected {
        return TestResult::Fail("amdgpu_rdna4 policy differs from Linux (policy.txt)");
    }
    // Every image the tables can name, over every die, MP/SDMA revision and
    // kicker choice, against Linux's MODULE_FIRMWARE list. TOC images are
    // RLC-backdoor autoload only; PSP loading never asks for them.
    let mut named: Vec<&str> = alloc::vec![
        VCN_5_0_0_FW,
        DCN_4_0_1_DMCUB_FW,
        SDMA_7_0_0_FW,
        SDMA_7_0_1_FW
    ];
    for g in [GC_12_0_0_FW, GC_12_0_1_FW] {
        named.extend([g.pfp, g.me, g.mec, g.rlc, g.imu, g.mes, g.mes1, g.uni_mes]);
        named.extend(g.rlc_kicker.into_iter().chain(g.imu_kicker));
    }
    for m in [MP_14_0_2_FW, MP_14_0_3_FW] {
        named.extend([m.sos, m.ta, m.smu]);
        named.extend(
            m.sos_kicker
                .into_iter()
                .chain(m.ta_kicker)
                .chain(m.smu_kicker),
        );
    }
    named.sort_unstable();
    let mut declared: Vec<&str> = FIRMWARE
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.ends_with("_toc.bin"))
        .collect();
    declared.sort_unstable();
    if named != declared {
        return TestResult::Fail("amdgpu_rdna4 firmware names differ from Linux (firmware.txt)");
    }
    // The PSP SOS names the boot path opens are the table's.
    if crate::amdgpu_psp_firmware::PSP14_0_2_SOS != MP_14_0_2_FW.sos
        || crate::amdgpu_psp_firmware::PSP14_0_3_SOS != MP_14_0_3_FW.sos
        || Some(crate::amdgpu_psp_firmware::PSP14_0_3_SOS_KICKER) != MP_14_0_3_FW.sos_kicker
    {
        return TestResult::Fail("PSP boot SOS names diverge from the RDNA4 table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/rdna4",
    rdna4_tables_match_linux_policy_and_firmware
);
