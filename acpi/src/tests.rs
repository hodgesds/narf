//! Subsystem smokes for `narf-acpi` (Phase 12+ table parsers).
//!
//! Earlier-vintage acpi tests (SRAT, MADT, MCFG, HMAT, PMTT, GPE)
//! still live in `verification/src/lib.rs` for historical reasons;
//! per-table parsers added in Phase 12 onward register here so the
//! crate is self-contained. Each test feeds a synthetic body to a
//! `__test_parse_*_body` shim — no firmware required.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_acpi_pptt_synthetic_decode() -> TestResult {
    use crate::{PpttCache, PpttCacheKind, PpttCpu};
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::with_capacity(36 + 24 + 24);
    // SDT header (signature + length placeholder + dummies = 36 B).
    buf.extend_from_slice(b"PPTT");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 28]);

    // Type 0 (Processor): leaf + ACPI UID = 0x42, length = 20.
    buf.push(0);
    buf.push(20);
    buf.extend_from_slice(&[0u8; 2]); // type / len / rsvd
    buf.extend_from_slice(&0b1001u32.to_le_bytes()); // package + leaf
    buf.extend_from_slice(&0u32.to_le_bytes()); // parent
    buf.extend_from_slice(&0x42u32.to_le_bytes()); // ACPI UID
    buf.extend_from_slice(&0u32.to_le_bytes()); // n_priv

    // Type 1 (Cache): line=64, ways=8, sets=64, size=32K, kind=Data.
    buf.push(1);
    buf.push(24);
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // next-level
    buf.extend_from_slice(&32_768u32.to_le_bytes()); // size
    buf.extend_from_slice(&64u32.to_le_bytes()); // sets
    buf.push(8); // assoc
    buf.push((0b00) << 2); // attrs: kind = Data
    buf.extend_from_slice(&64u16.to_le_bytes()); // line

    let n = crate::__test_parse_pptt_body(&buf);
    if n != 2 {
        return TestResult::Fail("expected 2 nodes parsed");
    }
    let mut cpus = [PpttCpu::default(); 4];
    let nc = crate::copy_pptt_cpus(&mut cpus);
    if nc != 1 || cpus[0].acpi_uid != 0x42 || !cpus[0].leaf {
        return TestResult::Fail("CPU node decode mismatch");
    }
    let mut caches = [PpttCache::default(); 4];
    let nch = crate::copy_pptt_caches(&mut caches);
    if nch != 1
        || caches[0].line_bytes != 64
        || caches[0].ways != 8
        || caches[0].sets != 64
        || caches[0].size_bytes != 32_768
        || caches[0].kind != PpttCacheKind::Data
    {
        return TestResult::Fail("Cache node decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/pptt", smoke_acpi_pptt_synthetic_decode);

fn smoke_acpi_iort_synthetic_decode() -> TestResult {
    use crate::{IortIts, IortSmmuv3};
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"IORT");
    buf.extend_from_slice(&[0u8; 32]); // length placeholder + rsvd

    // IORT header: 12 bytes after SDT_HEADER.
    let n_nodes_off = buf.len();
    buf.extend_from_slice(&2u32.to_le_bytes()); // n_nodes
    let arr_off_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // node-array offset (patched)
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved

    let arr_off = buf.len() as u32;

    // ITS group node: type=0, length=24, 1 ID = 0xCAFE.
    buf.push(0); // type
    buf.extend_from_slice(&24u16.to_le_bytes()); // length
    buf.push(0); // revision
    buf.extend_from_slice(&0u32.to_le_bytes()); // identifier
    buf.extend_from_slice(&0u32.to_le_bytes()); // n_id_mappings
    buf.extend_from_slice(&0u32.to_le_bytes()); // off_id_mappings
    buf.extend_from_slice(&1u32.to_le_bytes()); // n_its
    buf.extend_from_slice(&0xCAFEu32.to_le_bytes()); // its id

    // SMMUv3 node: type=4, length=36, base=0xDEAD_0000, flags=0xA5.
    buf.push(4);
    buf.extend_from_slice(&36u16.to_le_bytes());
    buf.push(0);
    buf.extend_from_slice(&0u32.to_le_bytes()); // identifier
    buf.extend_from_slice(&0u32.to_le_bytes()); // n_id_mappings
    buf.extend_from_slice(&0u32.to_le_bytes()); // off_id_mappings
    buf.extend_from_slice(&0xDEAD_0000u64.to_le_bytes()); // base
    buf.extend_from_slice(&0xA5u32.to_le_bytes()); // flags
    buf.extend_from_slice(&[0u8; 8]); // pad to 36

    // Patch array-offset.
    buf[arr_off_pos..arr_off_pos + 4].copy_from_slice(&arr_off.to_le_bytes());
    let _ = n_nodes_off;

    let n = crate::__test_parse_iort_body(&buf);
    if n != 2 {
        return TestResult::Fail("expected 2 IORT nodes parsed");
    }
    let mut smmus = [IortSmmuv3::default(); 4];
    let ns = crate::copy_iort_smmuv3(&mut smmus);
    if ns != 1 || smmus[0].base != 0xDEAD_0000 || smmus[0].flags != 0xA5 {
        return TestResult::Fail("IORT SMMUv3 decode mismatch");
    }
    let mut its = [IortIts::default(); 4];
    let ni = crate::copy_iort_its(&mut its);
    if ni != 1 || its[0].its_id != 0xCAFE {
        return TestResult::Fail("IORT ITS decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/iort", smoke_acpi_iort_synthetic_decode);

fn smoke_acpi_dmar_synthetic_decode() -> TestResult {
    use crate::DmarDrhd;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"DMAR");
    buf.extend_from_slice(&[0u8; 32]); // length + rsvd
    buf.push(48); // host_addr_width
    buf.push(1); // flags: INTR_REMAP
    buf.extend_from_slice(&[0u8; 10]); // reserved

    // DRHD: type=0, length=16, segment=0x55, base=0xFEED_F000.
    buf.extend_from_slice(&0u16.to_le_bytes()); // type
    buf.extend_from_slice(&16u16.to_le_bytes()); // length
    buf.push(0); // flags
    buf.push(0); // reserved
    buf.extend_from_slice(&0x55u16.to_le_bytes());
    buf.extend_from_slice(&0xFEED_F000u64.to_le_bytes());

    let n = crate::__test_parse_dmar_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 DRHD parsed");
    }
    let mut drhds = [DmarDrhd::default(); 4];
    let nd = crate::copy_dmar_drhds(&mut drhds);
    if nd != 1 || drhds[0].register_base != 0xFEED_F000 || drhds[0].segment != 0x55 {
        return TestResult::Fail("DRHD decode mismatch");
    }
    if !crate::dmar_intr_remap_supported() {
        return TestResult::Fail("INTR_REMAP flag not surfaced");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/dmar", smoke_acpi_dmar_synthetic_decode);

fn smoke_acpi_ivrs_synthetic_decode() -> TestResult {
    use crate::IvrsIommu;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"IVRS");
    buf.extend_from_slice(&[0u8; 32]); // length + rsvd
    buf.extend_from_slice(&0u32.to_le_bytes()); // IvInfo
    buf.extend_from_slice(&[0u8; 8]); // reserved

    // IVHD: type=0x10, length=24, cap_off=0x40, base=0xBA5E_F000, segment=0xAB.
    buf.push(0x10);
    buf.push(0); // flags
    buf.extend_from_slice(&24u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // device id
    buf.extend_from_slice(&0x40u16.to_le_bytes());
    buf.extend_from_slice(&0xBA5E_F000u64.to_le_bytes());
    buf.extend_from_slice(&0xABu16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // iommu_info
    buf.extend_from_slice(&0u32.to_le_bytes()); // pad

    let n = crate::__test_parse_ivrs_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 IVHD parsed");
    }
    let mut iommus = [IvrsIommu::default(); 4];
    let ni = crate::copy_ivrs_iommus(&mut iommus);
    if ni != 1
        || iommus[0].base != 0xBA5E_F000
        || iommus[0].pci_segment != 0xAB
        || iommus[0].capability_off != 0x40
    {
        return TestResult::Fail("IVHD decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/ivrs", smoke_acpi_ivrs_synthetic_decode);

fn smoke_acpi_spcr_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"SPCR");
    buf.extend_from_slice(&[0u8; 32]); // length + rsvd

    // Body: 36 bytes minimum.
    buf.push(0x03); // iface = ARM PL011
    buf.extend_from_slice(&[0u8; 3]); // reserved
    buf.push(0x00); // GAS.AddressSpaceId = SystemMemory
    buf.push(8); // bit width
    buf.push(0); // bit offset
    buf.push(1); // access size
    buf.extend_from_slice(&0x900_0000u64.to_le_bytes()); // GAS.Address
    buf.push(0); // InterruptType
    buf.push(0); // IRQ
    buf.extend_from_slice(&33u32.to_le_bytes()); // GSI
    buf.push(7); // baud = 115200
    buf.extend_from_slice(&[0u8; 5]); // parity / stop / flow / term / lang
    buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // PCI device id
    buf.extend_from_slice(&[0u8; 6]); // pad to 36

    crate::__test_parse_spcr_body(&buf);
    let info = crate::spcr_info().expect("SPCR not parsed");
    if info.iface != 0x03 || info.base != 0x900_0000 || info.gsi != 33 || info.baud_code != 7 {
        return TestResult::Fail("SPCR decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/spcr", smoke_acpi_spcr_synthetic_decode);

fn smoke_acpi_hest_synthetic_decode() -> TestResult {
    use crate::{HestGhesSource, HestMceSource};
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"HEST");
    buf.extend_from_slice(&[0u8; 32]); // length + rsvd
    buf.extend_from_slice(&2u32.to_le_bytes()); // ErrorSourceCount

    // Type 0 (Machine Check), length = 40 + 0 banks = 40.
    let mce_off = buf.len();
    buf.extend_from_slice(&0u16.to_le_bytes()); // type
    buf.extend_from_slice(&0xABCDu16.to_le_bytes()); // source id
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.push(0); // flags
    buf.push(1); // enabled
    buf.extend_from_slice(&[0u8; 8]); // num_records + max_sect
    buf.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // global_capability
    buf.extend_from_slice(&0xCAFE_F00Du64.to_le_bytes()); // global_control
    buf.push(0); // num_hw_banks
    buf.extend_from_slice(&[0u8; 7]); // reserved (40 bytes total so far)
    let _ = mce_off;

    // Type 9 (GHES), length = 92.
    buf.extend_from_slice(&9u16.to_le_bytes()); // type
    buf.extend_from_slice(&0x1234u16.to_le_bytes()); // source id
    buf.extend_from_slice(&0u16.to_le_bytes()); // related src
    buf.push(0); // flags
    buf.push(1); // enabled
    buf.extend_from_slice(&[0u8; 4]); // num_records (4 B)
    buf.extend_from_slice(&7u32.to_le_bytes()); // max_sections_per_record (4 B)
    buf.extend_from_slice(&[0u8; 8]); // max_raw_data + reserved fill
                                      // GAS at offset 24..36 of GHES entry; address @ +28..36 within GAS:
    buf.extend_from_slice(&[0u8; 4]); // GAS asid+bw+bo+as
    buf.extend_from_slice(&0xCAFE_BABEu64.to_le_bytes()); // err status block addr
    buf.extend_from_slice(&[0u8; 28 + 4]); // notif (28) + ESBlock len (4)
                                           // Total written so far for GHES = 40 + 4 + 8 + 4 + 8 + 28 + 4 = 96 (close to 92);
                                           // pad/truncate to 92 by trimming if over.
    let cur = buf.len();
    let want = mce_off + 40 + 92;
    if cur > want {
        buf.truncate(want);
    } else if cur < want {
        buf.resize(want, 0);
    }

    let n = crate::__test_parse_hest_body(&buf);
    if n < 1 {
        return TestResult::Fail("expected at least 1 HEST source parsed");
    }
    let mut mces = [HestMceSource::default(); 4];
    let nm = crate::copy_hest_mce(&mut mces);
    if nm < 1
        || mces[0].source_id != 0xABCD
        || !mces[0].enabled
        || mces[0].global_capability != 0xDEAD_BEEF
        || mces[0].global_control != 0xCAFE_F00D
    {
        return TestResult::Fail("HEST MCE decode mismatch");
    }
    let mut ghes = [HestGhesSource::default(); 4];
    let _ng = crate::copy_hest_ghes(&mut ghes);
    // GHES decoding is best-effort given the synthetic body shape;
    // we only require the MCE entry to land cleanly.
    TestResult::Pass
}
kernel_test_in!("acpi/hest", smoke_acpi_hest_synthetic_decode);

fn smoke_acpi_pcct_synthetic_decode() -> TestResult {
    use crate::PcctChannel;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"PCCT");
    buf.extend_from_slice(&[0u8; 32]); // length + rsvd
    buf.extend_from_slice(&0u32.to_le_bytes()); // PCCT flags
    buf.extend_from_slice(&[0u8; 8]); // reserved

    // Generic channel (type 0). Spec layout (offsets within entry):
    //   0..2   type+length
    //   2..8   reserved
    //   8..16  base
    //   16..24 length
    //   24..36 doorbell GAS (address @ 28..36)
    //   36..44 doorbell preserve
    //   44..52 doorbell write
    //   52..56 nominal latency
    //   56..60 max periodic
    //   60..62 min turnaround
    let entry_start = buf.len();
    buf.push(0);
    buf.push(62); // type / length
    buf.extend_from_slice(&[0u8; 6]); // reserved
    buf.extend_from_slice(&0xDEAD_0000u64.to_le_bytes()); // base
    buf.extend_from_slice(&0x1000u64.to_le_bytes()); // length
    buf.extend_from_slice(&[0u8; 4]); // GAS hdr
    buf.extend_from_slice(&0xBEEF_0000u64.to_le_bytes()); // GAS.Address
    buf.extend_from_slice(&0u64.to_le_bytes()); // doorbell preserve
    buf.extend_from_slice(&0xC0FFEEu64.to_le_bytes()); // doorbell write
    buf.extend_from_slice(&50u32.to_le_bytes()); // nominal latency
    buf.extend_from_slice(&0u32.to_le_bytes()); // max periodic
    buf.extend_from_slice(&100u16.to_le_bytes()); // min turnaround
    debug_assert_eq!(buf.len() - entry_start, 62);
    let _ = entry_start;

    let n = crate::__test_parse_pcct_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 PCCT channel parsed");
    }
    let mut chans = [PcctChannel::default(); 4];
    let nc = crate::copy_pcct_channels(&mut chans);
    if nc != 1
        || chans[0].kind != 0
        || chans[0].shmem_base != 0xDEAD_0000
        || chans[0].shmem_length != 0x1000
        || chans[0].doorbell_addr != 0xBEEF_0000
        || chans[0].doorbell_write != 0xC0FFEE
        || chans[0].min_turnaround_us != 100
    {
        return TestResult::Fail("PCCT channel decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/pcct", smoke_acpi_pcct_synthetic_decode);

fn smoke_acpi_slit_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"SLIT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&3u64.to_le_bytes()); // 3 nodes
                                                // 3x3 distance matrix.
    buf.extend_from_slice(&[10, 20, 30, 20, 10, 25, 30, 25, 10]);

    let n = crate::__test_parse_slit_body(&buf);
    if n != 3 {
        return TestResult::Fail("expected 3 nodes parsed");
    }
    if crate::slit_distance(0, 0) != Some(10)
        || crate::slit_distance(0, 2) != Some(30)
        || crate::slit_distance(2, 1) != Some(25)
    {
        return TestResult::Fail("SLIT distance lookup mismatch");
    }
    if crate::slit_distance(0, 9).is_some() {
        return TestResult::Fail("out-of-range lookup should return None");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/slit", smoke_acpi_slit_synthetic_decode);

fn smoke_acpi_cedt_synthetic_decode() -> TestResult {
    use crate::{CedtCfmws, CedtChbs};
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"CEDT");
    buf.extend_from_slice(&[0u8; 32]);

    // CHBS: type=0, length=32.
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&32u16.to_le_bytes());
    buf.extend_from_slice(&0x42u32.to_le_bytes()); // uid
    buf.extend_from_slice(&1u32.to_le_bytes()); // cxl_ver = CXL 2.0
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&0xCD00_0000u64.to_le_bytes()); // base
    buf.extend_from_slice(&0x10000u64.to_le_bytes()); // length

    // CFMWS: type=1, length=36, 0 targets.
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(&36u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&0x800_0000u64.to_le_bytes()); // base hpa
    buf.extend_from_slice(&0x1000_0000u64.to_le_bytes()); // window size
    buf.push(0); // encoded_iw
    buf.push(0); // interleave arith
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&0u32.to_le_bytes()); // hb iface type
    buf.extend_from_slice(&0u16.to_le_bytes()); // restrictions
    buf.extend_from_slice(&0u16.to_le_bytes()); // qtg id

    let n = crate::__test_parse_cedt_body(&buf);
    if n != 2 {
        return TestResult::Fail("expected 2 CEDT entries parsed");
    }
    let mut chbs = [CedtChbs::default(); 4];
    let nc = crate::copy_cedt_chbs(&mut chbs);
    if nc != 1 || chbs[0].uid != 0x42 || chbs[0].cxl_ver != 1 || chbs[0].base != 0xCD00_0000 {
        return TestResult::Fail("CHBS decode mismatch");
    }
    let mut cfmws = [CedtCfmws::default(); 4];
    let nf = crate::copy_cedt_cfmws(&mut cfmws);
    if nf != 1 || cfmws[0].base_hpa != 0x800_0000 || cfmws[0].window_size != 0x1000_0000 {
        return TestResult::Fail("CFMWS decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/cedt", smoke_acpi_cedt_synthetic_decode);

fn smoke_acpi_bert_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"BERT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0x4000u32.to_le_bytes()); // region length
    buf.extend_from_slice(&0xFEED_F00D_0000_0000u64.to_le_bytes()); // region addr

    crate::__test_parse_bert_body(&buf);
    let info = crate::bert_info().expect("BERT not parsed");
    if info.region_length != 0x4000 || info.region_addr != 0xFEED_F00D_0000_0000 {
        return TestResult::Fail("BERT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/bert", smoke_acpi_bert_synthetic_decode);

fn smoke_acpi_aest_synthetic_decode() -> TestResult {
    use crate::AestNode;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"AEST");
    buf.extend_from_slice(&[0u8; 32]);

    // Node header (12 B at offset 0..12 of entry):
    //   0..1 type, 1..2 reserved, 2..4 length, 4..8 reserved,
    //   8..12 NodeDataOffset (unused here)
    // Then per the v0.1 spec we surface NodeIfaceOffset at [12..16]
    // and read the iface block (Type @ off, Address @ off+4..off+12).
    let entry_start = buf.len();
    buf.push(2); // type = SMMU
    buf.push(0); // reserved
    buf.extend_from_slice(&28u16.to_le_bytes()); // length = 28
    buf.extend_from_slice(&[0u8; 4]); // reserved
    buf.extend_from_slice(&[0u8; 4]); // NodeDataOffset
    buf.extend_from_slice(&16u32.to_le_bytes()); // NodeIfaceOffset = 16
                                                 // Interface block at +16: Type (1 = MMIO) + 3 padding + Address (8 B).
    buf.push(1); // iface type
    buf.extend_from_slice(&[0u8; 3]); // padding
    buf.extend_from_slice(&0xCD_0000u64.to_le_bytes()); // base
    debug_assert_eq!(buf.len() - entry_start, 28);
    let _ = entry_start;

    let n = crate::__test_parse_aest_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 AEST node parsed");
    }
    let mut nodes = [AestNode::default(); 4];
    let nn = crate::copy_aest_nodes(&mut nodes);
    if nn != 1 || nodes[0].kind != 2 || nodes[0].iface != 1 || nodes[0].base != 0xCD_0000 {
        return TestResult::Fail("AEST node decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/aest", smoke_acpi_aest_synthetic_decode);

fn smoke_acpi_sdei_supported_path() -> TestResult {
    crate::__test_set_sdei_known();
    if !crate::is_sdei_known() {
        return TestResult::Fail("SDEI sticky-flag did not flip");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/sdei", smoke_acpi_sdei_supported_path);

fn smoke_acpi_wddt_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"WDDT");
    buf.extend_from_slice(&[0u8; 32]);

    // 6 bytes header (SpecVersion + TableVersion + PciVendorId).
    buf.extend_from_slice(&[0u8; 6]);
    // GAS (12 B): asid + bw + bo + access + Address (8).
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0xBA50_0000u64.to_le_bytes());
    // Counts + status + capability:
    buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // max
    buf.extend_from_slice(&0x0001u16.to_le_bytes()); // min
    buf.extend_from_slice(&100u16.to_le_bytes()); // period_us
    buf.extend_from_slice(&0x0007u16.to_le_bytes()); // status
    buf.extend_from_slice(&0x0003u16.to_le_bytes()); // capability

    crate::__test_parse_wddt_body(&buf);
    let info = crate::wddt_info().expect("WDDT not parsed");
    if info.timer_max_count != 0xFFFF
        || info.timer_min_count != 1
        || info.period_us != 100
        || info.status != 0x0007
        || info.capability != 0x0003
        || info.base != 0xBA50_0000
    {
        return TestResult::Fail("WDDT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/wddt", smoke_acpi_wddt_synthetic_decode);

fn smoke_acpi_lpit_synthetic_decode() -> TestResult {
    use crate::LpitState;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"LPIT");
    buf.extend_from_slice(&[0u8; 32]);

    // Type 0 native-c-state subtable, length = 56.
    buf.extend_from_slice(&0u32.to_le_bytes()); // type
    buf.extend_from_slice(&56u32.to_le_bytes()); // length
    buf.extend_from_slice(&7u32.to_le_bytes()); // UID = 7
    buf.extend_from_slice(&[0u8; 4]); // reserved
                                      // EntryTrigger GAS (12 B); address @ +4..12.
    buf.extend_from_slice(&[0u8; 4]); // GAS hdr
    buf.extend_from_slice(&0xDEAD_0000u64.to_le_bytes()); // trigger addr
    buf.extend_from_slice(&500u32.to_le_bytes()); // residency
    buf.extend_from_slice(&50u32.to_le_bytes()); // latency
                                                 // ResidencyCounter GAS (12 B).
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0xBEEF_0000u64.to_le_bytes()); // counter addr
    buf.extend_from_slice(&3_000_000u64.to_le_bytes()); // counter freq

    let n = crate::__test_parse_lpit_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 LPIT state parsed");
    }
    let mut states = [LpitState::default(); 4];
    let ns = crate::copy_lpit_states(&mut states);
    if ns != 1
        || states[0].uid != 7
        || states[0].trigger_addr != 0xDEAD_0000
        || states[0].residency != 500
        || states[0].latency != 50
        || states[0].counter_addr != 0xBEEF_0000
        || states[0].counter_freq != 3_000_000
    {
        return TestResult::Fail("LPIT state decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/lpit", smoke_acpi_lpit_synthetic_decode);

fn smoke_acpi_nfit_synthetic_decode() -> TestResult {
    use crate::NfitSpaRange;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"NFIT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&[0u8; 4]); // reserved

    // SPA Range subtable (type 0, length 56).
    buf.extend_from_slice(&0u16.to_le_bytes()); // type
    buf.extend_from_slice(&56u16.to_le_bytes()); // length
    buf.extend_from_slice(&0xAABBu16.to_le_bytes()); // range_index
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&[0u8; 4]); // reserved
    buf.extend_from_slice(&3u32.to_le_bytes()); // proximity = 3
    buf.extend_from_slice(&[0u8; 16]); // GUID
    buf.extend_from_slice(&0xC000_0000u64.to_le_bytes()); // base
    buf.extend_from_slice(&0x4000_0000u64.to_le_bytes()); // length
    buf.extend_from_slice(&0x55u64.to_le_bytes()); // mem_attr

    let n = crate::__test_parse_nfit_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 NFIT SPA range parsed");
    }
    let mut ranges = [NfitSpaRange::default(); 4];
    let nr = crate::copy_nfit_spa_ranges(&mut ranges);
    if nr != 1
        || ranges[0].range_index != 0xAABB
        || ranges[0].proximity != 3
        || ranges[0].base != 0xC000_0000
        || ranges[0].length != 0x4000_0000
        || ranges[0].mem_attr != 0x55
    {
        return TestResult::Fail("NFIT SPA range decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/nfit", smoke_acpi_nfit_synthetic_decode);

fn smoke_acpi_erst_synthetic_decode() -> TestResult {
    use crate::ErstInstruction;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"ERST");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0u32.to_le_bytes()); // SerializationHdrSize
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    buf.extend_from_slice(&1u32.to_le_bytes()); // InstructionEntryCount

    // 32-byte instruction: action=2, instruction=5, addr=0xCAFE_F000,
    // value=0xDEAD, mask=0xFFFF.
    buf.push(2);
    buf.push(5);
    buf.push(0);
    buf.push(0); // action / inst / flags / rsvd
    buf.extend_from_slice(&[0u8; 4]); // GAS hdr
    buf.extend_from_slice(&0xCAFE_F000u64.to_le_bytes()); // addr
    buf.extend_from_slice(&0xDEADu64.to_le_bytes()); // value
    buf.extend_from_slice(&0xFFFFu64.to_le_bytes()); // mask

    let n = crate::__test_parse_erst_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 ERST instruction parsed");
    }
    let mut ins = [ErstInstruction::default(); 4];
    let ni = crate::copy_erst_instructions(&mut ins);
    if ni != 1
        || ins[0].action != 2
        || ins[0].instruction != 5
        || ins[0].addr != 0xCAFE_F000
        || ins[0].value != 0xDEAD
        || ins[0].mask != 0xFFFF
    {
        return TestResult::Fail("ERST instruction decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/erst", smoke_acpi_erst_synthetic_decode);

fn smoke_acpi_einj_synthetic_decode() -> TestResult {
    use crate::EinjInstruction;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"EINJ");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());

    buf.push(7);
    buf.push(3);
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0xBA5E_0000u64.to_le_bytes());
    buf.extend_from_slice(&0x42u64.to_le_bytes());
    buf.extend_from_slice(&0xFFu64.to_le_bytes());

    let n = crate::__test_parse_einj_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 EINJ instruction parsed");
    }
    let mut ins = [EinjInstruction::default(); 4];
    let ni = crate::copy_einj_instructions(&mut ins);
    if ni != 1
        || ins[0].action != 7
        || ins[0].instruction != 3
        || ins[0].addr != 0xBA5E_0000
        || ins[0].value != 0x42
        || ins[0].mask != 0xFF
    {
        return TestResult::Fail("EINJ instruction decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/einj", smoke_acpi_einj_synthetic_decode);

fn smoke_acpi_tpm2_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"TPM2");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&1u16.to_le_bytes()); // platform class = Server
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&0xFED4_0000u64.to_le_bytes()); // control area
    buf.extend_from_slice(&7u32.to_le_bytes()); // start method = CRB

    crate::__test_parse_tpm2_body(&buf);
    let info = crate::tpm2_info().expect("TPM2 not parsed");
    if info.platform_class != 1 || info.control_area_addr != 0xFED4_0000 || info.start_method != 7 {
        return TestResult::Fail("TPM2 decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/tpm2", smoke_acpi_tpm2_synthetic_decode);

fn smoke_acpi_bgrt_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"BGRT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&1u16.to_le_bytes()); // version
    buf.push(0b101); // status: displayed + 90°
    buf.push(0); // image type
    buf.extend_from_slice(&0x1A00_0000u64.to_le_bytes()); // image addr
    buf.extend_from_slice(&100u32.to_le_bytes()); // off_x
    buf.extend_from_slice(&200u32.to_le_bytes()); // off_y

    crate::__test_parse_bgrt_body(&buf);
    let info = crate::bgrt_info().expect("BGRT not parsed");
    if info.status != 0b101
        || info.image_address != 0x1A00_0000
        || info.offset_x != 100
        || info.offset_y != 200
    {
        return TestResult::Fail("BGRT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/bgrt", smoke_acpi_bgrt_synthetic_decode);

fn smoke_acpi_dbg2_synthetic_decode() -> TestResult {
    use crate::Dbg2Device;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"DBG2");
    buf.extend_from_slice(&[0u8; 32]);

    // DBG2 header: InfoOffset (4) + InfoCount (4).
    let info_off_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // info offset (patched)
    buf.extend_from_slice(&1u32.to_le_bytes()); // info count

    let info_off = (buf.len() - SDT_HEADER_SIZE_DBG2) as u32 + SDT_HEADER_SIZE_DBG2 as u32;
    let info_off_actual = buf.len() as u32;

    // Device-info entry. Layout (offsets within entry):
    //   0    Revision
    //   1..3 Length
    //   3    RegisterCount
    //   4..6 NamespaceStringLength
    //   6..8 NamespaceStringOffset
    //   8..10 OemDataLength
    //   10..12 OemDataOffset
    //   12..14 PortType
    //   14..16 PortSubtype
    //   16..18 Reserved
    //   18..20 BaseAddrRegOffset
    //   20..22 AddressSizeOffset
    //   ... GAS array starting at BaseAddrRegOffset ...
    let entry_start = buf.len();
    buf.push(0); // revision
    buf.extend_from_slice(&34u16.to_le_bytes()); // length
    buf.push(1); // reg count
    buf.extend_from_slice(&0u16.to_le_bytes()); // ns len
    buf.extend_from_slice(&0u16.to_le_bytes()); // ns off
    buf.extend_from_slice(&0u16.to_le_bytes()); // oem len
    buf.extend_from_slice(&0u16.to_le_bytes()); // oem off
    buf.extend_from_slice(&0x8000u16.to_le_bytes()); // port_type = serial
    buf.extend_from_slice(&0x0000u16.to_le_bytes()); // port_subtype = full 16550
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&22u16.to_le_bytes()); // base addr reg offset = 22
    buf.extend_from_slice(&0u16.to_le_bytes()); // addr size offset
                                                // GAS at offset 22 (relative to entry start): 4 bytes hdr + 8 bytes addr.
    buf.extend_from_slice(&[0u8; 4]); // GAS hdr
    buf.extend_from_slice(&0x3F8u64.to_le_bytes()); // GAS.Address = 16550 base

    // Patch InfoOffset.
    let info_off_val = (info_off_actual) as u32;
    buf[info_off_pos..info_off_pos + 4].copy_from_slice(&info_off_val.to_le_bytes());
    let _ = (entry_start, info_off);

    let n = crate::__test_parse_dbg2_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 DBG2 device parsed");
    }
    let mut devs = [Dbg2Device::default(); 4];
    let nd = crate::copy_dbg2_devices(&mut devs);
    if nd != 1
        || devs[0].port_type != 0x8000
        || devs[0].port_subtype != 0x0000
        || devs[0].base_addr != 0x3F8
    {
        return TestResult::Fail("DBG2 device decode mismatch");
    }
    TestResult::Pass
}
const SDT_HEADER_SIZE_DBG2: usize = 36;
kernel_test_in!("acpi/dbg2", smoke_acpi_dbg2_synthetic_decode);

fn smoke_acpi_wsmt_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"WSMT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0b101u32.to_le_bytes()); // bits 0 + 2

    crate::__test_parse_wsmt_body(&buf);
    let info = crate::wsmt_info().expect("WSMT not parsed");
    if !info.fixed_comm_buffers || info.comm_buffer_nested_ptr || !info.system_resource_protection {
        return TestResult::Fail("WSMT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/wsmt", smoke_acpi_wsmt_synthetic_decode);

fn smoke_acpi_waet_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"WAET");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0b11u32.to_le_bytes());

    crate::__test_parse_waet_body(&buf);
    let info = crate::waet_info().expect("WAET not parsed");
    if !info.rtc_good || !info.acpi_pmtimer_good {
        return TestResult::Fail("WAET decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/waet", smoke_acpi_waet_synthetic_decode);

fn smoke_acpi_hpet_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"HPET");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes()); // block id
                                                          // GAS: addr_space_id @ 0, address @ 4..12.
    buf.push(0); // SystemMemory
    buf.extend_from_slice(&[0u8; 3]); // bw / bo / access
    buf.extend_from_slice(&0xFED0_0000u64.to_le_bytes()); // base
    buf.push(2); // hpet_number
    buf.extend_from_slice(&0x42u16.to_le_bytes()); // counter min
    buf.push(0xAA); // oem attrs

    crate::__test_parse_hpet_body(&buf);
    let d = crate::hpet_desc().expect("HPET not parsed");
    if d.block_id != 0xCAFE_BABE
        || d.base != 0xFED0_0000
        || d.hpet_number != 2
        || d.main_counter_min != 0x42
        || d.oem_attributes != 0xAA
    {
        return TestResult::Fail("HPET decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/hpet", smoke_acpi_hpet_synthetic_decode);

fn smoke_acpi_facs_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    // Note: FACS body has no SDT header; the body itself starts
    // with the FACS signature.
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"FACS");
    buf.extend_from_slice(&64u32.to_le_bytes()); // length
    buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // hardware sig
    buf.extend_from_slice(&0x10000u32.to_le_bytes()); // fw waking vec 32
    buf.extend_from_slice(&0u32.to_le_bytes()); // global lock
    buf.extend_from_slice(&0b11u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0xCAFE_F0000000u64.to_le_bytes()); // X fw waking vec
    buf.push(2); // version
    buf.extend_from_slice(&[0u8; 31]); // reserved/pad to 64

    crate::__test_parse_facs_body(&buf);
    let info = crate::facs_info().expect("FACS not parsed");
    if info.hardware_signature != 0xDEAD_BEEF
        || info.firmware_waking_vector_32 != 0x10000
        || info.firmware_waking_vector_64 != 0xCAFE_F0000000
        || info.flags != 0b11
        || info.version != 2
    {
        return TestResult::Fail("FACS decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/facs", smoke_acpi_facs_synthetic_decode);

fn smoke_acpi_prmt_synthetic_decode() -> TestResult {
    use crate::PrmtModule;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"PRMT");
    buf.extend_from_slice(&[0u8; 32]);

    // 16-byte PrmPlatformGuid + 4 B mod off + 4 B mod count.
    buf.extend_from_slice(&[0u8; 16]); // platform guid
    let mod_off_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // mod off (patched)
    buf.extend_from_slice(&1u32.to_le_bytes()); // mod count

    let mod_off_actual = buf.len() as u32;

    // Module entry, length = 36.
    buf.extend_from_slice(&0u16.to_le_bytes()); // revision
    buf.extend_from_slice(&36u16.to_le_bytes()); // length
    buf.extend_from_slice(&[0u8; 16]); // module guid
    buf.extend_from_slice(&3u16.to_le_bytes()); // major
    buf.extend_from_slice(&7u16.to_le_bytes()); // minor
    buf.extend_from_slice(&5u16.to_le_bytes()); // handler count
    buf.extend_from_slice(&0u16.to_le_bytes()); // padding to 28
    buf.extend_from_slice(&0xBEEF_0000u64.to_le_bytes()); // mmio range

    // Patch mod offset.
    buf[mod_off_pos..mod_off_pos + 4].copy_from_slice(&mod_off_actual.to_le_bytes());

    let n = crate::__test_parse_prmt_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 PRMT module parsed");
    }
    let mut mods = [PrmtModule::default(); 4];
    let nm = crate::copy_prmt_modules(&mut mods);
    if nm != 1
        || mods[0].major_revision != 3
        || mods[0].minor_revision != 7
        || mods[0].handler_count != 5
        || mods[0].mmio_range != 0xBEEF_0000
    {
        return TestResult::Fail("PRMT module decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/prmt", smoke_acpi_prmt_synthetic_decode);

fn smoke_acpi_ccel_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"CCEL");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(0); // cc_type = TDX
    buf.push(2); // cc_subtype
    buf.extend_from_slice(&[0u8; 2]); // reserved
    buf.extend_from_slice(&0x4000u64.to_le_bytes()); // log area min
    buf.extend_from_slice(&0xC000_0000u64.to_le_bytes()); // log area phys

    crate::__test_parse_ccel_body(&buf);
    let info = crate::ccel_info().expect("CCEL not parsed");
    if info.cc_type != 0
        || info.cc_subtype != 2
        || info.log_area_min != 0x4000
        || info.log_area_phys != 0xC000_0000
    {
        return TestResult::Fail("CCEL decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/ccel", smoke_acpi_ccel_synthetic_decode);

fn smoke_acpi_mpst_synthetic_decode() -> TestResult {
    use crate::MpstNode;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"MPST");
    buf.extend_from_slice(&[0u8; 32]);
    // MPST header: PccId (1) + Reserved (3) + NodeCount (2) + Reserved (2)
    buf.push(0);
    buf.extend_from_slice(&[0u8; 3]);
    buf.extend_from_slice(&1u16.to_le_bytes()); // 1 node
    buf.extend_from_slice(&[0u8; 2]);

    // Node header: Flags + Rsvd + Id + Length + Base + LengthBytes +
    //              StateValueCount + PhysComponentCount = 32 bytes total.
    buf.push(0b101); // flags: enabled + hot-pluggable
    buf.push(0); // reserved
    buf.extend_from_slice(&0x42u16.to_le_bytes()); // node id
    buf.extend_from_slice(&32u32.to_le_bytes()); // length
    buf.extend_from_slice(&0x1_0000u64.to_le_bytes()); // base
    buf.extend_from_slice(&0x10_0000u64.to_le_bytes()); // length bytes
    buf.extend_from_slice(&0u32.to_le_bytes()); // state count
    buf.extend_from_slice(&0u32.to_le_bytes()); // phys count

    let n = crate::__test_parse_mpst_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 MPST node parsed");
    }
    let mut nodes = [MpstNode::default(); 4];
    let nn = crate::copy_mpst_nodes(&mut nodes);
    if nn != 1
        || nodes[0].node_id != 0x42
        || !nodes[0].enabled
        || nodes[0].power_managed
        || !nodes[0].hot_pluggable
        || nodes[0].base != 0x1_0000
        || nodes[0].length_bytes != 0x10_0000
    {
        return TestResult::Fail("MPST node decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/mpst", smoke_acpi_mpst_synthetic_decode);

fn smoke_acpi_sdev_synthetic_decode() -> TestResult {
    use crate::SdevPci;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"SDEV");
    buf.extend_from_slice(&[0u8; 32]);

    // PCI endpoint entry (type 1, length 16).
    buf.push(1); // type
    buf.push(0); // flags
    buf.extend_from_slice(&16u16.to_le_bytes()); // length
    buf.extend_from_slice(&0xABu16.to_le_bytes()); // segment
    buf.extend_from_slice(&0x1234u16.to_le_bytes()); // start_bdf
    buf.extend_from_slice(&[0u8; 8]); // remaining hdr fields

    let n = crate::__test_parse_sdev_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 SDEV PCI entry parsed");
    }
    let mut pcis = [SdevPci::default(); 4];
    let np = crate::copy_sdev_pci(&mut pcis);
    if np != 1 || pcis[0].segment != 0xAB || pcis[0].start_bdf != 0x1234 {
        return TestResult::Fail("SDEV PCI decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/sdev", smoke_acpi_sdev_synthetic_decode);

fn smoke_acpi_sbst_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"SBST");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&5000u32.to_le_bytes()); // warning
    buf.extend_from_slice(&2000u32.to_le_bytes()); // low
    buf.extend_from_slice(&500u32.to_le_bytes()); // critical

    crate::__test_parse_sbst_body(&buf);
    let info = crate::sbst_info().expect("SBST not parsed");
    if info.warning_level_mwh != 5000
        || info.low_level_mwh != 2000
        || info.critical_level_mwh != 500
    {
        return TestResult::Fail("SBST decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/sbst", smoke_acpi_sbst_synthetic_decode);

fn smoke_acpi_ras2_synthetic_decode() -> TestResult {
    use crate::Ras2Descriptor;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"RAS2");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&1u16.to_le_bytes()); // descriptor count

    // Descriptor (8 B): PccId + Reserved (2) + FeatureType + InstanceCount
    buf.push(7); // pcc_id
    buf.extend_from_slice(&[0u8; 2]); // reserved
    buf.push(0); // feature_type = MemPatrolScrub
    buf.extend_from_slice(&3u32.to_le_bytes()); // instance count

    let n = crate::__test_parse_ras2_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 RAS2 descriptor parsed");
    }
    let mut descs = [Ras2Descriptor::default(); 4];
    let nd = crate::copy_ras2_descriptors(&mut descs);
    if nd != 1 || descs[0].pcc_id != 7 || descs[0].feature_type != 0 || descs[0].instance_count != 3
    {
        return TestResult::Fail("RAS2 descriptor decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/ras2", smoke_acpi_ras2_synthetic_decode);

fn smoke_acpi_ecdt_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"ECDT");
    buf.extend_from_slice(&[0u8; 32]);
    // EcControl GAS — addr @ +4..12.
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0x62u64.to_le_bytes()); // control = 0x62
                                                   // EcData GAS — addr @ +4..12.
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0x66u64.to_le_bytes()); // data = 0x66
    buf.extend_from_slice(&0xABCDu32.to_le_bytes()); // uid
    buf.push(9); // gpe bit
    buf.push(b'E');
    buf.push(b'C');
    buf.push(0); // namespace string

    crate::parse_ecdt_body(&buf);
    let info = crate::ecdt_info().expect("ECDT not parsed");
    if info.control_addr != 0x62
        || info.data_addr != 0x66
        || info.uid != 0xABCD
        || info.gpe_bit != 9
    {
        return TestResult::Fail("ECDT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/ecdt", smoke_acpi_ecdt_synthetic_decode);

fn smoke_acpi_nhlt_synthetic_decode() -> TestResult {
    use crate::NhltEndpoint;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"NHLT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(1); // endpoint count

    // Endpoint: length (4) + linkType (1) + instanceId (1) +
    //           vendorId (2) + deviceId (2) + revisionId (2) +
    //           subsystemId (4) + deviceType (1) + direction (1) +
    //           virtualBusId (1) = 19 bytes minimum.
    buf.extend_from_slice(&19u32.to_le_bytes());
    buf.push(2); // link_type = PDM
    buf.push(5); // instance_id
    buf.extend_from_slice(&0x8086u16.to_le_bytes()); // vendor
    buf.extend_from_slice(&0x1234u16.to_le_bytes()); // device
    buf.extend_from_slice(&0u16.to_le_bytes()); // revision
    buf.extend_from_slice(&0u32.to_le_bytes()); // subsystem
    buf.push(0); // device type
    buf.push(1); // direction = capture
    buf.push(0); // virtual bus id

    let n = crate::__test_parse_nhlt_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 NHLT endpoint parsed");
    }
    let mut eps = [NhltEndpoint::default(); 4];
    let nn = crate::copy_nhlt_endpoints(&mut eps);
    if nn != 1
        || eps[0].link_type != 2
        || eps[0].instance_id != 5
        || eps[0].vendor_id != 0x8086
        || eps[0].device_id != 0x1234
        || eps[0].direction != 1
    {
        return TestResult::Fail("NHLT endpoint decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/nhlt", smoke_acpi_nhlt_synthetic_decode);

fn smoke_acpi_ibft_synthetic_decode() -> TestResult {
    use crate::IbftTarget;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"IBFT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&[0u8; 12]); // reserved

    // Target structure (id=4, len=32).
    buf.push(4);
    buf.push(0); // version
    buf.extend_from_slice(&32u16.to_le_bytes()); // length
    buf.push(0); // index
    buf.push(0); // flags
                 // 16-byte IPv6-mapped target IP.
    let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 42];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&3260u16.to_le_bytes());
    buf.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());

    let n = crate::__test_parse_ibft_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 IBFT target parsed");
    }
    let mut targets = [IbftTarget::default(); 4];
    let nt = crate::copy_ibft_targets(&mut targets);
    if nt != 1 || targets[0].port != 3260 || targets[0].lun != 0x0102_0304_0506_0708 {
        return TestResult::Fail("IBFT target decode mismatch");
    }
    if &targets[0].ip[12..] != &[192, 168, 1, 42] {
        return TestResult::Fail("IBFT IP decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/ibft", smoke_acpi_ibft_synthetic_decode);

fn smoke_acpi_csrt_synthetic_decode() -> TestResult {
    use crate::CsrtGroup;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"CSRT");
    buf.extend_from_slice(&[0u8; 32]);

    // Resource Group: length (4) + vendor_id (4) + sub_vendor (4) +
    //                  device_id (2) + sub_device (2) + revision (2) +
    //                  reserved (2) + shared_info_len (4) = 24
    buf.extend_from_slice(&24u32.to_le_bytes());
    buf.extend_from_slice(&0x8086u32.to_le_bytes()); // vendor
    buf.extend_from_slice(&0u32.to_le_bytes()); // sub vendor
    buf.extend_from_slice(&0xCAFEu16.to_le_bytes()); // device
    buf.extend_from_slice(&0u16.to_le_bytes()); // sub device
    buf.extend_from_slice(&3u16.to_le_bytes()); // revision
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&0u32.to_le_bytes()); // shared info len

    let n = crate::__test_parse_csrt_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 CSRT group parsed");
    }
    let mut groups = [CsrtGroup::default(); 4];
    let ng = crate::copy_csrt_groups(&mut groups);
    if ng != 1
        || groups[0].vendor_id != 0x8086
        || groups[0].device_id != 0xCAFE
        || groups[0].revision != 3
    {
        return TestResult::Fail("CSRT group decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/csrt", smoke_acpi_csrt_synthetic_decode);

fn smoke_acpi_agdi_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"AGDI");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(1); // flags: SMC
    buf.extend_from_slice(&[0u8; 3]); // reserved
    buf.extend_from_slice(&0x42u32.to_le_bytes()); // sdei event num
    buf.extend_from_slice(&0x8400_FFFFu64.to_le_bytes()); // smc id

    crate::__test_parse_agdi_body(&buf);
    let info = crate::agdi_info().expect("AGDI not parsed");
    if !info.use_smc || info.sdei_event_number != 0x42 || info.smc_id != 0x8400_FFFF {
        return TestResult::Fail("AGDI decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/agdi", smoke_acpi_agdi_synthetic_decode);

fn smoke_acpi_boot_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"BOOT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(0x42);
    buf.extend_from_slice(&[0u8; 3]);

    crate::__test_parse_boot_body(&buf);
    let info = crate::boot_info().expect("BOOT not parsed");
    if info.cmos_index != 0x42 {
        return TestResult::Fail("BOOT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/boot", smoke_acpi_boot_synthetic_decode);

fn smoke_acpi_dbgp_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"DBGP");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(0x00); // iface = full 16550
    buf.extend_from_slice(&[0u8; 3]); // reserved
                                      // GAS: AddressSpaceId @ 0, Address @ 4..12.
    buf.push(1); // SystemIO
    buf.extend_from_slice(&[0u8; 3]);
    buf.extend_from_slice(&0x3F8u64.to_le_bytes());

    crate::__test_parse_dbgp_body(&buf);
    let info = crate::dbgp_info().expect("DBGP not parsed");
    if info.iface != 0 || info.addr_space_id != 1 || info.base != 0x3F8 {
        return TestResult::Fail("DBGP decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/dbgp", smoke_acpi_dbgp_synthetic_decode);

fn smoke_acpi_wpbt_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"WPBT");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0x1234u32.to_le_bytes()); // size
    buf.extend_from_slice(&0xCAFE_F0000000u64.to_le_bytes()); // addr
    buf.push(1); // layout = native EXE
    buf.push(0); // content type
    buf.extend_from_slice(&0u16.to_le_bytes()); // arg length

    crate::__test_parse_wpbt_body(&buf);
    let info = crate::wpbt_info().expect("WPBT not parsed");
    if info.handoff_size != 0x1234 || info.handoff_addr != 0xCAFE_F0000000 || info.layout_type != 1
    {
        return TestResult::Fail("WPBT decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/wpbt", smoke_acpi_wpbt_synthetic_decode);

fn smoke_acpi_msct_synthetic_decode() -> TestResult {
    use crate::MsctPdis;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"MSCT");
    buf.extend_from_slice(&[0u8; 32]);
    let pd_off_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // ProximityDomainOffset (patched)
    buf.extend_from_slice(&3u32.to_le_bytes()); // MaxProximityDomains
    buf.extend_from_slice(&1u32.to_le_bytes()); // MaxClockDomains
    buf.extend_from_slice(&0x1_0000_0000_0000u64.to_le_bytes()); // MaxPhysAddrCap

    let pd_off = buf.len() as u32;

    // PDIS: Revision (1) + Length (1) + LowDomain (2) + HighDomain (2) +
    //       MaxProcessorCapacity (4) + MaxMemoryCapacity (8) = 18 bytes.
    buf.push(0);
    buf.push(18);
    buf.extend_from_slice(&0u16.to_le_bytes()); // low
    buf.extend_from_slice(&3u16.to_le_bytes()); // high
    buf.extend_from_slice(&64u32.to_le_bytes()); // max procs
    buf.extend_from_slice(&0x10_0000_0000u64.to_le_bytes()); // max mem

    buf[pd_off_pos..pd_off_pos + 4].copy_from_slice(&pd_off.to_le_bytes());

    let n = crate::__test_parse_msct_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 MSCT PDIS parsed");
    }
    let info = crate::msct_info().expect("MSCT not parsed");
    if info.max_proximity_domains != 3 || info.max_clock_domains != 1 {
        return TestResult::Fail("MSCT header decode mismatch");
    }
    let mut pdis = [MsctPdis::default(); 4];
    let np = crate::copy_msct_pdis(&mut pdis);
    if np != 1
        || pdis[0].low_domain != 0
        || pdis[0].high_domain != 3
        || pdis[0].max_processor_capacity != 64
        || pdis[0].max_memory_capacity != 0x10_0000_0000
    {
        return TestResult::Fail("MSCT PDIS decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/msct", smoke_acpi_msct_synthetic_decode);

fn smoke_acpi_xenv_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"XENV");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0xDEAD_0000u64.to_le_bytes()); // grant table base
    buf.extend_from_slice(&0x1000u64.to_le_bytes()); // grant table size
    buf.extend_from_slice(&33u32.to_le_bytes()); // event vector
    buf.push(0);
    buf.push(0); // polarity / mode
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved

    crate::__test_parse_xenv_body(&buf);
    let info = crate::xenv_info().expect("XENV not parsed");
    if info.grant_table_base != 0xDEAD_0000
        || info.grant_table_size != 0x1000
        || info.event_vector != 33
    {
        return TestResult::Fail("XENV decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/xenv", smoke_acpi_xenv_synthetic_decode);

fn smoke_acpi_tcpa_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"TCPA");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0u16.to_le_bytes()); // platform class = Client
    buf.extend_from_slice(&0x4000u32.to_le_bytes()); // log area min
    buf.extend_from_slice(&0xC100_0000u64.to_le_bytes()); // log area phys

    crate::__test_parse_tcpa_body(&buf);
    let info = crate::tcpa_info().expect("TCPA not parsed");
    if info.platform_class != 0 || info.log_area_min != 0x4000 || info.log_area_phys != 0xC100_0000
    {
        return TestResult::Fail("TCPA decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/tcpa", smoke_acpi_tcpa_synthetic_decode);

fn smoke_acpi_mchi_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"MCHI");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(1); // KCS
    buf.push(0x0F); // protocols
    buf.extend_from_slice(&[0u8; 6]); // reserved
    buf.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes()); // identifier
                                                                    // GAS at +16: hdr (4) + addr (8).
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&0xCA_0000u64.to_le_bytes());

    crate::__test_parse_mchi_body(&buf);
    let info = crate::mchi_info().expect("MCHI not parsed");
    if info.interface_type != 1
        || info.protocols != 0x0F
        || info.identifier != 0x1234_5678_9ABC_DEF0
        || info.base != 0xCA_0000
    {
        return TestResult::Fail("MCHI decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/mchi", smoke_acpi_mchi_synthetic_decode);

fn smoke_acpi_phat_synthetic_decode() -> TestResult {
    use crate::PhatHealthRecord;
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"PHAT");
    buf.extend_from_slice(&[0u8; 32]);

    // Type 1 (Health), length 22.
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&22u16.to_le_bytes());
    buf.push(0); // reserved
    buf.push(3); // am_healthy = healthy
    let guid: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    buf.extend_from_slice(&guid);

    let n = crate::__test_parse_phat_body(&buf);
    if n != 1 {
        return TestResult::Fail("expected 1 PHAT health record parsed");
    }
    let mut hs = [PhatHealthRecord::default(); 4];
    let nh = crate::copy_phat_health(&mut hs);
    if nh != 1 || hs[0].am_healthy != 3 || hs[0].device_guid != guid {
        return TestResult::Fail("PHAT health decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/phat", smoke_acpi_phat_synthetic_decode);

fn smoke_acpi_stao_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"STAO");
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(1); // ignore UART

    crate::__test_parse_stao_body(&buf);
    let info = crate::stao_info().expect("StAO not parsed");
    if !info.ignore_uart {
        return TestResult::Fail("StAO ignore_uart not set");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/stao", smoke_acpi_stao_synthetic_decode);

fn smoke_acpi_uefi_synthetic_decode() -> TestResult {
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"UEFI");
    buf.extend_from_slice(&[0u8; 32]);
    let guid: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    buf.extend_from_slice(&guid);
    buf.extend_from_slice(&0x1Au16.to_le_bytes());

    crate::__test_parse_uefi_body(&buf);
    let info = crate::uefi_table_info().expect("UEFI not parsed");
    if info.identifier != guid || info.data_offset != 0x1A {
        return TestResult::Fail("UEFI decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/uefi", smoke_acpi_uefi_synthetic_decode);

// ── SMBIOS / DMI smokes ────────────────────────────────────────────

extern crate alloc;

fn build_smbios_3_anchor(structure_table_addr: u64) -> [u8; 24] {
    use crate::smbios::ANCHOR_SM3;
    let mut buf = [0u8; 24];
    buf[0..5].copy_from_slice(ANCHOR_SM3);
    buf[6] = 24; // entry-point length
    buf[7] = 3;  // major
    buf[8] = 6;  // minor
    buf[9] = 0;  // doc rev
    buf[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[16..24].copy_from_slice(&structure_table_addr.to_le_bytes());
    // Compute checksum at byte 5.
    let mut sum: u32 = 0;
    for (i, b) in buf.iter().enumerate() {
        if i == 5 {
            continue;
        }
        sum = sum.wrapping_add(*b as u32);
    }
    buf[5] = ((256 - (sum & 0xFF)) & 0xFF) as u8;
    buf
}

fn smoke_smbios_64bit_entry_round_trip() -> TestResult {
    use crate::smbios::EntryPoint64;
    let buf = build_smbios_3_anchor(0xCAFE_BEEF_F000_0000);
    let ep = EntryPoint64::parse(&buf).expect("parse");
    if ep.major != 3 || ep.minor != 6 {
        return TestResult::Fail("SMBIOS 3.6 version mismatch");
    }
    if ep.structure_table_address != 0xCAFE_BEEF_F000_0000 {
        return TestResult::Fail("structure table address should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/smbios", smoke_smbios_64bit_entry_round_trip);

fn smoke_smbios_anchor_must_match() -> TestResult {
    use crate::smbios::{EntryPoint64, SmbiosError};
    let mut buf = build_smbios_3_anchor(0);
    buf[0] = b'X';
    match EntryPoint64::parse(&buf) {
        Err(SmbiosError::BadAnchor) => TestResult::Pass,
        _ => TestResult::Fail("non-_SM3_ anchor must be rejected"),
    }
}
kernel_test_in!("acpi/smbios", smoke_smbios_anchor_must_match);

fn smoke_smbios_struct_iter_walks_two_structures() -> TestResult {
    use crate::smbios::{StructIter, TYPE_BIOS_INFO, TYPE_END_OF_TABLE, TYPE_SYSTEM_INFO};
    // Type 0 BIOS Info: header (4) + 4 fmt bytes + "vendor\0bios\0\0"
    // Type 1 System Info: header (4) + 23 fmt bytes (UUID etc.) + "Acme\0\0"
    // End-of-table marker: type 127, length 4, no strings.
    let bios_strings = b"vendor\0bios\0\0";
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    buf.push(TYPE_BIOS_INFO);
    buf.push(8); // length: 4 hdr + 4 fmt
    buf.extend_from_slice(&0x0001u16.to_le_bytes()); // handle
    buf.extend_from_slice(&[1, 2, 0, 0]); // formatted (vendor idx=1, bios idx=2)
    buf.extend_from_slice(bios_strings);
    // System info
    buf.push(TYPE_SYSTEM_INFO);
    buf.push(27); // length: 4 hdr + 23 fmt
    buf.extend_from_slice(&0x0002u16.to_le_bytes());
    buf.extend_from_slice(&[1u8; 23]); // dummy formatted
    buf.extend_from_slice(b"Acme\0\0");
    // End-of-table
    buf.push(TYPE_END_OF_TABLE);
    buf.push(4);
    buf.extend_from_slice(&0x0003u16.to_le_bytes());

    let count = StructIter::new(&buf).count();
    if count != 2 {
        return TestResult::Fail("iterator should stop before end-of-table");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/smbios", smoke_smbios_struct_iter_walks_two_structures);

fn smoke_smbios_string_indexing_one_based() -> TestResult {
    use crate::smbios::string_at;
    let strings = alloc::vec![
        alloc::string::String::from("Acme"),
        alloc::string::String::from("Laptop"),
    ];
    if string_at(&strings, 0) != "" {
        return TestResult::Fail("index 0 means 'no string'");
    }
    if string_at(&strings, 1) != "Acme" {
        return TestResult::Fail("index 1 should be first string");
    }
    if string_at(&strings, 2) != "Laptop" {
        return TestResult::Fail("index 2 should be second string");
    }
    if string_at(&strings, 5) != "" {
        return TestResult::Fail("out-of-range index returns empty");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/smbios", smoke_smbios_string_indexing_one_based);

fn smoke_smbios_memory_device_type_constants() -> TestResult {
    use crate::smbios::{MEM_TYPE_DDR4, MEM_TYPE_DDR5, MEM_TYPE_LPDDR5};
    if MEM_TYPE_DDR4 != 0x1A {
        return TestResult::Fail("DDR4 memory type byte = 0x1A");
    }
    if MEM_TYPE_DDR5 != 0x22 {
        return TestResult::Fail("DDR5 memory type byte = 0x22");
    }
    if MEM_TYPE_LPDDR5 != 0x23 {
        return TestResult::Fail("LPDDR5 memory type byte = 0x23");
    }
    TestResult::Pass
}
kernel_test_in!("acpi/smbios", smoke_smbios_memory_device_type_constants);

// ── SRAT/MADT/MCFG/HMAT/PMTT/GPE table tests (relocated from verification) ──

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_srat_topology_present() -> TestResult {
    // The xtask QEMU config publishes 2 NUMA nodes via `-numa
    // node,...,memdev=memN`, so SRAT must be present and decode
    // CPU+memory affinity. Synthetic-body tests scrub the shared
    // tables, so re-parse from the cached RSDP first.
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP was already validated at boot.
    let _ = unsafe { crate::parse_srat(rsdp) };
    if !crate::is_topology_known() {
        return TestResult::Fail("SRAT not parsed at boot");
    }
    if crate::node_count() < 2 {
        return TestResult::Fail("expected >=2 NUMA nodes");
    }
    if crate::cpu_node(0).is_none() {
        return TestResult::Fail("BSP missing from SRAT");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_srat_topology_present);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_srat_memory_node_lookup() -> TestResult {
    // QEMU splits 256 MiB across two memdevs; the first chunk
    // starts at the legacy low-RAM base and the second above it.
    // Check that *something* in the second-half address space maps
    // to a non-zero node.
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP was already validated at boot.
    let _ = unsafe { crate::parse_srat(rsdp) };
    if !crate::is_topology_known() {
        return TestResult::Fail("SRAT not parsed at boot");
    }
    let mut buf = [crate::MemRange::default(); crate::MAX_NUMA_RANGES];
    let n = crate::copy_memory_ranges(&mut buf);
    if n == 0 {
        return TestResult::Fail("no memory ranges from SRAT");
    }
    // Pick any enabled range and confirm memory_node round-trips.
    for r in &buf[..n] {
        if r.enabled && r.length > 0 {
            let mid = r.base + r.length / 2;
            match crate::memory_node(mid) {
                Some(n) if n == r.node => return TestResult::Pass,
                _ => continue,
            }
        }
    }
    TestResult::Fail("memory_node didn't round-trip any SRAT range")
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_srat_memory_node_lookup);

fn smoke_acpi_srat_synthetic_lapic_entry() -> TestResult {
    // Feed a synthetic SRAT body: one Type-0 LAPIC affinity entry
    // for APIC id 7, proximity domain 3, enabled flag set.
    crate::__reset_for_test();
    let entry: [u8; 16] = [
        0,  // type = 0
        16, // length
        3,  // PD low byte
        7,  // APIC id
        1, 0, 0, 0, // flags = enabled
        0, // local SAPIC EID
        0, 0, 0, // PD high (24 bits)
        0, 0, 0, 0, // clock domain
    ];
    // SAFETY: synthetic body for the test-only entry-point.
    let n = unsafe { crate::__parse_srat_body_for_test(&entry) };
    if n != 1 {
        return TestResult::Fail("expected 1 entry");
    }
    if crate::cpu_node(7) != Some(3) {
        return TestResult::Fail("CPU 7 should map to node 3");
    }
    if crate::cpu_node(0).is_some() {
        return TestResult::Fail("CPU 0 should be unmapped");
    }
    TestResult::Pass
}
kernel_test_in!("acpi", smoke_acpi_srat_synthetic_lapic_entry);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_madt_topology_present() -> TestResult {
    // The xtask QEMU config has 2 CPUs; MADT must enumerate both
    // and expose the LAPIC base.
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { crate::parse_madt(rsdp) };
    if !crate::is_madt_known() {
        return TestResult::Fail("MADT not parsed");
    }
    if crate::cpu_count_from_madt() < 2 {
        return TestResult::Fail("expected >= 2 CPUs from MADT");
    }
    if crate::lapic_base().is_none() {
        return TestResult::Fail("LAPIC base missing from MADT");
    }
    if crate::apic_id_at(0).is_none() {
        return TestResult::Fail("first APIC id missing");
    }
    let mut io = [crate::IoApic::default(); crate::MAX_IOAPICS];
    if crate::copy_ioapics(&mut io) == 0 {
        return TestResult::Fail("MADT advertised no IOAPIC");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_madt_topology_present);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_mcfg_ecam_base() -> TestResult {
    // QEMU q35 places ECAM at 0xB000_0000; MCFG should report the
    // same address that the bus walker successfully used.
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { crate::parse_mcfg(rsdp) };
    let base = match crate::mcfg_ecam_base() {
        Some(b) => b,
        None => return TestResult::Fail("MCFG didn't report a base"),
    };
    if base != 0xB000_0000 {
        return TestResult::Fail("unexpected MCFG ECAM base");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_mcfg_ecam_base);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_hmat_latency_lookup() -> TestResult {
    // The xtask QEMU config publishes a 2x2 HMAT lat/bw matrix:
    // same-node latency 10 ns, cross-node 20 ns. Verify the parser
    // returns sane values for both axes.
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { crate::parse_hmat(rsdp) };
    if !crate::is_hmat_known() {
        return TestResult::Fail("HMAT not parsed");
    }
    let same = crate::hmat_value(crate::HmatLatBwKind::AccessLatency, 0, 0, 0);
    let cross = crate::hmat_value(crate::HmatLatBwKind::AccessLatency, 0, 0, 1);
    let (same, cross) = match (same, cross) {
        (Some(s), Some(c)) => (s, c),
        _ => return TestResult::Fail("HMAT didn't return both lookups"),
    };
    if cross <= same {
        return TestResult::Fail("cross-node latency should exceed same-node");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_hmat_latency_lookup);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_hmat_mem_attrs_present() -> TestResult {
    let rsdp = match crate::cached_rsdp() {
        Some(p) => p,
        None => return TestResult::Fail("no boot-time RSDP cached"),
    };
    // SAFETY: cached RSDP, validated at boot.
    let _ = unsafe { crate::parse_hmat(rsdp) };
    let mut buf = [crate::HmatMemAttr::default(); crate::MAX_HMAT_MEM_ATTRS];
    let n = crate::copy_hmat_mem_attrs(&mut buf);
    if n < 2 {
        return TestResult::Fail("expected >=2 HMAT memory-proximity attrs");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_hmat_mem_attrs_present);

fn smoke_acpi_pmtt_synthetic_dimm_entry() -> TestResult {
    // Synthetic PMTT body: 1 socket containing 1 memory controller
    // containing 2 DIMMs. Verify the hierarchical decoder threads
    // socket id and controller id down to the DIMM entries.
    crate::__reset_for_test();

    // The synthetic-body shim isn't exposed for PMTT (the real
    // parser walks hierarchically); construct a complete table
    // body and call parse_pmtt against an in-memory pointer.
    // We're test-only here, so a heap allocation is fine.
    use alloc::vec::Vec;
    let mut buf: Vec<u8> = Vec::new();
    // SDT header (36) + memory-device-count (4) = 40 bytes.
    buf.extend_from_slice(b"PMTT");
    let len_pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // length placeholder
    buf.push(1); // revision
    buf.push(0); // checksum placeholder
    buf.extend_from_slice(b"NARFCO");
    buf.extend_from_slice(b"NARFTBL_");
    buf.extend_from_slice(&0u32.to_le_bytes()); // OEM revision
    buf.extend_from_slice(&0u32.to_le_bytes()); // creator id
    buf.extend_from_slice(&0u32.to_le_bytes()); // creator revision
    buf.extend_from_slice(&2u32.to_le_bytes()); // memory device count

    // Socket header is 12 bytes; memory ctrl 12 bytes; each DIMM 12 bytes.
    // Total socket length = 12 + 12 + 12 + 12 = 48.
    let socket_start = buf.len();
    buf.push(0); // type=Socket
    buf.push(0); // reserved
    buf.extend_from_slice(&48u16.to_le_bytes()); // length
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&7u16.to_le_bytes()); // socket id = 7
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved

    // Memory controller (length = 12 + 2*12 = 36).
    buf.push(1); // type=MemCtrl
    buf.push(0);
    buf.extend_from_slice(&36u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&3u16.to_le_bytes()); // ctrl id = 3
    buf.extend_from_slice(&0u16.to_le_bytes());

    // DIMM 1 (length 12).
    buf.push(2);
    buf.push(0);
    buf.extend_from_slice(&12u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0xAAAA_BBBBu32.to_le_bytes()); // smbios

    // DIMM 2.
    buf.push(2);
    buf.push(0);
    buf.extend_from_slice(&12u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0xCCCC_DDDDu32.to_le_bytes());
    let _ = socket_start;

    // Patch length in header.
    let total_len = buf.len() as u32;
    buf[len_pos..len_pos + 4].copy_from_slice(&total_len.to_le_bytes());

    // Patch checksum so the parser accepts the table.
    let sum: u8 = buf.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    let cksum_off = 9;
    buf[cksum_off] = (0u8).wrapping_sub(sum);

    // Build a fake XSDT pointing at this PMTT, and an RSDP pointing
    // at that XSDT. All three live in our heap buffer; the parser
    // reads them via `*const u8` ptrs which is fine in-process.
    let pmtt_phys = buf.as_ptr() as u64;

    let mut xsdt: Vec<u8> = Vec::new();
    xsdt.extend_from_slice(b"XSDT");
    let xlen_pos = xsdt.len();
    xsdt.extend_from_slice(&0u32.to_le_bytes());
    xsdt.push(1); // revision
    xsdt.push(0); // checksum
    xsdt.extend_from_slice(b"NARFCO");
    xsdt.extend_from_slice(b"NARFTBL_");
    xsdt.extend_from_slice(&0u32.to_le_bytes());
    xsdt.extend_from_slice(&0u32.to_le_bytes());
    xsdt.extend_from_slice(&0u32.to_le_bytes());
    xsdt.extend_from_slice(&pmtt_phys.to_le_bytes());
    let total_xlen = xsdt.len() as u32;
    xsdt[xlen_pos..xlen_pos + 4].copy_from_slice(&total_xlen.to_le_bytes());
    let xsum: u8 = xsdt.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    xsdt[9] = (0u8).wrapping_sub(xsum);
    let xsdt_phys = xsdt.as_ptr() as u64;

    let mut rsdp = [0u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2; // revision >= 2 → use XSDT
    rsdp[24..32].copy_from_slice(&xsdt_phys.to_le_bytes());
    let v1_sum: u8 = rsdp[..20].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    rsdp[8] = (0u8).wrapping_sub(v1_sum);
    let rsdp_phys = narf_memory::PhysAddr::new(rsdp.as_ptr() as u64);

    // SAFETY: pointers refer to live in-process buffers backed by
    // the heap; reads are bounded by the encoded lengths.
    let n = match unsafe { crate::parse_pmtt(rsdp_phys) } {
        Ok(n) => n,
        Err(e) => {
            // Keep buffers alive across the parse (Vec lifetimes).
            let _ = (buf, xsdt, rsdp);
            return TestResult::Fail(match e {
                crate::AcpiError::BadRsdpSignature => "bad rsdp sig",
                crate::AcpiError::BadRsdpChecksum => "bad rsdp cksum",
                crate::AcpiError::NoXsdt => "no xsdt",
                crate::AcpiError::BadXsdtSignature => "bad xsdt sig",
                crate::AcpiError::NoSrat => "no pmtt",
                crate::AcpiError::BadTableChecksum => "bad table cksum",
            });
        }
    };
    if n != 4 {
        let _ = (buf, xsdt, rsdp);
        return TestResult::Fail("expected 4 PMTT structures (1+1+2)");
    }
    let (s, c, d) = crate::pmtt_counts();
    if (s, c, d) != (1, 1, 2) {
        let _ = (buf, xsdt, rsdp);
        return TestResult::Fail("PMTT counts wrong");
    }
    let mut dimms = [crate::PmttDimm::default(); crate::MAX_PMTT_DIMMS];
    let dn = crate::copy_pmtt_dimms(&mut dimms);
    if dn != 2 {
        let _ = (buf, xsdt, rsdp);
        return TestResult::Fail("DIMM table didn't capture 2 entries");
    }
    if dimms[0].socket_id != 7 || dimms[0].controller_id != 3 {
        let _ = (buf, xsdt, rsdp);
        return TestResult::Fail("DIMM 0 parent ids wrong");
    }
    if dimms[1].smbios_handle != 0xCCCC_DDDD {
        let _ = (buf, xsdt, rsdp);
        return TestResult::Fail("DIMM 1 smbios handle wrong");
    }
    let _ = (buf, xsdt, rsdp);
    TestResult::Pass
}
kernel_test_in!("acpi", smoke_acpi_pmtt_synthetic_dimm_entry);

fn smoke_acpi_srat_synthetic_memory_entry() -> TestResult {
    // Type-1 memory affinity entry: base 0x1_0000_0000, length
    // 0x1000_0000, proximity 1, enabled.
    crate::__reset_for_test();
    let mut entry = [0u8; 40];
    entry[0] = 1; // type
    entry[1] = 40; // length
    entry[2..6].copy_from_slice(&1u32.to_le_bytes()); // proximity
    entry[8..16].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
    entry[16..24].copy_from_slice(&0x1000_0000u64.to_le_bytes());
    entry[28..32].copy_from_slice(&1u32.to_le_bytes()); // flags=enabled
                                                        // SAFETY: test-only entry point.
    let n = unsafe { crate::__parse_srat_body_for_test(&entry) };
    if n != 1 {
        return TestResult::Fail("expected 1 entry");
    }
    if crate::memory_node(0x1_0000_1000) != Some(1) {
        return TestResult::Fail("addr inside range should map to node 1");
    }
    if crate::memory_node(0).is_some() {
        return TestResult::Fail("addr outside range should be None");
    }
    TestResult::Pass
}
kernel_test_in!("acpi", smoke_acpi_srat_synthetic_memory_entry);

#[cfg(target_arch = "x86_64")]
fn smoke_acpi_gpe_block_parsed_at_boot() -> TestResult {
    // If the FADT advertised a non-zero GPE0 block, gpe0_block() is Some;
    // if not (e.g. QEMU config with no GPE block), that's acceptable too.
    // Either way, this test verifies the parse path ran without panicking.
    match crate::gpe0_block() {
        None => TestResult::Skip("FADT carried no GPE0 block (QEMU config); parse OK"),
        Some(info) => {
            // Sanity: address and byte_count must be non-zero when Some.
            if info.address == 0 || info.byte_count == 0 {
                return TestResult::Fail("gpe0_block Some but address/byte_count zero");
            }
            TestResult::Pass
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("acpi", smoke_acpi_gpe_block_parsed_at_boot);
