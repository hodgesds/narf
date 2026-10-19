//! Smokes for boot-time SMBIOS discovery (`discover.rs`): Linux
//! `dmi_scan.c` entry-point checks, EFI configuration-table lookup,
//! the 0xF0000 scan, `dmi_decode_table` walk bounds, raw-structure
//! retention, and the table the boot scan actually found.

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    self as smbios, dmi_present, efi_smbios_tables, scan_legacy_region, scan_machine,
    smbios3_present, PhysRead, RawTable, Source, Sources, TableLocation,
    EFI_SYSTEM_TABLE_SIGNATURE, SMBIOS3_TABLE_GUID, SMBIOS_TABLE_GUID,
};

macro_rules! check {
    ($c:expr, $m:expr) => {
        if !$c {
            return TestResult::Fail($m);
        }
    };
}

/// Sparse synthetic physical memory: a read succeeds only when it lies
/// inside one region.
struct Mem(Vec<(u64, Vec<u8>)>);

impl Mem {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn put(&mut self, base: u64, bytes: &[u8]) {
        self.0.push((base, bytes.to_vec()));
    }
}

impl PhysRead for Mem {
    fn read(&self, phys: u64, out: &mut [u8]) -> bool {
        for (base, b) in &self.0 {
            if phys >= *base && phys + out.len() as u64 <= *base + b.len() as u64 {
                let o = (phys - base) as usize;
                out.copy_from_slice(&b[o..o + out.len()]);
                return true;
            }
        }
        false
    }
}

fn fix_sum(buf: &mut [u8], at: usize, len: usize) {
    buf[at] = 0;
    let s = buf[..len].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    buf[at] = 0u8.wrapping_sub(s);
}

fn sm3_entry(base: u64, len: u32, ep_len: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..5].copy_from_slice(b"_SM3_");
    b[6] = ep_len;
    b[7] = 3;
    b[8] = 5;
    b[9] = 1;
    b[10] = 1;
    b[12..16].copy_from_slice(&len.to_le_bytes());
    b[16..24].copy_from_slice(&base.to_le_bytes());
    fix_sum(&mut b, 5, ep_len as usize);
    b
}

fn sm_entry(base: u32, len: u16, num: u16, ver: (u8, u8), ep_len: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(b"_SM_");
    b[5] = ep_len;
    b[6] = ver.0;
    b[7] = ver.1;
    b[16..21].copy_from_slice(b"_DMI_");
    b[22..24].copy_from_slice(&len.to_le_bytes());
    b[24..28].copy_from_slice(&base.to_le_bytes());
    b[28..30].copy_from_slice(&num.to_le_bytes());
    b[30] = (ver.0 << 4) | ver.1;
    let mut d = [0u8; 16];
    d.copy_from_slice(&b[16..32]);
    fix_sum(&mut d, 5, 15);
    b[16..32].copy_from_slice(&d);
    fix_sum(&mut b, 4, ep_len as usize);
    b
}

/// One structure: formatted area `fmt` (header patched in) + strings.
fn push(t: &mut Vec<u8>, kind: u8, handle: u16, fmt_tail: &[u8], strings: &[&[u8]]) {
    t.push(kind);
    t.push(4 + fmt_tail.len() as u8);
    t.extend_from_slice(&handle.to_le_bytes());
    t.extend_from_slice(fmt_tail);
    if strings.is_empty() {
        t.push(0);
    }
    for s in strings {
        t.extend_from_slice(s);
        t.push(0);
    }
    t.push(0);
}

/// Type 1 (product "NARF-Box") + type 0xF8 (`BDF_le_lfr-1`) + EOT.
fn sample_table() -> Vec<u8> {
    let mut t = Vec::new();
    let mut sys = [0u8; 21];
    sys[0] = 1; // manufacturer
    sys[1] = 2; // product
    push(&mut t, 1, 0x0100, &sys, &[b"Vendor", b"NARF-Box"]);
    // ath11k_smbios_bdf: features_disabled, cc flag, cc_code, bdf_enabled
    push(
        &mut t,
        0xF8,
        0x0F80,
        &[0, 1, 0x53, 0x55, 1],
        &[b"BDF_le_lfr-1"],
    );
    push(&mut t, 127, 0xFEFF, &[], &[]);
    t
}

const SYSTAB: u64 = 0x10_0000;
const CFG: u64 = 0x10_1000;
const EP3: u64 = 0x10_2000;
const EP: u64 = 0x10_3000;
const TABLE: u64 = 0x20_0000;

fn efi_mem(rows: &[([u8; 16], u64)], sig: u64) -> Mem {
    let mut st = [0u8; 120];
    st[0..8].copy_from_slice(&sig.to_le_bytes());
    st[104..112].copy_from_slice(&(rows.len() as u64).to_le_bytes());
    st[112..120].copy_from_slice(&CFG.to_le_bytes());
    let mut cfg = Vec::new();
    for (g, t) in rows {
        cfg.extend_from_slice(g);
        cfg.extend_from_slice(&t.to_le_bytes());
    }
    let mut m = Mem::new();
    m.put(SYSTAB, &st);
    m.put(CFG, &cfg);
    m
}

fn has_product(t: &RawTable, want: &[u8]) -> bool {
    t.structures_of_type(1)
        .first()
        .and_then(|s| s.string(s.formatted()[5]))
        == Some(want)
}

// ── entry-point checks (dmi_smbios3_present / dmi_present) ─────────

fn smoke_smbios_ep3_linux_window() -> TestResult {
    let ok = sm3_entry(0x1234_5678_9000, 0x800, 24);
    let loc = smbios3_present(&ok);
    check!(
        loc == Some(TableLocation {
            base: 0x1234_5678_9000,
            len: 0x800,
            num: 0,
            version: 0x03_05_01,
        }),
        "SM3: base/len/num/be24 version"
    );
    check!(
        smbios3_present(&sm3_entry(0, 0, 32)).is_some(),
        "SM3: 32 is inside 24..=32"
    );
    // Length 23 / 33: outside Linux's window even with a good checksum.
    let mut short = sm3_entry(1, 1, 24);
    short[6] = 23;
    fix_sum(&mut short, 5, 23);
    check!(smbios3_present(&short).is_none(), "SM3: length 23 rejected");
    let mut bad = ok;
    bad[5] ^= 1;
    check!(smbios3_present(&bad).is_none(), "SM3: checksum");
    let mut anchor = ok;
    anchor[3] = b'4';
    check!(smbios3_present(&anchor).is_none(), "SM3: anchor");
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_ep3_linux_window);

fn smoke_smbios_ep_linux_window() -> TestResult {
    let e = sm_entry(0xE_0000, 0x400, 9, (2, 8), 31);
    check!(
        dmi_present(&e)
            == Some(TableLocation {
                base: 0xE_0000,
                len: 0x400,
                num: 9,
                version: 0x02_08_00,
            }),
        "SM: base/len/num/version"
    );
    // 30 = the SMBIOS 2.1 spec mistake Linux tolerates.
    let e30 = sm_entry(1, 1, 1, (2, 1), 30);
    check!(
        dmi_present(&e30).map(|l| l.version) == Some(0x02_01_00),
        "SM: length 30"
    );
    // Version fixups: 2.51 -> 2.6, 2.31/2.33 -> 2.3.
    check!(
        dmi_present(&sm_entry(1, 1, 1, (2, 0x33), 31)).map(|l| l.version) == Some(0x02_06_00),
        "SM: 2.51 fixup"
    );
    check!(
        dmi_present(&sm_entry(1, 1, 1, (2, 0x1F), 31)).map(|l| l.version) == Some(0x02_03_00),
        "SM: 2.31 fixup"
    );
    // A broken _SM_ header with a valid _DMI_ is legacy DMI (BCD ver).
    let mut legacy = sm_entry(1, 1, 1, (2, 4), 31);
    legacy[4] ^= 0x55;
    check!(
        dmi_present(&legacy).map(|l| l.version) == Some(0x02_04_00),
        "SM: legacy DMI BCD version"
    );
    // ... and from_anchor_bytes, which needs the _SM_ header, refuses it.
    check!(
        smbios::from_anchor_bytes(&legacy).is_none(),
        "anchor: needs _SM_"
    );
    // _DMI_ checksum broken: nothing, whatever _SM_ says.
    let mut nodmi = e;
    nodmi[21] ^= 1;
    check!(dmi_present(&nodmi).is_none(), "SM: _DMI_ checksum");
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_ep_linux_window);

// ── EFI configuration table ───────────────────────────────────────

fn smoke_smbios_efi_config_table() -> TestResult {
    let other = [0xAAu8; 16];
    let m = efi_mem(
        &[
            (other, 0x999),
            (SMBIOS_TABLE_GUID, EP),
            (SMBIOS3_TABLE_GUID, 0x111),
            (SMBIOS3_TABLE_GUID, EP3), // later duplicate wins
        ],
        EFI_SYSTEM_TABLE_SIGNATURE,
    );
    check!(
        efi_smbios_tables(SYSTAB, &m) == Some((Some(EP3), Some(EP))),
        "both GUIDs found; last duplicate wins"
    );
    let m = efi_mem(&[(SMBIOS_TABLE_GUID, EP)], EFI_SYSTEM_TABLE_SIGNATURE ^ 1);
    check!(
        efi_smbios_tables(SYSTAB, &m).is_none(),
        "bad signature = no EFI"
    );
    let m = efi_mem(&[(other, 1)], EFI_SYSTEM_TABLE_SIGNATURE);
    check!(
        efi_smbios_tables(SYSTAB, &m) == Some((None, None)),
        "no SMBIOS rows"
    );
    check!(efi_smbios_tables(0x5000, &m).is_none(), "unreadable systab");
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_efi_config_table);

// ── dmi_scan_machine precedence ───────────────────────────────────

fn smoke_smbios_scan_machine_efi_precedence() -> TestResult {
    let table = sample_table();
    let mut m = efi_mem(
        &[(SMBIOS_TABLE_GUID, EP), (SMBIOS3_TABLE_GUID, EP3)],
        EFI_SYSTEM_TABLE_SIGNATURE,
    );
    m.put(EP3, &sm3_entry(TABLE, table.len() as u32 + 64, 24));
    m.put(
        EP,
        &sm_entry(TABLE as u32, table.len() as u16, 3, (2, 8), 31),
    );
    // The SM3 length is a maximum: the table is followed by slack.
    let mut padded = table.clone();
    padded.resize(table.len() + 64, 0);
    m.put(TABLE, &padded);
    let src = Sources {
        efi_system_table: Some(SYSTAB),
        legacy_scan: true,
        ..Sources::default()
    };
    let Some(t) = scan_machine(&src, &m) else {
        return TestResult::Fail("EFI SMBIOS3 table not found");
    };
    check!(
        t.source() == Some(Source::EfiSmbios3),
        "SMBIOS3 has precedence"
    );
    check!(t.version() == 0x03_05_01, "dmi_ver from SM3");
    // SMBIOS 3 walks to the end-of-table marker and trims after it.
    check!(t.bytes().len() == table.len(), "trimmed to end-of-table");
    check!(has_product(&t, b"NARF-Box"), "type-1 product string");

    // A corrupt 64-bit entry falls back to the 32-bit one.
    let mut bad3 = sm3_entry(TABLE, 64, 24);
    bad3[5] ^= 1;
    let mut m2 = efi_mem(
        &[(SMBIOS_TABLE_GUID, EP), (SMBIOS3_TABLE_GUID, EP3)],
        EFI_SYSTEM_TABLE_SIGNATURE,
    );
    m2.put(EP3, &bad3);
    m2.put(
        EP,
        &sm_entry(TABLE as u32, table.len() as u16, 3, (2, 8), 31),
    );
    m2.put(TABLE, &table);
    let t = scan_machine(&src, &m2);
    check!(
        t.as_ref().and_then(|t| t.source()) == Some(Source::EfiSmbios),
        "fallback to efi.smbios"
    );
    check!(
        t.map(|t| t.structure_count()) == Some(3),
        "dmi_num from the 32-bit entry"
    );
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_scan_machine_efi_precedence);

fn smoke_smbios_scan_machine_no_legacy_under_efi() -> TestResult {
    // EFI enabled but no SMBIOS rows: Linux does not fall back to the
    // F-segment scan, even with a valid anchor there.
    let table = sample_table();
    let mut m = efi_mem(&[([1u8; 16], 0)], EFI_SYSTEM_TABLE_SIGNATURE);
    let mut region = alloc::vec![0u8; 0x10000];
    region[0x100..0x120].copy_from_slice(&sm3_entry(TABLE, table.len() as u32, 24));
    m.put(0xF0000, &region);
    m.put(TABLE, &table);
    let efi = Sources {
        efi_system_table: Some(SYSTAB),
        legacy_scan: true,
        ..Sources::default()
    };
    check!(scan_machine(&efi, &m).is_none(), "EFI: no legacy scan");
    // The loader's multiboot2 copy still finds it.
    let tagged = Sources {
        loader_smbios3: Some(sm3_entry(TABLE, table.len() as u32, 24)),
        ..efi
    };
    check!(
        scan_machine(&tagged, &m).and_then(|t| t.source()) == Some(Source::LoaderSmbios3),
        "loader tag"
    );
    // Without EFI the scan runs.
    let bios = Sources {
        legacy_scan: true,
        ..Sources::default()
    };
    check!(
        scan_machine(&bios, &m).and_then(|t| t.source()) == Some(Source::LegacySmbios3),
        "non-EFI legacy scan"
    );
    // ... unless the arch has no fallback (CONFIG_..._NON_EFI_FALLBACK=n).
    check!(
        scan_machine(&Sources::default(), &m).is_none(),
        "no fallback"
    );
    // An entry whose table cannot be read is not "present".
    let unread = Sources {
        loader_smbios3: Some(sm3_entry(0x7000_0000, 64, 24)),
        ..Sources::default()
    };
    check!(
        scan_machine(&unread, &m).is_none(),
        "dmi_walk_early failure"
    );
    TestResult::Pass
}
kernel_test_in!(
    "firmware/smbios",
    smoke_smbios_scan_machine_no_legacy_under_efi
);

fn smoke_smbios_legacy_scan_order() -> TestResult {
    let mut region = alloc::vec![0u8; 0x10000];
    // _SM_ low, _SM3_ high: every SM3 candidate is tried first.
    region[0x10..0x30].copy_from_slice(&sm_entry(0xE_0000, 16, 1, (2, 8), 31));
    region[0x8000..0x8020].copy_from_slice(&sm3_entry(0x1000, 16, 24));
    let hit = scan_legacy_region(&region, |b, sm3| {
        if sm3 {
            smbios3_present(b).map(|l| (true, l.base))
        } else {
            dmi_present(b).map(|l| (false, l.base))
        }
    });
    check!(hit == Some((true, 0x1000)), "SM3 pass first");
    // Without the SM3 anchor the second pass finds _SM_ (window q-16).
    region[0x8000..0x8020].fill(0);
    let hit = scan_legacy_region(&region, |b, sm3| {
        if sm3 {
            smbios3_present(b).map(|l| l.base)
        } else {
            dmi_present(b).map(|l| l.base)
        }
    });
    check!(hit == Some(0xE_0000), "SM pass");
    // A rejected candidate keeps the scan going.
    let mut tries = 0;
    let hit = scan_legacy_region(&region, |b, sm3| {
        if sm3 {
            return None;
        }
        let l = dmi_present(b)?;
        tries += 1;
        (tries > 1).then_some(l)
    });
    check!(
        hit.is_none() && tries == 1,
        "dmi_walk_early failure continues"
    );
    // Linux's SM3 window never starts at the last paragraph.
    let mut tail = alloc::vec![0u8; 0x10000];
    let ep = sm3_entry(0x1000, 16, 24);
    tail[0xFFF0..].copy_from_slice(&ep[..16]);
    check!(
        scan_legacy_region(&tail, |b, sm3| if sm3 { smbios3_present(b) } else { None }).is_none(),
        "last paragraph not an SM3 candidate"
    );
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_legacy_scan_order);

// ── dmi_decode_table walk + raw retention ─────────────────────────

fn smoke_smbios_raw_type_f8_retained() -> TestResult {
    let t = RawTable::from_bytes(sample_table(), 0);
    let f8 = t.structures_of_type(0xF8);
    check!(f8.len() == 1, "one type-0xF8 structure");
    let s = f8[0];
    check!(s.handle == 0x0F80 && s.length() == 9, "handle + length 9");
    check!(
        s.formatted() == [0xF8, 9, 0x80, 0x0F, 0, 1, 0x53, 0x55, 1],
        "formatted area"
    );
    check!(
        s.strings() == b"BDF_le_lfr-1\0\0",
        "string set incl. double NUL"
    );
    check!(s.string(1) == Some(&b"BDF_le_lfr-1"[..]), "string 1");
    check!(
        s.string(2).is_none() && s.string(0).is_none(),
        "strings 0 / 2"
    );
    check!(t.structures().len() == 3, "type 1, 0xF8, 127");
    check!(t.structures_of_type(0x42).is_empty(), "absent type");
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_raw_type_f8_retained);

fn smoke_smbios_walk_bounds() -> TestResult {
    // 32-bit table: end-of-table is NOT trusted; num bounds the walk.
    let mut t = sample_table();
    push(&mut t, 0xF8, 0x0F81, &[0, 0, 0, 0, 1], &[b"BDF_after"]);
    let raw = RawTable::from_bytes(t.clone(), 4);
    check!(
        raw.structures_of_type(0xF8).len() == 2,
        "OEM past EOT (32-bit)"
    );
    let raw = RawTable::from_bytes(t.clone(), 3);
    check!(
        raw.structures_of_type(0xF8).len() == 1,
        "dmi_num stops the walk"
    );
    // SMBIOS 3: stops at type 127 and trims.
    let raw = RawTable::from_bytes(t.clone(), 0);
    check!(
        raw.structures_of_type(0xF8).len() == 1,
        "SMBIOS3 stops at EOT"
    );
    check!(raw.bytes().len() == sample_table().len(), "trim after EOT");
    // A structure whose string set runs off the table is not decoded.
    let mut cut2 = Vec::new();
    push(&mut cut2, 0xF8, 1, &[0, 0, 0, 0, 1], &[b"BDF_x"]);
    cut2.truncate(cut2.len() - 1); // lose the final NUL
    let raw = RawTable::from_bytes(cut2, 0);
    check!(
        raw.structures().is_empty(),
        "unterminated string set dropped"
    );
    // A short (<4) entry stops the walk.
    let mut short = Vec::new();
    push(&mut short, 1, 1, &[0; 21], &[]);
    short.extend_from_slice(&[0xF8, 2, 0, 0, 0, 0]);
    push(&mut short, 0xF8, 2, &[0, 0, 0, 0, 1], &[b"BDF_x"]);
    let raw = RawTable::from_bytes(short, 0);
    check!(
        raw.structures().len() == 1 && raw.structures_of_type(0xF8).is_empty(),
        "short entry stops the walk"
    );
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_walk_bounds);

// ── the table this boot found ─────────────────────────────────────

fn smoke_smbios_parsed_at_boot() -> TestResult {
    let Some(t) = smbios::boot_table() else {
        return TestResult::Skip("firmware provided no SMBIOS table");
    };
    check!(smbios::is_known(), "is_known after the boot scan");
    let sys = t.structures_of_type(1);
    check!(!sys.is_empty(), "type 1 (System Information) present");
    check!(
        !t.structures_of_type(127).is_empty() || t.structure_count() != 0,
        "SMBIOS3 table ends with end-of-table"
    );
    check!(
        smbios::raw_structures_of_type(1).len() == sys.len(),
        "raw_structures_of_type reads the boot table"
    );
    let s = sys[0];
    check!(s.formatted().len() >= 8, "type 1 formatted area");
    // QEMU names itself in type 1 (manufacturer "QEMU" unless -smbios
    // overrides it); any firmware must at least give a manufacturer.
    let manufacturer = s.string(s.formatted()[4]);
    check!(manufacturer.is_some(), "type-1 manufacturer string");
    TestResult::Pass
}
kernel_test_in!("firmware/smbios", smoke_smbios_parsed_at_boot);
