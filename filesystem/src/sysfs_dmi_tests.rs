//! Smokes for the DMI projections in sysfs: Linux `drivers/firmware/dmi-id.c`
//! (`/sys/class/dmi/id`, the class device at `/sys/devices/virtual/dmi/id`)
//! and the raw tables `dmi_scan.c::dmi_init` publishes under
//! `/sys/firmware/dmi/tables`.
//!
//! The fixture tables are found the way the boot scan finds one
//! (`narf_firmware_smbios::scan_machine` over synthetic memory, through the
//! loader's copy of the entry point), so the entry point a table was found
//! through is the one `smbios_entry_point` must hand back.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_firmware_smbios::{scan_machine, PhysRead, Sources};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::procfs::poll_once;
use crate::sysfs::SysFs;
use crate::{DirOps, FileOps, FileType, FsInstance};

/// Sparse synthetic physical memory: a read succeeds only inside one region.
struct Mem(Vec<(u64, Vec<u8>)>);

impl PhysRead for Mem {
    fn read(&self, phys: u64, out: &mut [u8]) -> bool {
        for (base, bytes) in &self.0 {
            if phys >= *base && phys + out.len() as u64 <= *base + bytes.len() as u64 {
                let at = (phys - base) as usize;
                out.copy_from_slice(&bytes[at..at + out.len()]);
                return true;
            }
        }
        false
    }
}

fn fix_sum(buf: &mut [u8], at: usize, len: usize) {
    buf[at] = 0;
    let sum = buf[..len].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    buf[at] = 0u8.wrapping_sub(sum);
}

/// One structure: its formatted area (`formatted[1]` is its length) and
/// its string set, which ends in a double NUL.
fn structure(formatted: &[u8], strings: &[&str]) -> Vec<u8> {
    let mut s = formatted.to_vec();
    if strings.is_empty() {
        s.push(0);
    }
    for string in strings {
        s.extend_from_slice(string.as_bytes());
        s.push(0);
    }
    s.push(0);
    s
}

/// The 16 UUID bytes of the type-1 fixture.
const UUID: [u8; 16] = [
    0x03, 0x02, 0x01, 0x00, 0x05, 0x04, 0x07, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// A structure table with BIOS, system, two baseboards, chassis and
/// end-of-table, and its structure count.
fn fixture_table() -> (Vec<u8>, u16) {
    let mut bios = [0u8; 0x1A];
    bios[..4].copy_from_slice(&[0, 0x1A, 0x00, 0x00]);
    bios[4] = 1; // vendor
    bios[5] = 2; // version
    bios[6..8].copy_from_slice(&0xF000u16.to_le_bytes());
    bios[8] = 3; // release date
    bios[9] = 0xFF;
    bios[20] = 5; // system BIOS major release
    bios[21] = 32; // system BIOS minor release
    bios[22] = 0xFF; // EC firmware major: "not supported"
    bios[23] = 0xFF; // EC firmware minor
    let mut sys = [0u8; 0x1B];
    sys[..4].copy_from_slice(&[1, 0x1B, 0x01, 0x00]);
    sys[4] = 1; // manufacturer
    sys[5] = 2; // product name
    sys[6] = 3; // version
    sys[7] = 4; // serial number
    sys[8..24].copy_from_slice(&UUID);
    sys[24] = 6; // wake-up type
    sys[25] = 5; // SKU number
    sys[26] = 6; // family
    let mut board = [0u8; 0x0F];
    board[..4].copy_from_slice(&[2, 0x0F, 0x02, 0x00]);
    board[4] = 1; // manufacturer
    board[5] = 2; // product
    board[6] = 3; // version
    board[7] = 4; // serial number
    board[8] = 5; // asset tag
    board[9] = 0x09;
    board[10] = 6; // location in chassis
    board[11..13].copy_from_slice(&3u16.to_le_bytes());
    board[13] = 0x0A; // motherboard
    let mut board2 = board;
    board2[2] = 0x04;
    let mut chassis = [0u8; 0x16];
    chassis[..4].copy_from_slice(&[3, 0x16, 0x03, 0x00]);
    chassis[4] = 1; // manufacturer
    chassis[5] = 0x83; // chassis lock present | desktop
    chassis[6] = 2; // version
    chassis[7] = 3; // serial number
    chassis[8] = 0; // asset tag: no string
    chassis[9..13].copy_from_slice(&[3, 3, 3, 3]);
    let mut table = Vec::new();
    table.extend(structure(
        &bios,
        &[
            "American Megatrends International, LLC.",
            "F31",
            "06/24/2024",
        ],
    ));
    table.extend(structure(
        &sys,
        &[
            "Gigabyte Technology Co., Ltd.",
            "B650I AORUS ULTRA",
            "1.0: rev A ",
            "SN0001",
            "Default string",
            "B650 MB",
        ],
    ));
    table.extend(structure(
        &board,
        &[
            "Gigabyte Technology Co., Ltd.",
            "B650I AORUS ULTRA",
            "   ",
            "BSN0001",
            "Default string",
            "Default string",
        ],
    ));
    // A second baseboard: `dmi_save_ident` keeps the first one's strings.
    table.extend(structure(
        &board2,
        &["Second Board Vendor", "Second", "1", "2", "3", "4"],
    ));
    table.extend(structure(
        &chassis,
        &["Default string", "Default string", "CSN0001"],
    ));
    table.extend(structure(&[127, 4, 0x05, 0x00], &[]));
    (table, 6)
}

/// A 24-byte SMBIOS 3.8.0 `_SM3_` entry point.
fn sm3_entry(base: u64, max_len: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..5].copy_from_slice(b"_SM3_");
    b[6] = 24;
    b[7] = 3;
    b[8] = 8;
    b[9] = 0;
    b[10] = 1;
    b[12..16].copy_from_slice(&max_len.to_le_bytes());
    b[16..24].copy_from_slice(&base.to_le_bytes());
    fix_sum(&mut b, 5, 24);
    b
}

/// A 31-byte `_SM_` entry point with its `_DMI_` header, or the 15-byte
/// `_DMI_` header alone (legacy DMI) when `smbios` is false.
fn sm_entry(base: u32, len: u16, num: u16, ver: (u8, u8), smbios: bool) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..21].copy_from_slice(b"_DMI_");
    b[22..24].copy_from_slice(&len.to_le_bytes());
    b[24..28].copy_from_slice(&base.to_le_bytes());
    b[28..30].copy_from_slice(&num.to_le_bytes());
    b[30] = (ver.0 << 4) | ver.1;
    fix_sum(&mut b[16..], 5, 15);
    if smbios {
        b[0..4].copy_from_slice(b"_SM_");
        b[5] = 31;
        b[6] = ver.0;
        b[7] = ver.1;
        fix_sum(&mut b, 4, 31);
    }
    b
}

fn dir(parent: &Arc<dyn DirOps>, name: &str) -> Result<Arc<dyn DirOps>, &'static str> {
    parent
        .lookup_dir(name)
        .ok_or("a sysfs directory is missing")
}

/// `/sys/<components>` as a directory.
fn sys_dir(components: &[&str]) -> Result<Arc<dyn DirOps>, &'static str> {
    let mut at = SysFs::new().root();
    for name in components {
        at = dir(&at, name)?;
    }
    Ok(at)
}

fn read_all(file: &Arc<dyn FileOps>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 512];
        match poll_once(file.read(out.len() as u64, &mut chunk)) {
            Some(Ok(n)) if n > 0 => out.extend_from_slice(&chunk[..n]),
            _ => return out,
        }
    }
}

fn readlink(parent: &Arc<dyn DirOps>, name: &str) -> Option<String> {
    let link = parent.lookup(name)?;
    if link.stat().mode.file_type != FileType::Symlink {
        return None;
    }
    String::from_utf8(read_all(&link)).ok()
}

/// What `dmi_id_init_attr_table` publishes for the fixture: name, mode and
/// `sys_dmi_field_show`'s "%s\n". `dmi_string` does not trim: an all-space
/// string is empty, anything else is kept as the table spells it.
const ID_ATTRS: &[(&str, u16, &str)] = &[
    (
        "bios_vendor",
        0o444,
        "American Megatrends International, LLC.\n",
    ),
    ("bios_version", 0o444, "F31\n"),
    ("bios_date", 0o444, "06/24/2024\n"),
    ("bios_release", 0o444, "5.32\n"),
    ("sys_vendor", 0o444, "Gigabyte Technology Co., Ltd.\n"),
    ("product_name", 0o444, "B650I AORUS ULTRA\n"),
    ("product_version", 0o444, "1.0: rev A \n"),
    ("product_serial", 0o400, "SN0001\n"),
    // `%pUl`: SMBIOS 2.6+ stores the first three fields little-endian.
    (
        "product_uuid",
        0o400,
        "00010203-0405-0607-0809-0a0b0c0d0e0f\n",
    ),
    ("product_sku", 0o444, "Default string\n"),
    ("product_family", 0o444, "B650 MB\n"),
    ("board_vendor", 0o444, "Gigabyte Technology Co., Ltd.\n"),
    ("board_name", 0o444, "B650I AORUS ULTRA\n"),
    ("board_version", 0o444, "\n"),
    ("board_serial", 0o400, "BSN0001\n"),
    ("board_asset_tag", 0o444, "Default string\n"),
    ("chassis_vendor", 0o444, "Default string\n"),
    // `dmi_save_type`: the type byte's low 7 bits (0x83 = locked desktop).
    ("chassis_type", 0o444, "3\n"),
    ("chassis_version", 0o444, "Default string\n"),
    ("chassis_serial", 0o400, "CSN0001\n"),
    ("chassis_asset_tag", 0o444, "\n"),
];

/// `get_modalias` for the fixture: each present field in dmi-id.c's order
/// (`efr` is absent), `ascii_filter`ed (no spaces, controls, DEL or ':').
const MODALIAS: &str = "dmi:bvnAmericanMegatrendsInternational,LLC.:bvrF31:bd06/24/2024:br5.32\
:svnGigabyteTechnologyCo.,Ltd.:pnB650IAORUSULTRA:pvr1.0revA:rvnGigabyteTechnologyCo.,Ltd.\
:rnB650IAORUSULTRA:rvr:cvnDefaultstring:ct3:cvrDefaultstring:skuDefaultstring:pfaB650MB:";

fn check_id_device() -> Result<(), &'static str> {
    use core::fmt::Write as _;
    let class = sys_dir(&["class", "dmi"]).map_err(|_| "/sys/class/dmi is missing")?;
    if readlink(&class, "id").as_deref() != Some("../../devices/virtual/dmi/id") {
        return Err("/sys/class/dmi/id is not a link to ../../devices/virtual/dmi/id");
    }
    let id = sys_dir(&["devices", "virtual", "dmi", "id"])
        .map_err(|_| "/sys/devices/virtual/dmi/id is missing")?;
    for (name, mode, want) in ID_ATTRS {
        let Some(file) = id.lookup(name) else {
            let _ = writeln!(narf_console::Writer, "dmi/id/{name} missing");
            return Err("a DMI attribute the table has is missing");
        };
        let got = read_all(&file);
        if got != want.as_bytes() {
            let _ = writeln!(
                narf_console::Writer,
                "dmi/id/{name}: {:?}, want {want:?}",
                String::from_utf8_lossy(&got)
            );
            return Err("a DMI attribute's value is not dmi-id.c's");
        }
        let stat = file.stat();
        if stat.mode.file_type != FileType::File || stat.mode.perms != *mode {
            let _ = writeln!(
                narf_console::Writer,
                "dmi/id/{name}: mode {:o}, want {mode:o}",
                stat.mode.perms
            );
            return Err("a DMI attribute's mode is not dmi-id.c's");
        }
        if file.owners() != (0, 0) {
            return Err("a DMI attribute is not owned by root");
        }
    }
    // `ADD_DMI_ATTR` leaves out a field the table does not have.
    if id.lookup("ec_firmware_release").is_some() {
        return Err("ec_firmware_release is published for an EC release of 0xFF.0xFF");
    }
    let modalias = id.lookup("modalias").ok_or("dmi/id/modalias is missing")?;
    let got = read_all(&modalias);
    if got.strip_suffix(b"\n") != Some(MODALIAS.as_bytes()) {
        let _ = writeln!(
            narf_console::Writer,
            "dmi/id/modalias: {:?}",
            String::from_utf8_lossy(&got)
        );
        return Err("dmi/id/modalias is not get_modalias's string");
    }
    if modalias.stat().mode.perms != 0o444 {
        return Err("dmi/id/modalias is not 0444");
    }
    // `dmi_dev_uevent`: the class device carries MODALIAS only.
    let uevent = id.lookup("uevent").ok_or("dmi/id/uevent is missing")?;
    let mut want = String::from("MODALIAS=");
    want.push_str(MODALIAS);
    want.push('\n');
    if read_all(&uevent) != want.as_bytes() {
        return Err("dmi/id/uevent is not MODALIAS=<modalias>");
    }
    if uevent.stat().mode.perms != 0o644 {
        return Err("dmi/id/uevent is not the writable 0644 uevent");
    }
    if readlink(&id, "subsystem").as_deref() != Some("../../../../class/dmi") {
        return Err("dmi/id/subsystem does not lead to /sys/class/dmi");
    }
    let listed: Vec<String> = id.enumerate(0, 128).into_iter().map(|(n, _)| n).collect();
    for (name, ..) in ID_ATTRS {
        if !listed.iter().any(|n| n == name) {
            return Err("a DMI attribute is missing from the directory listing");
        }
    }
    Ok(())
}

/// `dmi_init`'s binary files: 0400, sized as the entry point and the
/// walked table, and holding them.
fn check_tables(entry_point: &[u8], table: &[u8]) -> Result<(), &'static str> {
    let tables = sys_dir(&["firmware", "dmi", "tables"])
        .map_err(|_| "/sys/firmware/dmi/tables is missing")?;
    for (name, want) in [("smbios_entry_point", entry_point), ("DMI", table)] {
        let file = tables
            .lookup(name)
            .ok_or("a /sys/firmware/dmi/tables file is missing")?;
        let stat = file.stat();
        if stat.mode.perms != 0o400 {
            return Err("a raw DMI table file is not root-only 0400");
        }
        if stat.size != want.len() as u64 {
            return Err("a raw DMI table file's size is not the table's");
        }
        if read_all(&file) != want {
            return Err("a raw DMI table file does not hold the firmware's bytes");
        }
    }
    Ok(())
}

/// A table behind an SMBIOS 3 entry point: every dmi-id attribute, its
/// mode, the modalias and uevent, the class link, and the raw files.
fn smoke_sysfs_dmi_id_publishes_a_smbios3_table() -> TestResult {
    crate::sysfs::__reset_for_test();
    let (table, _) = fixture_table();
    const BASE: u64 = 0x1_2340_0000;
    // The entry point's length is only a maximum: the walk stops at the
    // end-of-table marker, and DMI holds what was walked.
    let mut image = table.clone();
    image.extend_from_slice(&[0xAA; 64]);
    let entry = sm3_entry(BASE, image.len() as u32);
    let mem = Mem(alloc::vec![(BASE, image)]);
    let src = Sources {
        loader_smbios3: Some(entry),
        ..Sources::default()
    };
    let Some(found) = scan_machine(&src, &mem) else {
        return TestResult::Fail("the fixture SMBIOS 3 table was not found");
    };
    crate::sysfs::publish_dmi(&found);
    let result = check_id_device().and_then(|()| check_tables(&entry[..24], &table));
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "filesystem/sysfs/dmi",
    smoke_sysfs_dmi_id_publishes_a_smbios3_table
);

/// Tables behind 32-bit entry points: `smbios_entry_point` is the `_SM_`
/// header (its own length, 31) or, for legacy DMI, the 15-byte `_DMI_`
/// header; and below SMBIOS 2.6 `dmi_save_uuid` prints the UUID bytes in
/// table order (`%pUb`).
fn smoke_sysfs_dmi_tables_keep_a_32bit_entry_point() -> TestResult {
    const BASE: u32 = 0x000E_0000;
    let (table, num) = fixture_table();
    for smbios in [true, false] {
        crate::sysfs::__reset_for_test();
        let ver = if smbios { (2, 4) } else { (2, 0) };
        let entry = sm_entry(BASE, table.len() as u16, num, ver, smbios);
        let mem = Mem(alloc::vec![(BASE as u64, table.clone())]);
        let src = Sources {
            loader_smbios: Some(entry),
            ..Sources::default()
        };
        let Some(found) = scan_machine(&src, &mem) else {
            return TestResult::Fail("the fixture 32-bit SMBIOS table was not found");
        };
        crate::sysfs::publish_dmi(&found);
        let kept: &[u8] = if smbios { &entry[..31] } else { &entry[16..31] };
        if let Err(why) = check_tables(kept, &table) {
            return TestResult::Fail(why);
        }
        let uuid = sys_dir(&["devices", "virtual", "dmi", "id"])
            .ok()
            .and_then(|id| id.lookup("product_uuid"))
            .map(|file| read_all(&file));
        if uuid.as_deref() != Some(b"03020100-0504-0706-0809-0a0b0c0d0e0f\n".as_slice()) {
            return TestResult::Fail("below SMBIOS 2.6 product_uuid is not the bytes in order");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/sysfs/dmi",
    smoke_sysfs_dmi_tables_keep_a_32bit_entry_point
);

/// The boot table: when the firmware has one, its product name is what
/// `dmi/id/product_name` shows.
fn smoke_sysfs_dmi_id_shows_the_boot_table() -> TestResult {
    let Some(boot) = narf_firmware_smbios::boot_table() else {
        return TestResult::Skip("no SMBIOS table at boot");
    };
    let want = boot
        .structures_of_type(1)
        .first()
        .filter(|s| s.length() > 5)
        .map(|s| s.string(s.formatted()[5]).unwrap_or(b"").to_vec());
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_all();
    let shown = sys_dir(&["class", "dmi"])
        .ok()
        .and_then(|_| sys_dir(&["devices", "virtual", "dmi", "id"]).ok())
        .and_then(|id| id.lookup("product_name"))
        .map(|file| read_all(&file));
    match (want, shown) {
        (Some(want), Some(shown)) if shown.strip_suffix(b"\n") == Some(&want[..]) => {
            TestResult::Pass
        }
        (None, _) => TestResult::Skip("the boot table has no system information"),
        _ => TestResult::Fail("dmi/id/product_name is not the boot table's product name"),
    }
}
kernel_test_in!(
    "filesystem/sysfs/dmi",
    smoke_sysfs_dmi_id_shows_the_boot_table
);
