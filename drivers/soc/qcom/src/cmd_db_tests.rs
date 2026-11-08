//! cmd-db smokes. The table below is built from the layout text in
//! `cmd_db.rs` (itself transcribed from Linux `cmd-db.c`), not from
//! the code under test: one slave header with three entries.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, kt_assert_eq, TestResult};

use crate::cmd_db::{CmdDb, CmdDbError};

const SUB: &str = "drivers/soc/qcom";

/// A 112-byte header + 3 entries: `cx.lvl`, `mx.lvl`, `xo.lvl`.
fn table() -> Vec<u8> {
    // Slave header 0 at offset 8: slv_id 1, header_offset 0,
    // data_offset 0, cnt 3, version 1.
    let mut b = alloc::vec![0u8; 112 + 3 * 24];
    b[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
    b[4..8].copy_from_slice(&[0xdb, 0x30, 0x03, 0x0c]); // magic
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[10..12].copy_from_slice(&0u16.to_le_bytes());
    b[12..14].copy_from_slice(&0u16.to_le_bytes());
    b[14..16].copy_from_slice(&3u16.to_le_bytes());
    b[16..18].copy_from_slice(&1u16.to_le_bytes());
    // Slave headers 1..7 stay zero: slv_id 0 stops the scan.
    let mut put = |i: usize, id: &[u8; 8], addr: u32| {
        let e = 112 + i * 24;
        b[e..e + 8].copy_from_slice(id);
        // priority[2] stays 0.
        b[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
    };
    put(0, b"cx.lvl\0\0", 0x0011_0000);
    put(1, b"mx.lvl\0\0", 0x0022_0000);
    put(2, b"xo.lvl\0\0", 0x0033_0000);
    b
}

fn smoke_qcom_cmddb_read_addr() -> TestResult {
    let t = table();
    let db = CmdDb::parse(&t).unwrap();
    kt_assert_eq!(db.read_addr("cx.lvl"), Some(0x0011_0000));
    kt_assert_eq!(db.read_addr("mx.lvl"), Some(0x0022_0000));
    kt_assert_eq!(db.read_addr("xo.lvl"), Some(0x0033_0000));
    // Absent ids read None, never a fabricated address.
    kt_assert_eq!(db.read_addr("ebi.lvl"), None);
    // Padding does not fuzzy-match: "cx" is not "cx.lvl".
    kt_assert_eq!(db.read_addr("cx"), None);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_cmddb_read_addr);

fn smoke_qcom_cmddb_bad_magic_and_truncated() -> TestResult {
    let mut t = table();
    t[4] = 0x00;
    kt_assert_eq!(CmdDb::parse(&t).unwrap_err(), CmdDbError::BadMagic);
    kt_assert_eq!(CmdDb::parse(&t[..100]).unwrap_err(), CmdDbError::Truncated);
    // A header claiming more entries than the blob holds reads None
    // instead of running past the end.
    let mut t = table();
    t[14..16].copy_from_slice(&99u16.to_le_bytes());
    let db = CmdDb::parse(&t).unwrap();
    kt_assert_eq!(db.read_addr("cx.lvl"), Some(0x0011_0000));
    kt_assert_eq!(db.read_addr("mx.lvl"), Some(0x0022_0000));
    kt_assert_eq!(db.read_addr("xo.lvl"), Some(0x0033_0000));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_cmddb_bad_magic_and_truncated);
