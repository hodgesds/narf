//! Per-crate smoke tests for `narf-firmware-fw-cfg`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `firmware/fw_cfg`. x86_64-only — the
//! aarch64 MMIO port is a TODO.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    decode_file_entry, find, is_present, read_directory, read_string, FwCfgFile, FILE_ENTRY_SIZE,
    FILE_NAME_LEN, MAGIC,
};

// 1. Live presence — QEMU always exposes fw_cfg under `cargo xtask
//    test`. Skip cleanly on bare-metal / non-QEMU runs.
fn smoke_fw_cfg_signature_detected() -> TestResult {
    if !is_present() {
        return TestResult::Skip("fw_cfg absent");
    }
    // Re-probe to double-check the magic string sequence is stable
    // across calls (each probe re-selects FW_CFG_SIGNATURE).
    if !is_present() {
        return TestResult::Fail("magic not stable");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fw_cfg", smoke_fw_cfg_signature_detected);

// 2. Live directory parse — read FW_CFG_FILE_DIR and assert at least
//    one canonical entry name decodes to printable ASCII.
fn smoke_fw_cfg_file_directory_parses() -> TestResult {
    if !is_present() {
        return TestResult::Skip("fw_cfg absent");
    }
    let dir = match read_directory() {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("read_directory errored"),
    };
    if dir.is_empty() {
        return TestResult::Skip("directory empty (older QEMU)");
    }
    for f in &dir {
        // Every entry's name must be printable ASCII (spec §4 — the
        // 56-byte field is a NUL-terminated path). Catches a botched
        // big-endian decode pointing at random bytes.
        for &b in f.name().as_bytes() {
            if !(0x20..=0x7e).contains(&b) {
                return TestResult::Fail("non-ASCII byte in entry name");
            }
        }
        // Selectors for files start at 0x0020 per spec §4.
        if f.select < 0x0020 {
            return TestResult::Fail("file selector below 0x0020");
        }
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fw_cfg", smoke_fw_cfg_file_directory_parses);

// 3. Live read — find a well-known QEMU entry. `etc/boot-fail-wait`
//    is set on every q35/pc default, so its absence is itself a
//    diagnosis (skip rather than fail). Reading it via `read_string`
//    exercises select → stream-read → strip-NUL.
fn smoke_fw_cfg_read_string_well_known() -> TestResult {
    if !is_present() {
        return TestResult::Skip("fw_cfg absent");
    }
    // Try a sequence of entries QEMU exposes by default; first hit
    // wins. We only need one to demonstrate the path works.
    for name in &["bootorder", "etc/boot-fail-wait", "etc/system-states"] {
        if let Some(f) = find(name) {
            let mut buf = alloc::vec![0u8; f.size as usize];
            let n = crate::read(&f, &mut buf);
            if n != f.size as usize {
                return TestResult::Fail("short read");
            }
            // For `bootorder` the value is ASCII-ish; for binary
            // entries `read_string` may return None — that's fine,
            // we only need to confirm `read` itself worked.
            let _ = read_string(name);
            return TestResult::Pass;
        }
    }
    TestResult::Skip("no well-known entry found")
}
kernel_test_in!("firmware/fw_cfg", smoke_fw_cfg_read_string_well_known);

// 4. Pure-data — synthesise a 64-byte directory entry and confirm
//    every field decodes per spec §4 (size+select are big-endian).
fn smoke_fw_cfg_decode_synthetic_entry() -> TestResult {
    let mut raw = [0u8; FILE_ENTRY_SIZE];
    // size = 0x0000_1234 BE
    raw[0..4].copy_from_slice(&0x0000_1234u32.to_be_bytes());
    // select = 0x0042 BE
    raw[4..6].copy_from_slice(&0x0042u16.to_be_bytes());
    // reserved = 0xCAFE — must be ignored
    raw[6..8].copy_from_slice(&0xCAFEu16.to_be_bytes());
    // name = "etc/foo" + NUL-terminated
    let name = b"etc/foo";
    raw[8..8 + name.len()].copy_from_slice(name);

    let f: FwCfgFile = decode_file_entry(&raw);
    if f.size != 0x0000_1234 {
        return TestResult::Fail("size decode");
    }
    if f.select != 0x0042 {
        return TestResult::Fail("select decode");
    }
    if f.name() != "etc/foo" {
        return TestResult::Fail("name decode");
    }
    if f.name_len as usize != name.len() {
        return TestResult::Fail("name_len decode");
    }
    if f.name_buf.len() != FILE_NAME_LEN {
        return TestResult::Fail("name buffer width");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fw_cfg", smoke_fw_cfg_decode_synthetic_entry);

// 5. Pure-data — magic constant matches the spec text "QEMU".
fn smoke_fw_cfg_magic_constant() -> TestResult {
    if MAGIC != *b"QEMU" {
        return TestResult::Fail("MAGIC mismatch");
    }
    // u32 LE of "QEMU" = 0x554D4551 per the spec note (and what
    // the data port emits when FW_CFG_SIGNATURE is selected).
    let as_u32 = u32::from_le_bytes(MAGIC);
    if as_u32 != 0x554D_4551 {
        return TestResult::Fail("LE form mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fw_cfg", smoke_fw_cfg_magic_constant);
