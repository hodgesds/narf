use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// Frozen FNV1a digests over the captured physical-fuse recognition tuples,
// with unrecognized/erased selections normalized to zero. The Rust decoder
// is checked against stored data; see REFERENCE_FIXTURES.md.
include!("secure/golden.rs");

fn smoke_rtw89_all_physical_secure_selections() -> TestResult {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut unknown = 0;
    for chip in [ChipId::Rtl8852C, ChipId::Rtl8852B] {
        for raw in 0..=u16::MAX {
            let found = Fuses::decode(chip, (raw >> 8) as u8, raw as u8);
            let record = match found {
                Ok(f) if f.enabled => {
                    let m = f.modern.unwrap_or(Modern {
                        device: 0,
                        customer: 0,
                        key: 0,
                    });
                    [
                        1,
                        u8::from(f.legacy.is_some()),
                        f.legacy.unwrap_or(0),
                        u8::from(f.modern.is_some()),
                        m.device,
                        m.customer,
                        m.key,
                    ]
                }
                Ok(f) if raw == 0xffff && !f.enabled => [0; 7],
                Err(Error::UnknownFuses) if raw != 0xffff => {
                    unknown += 1;
                    [0; 7]
                }
                _ => return TestResult::Fail("fuse selection error/disabled fallback"),
            };
            for byte in record {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    if hash != LINUX_FUSE_HASH || unknown != LINUX_UNKNOWN_FUSES {
        return TestResult::Fail("frozen exhaustive physical-fuse reference");
    }
    if Fuses::decode(ChipId::Rtl8922A, 255, 255) != Err(Error::UnsupportedChip) {
        return TestResult::Fail("BE interpreted as AX secure fuses");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_all_physical_secure_selections
);

fn smoke_rtw89_8851b_secure_policy_is_linux_null_list() -> TestResult {
    // The exact Linux RTL8851B policy: `rtw8851b_chip_info.fw_blacklist`
    // is NULL, so no host chip list is enforced at all.
    let policy = match Blacklist::upstream(ChipId::Rtl8851B) {
        Some(policy) if !policy.has_chip_list() => policy,
        _ => return TestResult::Fail("8851B upstream policy is not the NULL list"),
    };
    // Contrast: 8852B/8852C carry the version-0/all-clear default list.
    if Blacklist::upstream(ChipId::Rtl8852B).map(|p| p.has_chip_list()) != Some(true) {
        return TestResult::Fail("8852B upstream policy lost its chip list");
    }
    // Legacy fuse selection (255, 0x7F): secure boot enabled.
    let fuses = Fuses::decode(ChipId::Rtl8851B, 255, 0x7F).unwrap();
    if !fuses.enabled {
        return TestResult::Fail("8851B legacy fuses decode as disabled");
    }
    // Content present but hostile — bit byte and version both 0xFF —
    // still passes: with no chip list, only the bounds are enforced
    // (fw.c `__check_secure_blacklist` returns -ENOENT, the section
    // parse only WARN_ONCEs, and the MSS signature is the policy).
    let mut content = [0u8; 64];
    content[32] = 0xFF;
    content[33] = 0xFF;
    if fuses.check_blacklist(Some(policy), &content).is_err() {
        return TestResult::Fail("8851B NULL list rejected present content");
    }
    // Content too short: the bounds are still enforced.
    if fuses.check_blacklist(Some(policy), &[0; 10]).is_ok() {
        return TestResult::Fail("8851B NULL list accepted truncated content");
    }
    // Secure boot off: no policy is needed.
    let off = Fuses::decode(ChipId::Rtl8851B, 255, 255).unwrap();
    if off.check_blacklist(None, &content).is_err() {
        return TestResult::Fail("8851B disabled fuses demanded a policy");
    }
    // Secure boot on without a policy: refused, never silently allowed.
    if fuses.check_blacklist(None, &content).is_ok() {
        return TestResult::Fail("8851B enabled fuses accepted a missing policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_secure_policy_is_linux_null_list
);

fn smoke_rtw89_signature_rank_dimensions_and_dsp_stride() -> TestResult {
    let mut image = vec![0; 32 + 32 + 3 * 520];
    image[21] = 1;
    image[24..26].copy_from_slice(&16u16.to_le_bytes());
    image[26..28].copy_from_slice(&16u16.to_le_bytes());
    // Selection(device0/customer2/key9) is bit41. Two lower populated bits
    // put it at packed signature rank2, regardless of sparse logical index.
    image[32] = 0x80;
    image[36] = 8;
    image[37] = 2;
    image[64 + 2 * 520..].fill(0xa7);
    let pool = SignaturePool {
        offset: 0,
        len: image.len(),
        signatures_offset: 64,
        signature_len: 520,
        signature_count: 3,
        bitmap: true,
    };
    let fuses = Fuses::decode(ChipId::Rtl8852C, 0xdc, 0x46).unwrap();
    let content = [0; 64];
    if fuses.signature(&image, pool, &content) != Ok(Some(1104..1624)) {
        return TestResult::Fail("formatted bitmap rank / DSP signature stride");
    }
    image[26..28].copy_from_slice(&8u16.to_le_bytes());
    if fuses.signature(&image, pool, &content) != Ok(None) {
        return TestResult::Fail("out-of-dimension key aliased another customer");
    }
    image[26..28].copy_from_slice(&16u16.to_le_bytes());
    let fewer = SignaturePool {
        signature_count: 2,
        ..pool
    };
    if fuses.signature(&image, fewer, &content) != Err(Error::MissingSignature) {
        return TestResult::Fail("bitmap rank exceeds actual signature storage");
    }
    let legacy = Fuses::decode(ChipId::Rtl8852B, 255, 0x6e).unwrap();
    let indexed = SignaturePool {
        offset: 0,
        len: 1040,
        signatures_offset: 0,
        signature_len: 520,
        signature_count: 2,
        bitmap: false,
    };
    if legacy.signature(&image, indexed, &content) != Ok(Some(512..1024)) {
        return TestResult::Fail("Linux indexed DSP layout changed to formatted stride");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_signature_rank_dimensions_and_dsp_stride
);

fn smoke_rtw89_8852a_board_blacklist() -> TestResult {
    // Upstream has no 8852A blacklist, and NARF must not fall back to
    // the 8851B signature-only path for A.
    if Blacklist::upstream(ChipId::Rtl8852A).is_some() {
        return TestResult::Fail("8852A must have no upstream blacklist");
    }
    let enabled = Fuses::decode(ChipId::Rtl8852A, 255, 0x7f);
    if !enabled.map(|f| f.enabled()).unwrap_or(false) {
        return TestResult::Fail("8852A legacy fuses must decode enabled");
    }
    let enabled = Fuses::decode(ChipId::Rtl8852A, 255, 0x7f).unwrap();
    // Board policy v1 blacklists firmware bit 5 only.
    let mut bits = [0u8; 32];
    bits[0] = 1 << 5;
    let policy = Blacklist::board_8852a(1, bits);
    if !policy.has_chip_list() {
        return TestResult::Fail("8852A board policy must carry a chip list");
    }
    let mut listed = [0u8; 40];
    listed[32] = 5;
    listed[33] = 1;
    if enabled.check_blacklist(Some(policy), &listed) != Err(Error::Blacklisted) {
        return TestResult::Fail("8852A board blacklist did not reject bit 5");
    }
    let mut newer = [0u8; 40];
    newer[32] = 5;
    newer[33] = 2;
    if enabled.check_blacklist(Some(policy), &newer) != Err(Error::NewerBlacklist) {
        return TestResult::Fail("8852A board blacklist did not reject newer version");
    }
    let mut clear = [0u8; 40];
    clear[32] = 3;
    clear[33] = 1;
    if enabled.check_blacklist(Some(policy), &clear) != Ok(()) {
        return TestResult::Fail("8852A board blacklist rejected a clear firmware");
    }
    if enabled.check_blacklist(Some(policy), &listed[..33]) != Err(Error::Bounds) {
        return TestResult::Fail("8852A board blacklist accepted short content");
    }
    // Enabled fuses with no policy fail; disabled fuses pass regardless.
    if enabled.check_blacklist(None, &clear) != Err(Error::UnknownBlacklist) {
        return TestResult::Fail("8852A missing board policy passed silently");
    }
    let disabled = Fuses::decode(ChipId::Rtl8852A, 255, 255).unwrap();
    if disabled.check_blacklist(None, &clear) != Ok(()) {
        return TestResult::Fail("8852A disabled fuses must pass without a policy");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8852a_board_blacklist);
