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
