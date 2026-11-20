//! `firmware-N.bin` tests: the container parse against files written out
//! byte by byte from Linux `fw.h` / `hw.h` (`ATH11K_FIRMWARE_MAGIC` + NUL,
//! padding to 4, `struct ath11k_fw_ie { __le32 id; __le32 len; u8
//! data[]; }` padded to 4), every `-EINVAL` branch of
//! `ath11k_fw_request_firmware_api_n`, and `ath11k_fw_pre_init`'s choice
//! between API 2 and API 1.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::fw::*;

type R = Result<(), &'static str>;

fn run_test(f: impl FnOnce() -> R) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

macro_rules! ensure {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return Err($msg);
        }
    };
}

/// `"QCOM-ATH11K-FW"`, its NUL, one byte of padding (15 → 16).
const MAGIC: [u8; 16] = [
    b'Q', b'C', b'O', b'M', b'-', b'A', b'T', b'H', b'1', b'1', b'K', b'-', b'F', b'W', 0x00, 0x00,
];

/// A firmware-2.bin as linux-firmware ships it (timestamp, features,
/// AMSS, M3), plus an unknown IE between them. Every byte written out.
fn container() -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    // TIMESTAMP: id 0, len 4, 0x6543_2101.
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x01, 0x21, 0x43, 0x65]);
    // FEATURES: id 1, len 1, 0xff, 3 bytes padding.
    v.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0xff, 0x00, 0x00, 0x00]);
    // AMSS_IMAGE: id 2, len 6, "\x7fELF\x01\x02", 2 bytes padding.
    v.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x00, 0x00]);
    // Unknown id 9, len 2, 2 bytes padding.
    v.extend_from_slice(&[0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0xaa, 0xbb, 0x00, 0x00]);
    // M3_IMAGE: id 3, len 5, "M3IMG", 3 bytes padding.
    v.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[b'M', b'3', b'I', b'M', b'G', 0x00, 0x00, 0x00]);
    v
}

fn smoke_ath11k_fw_api_n_container_parse() -> TestResult {
    run_test(|| {
        let f = container();
        ensure!(f.len() == 16 + 12 + 12 + 16 + 12 + 16, "fixture length");
        let ies = parse_api_n(&f).map_err(|_| "container parses")?;
        ensure!(ies.timestamp == Some(0x6543_2101), "fw timestamp");
        ensure!(ies.features_len == Some(1), "features IE seen");
        // enum ath11k_fw_features is empty: no bit can be set.
        ensure!(ies.features == 0, "ATH11K_FW_FEATURE_COUNT = 0");
        ensure!(ies.amss == Some(48..54), "AMSS IE range");
        ensure!(ies.m3 == Some(76..81), "M3 IE range");
        ensure!(ies.unknown == [9], "unknown IE reported, skipped");
        ensure!(&f[48..54] == b"\x7fELF\x01\x02", "AMSS bytes");
        ensure!(&f[76..81] == b"M3IMG", "M3 bytes");

        // The FEATURES loop itself (count > 0 once Linux adds a feature):
        // bit i = byte i/8 bit i%8, stopping at the end of the IE.
        ensure!(feature_bits(&[0b0000_0101], 3) == 0b101, "bits 0 and 2");
        ensure!(feature_bits(&[0xff], 12) == 0xff, "stops at ie_len");
        ensure!(feature_bits(&[0x00, 0x02], 10) == 1 << 9, "second byte");
        ensure!(feature_bits(&[], 4) == 0, "empty IE");

        // A 2-byte timestamp is ignored (`ie_len != sizeof(u32)`).
        let mut t = MAGIC.to_vec();
        t.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0, 0x11, 0x22, 0, 0]);
        let ies = parse_api_n(&t).map_err(|_| "short timestamp parses")?;
        ensure!(ies.timestamp.is_none(), "short timestamp ignored");

        // A later IE of the same id wins (Linux overwrites amss_data).
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&[2, 0, 0, 0, 1, 0, 0, 0, 0xa1, 0, 0, 0]);
        d.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0, 0xb1, 0xb2, 0, 0]);
        let ies = parse_api_n(&d).map_err(|_| "duplicate parses")?;
        ensure!(ies.amss == Some(36..38), "last AMSS IE kept");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_fw_api_n_container_parse
);

fn smoke_ath11k_fw_api_n_container_edges() -> TestResult {
    run_test(|| {
        // Shorter than the magic and its NUL.
        ensure!(
            parse_api_n(b"QCOM-ATH11K-F") == Err(FwError::TooSmall(13)),
            "too small to contain magic"
        );
        ensure!(parse_api_n(&[]) == Err(FwError::TooSmall(0)), "empty file");
        // Magic without its NUL.
        let mut m = MAGIC.to_vec();
        m[14] = b'!';
        ensure!(parse_api_n(&m) == Err(FwError::BadMagic), "NUL checked");
        let mut m = MAGIC.to_vec();
        m[0] = b'q';
        ensure!(parse_api_n(&m) == Err(FwError::BadMagic), "magic checked");
        ensure!(FwError::BadMagic.errno() == 22, "every refusal is -EINVAL");
        // Magic + NUL with no room for the padding byte (15 < 16).
        ensure!(
            parse_api_n(&MAGIC[..15]) == Err(FwError::NoPadding),
            "no space for padding after magic"
        );
        // Magic + padding and nothing else: no IE, accepted.
        let ies = parse_api_n(&MAGIC).map_err(|_| "bare magic")?;
        ensure!(ies == FwIes::default(), "no IEs");
        // An IE claiming more than the file holds.
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&[2, 0, 0, 0, 9, 0, 0, 0, 1, 2, 3, 4]);
        ensure!(
            parse_api_n(&b) == Err(FwError::IeLength(2, 4, 9)),
            "IE length past the end"
        );
        // `while (len > sizeof(struct ath11k_fw_ie))`: a header with no
        // byte after it is not parsed.
        let mut h = MAGIC.to_vec();
        h.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
        let ies = parse_api_n(&h).map_err(|_| "trailing bare header")?;
        ensure!(ies.m3.is_none(), "8-byte tail ignored");
        // A last IE whose padding is missing ends the walk after it.
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[3, 0, 0, 0, 3, 0, 0, 0, b'a', b'b', b'c']);
        let ies = parse_api_n(&p).map_err(|_| "unpadded last IE")?;
        ensure!(ies.m3 == Some(24..27), "unpadded last IE recorded");
        // A zero-length AMSS IE parses but is not used.
        let mut z = MAGIC.to_vec();
        z.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0xee]);
        let ies = parse_api_n(&z).map_err(|_| "empty AMSS IE")?;
        ensure!(ies.amss == Some(24..24), "empty AMSS IE range");
        let api = FwApi {
            api_version: 2,
            file: z,
            ies,
        };
        ensure!(api.amss().is_none(), "amss_len > 0 required");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_fw_api_n_container_edges
);

fn smoke_ath11k_fw_pre_init_selects_api() -> TestResult {
    run_test(|| {
        // firmware-2.bin present: api 2, AMSS + M3 from the container.
        let mut asked: Vec<String> = Vec::new();
        let (api, refused) = FwApi::pre_init(|name| {
            asked.push(String::from(name));
            Ok(container())
        });
        ensure!(asked == ["firmware-2.bin"], "requests firmware-2.bin");
        ensure!(refused.is_none() && api.api_version == 2, "fw api 2");
        ensure!(api.amss() == Some(&b"\x7fELF\x01\x02"[..]), "AMSS from IE");
        ensure!(api.m3() == Some(&b"M3IMG"[..]), "M3 from IE");

        // Absent: api 1, nothing from a container.
        let (api, refused) = FwApi::pre_init(|_| Err(2));
        ensure!(
            refused.is_none() && api.api_version == 1,
            "missing file is api 1"
        );
        ensure!(api.amss().is_none() && api.m3().is_none(), "no IEs");

        // Present but refused: api 1, the reason reported.
        let mut bad = container();
        bad[3] = b'X';
        let (api, refused) = FwApi::pre_init(|_| Ok(bad.clone()));
        ensure!(
            api.api_version == 1 && refused == Some(FwError::BadMagic),
            "corrupt container falls back to api 1"
        );
        ensure!(api.file.is_empty(), "release_firmware on error");

        // A container with only an M3 IE: api 2, `amss.bin` for MHI.
        let mut m3only = MAGIC.to_vec();
        m3only.extend_from_slice(&[3, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]);
        let (api, _) = FwApi::pre_init(|_| Ok(m3only.clone()));
        ensure!(
            api.api_version == 2 && api.amss().is_none(),
            "no AMSS IE: amss.bin"
        );
        ensure!(api.m3() == Some(&[1u8, 2, 3, 4][..]), "M3 IE used");
        ensure!(FwApi::api1() == FwApi::pre_init(|_| Err(2)).0, "api1()");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_fw_pre_init_selects_api
);
