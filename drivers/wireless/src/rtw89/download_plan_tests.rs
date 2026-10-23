use super::*;
use crate::rtw89::prepared::{self, Files};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
struct File(Vec<u8>);
impl Files for File {
    fn load(&mut self, _: &'static str) -> Result<Vec<u8>, FwError> {
        Ok(self.0.clone())
    }
}
fn prepare(bytes: Vec<u8>, chip: ChipId) -> PreparedFirmware {
    prepared::load(&mut File(bytes), chip, 1).unwrap()
}
// Independent literal packed layouts from Linux fw.h, not parser constants.
fn firmware(version: u8, security: usize, formatted: bool) -> Vec<u8> {
    let base = if version == 0 { 32 } else { 48 };
    let mut image = vec![0; base + 16 * (security + 1)];
    put(&mut image, 12, u32::from(version) << 24);
    put(&mut image, 24, ((security + 1) as u32) << 8);
    put(&mut image, 28, 0x8765);
    for index in 0..security {
        let descriptor = base + index * 16;
        put(&mut image, descriptor, 0x0010_0000 + index as u32 * 0x1000);
        put(&mut image, descriptor + 4, 0x0900_03c0);
        put(&mut image, descriptor + 8, if formatted { 255 } else { 2 });
        let content = image.len();
        image.resize(content + 960, 0x99);
        image[content + 32] = index as u8;
        image[content + 33] = 0;
        image[content + 58..content + 62].fill(0);
        if formatted {
            let pool = image.len();
            image.resize(pool + 32 + 256 + 2 * 512, 0);
            image[pool..pool + 8].copy_from_slice(b"MSSKPOOL");
            put(&mut image, pool + 8, 32);
            put(&mut image, pool + 12, 288);
            image[pool + 21] = 4;
            image[pool + 22..pool + 24].copy_from_slice(&2u16.to_le_bytes());
            image[pool + 24..pool + 26].copy_from_slice(&32u16.to_le_bytes());
            image[pool + 26..pool + 28].copy_from_slice(&16u16.to_le_bytes());
            // FuseFC:EF -> device0, customer0, key0. The first candidate's
            // bitmap doesn't match; the second matches at packed rank0.
            image[pool + 32] = if index == 0 { 0x82 } else { 0x81 };
            image[pool + 288..pool + 800].fill(0x41 + index as u8);
            image[pool + 800..].fill(0x51 + index as u8);
        } else {
            image.extend_from_slice(&vec![0x41 + index as u8; 512]);
            image.extend_from_slice(&vec![0x51 + index as u8; 512]);
        }
    }
    let descriptor = base + security * 16;
    put(&mut image, descriptor, 0x0020_0000);
    put(&mut image, descriptor + 4, 0x0100_0fd9); //4057 =>2020+2020+17.
    image.extend((0..4057).map(|n| (n % 251) as u8));
    image
}

fn smoke_rtw89_download_compaction_and_raw_chunks() -> TestResult {
    let original = firmware(1, 2, true);
    let fuses = Fuses::decode(ChipId::Rtl8852C, 0xfc, 0xef).unwrap();
    let plan = match DownloadPlan::new(
        prepare(original.clone(), ChipId::Rtl8852C),
        fuses,
        Blacklist::upstream(ChipId::Rtl8852C),
    ) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("formatted fuse-selected plan"),
    };
    if plan.section_count() != 2
        || plan.header().len() != 80
        || plan.header()[25] != 2
        || plan.header()[64..80] != original[80..96]
        || plan.header()[28..30] != [0xe4, 7]
    {
        return TestResult::Fail("compacted descriptors/count/AX part size");
    }
    let key = plan.chunk(0, 0).unwrap();
    if key.len() != 960 || key[..448] != original[2368..2816] || key[448..] != vec![0x42; 512] {
        return TestResult::Fail("selected signature not coupled to selected payload");
    }
    let command = plan.header_command(0xa7).unwrap();
    if command[..8] != [0x0d, 0, 0, 0xa7, 88, 0, 0, 0] || command[8..] != *plan.header() {
        return TestResult::Fail("literal FWHDR_DL command without runtime ACK");
    }
    let mut raw = Vec::new();
    for offset in [0, 2020, 4040] {
        raw.extend_from_slice(&plan.chunk(1, offset).unwrap());
    }
    if raw != (0..4057).map(|n| (n % 251) as u8).collect::<Vec<_>>()
        || plan.chunk(1, 1).is_ok()
        || plan.chunk(1, 6060).is_ok()
        || plan.chunk(2, 0).is_ok()
    {
        return TestResult::Fail("raw section chunk extent/order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_download_compaction_and_raw_chunks
);

fn smoke_rtw89_download_secure_policy_and_legacy_override() -> TestResult {
    // FF:6E is B's physical special selector and indexed key1.
    let fuses = Fuses::decode(ChipId::Rtl8852B, 255, 0x6e).unwrap();
    let bytes = firmware(0, 1, false);
    let plan = DownloadPlan::new(
        prepare(bytes.clone(), ChipId::Rtl8852B),
        fuses,
        Blacklist::upstream(ChipId::Rtl8852B),
    )
    .unwrap();
    let key = plan.chunk(0, 0).unwrap();
    if key[448..] != vec![0x51; 512] || plan.section_len(0) != Some(960) {
        return TestResult::Fail("B v0 indexed selector/override");
    }
    let mut larger = bytes.clone();
    put(&mut larger, 36, 0x0900_0400); //1024 original,960 override.
    larger.splice(64 + 960..64 + 960, [0xaa; 64]);
    let larger = DownloadPlan::new(
        prepare(larger, ChipId::Rtl8852B),
        fuses,
        Blacklist::upstream(ChipId::Rtl8852B),
    )
    .unwrap();
    if larger.header()[36..40] != [0xc0, 3, 0, 9]
        || larger.chunk(0, 0).unwrap()[448..] != vec![0x51; 512]
    {
        return TestResult::Fail("header/payload length override diverged");
    }
    let mut deny = [0; 32];
    deny[0] = 1;
    for (policy, expected) in [
        (None, secure::Error::UnknownBlacklist),
        (
            Some(Blacklist::authenticated(0, deny)),
            secure::Error::Blacklisted,
        ),
    ] {
        if !matches!(DownloadPlan::new(prepare(bytes.clone(), ChipId::Rtl8852B), fuses, policy), Err(Error::Secure(e)) if e == expected)
        {
            return TestResult::Fail("missing/deny blacklist accepted");
        }
    }
    let mut newer = bytes.clone();
    newer[64 + 33] = 1;
    if !matches!(
        DownloadPlan::new(
            prepare(newer, ChipId::Rtl8852B),
            fuses,
            Blacklist::upstream(ChipId::Rtl8852B)
        ),
        Err(Error::Secure(secure::Error::NewerBlacklist))
    ) {
        return TestResult::Fail("newer blacklist version accepted");
    }
    if !matches!(
        DownloadPlan::new(prepare(bytes, ChipId::Rtl8852C), fuses, None),
        Err(Error::ChipMismatch)
    ) {
        return TestResult::Fail("foreign physical chip policy accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_download_secure_policy_and_legacy_override
);

fn smoke_rtw89_download_no_insecure_fallback() -> TestResult {
    let secure = Fuses::decode(ChipId::Rtl8852C, 0xfc, 0xef).unwrap();
    if !matches!(
        DownloadPlan::new(
            prepare(firmware(1, 0, false), ChipId::Rtl8852C),
            secure,
            Blacklist::upstream(ChipId::Rtl8852C)
        ),
        Err(Error::Secure(secure::Error::MissingSignature))
    ) {
        return TestResult::Fail("secure hardware without signature accepted");
    }
    let mut no_match = firmware(1, 1, true);
    no_match[80 + 58] = 1;
    if !matches!(
        DownloadPlan::new(
            prepare(no_match, ChipId::Rtl8852C),
            secure,
            Blacklist::upstream(ChipId::Rtl8852C)
        ),
        Err(Error::Secure(secure::Error::MissingSignature))
    ) {
        return TestResult::Fail("incompatible suite fell back to insecure payload");
    }
    let off = Fuses::decode(ChipId::Rtl8852C, 255, 255).unwrap();
    let plan =
        DownloadPlan::new(prepare(firmware(1, 2, true), ChipId::Rtl8852C), off, None).unwrap();
    if plan.section_count() != 2 || plan.chunk(0, 0).unwrap()[448..] != vec![0x99; 512] {
        return TestResult::Fail(
            "disabled secure boot changed signature or retained later formatted section",
        );
    }
    let legacy = Fuses::decode(ChipId::Rtl8852B, 255, 0x6e).unwrap();
    let mut checksum = firmware(0, 1, false);
    put(&mut checksum, 36, 0x1900_03c0);
    checksum.splice(64 + 960..64 + 960, [0; 8]);
    if !matches!(
        DownloadPlan::new(
            prepare(checksum, ChipId::Rtl8852B),
            legacy,
            Blacklist::upstream(ChipId::Rtl8852B)
        ),
        Err(Error::SectionGeometry)
    ) {
        return TestResult::Fail("ambiguous checksum override accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_download_no_insecure_fallback
);
