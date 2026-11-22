use super::*;
use alloc::vec;
use narf_aml::Value;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A `_DSM` that answers function 0 with a fixed mask per UUID (or fails)
/// and records every other call.
struct Fake {
    masks: Vec<([u8; 16], Option<Vec<u8>>)>,
    calls: Vec<(&'static str, u64, u32)>,
}
impl Fake {
    fn new(masks: &[([u8; 16], Option<&[u8]>)]) -> Self {
        Self {
            masks: masks
                .iter()
                .map(|(u, m)| (*u, m.map(<[u8]>::to_vec)))
                .collect(),
            calls: Vec::new(),
        }
    }
}
fn name(uuid: [u8; 16]) -> &'static str {
    match uuid {
        UUID_AMD => "amd",
        UUID_MICROSOFT => "ms",
        UUID_INTEL => "intel",
        _ => "?",
    }
}
impl Dsm for Fake {
    fn call(&mut self, uuid: [u8; 16], revision: u64, function: u32) -> Option<Value> {
        if function == 0 {
            let (_, mask) = self.masks.iter().find(|(u, _)| *u == uuid)?;
            return mask.clone().map(Value::Buffer);
        }
        self.calls.push((name(uuid), revision, function));
        Some(Value::Buffer(vec![0]))
    }
}

/// `guid_parse` byte order for the three LPS0 UUIDs.
fn lps0_uuids_follow_guid_parse() -> TestResult {
    if UUID_AMD
        != [
            0x52, 0x24, 0xf3, 0xe3, 0xbc, 0xfe, 0xce, 0x43, 0x90, 0x39, 0x93, 0x21, 0x22, 0xd3,
            0x77, 0x21,
        ]
        || UUID_MICROSOFT[..4] != [0x56, 0x0d, 0xe0, 0x11]
        || UUID_INTEL[4..8] != [0xd2, 0x6c, 0xe2, 0x11]
    {
        return TestResult::Fail("LPS0 UUID byte order");
    }
    TestResult::Pass
}
kernel_test_in!("power/lps0", lps0_uuids_follow_guid_parse);

/// An AMD laptop with both UUIDs (the common Rembrandt-to-Phoenix shape):
/// prepare runs screen off (AMD, then Microsoft), AMD entry, then the
/// Microsoft Modern Standby entry pair; restore runs AMD exit, the Microsoft
/// exit sequence, then screen on (Microsoft, then AMD). All at revision 0.
fn lps0_amd_sequence_follows_acpi_s2idle() -> TestResult {
    let all: &[u8] = &[0xff, 0x03];
    let mut dsm = Fake::new(&[(UUID_AMD, Some(&[0x3f])), (UUID_MICROSOFT, Some(all))]);
    let Some(lps0) = Lps0::attach(&mut dsm, true, Some("AMDI0007")) else {
        return TestResult::Fail("attach");
    };
    if (lps0.vendor, lps0.microsoft) != (Some(0x3f), Some(0x3ff)) {
        return TestResult::Fail("masks");
    }
    lps0.prepare_late(&mut dsm);
    let prepare = [
        ("amd", 0, 4),
        ("ms", 0, 3),
        ("amd", 0, 2),
        ("ms", 0, 7),
        ("ms", 0, 5),
    ];
    if dsm.calls != prepare {
        return TestResult::Fail("prepare_late order");
    }
    dsm.calls.clear();
    lps0.restore_early(&mut dsm);
    let restore = [
        ("amd", 0, 3),
        ("ms", 0, 6),
        ("ms", 0, 9),
        ("ms", 0, 8),
        ("ms", 0, 4),
        ("amd", 0, 5),
    ];
    if dsm.calls != restore {
        return TestResult::Fail("restore_early order");
    }
    TestResult::Pass
}
kernel_test_in!("power/lps0", lps0_amd_sequence_follows_acpi_s2idle);

/// The masks gate each call. The Picasso HIDs shift an AMD mask above 0x3
/// left by one and set bit 0, and a failed or malformed function 0 leaves
/// that UUID unused. With both failed, nothing attaches. Intel uses its
/// own UUID at revision 1, its entry after the Microsoft pair.
fn lps0_masks_quirks_and_intel() -> TestResult {
    let mut dsm = Fake::new(&[(UUID_AMD, Some(&[0x1f])), (UUID_MICROSOFT, None)]);
    let picasso = Lps0::attach(&mut dsm, true, Some("AMDI0005")).map(|l| l.vendor);
    let mut dsm = Fake::new(&[(UUID_AMD, Some(&[0x03])), (UUID_MICROSOFT, None)]);
    let small = Lps0::attach(&mut dsm, true, Some("AMD0004")).map(|l| l.vendor);
    if picasso != Some(Some(0x3f)) || small != Some(Some(0x03)) {
        return TestResult::Fail("Picasso off-by-one");
    }
    // Only screen off and LPS0 entry listed (bits 2 and 4 of AMD's).
    let mut dsm = Fake::new(&[(UUID_AMD, Some(&[0x14])), (UUID_MICROSOFT, Some(&[]))]);
    let lps0 = Lps0::attach(&mut dsm, true, None).unwrap();
    lps0.prepare_late(&mut dsm);
    lps0.restore_early(&mut dsm);
    if lps0.microsoft.is_some() || dsm.calls != [("amd", 0, 4), ("amd", 0, 2)] {
        return TestResult::Fail("a call outside its mask, or an empty mask buffer accepted");
    }
    let mut dsm = Fake::new(&[(UUID_AMD, None), (UUID_MICROSOFT, Some(&[1, 2, 3, 4, 5]))]);
    if Lps0::attach(&mut dsm, true, None).is_some() {
        return TestResult::Fail("attached with no valid mask");
    }
    let mut dsm = Fake::new(&[(UUID_INTEL, Some(&[0x7e])), (UUID_MICROSOFT, Some(&[0x80]))]);
    let intel = Lps0::attach(&mut dsm, false, None).unwrap();
    intel.prepare_late(&mut dsm);
    if dsm.calls != [("intel", 1, 3), ("ms", 1, 7), ("intel", 1, 5)] {
        return TestResult::Fail("Intel prepare_late");
    }
    TestResult::Pass
}
kernel_test_in!("power/lps0", lps0_masks_quirks_and_intel);
