use super::*;
use crate::amdgpu_gfx_firmware::tests::put;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) fn container(source: Source) -> Vec<u8> {
    if source == Source::Rlc {
        let mut b =
            crate::amdgpu_gfx_firmware::tests::container(crate::amdgpu_gfx_firmware::Source::Rlc);
        put(&mut b, 4, 172);
        put(&mut b, 8, 0x20002);
        put(&mut b, 12, 12);
        return b;
    }
    let mut b = vec![0; 288];
    let (header, version, ip) = match source {
        Source::Smc => (44, 2, 14),
        Source::Sdma => (44, 3, 7),
        Source::Pfp | Source::Me | Source::Mec => (60, 2, 12),
        Source::Mes | Source::Mes1 => (72, 1, 12),
        Source::Imu => (48, 1, 12),
        Source::Vcn => (32, 1, 5),
        Source::Dmcub => (40, 1, 4),
        _ => unreachable!(),
    };
    for (at, v) in [
        (0, 288),
        (4, header),
        (8, version),
        (12, ip),
        (16, 74),
        (20, 32),
        (24, 256),
    ] {
        put(&mut b, at, v);
    }
    b[256..272].fill(0x11);
    b[272..].fill(0x22);
    match source {
        Source::Pfp | Source::Me | Source::Mec => {
            for (at, v) in [
                (36, 16),
                (40, 256),
                (44, 16),
                (48, 272),
                (52, 0x3000),
                (56, 0x70000),
            ] {
                put(&mut b, at, v);
            }
        }
        Source::Mes | Source::Mes1 => {
            for (at, v) in [
                (36, 16),
                (40, 256),
                (48, 16),
                (52, 272),
                (56, 0xf0005000),
                (60, u32::MAX),
                (64, 0xf0100000),
                (68, u32::MAX),
            ] {
                put(&mut b, at, v);
            }
        }
        Source::Sdma => {
            put(&mut b, 36, 256);
            put(&mut b, 40, 32);
        }
        Source::Imu => {
            put(&mut b, 32, 16);
            put(&mut b, 40, 16);
            put(&mut b, 44, 16);
        }
        Source::Dmcub => {
            put(&mut b, 32, 16);
            put(&mut b, 36, 16);
        }
        _ => {}
    }
    b
}
fn navi48_ucode_splits_stacks_imu_and_signed_media() -> TestResult {
    for source in Source::ALL {
        let b = container(source);
        let image = Image::parse(source, &b).unwrap();
        let expected: &[u32] = match source {
            Source::Smc => &[18],
            Source::Sdma => &[71],
            Source::Pfp => &[87, 90, 91],
            Source::Me => &[88, 92, 93],
            Source::Mec => &[89, 94, 95, 96, 97],
            Source::Mes => &[33, 34],
            Source::Mes1 => &[81, 82],
            Source::Imu => &[68, 69],
            Source::Rlc => &[22, 20, 21, 26, 48, 8],
            Source::Vcn => &[13],
            Source::Dmcub => &[51],
        };
        if image.source() != source
            || image.version() != 74
            || image.payloads().map(|p| p.kind).collect::<Vec<_>>() != expected
        {
            return TestResult::Fail("GC12 firmware type/stack count/version");
        }
        if matches!(
            source,
            Source::Pfp | Source::Me | Source::Mec | Source::Mes | Source::Mes1 | Source::Imu
        ) {
            for (i, p) in image.payloads().enumerate() {
                if p.bytes() != if i == 0 { &[0x11; 16] } else { &[0x22; 16] } {
                    return TestResult::Fail("instruction and data payloads mixed");
                }
            }
        }
        if source == Source::Dmcub && image.payloads().next().unwrap().bytes() != [0x11; 16] {
            return TestResult::Fail("DMCUB BSS sent to PSP");
        }
        if source == Source::Mec
            && image.entries
                != Some(EntryPoints {
                    code: 0x70000_00003000,
                    data: None,
                })
        {
            return TestResult::Fail("RS64 entry point lost upper bits");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_ucode_splits_stacks_imu_and_signed_media
);

fn navi48_ucode_rejects_truncation_wrong_ips_and_overlaps() -> TestResult {
    for source in Source::ALL {
        let b = container(source);
        for size in 0..b.len() {
            if Image::parse(source, &b[..size]).is_ok() {
                return TestResult::Fail("truncated GC12 container accepted");
            }
        }
        for (field, value) in [
            (0, 0),
            (4, 0),
            (8, u32::MAX),
            (12, 0x3000a),
            (20, 0),
            (20, u32::MAX),
            (24, 0),
            (24, 255),
            (24, u32::MAX),
        ] {
            let mut bad = b.clone();
            put(&mut bad, field, value);
            if Image::parse(source, &bad).is_ok() {
                return TestResult::Fail("invalid GC12 common header");
            }
        }
        let fields: &[usize] = match source {
            Source::Pfp | Source::Me | Source::Mec => &[36, 40, 44, 48, 52],
            Source::Mes | Source::Mes1 => &[36, 40, 48, 52, 56, 64],
            Source::Imu => &[32, 36, 40, 44],
            Source::Sdma => &[36, 40],
            Source::Dmcub => &[32, 36],
            Source::Rlc => &[120, 136, 152, 160, 168],
            _ => &[],
        };
        for &field in fields {
            let mut bad = b.clone();
            put(&mut bad, field, u32::MAX);
            if Image::parse(source, &bad).is_ok() {
                return TestResult::Fail("out-of-bounds or unaligned GC12 subimage");
            }
        }
        if matches!(source, Source::Pfp | Source::Me | Source::Mec) {
            let mut bad = b.clone();
            put(&mut bad, 48, 260);
            if Image::parse(source, &bad).is_ok() {
                return TestResult::Fail("overlapping RS64 code/data accepted");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_ucode_rejects_truncation_wrong_ips_and_overlaps
);
