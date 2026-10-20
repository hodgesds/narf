use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Linux's output for each input; see tests/dcn401_color/check.sh.
const VECTORS: &str = include_str!("../tests/dcn401_color/vectors.txt");

/// harness.c's xorshift64 LUT generator, step for step.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u32
    }
}

fn ramp(i: u32, n: u32) -> u16 {
    (u64::from(i) * 0xffff / u64::from(n - 1)) as u16
}

/// harness.c's lut(): see its kinds there.
fn lut(n: u32, kind: u32, seed: u64) -> Vec<DrmColorLut> {
    let mut rng = Rng(seed.wrapping_mul(2).wrapping_add(1));
    let mut acc = [0u32; 3];
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut c = [0u16; 3];
        for (k, ck) in c.iter_mut().enumerate() {
            let kk = if kind == 5 { k as u32 } else { kind };
            let v: u32 = match kk {
                0 => u32::from(ramp(i, n)),
                1 => 0xffff - u32::from(ramp(i, n)),
                2 => {
                    acc[k] += rng.next() % (2 * 0x10000 / n + 1);
                    acc[k].min(0xffff)
                }
                3 => rng.next() & 0xffff,
                4 => {
                    let v = 2 * u32::from(ramp(i, n));
                    let v = v.saturating_sub(0x4000);
                    v.min(0xffff)
                }
                6 => {
                    let (x, d) = (u64::from(i), u64::from(n - 1));
                    if k == 2 {
                        (x * x * x * 0xffff / (d * d * d)) as u32
                    } else {
                        (x * x * 0xffff / (d * d)) as u32
                    }
                }
                7 => (u64::from(i) * 0xff00 / u64::from(n - 1)) as u32,
                8 => {
                    let x = i64::from(ramp(i, n)) + i64::from(rng.next() % 3) - 1;
                    x.clamp(0, 0xffff) as u32
                }
                9 => 0x8000,
                _ => {
                    if k == 1 && i == n - 1 {
                        0xff80
                    } else if k == 1 {
                        (u64::from(i) * 0xff00 / u64::from(n - 1)) as u32
                    } else {
                        u32::from(ramp(i, n))
                    }
                }
            };
            *ck = v as u16;
        }
        out.push(DrmColorLut {
            red: c[0],
            green: c[1],
            blue: c[2],
            reserved: 0,
        });
    }
    out
}

fn fnv(mut h: u32, w: u32) -> u32 {
    for b in 0..4 {
        h ^= (w >> (8 * b)) & 0xff;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

/// One gamma vector's output, formatted as harness.c prints it.
fn gamma_line(full: bool, n: u32, kind: u32, seed: u64) -> String {
    let l = lut(n, kind, seed);
    let Some(pwl) = regamma_pwl(&l) else {
        return String::from("-");
    };
    let r = pwl.registers();
    let mut s = String::new();
    for w in r
        .start_cntl
        .iter()
        .chain(&r.start_slope_cntl)
        .chain(&r.end_cntl1)
        .chain(&r.end_cntl2)
        .chain(&r.region)
    {
        let _ = write!(s, "{w:x} ");
    }
    let mask = |v: &[u32]| v.iter().map(|w| w & 0x3ffff).collect::<Vec<_>>();
    let words = [
        mask(&pwl.red_reg),
        mask(&pwl.green_reg),
        mask(&pwl.blue_reg),
    ];
    let h = words
        .iter()
        .flatten()
        .fold(2_166_136_261u32, |h, &w| fnv(h, w));
    let eq = if pwl.rgb_equal() { "eq" } else { "ne" };
    let _ = write!(s, "{eq} {} {h:08x}", pwl.hw_points_num);
    if full {
        for w in words.iter().flatten() {
            let _ = write!(s, " {w:x}");
        }
    }
    s
}

fn ctm_line(words: &[u64; 9]) -> String {
    let g = gamut_remap(&ctm_matrix(words));
    let mut s = String::new();
    let _ = write!(s, "{}", u8::from(g.s3_12));
    for w in g.words() {
        let _ = write!(s, " {w:x}");
    }
    s
}

fn run(input: &str) -> Option<String> {
    let w: Vec<&str> = input.split_whitespace().collect();
    match *w.first()? {
        tag @ ("G" | "F") => Some(gamma_line(
            tag == "F",
            w.get(1)?.parse().ok()?,
            w.get(2)?.parse().ok()?,
            w.get(3)?.parse().ok()?,
        )),
        "C" => {
            let mut m = [0u64; 9];
            for (v, t) in m.iter_mut().zip(w.get(1..10)?) {
                *v = u64::from_str_radix(t, 16).ok()?;
            }
            Some(ctm_line(&m))
        }
        _ => None,
    }
}

/// Every GAMMA_LUT's OGAM register image and LUT words, and every CTM's
/// gamut-remap words, equal Linux's.
fn dcn_color_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        match run(input) {
            Some(got) if got == want => checked += 1,
            Some(_) => return TestResult::Fail("output differs from Linux"),
            None => return TestResult::Fail("vector input"),
        }
    }
    if checked < 250 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-color", dcn_color_matches_linux_vectors);

/// __is_lut_linear: at least two entries, equal channels, +-1 of the ramp.
fn dcn_color_lut_linearity() -> TestResult {
    let e = |v: u16| DrmColorLut {
        red: v,
        green: v,
        blue: v,
        reserved: 0,
    };
    let mut id: Vec<DrmColorLut> = (0..4096).map(|i| e(ramp(i, 4096))).collect();
    let ok = !is_lut_linear(&[])
        && !is_lut_linear(&[e(0)])
        && is_lut_linear(&[e(0), e(0xffff)])
        && is_lut_linear(&[e(1), e(0xfffe)])
        && !is_lut_linear(&[e(2), e(0xffff)])
        && !is_lut_linear(&[e(0), e(0xfffd)])
        && is_lut_linear(&id)
        && {
            id[100].red += 1;
            !is_lut_linear(&id)
        }
        && {
            id[100] = e(ramp(100, 4096) + 1);
            id[200] = e(ramp(200, 4096) - 1);
            is_lut_linear(&id)
        }
        && {
            id[300] = e(ramp(300, 4096) + 2);
            !is_lut_linear(&id)
        };
    if !ok {
        return TestResult::Fail("is_lut_linear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-color", dcn_color_lut_linearity);

/// Fixed31_32 corner cases, by Linux's definitions.
fn dcn_color_fixpt_matches_linux() -> TestResult {
    let f = Fixed31_32::from_fraction;
    let checks = [
        // 1/3 rounds its last bit up; -1/3 is its negation.
        f(1, 3).0 == 0x5555_5555,
        f(2, 3).0 == 0xaaaa_aaab,
        f(-1, 3).0 == -0x5555_5555,
        f(1, -3) == f(-1, 3),
        f(5, 0) == Fixed31_32::ZERO,
        Fixed31_32::from_int(-2).0 == -(2i64 << 32),
        // Floor and round go by magnitude; round is half away from zero.
        f(-3, 2).floor() == -1,
        f(-3, 2).round() == -2,
        f(5, 2).round() == 3,
        f(1, 2).ceil() == 1,
        f(-1, 3).ceil() == -1,
        // Products round their fraction half up.
        Fixed31_32::HALF.mul(Fixed31_32::EPSILON).0 == 1,
        Fixed31_32(-3).shr(1).0 == -1,
        // 2^-12 exactly, 2^1 exactly.
        Fixed31_32::from_int(2).pow(Fixed31_32::from_int(-12)).0 == 1 << 20,
        Fixed31_32::from_int(2).pow(Fixed31_32::ONE).0 == 2 << 32,
        Fixed31_32::ZERO.pow(Fixed31_32::ZERO) == Fixed31_32::ONE,
        Fixed31_32::ZERO.pow(Fixed31_32::ONE) == Fixed31_32::ZERO,
        // clamp_u0d14: one and above saturate, below 2^-14 floors at 1.
        Fixed31_32::ONE.clamp_u0d14() == 0x3fff,
        Fixed31_32::HALF.clamp_u0d14() == 0x2000,
        Fixed31_32::ZERO.clamp_u0d14() == 1,
        // DRM's sign-magnitude: negative zero is zero.
        fixpt_from_s3132(1 << 63) == Fixed31_32::ZERO,
        fixpt_from_s3132(1 << 63 | 1 << 32) == Fixed31_32::from_int(-1),
    ];
    if checks.iter().any(|&c| !c) {
        return TestResult::Fail("fixed point");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-color", dcn_color_fixpt_matches_linux);

/// No input of either supported size panics, extremes included, and other
/// sizes have no curve; blobs decode only as whole entries or nine words.
fn dcn_color_entry_points_never_panic() -> TestResult {
    for n in [256u32, 4096] {
        for v in [0u16, 1, 0x7fff, 0xff00, 0xff01, 0xfffe, 0xffff] {
            let l = alloc::vec![
                DrmColorLut {
                    red: v,
                    green: !v,
                    blue: v / 2,
                    reserved: 0xffff,
                };
                n as usize
            ];
            if regamma_pwl(&l).is_none() {
                return TestResult::Fail("constant LUT");
            }
        }
        // Alternating extremes.
        let l: Vec<DrmColorLut> = (0..n)
            .map(|i| {
                let v = if i % 2 == 0 { 0 } else { 0xffff };
                DrmColorLut {
                    red: v,
                    green: !v,
                    blue: v,
                    reserved: 0,
                }
            })
            .collect();
        if regamma_pwl(&l).is_none() {
            return TestResult::Fail("alternating LUT");
        }
    }
    for n in [0usize, 1, 2, 255, 257, 1024, 4095, 4097] {
        if regamma_tf(&alloc::vec![DrmColorLut::default(); n]).is_some() {
            return TestResult::Fail("unsupported size");
        }
    }
    let blob = [1u8, 0, 2, 0, 3, 0, 4, 0];
    if DrmColorLut::from_bytes(&blob)
        != Some(alloc::vec![DrmColorLut {
            red: 1,
            green: 2,
            blue: 3,
            reserved: 4
        }])
        || DrmColorLut::from_bytes(&blob[..7]).is_some()
        || ctm_from_bytes(&[0; 71]).is_some()
        || ctm_from_bytes(&[0xff; 72]) != Some([u64::MAX; 9])
    {
        return TestResult::Fail("blob decoding");
    }
    // Extreme CTMs saturate to the S3.12 range.
    let g = gamut_remap(&ctm_matrix(&[
        u64::MAX,
        i64::MAX as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]));
    if !g.s3_12 || g.coef[0] == 0 || g.coef[1] == 0 {
        return TestResult::Fail("saturating CTM");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-color", dcn_color_entry_points_never_panic);
