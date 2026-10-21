use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Linux DC's DCN401 pipe acquisition over amdgpu_dm-shaped transactions
/// (tests/dcn401_pipes: harness.c documents the format).
const VECTORS: &str = include_str!("../tests/dcn401_pipes/vectors.txt");

/// harness.c's dump of a committed state's pool pipes.
fn dump(s: &DcState) -> String {
    let mut out = String::from("commit");
    for p in &s.pipes[..usize::from(s.pipe_count)] {
        if *p == PipeCtx::default() {
            out.push_str(" -");
            continue;
        }
        let _ = write!(out, " s{}", p.stream.map_or(-1, i32::from));
        for (tag, v) in [
            ("p", p.plane),
            ("t", p.top),
            ("b", p.bottom),
            ("l", p.prev_odm),
            ("r", p.next_odm),
        ] {
            if let Some(v) = v {
                let _ = write!(out, "{tag}{v}");
            }
        }
    }
    out
}

/// `map`'s targets: `<stream>:<odm>:<mpc>,<mpc>..` per stream.
fn targets(args: &str) -> Option<[(u8, Target); MAX_STREAMS]> {
    let mut out = [(0xff, Target::default()); MAX_STREAMS];
    for (slot, tok) in out.iter_mut().zip(args.split_whitespace()) {
        let mut f = tok.split(':');
        let stream = f.next()?.parse().ok()?;
        let odm = f.next()?.parse().ok()?;
        let mut t = Target {
            odm,
            mpc: [1; MAX_SURFACES],
        };
        for (m, v) in t.mpc.iter_mut().zip(f.next()?.split(',')) {
            *m = v.parse().ok()?;
        }
        *slot = (stream, t);
    }
    Some(out)
}

/// Every transaction of the vectors on `DcState`: each operation's result
/// and every committed state's pipes as Linux's.
fn dcn401_pipe_acquisition_matches_linux() -> TestResult {
    let mut cur = DcState::new(0);
    let mut next = cur;
    let (mut commits, mut ops) = (0, 0);
    for line in VECTORS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(fuses) = line.strip_prefix("pool ") {
            let fuses = u32::from_str_radix(fuses.trim_start_matches("0x"), 16).unwrap_or(0xff);
            let count = crate::amdgpu_rdna4::PipePool::from_fuses(fuses).count();
            cur = DcState::new(count);
            next = cur;
            continue;
        }
        if line == "begin" {
            next = cur;
            continue;
        }
        if line.starts_with("commit") {
            cur = next;
            commits += 1;
            if dump(&cur) != line {
                let _ = writeln!(
                    narf_console::Writer,
                    "dcn401 pipes: {line} != {}",
                    dump(&cur)
                );
                return TestResult::Fail("committed pipes differ from Linux");
            }
            continue;
        }
        let (op, want) = match line.rsplit_once(' ') {
            Some((op, "ok")) => (op, true),
            Some((op, "fail")) => (op, false),
            _ => return TestResult::Fail("vector line"),
        };
        let mut f = op.split_whitespace();
        let name = f.next().unwrap_or("");
        let mut arg = || f.next().and_then(|v| v.parse::<u8>().ok());
        let got = match name {
            "+stream" => {
                let Some(s) = arg() else {
                    return TestResult::Fail("stream");
                };
                next.add_stream(&cur, s)
            }
            "-stream" => {
                let Some(s) = arg() else {
                    return TestResult::Fail("stream");
                };
                next.remove_stream(&cur, s)
            }
            "+plane" | "-plane" => {
                let (Some(s), Some(p)) = (arg(), arg()) else {
                    return TestResult::Fail("plane");
                };
                if name == "+plane" {
                    next.add_plane(&cur, s, p)
                } else {
                    next.remove_plane(s, p)
                }
            }
            "map" => {
                let Some(t) = targets(&op[4..]) else {
                    return TestResult::Fail("map targets");
                };
                next.map_pipes(&cur, |s| {
                    t.iter().find(|(id, _)| *id == s).map_or(
                        Target {
                            odm: 1,
                            mpc: [1; MAX_SURFACES],
                        },
                        |&(_, t)| t,
                    )
                })
            }
            _ => return TestResult::Fail("unknown operation"),
        };
        ops += 1;
        if got != want {
            let _ = writeln!(narf_console::Writer, "dcn401 pipes: {line} gave {got}");
            return TestResult::Fail("operation result differs from Linux");
        }
    }
    if commits < 40 || ops < 100 {
        return TestResult::Fail("vectors.txt lost its transactions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pipes",
    dcn401_pipe_acquisition_matches_linux
);
