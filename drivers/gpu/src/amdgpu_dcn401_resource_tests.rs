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

/// harness.c's resource_build_scaling_params: SPL on the pipe's slice of
/// its plane (an RGB plane at its geometry, the slice its
/// resource_get_odm_slice_src_rect and MPC slice), or true for a plane the
/// script gave no geometry.
struct Geometry {
    timing: alloc::collections::BTreeMap<u8, (i32, i32)>,
    planes: alloc::collections::BTreeMap<u8, ([i32; 2], crate::amdgpu_dcn401_spl::Rect)>,
}
impl Scaling for Geometry {
    fn build(&self, s: &DcState, pipe: u8) -> bool {
        use crate::amdgpu_dcn401_spl as spl;
        let p = s.pipes[usize::from(pipe)];
        let (Some(plane), Some(stream)) = (p.plane, p.stream) else {
            return true;
        };
        let Some(&([sw, sh], dst)) = self.planes.get(&plane) else {
            return true;
        };
        let (w, h) = self.timing.get(&stream).copied().unwrap_or((3840, 2160));
        // resource_get_odm_slice_dst_width/_rect: h_active over the count,
        // the last slice the rest.
        let count = s.odm_slice_count(pipe) as i32;
        let index = s.odm_slice_index(pipe) as i32;
        let width = w / count;
        let odm_slice = spl::Rect::new(
            width * index,
            0,
            if index + 1 == count {
                w - width * (count - 1)
            } else {
                width
            },
            h,
        );
        spl::calculate(&spl::Input {
            src: spl::Rect::new(0, 0, sw, sh),
            dst,
            clip: dst,
            stream_width: w,
            stream_height: h,
            odm_slice,
            mpc_slice: (
                s.mpc_slice_index(pipe) as i32,
                s.mpc_slice_count(pipe) as i32,
            ),
            rotation: spl::Rotation::R0,
            horizontal_mirror: false,
            alpha: false,
            video: None,
        })
        .ok
    }
}

/// Every transaction of the vectors on `DcState`: each operation's result
/// and every committed state's pipes as Linux's.
fn dcn401_pipe_acquisition_matches_linux() -> TestResult {
    let mut cur = DcState::new(0);
    let mut next = cur;
    let (mut commits, mut ops) = (0, 0);
    let mut sc = Geometry {
        timing: alloc::collections::BTreeMap::new(),
        planes: alloc::collections::BTreeMap::new(),
    };
    for line in VECTORS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(fuses) = line.strip_prefix("pool ") {
            let fuses = u32::from_str_radix(fuses.trim_start_matches("0x"), 16).unwrap_or(0xff);
            let count = crate::amdgpu_rdna4::PipePool::from_fuses(fuses).count();
            cur = DcState::new(count);
            next = cur;
            sc.timing.clear();
            sc.planes.clear();
            continue;
        }
        let words: alloc::vec::Vec<i32> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|v| v.parse().ok())
            .collect();
        if line.starts_with("timing ") {
            let [s, w, h] = words[..] else {
                return TestResult::Fail("timing");
            };
            sc.timing.insert(s as u8, (w, h));
            continue;
        }
        if line.starts_with("geom ") {
            let [p, sw, sh, dx, dy, dw, dh] = words[..] else {
                return TestResult::Fail("geom");
            };
            sc.planes.insert(
                p as u8,
                (
                    [sw, sh],
                    crate::amdgpu_dcn401_spl::Rect::new(dx, dy, dw, dh),
                ),
            );
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
                next.add_stream(&cur, s, &sc)
            }
            "-stream" => {
                let Some(s) = arg() else {
                    return TestResult::Fail("stream");
                };
                next.remove_stream(&cur, s, &sc)
            }
            "+plane" | "-plane" => {
                let (Some(s), Some(p)) = (arg(), arg()) else {
                    return TestResult::Fail("plane");
                };
                if name == "+plane" {
                    next.add_plane(&cur, s, p, &sc)
                } else {
                    next.remove_plane(s, p)
                }
            }
            "map" => {
                let Some(t) = targets(&op[4..]) else {
                    return TestResult::Fail("map targets");
                };
                next.map_pipes(
                    &cur,
                    |s| {
                        t.iter().find(|(id, _)| *id == s).map_or(
                            Target {
                                odm: 1,
                                mpc: [1; MAX_SURFACES],
                            },
                            |&(_, t)| t,
                        )
                    },
                    &sc,
                )
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

/// Linux DC's DCN401 stream-encoder acquisition over add/remove sequences
/// (tests/dcn401_stream_enc: harness.c documents the format): each
/// stream's DIO stream encoder, HPO DP stream encoder, its link's HPO DP
/// link encoder and its audio endpoint after its OTG master, and their
/// release; then find_first_free_audio over every acquisition state.
const ENCODER_VECTORS: &str = include_str!("../tests/dcn401_stream_enc/vectors.txt");

fn dcn401_stream_encoder_acquisition_matches_linux() -> TestResult {
    let cur = DcState::new(4);
    let mut checked = 0;
    for line in ENCODER_VECTORS.lines().filter(|l| !l.starts_with('#')) {
        if let Some(v) = line.strip_prefix("audio ") {
            let Some((args, want)) = v.split_once(" = ") else {
                return TestResult::Fail("audio line");
            };
            let f: alloc::vec::Vec<u8> = args.split(' ').filter_map(|x| x.parse().ok()).collect();
            let [se, aud, id] = f[..] else {
                return TestResult::Fail("audio args");
            };
            let mut state = DcState::new(4);
            for i in 0..4 {
                state.stream_enc_acquired[i] = se >> i & 1 != 0;
                state.audio_acquired[i] = aud >> i & 1 != 0;
            }
            let got = state
                .find_first_free_audio(id)
                .map_or(String::from("-"), |a| alloc::format!("{a}"));
            checked += 1;
            if got != want {
                let _ = writeln!(narf_console::Writer, "dcn401 audio: {line}: gave {got}");
                return TestResult::Fail("audio acquisition differs from Linux");
            }
            continue;
        }
        let Some((ops, results)) = line.strip_prefix("seq ").and_then(|l| l.split_once(" = "))
        else {
            return TestResult::Fail("vector line");
        };
        let mut state = DcState::new(4);
        for (op, want) in ops.split(' ').zip(results.split(' ')) {
            let got = if let Some(r) = op.strip_prefix('-') {
                let Ok(s) = r.parse::<u8>() else {
                    return TestResult::Fail("remove op");
                };
                if !state.remove_stream(&cur, s, &ScalesAnywhere) {
                    return TestResult::Fail("remove a stream");
                }
                String::from("r")
            } else {
                let f: alloc::vec::Vec<u8> =
                    op[1..].split('.').filter_map(|x| x.parse().ok()).collect();
                let [s, link, engine, hpo, audio] = f[..] else {
                    return TestResult::Fail("add op");
                };
                if !state.add_stream(&cur, s, &ScalesAnywhere) {
                    return TestResult::Fail("OTG master");
                }
                let output = StreamOutput {
                    link,
                    preferred_engine: engine,
                    hpo_dp: hpo == 1,
                    audio: audio == 1,
                };
                let opt = |v: Option<u8>| v.map_or(String::from("-"), |v| alloc::format!("{v}"));
                match state.map_stream_encoders(s, output) {
                    Some(e) => alloc::format!(
                        "{}.{}.{}.{}",
                        e.stream_enc,
                        opt(e.hpo_dp_stream_enc),
                        opt(e.hpo_dp_link_enc),
                        opt(e.audio)
                    ),
                    None => String::from("E"),
                }
            };
            checked += 1;
            if got != want {
                let _ = writeln!(
                    narf_console::Writer,
                    "dcn401 encoders: {line}: {op} gave {got}"
                );
                return TestResult::Fail("encoder acquisition differs from Linux");
            }
        }
    }
    if checked < 6000 {
        return TestResult::Fail("vectors.txt lost its sequences");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pipes",
    dcn401_stream_encoder_acquisition_matches_linux
);

/// Two 128b/132b MST streams on one link share its HPO DP link encoder
/// whatever pipes they run on; once the stream that trained the link
/// leaves, the link keeps that encoder for the other, and a 128b/132b
/// stream on another link takes a free one (not the departed stream's
/// pipe's); its DIO and HPO DP stream encoders come from the free pools.
fn dcn401_hpo_dp_link_encoder_follows_the_link() -> TestResult {
    let cur = DcState::new(4);
    let mut state = DcState::new(4);
    let mst = |engine| StreamOutput {
        link: 0,
        preferred_engine: engine,
        hpo_dp: true,
        audio: false,
    };
    for s in [5, 6] {
        if !state.add_stream(&cur, s, &ScalesAnywhere) {
            return TestResult::Fail("OTG masters");
        }
    }
    let a = state.map_stream_encoders(5, mst(0));
    let b = state.map_stream_encoders(6, mst(0));
    let want_b = StreamEncoders {
        stream_enc: 3,
        hpo_dp_stream_enc: Some(1),
        hpo_dp_link_enc: Some(0),
        audio: None,
    };
    if a.map(|e| e.hpo_dp_link_enc) != Some(Some(0)) || b != Some(want_b) {
        return TestResult::Fail("one link encoder per link");
    }
    // The owner (on the first pipe) leaves; its link encoder stays the link's.
    if !state.remove_stream(&cur, 5, &ScalesAnywhere)
        || state.find_acquired_hpo_dp_link_enc_for_link(0) != Some(0)
    {
        return TestResult::Fail("the link keeps its encoder");
    }
    if !state.add_stream(&cur, 7, &ScalesAnywhere) {
        return TestResult::Fail("third OTG master");
    }
    let sst = state.map_stream_encoders(
        7,
        StreamOutput {
            link: 1,
            preferred_engine: 1,
            hpo_dp: true,
            audio: false,
        },
    );
    let want = StreamEncoders {
        stream_enc: 1,
        hpo_dp_stream_enc: Some(0),
        hpo_dp_link_enc: Some(1),
        audio: None,
    };
    if sst != Some(want) {
        return TestResult::Fail("another link's encoder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pipes",
    dcn401_hpo_dp_link_encoder_follows_the_link
);
