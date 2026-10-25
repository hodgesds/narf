use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

const VECTORS: &str = include_str!("../tests/dp_mst/vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn hex(out: &mut String, b: &[u8]) {
    if b.is_empty() {
        out.push('-');
    }
    for x in b {
        write!(out, "{x:02x}").unwrap();
    }
}
fn num(w: &str) -> u32 {
    w.parse().unwrap()
}

/// A parse result formatted in the retained sideband fixture grammar.
fn reply_line(out: &mut String, parsed: Option<Reply>, kind_byte: u8) {
    let kind = kind_byte & 0x7f;
    let nak = kind_byte & 0x80 != 0;
    let ok = parsed.is_some() && !nak;
    write!(out, "{} {} {}", u8::from(ok), u8::from(nak), kind).unwrap();
    match parsed {
        Some(Reply::Nak {
            guid, reason, data, ..
        }) => {
            out.push(' ');
            hex(out, &guid);
            write!(out, " {reason} {data}").unwrap();
        }
        Some(Reply::LinkAddress { guid, ports }) => {
            out.push(' ');
            hex(out, &guid);
            write!(out, " {}", ports.len()).unwrap();
            for p in ports {
                write!(
                    out,
                    " {},{},{},{},{},{},{},",
                    u8::from(p.input),
                    p.peer_device_type,
                    p.port,
                    u8::from(p.mcs),
                    u8::from(p.ddps),
                    u8::from(p.legacy_plug),
                    p.dpcd_revision
                )
                .unwrap();
                hex(out, &p.peer_guid);
                write!(out, ",{},{}", p.sdp_streams, p.sdp_stream_sinks).unwrap();
            }
        }
        Some(Reply::EnumPathResources {
            port,
            fec,
            full_pbn,
            available_pbn,
        }) => write!(out, " {port} {} {full_pbn} {available_pbn}", u8::from(fec)).unwrap(),
        Some(Reply::AllocatePayload { port, vcpi, pbn }) => {
            write!(out, " {port} {vcpi} {pbn}").unwrap()
        }
        Some(Reply::QueryPayload { port, pbn }) => write!(out, " {port} {pbn}").unwrap(),
        Some(Reply::RemoteDpcdRead { port, bytes })
        | Some(Reply::RemoteI2cRead { port, bytes }) => {
            write!(out, " {port} ").unwrap();
            hex(out, &bytes);
        }
        Some(Reply::RemoteDpcdWrite { port }) | Some(Reply::PowerUpDownPhy { port, .. }) => {
            write!(out, " {port}").unwrap()
        }
        Some(Reply::RemoteI2cWrite) | Some(Reply::ClearPayloadIdTable) | None => {}
    }
}

fn request(w: &[&str]) -> Request {
    let n = |i: usize| num(w[i]) as u8;
    match n(0) {
        LINK_ADDRESS => Request::LinkAddress,
        CLEAR_PAYLOAD_ID_TABLE => Request::ClearPayloadIdTable,
        ENUM_PATH_RESOURCES => Request::EnumPathResources { port: n(1) },
        POWER_UP_PHY => Request::PowerUpPhy { port: n(1) },
        POWER_DOWN_PHY => Request::PowerDownPhy { port: n(1) },
        ALLOCATE_PAYLOAD => Request::AllocatePayload {
            port: n(1),
            vcpi: n(2),
            pbn: num(w[3]) as u16,
            sdp_stream_sinks: (0..usize::from(n(4))).map(|i| n(5 + i)).collect(),
        },
        QUERY_PAYLOAD => Request::QueryPayload {
            port: n(1),
            vcpi: n(2),
        },
        REMOTE_DPCD_READ => Request::RemoteDpcdRead {
            port: n(1),
            address: num(w[2]),
            len: n(3),
        },
        REMOTE_DPCD_WRITE => Request::RemoteDpcdWrite {
            port: n(1),
            address: num(w[2]),
            bytes: unhex(w[3]),
        },
        REMOTE_I2C_READ => {
            let count = usize::from(n(2));
            let writes = (0..count)
                .map(|i| {
                    let f: Vec<&str> = w[3 + i].split(',').collect();
                    I2cWrite {
                        device: num(f[0]) as u8,
                        bytes: unhex(f[1]),
                        no_stop: f[2] == "1",
                        delay: num(f[3]) as u8,
                    }
                })
                .collect();
            Request::RemoteI2cRead {
                port: n(1),
                writes,
                device: n(3 + count),
                len: n(4 + count),
            }
        }
        _ => Request::RemoteI2cWrite {
            port: n(1),
            device: n(2),
            bytes: unhex(w[3]),
        },
    }
}

fn run_vector(input: &str) -> String {
    let w: Vec<&str> = input.split_whitespace().collect();
    let mut out = String::new();
    match w[0] {
        "hdr" => {
            let rad: [u8; 8] = unhex(w[3]).try_into().unwrap();
            let h = Header {
                lct: num(w[1]) as u8,
                lcr: num(w[2]) as u8,
                rad,
                broadcast: w[4] == "1",
                path_msg: w[5] == "1",
                msg_len: num(w[6]) as u8,
                somt: w[7] == "1",
                eomt: w[8] == "1",
                seqno: w[9] == "1",
            };
            let buf = h.encode();
            hex(&mut out, &buf);
            let ok = Header::decode(&buf).is_some();
            write!(out, " {}", u8::from(ok)).unwrap();
        }
        "crc" => write!(out, "{}", data_crc(&unhex(w[1]))).unwrap(),
        "req" => hex(&mut out, &request(&w[1..]).encode()),
        "tx" => {
            let rad: [u8; 8] = unhex(w[2]).try_into().unwrap();
            for (i, c) in chunks(num(w[1]) as u8, &rad, w[3] == "1", &unhex(w[4]))
                .iter()
                .enumerate()
            {
                if i > 0 {
                    out.push(' ');
                }
                hex(&mut out, c);
            }
        }
        "rx" => {
            let body = unhex(w[1]);
            let mut rx = Rx::default();
            let ok = chunks(1, &[0; 8], false, &body).iter().all(|c| rx.add(c));
            write!(out, "{} {} ", u8::from(ok), rx.len).unwrap();
            if ok && rx.have_eomt {
                reply_line(&mut out, Reply::parse(&rx), body[0]);
            } else {
                out.push_str("0 0 0");
            }
        }
        "up" => {
            let body = unhex(w[1]);
            let mut rx = Rx::default();
            rx.msg[..body.len()].copy_from_slice(&body);
            rx.len = body.len() as u8;
            match UpRequest::parse(&rx) {
                Some(UpRequest::ConnectionStatus {
                    port,
                    guid,
                    legacy_plug,
                    dp_plug,
                    message_capable,
                    input,
                    peer_device_type,
                }) => {
                    write!(out, "1 {CONNECTION_STATUS_NOTIFY} {port} ").unwrap();
                    hex(&mut out, &guid);
                    write!(
                        out,
                        " {} {} {} {} {peer_device_type}",
                        u8::from(legacy_plug),
                        u8::from(dp_plug),
                        u8::from(message_capable),
                        u8::from(input)
                    )
                    .unwrap();
                }
                Some(UpRequest::ResourceStatus {
                    port,
                    guid,
                    available_pbn,
                }) => {
                    write!(out, "1 {RESOURCE_STATUS_NOTIFY} {port} ").unwrap();
                    hex(&mut out, &guid);
                    write!(out, " {available_pbn}").unwrap();
                }
                None => write!(out, "0 {}", body[0] & 0x7f).unwrap(),
            }
        }
        "upack" => hex(&mut out, &UpRequest::ack(num(w[1]) as u8)),
        "pbn" => write!(out, "{}", calc_pbn_mode(num(w[1]), num(w[2]))).unwrap(),
        _ => out.push('?'),
    }
    out
}

/// Every reference vector from Linux's own sideband codec and PBN math.
fn dp_mst_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        let got = run_vector(input);
        if got != want {
            panic!("MST vector {input}\n want {want}\n  got {got}");
        }
        checked += 1;
    }
    if checked < 1800 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", dp_mst_matches_linux_vectors);

/// Linux's KUnit cases: drm_dp_calc_pbn_mode, and amdgpu's PBN divider and
/// slot count for 4 x HBR2 (17,280,000 kbps: 40 PBN per slot).
fn dp_mst_pbn_matches_linux_kunit() -> TestResult {
    for (clock, bpp, want) in [
        (154_000, 30, 689),
        (234_000, 30, 1047),
        (297_000, 24, 1063),
        (332_880, 24, 1191),
        (324_540, 24, 1161),
    ] {
        if calc_pbn_mode(clock, bpp << 4) != want {
            return TestResult::Fail("PBN");
        }
    }
    let div = pbn_div(17_280_000);
    if div != 40 << 12 || time_slots(1063, div) != 27 || time_slots(40, div) != 1 {
        return TestResult::Fail("PBN divider");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dp-mst", dp_mst_pbn_matches_linux_kunit);
