//! Native firmware scan scheduler fixture. Expected packets use the reviewed
//! source vectors plus explicit channel/power words, never driver encoders.
use super::*;
use alloc::collections::VecDeque;
include!("../wmi_runtime/station_wire_golden.rs");

#[derive(Debug)]
pub(super) struct Fixture {
    expected: VecDeque<Vec<u8>>,
    pub started: bool,
    pub stopped: bool,
    pub done: bool,
    pub stop_receipt: bool,
    pub stall: Option<usize>,
    pub release_after_ready: Option<(usize, Vec<u8>)>,
    sent: usize,
    sequence: u16,
    scan: Vec<u8>,
}

pub(super) fn domain(dialect: Dialect, home: u16) -> Vec<u8> {
    let mut packet = match dialect {
        Dialect::Main => RD_MAIN,
        Dialect::TenOne => RD_10X,
        Dialect::TenTwo | Dialect::TenTwoFour => RD_102,
        Dialect::TenFour => RD_104,
        Dialect::Tlv => RD_TLV,
    }
    .to_vec();
    if home > 3000 {
        let at = if dialect == Dialect::Tlv { 12 } else { 4 };
        for (i, value) in [0x3a, 0x3a, 0x3a, 0x10, 0x10].into_iter().enumerate() {
            u32at(&mut packet, at + i * 4, value);
        }
    }
    packet
}
pub(super) fn power(dialect: Dialect, frequency: u16) -> Vec<u8> {
    let mut packet = match dialect {
        Dialect::Main => POWER_MAIN,
        Dialect::TenOne => POWER_10X,
        Dialect::TenTwo | Dialect::TenTwoFour => POWER_102,
        Dialect::TenFour => POWER_104,
        Dialect::Tlv => POWER_TLV,
    }
    .to_vec();
    let at = packet.len() - 8;
    u32at(&mut packet, at, if frequency < 3000 { 3 } else { 4 });
    u32at(&mut packet, at + 4, if frequency < 3000 { 34 } else { 54 });
    packet
}
pub(super) fn inventory(
    dialect: Dialect,
    receive: &[u16],
    home: u16,
    width: u8,
    probes: &[u16],
) -> Vec<u8> {
    let mut frequencies = receive.to_vec();
    let occupied: Vec<u16> = match width {
        80 => vec![5180, 5200, 5220, 5240],
        40 => vec![home, if home == 5180 { 5200 } else { 5180 }],
        _ => vec![home],
    };
    for frequency in &occupied {
        if !frequencies.contains(frequency) {
            frequencies.push(*frequency);
        }
    }
    let mut packet = active_scan_tests::receive_on(dialect, &frequencies);
    let (base, stride) = if dialect == Dialect::Tlv {
        (20, 28)
    } else {
        (8, 24)
    };
    for (i, frequency) in frequencies.iter().copied().enumerate() {
        let at = base + i * stride;
        let is_home = occupied.contains(&frequency);
        if is_home || probes.contains(&frequency) {
            let flags = u32::from(frequency < 3000)
                | if is_home && width >= 40 { 1 << 11 } else { 0 }
                | if is_home && width == 80 { 1 << 12 } else { 0 }
                | if is_home && width >= 40 && (frequency - 5180) % 40 == 0 {
                    1 << 6
                } else {
                    0
                };
            u32at(&mut packet, at + 12, flags);
            let limit = if frequency < 3000 { 34 } else { 54 };
            packet[at + 17] = limit;
            packet[at + 18] = limit;
            packet[at + 21] = limit;
        }
    }
    packet
}
fn scan(dialect: Dialect, active: bool, frequencies: &[u16]) -> Vec<u8> {
    let mut packet = if active {
        active_scan_tests::scan(dialect, 2, &[b"narf".to_vec()], &[], [2412, 2437])
    } else {
        match dialect {
            Dialect::Main => SCAN_MAIN,
            Dialect::Tlv => SCAN_TLV,
            Dialect::TenFour => SCAN_104,
            _ => SCAN_10X,
        }
        .to_vec()
    };
    let (base, common) = match dialect {
        Dialect::Tlv => (8, 100),
        Dialect::Main | Dialect::TenFour => (4, 64),
        _ => (4, 60),
    };
    u32at(&mut packet, base, 0xa002);
    let at = base + common + if dialect == Dialect::Tlv { 4 } else { 8 };
    let channel_bytes: Vec<u8> = frequencies
        .iter()
        .flat_map(|f| u32::from(*f).to_le_bytes())
        .collect();
    packet.splice(at..at + 8, channel_bytes);
    if dialect == Dialect::Tlv {
        u32at(&mut packet, base + 64, frequencies.len() as u32);
        u32at(
            &mut packet,
            at - 4,
            (16 << 16) | (4 * frequencies.len()) as u32,
        );
    } else {
        u32at(&mut packet, at - 4, frequencies.len() as u32);
    }
    packet
}
impl Fixture {
    pub(super) fn new(
        dialect: Dialect,
        receive: &[u16],
        home: u16,
        width: u8,
        frequencies: &[u16],
        active: bool,
    ) -> Self {
        let restore = [
            domain(dialect, home),
            power(dialect, home),
            inventory(dialect, receive, home, width, &[]),
        ];
        let mut expected = VecDeque::new();
        if active {
            expected.push_back(domain(dialect, home));
            for two_ghz in [true, false] {
                if let Some(frequency) = frequencies
                    .iter()
                    .copied()
                    .chain(core::iter::once(home))
                    .find(|f| (*f < 3000) == two_ghz)
                {
                    expected.push_back(power(dialect, frequency));
                }
            }
            expected.push_back(inventory(dialect, receive, home, width, frequencies));
        } else {
            expected.extend(restore.iter().cloned());
        }
        let scan = scan(dialect, active, frequencies);
        expected.push_back(scan.clone());
        expected.extend(restore);
        Self {
            expected,
            started: false,
            stopped: false,
            done: false,
            stop_receipt: true,
            stall: None,
            release_after_ready: None,
            sent: 0,
            sequence: 2,
            scan,
        }
    }
}
pub(super) fn handles(f: &Fixture, dialect: Dialect, packet: &[u8]) -> bool {
    if f.done {
        return false;
    }
    let id = u32::from_le_bytes(packet[..4].try_into().unwrap());
    let modern = matches!(dialect, Dialect::Main | Dialect::Tlv);
    let domain_id = u32::from_le_bytes(domain(dialect, 2412)[..4].try_into().unwrap());
    let power_id = u32::from_le_bytes(power(dialect, 2412)[..4].try_into().unwrap());
    id == domain_id
        || id == power_id
        || if modern {
            matches!(id, 0x3001..=0x3003)
        } else {
            matches!(id, 0x9000..=0x9002)
        }
}
pub(super) fn send_now(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let dialect = m.inner.inner.dialect;
    let f = m.associated.as_mut().unwrap();
    let stopping = bytes[8..] == active_scan_tests::stop(dialect, f.sequence);
    let starting = bytes[8..] == f.scan;
    if stopping {
        f.stopped = true;
        f.done = true;
        f.expected.clear();
    } else if f.expected.pop_front().as_deref() != Some(&bytes[8..]) {
        return Err(BmiError::BadResponse);
    }
    f.sent += 1;
    f.started |= starting;
    f.done |= f.expected.is_empty();
    let receipt = stopping && f.stop_receipt;
    m.sent.push(bytes.to_vec());
    // Independent CE credit return, never used as firmware scan completion.
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    if starting {
        scan_event(m, 2, 0xa001, 0xa001);
        scan_event(m, 2, 0xa002, 0xa002);
        scan_event(m, 1, 0xa002, 0xa001);
    }
    if receipt {
        scan_event(m, 2, 0xa002, 0xa001);
    }
    Ok(())
}
pub(super) async fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    send_now(m, bytes)
}
pub(super) fn stall_next(fixture: &Fixture) -> bool {
    fixture.stall == Some(fixture.sent)
}
pub(super) fn complete(m: &mut RadioModel) {
    scan_event(m, 2, 0xa002, 0xa001);
}
