//! Independent literal firmware observations for OBSS and one native restart.
//! No production coexistence/channel encoder supplies an expected byte.
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const AP: [u8; 6] = [2, 8, 9, 10, 11, 12];
#[derive(Debug)]
pub(super) struct Fixture {
    pub channels: Vec<u16>,
    pub receive: Vec<u16>,
    pub scans: usize,
    pub narrow: bool,
    pub step: usize,
    pub restart: bool,
    pub hold_restart: bool,
    pub entered: Arc<AtomicBool>,
    pub observed_steps: Arc<AtomicUsize>,
    pub legacy: bool,
    pub periodic: bool,
    setup: usize,
}
impl Fixture {
    pub(super) fn new(primary: u16, secondary: u16, receive: Vec<u16>) -> Self {
        let low = primary.min(secondary) - 10;
        let high = primary.max(secondary) + 10;
        Self {
            receive,
            channels: (2412..=2472)
                .step_by(5)
                .filter(|f| f - 10 < high && low < f + 10)
                .collect(),
            scans: 0,
            narrow: false,
            step: 0,
            restart: false,
            hold_restart: false,
            entered: Arc::new(AtomicBool::new(false)),
            observed_steps: Arc::new(AtomicUsize::new(0)),
            legacy: false,
            periodic: false,
            setup: 0,
        }
    }
}
fn id(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
pub(super) fn handles(m: &RadioModel, b: &[u8]) -> bool {
    let Some(f) = &m.coexistence else {
        return false;
    };
    let command = id(b);
    let modern = matches!(m.inner.inner.dialect, Dialect::Main | Dialect::Tlv);
    if command == if modern { 0x3001 } else { 0x9000 } {
        // The ordinary one-channel discovery remains the preexisting fixture;
        // only the subsequent required OBSS request belongs to this observer.
        return m.scan >= 1;
    }
    (f.narrow || f.periodic)
        && match m.inner.inner.dialect {
            Dialect::Main | Dialect::Tlv => {
                matches!(command, 0x6004 | 0x4001 | 0x4003 | 0x3003 | 0x5004)
            }
            Dialect::TenOne => matches!(command, 0x901f | 0x9004 | 0x9006 | 0x9002 | 0x9014),
            Dialect::TenTwo | Dialect::TenTwoFour => {
                matches!(command, 0x901f | 0x9004 | 0x9006 | 0x9002 | 0x9013)
            }
            Dialect::TenFour => matches!(command, 0x9025 | 0x9006 | 0x9008 | 0x9002 | 0x9016),
        }
}
fn credit(m: &mut RadioModel, bytes: &[u8]) {
    m.sent.push(bytes.to_vec());
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
}
fn passive(d: Dialect, sequence: u16, channels: &[u16]) -> Vec<u8> {
    let mut expected = match d {
        Dialect::Main => SCAN_MAIN,
        Dialect::Tlv => SCAN_TLV,
        Dialect::TenFour => SCAN_104,
        _ => SCAN_10X,
    }
    .to_vec();
    let (base, common) = match d {
        Dialect::Tlv => (8, 100),
        Dialect::Main | Dialect::TenFour => (4, 64),
        _ => (4, 60),
    };
    u32at(&mut expected, base, 0xa000 | u32::from(sequence));
    let at = base + common;
    let start = at + if d == Dialect::Tlv { 4 } else { 8 };
    let values: Vec<u8> = channels
        .iter()
        .flat_map(|f| u32::from(*f).to_le_bytes())
        .collect();
    expected.splice(start..start + 8, values);
    if d == Dialect::Tlv {
        u32at(&mut expected, base + 64, channels.len() as u32);
        u32at(&mut expected, at, (16 << 16) | (channels.len() * 4) as u32);
    } else {
        u32at(&mut expected, at + 4, channels.len() as u32);
    }
    expected
}
pub(super) fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let b = &bytes[8..];
    let d = m.inner.inner.dialect;
    let modern = matches!(d, Dialect::Main | Dialect::Tlv);
    if m.coexistence.as_ref().unwrap().periodic && id(b) != if modern { 0x3001 } else { 0x9000 } {
        periodic_setup(m, b)?;
        credit(m, bytes);
        return Ok(());
    }
    if id(b) == if modern { 0x3001 } else { 0x9000 } {
        m.scan += 1;
        if b != passive(d, m.scan, &m.coexistence.as_ref().unwrap().channels) {
            return Err(BmiError::BadResponse);
        }
        m.coexistence.as_mut().unwrap().scans += 1;
        credit(m, bytes);
        let sequence = 0xa000 | m.scan;
        scan_event(m, 1, sequence, 0xa001);
        let frame = m.data.as_ref().unwrap().beacon();
        management_frame(m, frame);
        if m.coexistence.as_ref().unwrap().legacy {
            let beacon = m.data.as_ref().unwrap().beacon();
            let mut foreign = beacon[..36].to_vec();
            foreign[10] ^= 2;
            foreign[16] ^= 2;
            let mut at = 36;
            while at < beacon.len() {
                let end = at + 2 + usize::from(beacon[at + 1]);
                if !matches!(beacon[at], 45 | 61 | 74) {
                    foreign.extend_from_slice(&beacon[at..end]);
                }
                at = end;
            }
            management_frame(m, foreign);
            let f = m.data.as_mut().unwrap();
            f.ht_secondary = None;
            f.ht_capabilities = 0x2c;
            f.ht_request_sgi40 = false;
            f.rx_phy = Some((8, 7, 0));
        }
        scan_event(m, 2, sequence, 0xa001);
        if m.coexistence.as_ref().unwrap().periodic {
            m.coexistence.as_mut().unwrap().setup = 3;
        }
        return Ok(());
    }
    let word = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let step = m.coexistence.as_ref().unwrap().step;
    let tlv = d == Dialect::Tlv;
    let at = if tlv { 8 } else { 4 };
    let ok = match step {
        0 | 1 => {
            word(0)
                == if modern {
                    0x6004
                } else if d == Dialect::TenFour {
                    0x9025
                } else {
                    0x901f
                }
                && b.len() == if tlv { 28 } else { 24 }
                && (!tlv || word(4) == (100 << 16 | 20))
                && word(at) == 0
                && b[at + 4..at + 10] == AP
                && b[at + 10..at + 12] == [0, 0]
                && word(at + 12) == if step == 0 { 13 } else { 4 }
                && word(at + 16) == if step == 0 { 5 } else { 0 }
        }
        4 => {
            word(0)
                == if modern {
                    0x4003
                } else if d == Dialect::TenFour {
                    0x9008
                } else {
                    0x9006
                }
                && word(if tlv { 12 } else { 4 }) == 3
                && word(if tlv { 16 } else { 8 }) == 34
        }
        2 => {
            let radio_channels = &m.coexistence.as_ref().unwrap().receive;
            let mut expected = active_scan_tests::receive_on(d, radio_channels);
            let row = if tlv { 20 } else { 8 };
            let index = usize::from((m.frequency - 2412) / 5);
            let pos = row + index * if tlv { 28 } else { 24 };
            u32at(&mut expected, pos + 12, 0x801);
            for off in [17, 18, 21] {
                expected[pos + off] = 34;
            }
            b == expected
        }
        3 => {
            let mut expected = vec![0; if tlv { 112 } else { 132 }];
            let command = match d {
                Dialect::Main | Dialect::Tlv => 0x5004,
                Dialect::TenOne => 0x9014,
                Dialect::TenTwo | Dialect::TenTwoFour => 0x9013,
                Dialect::TenFour => 0x9016,
            };
            u32at(&mut expected, 0, command);
            if tlv {
                u32at(&mut expected, 4, (88 << 16) | 72);
                u32at(&mut expected, 80, (80 << 16) | 24);
                u32at(&mut expected, 108, 18 << 16);
            }
            let channel = if tlv { 84 } else { 4 };
            let owner = if tlv { 8 } else { 28 };
            u32at(&mut expected, owner + 8, 100);
            u32at(&mut expected, owner + 12, 1);
            u32at(&mut expected, channel, u32::from(m.frequency));
            u32at(&mut expected, channel + 4, u32::from(m.frequency));
            u32at(&mut expected, channel + 12, 0x805);
            for off in [17, 18, 21] {
                expected[channel + off] = 34;
            }
            b == expected
        }
        _ => false,
    };
    if !ok {
        return Err(BmiError::BadResponse);
    }
    m.coexistence.as_mut().unwrap().step += 1;
    m.coexistence
        .as_ref()
        .unwrap()
        .observed_steps
        .store(step + 1, Ordering::Release);
    credit(m, bytes);
    if step == 3 {
        m.coexistence.as_mut().unwrap().restart = true;
        m.coexistence
            .as_ref()
            .unwrap()
            .entered
            .store(true, Ordering::Release);
        let event = match d {
            Dialect::Main | Dialect::Tlv => 0x5001,
            Dialect::TenOne => 0x9005,
            _ => 0x9004,
        };
        for (vdev, kind) in [(0u32, 0u32), (1, 1)]
            .into_iter()
            .chain((!m.coexistence.as_ref().unwrap().hold_restart).then_some((0, 1)))
        {
            let mut body = Vec::new();
            for value in [vdev, 0, kind, 0] {
                body.extend_from_slice(&value.to_le_bytes());
            }
            if tlv {
                let mut tagged = Vec::new();
                item(&mut tagged, 40, &body);
                body = tagged;
            }
            add_event(m, event, &body);
        }
    }
    Ok(())
}
fn periodic_setup(m: &mut RadioModel, b: &[u8]) -> Result<(), BmiError> {
    let d = m.inner.inner.dialect;
    let tlv = d == Dialect::Tlv;
    let modern = matches!(d, Dialect::Main | Dialect::Tlv);
    let step = m.coexistence.as_ref().unwrap().setup;
    let expected = match step % 3 {
        0 => {
            let mut out = vec![
                0;
                if tlv {
                    32
                } else if d == Dialect::Main {
                    24
                } else {
                    28
                }
            ];
            u32at(
                &mut out,
                0,
                if modern {
                    0x4001
                } else if d == Dialect::TenFour {
                    0x9006
                } else {
                    0x9004
                },
            );
            let at = if tlv {
                u32at(&mut out, 4, (81 << 16) | 24);
                12
            } else {
                4
            };
            for (i, value) in [0x64, 0x64, 0x64, 0xff, 0xff].into_iter().enumerate() {
                u32at(&mut out, at + i * 4, value);
            }
            out
        }
        1 => {
            let mut out = vec![0; if tlv { 20 } else { 12 }];
            u32at(
                &mut out,
                0,
                if modern {
                    0x4003
                } else if d == Dialect::TenFour {
                    0x9008
                } else {
                    0x9006
                },
            );
            let at = if tlv {
                u32at(&mut out, 4, (82 << 16) | 12);
                12
            } else {
                4
            };
            u32at(&mut out, at, 3);
            u32at(&mut out, at + 4, 34);
            out
        }
        _ => {
            let f = m.coexistence.as_ref().unwrap();
            let secondary = m.data.as_ref().unwrap().ht_secondary.unwrap();
            let mut out = active_scan_tests::receive_on(d, &f.receive);
            for frequency in [m.frequency, secondary] {
                let index = f
                    .receive
                    .iter()
                    .position(|v| *v == frequency)
                    .ok_or(BmiError::BadResponse)?;
                let at = if tlv { 20 + index * 28 } else { 8 + index * 24 };
                u32at(
                    &mut out,
                    at + 12,
                    0x801
                        | if frequency == m.frequency.min(secondary) {
                            64
                        } else {
                            0
                        },
                );
                for off in [17, 18, 21] {
                    out[at + off] = 34;
                }
            }
            out
        }
    };
    if b != expected {
        return Err(BmiError::BadResponse);
    }
    let f = m.coexistence.as_mut().unwrap();
    f.setup += 1;
    if f.setup == 6 {
        f.periodic = false;
        f.setup = 0;
    }
    Ok(())
}
