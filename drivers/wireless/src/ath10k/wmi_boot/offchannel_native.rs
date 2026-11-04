//! Independent WMI scan/peer and HTT/DMA observations. No production encoder
//! constructs any expected packet. Ordinary station fixtures remain unchanged.
use super::*;
use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[derive(Debug)]
pub(super) struct Signals {
    pub foreign: AtomicBool,
    pub started: AtomicBool,
    pub stop_receipt: AtomicBool,
    pub terminal: AtomicBool,
    pub multicast: AtomicBool,
    pub descriptors: AtomicU32,
    pub deletes: AtomicU32,
}
impl Signals {
    fn new() -> Self {
        Self {
            foreign: AtomicBool::new(true),
            started: AtomicBool::new(false),
            stop_receipt: AtomicBool::new(true),
            terminal: AtomicBool::new(true),
            multicast: AtomicBool::new(false),
            descriptors: AtomicU32::new(0),
            deletes: AtomicU32::new(0),
        }
    }
}
#[derive(Debug)]
pub(super) struct Fixture {
    pub signals: Arc<Signals>,
    setup: VecDeque<Vec<u8>>,
    restore: VecDeque<Vec<u8>>,
    sequence: u16,
    frequency: u16,
    home: Option<u16>,
    scan: Vec<u8>,
    foreign_sent: bool,
    stopped: bool,
    terminal_scan_sent: bool,
    tx: Option<(u32, bool)>,
    tx_delivered: bool,
    destination: Option<[u8; 6]>,
    pub done: bool,
}
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn patch(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
impl Fixture {
    pub(super) fn new(
        d: Dialect,
        channels: &[u16],
        home: Option<u16>,
        sequence: u16,
        frequency: u16,
        duration: u32,
        transmit: bool,
    ) -> Self {
        let mut setup = VecDeque::new();
        let mut restore = VecDeque::new();
        if let Some(home) = home {
            restore.push_back(associated_scan_tests::domain(d, 5180));
            restore.push_back(associated_scan_tests::power(d, home));
            restore.push_back(associated_scan_tests::inventory(d, channels, home, 20, &[]));
        } else {
            restore.push_back(active_scan_tests::receive_on(d, channels));
        }
        if transmit {
            // Actual EEPROM0x8348 is fixed US/pair0x3a with CTL0x10.
            // Both bands retain those actual board facts.
            setup.push_back(associated_scan_tests::domain(d, 5180));
            if let Some(home) = home.filter(|h| *h < 3000 && frequency > 3000) {
                setup.push_back(associated_scan_tests::power(d, home));
            }
            setup.push_back(associated_scan_tests::power(d, frequency));
            setup.push_back(if let Some(home) = home {
                associated_scan_tests::inventory(d, channels, home, 20, &[frequency])
            } else {
                let mut table = active_scan_tests::receive_on(d, &[frequency]);
                let at = if d == Dialect::Tlv { 20 } else { 8 };
                patch(&mut table, at + 12, u32::from(frequency < 3000));
                let limit = if frequency < 3000 { 34 } else { 54 };
                for offset in [17, 18, 21] {
                    table[at + offset] = limit;
                }
                table
            });
        } else {
            setup.extend(restore.iter().cloned());
        }
        let mut scan = match d {
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
        patch(&mut scan, base, 0xa000 | u32::from(sequence));
        for offset in [20, 24, 48] {
            patch(&mut scan, base + offset, duration);
        }
        if matches!(d, Dialect::Main | Dialect::TenFour | Dialect::Tlv) {
            patch(&mut scan, base + 60, duration);
        }
        let at = base + common + if d == Dialect::Tlv { 4 } else { 8 };
        scan.splice(at..at + 8, u32::from(frequency).to_le_bytes());
        if d == Dialect::Tlv {
            patch(&mut scan, base + 64, 1);
            patch(&mut scan, at - 4, (16 << 16) | 4);
        } else {
            patch(&mut scan, at - 4, 1);
        }
        setup.push_back(scan.clone());
        Self {
            signals: Arc::new(Signals::new()),
            setup,
            restore,
            sequence,
            frequency,
            home,
            scan,
            foreign_sent: false,
            stopped: false,
            terminal_scan_sent: false,
            tx: None,
            tx_delivered: false,
            destination: None,
            done: false,
        }
    }
}
pub(super) fn handles(m: &RadioModel, b: &[u8]) -> bool {
    if m.offchannel.as_ref().is_none_or(|f| f.done) || b.len() < 4 {
        return false;
    }
    let id = word(b, 0);
    match m.inner.inner.dialect {
        Dialect::Main | Dialect::Tlv => matches!(
            id,
            0x3001..=0x3003 | 0x4001 | 0x4003 | 0x6001 | 0x6002 | 0x7008
        ),
        Dialect::TenOne => matches!(id, 0x9000..=0x9002 | 0x9004 | 0x9006 | 0x901c | 0x901d),
        Dialect::TenTwo | Dialect::TenTwoFour => {
            matches!(id, 0x9000..=0x9002 | 0x9004 | 0x9006 | 0x901c | 0x901d)
        }
        Dialect::TenFour => matches!(id, 0x9000..=0x9002 | 0x9006 | 0x9008 | 0x9022 | 0x9023),
    }
}
fn event(m: &mut RadioModel, kind: u32, frequency: u16, sequence: u16, request: u16) {
    let mut b = Vec::new();
    for value in [
        kind,
        0,
        u32::from(frequency),
        u32::from(request),
        u32::from(sequence),
        0,
    ] {
        b.extend_from_slice(&value.to_le_bytes());
    }
    if m.inner.inner.dialect == Dialect::Tlv {
        let mut tlv = Vec::new();
        item(&mut tlv, 36, &b);
        b = tlv;
    }
    add_event(
        m,
        if matches!(m.inner.inner.dialect, Dialect::Main | Dialect::Tlv) {
            0x3001
        } else {
            0x9000
        },
        &b,
    );
}
fn credit(m: &mut RadioModel, b: &[u8]) {
    m.sent.push(b.to_vec());
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
            b.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
}
pub(super) fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let d = m.inner.inner.dialect;
    let b = &bytes[8..];
    let id = word(b, 0);
    let create = match d {
        Dialect::Main | Dialect::Tlv => 0x6001,
        Dialect::TenFour => 0x9022,
        _ => 0x901c,
    };
    let delete = match d {
        Dialect::Main | Dialect::Tlv => 0x6002,
        Dialect::TenFour => 0x9023,
        _ => 0x901d,
    };
    let base = if d == Dialect::Tlv { 8 } else { 4 };
    if id == create {
        if b.len() != base + 16
            || word(b, base) != 0
            || word(b, base + 12) != 0
            || m.offchannel.as_ref().unwrap().destination.is_some()
        {
            return Err(BmiError::BadResponse);
        }
        let destination: [u8; 6] = b[base + 4..base + 10].try_into().unwrap();
        m.offchannel.as_mut().unwrap().destination = Some(destination);
        let mut map = vec![3, 0, 29, 0];
        map.extend_from_slice(&destination);
        map.extend_from_slice(&[0, 0]);
        m.inner
            .inner
            .rx
            .push_back((m.inner.receive_pipe, header(1, &map)));
    } else if id == delete {
        let f = m.offchannel.as_mut().unwrap();
        if b.len() != base + 12
            || word(b, base) != 0
            || Some(b[base + 4..base + 10].try_into().unwrap()) != f.destination
            || f.tx.is_some() && !f.tx_delivered
        {
            return Err(BmiError::BadResponse);
        }
        f.signals.deletes.fetch_add(1, Ordering::AcqRel);
        m.inner
            .inner
            .rx
            .push_back((m.inner.receive_pipe, header(1, &[4, 0, 29, 0])));
    } else if id == 0x7008 {
        let desc = word(b, 12);
        let len = word(b, 28) as usize;
        let prefix = len.min(64).div_ceil(4) * 4;
        if d != Dialect::Tlv
            || word(b, 4) != (422 << 16 | 28)
            || word(b, 8) != 0
            || word(b, 16) != 0
            || word(b, 32) as usize != prefix
            || word(b, 36) != (17 << 16 | prefix as u32)
        {
            return Err(BmiError::BadResponse);
        }
        let (address, payload) = m
            .management_memory
            .as_ref()
            .ok_or(BmiError::BadResponse)?
            .snapshot(desc)
            .ok_or(BmiError::BadResponse)?;
        if word(b, 20) != address as u32
            || word(b, 24) != 0
            || payload.len() < len
            || b[40..40 + len.min(64)] != payload[..len.min(64)]
            || payload[..len] != expected_frame(m)
        {
            return Err(BmiError::BadResponse);
        }
        let f = m.offchannel.as_mut().unwrap();
        f.tx = Some((desc, true));
        f.signals.descriptors.fetch_add(1, Ordering::AcqRel);
    } else {
        let f = m.offchannel.as_mut().unwrap();
        if b == active_scan_tests::stop(d, f.sequence) {
            f.stopped = true;
        } else if !f.setup.is_empty() {
            if f.setup.pop_front().as_deref() != Some(b) {
                return Err(BmiError::BadResponse);
            }
        } else if !f.stopped || f.restore.pop_front().as_deref() != Some(b) {
            return Err(BmiError::BadResponse);
        } else {
            f.done = f.restore.is_empty();
        }
        if b == f.scan {
            f.signals.started.store(true, Ordering::Release);
        }
    }
    if b == m.offchannel.as_ref().unwrap().scan {
        let f = m.offchannel.as_ref().unwrap();
        let (freq, seq) = (f.frequency, 0xa000 | f.sequence);
        event(m, 2, freq, seq.wrapping_sub(1), 0xa001);
        event(m, 1, freq, seq, 0xa001);
        event(m, 8, freq + 20, seq, 0xa001);
    }
    credit(m, bytes);
    poll(m)
}
pub(super) fn frame() -> Vec<u8> {
    let mut b = vec![0; 30];
    b[0] = 0xd0;
    b[4..10].copy_from_slice(&[2, 0, 0, 0, 0x10, 0xcc]);
    b[10..16].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    b[16..22].fill(255);
    b[24..].copy_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9]);
    b
}
fn expected_frame(m: &RadioModel) -> Vec<u8> {
    let mut frame = frame();
    if m.offchannel
        .as_ref()
        .unwrap()
        .signals
        .multicast
        .load(Ordering::Acquire)
    {
        frame[4..10].fill(255);
    }
    frame
}
pub(super) fn is_htt(m: &RadioModel, b: &[u8]) -> bool {
    m.offchannel
        .as_ref()
        .is_some_and(|f| !f.done && f.signals.started.load(Ordering::Acquire))
        && (b.get(8..10) == Some(&[1, 0x65]) || b.get(8) == Some(&7))
}
pub(super) fn htt_send(m: &mut RadioModel, b: &[u8]) -> Result<(), BmiError> {
    let body = b.get(8..).ok_or(BmiError::BadResponse)?;
    if b[0] != 1
        || b[1] != 0
        || b[5] != m.inner.sequence
        || b[2..4] != (b.len() as u16 - 8).to_le_bytes()
    {
        return Err(BmiError::BadResponse);
    }
    let legacy = m.inner.version < 3;
    let freq = m.inner.config.dialect == 3 && m.inner.version >= 3 && m.inner.minor >= 4;
    let (id, len, address, prefetch_at) = if legacy {
        if body.len() != 56 || body[..4] != [7, 0, 0, 0] || word(body, 16) != 0 {
            return Err(BmiError::BadResponse);
        }
        (
            word(body, 8) as u16,
            word(body, 12) as usize,
            word(body, 4),
            20,
        )
    } else {
        let expected_frequency = if freq {
            [255, 255, 0x3c, 0x14]
        } else {
            [255, 255, 0, 0]
        }; //5180MHz
        if body.len() != 48
            || body[..2] != [1, 0x65]
            || body[2..4] != (0x800u16 | (17 << 6)).to_le_bytes()
            || body[12..16] != expected_frequency
        {
            return Err(BmiError::BadResponse);
        }
        (
            u16::from_le_bytes(body[6..8].try_into().unwrap()),
            usize::from(u16::from_le_bytes(body[4..6].try_into().unwrap())),
            word(body, 8),
            16,
        )
    };
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    let (actual_address, payload) = m
        .inner
        .storage
        .as_ref()
        .ok_or(BmiError::BadResponse)?
        .tx
        .snapshot(id)
        .ok_or(BmiError::BadResponse)?;
    if len != 30
        || address != actual_address as u32
        || body[prefetch_at..prefetch_at + 32] != payload[..32]
        || payload[..30] != expected_frame(m)
    {
        return Err(BmiError::BadResponse);
    }
    let f = m.offchannel.as_mut().unwrap();
    if freq && f.destination.is_some() {
        return Err(BmiError::BadResponse);
    }
    f.tx = Some((u32::from(id), false));
    f.signals.descriptors.fetch_add(1, Ordering::AcqRel);
    m.sent.push(b.to_vec());
    poll(m)
}
pub(super) fn poll(m: &mut RadioModel) -> Result<(), BmiError> {
    let Some(f) = &mut m.offchannel else {
        return Ok(());
    };
    let (freq, seq) = (f.frequency, 0xa000 | f.sequence);
    if f.signals.started.load(Ordering::Acquire)
        && !f.foreign_sent
        && f.signals.foreign.load(Ordering::Acquire)
    {
        f.foreign_sent = true;
        // Wrong scan/request/foreign frequency cannot establish READY.
        event(m, 8, freq, seq.wrapping_sub(1), 0xa001);
        event(m, 1, freq, seq, 0xa001);
        event(m, 8, freq + 20, seq, 0xa001);
        event(m, 8, freq, seq, 0xa001);
    }
    let f = m.offchannel.as_mut().unwrap();
    if f.stopped && !f.terminal_scan_sent && f.signals.stop_receipt.load(Ordering::Acquire) {
        f.terminal_scan_sent = true;
        let home = f.home;
        event(m, 2, freq, seq, 0xa002);
        if let Some(home) = home {
            event(m, 4, home, seq, 0xa001);
        }
        event(m, 2, freq, seq, 0xa001);
    }
    let f = m.offchannel.as_mut().unwrap();
    if let Some((id, reference)) = f.tx {
        if !f.tx_delivered && f.signals.terminal.load(Ordering::Acquire) {
            f.tx_delivered = true;
            if reference {
                let mut body = Vec::new();
                let mut fixed = vec![0; 16];
                patch(&mut fixed, 0, id);
                item(&mut body, 423, &fixed);
                add_event(m, 0x7006, &body);
            } else {
                let id = id as u16;
                let terminal = if m.inner.version < 3 {
                    let mut terminal = vec![0; 20];
                    terminal[0] = if m.inner.config.dialect == 2 {
                        0x13
                    } else {
                        0xe
                    };
                    patch(&mut terminal, 4, u32::from(id));
                    terminal
                } else {
                    vec![7, 0, 1, 0, id as u8, (id >> 8) as u8, 0, 0]
                };
                m.inner
                    .inner
                    .rx
                    .push_back((m.inner.receive_pipe, header(1, &terminal)));
            }
        }
    }
    Ok(())
}
