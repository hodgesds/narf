//! Native API77 interface conversations after ALIVE/unified init. The real
//! configure/scan/MLME/power/RSNA/packet/retirement paths run through TFH/RFH.
use super::super::{firmware_parser_tests, runtime::model, rx_rfh::CompletionFormat};
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::reg::{db::Database, RegFlags, RegRule};
const OWN: [u8; 6] = [2; 6];
const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const PMK: [u8; 32] = [0x55; 32];
const BINDING: [u8; 32] = [0xa5; 32];
const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: AP,
    server_ip: [10, 1, 1, 1],
    lease_ip: [10, 1, 1, 2],
    netmask: [255, 255, 255, 0],
    lease_seconds: 60,
};
fn domain() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    }
}
fn tlv(bytes: &mut Vec<u8>, tag: u32, body: &[u8]) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn image() -> Vec<u8> {
    let mut bytes = firmware_parser_tests::mvm_image();
    bytes[72..76].copy_from_slice(&77u32.to_le_bytes());
    let parsed = super::super::parse_ucode(&bytes).unwrap();
    let mut versions = parsed.api.commands.to_vec();
    versions.extend_from_slice(&[
        2, 12, 1, 4, 0x98, 1, 1, 0, 0x9b, 1, 6, 0, 1, 2, 2, 0, 0x77, 1, 6, 0, 0x1c, 0, 9, 0, 0x1c,
        1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3, 15, 5, 3, 0, 0x17, 1, 3, 0, 2, 5, 1, 0, 0xff, 5, 0,
        1,
    ]);
    tlv(&mut bytes, 48, &versions);
    tlv(&mut bytes, 29, &[0, 0, 0, 0, 0, 0, 0x10, 0x20]);
    bytes
}
fn asset(name: &'static str, bytes: &[u8], signed: bool) -> Result<Asset, &'static str> {
    let (write, read) = narf_firmware::bootstrap_authority();
    crate::firmware_asset::tests::install(&write, name, bytes, signed)
        .map_err(|_| "MVM interface fixture source install")?;
    crate::firmware_asset::load(&read, name, 16 * 1024 * 1024, signed)
        .map_err(|_| "MVM interface fixture source copy")
}
fn power() -> Vec<u8> {
    let mut b = vec![0; 64];
    b[..8].copy_from_slice(b"NIPW\x01\0\x40\0");
    b[8..40].copy_from_slice(&BINDING);
    b[40..46].copy_from_slice(&OWN);
    b[46] = 1;
    b[48..58].copy_from_slice(&[80, 81, 82, 83, 84, 85, 86, 87, 88, 89]);
    b[58..60].copy_from_slice(&128i16.to_le_bytes());
    b[60..62].copy_from_slice(&16i16.to_le_bytes());
    b
}
fn nvm() -> Vec<u8> {
    let mut b = vec![0; 28 + 110 * 4];
    b[12] = 3;
    b[16] = 3;
    b[24] = 1;
    b[28..32].copy_from_slice(&0x10bu32.to_le_bytes());
    b
}
fn envelope(frame: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 48];
    b[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    b[12] = 3;
    // No BA agreement exists in this native fixture. API4 encodes an
    // unaggregated packet with INVALID_BAID0x7f, including initial M1.
    b[16..20].copy_from_slice(&0x7f000000u32.to_le_bytes());
    b[32] = 40;
    b[34] = 1;
    b.extend_from_slice(frame);
    b
}
fn from_ap(ethernet: &[u8], sequence: u16) -> Vec<u8> {
    let mut b = vec![8, 2, 0, 0];
    b.extend_from_slice(&ethernet[..6]);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&ethernet[6..12]);
    b.extend_from_slice(&(sequence << 4).to_le_bytes());
    b.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    b.extend_from_slice(&ethernet[12..]);
    b
}
fn ap(protected: bool) -> Result<FakeAp, &'static str> {
    if protected {
        FakeAp::wpa2(NETWORK, b"net", 1, 7, PMK, [0x22; 32])
    } else {
        FakeAp::open(NETWORK, b"net", 1, 7)
    }
    .map_err(|_| "MVM interface AP config")?
    .with_basic_1mbps()
    .map_err(|_| "MVM interface AP rate")
}
fn ht_ies() -> Vec<u8> {
    let mut ht = [0; 26];
    ht[0] = 0x2c;
    ht[2] = 19;
    ht[3] = 0xff;
    ht[15] = 1;
    let mut op = [0; 22];
    op[0] = 1;
    op[6] = 1;
    let mut out = vec![45, 26];
    out.extend_from_slice(&ht);
    out.extend_from_slice(&[61, 22]);
    out.extend_from_slice(&op);
    out.extend_from_slice(&[
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
        0x62, 0x32, 47, 0,
    ]);
    out
}
struct Actor {
    ht: bool,
    ba: bool,
    rx_ba: [Option<(u8, u16, u16)>; 8],
    retiring_baid: Option<u8>,
    tx_ba_enabled: bool,
    tx_dialog: Option<(Vec<u8>, Vec<u8>)>,
    tx_ba_refuse: bool,
    hold_batch: bool,
    batch: Vec<u16>,
    batch_dma: Vec<(u64, u16)>,
    action_responses: Vec<Vec<u8>>,
    hold_action: bool,
    rx_rate: u32,
    tlc_version: u8,
    stopped: bool,
    firmware: model::Firmware,
    trace: model::TxTrace,
    security: super::super::mvm_boot::SecurityModel,
    protected: bool,
    server: DhcpServer,
    ap_pn: u64,
    data_added: bool,
    m1_sent: bool,
    commands: Vec<(u8, u8, Vec<u8>)>,
    hold_m4: bool,
    hold_close: bool,
    held: Option<(u8, u8, u16, Vec<u8>)>,
    closing: bool,
    scan_clock: Option<(Arc<AtomicU64>, u64)>,
    hold_phy: Option<u8>,
    fail_phy: Option<u8>,
    beacon_ies: Option<Vec<u8>>,
    response_ies: Option<Vec<u8>>,
}
// SAFETY: fixture-only device-side pointers refer to the retained Owner's
// posted coherent buffers. CURRENT retains both endpoints; every device-side
// access is serialized by Actor's IRQ-safe lock and uses RFH release ordering.
// Teardown closes admission/removes CURRENT, then sets stopped and destroys
// the native owner while holding that same lock. A stale endpoint cannot
// inject into retired DMA. No production pointer type gains Send here.
unsafe impl Send for Actor {}
impl Actor {
    fn inject(&mut self, command: u8, group: u8, sequence: u16, body: &[u8]) {
        self.firmware.inject(command, group, sequence, body)
    }
    fn reply(&mut self, command: u8, group: u8, sequence: u16, mut body: Vec<u8>) {
        let stage = self.commands.last().and_then(|(g, c, b)| match (*g, *c) {
            (1, 0x18) if b[17] == 6 => Some(1),
            (3, 9) if b[24] == 8 && b[56] == 3 => Some(2),
            (5, 15) if b[5] == 1 => Some(3),
            (1, 0x18) if b[17] == 8 => Some(4),
            (1, 0x18) if b[17] == 2 => Some(5),
            (1, 0x18) if b[17] == 16 => Some(6),
            _ => None,
        });
        if stage.is_some() && self.fail_phy == stage {
            body = vec![0];
            self.fail_phy = None;
        }
        if stage.is_some() && self.hold_phy == stage {
            self.held = Some((command, group, sequence, body));
            self.hold_phy = None;
            return;
        }
        if self.hold_close && self.closing && command == 0x18 && group == 0 {
            self.held = Some((command, group, sequence, body));
            self.hold_close = false;
        } else {
            self.inject(command, group, sequence, &body);
        }
    }
    fn release(&mut self) {
        self.hold_m4 = false;
        if let Some((c, g, s, b)) = self.held.take() {
            self.inject(c, g, s, &b);
        }
        self.security.release(&mut self.firmware);
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Result<(), &'static str> {
        self.ap_pn += 1;
        let mut packet = if self.protected {
            self.security
                .encrypted_rx_profile(ethernet, self.ap_pn, false, self.ht.then_some(0))?
        } else {
            let mut frame = from_ap(ethernet, self.ap_pn as u16);
            if self.ht {
                frame[0] = 0x88;
                frame.splice(24..24, [0, 0]);
            }
            envelope(&frame)
        };
        if self.ht {
            packet[16..20].copy_from_slice(&0x7f000000u32.to_le_bytes());
            packet[28..32].copy_from_slice(&self.rx_rate.to_le_bytes());
        }
        if let Some((id, sn, window)) = self.rx_ba[0] {
            packet[48 + 22..48 + 24].copy_from_slice(&(sn << 4).to_le_bytes());
            packet[16..20].copy_from_slice(
                &((u32::from(id) << 24) | (u32::from(sn) << 12) | u32::from((sn + 1) & 4095))
                    .to_le_bytes(),
            );
            self.rx_ba[0] = Some((id, (sn + 1) & 4095, window));
        }
        self.inject(0xc1, 0, 0x8000, &packet);
        Ok(())
    }
    fn serve(&mut self) -> Result<bool, &'static str> {
        if self.stopped {
            return Ok(false);
        }
        let mut progress = false;
        for _ in 0..128 {
            let Some(p) = self.trace.take() else { break };
            progress = true;
            self.react(p)?;
        }
        if !self.hold_batch {
            self.finish_batch()?;
        }
        Ok(progress)
    }
    fn finish_batch(&mut self) -> Result<(), &'static str> {
        if self.batch.is_empty() {
            return Ok(());
        }
        if !self.tx_ba_enabled {
            return Err("model aggregated without native TID0 receipt");
        }
        if self.tx_dialog.is_none() {
            // TLC43's firmware manager exchanges this actual dialog with the
            // model AP. Host code never sends ADDBA or invents its SSN.
            let request = vec![3, 0, 71, 2, 8, 0, 0, 0x50, 0x73]; // window32, SSN0x735
            if request[0..3] != [3, 0, 71]
                || request[3..5] != [2, 8]
                || request[7..] != [0x50, 0x73]
            {
                return Err("independent firmware-manager ADDBA geometry");
            }
            let response = vec![
                3,
                1,
                71,
                if self.tx_ba_refuse { 37 } else { 0 },
                0,
                2,
                8,
                0,
                0,
            ];
            if response[2] != request[2] || response[5..7] != request[3..5] {
                return Err("independent AP BA response binding");
            }
            self.tx_dialog = Some((request, response));
        }
        if self.tx_ba_refuse || self.batch.len() == 1 {
            for pointer in core::mem::take(&mut self.batch) {
                self.firmware.tx_complete(24, pointer);
            }
        } else {
            let mut notification = vec![0; 40];
            notification[14..16].copy_from_slice(&(self.batch.len() as u16).to_le_bytes());
            notification[16..18].copy_from_slice(&(self.batch.len() as u16).to_le_bytes());
            notification[28] = 1;
            notification[32] = 24;
            notification[34..36].copy_from_slice(&self.batch.last().unwrap().to_le_bytes());
            self.inject(0xc5, 0, 0x8000, &notification);
            self.batch.clear();
        }
        Ok(())
    }
    fn react(&mut self, p: model::Published) -> Result<(), &'static str> {
        if p.queue == 0 {
            if p.bytes.len() < 8 || p.bytes[7] != 0 {
                return Err("MVM interface native control header");
            }
            let c = p.bytes[0];
            let g = p.bytes[1];
            let s = u16::from_le_bytes([p.bytes[2], p.bytes[3]]);
            let b = &p.bytes[8..];
            self.commands.push((g, c, b.to_vec()));
            if self.ba && g == 5 && c == 2 && b.get(12) == Some(&1) {
                if b.len() != 24 || self.retiring_baid != Some(b[20]) {
                    return Err("DEL_BA fence without exact native removed BAID");
                }
                self.retiring_baid = None;
                let hold = (self.hold_phy == Some(7)).then_some(self.security.events.len());
                self.hold_phy = None;
                self.security.react(p, &mut self.firmware, hold, None)?;
                return Ok(());
            }
            if self.protected
                && (g == 1 && c == 0x17
                    || g == 5 && c == 2
                    || self.data_added && g == 1 && c == 0x18 && b.len() == 48 && b[24] == 16
                    || self.data_added
                        && g == 5
                        && c == 0x17
                        && b.get(4) == Some(&1)
                        && b.get(8) == Some(&0))
            {
                let enable = g == 1 && c == 0x18 && b[20] == 0;
                let marker = self.closing && self.hold_phy == Some(9) && g == 5 && c == 2;
                if marker {
                    self.hold_phy = None;
                }
                let hold = (self.hold_close && self.closing && g == 1 && c == 0x18 || marker)
                    .then_some(self.security.events.len());
                if hold.is_some() {
                    self.hold_close = false;
                }
                self.security.react(p, &mut self.firmware, hold, None)?;
                if enable && !self.m1_sent {
                    self.m1_sent = true;
                    let m1 = self.security.m1.clone();
                    self.inject(0xc1, 0, 0x8000, &envelope(&m1));
                }
                return Ok(());
            }
            let body = match (g, c) {
                (12, 2) => {
                    if b != [0; 4] {
                        return Err("MVM configure NVM body");
                    }
                    let mut nvm = nvm();
                    if self.ht {
                        nvm[8] = 4;
                    }
                    nvm
                }
                (1, 0x98) => {
                    if b != 3u32.to_le_bytes() {
                        return Err("MVM configure chains");
                    }
                    vec![]
                }
                (1, 0x9b) => {
                    if b != [1, 0, 0, 0, 17, 0, 0, 0] {
                        return Err("MVM configure coexistence");
                    }
                    vec![]
                }
                (2, 1) => {
                    if b != [10, 0, 0, 0, 0xe0, 0x2e, 0, 0] {
                        return Err("MVM configure native SoC");
                    }
                    vec![]
                }
                (1, 0x77) => {
                    if b != [0; 4] {
                        return Err("MVM configure awake power");
                    }
                    vec![]
                }
                (1, 0xc) => {
                    if b.len() != 12 || b[4..12] != [3, 0, 0, 0, 3, 0, 0, 0] {
                        return Err("MVM native reduced scan config extent");
                    }
                    vec![]
                }
                (3, 8) => {
                    if b.len() != 52 {
                        return Err("MVM native MAC extent");
                    }
                    vec![]
                }
                (1, 0xd2) => {
                    if b.len() != 60 || b.iter().any(|v| *v != 0) {
                        return Err("MVM native beacon filter extent");
                    }
                    vec![]
                }
                (1, 0xd1) => {
                    if b.len() != 92 {
                        return Err("MVM native SF extent");
                    }
                    vec![]
                }
                (3, 9) => {
                    if b.len() != 208 {
                        return Err("MVM native LINK extent");
                    }
                    vec![]
                }
                (1, 0xa9) => {
                    if b.len() != 40 {
                        return Err("MVM native MAC power extent");
                    }
                    vec![]
                }
                (1, 0xd) => {
                    if b.len() != 1940 {
                        return Err("MVM native scan request extent");
                    }
                    let mut beacon = self.security.ap.beacon();
                    if self.ht {
                        beacon.extend_from_slice(self.beacon_ies.as_ref().unwrap_or(&ht_ies()));
                    }
                    self.inject(0xc1, 0, 0x8000, &envelope(&beacon));
                    if let Some((clock, elapsed)) = self.scan_clock.take() {
                        clock.fetch_add(elapsed, Ordering::AcqRel);
                    }
                    let mut done = [0; 16];
                    done[6] = 1;
                    self.inject(0xf, 0, 0x8000, &done);
                    vec![]
                }
                (1, 8) => {
                    if b.len() != 36 || b[17] != 1 || !matches!(b[4], 1 | 3) {
                        return Err("MVM native PHY identity/extent");
                    }
                    vec![]
                }
                (1, 0x18) => {
                    if b.len() != 48 || b[16] != 0 {
                        return Err("MVM native station0 identity/extent");
                    }
                    if self.ba && b[17] == 8 {
                        let tid = usize::from(b[28]);
                        if tid > 7 || self.rx_ba[tid].is_some() || b[0] != 1 {
                            return Err("native RX BA duplicate/foreign reservation");
                        }
                        let ssn = u16::from_le_bytes([b[30], b[31]]);
                        let window = u16::from_le_bytes([b[44], b[45]]);
                        let mut expected = [0; 48];
                        expected[0] = 1;
                        expected[17] = 8;
                        expected[28] = tid as u8;
                        expected[30..32].copy_from_slice(&ssn.to_le_bytes());
                        expected[44..46].copy_from_slice(&window.to_le_bytes());
                        if b != expected || ssn >= 4096 || !(1..=32).contains(&window) {
                            return Err("native ADD_STA48 BA field/mask");
                        }
                        let id = tid as u8 + 1;
                        self.rx_ba[tid] = Some((id, ssn, window));
                        vec![1, id | 0x80, 0, 0]
                    } else if self.ba && b[17] == 16 {
                        let tid = usize::from(b[29]);
                        let mut expected = [0; 48];
                        expected[0] = 1;
                        expected[17] = 16;
                        expected[29] = tid as u8;
                        if tid > 7 || b != expected || self.rx_ba[tid].is_none() {
                            return Err("native RX BA remove ownership");
                        }
                        self.retiring_baid = self.rx_ba[tid].take().map(|s| s.0);
                        vec![1, 0, 0, 0]
                    } else if self.ba && b[17] == 2 {
                        let mut expected = [0; 48];
                        expected[0] = 1;
                        expected[17] = 2;
                        expected[2..4].copy_from_slice(if b[2] == 254 {
                            &[254, 255]
                        } else {
                            &[255, 255]
                        });
                        if b != expected {
                            return Err("native TX BA permission changed other peer fields");
                        }
                        self.tx_ba_enabled = b[2] == 254;
                        vec![1, 0, 0, 0]
                    } else {
                        vec![1, 0, 0, 0]
                    }
                }
                (5, 2) if self.ba && !self.protected => {
                    if b.len() != 20 || b[..16] != [0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 0]
                    {
                        return Err("Open BA RX marker command");
                    }
                    let mut marker = vec![8, 0, 0, 0, 0, 0, 1, 0];
                    marker.extend_from_slice(&b[16..20]);
                    self.inject(0xff, 5, 0x8000, &marker);
                    vec![]
                }
                (5, 0x17) => {
                    if b.len() != 36 || b[4..8] != [1, 0, 0, 0] || !matches!(b[8], 0 | 15) {
                        return Err("MVM native queue identity/extent");
                    }
                    let id = if b[8] == 15 { 23u16 } else { 24u16 };
                    if b[0] == 0 {
                        if b[8] == 0 {
                            self.data_added = true;
                        }
                        let mut r = vec![0; 8];
                        r[..2].copy_from_slice(&id.to_le_bytes());
                        r[4..6].copy_from_slice(
                            &(if id == 23 { 0x45u16 } else { 0x91u16 }).to_le_bytes(),
                        );
                        r
                    } else if b[0] == 1 {
                        let mut r = vec![0; 8];
                        r[..2].copy_from_slice(&id.to_le_bytes());
                        r
                    } else {
                        return Err("MVM queue action");
                    }
                }
                (1, 0x9f) => {
                    if b.len() != 44 {
                        return Err("MVM native v5 power extent");
                    }
                    if b[0] == 2 {
                        for (i, value) in (80u16..90).enumerate() {
                            if b[16 + i * 2..18 + i * 2] != value.to_le_bytes() {
                                return Err("MVM real signed SAR limit differs");
                            }
                        }
                    } else if b[0] != 0 || b[8..10] != 64i16.to_le_bytes() {
                        return Err("MVM real link power ceiling differs");
                    }
                    vec![]
                }
                (5, 15) => {
                    if b.len() != if self.tlc_version == 2 { 24 } else { 28 }
                        || b[6] != 1
                        || b[10..12] != [1, 0]
                    {
                        return Err("MVM native response-bound TLC profile");
                    }
                    vec![]
                }
                (1, 0x19) => {
                    if b != [0; 4] {
                        return Err("MVM native peer retirement identity");
                    }
                    vec![]
                }
                _ => return Err("unexpected MVM interface control publication"),
            };
            self.reply(c, if g == 1 && c == 0x18 { 0 } else { g }, s, body);
            return Ok(());
        }
        if !matches!(p.queue, 23 | 24) || p.bytes.len() < 48 {
            return Err("MVM native interface packet queue/header");
        }
        let frame = &p.bytes[24..];
        if p.queue == 23 && matches!(frame[0], 0 | 0xb0) {
            let replies = self
                .security
                .ap
                .receive(frame)
                .map_err(|_| "independent AP rejected actual native MLME")?;
            self.firmware.tx_complete(23, p.pointer);
            for mut reply in replies {
                if reply.first() == Some(&8) {
                    self.security.m1 = reply;
                } else {
                    if self.ht && reply.first() == Some(&0x10) {
                        reply.extend_from_slice(self.response_ies.as_ref().unwrap_or(&ht_ies()));
                    }
                    self.inject(0xc1, 0, 0x8000, &envelope(&reply));
                }
            }
            return Ok(());
        }
        if self.ht && p.queue == 23 && frame[0] == 0xd0 {
            if self.ba {
                let body = frame.get(24..).ok_or("BA management frame truncated")?;
                if body.len() != 9 && body.len() != 6 {
                    return Err("BA response extent");
                }
                self.action_responses.push(body.to_vec());
            } else if frame.get(24..) != Some(&[3, 1, 9, 37, 0, 2, 0, 0, 0]) {
                return Err("native ADDBA decline bytes");
            }
            if self.hold_action {
                self.hold_action = false;
                let mut receipt = vec![0; 48];
                receipt[0] = 1;
                receipt[36] = 23;
                receipt[40] = 1;
                receipt[44..48].copy_from_slice(&u32::from(p.pointer).to_le_bytes());
                self.held = Some((0x1c, 0, 0x8000, receipt));
            } else {
                self.firmware.tx_complete(23, p.pointer);
            }
            return Ok(());
        }
        if self.protected {
            let m4 = p.queue == 23
                && frame
                    .get(36..)
                    .and_then(|b| narf_wireless::eapol::KeyFrame::decode(b, 16))
                    .is_some_and(|k| k.key_information == 0x30a);
            let held = (m4 && self.hold_m4).then_some(self.security.events.len());
            let before = self.security.data.len();
            if self.ba && p.queue == 24 && self.tx_ba_enabled {
                self.batch_dma.push((p.dma_base, p.pointer));
                self.batch.push(p.pointer);
                self.security.aggregate_packet(p, &mut self.firmware)?;
            } else {
                self.security.react(p, &mut self.firmware, held, None)?;
            }
            if self.security.data.len() > before {
                let frame = self.security.data.last().unwrap().clone();
                if let Some(reply) = self.server.receive(&frame) {
                    self.downlink(&reply)?;
                }
            }
        } else {
            let mut frame = frame.to_vec();
            let header = if self.ht { 26 } else { 24 };
            if self.ht {
                if frame.get(26..28) != Some(&[0, 0]) || frame.get(24..26) != Some(&[0, 0]) {
                    return Err("Open QoS padding/TID");
                }
                frame.drain(26..28);
            }
            if p.queue != 24
                || frame[0..2] != [if self.ht { 0x88 } else { 8 }, 1]
                || frame[4..10] != AP
                || frame[10..16] != OWN
                || frame.get(header..header + 6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0])
            {
                return Err("MVM actual Open Ethernet header");
            }
            let mut ethernet = frame[16..22].to_vec();
            ethernet.extend_from_slice(&OWN);
            ethernet.extend_from_slice(&frame[header + 6..]);
            self.security.data.push(ethernet.clone());
            if self.ba && self.tx_ba_enabled {
                self.batch_dma.push((p.dma_base, p.pointer));
                self.batch.push(p.pointer);
            } else {
                self.firmware.tx_complete(24, p.pointer);
            }
            if let Some(reply) = self.server.receive(&ethernet) {
                self.downlink(&reply)?;
            }
        }
        Ok(())
    }
}
struct Harness {
    device: Arc<Device>,
    actor: Arc<IrqSafeSpinLock<Actor>>,
    db: Arc<Database>,
    firmware: Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    power: Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    available: Arc<AtomicBool>,
    clock: Arc<AtomicU64>,
}
type Endpoint = (Arc<Device>, Arc<IrqSafeSpinLock<Actor>>);
static CURRENT: IrqSafeSpinLock<Option<Endpoint>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = CURRENT.lock().as_ref().map(|p| p.0.clone()).ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let current = CURRENT.lock().clone();
    if let Some((device, actor)) = current {
        let before = actor.lock().serve().unwrap_or(false);
        let data = device.drain();
        let after = actor.lock().serve().unwrap_or(false);
        before || data || after
    } else {
        false
    }
}
fn once<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let value = future.poll(&mut Context::from_waker(Waker::noop()));
    if value.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    value
}
fn run<T>(future: impl Future<Output = T>) -> Result<T, &'static str> {
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        let result = once(future.as_mut());
        if let Some((_, actor)) = CURRENT.lock().clone() {
            actor.lock().serve()?;
        }
        if let Poll::Ready(value) = result {
            return Ok(value);
        }
    }
    Err("MVM native interface fixture progress budget")
}
impl Harness {
    fn new(protected: bool) -> Result<Self, &'static str> {
        Self::profile(protected, false)
    }
    fn profile(protected: bool, ht: bool) -> Result<Self, &'static str> {
        Self::qualified_profile(protected, ht, if ht { 2 } else { 1 })
    }
    fn qualified_profile(protected: bool, ht: bool, emission: u8) -> Result<Self, &'static str> {
        Self::version_profile(protected, ht, emission, 3)
    }
    fn version_profile(
        protected: bool,
        ht: bool,
        emission: u8,
        tlc_version: u8,
    ) -> Result<Self, &'static str> {
        Self::build_profile(protected, ht, emission, tlc_version, false)
    }
    fn build_profile(
        protected: bool,
        ht: bool,
        emission: u8,
        tlc_version: u8,
        ba: bool,
    ) -> Result<Self, &'static str> {
        Self::build_profile_caps(protected, ht, emission, tlc_version, ba, false)
    }
    fn build_profile_caps(
        protected: bool,
        ht: bool,
        emission: u8,
        tlc_version: u8,
        ba: bool,
        ml_baid: bool,
    ) -> Result<Self, &'static str> {
        if CURRENT.lock().is_some() {
            return Err("MVM interface fixture already owned");
        }
        let mut image = image();
        let parsed = super::super::parse_ucode(&image).unwrap();
        let mut versions = parsed.api.commands.to_vec();
        if ba {
            versions.extend_from_slice(&[0xc2, 0, 0, 1, 0xc3, 0, 0, 1, 0xc5, 0, 0, 7]);
        }
        for entry in versions.chunks_exact_mut(4) {
            if entry[0] == 15 && entry[1] == 5 {
                entry[2] = tlc_version;
            }
        }
        tlv(&mut image, 48, &versions);
        if ht {
            tlv(
                &mut image,
                30,
                &[1, 0, 0, 0, 0, 8, 0, if ml_baid { 128 } else { 0 }],
            );
        }
        let executable = asset("narf-test/mvm-interface/executable", &image, true)?;
        let parsed = super::super::parse_ucode(&executable.bytes).unwrap();
        let (mut hardware, firmware, trace) = model::station_model_for_format(CompletionFormat::Qu);
        model::versions(&mut hardware, parsed.api.commands);
        let mut owner = Owner::model_after_alive(hardware, &executable.bytes);
        let mut security = super::super::mvm_boot::SecurityModel::new(3)?;
        security.ap = ap(protected)?;
        let mut actor = Actor {
            ht,
            ba,
            rx_ba: [None; 8],
            retiring_baid: None,
            tx_ba_enabled: false,
            tx_dialog: None,
            tx_ba_refuse: false,
            hold_batch: false,
            batch: Vec::new(),
            batch_dma: Vec::new(),
            action_responses: Vec::new(),
            hold_action: false,
            rx_rate: if ht { 0x00100207 } else { 0 },
            tlc_version,
            stopped: false,
            firmware,
            trace,
            security,
            protected,
            server: DhcpServer::new(NETWORK),
            ap_pn: 1,
            data_added: false,
            m1_sent: false,
            commands: Vec::new(),
            hold_m4: false,
            hold_close: false,
            held: None,
            closing: false,
            scan_clock: None,
            hold_phy: None,
            fail_phy: None,
            beacon_ies: None,
            response_ies: None,
        };
        {
            let mut configure = Box::pin(owner.model_configure());
            let mut complete = false;
            for _ in 0..64 {
                let result = once(configure.as_mut());
                actor.serve()?;
                if let Poll::Ready(result) = result {
                    result?;
                    complete = true;
                    break;
                }
            }
            if !complete {
                return Err("MVM actual NVM/default configure did not complete");
            }
        }
        let source = owner.station_source(executable.cap, true);
        let mut limits = power();
        limits[46] = emission;
        let signed = asset("narf-test/mvm-interface/power", &limits, true)?;
        let cap = signed.cap;
        let digest = signed.digest;
        let signer = signed.signer;
        let bytes = signed.bytes;
        let db = Arc::new(Database::new());
        db.install(domain());
        let policy = db.clone();
        let nonce = Arc::new(AtomicU64::new(0));
        let available = Arc::new(AtomicBool::new(true));
        let staged = available.clone();
        let clock = Arc::new(AtomicU64::new(narf_time::now_cycles()));
        let observation_clock = clock.clone();
        let environment = Environment {
            observation_clock: Arc::new(move || observation_clock.load(Ordering::Acquire)),
            policy: Arc::new(move || {
                policy
                    .snapshot()
                    .map(|d| d.as_ref().clone())
                    .ok_or("MVM fixture current policy cleared")
            }),
            nonce: Arc::new(move || {
                Ok([0x11
                    + u8::try_from(nonce.fetch_add(1, Ordering::Relaxed))
                        .map_err(|_| "fixture nonce exhausted")?; 32])
            }),
            power: Arc::new(move |_| {
                if !staged.load(Ordering::Acquire) {
                    return Err("fixture measured power asset not staged");
                }
                Ok((
                    Asset {
                        bytes: bytes.clone(),
                        cap,
                        signer,
                        digest,
                    },
                    BINDING,
                ))
            }),
        };
        let device = Device::configured(owner, source, environment)?;
        let name = narf_net::iface::reserve_name("iwlmvm%d");
        *device.test_name.lock() = Some(name);
        {
            let mut state = device.state.try_lock().unwrap();
            let (rxp, rxc) = narf_ipc::channel::<Frame, RX_RING_N>();
            let (txp, txc) = narf_ipc::channel::<Frame, TX_RING_N>();
            state.receive = Some(rxp);
            state.transmit = Some(txc);
            *device.rx.lock() = Some(rxc);
            *device.tx.lock() = Some(txp);
        }
        device.publication.store(true, Ordering::Release);
        let actor = Arc::new(IrqSafeSpinLock::new(actor));
        *CURRENT.lock() = Some((device.clone(), actor.clone()));
        narf_net::iface::register(name, OWN, send);
        narf_net::iface::set_link_state(name, true);
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device,
            actor,
            db,
            firmware: executable.cap,
            power: cap,
            available,
            clock,
        })
    }
    fn scan(&self) -> Result<(), &'static str> {
        let results = run(self.device.scan(ScanRequest {
            ssids: vec![],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: vec![],
        }))?
        .map_err(|_| "MVM native public passive scan failed")?;
        if results.len() != 1 || results[0].bssid != AP {
            return Err("MVM actual scan observation not retained");
        }
        Ok(())
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: b"net".to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.actor.lock().protected {
                narf_wireless::SecurityConfig::Wpa2 { psk: PMK }
            } else {
                narf_wireless::SecurityConfig::Open
            },
            ie: vec![],
        }
    }
    fn join(&self) -> Result<(), &'static str> {
        self.scan()?;
        run(self.device.associate(self.request()))?
            .map_err(|_| "MVM native public association failed")?;
        if !self.device.link_up() || self.device.connected_bssid() != Some(AP) {
            return Err("MVM interface carrier not actual completed port");
        }
        Ok(())
    }
    fn pump(&self) -> Result<(), &'static str> {
        for _ in 0..128 {
            self.actor.lock().serve()?;
            self.device.drain();
            self.actor.lock().serve()?;
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
        }
        Ok(())
    }
    fn retained(&self) -> (usize, usize, usize) {
        self.device
            .state
            .try_lock()
            .unwrap()
            .owner
            .as_ref()
            .unwrap()
            .model_retained()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.device.down(true);
        CURRENT.lock().take();
        narf_net::iface::unregister(self.device.name());
        let mut actor = self.actor.lock();
        actor.stopped = true;
        self.device.control.try_lock().unwrap().take();
        if let Some(owner) = self.device.state.try_lock().unwrap().owner.take() {
            // SAFETY: private RAM device only; CURRENT is removed and Actor's
            // lock is held with stopped=true, so no producer can touch DMA.
            // The retained Work was dropped before destroying its owner.
            unsafe { owner.model_destroy() };
        }
    }
}
fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    if super::super::OWNED.lock().is_some() {
        return TestResult::Skip("physical Intel PCI owner exists");
    }
    if CURRENT.lock().is_some() {
        return TestResult::Skip("MVM native fixture already owns endpoint");
    }
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn conversation(protected: bool) -> Result<(), &'static str> {
    conversation_profile(protected, false)
}
fn conversation_profile(protected: bool, ht: bool) -> Result<(), &'static str> {
    let h = Harness::profile(protected, ht)?;
    h.join()?;
    let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
        .map_err(|_| "MVM actual kernel DORA failed")?;
    if !NETWORK.matches_lease(&lease) {
        return Err("MVM native DORA leased wrong address");
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"MVM native uplink",
    );
    narf_net::iface::send_on(h.device.name(), &uplink)
        .map_err(|_| "MVM public Ethernet enqueue")?;
    h.pump()?;
    if !h.actor.lock().security.data.contains(&uplink) {
        return Err("MVM actual native TX bytes differ");
    }
    let downlink = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        b"MVM native downlink",
    );
    h.actor.lock().downlink(&downlink)?;
    h.pump()?;
    let mut seen = false;
    {
        let mut rx = h.device.rx.lock();
        while let Ok(Some(frame)) = rx.as_mut().unwrap().try_recv() {
            seen |= frame.payload() == downlink;
        }
    }
    if !seen {
        return Err("MVM actual native Ethernet absent from RX IPC");
    }
    h.actor.lock().closing = true;
    run(h.device.disassociate())?.map_err(|_| "MVM actual ordered station close")?;
    if h.device.link_up()
        || h.retained() != (0, 0, 0)
        || h.device
            .state
            .try_lock()
            .unwrap()
            .owner
            .as_ref()
            .unwrap()
            .phase()
            != Phase::Configured
    {
        return Err("MVM close did not retire exact queue/peer/PHY receipts");
    }
    if narf_net::iface::send_on(h.device.name(), &uplink).is_ok() {
        return Err("MVM closed interface admitted Ethernet");
    }
    h.scan()?;
    Ok(())
}
fn smoke_mvm_interface_native_open_scan_join_dhcp_ip_and_retire() -> TestResult {
    check(|| conversation(false))
}
fn smoke_mvm_interface_native_wpa2_m4_keys_dhcp_ip_and_retire() -> TestResult {
    check(|| conversation(true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_native_open_scan_join_dhcp_ip_and_retire
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_native_wpa2_m4_keys_dhcp_ip_and_retire
);

fn held_join(h: &Harness) -> Result<(), &'static str> {
    h.scan()?;
    h.actor.lock().hold_m4 = true;
    {
        let mut join = Box::pin(h.device.associate(h.request()));
        let mut held = false;
        for _ in 0..512 {
            if once(join.as_mut()).is_ready() {
                return Err("MVM join skipped held native M4 receipt");
            }
            h.actor.lock().serve()?;
            if h.actor.lock().security.holding() {
                held = true;
                break;
            }
        }
        if !held {
            return Err("MVM native M4 hold not reached");
        }
    }
    if h.device.link_up()
        || h.device.control.try_lock().unwrap().is_none()
        || h.device.state.try_lock().is_some()
    {
        return Err("cancelled MVM waiter lost retained native future/state or opened port");
    }
    Ok(())
}
fn smoke_mvm_interface_cancelled_m4_waiter_synchronous_drain_finishes_same_owner() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        held_join(&h)?;
        h.actor.lock().release();
        h.pump()?;
        if !h.device.link_up() || h.retained() != (0, 2, 0) {
            return Err("retained M4/native-key owner did not complete through sync drain");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_cancelled_m4_waiter_synchronous_drain_finishes_same_owner
);
fn smoke_mvm_interface_current_executable_power_policy_fence_late_m4() -> TestResult {
    check(|| {
        for fault in 0..3 {
            let h = Harness::new(true)?;
            held_join(&h)?;
            match fault {
                0 => h.firmware.revoke(),
                1 => h.power.revoke(),
                _ => h.db.clear(),
            };
            h.actor.lock().release();
            h.pump()?;
            if h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 != 2
            {
                return Err("MVM late M4 revived denied source/policy or dropped DMA");
            }
            h.db.install(domain());
            h.pump()?;
            if h.device.link_up() {
                return Err("MVM reinstall revived terminal native owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_current_executable_power_policy_fence_late_m4
);
fn smoke_mvm_interface_cancelled_close_retains_and_finishes_native_keys_queues_phy() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        h.join()?;
        {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.hold_close = true;
        }
        {
            let mut close = Box::pin(h.device.disassociate());
            if !once(close.as_mut()).is_pending() {
                return Err("MVM close skipped native disable wait");
            }
            h.actor.lock().serve()?;
        }
        if h.device.link_up()
            || !h.device.stopping.load(Ordering::Acquire)
            || h.device.control.try_lock().unwrap().is_none()
        {
            return Err("cancelled MVM close discarded cleanup intent");
        }
        h.actor.lock().release();
        h.pump()?;
        if h.device.stopping.load(Ordering::Acquire) || h.retained() != (0, 0, 0) {
            return Err("MVM dropped close waiter lost ordered native retirement");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_cancelled_close_retains_and_finishes_native_keys_queues_phy
);

fn smoke_mvm_interface_native_rekey_worker_real_key_epoch_and_encrypted_data() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        h.join()?;
        {
            let mut actor = h.actor.lock();
            let Actor {
                security, firmware, ..
            } = &mut *actor;
            security.challenge(firmware, None, 3, [0x88; 16], 20)?;
        }
        h.pump()?;
        if !h.device.link_up() {
            return Err("MVM native group rekey did not republish actual port");
        }
        {
            let mut actor = h.actor.lock();
            let Actor {
                security, firmware, ..
            } = &mut *actor;
            security.challenge(firmware, Some([0x44; 32]), 4, [0x88; 16], 20)?;
        }
        h.pump()?;
        let ethernet = udp_ipv4(
            AP,
            OWN,
            NETWORK.lease_ip,
            NETWORK.server_ip,
            49152,
            7,
            b"MVM after native pairwise rekey",
        );
        h.device
            .enqueue(&ethernet, narf_net::TxMeta::default())
            .map_err(|_| "MVM rekeyed native enqueue")?;
        h.pump()?;
        if !h.device.link_up()
            || !h.actor.lock().security.data.contains(&ethernet)
            || h.retained() != (0, 2, 0)
        {
            return Err("MVM worker rekey changed owner/DMA or failed actual new-key TX");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_native_rekey_worker_real_key_epoch_and_encrypted_data
);

fn smoke_mvm_interface_current_grants_deny_ipc_and_queued_rx_permanently() -> TestResult {
    check(|| {
        for fault in 0..3 {
            for outgoing in [false, true] {
                let h = Harness::new(true)?;
                h.join()?;
                let ethernet = if outgoing {
                    udp_ipv4(
                        AP,
                        OWN,
                        NETWORK.lease_ip,
                        NETWORK.server_ip,
                        49152,
                        7,
                        b"denied native TX",
                    )
                } else {
                    udp_ipv4(
                        OWN,
                        AP,
                        NETWORK.server_ip,
                        NETWORK.lease_ip,
                        7,
                        49152,
                        b"denied native RX",
                    )
                };
                if !outgoing {
                    h.actor.lock().downlink(&ethernet)?;
                }
                match fault {
                    0 => h.firmware.revoke(),
                    1 => h.power.revoke(),
                    _ => h.db.clear(),
                };
                if outgoing
                    && h.device
                        .enqueue(&ethernet, narf_net::TxMeta::default())
                        .is_ok()
                {
                    return Err("MVM revoked source/policy enqueued native IPC frame");
                }
                h.pump()?;
                h.db.install(domain());
                h.pump()?;
                if h.device.link_up()
                    || !h.device.terminal.load(Ordering::Acquire)
                    || !h.actor.lock().security.data.is_empty()
                    || h.device
                        .rx
                        .lock()
                        .as_mut()
                        .unwrap()
                        .try_recv()
                        .ok()
                        .flatten()
                        .is_some()
                    || h.retained().1 != 2
                {
                    return Err(
                        "MVM queued publication escaped current grant or reopened after reinstall",
                    );
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_current_grants_deny_ipc_and_queued_rx_permanently
);

fn smoke_mvm_interface_bound_beacon_liveness_and_native_ap_close_are_terminal() -> TestResult {
    check(|| {
        for close in [false, true] {
            let h = Harness::new(true)?;
            h.join()?;
            h.device
                .state
                .try_lock()
                .unwrap()
                .owner
                .as_mut()
                .unwrap()
                .model_expire_peer();
            {
                let mut actor = h.actor.lock();
                let beacon = actor.security.ap.beacon();
                actor.inject(0xc1, 0, 0x8000, &envelope(&beacon));
            }
            h.device.drain();
            if !h.device.link_up() {
                return Err("MVM current native beacon did not refresh liveness");
            }
            if close {
                let mut frame = vec![0xc0, 0, 0, 0];
                frame.extend_from_slice(&OWN);
                frame.extend_from_slice(&AP);
                frame.extend_from_slice(&AP);
                frame.extend_from_slice(&[0, 0, 3, 0]);
                h.actor.lock().inject(0xc1, 0, 0x8000, &envelope(&frame));
            } else {
                h.device
                    .state
                    .try_lock()
                    .unwrap()
                    .owner
                    .as_mut()
                    .unwrap()
                    .model_expire_peer();
            }
            h.pump()?;
            if h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 != 2
            {
                return Err("MVM native AP close/liveness loss released DMA or left carrier");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_bound_beacon_liveness_and_native_ap_close_are_terminal
);

fn smoke_mvm_interface_caller_shapes_busy_and_missing_power_are_pre_io() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        h.scan()?;
        let before = h.actor.lock().commands.len();
        h.available.store(false, Ordering::Release);
        if run(h.device.associate(h.request()))?.is_ok()
            || h.device.terminal.load(Ordering::Acquire)
            || h.actor.lock().commands.len() != before
        {
            return Err("MVM absent measured input consumed native lifecycle");
        }
        h.available.store(true, Ordering::Release);
        let mut request = h.request();
        request.ie = vec![221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];
        if run(h.device.associate(request))?.is_ok() || h.actor.lock().commands.len() != before {
            return Err("MVM caller WMM was ignored or emitted native commands");
        }
        run(h.device.associate(h.request()))?
            .map_err(|_| "MVM same owner retry after staged power")?;
        let before = h.actor.lock().commands.len();
        let scan = ScanRequest {
            ssids: vec![],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: vec![],
        };
        if !matches!(run(h.device.scan(scan))?, Err(WirelessError::Busy))
            || !h.device.link_up()
            || h.actor.lock().commands.len() != before
        {
            return Err("MVM connected scan destroyed active owner instead of Busy");
        }
        let mut eapol = vec![0; 18];
        eapol[6..12].copy_from_slice(&OWN);
        eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
        if h.device
            .enqueue(&eapol, narf_net::TxMeta::default())
            .is_ok()
        {
            return Err("MVM ordinary caller injected EAPOL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_caller_shapes_busy_and_missing_power_are_pre_io
);

fn smoke_mvm_interface_native_scan_start_bounds_observation_age() -> TestResult {
    check(|| {
        let h = Harness::new(false)?;
        let start = h.clock.load(Ordering::Acquire);
        // The early beacon precedes15s of scan work; only the host observation
        // clock advances, while genuine RFH/TFH receipts still complete scan.
        h.actor.lock().scan_clock = Some((
            h.clock.clone(),
            narf_time::wall::ns_to_cycles(15_000_000_000),
        ));
        h.scan()?;
        if h.device.state.try_lock().unwrap().scan_time != Some(start) {
            return Err("MVM native scan completion refreshed its early beacon timestamp");
        }
        let before = h.actor.lock().commands.len();
        if run(h.device.associate(h.request()))?.is_ok()
            || h.actor.lock().commands.len() != before
            || h.device.terminal.load(Ordering::Acquire)
        {
            return Err("MVM long scan admitted stale observation or consumed native ownership");
        }
        h.scan()?;
        h.clock.fetch_add(
            narf_time::wall::ns_to_cycles(10_000_000_000) + 1,
            Ordering::AcqRel,
        );
        let before = h.actor.lock().commands.len();
        if run(h.device.associate(h.request()))?.is_ok() || h.actor.lock().commands.len() != before
        {
            return Err("MVM observation beyond ten-second boundary emitted native commands");
        }
        h.scan()?;
        h.clock.fetch_add(
            narf_time::wall::ns_to_cycles(10_000_000_000),
            Ordering::AcqRel,
        );
        run(h.device.associate(h.request()))?
            .map_err(|_| "MVM exact ten-second observation boundary rejected")?;
        if !h.device.link_up() {
            return Err("MVM fresh scan retry did not finish native station admission");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_native_scan_start_bounds_observation_age
);

fn smoke_mvm_interface_one_shot_publication_requires_actual_network_capability() -> TestResult {
    check(|| {
        if ACTIVE.lock().is_some() {
            return Err("unexpected live native MVM publisher");
        }
        let h = Harness::new(false)?;
        // The private harness endpoint is removed before exercising the same
        // configured owner's real one-shot production registration entry.
        narf_net::iface::unregister(h.device.name());
        h.device.publication.store(false, Ordering::Release);
        let cap = Cap::<narf_net::NetIface, Grant>::bootstrap();
        cap.revoke();
        if h.device.publish(&cap, false).is_ok()
            || ACTIVE.lock().is_some()
            || narf_net::iface::lookup(h.device.name()).is_some()
        {
            return Err("MVM revoked network cap published endpoints/carrier");
        }
        let fresh = Cap::<narf_net::NetIface, Grant>::bootstrap();
        if h.device.publish(&fresh, false).is_ok()
            || ACTIVE.lock().is_some()
            || h.retained() != (0, 0, 0)
        {
            return Err("MVM failed one-shot publication replaced live ownership");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_one_shot_publication_requires_actual_network_capability
);

fn smoke_mvm_interface_retired_publication_token_cannot_follow_new_station() -> TestResult {
    check(|| {
        let h = Harness::new(true)?;
        h.join()?;
        let ethernet = udp_ipv4(
            OWN,
            AP,
            NETWORK.server_ip,
            NETWORK.lease_ip,
            7,
            49152,
            b"retired RX",
        );
        h.actor.lock().downlink(&ethernet)?;
        let output = h.device.step(None);
        if output.len() != 1 || output[0].0 != ethernet {
            return Err("MVM old native encrypted RX was not captured before close");
        }
        let old = h
            .device
            .fence
            .lock()
            .clone()
            .ok_or("MVM completed publication token absent")?;
        h.actor.lock().closing = true;
        run(h.device.disassociate())?.map_err(|_| "MVM old station retirement")?;
        if h.device
            .rx
            .lock()
            .as_mut()
            .unwrap()
            .try_recv()
            .ok()
            .flatten()
            .is_some()
        {
            return Err("MVM retired station left an Ethernet packet in RX IPC");
        }
        {
            let mut actor = h.actor.lock();
            actor.protected = false;
            actor.security.ap = ap(false)?;
            actor.closing = false;
            actor.data_added = false;
            actor.m1_sent = false;
        }
        h.join()?;
        h.device.dispatch(output);
        if !h.device.link_up()
            || old.invoke(&domain(), || Ok(())).is_ok()
            || h.device.terminal.load(Ordering::Acquire)
            || h.retained() != (0, 2, 0)
        {
            return Err("MVM retired publication token followed new current power/PCI station");
        }
        let current = h
            .device
            .fence
            .lock()
            .clone()
            .ok_or("MVM successor publication absent")?;
        current.invoke(&domain(), || Ok(()))?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/interface",
    smoke_mvm_interface_retired_publication_token_cannot_follow_new_station
);
#[path = "mvm_ba_tests.rs"]
mod ba_tests;
#[path = "mvm_ht_tests.rs"]
mod ht_tests;
#[path = "mvm_reconnect_tests.rs"]
mod reconnect_tests;
