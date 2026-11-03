// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822CE WoW source-sequence fixtures against a register model. Expected
//! values derive from Linux 7.3-rc4 `rtw88/wow.c`, `fw.c`, `fw.h`, `reg.h`.
use super::super::firmware_transport::preflight_image;
use super::super::security_cam::{
    CMD_POLLING, CMD_WRITE_ENABLE, CR_HIGH, ENGINE_EN, SEC_CMD, SEC_CONFIG, SEC_WRITE,
};
use super::*;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::station_security::SuspendKeys;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Download(usize),
    H2c([u8; 8]),
    Page(usize),
    HciStop,
    HciRestart,
    Write8(u16, u8),
    Write32(u16, u32),
}
struct Model {
    mem: Vec<u8>,
    events: Vec<Event>,
    /// Wake reason the WoW firmware leaves set (never clears when true).
    stuck_reason: bool,
    fail_download: Option<usize>,
    downloads: usize,
    /// Security CAM words (`entry << 3 | word`).
    sec_cam: [u32; 256],
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            mem: vec![0; 0x10000],
            events: Vec::new(),
            stuck_reason: false,
            fail_download: None,
            downloads: 0,
            sec_cam: [0; 256],
        };
        m.mem[REG_TXPAUSE as usize] = 0x0f;
        m.mem[REG_SYS_FUNC_EN as usize] = 0xe3;
        m.set32(REG_BCNQ_INFO, BIT_MGQ_CPU_EMPTY);
        m
    }
    fn get32(&self, reg: u16) -> u32 {
        let r = reg as usize;
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set32(&mut self, reg: u16, v: u32) {
        let r = reg as usize;
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn h2c(&self) -> Vec<[u8; 8]> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::H2c(c) => Some(*c),
                _ => None,
            })
            .collect()
    }
    fn cam_words(&self) -> Vec<(u8, u32)> {
        let mut out = Vec::new();
        let mut data = 0;
        for e in &self.events {
            match *e {
                Event::Write32(REG_WKFMCAM_RWD, v) => data = v,
                Event::Write32(REG_WKFMCAM_CMD, v) if v & BIT_WKFCAM_WE != 0 => {
                    out.push(((v >> 8) as u8, data))
                }
                _ => {}
            }
        }
        out
    }
}
#[async_trait::async_trait]
impl Io for Model {
    fn read8(&mut self, reg: u16) -> Result<u8, NativeError> {
        Ok(self.mem[reg as usize])
    }
    fn read32(&mut self, reg: u16) -> Result<u32, NativeError> {
        Ok(self.get32(reg))
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), NativeError> {
        self.events.push(Event::Write8(reg, value));
        self.mem[reg as usize] = value;
        Ok(())
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), NativeError> {
        self.events.push(Event::Write32(reg, value));
        let mut v = value;
        if reg == REG_WKFMCAM_CMD {
            v &= !BIT_WKFCAM_POLLING_V1; // hardware completes immediately
        }
        if reg == SEC_CMD {
            v &= !CMD_POLLING;
            if value & CMD_WRITE_ENABLE != 0 {
                let addr = (value & 0xff) as usize;
                self.sec_cam[addr] = self.get32(SEC_WRITE);
            }
        }
        if reg == REG_RXPKT_NUM {
            v = if v & BIT_RW_RELEASE != 0 {
                v | BIT_RXDMA_IDLE
            } else {
                v & !BIT_RXDMA_IDLE
            };
        }
        self.set32(reg, v);
        Ok(())
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn download(&mut self, image: &PreparedImage) -> Result<(), NativeError> {
        self.downloads += 1;
        if self.fail_download == Some(self.downloads) {
            return Err(NativeError::Ready);
        }
        self.events.push(Event::Download(image_len(image)));
        // WoW firmware clears the wake reason once running.
        if !self.stuck_reason {
            self.mem[REG_WOWLAN_WAKE_REASON as usize] = 0;
        }
        Ok(())
    }
    async fn reserved_page(&mut self, pages: &[u8]) -> Result<(), NativeError> {
        self.events.push(Event::Page(pages.len()));
        Ok(())
    }
    async fn h2c(&mut self, command: [u8; 8]) -> Result<(), NativeError> {
        self.events.push(Event::H2c(command));
        // Firmware releases RX DMA when WoW is disabled (check_fw_status).
        if command[0] == 0x80 && command[1] & 1 == 0 {
            let v = self.get32(REG_RXPKT_NUM) & !(BIT_RW_RELEASE | BIT_RXDMA_IDLE);
            self.set32(REG_RXPKT_NUM, v);
        }
        Ok(())
    }
    fn hci_stop(&mut self) -> Result<(), NativeError> {
        self.events.push(Event::HciStop);
        Ok(())
    }
    async fn hci_restart(&mut self) -> Result<(), NativeError> {
        self.events.push(Event::HciRestart);
        Ok(())
    }
}
fn image_len(image: &PreparedImage) -> usize {
    image.size()
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
fn image(dmem: usize) -> PreparedImage {
    let imem = 8;
    let mut bytes = vec![0; 64 + dmem + 8 + imem + 8];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, dmem as u32),
        (0x30, imem as u32),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    preflight_image(0xc822, bytes).unwrap()
}
const OWN: [u8; 6] = [0x00, 0xe0, 0x4c, 0x01, 0x02, 0x03];
const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
fn config() -> WowlanConfig {
    // Unicast to OWN, match DA (bytes 0..5) and bytes 12..13 (EtherType).
    let mut pattern = vec![0u8; 14];
    pattern[..6].copy_from_slice(&OWN);
    pattern[12..14].copy_from_slice(&[0x08, 0x00]);
    WowlanConfig {
        disconnect: true,
        magic_packet: true,
        gtk_rekey_failure: true,
        patterns: vec![WowlanPattern {
            mask: vec![0x3f, 0x30],
            pattern,
            offset: 0,
        }],
        net_detect: None,
    }
}
const PTK: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const GTK: [u8; 16] = [0xa5; 16];
fn keys() -> SuspendKeys {
    SuspendKeys {
        pairwise: Zeroizing::new(PTK),
        groups: vec![(1, Zeroizing::new(GTK))],
    }
}
fn plan() -> Plan {
    Plan::new(0xc822, &config(), OWN, PEER, 1, true, Some(&keys())).unwrap()
}
/// Independent CRC16/0x1021, LSB-first input, seed 0xffff, inverted.
fn reference_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in data {
        for i in 0..8 {
            let fb = (crc >> 15) ^ u16::from((b >> i) & 1);
            crc <<= 1;
            if fb != 0 {
                crc ^= 0x1021;
            }
        }
    }
    !crc
}

fn smoke_rtw88_wow_support_and_validation() -> TestResult {
    let Some(s) = support(0xc822) else {
        return TestResult::Fail("RTL8822CE wowlan_stub not advertised");
    };
    if !s.disconnect
        || !s.magic_packet
        || !s.gtk_rekey_failure
        || s.gtk_rekey
        || s.max_patterns != 12
        || s.min_pattern_len != 1
        || s.max_pattern_len != 128
        || s.net_detect_max_match_sets != 0
    {
        return TestResult::Fail("support differs from rtw_wowlan_stub_8822c minus ported gaps");
    }
    if support(0xc821).is_some() || support(0xb822).is_some() {
        return TestResult::Fail("WoW advertised on a chip without wow_fw_name");
    }
    if validate(0xc822, &config()).is_err() {
        return TestResult::Fail("valid configuration refused");
    }
    let mut c = config();
    c.patterns[0].offset = 1;
    if validate(0xc822, &c) != Err(Error::Invalid) {
        return TestResult::Fail("packet offset admitted");
    }
    let mut c = config();
    c.patterns[0].mask.push(0);
    if validate(0xc822, &c) != Err(Error::Invalid) {
        return TestResult::Fail("mask length mismatch admitted");
    }
    let mut c = config();
    c.patterns = vec![c.patterns[0].clone(); 13];
    if validate(0xc822, &c) != Err(Error::Invalid) {
        return TestResult::Fail("13 patterns admitted");
    }
    if validate(0xc822, &WowlanConfig::default()) != Err(Error::Invalid) {
        return TestResult::Fail("empty trigger set admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_support_and_validation
);

fn smoke_rtw88_wow_pattern_cam_layout() -> TestResult {
    if crc16(&[]) != 0 || crc16(b"123456789") != reference_crc(b"123456789") {
        return TestResult::Fail("rtw_calc_crc mismatch");
    }
    let c = config();
    let p = generate(&c.patterns[0], OWN);
    if p.kind != PatternType::Unicast {
        return TestResult::Fail("DA == own MAC not classified unicast");
    }
    // mask 0x3f,0x30: hw[0] = (0x3f>>6)|(0x30&0x3f)<<2 = 0xc0, low6 cleared;
    // hw[1] = 0x30>>6 = 0.
    let mut want = [0u8; MASK_SIZE];
    want[0] = 0xc0;
    if p.mask != want {
        return TestResult::Fail("mask not shifted by the 6-byte SA offset");
    }
    if p.crc != reference_crc(&[0x08, 0x00]) {
        return TestResult::Fail("CRC does not cover masked bytes from offset 12");
    }
    let cam = cam_entry(2, &p);
    if cam[0] != (16, 0xc0) || cam[1] != (17, 0) || cam[3] != (19, 0) {
        return TestResult::Fail("mask words not at (id << 3) + 0..3");
    }
    if cam[4] != (20, u32::from(p.crc) | BIT_WKFMCAM_UC | BIT_WKFMCAM_VALID) {
        return TestResult::Fail("CRC/type/valid word wrong");
    }
    let mut bc = c.patterns[0].clone();
    bc.pattern[..6].copy_from_slice(&[0xff; 6]);
    let mut other = c.patterns[0].clone();
    other.pattern[..6].copy_from_slice(&PEER);
    if generate(&bc, OWN).kind != PatternType::Broadcast
        || cam_entry(0, &generate(&other, OWN))[4].1 & BIT_WKFMCAM_VALID != 0
    {
        return TestResult::Fail("broadcast/invalid type handling wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_pattern_cam_layout
);

fn smoke_rtw88_wow_suspend_config_sequence() -> TestResult {
    let mut io = Model::new();
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x99;
    let plan = plan();
    let wow = image(16);
    if run(suspend(&mut io, &plan, &wow)).is_err() {
        return TestResult::Fail("suspend failed on a healthy model");
    }
    if io.events.first() != Some(&Event::Write8(REG_TXPAUSE, 0xff)) {
        return TestResult::Fail("TX not paused first (rtw_wow_bb_stop)");
    }
    let pos = |e: &Event| io.events.iter().position(|x| x == e);
    let (Some(dl), Some(page), Some(stop)) = (
        pos(&Event::Download(image_len(&wow))),
        pos(&Event::Page(plan.pages.len())),
        pos(&Event::HciStop),
    ) else {
        return TestResult::Fail("download/reserved page/hci_stop missing");
    };
    let rx_stop = pos(&Event::Write32(REG_RXPKT_NUM, BIT_RW_RELEASE));
    if !(rx_stop.is_some_and(|r| r < dl) && dl < page && page < stop) {
        return TestResult::Fail("stop_trx -> swap -> rsvd page -> hci_stop order broken");
    }
    let flags = plan.flags;
    let want = [
        h2c::media_status(0, true),
        h2c::rsvd_page(plan.locations),
        h2c::aoac(KeyType::Aes, KeyType::Aes),
        h2c::disconnect_decision(flags, true),
        h2c::keep_alive(true),
        h2c::wowlan(flags, true),
        h2c::remote_wake(true),
    ];
    if io.h2c() != want {
        return TestResult::Fail("WoW H2C sequence differs from rtw_wow_fw_start");
    }
    // fw.h bit layouts.
    if want[5][..4] != [0x80, 0x07 | 0x40 | 0x80, 0, 0]
        || want[6][..2] != [0x81, 0x01]
        || want[2][..3] != [0x82, 4, 4]
        || want[4][..3] != [0x03, 0x03, 5]
        || want[3][..4] != [0x04, 0x03, 30, 5]
    {
        return TestResult::Fail("H2C bit layout differs from fw.h");
    }
    if io.cam_words().len() != 5 || io.cam_words()[4].1 & BIT_WKFMCAM_VALID == 0 {
        return TestResult::Fail("pattern CAM not written");
    }
    if io.mem[REG_TXPAUSE as usize] != 0x0f || io.mem[REG_SYS_FUNC_EN as usize] & 1 == 0 {
        return TestResult::Fail("BB/TXPAUSE not restored by rtw_wow_bb_start");
    }
    let tail: Vec<_> = io.events[io.events.len() - 2..].to_vec();
    if tail
        != [
            Event::Write8(REG_RSV_CTRL, 0x20),
            Event::Write8(REG_RSV_CTRL, 0x60),
        ]
    {
        return TestResult::Fail("rtw_wow_avoid_reset_mac not last");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_suspend_config_sequence
);

fn smoke_rtw88_wow_resume_reason_and_firmware_restore() -> TestResult {
    for (reason, magic, disconnect) in [(0x21u8, true, false), (0x10, false, true)] {
        let mut io = Model::new();
        let plan = plan();
        let (wow, normal) = (image(16), image(32));
        let Ok(armed) = run(suspend(&mut io, &plan, &wow)) else {
            return TestResult::Fail("suspend failed");
        };
        io.mem[REG_WOWLAN_WAKE_REASON as usize] = reason;
        io.events.clear();
        let (report, result) = run(resume(&mut io, armed, &normal));
        let Some(report) = report else {
            return TestResult::Fail("wake reason not captured");
        };
        if result.is_err() {
            return TestResult::Fail("resume failed on a healthy model");
        }
        if report.magic_packet != magic
            || report.disconnect != disconnect
            || keeps_link(&report) == disconnect
        {
            return TestResult::Fail("wake reason decode/link policy wrong");
        }
        let Some(restart) = io.events.iter().position(|e| *e == Event::HciRestart) else {
            return TestResult::Fail("hci not restarted");
        };
        // Only the security-CAM teardown may precede the host ring restart.
        if io.events[..restart].iter().any(|e| {
            !matches!(
                e,
                Event::Write32(SEC_CMD | SEC_WRITE, _) | Event::Write8(SEC_CONFIG | CR_HIGH, _)
            )
        }) || io.mem[CR_HIGH as usize] & ENGINE_EN != 0
            || io.mem[SEC_CONFIG as usize] != 0
            || io.sec_cam[1 << 3] & 1 << 15 != 0
            || io.sec_cam[4 << 3] & 1 << 15 != 0
        {
            return TestResult::Fail("security CAM not back to software CCMP before hci restart");
        }
        if !io.events.contains(&Event::Download(image_len(&normal)))
            || io.events.contains(&Event::Download(image_len(&wow)))
        {
            return TestResult::Fail("normal image not restored after hci restart");
        }
        let flags = plan.flags;
        let h = io.h2c();
        if h[..4]
            != [
                h2c::disconnect_decision(flags, false),
                h2c::keep_alive(false),
                h2c::wowlan(flags, false),
                h2c::remote_wake(false),
            ]
            || h[4] != h2c::media_status(0, true)
        {
            return TestResult::Fail("rtw_wow_fw_stop H2C sequence wrong");
        }
        if !io.events.contains(&Event::Write32(
            REG_WKFMCAM_CMD,
            BIT_WKFCAM_POLLING_V1 | BIT_WKFCAM_CLR_V1,
        )) {
            return TestResult::Fail("pattern CAM not cleared");
        }
        if io.get32(REG_RXPKT_NUM) & BIT_RW_RELEASE != 0
            || io.mem[REG_TXPAUSE as usize] != 0x0f
            || io.mem[REG_SYS_FUNC_EN as usize] & 1 == 0
        {
            return TestResult::Fail("rtw_wow_resume_trx did not reopen RX DMA/BB");
        }
    }
    for (reason, check) in [
        (
            0x02u8,
            WakeReport {
                gtk_rekey_failure: true,
                ..Default::default()
            },
        ),
        (
            0x23,
            WakeReport {
                pattern_index: Some(0),
                ..Default::default()
            },
        ),
        (
            0x08,
            WakeReport {
                disconnect: true,
                ..Default::default()
            },
        ),
        (
            0x01,
            WakeReport {
                unknown: Some(1),
                ..Default::default()
            },
        ),
    ] {
        if decode(reason) != check {
            return TestResult::Fail("rtw_wow_show_wakeup_reason mapping wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_resume_reason_and_firmware_restore
);

fn smoke_rtw88_wow_failure_requires_full_restart() -> TestResult {
    // WoW firmware never acknowledges: suspend fails before hci_stop.
    let mut io = Model::new();
    io.stuck_reason = true;
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x99;
    if run(suspend(&mut io, &plan(), &image(16))).err() != Some(Error::Timeout)
        || io.events.contains(&Event::HciStop)
    {
        return TestResult::Fail("unacknowledged WoW firmware armed the device");
    }
    // Normal-image restore failure: the report survives, the result errors.
    let mut io = Model::new();
    io.fail_download = Some(2);
    let Ok(armed) = run(suspend(&mut io, &plan(), &image(16))) else {
        return TestResult::Fail("suspend failed");
    };
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x21;
    let (report, result) = run(resume(&mut io, armed, &image(32)));
    if report.is_none_or(|r| !r.magic_packet) || result != Err(Error::Native(NativeError::Ready)) {
        return TestResult::Fail("restore failure not surfaced for full restart");
    }
    // A failed WoW image download leaves the source sequence unarmed.
    let mut io = Model::new();
    io.fail_download = Some(1);
    if run(suspend(&mut io, &plan(), &image(16))).is_ok() || io.events.contains(&Event::HciStop) {
        return TestResult::Fail("failed WoW image swap armed the device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_failure_requires_full_restart
);

fn smoke_rtw88_wow_security_cam_install_and_clear() -> TestResult {
    // sec.c::rtw_sec_write_cam word layout, independent of the builder.
    let entries = match super::super::security_cam::entries(&keys(), PEER) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("entries refused current keys"),
    };
    if entries.len() != 2
        || (entries[0].index, entries[0].key_id, entries[0].group) != (1, 1, true)
        || entries[0].addr != [0xff; 6]
        || (entries[1].index, entries[1].key_id, entries[1].group) != (4, 0, false)
        || entries[1].addr != PEER
    {
        return TestResult::Fail("default-key-search slot choice differs from rtw_ops_set_key");
    }
    let mut io = Model::new();
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x99;
    let plan = plan();
    let Ok(armed) = run(suspend(&mut io, &plan, &image(16))) else {
        return TestResult::Fail("suspend failed on a healthy model");
    };
    // Pairwise entry 4: AES(4)<<2 | valid, AP address, PTK little-endian.
    let w = |entry: usize, word: usize| io.sec_cam[entry << 3 | word];
    if w(4, 0) != (4 << 2 | 1 << 15 | 0x02 << 16 | 0x11 << 24)
        || w(4, 1) != u32::from_le_bytes([0x22, 0x33, 0x44, 0x55])
        || w(4, 2) != u32::from_le_bytes([0x00, 0x11, 0x22, 0x33])
        || w(4, 5) != u32::from_le_bytes([0xcc, 0xdd, 0xee, 0xff])
        || w(4, 6) != 0
        || w(4, 7) != 0
    {
        return TestResult::Fail("pairwise CAM entry layout differs from rtw_sec_write_cam");
    }
    // Group entry 1: key id 1, group bit, broadcast address.
    if w(1, 0) != (1 | 4 << 2 | 1 << 6 | 1 << 15 | 0xff << 16 | 0xff << 24)
        || w(1, 1) != u32::MAX
        || w(1, 3) != 0xa5a5_a5a5
    {
        return TestResult::Fail("group CAM entry layout differs from rtw_sec_write_cam");
    }
    // Word 0 (valid) of each entry is written last.
    let cmds: Vec<u32> = io
        .events
        .iter()
        .filter_map(|e| match *e {
            Event::Write32(SEC_CMD, v) => Some(v & 0xff),
            _ => None,
        })
        .collect();
    if cmds[..8] != [15, 14, 13, 12, 11, 10, 9, 8]
        || cmds[8..16] != [39, 38, 37, 36, 35, 34, 33, 32]
    {
        return TestResult::Fail("CAM words not written 7..0 per entry");
    }
    if io.mem[CR_HIGH as usize] & ENGINE_EN == 0 || io.mem[SEC_CONFIG as usize] != 0xcf {
        return TestResult::Fail("rtw_sec_enable_sec_engine state missing for WoW");
    }
    // Keys go in after host RX DMA stopped and the WoW image runs.
    let pos = |pred: &dyn Fn(&Event) -> bool| io.events.iter().position(pred);
    let (Some(dl), Some(first_cam), Some(page)) = (
        pos(&|e| matches!(e, Event::Download(_))),
        pos(&|e| matches!(e, Event::Write32(SEC_CMD, _))),
        pos(&|e| matches!(e, Event::Page(_))),
    ) else {
        return TestResult::Fail("download/CAM/page events missing");
    };
    if !(dl < first_cam && first_cam < page) {
        return TestResult::Fail("CAM install not between WoW swap and fw start");
    }
    io.events.clear();
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x21;
    let (_, result) = run(resume(&mut io, armed, &image(32)));
    if result.is_err() {
        return TestResult::Fail("resume failed on a healthy model");
    }
    if io.sec_cam[1 << 3] != 0 || io.sec_cam[4 << 3] != 0 {
        return TestResult::Fail("rtw_sec_clear_cam did not invalidate the WoW entries");
    }
    // Software crypto required before install: a live engine is refused.
    let mut io = Model::new();
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x99;
    io.mem[SEC_CONFIG as usize] = 0x0c;
    if run(suspend(&mut io, &plan, &image(16))).is_ok() || io.events.contains(&Event::HciStop) {
        return TestResult::Fail("CAM installed over a non-software crypto state");
    }
    // Open BSS: no CAM writes, AOAC reports no cipher.
    let open = match Plan::new(0xc822, &config(), OWN, PEER, 1, true, None) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("open BSS plan refused"),
    };
    let mut io = Model::new();
    io.mem[REG_WOWLAN_WAKE_REASON as usize] = 0x99;
    if run(suspend(&mut io, &open, &image(16))).is_err()
        || io
            .events
            .iter()
            .any(|e| matches!(e, Event::Write32(SEC_CMD, _)))
        || !io.h2c().contains(&h2c::aoac(KeyType::None, KeyType::None))
    {
        return TestResult::Fail("open BSS WoW touched the security CAM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_security_cam_install_and_clear
);
