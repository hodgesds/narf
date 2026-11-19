// SPDX-License-Identifier: GPL-2.0-or-later
//! Native coexistence state machine regressions against a byte-addressed register model.
//! Expected register values and H2C words are authored from Linux rtw88
//! `coex.c`, `rtw8822c.c` and `rtw8821c.c`.
use super::coex::{self, Coex, Facts, Link, Record};
use super::dm::Authority;
use super::firmware_transport::{Error, Io};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Regs {
    mem: Vec<u8>,
    writes: Vec<(u16, u32)>,
    delays: u64,
}
impl Regs {
    fn new() -> Self {
        Self {
            mem: vec![0; 0x10000],
            writes: Vec::new(),
            delays: 0,
        }
    }
    fn get(&self, r: u16) -> u32 {
        let r = usize::from(r);
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set(&mut self, r: u16, v: u32) {
        let r = usize::from(r);
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn wrote(&self, r: u16) -> bool {
        self.writes.iter().any(|(a, _)| *a == r)
    }
}
#[async_trait::async_trait]
// SAFETY: test model with no DMA or hardware.
unsafe impl Io for Regs {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Ok(())
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read8(&mut self, r: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        async move { Ok(self.mem[usize::from(r)]) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read16(&mut self, r: u16) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        async move {
            let r = usize::from(r);
            Ok(u16::from_le_bytes([self.mem[r], self.mem[r + 1]]))
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read32(&mut self, r: u16) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        async move { Ok(self.get(r)) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write8(
        &mut self,
        r: u16,
        v: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.mem[usize::from(r)] = v;
            self.writes.push((r, u32::from(v)));
            Ok(())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write16(
        &mut self,
        r: u16,
        v: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            let a = usize::from(r);
            self.mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
            self.writes.push((r, u32::from(v)));
            Ok(())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write32(
        &mut self,
        r: u16,
        v: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            // The LTE-coex indirect port stays ready in this model.
            self.set(r, if r == 0x1700 { v | 1 << 29 } else { v });
            self.writes.push((r, v));
            Ok(())
        }
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&mut self, us: u64) {
        self.delays += us;
    }
}
struct Auth(Cell<bool>);
impl Authority for Auth {
    fn run<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if self.0.get() {
            op()
        } else {
            Err(Error::Access)
        }
    }
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
fn payload(modes: u8, share: u8, rfe: u8, btcoex: u8) -> [u8; 64] {
    let mut p = [0; 64];
    p[..4].copy_from_slice(&[modes, share, rfe, btcoex]);
    p
}
fn c22_facts(bt_setting: u8) -> Facts {
    Facts {
        did: 0xc822,
        rfe: 0,
        board_option: 0x20,
        bt_setting,
    }
}
fn regs() -> Regs {
    let mut r = Regs::new();
    // LTECOEX_READY, BT scoreboard ONOFF, kt_ver 3, saved MAC values.
    r.set(0x1700, 1 << 29);
    r.set(0xaa, 0x2);
    r.mem[0xf1] = 0x30;
    r.set(0x42a, 0x3030);
    r.set(0x430, 0x1111);
    r.set(0x434, 0x2222);
    r.mem[0x455] = 0x40;
    r
}
fn link(connected: bool) -> Link {
    Link {
        now: 1000,
        connected,
        channel: 6,
        ..Link::default()
    }
}
fn has(cmds: &[[u8; 8]], want: [u8; 8]) -> bool {
    cmds.contains(&want)
}

fn smoke_rtw88_coex_record_admission_per_chip_and_board() -> TestResult {
    let all = coex::PTA | coex::TDMA | coex::FREERUN | coex::BAND5;
    let Some(r) = coex::record(0xc822, &payload(all, 0, 0, 1)) else {
        return TestResult::Fail("full C22 non-shared record");
    };
    if coex::record(0xc821, &payload(all, 1, 2, 1)).is_none() {
        return TestResult::Fail("C21 shared record");
    }
    // Coexistence-driven 1SS is C22 only (`wl_mimo_ps_support`); TDMA
    // without the PTA base, a WL-only board with more than PTA, unknown
    // chips and nonzero tails are refused.
    if coex::record(0xc822, &payload(all | coex::MIMO_PS, 0, 0, 1)).is_none() {
        return TestResult::Fail("C22 MIMO_PS record");
    }
    let refused = [
        (0xc821, payload(coex::PTA | coex::MIMO_PS, 0, 0, 1)),
        (0xc821, payload(coex::TDMA, 0, 0, 1)),
        (0xc822, payload(coex::PTA | coex::TDMA, 0, 0, 0)),
        (0xc812, payload(coex::PTA, 0, 0, 1)),
        (0xc822, payload(coex::PTA, 2, 0, 1)),
    ];
    if refused.iter().any(|(d, p)| coex::record(*d, p).is_some()) {
        return TestResult::Fail("unqualified record admitted");
    }
    let mut tail = payload(coex::PTA, 0, 0, 1);
    tail[9] = 1;
    if coex::record(0xc822, &tail).is_some() {
        return TestResult::Fail("nonzero tail admitted");
    }
    // main.c: share_ant from bt_setting bit0, btcoex from board option.
    if Coex::new(r, c22_facts(0x1)).is_some() || Coex::new(r, c22_facts(0x0)).is_none() {
        return TestResult::Fail("efuse antenna facts must match the record");
    }
    let wifi_only = Facts {
        board_option: 0xff,
        ..c22_facts(0)
    };
    if wifi_only.btcoex() || !c22_facts(0).btcoex() {
        return TestResult::Fail("btcoex derivation");
    }
    let _: Record = r;
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_record_admission_per_chip_and_board
);

fn smoke_rtw88_coex_c22_power_on_init_program() -> TestResult {
    let r = coex::record(0xc822, &payload(coex::PTA, 0, 0, 1)).unwrap();
    let mut c = Coex::new(r, c22_facts(0)).unwrap();
    let mut io = regs();
    let auth = Auth(Cell::new(true));
    let Ok(h2c) = run(c.start(&mut io, &auth, link(false))) else {
        return TestResult::Fail("init");
    };
    // slot extend off (h2c69 opcode 0x0c para 1) and BT info query. The
    // forced TDMA case 0 sends no H2C on a non-shared board: rtw_coex_tdma
    // indexes tdma_nsant[type - 100], and (u8)(0 - 100) is out of range.
    if !has(&h2c, [0x69, 0x0c, 0x01, 0, 0, 0, 0, 0])
        || h2c.iter().any(|c| c[0] == 0x60)
        || !has(&h2c, [0x61, 1, 0, 0, 0, 0, 0, 0])
    {
        return TestResult::Fail("init H2C");
    }
    // Scoreboard ACTIVE|ONOFF (+0x2) with BT_INT_EN.
    if io.get(0xaa) & 0xffff != 0x8003 {
        return TestResult::Fail("scoreboard");
    }
    // 8822c coex_cfg_init: 0x790 sample rate, 0x778, PTA enables, RF B 0x1.
    if io.mem[0x790] & 0x3f != 5
        || io.mem[0x778] != 1
        || io.get(0x40) & ((1 << 5) | (1 << 9)) != (1 << 5) | (1 << 9)
        || io.mem[0x4c6] & 0x30 != 0x10
        || io.mem[0x6cc] & 0x18 != 0x18
        || io.mem[0x6cf] & 0x08 != 0x08
    {
        return TestResult::Fail("coex_cfg_init / priority masks");
    }
    // Non-shared nsant table case 1 is out of range (1 - 100): no write.
    if io.wrote(0x6c0) {
        return TestResult::Fail("nsant table 1");
    }
    if !c.initialized() || c.bt_disabled() || !c.freeze() {
        return TestResult::Fail("init state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_c22_power_on_init_program
);

fn bt_a2dp() -> Vec<u8> {
    // C2H 0x09, seq, src BT_RSP, lb2 CONNECTION|ACL_BUSY|A2DP, rest 0.
    vec![0x09, 0, 0x01, 0x49, 0, 0, 0, 0, 0]
}
fn associated(c: &mut Coex, io: &mut Regs, auth: &Auth) -> Result<(), Error> {
    run(c.start(io, auth, link(false)))?;
    run(c.connect(io, auth, link(false), true))?;
    run(c.connect(io, auth, link(true), false))?;
    run(c.media(io, auth, link(true), true, 100))?;
    Ok(())
}

fn smoke_rtw88_coex_c22_a2dp_tdma_table_and_limited_tx() -> TestResult {
    let modes = coex::PTA | coex::TDMA;
    let r = coex::record(0xc822, &payload(modes, 0, 0, 1)).unwrap();
    let mut c = Coex::new(r, c22_facts(0)).unwrap();
    let mut io = regs();
    let auth = Auth(Cell::new(true));
    if associated(&mut c, &mut io, &auth).is_err() {
        return TestResult::Fail("associate");
    }
    let Ok(Some(h2c)) = run(c.c2h(&mut io, &auth, link(true), &bt_a2dp())) else {
        return TestResult::Fail("bt info");
    };
    if c.bt_status() != coex::BtStatus::AclBusy {
        return TestResult::Fail("bt status");
    }
    // rtw_coex_action_bt_a2dp, non-shared, WL RSSI low: table 112,
    // TDMA 113 in 4-slot mode (beacon 100 < 120 -> h2c69 0x0b 0xc1).
    if io.get(0x6c0) != 0xffff55ff || io.get(0x6c4) != 0xfafafafa || io.get(0x6c8) != 0xf0ffffff {
        return TestResult::Fail("table 112");
    }
    if !has(&h2c, [0x69, 0x0b, 0xc1, 0, 0, 0, 0, 0])
        || !has(&h2c, [0x60, 0x51, 0x08, 0x03, 0x10, 0x54, 0, 0])
    {
        return TestResult::Fail("4-slot TDMA 113");
    }
    // rtw_coex_limited_tx(true, true).
    if io.mem[0x42a] != 0x08
        || io.mem[0x42b] != 0x08
        || io.get(0x430) != 0x0100_0000
        || io.get(0x434) != 0x0403_0201
        || io.mem[0x455] != 0x20
        || io.mem[0x45e] & 0x8 == 0
    {
        return TestResult::Fail("limited tx");
    }
    // PS-TDMA byte1 0x51 (bit4 set, bit5 clear) forces LPS off.
    if !c.forces_lps_off() || c.tdma_state() != (true, 113, [0x51, 0x08, 0x03, 0x10, 0x54]) {
        return TestResult::Fail("ps-tdma state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_c22_a2dp_tdma_table_and_limited_tx
);

fn smoke_rtw88_coex_unqualified_tdma_refused_and_restore_exact() -> TestResult {
    let r = coex::record(0xc822, &payload(coex::PTA, 0, 0, 1)).unwrap();
    let mut c = Coex::new(r, c22_facts(0)).unwrap();
    let mut io = regs();
    let before = io.mem.clone();
    let auth = Auth(Cell::new(true));
    if run(c.start(&mut io, &auth, link(false))).is_err() {
        return TestResult::Fail("init");
    }
    // With BT enabled, a 2.4GHz connect runs rtw_coex_action_wl_linkscan,
    // whose non-shared case is PS-TDMA 107 (A2DP: 111): this PTA-only
    // record does not qualify TDMA, so the connect is refused.
    if !matches!(
        run(c.connect(&mut io, &auth, link(false), true)),
        Err(Error::Unsupported)
    ) {
        return TestResult::Fail("TDMA admitted without the record");
    }
    let Ok(h2c) = run(c.restore(&mut io, &auth)) else {
        return TestResult::Fail("restore");
    };
    // Every MAC/RF register returns to its pre-coex value (the LTE
    // indirect data port is not byte-modelled here).
    for a in [
        0x40usize, 0xaa, 0x550, 0x6cc, 0x6cf, 0x778, 0x790, 0x4c6, 0x762, 0x4fc, 0x73,
    ] {
        if io.mem[a] != before[a] {
            return TestResult::Fail("register not restored");
        }
    }
    // The refused connect never reached media connect, so no WL channel
    // info (H2C 0x66) or TDMA was sent and none is withdrawn.
    if h2c.iter().any(|c| c[0] == 0x66 || c[0] == 0x60) || c.initialized() {
        return TestResult::Fail("firmware coex state not returned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_unqualified_tdma_refused_and_restore_exact
);

fn smoke_rtw88_coex_revoked_authority_writes_nothing() -> TestResult {
    let r = coex::record(0xc821, &payload(coex::PTA, 0, 0, 1)).unwrap();
    let facts = Facts {
        did: 0xc821,
        ..c22_facts(0)
    };
    let mut c = Coex::new(r, facts).unwrap();
    let mut io = regs();
    let auth = Auth(Cell::new(false));
    if run(c.start(&mut io, &auth, link(false))).is_ok() || !io.writes.is_empty() {
        return TestResult::Fail("revoked authority wrote");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_revoked_authority_writes_nothing
);

/// The base TX/RX path fields `rtw8822c_config_trx_mode(AB, AB)` leaves
/// (two-path RX, 1SS TX on A, two-stream ANTMAP 0x31) with unrelated bits.
fn trx_base(io: &mut Regs) {
    io.set(0x1800, 0xa013_3312);
    io.set(0x4100, 0x3623_3312);
    io.set(0x1a2c, 0x0022_0000 | 0x0004_c000);
    io.set(0x1a04, 0x8169_5847);
    io.set(0x1d30, 0x0020_0100 | 0x1000_0000);
    io.set(0xc44, 1 << 17 | 3);
    io.set(0xc54, 1 << 20 | 5);
    io.set(0xc38, 1 << 24 | 7);
    io.set(0x824, 0x0333_0000 | 0x11);
    io.set(0x820, 0x0000_0031 | 0x2200);
    io.set(0x1e2c, 0x2211_0400);
    io.set(0x1d70, 0x2020);
}
const TRX_REGS: [u16; 12] = [
    0x1800, 0x4100, 0x1a2c, 0x1a04, 0x1d30, 0xc44, 0xc54, 0xc38, 0x824, 0x820, 0x1e2c, 0x1d70,
];

fn smoke_rtw88_coex_c22_mimo_ps_config_trx_mode_and_exact_restore() -> TestResult {
    let modes = coex::PTA | coex::TDMA | coex::FREERUN | coex::BAND5 | coex::MIMO_PS;
    let r = coex::record(0xc822, &payload(modes, 0, 0, 1)).unwrap();
    let mut c = Coex::new(r, c22_facts(0)).unwrap();
    let mut io = regs();
    trx_base(&mut io);
    let auth = Auth(Cell::new(true));
    if run(c.start(&mut io, &auth, link(true))).is_err() {
        return TestResult::Fail("init");
    }
    let base: Vec<u32> = TRX_REGS.iter().map(|&a| io.get(a)).collect();
    // rtw_coex_mimo_ps(force, true): hal.txrx_1ss and WL channel info.
    c.mimo_ps_for_test(true, true);
    if !c.txrx_1ss() || c.trx_1ss() {
        return TestResult::Fail("mimo_ps request");
    }
    io.writes.clear();
    if !matches!(run(c.config_trx(&mut io, &auth)), Ok(true)) || !c.trx_1ss() {
        return TestResult::Fail("config_trx_mode(A, A)");
    }
    // ORITXCODE 0x33312 / ORITXCODE2 0x11111; CCK RX A (CCANRX 0, RXCCKSEL
    // 27:24 = 0); OFDM RX A (RXFNCTL, AGCSWSH, ANTWTPD, MRCM 0, 0x824 = 1);
    // CCK TX A (8), OFDM TX A (ANTMAP0 0x11, TXLGMAP 7:0 = 0).
    if io.get(0x1800) != 0xa013_3312
        || io.get(0x4100) != 0x3621_1111
        || io.get(0x1a2c) != 0x0000_c000
        || io.get(0x1a04) != 0x8069_5847
        || io.get(0x1d30) != 0x1000_0000
        || io.get(0xc44) != 3
        || io.get(0xc54) != 5
        || io.get(0xc38) != 7
        || io.get(0x824) != 0x0131_0011
        || io.get(0x820) != 0x2211
        || io.get(0x1e2c) != 0x2211_0400
    {
        return TestResult::Fail("1SS TX/RX path fields");
    }
    // Three bb_resets (set/clear/set of BIT_FEN_BB_RSTB) and toggle_igi
    // (igi - 2 then igi on both paths).
    let resets = io.writes.iter().filter(|(a, _)| *a == 2).count();
    let igi: Vec<u32> = io
        .writes
        .iter()
        .filter(|(a, _)| *a == 0x1d70)
        .map(|(_, v)| *v & 0x7f7f)
        .collect();
    if resets != 9 || igi.first() != Some(&0x201e) || io.get(0x1d70) & 0x7f7f != 0x2020 {
        return TestResult::Fail("bb_reset / toggle_igi");
    }
    // Same state again: rtw_set_txrx_1ss returns early.
    io.writes.clear();
    if !matches!(run(c.config_trx(&mut io, &auth)), Ok(false)) || !io.writes.is_empty() {
        return TestResult::Fail("unchanged txrx_1ss rewrote");
    }
    // Leaving 2GFREE: the exact base fields come back.
    c.mimo_ps_for_test(false, false);
    if !matches!(run(c.config_trx(&mut io, &auth)), Ok(true)) || c.trx_1ss() {
        return TestResult::Fail("exit config_trx");
    }
    if TRX_REGS.iter().zip(&base).any(|(&a, &v)| io.get(a) != v) {
        return TestResult::Fail("exit did not restore the base paths exactly");
    }
    // Entered again, then unbound: restore returns the base paths too.
    c.mimo_ps_for_test(true, true);
    if !matches!(run(c.config_trx(&mut io, &auth)), Ok(true)) {
        return TestResult::Fail("re-enter");
    }
    if run(c.restore(&mut io, &auth)).is_err()
        || c.trx_1ss()
        || c.txrx_1ss()
        || TRX_REGS.iter().zip(&base).any(|(&a, &v)| io.get(a) != v)
    {
        return TestResult::Fail("restore did not return the base paths");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_c22_mimo_ps_config_trx_mode_and_exact_restore
);

fn smoke_rtw88_coex_mimo_ps_unqualified_refused_and_smps_frame_shape() -> TestResult {
    let r = coex::record(0xc822, &payload(coex::PTA, 0, 0, 1)).unwrap();
    let mut c = Coex::new(r, c22_facts(0)).unwrap();
    let mut io = regs();
    trx_base(&mut io);
    let auth = Auth(Cell::new(true));
    if run(c.start(&mut io, &auth, link(true))).is_err() {
        return TestResult::Fail("init");
    }
    c.mimo_ps_for_test(true, true);
    io.writes.clear();
    if !matches!(run(c.config_trx(&mut io, &auth)), Err(Error::Unsupported))
        || c.trx_1ss()
        || !io.writes.is_empty()
    {
        return TestResult::Fail("1SS without MIMO_PS must write nothing");
    }
    // ieee80211_send_smps_action: HT category 7, SMPS action 1, control
    // static (1) or disabled (0); DA = BSSID, never dynamic.
    let own = [2, 0, 0, 0, 0, 1];
    let ap = [2, 0, 0, 0, 0, 2];
    let frame = |control: u8, bssid: [u8; 6]| {
        let mut b = vec![0xd0, 0, 0, 0];
        b.extend_from_slice(&ap);
        b.extend_from_slice(&own);
        b.extend_from_slice(&bssid);
        b.extend_from_slice(&[0x10, 0, 7, 1, control]);
        b
    };
    use super::packet_format::smps_action;
    if !smps_action(&frame(1, ap))
        || !smps_action(&frame(0, ap))
        || smps_action(&frame(3, ap))
        || smps_action(&frame(1, own))
    {
        return TestResult::Fail("SMPS action shape");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/coex",
    smoke_rtw88_coex_mimo_ps_unqualified_refused_and_smps_frame_shape
);
