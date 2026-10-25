use super::mac_tests::Model;
use super::*;
use crate::rtw88::{
    command, dack,
    efuse::Factory,
    power_policy::{Board, Permission},
    radio,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[path = "retained_backend_tests.rs"]
mod retained_backend_tests;
include!("golden.rs");
pub(super) struct RadioIo {
    base: Model,
    radio: bool,
    commands: Vec<[u8; 32]>,
    pending: bool,
    polls: u16,
    finished: bool,
    hold_dma: bool,
    no_iqk: bool,
    stale_iqk: bool,
    cam_stuck: bool,
    awake_stuck: bool,
    bad_samples: bool,
    pause_command: bool,
    lost: Option<u16>,
    pub(super) packets: crate::rtw88::packet_core::tests::Model,
    core: Option<crate::rtw88::packet_core::Core>,
    gate: Option<crate::rtw88::power_policy::Gate>,
    pub(super) clock: Arc<AtomicU64>,
    pub(super) policy: Arc<narf_lib::sync::IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
    pub(super) mailbox_ready_hold: Arc<AtomicBool>,
    pub(super) mailbox_done_hold: Arc<AtomicBool>,
    pub(super) mailbox_pause: Arc<AtomicBool>,
    pub(super) mailboxes: Vec<[u8; 8]>,
    mailbox_pending: bool,
    pub(super) mailbox_cursor: u8,
}
impl RadioIo {
    pub(super) fn new() -> Self {
        let mut base = Model::new(0, 3);
        base.regs[0x1208..0x120c].fill(0);
        base.regs[0x80..0x84].fill(0);
        Self {
            base,
            radio: false,
            commands: Vec::new(),
            pending: false,
            polls: 0,
            finished: false,
            hold_dma: false,
            no_iqk: false,
            stale_iqk: false,
            cam_stuck: false,
            awake_stuck: false,
            bad_samples: false,
            pause_command: false,
            lost: None,
            packets: crate::rtw88::packet_core::tests::Model::new(),
            core: None,
            gate: None,
            clock: Arc::new(AtomicU64::new(0)),
            policy: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                super::power_policy_tests::domain(),
            )),
            mailbox_ready_hold: Arc::new(AtomicBool::new(false)),
            mailbox_done_hold: Arc::new(AtomicBool::new(false)),
            mailbox_pause: Arc::new(AtomicBool::new(false)),
            mailboxes: Vec::new(),
            mailbox_pending: false,
            mailbox_cursor: 0,
        }
    }
    fn reference() -> Self {
        let mut io = Self::new();
        io.radio = true;
        for (i, v) in io.base.regs.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        for reg in [0x3e3c, 0x4e3c] {
            io.base.regs[reg..reg + 4].copy_from_slice(&0x15678u32.to_le_bytes());
        }
        io
    }
    fn word(&self, r: usize) -> u32 {
        u32::from_le_bytes(self.base.regs[r..r + 4].try_into().unwrap())
    }
    pub(super) fn arm_calibration(&mut self) {
        self.radio = true;
        self.base.trace.clear();
        self.base.regs[0x670..0x674].fill(0);
        self.base.regs[0x3d9..0x3db].fill(0);
        self.base.regs[0x1d70..0x1d74].copy_from_slice(&0x30303030u32.to_le_bytes());
    }
    fn packet_with<T>(
        &mut self,
        operation: impl FnOnce(
            &mut crate::rtw88::packet_core::Core,
            &mut crate::rtw88::packet_core::tests::Model,
        ) -> Result<T, crate::rtw88::packet_core::Error>,
    ) -> Result<T, crate::rtw88::packet_core::Error> {
        self.packets.now = self.clock.load(Ordering::Acquire).saturating_mul(1000);
        let mut core = self
            .core
            .take()
            .ok_or(crate::rtw88::packet_core::Error::State)?;
        let result = operation(&mut core, &mut self.packets);
        self.core = Some(core);
        result
    }
}
#[async_trait::async_trait]
// SAFETY: isolated same-owner register/receipt model. It never accesses a
// physical device; every firmware/MAC stage uses the actual retained owner.
unsafe impl Io for RadioIo {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        self.base.claim_pristine()
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        let old = self.base.read8(r)?;
        if self.radio && r == 0x2d9c {
            return Ok(
                if self.stale_iqk || (!self.no_iqk && !self.pending && self.commands.len() == 3) {
                    0xaa
                } else {
                    0
                },
            );
        }
        Ok(old)
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        self.base.read16(r)
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        let v = self.base.read32(r)?;
        if !self.radio {
            return Ok(v);
        }
        Ok(match r {
            0x2dbc if self.bad_samples => 0x100100,
            0x2dbc => {
                if self.word(0x1868) == 0x4010 || self.word(0x4168) == 0x4010 {
                    0x10010
                } else {
                    0
                }
            }
            0x2808 | 0x2834 | 0x4508 | 0x4534 => 0x7fff80,
            0x2824 | 0x2850 | 0x4524 | 0x4550 => 128 << 19,
            0x670 if !self.cam_stuck => v & !(1 << 31),
            _ => v,
        })
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        self.base.write8(r, v)?;
        if self.radio && r == 0x3d9 && !self.awake_stuck {
            self.base.regs[0x3da] ^= 0x80;
        }
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        self.base.write16(r, v)
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        if self.finished && !self.packets.live {
            return Err(Error::Access);
        }
        let old = self.word(usize::from(r));
        self.base.write32(r, v)?;
        if self.lost == Some(r) {
            self.base.regs[usize::from(r)..usize::from(r) + 4].copy_from_slice(&old.to_le_bytes());
        }
        if r == 0x1808 || r == 0x4108 {
            let target = if r == 0x1808 { 0x3c00 } else { 0x4c00 };
            self.base.regs[target..target + 4].copy_from_slice(&(v & 0xfffff).to_le_bytes());
        }
        Ok(())
    }
    async fn reserved_page(&mut self, b: &[u8]) -> Result<(), Error> {
        self.base.reserved_page(b).await
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.base.lte_backup().await
    }
    async fn lte_restore(&mut self, v: u32) -> Result<(), Error> {
        self.base.lte_restore(v).await
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.base.finish_dma().await
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        self.base.begin_mac()
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.base.finish_mac()
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.base.begin_phy()
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.base.finish_phy()
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        if !self.radio || self.pending || !self.commands.is_empty() {
            return Err(Error::State);
        }
        // Native H2C ring/memory ownership is tested separately. Here the
        // independent firmware model controls terminal and applied receipts.
        self.base.regs[0x100] = 0x33;
        Ok(())
    }
    fn submit_h2c(&mut self, p: &[u8; 32]) -> Result<(), Error> {
        if self.pending {
            return Err(Error::State);
        }
        self.commands.push(*p);
        self.pending = true;
        self.polls = 0;
        Ok(())
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        if !self.pending {
            return Err(Error::State);
        }
        self.polls += 1;
        if self.hold_dma || self.polls == 1 {
            return Ok(false);
        }
        self.pending = false;
        Ok(true)
    }
    fn finish_radio(&mut self, gate: crate::rtw88::power_policy::Gate) -> Result<(), Error> {
        if self.pending || self.commands.len() != 3 || gate.own() != [2, 4, 6, 8, 10, 12] {
            return Err(Error::State);
        }
        self.base.regs[0x100] = 0x30;
        self.gate = Some(gate);
        self.finished = true;
        Ok(())
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.gate
            .as_ref()
            .map(|gate| gate.own())
            .ok_or(Error::State)
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        if !self.finished || !self.packets.live || !self.packets.allowed {
            return Err(Error::Access);
        }
        self.gate
            .as_ref()
            .ok_or(Error::State)?
            .current_with_policy_for_test(&self.policy.lock())
            .map_err(Error::Power)
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        if !self.packets.live {
            return Err(Error::Access);
        }
        Ok(!self.mailbox_pending && !self.mailbox_ready_hold.load(Ordering::Acquire))
    }
    fn mailbox_submit(&mut self, words: [u8; 8]) -> Result<(), Error> {
        if !self.mailbox_ready()? {
            return Err(Error::State);
        }
        self.mailbox_pending = true;
        self.mailboxes.push(words);
        Ok(())
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        if !self.packets.live {
            return Err(Error::Access);
        }
        if !self.mailbox_pending {
            return Err(Error::State);
        }
        if self.mailbox_done_hold.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.mailbox_pending = false;
        self.mailbox_cursor = (self.mailbox_cursor + 1) % 4;
        Ok(true)
    }
    fn mailbox_pending(&self) -> bool {
        self.mailbox_pending
    }
    fn packet_prepare(
        &mut self,
        own: [u8; 6],
        mac_id: u8,
    ) -> Result<(), crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        if self.core.is_some() || Some(own) != self.gate.as_ref().map(|gate| gate.own()) {
            return Err(crate::rtw88::packet_core::Error::State);
        }
        let gate = self
            .gate
            .as_ref()
            .ok_or(crate::rtw88::packet_core::Error::State)?
            .clone();
        let policy = self.policy.clone();
        self.packets.authority = Some(Arc::new(move || {
            gate.current_with_policy_for_test(&policy.lock()).is_ok()
        }));
        self.core = Some(crate::rtw88::packet_core::Core::prepare(
            &mut self.packets,
            own,
            mac_id,
        )?);
        Ok(())
    }
    fn packet_start(&mut self) -> Result<(), crate::rtw88::packet_core::Error> {
        self.packet_with(|core, port| core.start(port))
    }
    fn packet_ready(&self) -> bool {
        self.packets.active
            && self
                .core
                .as_ref()
                .is_some_and(crate::rtw88::packet_core::Core::ready)
    }
    fn packet_submit(
        &mut self,
        frame: &[u8],
        report: bool,
    ) -> Result<u64, crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        self.packet_with(|core, port| core.submit(port, frame, report))
    }
    fn packet_poll(
        &mut self,
    ) -> Result<crate::rtw88::packet_core::Step, crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        self.packet_with(|core, port| core.poll(port))
    }
    fn packet_stop(&mut self) -> Result<(), crate::rtw88::packet_core::Error> {
        self.packet_with(|core, port| core.stop(port))
    }
    async fn delay_us(&mut self, us: u64) {
        self.base.delay_us(us).await;
        if self.pause_command && self.pending {
            core::future::pending::<()>().await;
        }
        if self.finished {
            self.clock.fetch_add(us.div_ceil(1000), Ordering::AcqRel);
            core::future::poll_fn(|cx| {
                if self.mailbox_pause.load(Ordering::Acquire) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
    }
}
fn seeded_dack() -> RadioIo {
    RadioIo::reference()
}
fn smoke_rtw8822ce_radio_dack_channel_trims_and_h2c_match_frozen_references() -> TestResult {
    let mut io = seeded_dack();
    let result = narf_scheduler::block_on(dack::calibrate(&mut io));
    if !matches!(
        result,
        Ok(dack::Info {
            adc: [0, 0],
            residual: [[0, 0], [0, 0]]
        })
    ) {
        return TestResult::Fail("fresh native ADC/DAC convergence failed");
    }
    let trace: Vec<_> = io.base.trace.iter().copied().filter(|v| v.0 != 0).collect();
    if trace != LINUX_DACK {
        return TestResult::Fail("DACK writes/delays diverged from the frozen reference");
    }
    let mut io = RadioIo::reference();
    let mut raw = [255; 768];
    raw[0x120..0x126].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    let trims = core::array::from_fn(|i| 0x21u8.wrapping_add(i as u8 * 7));
    let factory = Factory::for_test_with_trims(raw, trims).unwrap();
    let result = narf_scheduler::block_on(async {
        radio::trx(&mut io)?;
        radio::channel(&mut io).await?;
        radio::trims(&mut io, &factory).await
    });
    if result.is_err() {
        return TestResult::Fail("source fixed TRX/channel/OTP rejected");
    }
    let trace: Vec<_> = io.base.trace.iter().copied().filter(|v| v.0 != 0).collect();
    if trace != LINUX_RADIO {
        return TestResult::Fail("TRX/channel/OTP diverged from the frozen reference");
    }
    let mut io = RadioIo::reference();
    if radio::gains(&mut io, [36, 32]).is_err() {
        return TestResult::Fail("source response gain plan rejected");
    }
    let trace: Vec<_> = io.base.trace.iter().copied().filter(|v| v.0 != 0).collect();
    if trace != LINUX_GAIN {
        return TestResult::Fail("native response gain/RRSR plan diverged from source callbacks");
    }
    let mut io = RadioIo::reference();
    if radio::receive_policy(&mut io).is_err() {
        return TestResult::Fail("source fixed EDCCA rejected");
    }
    let trace: Vec<_> = io.base.trace.iter().copied().filter(|v| v.0 != 0).collect();
    if trace != LINUX_EDCCA {
        return TestResult::Fail("fixed IGI/EDCCA differs from source adaptive threshold");
    }
    let mac = crate::rtw88::mac::Info {
        cut: 3,
        reserved_boundary: 1938,
        h2c_page: 1986,
        firmware_tx_page: 1994,
    };
    let phy = crate::rtw88::phy::Info {
        cut: 3,
        rfe: 5,
        paths: 2,
        crystal: 0x33,
    };
    if [
        command::general(mac, 0).unwrap(),
        command::phydm(phy, 1).unwrap(),
        command::iqk(2),
    ] != LINUX_H2C
    {
        return TestResult::Fail("H2C packets diverged from original header/field functions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_radio_dack_channel_trims_and_h2c_match_frozen_references
);
fn smoke_rtw8822ce_h2c_native_ring_occupancy_wrap_and_exact_retirement() -> TestResult {
    let mut ring = command::Ring::default();
    let mut bytes = [0u8; 80];
    for ordinal in 0..1024u16 {
        let slot = ordinal % 128;
        let current = u32::from(slot);
        let (reserved, next) = match ring.reserve(current | current << 16) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("exact empty H2C head did not reserve"),
        };
        if reserved != slot || next != (slot + 1) % 128 {
            return TestResult::Fail("H2C wrap selected wrong descriptor");
        }
        bytes.fill(ordinal as u8);
        let saved = bytes;
        // Production calls reserve before payload/BD copies. Busy and invalid
        // indices cannot authorize any mutation or consume the pending slot.
        if ring.reserve(u32::from(next) | u32::from(next) << 16) != Err(Error::State)
            || ring.poll(u32::from(next) | current << 16) != Ok(false)
            || bytes != saved
        {
            return TestResult::Fail("pending H2C command was reused before terminal DMA head");
        }
        let wrong = (u32::from(next) + 1) % 128;
        if ring.poll(u32::from(next) | wrong << 16) != Err(Error::Prerequisite) || !ring.pending() {
            return TestResult::Fail("foreign terminal H2C index released command ownership");
        }
        if ring.poll(u32::from(next) | u32::from(next) << 16) != Ok(true) || ring.pending() {
            return TestResult::Fail("exact H2C terminal DMA head did not retire");
        }
    }
    for index in [1, 1 << 16, 128 << 16, 0xfff << 16, u32::MAX] {
        let mut ring = command::Ring::default();
        if ring.reserve(index).is_ok() || ring.pending() {
            return TestResult::Fail("invalid initial H2C head committed occupancy");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_h2c_native_ring_occupancy_wrap_and_exact_retirement
);
type Prepared = (
    Owner<RadioIo>,
    Factory,
    Permission,
    narf_wireless::reg::RegulatoryDomain,
    narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
);
fn prepared() -> Prepared {
    let mut owner = Owner::new(RadioIo::new(), 0xc822);
    narf_scheduler::block_on(owner.download(&super::mac_tests::firmware())).unwrap();
    narf_scheduler::block_on(owner.prepare_mac()).unwrap();
    let factory = super::power_policy_tests::make_factory(0, 60);
    narf_scheduler::block_on(owner.prepare_phy_tables(&factory)).unwrap();
    let board = Board::new(
        &factory,
        owner.phy_info().unwrap(),
        owner.hardware_info().unwrap(),
        owner.image_digest().unwrap(),
    )
    .unwrap();
    let policy = super::power_policy_tests::domain();
    let cap = narf_capabilities::Cap::bootstrap();
    let source =
        super::power_policy_tests::source(super::power_policy_tests::image(board, &factory), cap);
    let permission = owner.qualify_with(&factory, &policy, source).unwrap();
    owner.io.radio = true;
    owner.io.base.trace.clear();
    owner.io.base.regs[0x670..0x674].fill(0);
    owner.io.base.regs[0x3d9..0x3db].fill(0);
    owner.io.base.regs[0x1d70..0x1d74].copy_from_slice(&0x30303030u32.to_le_bytes());
    (owner, factory, permission, policy, cap)
}
fn smoke_rtw8822ce_retained_firmware_to_calibrated_radio_requires_actual_receipts() -> TestResult {
    let (mut owner, factory, permission, policy, _) = prepared();
    let result =
        narf_scheduler::block_on(
            owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
        );
    if !matches!(
        result,
        Ok(radio::Info {
            channel: 1,
            gains: [36, 32],
            adc_dc: [0, 0],
            residual: [[0, 0], [0, 0]],
            ..
        })
    ) || owner.phase() != Phase::Calibrated
        || !owner.io.finished
        || owner.io.pending
        || owner.io.commands.len() != 3
        || owner.io.base.regs[0x100] & 0xcf != 0
        || owner.io.base.regs[0x101] & 2 != 0
        || owner.io.word(0x680) & 0xcf != 0
    {
        return TestResult::Fail(
            "actual retained firmware/PHY/qualification did not reach closed calibrated radio",
        );
    }
    let calls = owner.io.base.trace.len();
    if narf_scheduler::block_on(
        owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
    ) != Err(Error::State)
        || owner.io.base.trace.len() != calls
    {
        return TestResult::Fail("one-shot calibrated radio replayed");
    }
    for failure in 0..8 {
        let (mut owner, factory, permission, policy, _) = prepared();
        match failure {
            0 => owner.io.hold_dma = true,
            1 => owner.io.no_iqk = true,
            2 => owner.io.stale_iqk = true,
            3 => owner.io.cam_stuck = true,
            4 => owner.io.awake_stuck = true,
            5 => owner.io.bad_samples = true,
            6 => owner.io.lost = Some(0x18a0),
            _ => owner.io.lost = Some(0x440),
        }
        if narf_scheduler::block_on(
            owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
        )
        .is_ok()
            || owner.phase() != Phase::Failed
            || owner.io.finished
            || owner.radio_info().is_some()
        {
            return TestResult::Fail(
                "missing DMA/IQK/CAM/awake/DACK receipt fabricated calibration success",
            );
        }
        let calls = owner.io.base.trace.len();
        if narf_scheduler::block_on(
            owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
        ) != Err(Error::State)
            || owner.io.base.trace.len() != calls
        {
            return TestResult::Fail("failed radio owner retried ambiguous hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_retained_firmware_to_calibrated_radio_requires_actual_receipts
);
fn smoke_rtw8822ce_radio_current_policy_revocation_cancel_and_path_backup() -> TestResult {
    let mut io = seeded_dack();
    io.base.regs[0x3e3c..0x3e40].copy_from_slice(&0x12345u32.to_le_bytes());
    io.base.regs[0x4e3c..0x4e40].copy_from_slice(&0x56789u32.to_le_bytes());
    if narf_scheduler::block_on(dack::calibrate(&mut io)).is_err()
        || io.word(0x3e3c) & 0xfffff != 0x12345
        || io.word(0x4e3c) & 0xfffff != 0x56789
    {
        return TestResult::Fail("separate path originals aliased during DACK restoration");
    }
    let (mut owner, factory, permission, policy, cap) = prepared();
    cap.revoke();
    if narf_scheduler::block_on(
        owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
    ) != Err(Error::Power(crate::rtw88::power_policy::Error::Authority))
        || !owner.io.base.trace.is_empty()
    {
        return TestResult::Fail("revoked calibration asset touched radio");
    }
    let (mut owner, factory, permission, policy, _) = prepared();
    let calls = AtomicUsize::new(0);
    let result =
        narf_scheduler::block_on(owner.prepare_radio_with_policy(&factory, permission, || {
            let mut domain = policy.clone();
            if calls.fetch_add(1, Ordering::SeqCst) > 10 {
                domain.rules[0].max_power_dbm = 10;
            }
            Ok(domain)
        }));
    if result != Err(Error::Power(crate::rtw88::power_policy::Error::Policy))
        || owner.io.finished
        || !owner.io.commands.is_empty()
    {
        return TestResult::Fail("live isolated policy restriction allowed another radio stage");
    }
    let (mut owner, factory, permission, policy, _) = prepared();
    owner.io.pause_command = true;
    let mut future =
        alloc::boxed::Box::pin(
            owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
        );
    if !matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return TestResult::Fail("fixture failed to suspend pending native command");
    }
    drop(future);
    if owner.phase() != Phase::Failed
        || !owner.io.pending
        || owner.io.commands.len() != 1
        || owner.io.finished
        || narf_scheduler::block_on(
            owner.prepare_radio_with_policy(&factory, permission, || Ok(policy.clone())),
        ) != Err(Error::State)
    {
        return TestResult::Fail("cancelled H2C dropped ownership or reopened radio calibration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_radio_current_policy_revocation_cancel_and_path_backup
);

fn smoke_rtw8822ce_staged_policy_preserves_phy_checkpoint_and_resumes_same_owner() -> TestResult {
    use crate::rtw88::firmware_lifecycle::{Lifecycle, Stage};
    use crate::rtw88::firmware_transport::Phase;
    let lifecycle = Lifecycle::new(0xc822);
    let allocations = AtomicUsize::new(0);
    narf_scheduler::block_on(lifecycle.initialize_bytes(
        || {
            allocations.fetch_add(1, Ordering::SeqCst);
            Ok(RadioIo::new())
        },
        super::mac_tests::firmware(),
    ))
    .unwrap();
    narf_scheduler::block_on(lifecycle.prepare_mac()).unwrap();
    let factory = super::power_policy_tests::make_factory(0, 60);
    narf_scheduler::block_on(lifecycle.prepare_phy_tables(&factory)).unwrap();
    let domain = super::power_policy_tests::domain();
    let (board, pointer, trace) = {
        let retained = lifecycle.retained.try_lock().unwrap();
        let owner = retained.as_ref().unwrap();
        (
            Board::new(
                &factory,
                owner.phy_info().unwrap(),
                owner.hardware_info().unwrap(),
                owner.image_digest().unwrap(),
            )
            .unwrap(),
            owner as *const _ as usize,
            owner.io.base.trace.clone(),
        )
    };
    let cap = narf_capabilities::Cap::bootstrap();
    if narf_scheduler::block_on(lifecycle.qualify_board_with_source(
        &factory,
        &domain,
        super::power_policy_tests::source(Vec::new(), cap),
    ))
    .is_ok()
        || lifecycle.status().stage != Stage::PhyTablesPrepared
    {
        return TestResult::Fail("invalid staged board artifact consumed PHY checkpoint");
    }
    let permission = narf_scheduler::block_on(lifecycle.qualify_board_with_source(
        &factory,
        &domain,
        super::power_policy_tests::source(super::power_policy_tests::image(board, &factory), cap),
    ))
    .unwrap();
    let error = Error::Power(crate::rtw88::power_policy::Error::Policy);
    if narf_scheduler::block_on(
        lifecycle.prepare_radio_with_policy(&factory, permission, || Err(error)),
    ) != Err(error)
        || lifecycle.status().stage != Stage::PhyTablesPrepared
    {
        return TestResult::Fail("pure current-policy failure consumed calibration attempt");
    }
    {
        let mut retained = lifecycle.retained.try_lock().unwrap();
        let owner = retained.as_mut().unwrap();
        if owner.phase() != Phase::PhyTablesPrepared
            || owner as *const _ as usize != pointer
            || owner.io.base.trace != trace
        {
            return TestResult::Fail("asset/policy staging touched/replaced native hardware owner");
        }
        owner.io.arm_calibration();
        *owner.io.policy.lock() = domain.clone();
    }
    if narf_scheduler::block_on(
        lifecycle.prepare_radio_with_policy(&factory, permission, || Ok(domain.clone())),
    )
    .is_err()
        || lifecycle.status().stage != Stage::Calibrated
        || allocations.load(Ordering::SeqCst) != 1
    {
        return TestResult::Fail("later valid policy could not continue actual retained radio");
    }
    let retained = lifecycle.retained.try_lock().unwrap();
    let owner = retained.as_ref().unwrap();
    if owner as *const _ as usize != pointer
        || owner.phase() != Phase::Calibrated
        || owner.radio_info().is_none()
        || !owner.io.finished
        || owner.io.packets.tx_publications != 0
    {
        return TestResult::Fail("resumed calibration reconstructed owner or published packets");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_staged_policy_preserves_phy_checkpoint_and_resumes_same_owner
);
