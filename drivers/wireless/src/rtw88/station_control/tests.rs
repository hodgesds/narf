use super::*;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
include!("dcf_golden.rs");
struct Confirm;
impl narf_capabilities::CapOp<narf_firmware::FirmwareBlob, narf_capabilities::Read> for Confirm {
    type Output = ();
    fn execute(
        self,
        _: &narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    ) -> Result<(), narf_capabilities::CapError> {
        Ok(())
    }
}
struct Model {
    regs: Vec<u8>,
    commands: Vec<[u8; 8]>,
    pending: bool,
    cursor: u8,
    slots: Vec<u8>,
    ready_hold: bool,
    consumed_hold: bool,
    pause: bool,
    close: Option<Admission>,
    allowed: bool,
    ignore_write: Option<u16>,
    restrict_after: Option<u16>,
    writes: Vec<u16>,
    cap: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
}
impl Model {
    fn new() -> Self {
        Self {
            regs: vec![0; 0x700],
            commands: Vec::new(),
            pending: false,
            cursor: 0,
            slots: Vec::new(),
            ready_hold: false,
            consumed_hold: false,
            pause: false,
            close: None,
            allowed: true,
            ignore_write: None,
            restrict_after: None,
            writes: Vec::new(),
            cap: narf_capabilities::Cap::bootstrap(),
        }
    }
    fn word(&self, r: usize) -> u32 {
        u32::from_le_bytes(self.regs[r..r + 4].try_into().unwrap())
    }
}
#[async_trait::async_trait]
// SAFETY: isolated firmware register/mailbox model, never a physical BAR or
// DMA mapping. Actual current capability epochs authorize simulated controls.
unsafe impl Io for Model {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        Ok(self.regs[usize::from(r)])
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        let p = usize::from(r);
        Ok(u16::from_le_bytes(self.regs[p..p + 2].try_into().unwrap()))
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        Ok(self.word(usize::from(r)))
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.writes.push(r);
        if self.ignore_write != Some(r) {
            self.regs[usize::from(r)] = v;
        }
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        let p = usize::from(r);
        self.regs[p..p + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.writes.push(r);
        let p = usize::from(r);
        if self.ignore_write != Some(r) {
            self.regs[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        if self.restrict_after == Some(r) {
            self.allowed = false;
        }
        Ok(())
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::State)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        if !self.allowed {
            return Err(Error::Power(crate::rtw88::power_policy::Error::Policy));
        }
        self.cap.invoke(Confirm).map_err(|_| Error::Access)
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.station_allowed()?;
        Ok([2, 4, 6, 8, 10, 12])
    }
    fn mailbox_pending(&self) -> bool {
        self.pending
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        if self.pending {
            Err(Error::State)
        } else {
            Ok(!self.ready_hold)
        }
    }
    fn mailbox_submit(&mut self, words: [u8; 8]) -> Result<(), Error> {
        if !self.mailbox_ready()? {
            return Err(Error::State);
        }
        if words != [1, 0, 0, 0, 0, 0, 0, 0] {
            self.station_allowed()?;
        }
        self.pending = true;
        self.commands.push(words);
        self.slots.push(self.cursor);
        Ok(())
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        if !self.pending {
            return Err(Error::State);
        }
        if self.consumed_hold {
            return Ok(false);
        }
        self.pending = false;
        self.cursor = (self.cursor + 1) % 4;
        Ok(true)
    }
    async fn delay_us(&mut self, _: u64) {
        if let Some(close) = self.close.take() {
            close.close();
        }
        if self.pause {
            core::future::pending::<()>().await;
        }
    }
}
fn smoke_rtw8822ce_station_controls_bind_source_port_peer_and_real_mailbox_consumption(
) -> TestResult {
    let mut io = Model::new();
    let admission = Admission::new();
    let peer = [2, 3, 5, 7, 11, 13];
    let result = narf_scheduler::block_on(async {
        prepare_initial(&mut io, [2, 4, 6, 8, 10, 12], &admission).await?;
        if io.regs[0x51b] != LINUX_INITIAL_SLOT {
            return Err(Error::Prerequisite);
        }
        for register in [0x500, 0x504, 0x508, 0x50c] {
            if io.word(register) != (LINUX_DCF[0][0] & 0x07ff_ffff) {
                return Err(Error::Prerequisite);
            }
        }
        prepare_peer(&mut io, peer, &admission).await?;
        commit_peer(&mut io, peer, 42, true, &admission).await
    });
    if result.is_err()
        || io.commands != LINUX_MAILBOX
        || io.slots != [0, 1, 2, 3, 0, 1]
        || io.regs[0x610..0x616] != [2, 4, 6, 8, 10, 12]
        || io.regs[0x618..0x61e] != peer
        || io.word(0x100) & 0x30000 != 2 << 16
        || io.word(0x6a8) & 0x7ff != 42
        || io.regs[0x550] & 8 != 0
        || io.regs[0x51b] != 9
        || [0x500, 0x504, 0x508, 0x50c]
            .iter()
            .any(|r| io.word(*r) != (LINUX_DCF[1][0] & 0x07ff_ffff))
        || io.pending
    {
        return TestResult::Fail(
            "retained port0/fixed peer/RA/media/defaultport differs from source",
        );
    }
    admission.close();
    if narf_scheduler::block_on(disconnect(&mut io, peer)).is_err()
        || io.commands.last() != Some(&[1, 0, 0, 0, 0, 0, 0, 0])
        || io.word(0x100) & 0x30000 != 0
        || io.word(0x6a8) & 0x7ff != 0
        || io.regs[0x618..0x61e] != [0; 6]
    {
        return TestResult::Fail("closed publication gate prevented bounded native disconnect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_station_controls_bind_source_port_peer_and_real_mailbox_consumption
);

fn smoke_rtw8822ce_station_dcf_matches_original_non_qos_defaults_and_fails_closed() -> TestResult {
    for (short, expected) in [false, true].into_iter().zip(LINUX_DCF) {
        let mut io = Model::new();
        for register in [0x500usize, 0x504, 0x508, 0x50c] {
            io.regs[register..register + 4].copy_from_slice(&0xf8ff_ffffu32.to_le_bytes());
        }
        if configure_dcf(&mut io, short, &Admission::new()).is_err()
            || [0x500, 0x504, 0x508, 0x50c]
                .into_iter()
                .zip(expected)
                .any(|(r, word)| io.word(r) != word)
            || io.regs[0x51b] != if short { 9 } else { 20 }
            || io.writes != [0x500, 0x504, 0x508, 0x50c, 0x51b]
        {
            return TestResult::Fail("non-QoS CCK DCF differs from original mac80211/rtw88 output");
        }
    }
    for lost in [0x500, 0x504, 0x508, 0x50c, 0x51b] {
        let mut io = Model::new();
        io.ignore_write = Some(lost);
        if configure_dcf(&mut io, false, &Admission::new()) != Err(Error::Prerequisite)
            || io.writes.last() != Some(&lost)
            || !io.commands.is_empty()
        {
            return TestResult::Fail(
                "lost DCF/slot write fabricated readiness or published later controls",
            );
        }
    }
    let mut io = Model::new();
    let closed = Admission::new();
    closed.close();
    if configure_dcf(&mut io, false, &closed) != Err(Error::State) || !io.writes.is_empty() {
        return TestResult::Fail("closed admission published new DCF parameters");
    }
    io.cap.revoke();
    if configure_dcf(&mut io, false, &Admission::new()) != Err(Error::Access)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("revoked calibration authority published DCF parameters");
    }
    let mut io = Model::new();
    io.restrict_after = Some(0x500);
    if configure_dcf(&mut io, false, &Admission::new())
        != Err(Error::Power(crate::rtw88::power_policy::Error::Policy))
        || io.writes != [0x500]
        || io.regs[0x51b] != 0
        || !io.commands.is_empty()
    {
        return TestResult::Fail("restricted current policy completed DCF/slot publication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_station_dcf_matches_original_non_qos_defaults_and_fails_closed
);
fn smoke_rtw8822ce_station_control_close_cancel_revocation_and_missing_receipts_stay_closed(
) -> TestResult {
    let peer = [2, 3, 5, 7, 11, 13];
    let admission = Admission::new();
    let mut io = Model::new();
    io.ready_hold = true;
    io.close = Some(admission.clone());
    if narf_scheduler::block_on(prepare_peer(&mut io, peer, &admission)) != Err(Error::State)
        || !io.commands.is_empty()
    {
        return TestResult::Fail(
            "close while waiting allowed a later connected mailbox publication",
        );
    }
    let admission = Admission::new();
    let mut io = Model::new();
    io.consumed_hold = true;
    io.close = Some(admission.clone());
    if narf_scheduler::block_on(commit_peer(&mut io, peer, 42, false, &admission))
        != Err(Error::State)
        || io.commands != [[1, 1, 0, 0, 0, 0, 0, 0]]
        || !io.pending
        || io.word(0x100) & 0x30000 != 0
    {
        return TestResult::Fail(
            "close during outstanding media receipt published association state",
        );
    }
    io.consumed_hold = false;
    if narf_scheduler::block_on(disconnect(&mut io, peer)).is_err()
        || io.pending
        || io.commands.len() != 2
    {
        return TestResult::Fail("terminal disconnect lost/drained wrong pending mailbox owner");
    }
    let admission = Admission::new();
    let mut io = Model::new();
    io.cap.revoke();
    if narf_scheduler::block_on(prepare_initial(&mut io, [2, 4, 6, 8, 10, 12], &admission))
        != Err(Error::Access)
        || !io.commands.is_empty()
        || io.regs.iter().any(|v| *v != 0)
    {
        return TestResult::Fail("revoked source authority mutated station controls");
    }
    for hold_ready in [true, false] {
        let admission = Admission::new();
        let mut io = Model::new();
        io.ready_hold = hold_ready;
        io.consumed_hold = !hold_ready;
        if narf_scheduler::block_on(prepare_peer(&mut io, peer, &admission)) != Err(Error::Timeout)
            || io.commands.len() != usize::from(!hold_ready)
            || io.pending == hold_ready
        {
            return TestResult::Fail("missing mailbox readiness/consumption fabricated success");
        }
    }
    let admission = Admission::new();
    let mut io = Model::new();
    io.consumed_hold = true;
    io.pause = true;
    let mut future = Box::pin(prepare_peer(&mut io, peer, &admission));
    if !matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return TestResult::Fail("fixture did not suspend actual pending mailbox");
    }
    drop(future);
    admission.close();
    if !io.pending || io.commands.len() != 1 {
        return TestResult::Fail("cancellation forgot pending mailbox identity");
    }
    io.pause = false;
    io.consumed_hold = false;
    if narf_scheduler::block_on(disconnect(&mut io, peer)).is_err() || io.commands.len() != 2 {
        return TestResult::Fail("cancelled mailbox prevented safe terminal teardown");
    }
    let before = io.commands.len();
    if narf_scheduler::block_on(prepare_peer(&mut io, peer, &admission)) != Err(Error::State)
        || io.commands.len() != before
    {
        return TestResult::Fail("closed admission reopened peer firmware state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_station_control_close_cancel_revocation_and_missing_receipts_stay_closed
);
fn smoke_rtw8822ce_disconnect_reservation_preserves_cleanup_then_cancel_allows_terminal_stop(
) -> TestResult {
    let admission = Admission::new();
    let disconnect = match admission.begin_disconnect() {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("fresh disconnect reservation failed"),
    };
    if !admission.closed()
        || !admission.teardown_pending()
        || !matches!(admission.begin_disconnect(), Err(Error::State))
    {
        return TestResult::Fail(
            "disconnect failed to atomically close and retain one cleanup owner",
        );
    }
    admission.close();
    if !admission.teardown_pending() {
        return TestResult::Fail("generic close stole pending native teardown ownership");
    }
    let mut published = false;
    if admission.run(|| {
        published = true;
        Ok(())
    }) != Err(Error::State)
        || published
    {
        return TestResult::Fail("pending disconnect admitted another hardware publication");
    }
    // A worker preserves native controls while this explicit owner waits for
    // the lifecycle mutex. Dropping that owner represents cancellation there.
    let worker_stops = || admission.closed() && !admission.teardown_pending();
    if worker_stops() {
        return TestResult::Fail(
            "closed worker would poison native teardown before mutex acquisition",
        );
    }
    drop(disconnect);
    if !admission.closed() || !worker_stops() {
        return TestResult::Fail(
            "cancelled teardown reopened publication or stranded native shutdown",
        );
    }
    // A later explicit cleanup may reserve the still-closed terminal owner;
    // it cannot convert that cleanup into station/ring reuse.
    let next = admission.begin_disconnect().unwrap();
    if !admission.closed() || !admission.teardown_pending() {
        return TestResult::Fail("terminal cleanup reservation reopened station");
    }
    drop(next);
    if !admission.closed() || admission.teardown_pending() {
        return TestResult::Fail("completed cleanup reservation did not retire exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_disconnect_reservation_preserves_cleanup_then_cancel_allows_terminal_stop
);
