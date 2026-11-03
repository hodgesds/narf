//! System suspend/resume of the owned card (`card_pm.rs`) against the
//! register model. Written for the kernel-test harness.

use super::*;
use crate::sdio::function::PmFlags;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[derive(Clone, Default)]
struct WakeLine {
    unmasks: Arc<AtomicU32>,
    wake: Arc<AtomicBool>,
}
impl crate::card::InterruptLine for WakeLine {
    fn unmask(&self) {
        self.unmasks.fetch_add(1, Ordering::AcqRel);
    }
    fn set_wake(&self, on: bool) -> bool {
        self.wake.store(on, Ordering::Release);
        true
    }
}

const KEEP_WAKE: PmFlags = PmFlags::KEEP_POWER.union(PmFlags::WAKE_SDIO_IRQ);

fn powered_card(pm: PmFlags) -> Option<(Card<Model>, Arc<IrqSafeSpinLock<State>>, WakeLine)> {
    let model = Model::new();
    let shared = model.0.clone();
    shared.lock().pm = pm;
    let mut card = Card::initialize(model, Config::default()).ok()?;
    let line = WakeLine::default();
    let subscriber = Arc::new(crate::card::Subscriber::default());
    if !card.attach_interrupt(alloc::boxed::Box::new(line.clone()), subscriber) {
        return None;
    }
    card.enable_func(1).ok()?;
    card.enable_func(2).ok()?;
    if card.enable_card_interrupt(0b110, Arc::new(|| {})) != Ok(true) {
        return None;
    }
    Some((card, shared, line))
}

fn smoke_sdio_keep_power_wake_suspend_resume_like_linux() -> TestResult {
    let Some((mut card, shared, line)) = powered_card(KEEP_WAKE) else {
        return TestResult::Fail("powered card with claimed interrupt unavailable");
    };
    if card.host().bus_width != 4 {
        return TestResult::Fail("fixture did not negotiate a 4-bit bus");
    }
    if card.host_pm_caps() != KEEP_WAKE {
        return TestResult::Fail("host PM capabilities not reported");
    }
    let commands = shared.lock().commands.len();
    let int_enable = shared.lock().get32(INT_ENABLE);
    let signal_enable = shared.lock().get32(SIGNAL_ENABLE);
    if card.suspend_host(KEEP_WAKE).is_err() {
        return TestResult::Fail("keep-power wake suspend refused");
    }
    {
        let s = shared.lock();
        // mmc_sdio_suspend -> sdio_disable_wide; sdhci_enable_irq_wakeups.
        if s.common[CCCR_BUS_IFACE as usize] & (BUS_IFACE_BW_MASK | BUS_IFACE_ASYNC_INT)
            != BUS_IFACE_ASYNC_INT
            || s.registers[HOST_CONTROL as usize] & CTRL_4BITBUS != 0
        {
            return TestResult::Fail("waking card was not dropped to 1-bit async interrupt");
        }
        if s.registers[WAKE_UP_CONTROL as usize] != WAKE_ON_INT
            || s.get32(INT_ENABLE) != INT_CARD_INT
            || s.get32(SIGNAL_ENABLE) & INT_CARD_INT == 0
        {
            return TestResult::Fail("SDHCI wake-on-card-interrupt not armed");
        }
        if s.registers[POWER_CONTROL as usize] & POWER_ON == 0 || s.get16(CLOCK_CONTROL) == 0 {
            return TestResult::Fail("keep-power suspend cut card power or clock");
        }
    }
    if !line.wake.load(Ordering::Acquire) {
        return TestResult::Fail("host line not armed with enable_irq_wake");
    }
    if card.cmd52_read(0, CCCR_IO_ENABLE) != Err(SdioError::Busy)
        || card.suspend_host(KEEP_WAKE) != Err(SdioError::Busy)
    {
        return TestResult::Fail("suspended card accepted a command");
    }
    if card.resume_host().is_err() {
        return TestResult::Fail("keep-power resume failed");
    }
    {
        let s = shared.lock();
        // No CMD0/CMD5/CMD3/CMD7: the card was not re-enumerated.
        if s.commands[commands..]
            .iter()
            .any(|(command, _, _)| matches!(command, 0 | 3 | 5 | 7))
        {
            return TestResult::Fail("keep-power resume re-enumerated the card");
        }
        if s.common[CCCR_BUS_IFACE as usize] & BUS_IFACE_BW_MASK != BUS_IFACE_BW_4BIT
            || s.registers[HOST_CONTROL as usize] & CTRL_4BITBUS == 0
        {
            return TestResult::Fail("4-bit bus not restored on resume");
        }
        if s.registers[WAKE_UP_CONTROL as usize] != 0
            || s.get32(INT_ENABLE) != int_enable
            || s.get32(SIGNAL_ENABLE) != signal_enable
        {
            return TestResult::Fail("SDHCI interrupt/wake state not restored");
        }
    }
    if line.wake.load(Ordering::Acquire) {
        return TestResult::Fail("resume left the line wake-armed");
    }
    if card.cmd52_read(0, CCCR_IO_ENABLE) != Ok(0b110) {
        return TestResult::Fail("resumed card lost its function enables");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_keep_power_wake_suspend_resume_like_linux
);

fn smoke_sdio_suspend_refuses_unadvertised_flags() -> TestResult {
    let Some((mut card, shared, line)) = powered_card(PmFlags::KEEP_POWER) else {
        return TestResult::Fail("powered card unavailable");
    };
    // sdio_set_host_pm_flags: -EINVAL for a flag the host lacks.
    if card.suspend_host(KEEP_WAKE) != Err(SdioError::Unsupported)
        || card.suspend_host(PmFlags::WAKE_SDIO_IRQ) != Err(SdioError::Unsupported)
        || card.suspended()
    {
        return TestResult::Fail("unadvertised wake flag accepted");
    }
    // Keep power without wake: every interrupt enable cleared, power kept.
    if card.suspend_host(PmFlags::KEEP_POWER).is_err() {
        return TestResult::Fail("keep-power suspend refused");
    }
    {
        let s = shared.lock();
        if s.get32(INT_ENABLE) != 0
            || s.get32(SIGNAL_ENABLE) != 0
            || s.registers[POWER_CONTROL as usize] & POWER_ON == 0
            || s.common[CCCR_BUS_IFACE as usize] & BUS_IFACE_BW_MASK != BUS_IFACE_BW_4BIT
        {
            return TestResult::Fail("non-waking keep-power suspend state differs from Linux");
        }
    }
    if line.wake.load(Ordering::Acquire) {
        return TestResult::Fail("non-waking suspend armed the line");
    }
    // The card lost power after all (D3cold): the CCCR receipt fails.
    shared.lock().common[CCCR_IO_ENABLE as usize] = 0;
    if card.resume_host() != Err(SdioError::HostError)
        || card.cmd52_read(0, CCCR_IO_ENABLE) != Err(SdioError::HostError)
    {
        return TestResult::Fail("resume of a card that lost power was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_suspend_refuses_unadvertised_flags
);

fn smoke_sdio_power_off_suspend_reenumerates_on_resume() -> TestResult {
    let Some((mut card, shared, _line)) = powered_card(PmFlags::NONE) else {
        return TestResult::Fail("powered card unavailable");
    };
    if card.host_pm_caps() != PmFlags::NONE
        || card.suspend_host(PmFlags::KEEP_POWER) != Err(SdioError::Unsupported)
    {
        return TestResult::Fail("keep power accepted without a host grant");
    }
    if card.suspend_host(PmFlags::NONE).is_err() {
        return TestResult::Fail("power-off suspend refused");
    }
    {
        let s = shared.lock();
        if s.registers[POWER_CONTROL as usize] != 0 || s.get16(CLOCK_CONTROL) != 0 {
            return TestResult::Fail("power-off suspend left card power on");
        }
    }
    let commands = shared.lock().commands.len();
    if card.resume_host().is_err() {
        return TestResult::Fail("power-off resume failed to re-enumerate");
    }
    let enumerated: Vec<u8> = shared.lock().commands[commands..]
        .iter()
        .map(|c| c.0)
        .take(5)
        .collect();
    if enumerated != [0, 5, 5, 3, 7] {
        return TestResult::Fail("power-off resume did not run mmc_sdio_reinit_card");
    }
    // Functions come back disabled for their driver to probe again.
    if card.cmd53_write(2, 0, &[1; 8]) != Err(SdioError::NotEnabled) {
        return TestResult::Fail("re-enumerated card kept a stale function enable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_power_off_suspend_reenumerates_on_resume
);
