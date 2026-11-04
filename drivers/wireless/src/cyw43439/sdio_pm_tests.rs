//! CYW43439 SDIO system suspend/resume (`sdio_pm.rs`, `runtime_pm.rs`).
//! Written for the kernel-test harness.

use super::*;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use narf_drivers_sdio::PmFlags;

const KEEP_WAKE: PmFlags = PmFlags::KEEP_POWER.union(PmFlags::WAKE_SDIO_IRQ);

fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn sr_transport(caps: PmFlags) -> Option<SdioTransport<Host>> {
    let mut host = sleep_host(1);
    host.pm_caps = caps;
    let mut transport = SdioTransport::new(host);
    transport.prepare().ok()?;
    transport.initialize_packets(CORE).ok()?;
    (transport.initialize_sleep(13) == Ok(true)).then_some(transport)
}

fn reg(t: &SdioTransport<Host>, f: u8, a: u32) -> u8 {
    t.func.regs.get(&(f, a)).copied().unwrap_or(0)
}

fn smoke_cyw_sdio_wowl_supported_needs_keep_power_and_wake_irq() -> TestResult {
    // brcmf_sdio_probe_attach: KEEP_POWER && (WAKE_SDIO_IRQ || OOB).
    for (caps, line, expected) in [
        (PmFlags::NONE, true, false),
        (PmFlags::KEEP_POWER, true, false),
        (PmFlags::WAKE_SDIO_IRQ, true, false),
        (KEEP_WAKE, false, false),
        (KEEP_WAKE, true, true),
    ] {
        let mut transport = SdioTransport::new(Host {
            line,
            pm_caps: caps,
            ..Host::default()
        });
        if transport.prepare().is_err() || transport.initialize_packets(CORE).is_err() {
            return TestResult::Fail("packet init");
        }
        if transport.wowl_supported() != expected {
            return TestResult::Fail("wowl_supported differs from brcmf_sdio_probe_attach");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_wowl_supported_needs_keep_power_and_wake_irq
);

fn smoke_cyw_sdio_suspend_kso_sleeps_and_keeps_power_like_linux() -> TestResult {
    let Some(mut transport) = sr_transport(KEEP_WAKE) else {
        return TestResult::Fail("SR transport setup");
    };
    // brcmf_ops_sdio_suspend with wowl_enabled: KSO sleep, then
    // KEEP_POWER | WAKE_SDIO_IRQ host flags.
    if transport.suspend_bus(true).is_err() {
        return TestResult::Fail("keep-power WoWL suspend refused");
    }
    if transport.func.pm_suspended != Some(KEEP_WAKE)
        || reg(&transport, 1, 0x1001f) & 1 != 0
        || !transport.asleep()
    {
        return TestResult::Fail("dongle not in KSO sleep under keep-power wake flags");
    }
    // Frozen DPC: no card access, no failure, no rearm.
    let mut bytes = vec![0; super::super::super::runtime::MAX_PACKET];
    let ops = transport.func.ops.len();
    let rearmed = transport.func.rearmed;
    let mut frame = vec![0; 64];
    frame[..4].copy_from_slice(&[64, 0, !64u8, 0xff]);
    transport.interrupt_serviced();
    transport.idle();
    if transport.receive_packet(&mut bytes) != Ok(0)
        || transport.transmit_packet(&frame) != Err(TransportError::Busy)
        || transport.func.ops.len() != ops
        || transport.func.rearmed != rearmed
        || transport.failed
    {
        return TestResult::Fail("suspended transport touched the card");
    }
    if transport.suspend_bus(true) != Err(TransportError::Busy) {
        return TestResult::Fail("double suspend accepted");
    }
    // brcmf_ops_sdio_resume: host resume, then KSO wake + HT available.
    if transport.resume_bus().is_err()
        || transport.func.pm_suspended.is_some()
        || transport.asleep()
        || reg(&transport, 1, 0x1001f) & 3 != 3
        || transport.failed
    {
        return TestResult::Fail("resume did not wake the dongle");
    }
    if transport.receive_packet(&mut bytes).is_err() {
        return TestResult::Fail("resumed transport not usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_suspend_kso_sleeps_and_keeps_power_like_linux
);

fn smoke_cyw_sdio_suspend_refuses_without_keep_power() -> TestResult {
    // No keep-power grant: Linux would remove and re-probe the device;
    // NARF refuses before touching the dongle so the suspend unwinds.
    let Some(mut transport) = sr_transport(PmFlags::NONE) else {
        return TestResult::Fail("SR transport setup");
    };
    let ops = transport.func.ops.len();
    if transport.suspend_bus(false) != Err(TransportError::NotReady)
        || transport.func.ops.len() != ops
        || transport.failed
        || transport.asleep()
    {
        return TestResult::Fail("suspend without keep-power changed the dongle");
    }
    // Keep power without a wake grant refuses an armed WoWL suspend.
    let Some(mut transport) = sr_transport(PmFlags::KEEP_POWER) else {
        return TestResult::Fail("SR transport setup");
    };
    if transport.suspend_bus(true) != Err(TransportError::NotReady) || transport.asleep() {
        return TestResult::Fail("WoWL suspend accepted without a wake path");
    }
    // A plain keep-power suspend is fine; a card that lost power fails
    // resume terminally.
    if transport.suspend_bus(false).is_err() {
        return TestResult::Fail("plain keep-power suspend refused");
    }
    transport.func.pm_lost = true;
    if transport.resume_bus().is_ok() || !transport.failed {
        return TestResult::Fail("resume of a dongle that lost power succeeded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_suspend_refuses_without_keep_power
);

fn smoke_cyw_sdio_non_sr_suspend_drops_clock_request() -> TestResult {
    let mut host = sleep_host(0);
    host.pm_caps = PmFlags::KEEP_POWER;
    let mut transport = SdioTransport::new(host);
    if transport.prepare().is_err()
        || transport.initialize_packets(CORE).is_err()
        || transport.initialize_sleep(13) != Ok(false)
    {
        return TestResult::Fail("non-SR setup");
    }
    transport.func.regs.insert((1, 0x1000e), 0x02);
    // brcmf_sdio_clkctl(CLK_NONE) -> brcmf_sdio_htclk(false): clkreq 0.
    if transport.suspend_bus(false).is_err() || reg(&transport, 1, 0x1000e) != 0 {
        return TestResult::Fail("non-SR suspend kept the backplane clock request");
    }
    // CLK_AVAIL: SBSDIO_HT_AVAIL_REQ, then HT available.
    if transport.resume_bus().is_err() || reg(&transport, 1, 0x1000e) != 0x10 {
        return TestResult::Fail("non-SR resume did not request HT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_non_sr_suspend_drops_clock_request
);

fn smoke_cyw_runtime_suspend_follows_wowl_config() -> TestResult {
    let Some(transport) = sr_transport(KEEP_WAKE) else {
        return TestResult::Fail("SR transport setup");
    };
    let mut runtime = super::super::super::runtime::Runtime::new(transport);
    if !runtime.wowl_supported() {
        return TestResult::Fail("runtime did not report the bus wowl support");
    }
    // brcmf_configure_wowl -> brcmf_bus_wowl_config(true).
    runtime.wowl_config(true);
    if ready(runtime.suspend_transport()) != Some(Ok(())) || !runtime.suspended() {
        return TestResult::Fail("runtime suspend failed");
    }
    if runtime.poll() != Ok(0)
        || ready(runtime.command(super::super::super::ioctl::Direction::Get, 1, &[], 4))
            != Some(Err(super::super::super::runtime::Error::Busy))
        || runtime.is_failed()
    {
        return TestResult::Fail("suspended runtime reached the bus");
    }
    if ready(runtime.resume_transport()) != Some(Ok(())) || runtime.suspended() {
        return TestResult::Fail("runtime resume failed");
    }
    runtime.wowl_config(false);
    // Not suspended: a stray resume is refused without failing.
    if ready(runtime.resume_transport()) != Some(Err(super::super::super::runtime::Error::Busy))
        || runtime.is_failed()
    {
        return TestResult::Fail("stray resume changed the runtime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_runtime_suspend_follows_wowl_config
);
