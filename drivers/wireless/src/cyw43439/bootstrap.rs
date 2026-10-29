// SPDX-License-Identifier: GPL-2.0-or-later
//! SDIO function match → verified firmware → actual loader → FIFO station.
//! The SDHCI host hands over whole-card ownership, never a second F1 window.

use super::{firmware::FirmwareLoader, interface, sdio_bridge::SdioTransport};
use core::fmt::Write;
use narf_drivers_sdio::native::{FunctionDriver, NativeCard};

pub fn register() {
    for (name, vendor, device) in [
        ("cyw43439-sdio", 0x02d0, 0xa9af),
        ("cyw43439-cypress-sdio", 0x04b4, 0xbd3d),
    ] {
        let _ = narf_drivers_sdio::native::register_function_driver(FunctionDriver {
            name,
            vendor,
            device,
            function: 1,
            probe,
        });
    }
    narf_drivers_sdio::native::register_pci_driver();
}

/// A parked whole-card owner. Missing provisioning is retryable; once the
/// first F1/firmware mutation starts, cancellation/error is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvisionState {
    Parked = 0,
    Starting = 1,
    Ready = 2,
    Failed = 3,
}
pub struct Provisioner<R: narf_drivers_sdio::pio::Registers + Send + 'static> {
    card: narf_lib::mutex::Mutex<Option<narf_drivers_sdio::card::Card<R>>>,
    state: core::sync::atomic::AtomicU8,
}
impl<R: narf_drivers_sdio::pio::Registers + Send + 'static> core::fmt::Debug for Provisioner<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cyw43439Provisioner")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}
struct Attempt<'a>(&'a core::sync::atomic::AtomicU8);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        if self.0.load(Ordering::Acquire) == ProvisionState::Starting as u8 {
            self.0
                .store(ProvisionState::Failed as u8, Ordering::Release);
        }
    }
}
impl<R: narf_drivers_sdio::pio::Registers + Send + 'static> Provisioner<R> {
    pub fn new(card: narf_drivers_sdio::card::Card<R>) -> Self {
        Self {
            card: narf_lib::mutex::Mutex::new(Some(card)),
            state: core::sync::atomic::AtomicU8::new(ProvisionState::Parked as u8),
        }
    }
    pub fn state(&self) -> ProvisionState {
        use core::sync::atomic::Ordering;
        match self.state.load(Ordering::Acquire) {
            0 => ProvisionState::Parked,
            1 => ProvisionState::Starting,
            2 => ProvisionState::Ready,
            _ => ProvisionState::Failed,
        }
    }
    pub async fn provision(&self) -> Result<(), &'static str> {
        if narf_net::trusted_net_authority().is_none() {
            return Err("network registration authority unavailable");
        }
        let authority = crate::brcmfmac::provision::authority()
            .map_err(|_| "firmware authority unavailable")?;
        self.provision_using(&authority, crate::brcmfmac::provision::MANIFEST)
            .await
    }
    pub(crate) async fn provision_using(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        manifest: &str,
    ) -> Result<(), &'static str> {
        self.provision_checked(authority, manifest, || {
            narf_wireless::reg::db::ensure_domain()
                .map(|_| ())
                .map_err(|_| "signed regulatory policy unavailable")
        })
        .await
    }
    async fn provision_checked(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        manifest: &str,
        policy: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        use crate::brcmfmac::provision::{select_using, Family};
        use core::sync::atomic::Ordering;
        let mut slot = self.card.lock().await;
        if self.state() != ProvisionState::Parked {
            return Err("CYW43439 provisioning already attempted");
        }
        let card = slot.as_mut().ok_or("parked SDIO card unavailable")?;
        let host = card
            .host_identity()
            .ok_or("explicit SDIO host/board identity required")?;
        let function = card.function(1).ok_or("CYW43439 F1 identity unavailable")?;
        let vendor = super::fullmac::FirmwareVendor::sdio(function.vendor);
        let selection = select_using(
            authority,
            manifest,
            Family::Sdio43439,
            host,
            Some((1, function.vendor, function.device)),
        )
        .map_err(|_| "signed CYW43439 host/card board selection unavailable or mismatched")?;
        let assets = selection
            .load_using(authority)
            .map_err(|_| "selected CYW43439 asset signature/key/length/hash mismatch")?;
        // Shared single-board parser rejects generic/multi-device selectors.
        let nvram = crate::brcmfmac::boot::pack_nvram(&assets.nvram)
            .map_err(|_| "invalid selected CYW43439 NVRAM")?;
        policy()?;
        assets
            .proof
            .validate()
            .map_err(|_| "CYW43439 provisioning revoked/replaced before boot")?;
        self.state
            .store(ProvisionState::Starting as u8, Ordering::Release);
        let _attempt = Attempt(&self.state);
        let card = slot.take().ok_or("parked SDIO card unavailable")?;
        let mut transport = SdioTransport::new(card).qualify(assets.proof.clone());
        transport
            .prepare()
            .map_err(|_| "SDIO F1 preparation failed")?;
        let mut loader = FirmwareLoader::new(transport, &assets.firmware, &nvram, 0, false)
            .require_revisions(selection.revisions());
        loader
            .run()
            .map_err(|_| "firmware bootstrap/chip revision failed")?;
        let core = loader.packet_core().ok_or("firmware did not release CM3")?;
        let mut transport = loader
            .into_transport()
            .map_err(|_| "firmware owner not ready")?;
        transport
            .initialize_packets(core)
            .map_err(|_| "F2/mailbox setup failed")?;
        drop(slot);
        let name = narf_net::iface::reserve_name("wlan%d");
        let runtime = super::runtime::Runtime::new(transport).with_firmware_vendor(vendor);
        interface::attach_runtime(name, runtime, &assets.clm)
            .await
            .map_err(|_| "station initialization failed")?;
        self.state
            .store(ProvisionState::Ready as u8, Ordering::Release);
        narf_drivers::record_bound(narf_drivers::BoundDriver {
            name: "cyw43439".into(),
            kind: narf_drivers::BoundKind::Net,
            pci_vid: None,
            pci_did: None,
            domain: narf_drivers::BoundKind::Net.default_domain(),
        });
        Ok(())
    }
}
static NATIVE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::sync::Arc<Provisioner<narf_drivers_sdio::native::Mmio>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
pub(super) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut state: impl FnMut() -> ProvisionState,
    mut step: Step,
    mut wait: Wait,
) -> Result<(), &'static str>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<(), &'static str>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = "signed CYW43439 host/card board selection unavailable or mismatched";
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if state() != ProvisionState::Parked {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}
/// The native callback retains the exact card before the executor first polls
/// provisioning. A missing Stage::Late asset never loses the host/card owner.
fn probe(card: NativeCard) {
    let owner = alloc::sync::Arc::new(Provisioner::new(card));
    {
        let mut slot = NATIVE.lock();
        if slot.is_some() {
            return;
        }
        *slot = Some(owner.clone());
    }
    narf_scheduler::spawn(async move {
        let state_owner = owner.clone();
        if let Err(reason) = drive_scheduled(
            120,
            || state_owner.state(),
            || owner.provision(),
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
        )
        .await
        {
            let _ = writeln!(narf_console::Writer, "cyw43439: {}", reason);
        }
    });
}
/// Retry staged assets only before native firmware/packet initialization.
pub async fn provision() -> Result<(), &'static str> {
    let owner = NATIVE.lock().clone().ok_or("no retained CYW43439 card")?;
    owner.provision().await
}
pub fn provision_state() -> Option<ProvisionState> {
    Some(NATIVE.lock().as_ref()?.state())
}
/// Explicit platform convenience path. Its Registers must report actual host
/// identity. Platforms needing retries retain Provisioner::new(card) instead.
/// Clock/pin/regulator/WL_REG_ON authority stays with that platform owner.
pub async fn boot<R: narf_drivers_sdio::pio::Registers + Send + 'static>(
    card: narf_drivers_sdio::card::Card<R>,
) -> Result<(), &'static str> {
    Provisioner::new(card).provision().await
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::brcmfmac::provision::{tests::*, Family};
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn ready<F: Future>(future: F) -> Option<F::Output> {
        let mut future = core::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }
    fn smoke_cyw_board_provisioning_missing_assets_policy_and_revocation_keep_same_card(
    ) -> TestResult {
        let (write, read) = registry().unwrap();
        let selection = choose(&read, Family::Sdio43439).unwrap();
        let (card, model) =
            narf_drivers_sdio::card::tests::initialized_fixture(Some(selection.host()));
        let before = model.command_count();
        let owner = Provisioner::new(card);
        for _ in 0..2 {
            if !matches!(
                ready(owner.provision_using(&read, "narf-test/brcm/missing-selection")),
                Some(Err(_))
            ) || owner.state() != ProvisionState::Parked
                || model.command_count() != before
            {
                return TestResult::Fail(
                    "missing signed selection lost or mutated parked SDIO card",
                );
            }
        }
        stage_invalid_executable(&write, Family::Sdio43439);
        if !matches!(
            choose(&read, Family::Sdio43439),
            Err(crate::brcmfmac::provision::Error::Invalid)
        ) {
            return TestResult::Fail(
                "oversize signed CM3 declaration reached asset lookup instead of shape preflight",
            );
        }
        if !matches!(
            ready(owner.provision_checked(&read, TEST_MANIFEST, || Ok(()))),
            Some(Err(_))
        ) || owner.state() != ProvisionState::Parked
            || model.command_count() != before
        {
            return TestResult::Fail(
                "oversize signed CM3 selection began F1 setup or lost retryability",
            );
        }
        registry().unwrap(); // stage valid bytes; keep the original actual Card.
        if !matches!(
            ready(owner.provision_checked(&read, TEST_MANIFEST, || Err("policy absent"))),
            Some(Err(_))
        ) || owner.state() != ProvisionState::Parked
            || model.command_count() != before
            || ready(async { owner.card.lock().await.is_some() }) != Some(true)
        {
            return TestResult::Fail(
                "complete selection without regulatory authority began F1 setup",
            );
        }
        read.revoke();
        if !matches!(
            ready(owner.provision_using(&read, TEST_MANIFEST)),
            Some(Err(_))
        ) || owner.state() != ProvisionState::Parked
            || model.command_count() != before
        {
            return TestResult::Fail("revoked registry authority mutated retained SDIO card");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/bootstrap",
        smoke_cyw_board_provisioning_missing_assets_policy_and_revocation_keep_same_card
    );

    fn smoke_cyw_board_provisioning_first_native_f1_failure_is_terminal() -> TestResult {
        let (_, read) = registry().unwrap();
        let selection = choose(&read, Family::Sdio43439).unwrap();
        let (card, model) =
            narf_drivers_sdio::card::tests::initialized_fixture(Some(selection.host()));
        let owner = Provisioner::new(card);
        let before = model.command_count();
        model.refuse_commands();
        // Explicit test policy grants no global domain. Everything through
        // exact selection/signatures/Card::cmd52/controller completion is real.
        if !matches!(
            ready(owner.provision_checked(&read, TEST_MANIFEST, || Ok(()))),
            Some(Err(_))
        ) || owner.state() != ProvisionState::Failed
            || model.command_count() <= before
            || ready(async { owner.card.lock().await.is_none() }) != Some(true)
        {
            return TestResult::Fail(
                "published F1 command failure did not consume one-shot card attempt",
            );
        }
        let after = model.command_count();
        if !matches!(
            ready(owner.provision_checked(&read, TEST_MANIFEST, || Ok(()))),
            Some(Err(_))
        ) || owner.state() != ProvisionState::Failed
            || model.command_count() != after
        {
            return TestResult::Fail("terminal SDIO provisioning retried native hardware command");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/bootstrap",
        smoke_cyw_board_provisioning_first_native_f1_failure_is_terminal
    );

    fn smoke_cyw_drive_scheduled_retries_and_terminates() -> TestResult {
        let (_, read) = registry().unwrap();
        let selection = choose(&read, Family::Sdio43439).unwrap();
        let (card, _) = narf_drivers_sdio::card::tests::initialized_fixture(Some(selection.host()));
        let owner = Provisioner::new(card);

        // Case 1: retries while in ProvisionState::Parked and succeeds
        let attempts = core::cell::Cell::new(0);
        let waits = core::cell::Cell::new(0);
        let result = narf_scheduler::block_on(drive_scheduled(
            5,
            || owner.state(),
            || {
                let n = attempts.get();
                attempts.set(n + 1);
                async move {
                    if n < 2 {
                        Err("missing asset")
                    } else {
                        Ok(())
                    }
                }
            },
            || {
                waits.set(waits.get() + 1);
                async {}
            },
        ));
        if result.is_err() || attempts.get() != 3 || waits.get() != 2 {
            return TestResult::Fail("cyw43439 drive_scheduled failed to retry while parked");
        }

        // Case 2: exits immediately when state is unretryable (Failed)
        use core::sync::atomic::Ordering;
        owner
            .state
            .store(ProvisionState::Failed as u8, Ordering::Release);
        attempts.set(0);
        waits.set(0);
        let result = narf_scheduler::block_on(drive_scheduled(
            10,
            || owner.state(),
            || {
                let n = attempts.get();
                attempts.set(n + 1);
                async move { Err("missing asset") }
            },
            || {
                waits.set(waits.get() + 1);
                async {}
            },
        ));
        if result != Err("missing asset") || attempts.get() != 1 || waits.get() != 0 {
            return TestResult::Fail(
                "cyw43439 drive_scheduled did not exit immediately when unretryable",
            );
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/bootstrap",
        smoke_cyw_drive_scheduled_retries_and_terminates
    );
}
