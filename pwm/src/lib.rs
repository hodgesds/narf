#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};
use narf_lib::sync::IrqSafeSpinLock;

/// PWM Polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    Normal,
    Inversed,
}

/// PWM Configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwmConfig {
    pub frequency_hz: u32,
    pub duty_cycle_ns: u64,
    pub polarity: Polarity,
}

/// PWM Error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwmError {
    InvalidChannel,
    InvalidConfig,
    HardwareError,
}

/// Cap-type marker for `Cap<PwmCapType, R>`.
#[derive(Debug)]
pub struct PwmCapType;

impl CapType for PwmCapType {
    const KIND: CapKind = CapKind::Pwm;
}

/// Hardware-agnostic PWM device trait.
#[async_trait]
pub trait PwmDevice: Send + Sync {
    /// Configure a PWM channel.
    async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError>;

    /// Enable a PWM channel.
    async fn enable(&self, channel: u32) -> Result<(), PwmError>;

    /// Disable a PWM channel.
    async fn disable(&self, channel: u32) -> Result<(), PwmError>;

    /// Returns the number of channels supported by this device.
    fn channel_count(&self) -> u32;
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Controller registry ─────────────────────────────────────────────
//
// PWM controller drivers register the `PwmDevice` they drive under
// the controller node's Devicetree phandle, so DT-described
// consumers — a `pwm-fan` node whose `pwms` specifier carries that
// phandle, an LED, a backlight — can resolve the controller the
// board description points at without knowing which driver owns
// the silicon. The registry is deliberately dumb: one phandle,
// one controller, last registration wins. It holds no capability
// and performs no arbitration; the consumer owns the channel it
// was described with, and two consumers claiming the same channel
// is a board-description bug, not something this table can fix.
//
// Registration timing matters: a consumer probe that runs before
// its controller registers (e.g. the Stage::Device DT walk) gets
// `None` and defers — the consumer's probe must treat that as a
// retryable miss, not a hard failure. Controller drivers register
// no later than Stage::Device for their consumers to bind at boot.

/// Controllers registered by Devicetree phandle.
static CONTROLLERS: IrqSafeSpinLock<Vec<(u32, Arc<dyn PwmDevice>)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register `dev` as the controller at DT phandle `phandle`.
/// Re-registering under the same phandle replaces the previous
/// controller (a later driver claiming the node wins).
pub fn register_controller(phandle: u32, dev: Arc<dyn PwmDevice>) {
    let mut g = CONTROLLERS.lock();
    if let Some(slot) = g.iter_mut().find(|(ph, _)| *ph == phandle) {
        slot.1 = dev;
    } else {
        g.push((phandle, dev));
    }
}

/// The controller registered under DT phandle `phandle`, if any.
pub fn lookup_controller(phandle: u32) -> Option<Arc<dyn PwmDevice>> {
    CONTROLLERS
        .lock()
        .iter()
        .find(|(ph, _)| *ph == phandle)
        .map(|(_, dev)| dev.clone())
}

/// Drop the controller registered under `phandle`, if any.
pub fn unregister_controller(phandle: u32) {
    CONTROLLERS.lock().retain(|(ph, _)| *ph != phandle);
}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    struct MockPwm {
        state: IrqSafeSpinLock<Vec<(u32, PwmConfig, bool)>>,
        channels: u32,
    }

    #[async_trait]
    impl PwmDevice for MockPwm {
        async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.1 = *config;
            } else {
                state.push((channel, *config, false));
            }
            Ok(())
        }

        async fn enable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.2 = true;
            } else {
                state.push((
                    channel,
                    PwmConfig {
                        frequency_hz: 0,
                        duty_cycle_ns: 0,
                        polarity: Polarity::Normal,
                    },
                    true,
                ));
            }
            Ok(())
        }

        async fn disable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.2 = false;
            }
            Ok(())
        }

        fn channel_count(&self) -> u32 {
            self.channels
        }
    }

    fn smoke_pwm_async() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let pwm = Arc::new(MockPwm {
            state: IrqSafeSpinLock::new(Vec::new()),
            channels: 4,
        });
        let success = Arc::new(core::sync::atomic::AtomicBool::new(false));

        let p = pwm.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let config = PwmConfig {
                frequency_hz: 1000,
                duty_cycle_ns: 500000,
                polarity: Polarity::Normal,
            };
            p.set_config(0, &config).await.expect("set_config failed");
            p.enable(0).await.expect("enable failed");

            let state = p.state.lock();
            if let Some((ch, cfg, enabled)) = state.iter().find(|(ch, _, _)| *ch == 0) {
                if *ch == 0 && cfg.frequency_hz == 1000 && *enabled {
                    s.store(true, core::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(core::sync::atomic::Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("PWM async smoke test failed to verify state")
        }
    }
    kernel_test_in!("pwm", smoke_pwm_async);

    fn smoke_pwm_polarity_variants_distinct() -> TestResult {
        if Polarity::Normal == Polarity::Inversed {
            return TestResult::Fail("Polarity variants collapsed");
        }
        TestResult::Pass
    }
    kernel_test_in!("pwm", smoke_pwm_polarity_variants_distinct);

    fn smoke_pwm_error_variants_distinct() -> TestResult {
        let all = [
            PwmError::InvalidChannel,
            PwmError::InvalidConfig,
            PwmError::HardwareError,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("PwmError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("pwm", smoke_pwm_error_variants_distinct);

    fn smoke_pwm_config_round_trip() -> TestResult {
        let c = PwmConfig {
            frequency_hz: 100_000,
            duty_cycle_ns: 5_000,
            polarity: Polarity::Inversed,
        };
        if c.frequency_hz != 100_000 {
            return TestResult::Fail("frequency_hz round-trip");
        }
        if c.duty_cycle_ns != 5_000 {
            return TestResult::Fail("duty_cycle_ns round-trip");
        }
        if c.polarity != Polarity::Inversed {
            return TestResult::Fail("polarity round-trip");
        }
        #[allow(clippy::clone_on_copy)]
        let cloned = c.clone();
        if c != cloned {
            return TestResult::Fail("PwmConfig Clone broken");
        }
        TestResult::Pass
    }
    kernel_test_in!("pwm", smoke_pwm_config_round_trip);

    fn smoke_pwm_mock_rejects_invalid_channel() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let pwm = Arc::new(MockPwm {
            state: IrqSafeSpinLock::new(Vec::new()),
            channels: 2,
        });
        let outcome = Arc::new(core::sync::atomic::AtomicU8::new(0));
        let p = pwm.clone();
        let o = outcome.clone();
        narf_scheduler::spawn(async move {
            let cfg = PwmConfig {
                frequency_hz: 1000,
                duty_cycle_ns: 1000,
                polarity: Polarity::Normal,
            };
            // Valid channel 0 → Ok.
            if p.set_config(0, &cfg).await.is_ok() {
                o.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
            // Channel == channel_count (out of range, valid range is 0..count).
            if let Err(PwmError::InvalidChannel) = p.set_config(2, &cfg).await {
                o.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
            // Channel 100 → InvalidChannel.
            if let Err(PwmError::InvalidChannel) = p.enable(100).await {
                o.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if outcome.load(core::sync::atomic::Ordering::SeqCst) == 3 {
            TestResult::Pass
        } else {
            TestResult::Fail("PWM channel-bounds rejection not all 3 paths")
        }
    }
    kernel_test_in!("pwm", smoke_pwm_mock_rejects_invalid_channel);

    fn smoke_pwm_channel_count_reflects_construction() -> TestResult {
        let pwm = MockPwm {
            state: IrqSafeSpinLock::new(Vec::new()),
            channels: 8,
        };
        if pwm.channel_count() != 8 {
            return TestResult::Fail("channel_count doesn't reflect construction");
        }
        TestResult::Pass
    }
    kernel_test_in!("pwm", smoke_pwm_channel_count_reflects_construction);

    fn smoke_pwm_controller_registry_round_trip() -> TestResult {
        // A phandle no controller test has touched; unregister
        // first so a stale entry from an aborted earlier run
        // cannot make the miss check pass vacuously.
        let phandle = 0x9_911u32;
        unregister_controller(phandle);
        if lookup_controller(phandle).is_some() {
            return TestResult::Fail("unregistered phandle must miss");
        }
        let pwm = Arc::new(MockPwm {
            state: IrqSafeSpinLock::new(Vec::new()),
            channels: 2,
        });
        register_controller(phandle, pwm);
        match lookup_controller(phandle) {
            Some(found) => {
                if found.channel_count() != 2 {
                    return TestResult::Fail("registry returned the wrong controller");
                }
            }
            None => return TestResult::Fail("registered controller must be found"),
        }
        // Re-registering under the same phandle replaces.
        let pwm2 = Arc::new(MockPwm {
            state: IrqSafeSpinLock::new(Vec::new()),
            channels: 5,
        });
        register_controller(phandle, pwm2);
        if lookup_controller(phandle).map(|c| c.channel_count()) != Some(5) {
            return TestResult::Fail("re-register must replace the controller");
        }
        unregister_controller(phandle);
        if lookup_controller(phandle).is_some() {
            return TestResult::Fail("unregistered controller must be gone");
        }
        TestResult::Pass
    }
    kernel_test_in!("pwm", smoke_pwm_controller_registry_round_trip);
}
