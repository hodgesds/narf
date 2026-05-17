#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};

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
        if c != c.clone() {
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
            match p.set_config(2, &cfg).await {
                Err(PwmError::InvalidChannel) => {
                    o.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                }
                _ => {}
            }
            // Channel 100 → InvalidChannel.
            match p.enable(100).await {
                Err(PwmError::InvalidChannel) => {
                    o.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                }
                _ => {}
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
}
