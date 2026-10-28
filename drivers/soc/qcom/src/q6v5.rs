//! Hexagon (Q6v5) start/stop signalling shared by the WCSS and PAS
//! remoteprocs.
//!
//! Linux `drivers/remoteproc/qcom_q6v5.c`. The remote reports through
//! five interrupts: `wdog` (a GIC SPI) and the SMP2P inbound
//! `slave-kernel` bits `fatal`(0), `ready`(1), `handover`(2),
//! `stop-ack`(3) (+ `shutdown-ack`(7) on WPSS). The host requests a
//! graceful stop by setting the outbound `stop` state bit and waiting for
//! `stop-ack`.
//!
//! [`Q6v5`] is the interrupt-side state (atomics, so an IRQ handler can
//! [`Q6v5::signal`] while a task waits). [`Q6v5::wait_for_start`] /
//! [`Q6v5::wait_for_stop`] sleep between checks of that software state;
//! `pump` lets the caller service the SMP2P edge (in production a no-op
//! because the IRQ path calls `signal`; fixtures use it to play the
//! remote).

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::io::Delay;

/// SMP2P inbound bit numbers (`interrupts-extended = <&smp2p_in N 0>`).
pub const BIT_FATAL: u32 = 0;
pub const BIT_READY: u32 = 1;
pub const BIT_HANDOVER: u32 = 2;
pub const BIT_STOP_ACK: u32 = 3;
pub const BIT_SHUTDOWN_ACK: u32 = 7;
/// Outbound `stop` state bit (`qcom,smem-states = <&smp2p_out 0>`).
pub const STOP_BIT: u32 = 0;

/// `qcom_q6v5_wait_for_start` / `request_stop` budget (5 s).
pub const START_TIMEOUT_MS: u32 = 5000;
pub const STOP_TIMEOUT_MS: u32 = 5000;

/// A remote event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Q6Event {
    Wdog,
    Fatal,
    Ready,
    Handover,
    StopAck,
    ShutdownAck,
}

impl Q6Event {
    /// Map an `interrupt-names` entry.
    pub fn from_irq_name(name: &str) -> Option<Self> {
        Some(match name {
            "wdog" => Q6Event::Wdog,
            "fatal" => Q6Event::Fatal,
            "ready" => Q6Event::Ready,
            "handover" => Q6Event::Handover,
            "stop-ack" => Q6Event::StopAck,
            "shutdown-ack" => Q6Event::ShutdownAck,
            _ => return None,
        })
    }

    /// The SMP2P inbound bit for the SMP2P-routed events.
    pub fn from_smp2p_bit(bit: u32) -> Option<Self> {
        Some(match bit {
            BIT_FATAL => Q6Event::Fatal,
            BIT_READY => Q6Event::Ready,
            BIT_HANDOVER => Q6Event::Handover,
            BIT_STOP_ACK => Q6Event::StopAck,
            BIT_SHUTDOWN_ACK => Q6Event::ShutdownAck,
            _ => return None,
        })
    }
}

/// Why the remote crashed (`rproc_report_crash`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Crash {
    Watchdog,
    Fatal,
}

/// Wait failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Q6Error {
    /// `-ETIMEDOUT`.
    Timeout,
    /// The remote crashed while we waited.
    Crashed(Crash),
}

/// `struct qcom_q6v5` (signalling subset).
#[derive(Debug, Default)]
pub struct Q6v5 {
    running: AtomicBool,
    handover_issued: AtomicBool,
    handover_enabled: AtomicBool,
    start_done: AtomicBool,
    stop_done: AtomicBool,
    /// 0 = none, 1 = watchdog, 2 = fatal.
    crash: AtomicU8,
}

impl Q6v5 {
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            handover_issued: AtomicBool::new(false),
            handover_enabled: AtomicBool::new(false),
            start_done: AtomicBool::new(false),
            stop_done: AtomicBool::new(false),
            crash: AtomicU8::new(0),
        }
    }

    /// `qcom_q6v5_prepare`.
    pub fn prepare(&self) {
        self.start_done.store(false, Ordering::Release);
        self.stop_done.store(false, Ordering::Release);
        self.crash.store(0, Ordering::Release);
        self.handover_issued.store(false, Ordering::Release);
        self.running.store(true, Ordering::Release);
        self.handover_enabled.store(true, Ordering::Release);
    }

    /// `qcom_q6v5_unprepare`: `true` if handover never happened (the
    /// caller must release proxy votes itself).
    pub fn unprepare(&self) -> bool {
        self.handover_enabled.store(false, Ordering::Release);
        !self.handover_issued.load(Ordering::Acquire)
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub fn handover_issued(&self) -> bool {
        self.handover_issued.load(Ordering::Acquire)
    }
    pub fn crash(&self) -> Option<Crash> {
        match self.crash.load(Ordering::Acquire) {
            1 => Some(Crash::Watchdog),
            2 => Some(Crash::Fatal),
            _ => None,
        }
    }

    /// The interrupt handlers (`q6v5_{wdog,fatal,ready,handover,stop}_interrupt`).
    pub fn signal(&self, ev: Q6Event) {
        match ev {
            Q6Event::Wdog => {
                // A stop sometimes triggers the watchdog instead of stop-ack.
                if !self.running.load(Ordering::Acquire) {
                    self.stop_done.store(true, Ordering::Release);
                    return;
                }
                self.crash.store(1, Ordering::Release);
                self.running.store(false, Ordering::Release);
            }
            Q6Event::Fatal => {
                if !self.running.load(Ordering::Acquire) {
                    return;
                }
                self.crash.store(2, Ordering::Release);
                self.running.store(false, Ordering::Release);
            }
            Q6Event::Ready => self.start_done.store(true, Ordering::Release),
            Q6Event::Handover => {
                if self.handover_enabled.load(Ordering::Acquire) {
                    self.handover_issued.store(true, Ordering::Release);
                }
            }
            Q6Event::StopAck | Q6Event::ShutdownAck => {
                self.stop_done.store(true, Ordering::Release)
            }
        }
    }

    async fn wait<D: Delay + ?Sized>(
        &self,
        flag: &AtomicBool,
        delay: &D,
        timeout_ms: u32,
        pump: &mut dyn FnMut(&Self),
        crash_aborts: bool,
    ) -> Result<(), Q6Error> {
        let deadline = delay.now_us() + timeout_ms as u64 * 1000;
        loop {
            pump(self);
            if flag.load(Ordering::Acquire) {
                return Ok(());
            }
            if crash_aborts {
                if let Some(c) = self.crash() {
                    return Err(Q6Error::Crashed(c));
                }
            }
            if delay.now_us() >= deadline {
                return Err(Q6Error::Timeout);
            }
            delay.sleep_us(1000).await;
        }
    }

    /// `qcom_q6v5_wait_for_start`. On timeout handover is disabled, as
    /// Linux does.
    pub async fn wait_for_start<D: Delay + ?Sized>(
        &self,
        delay: &D,
        timeout_ms: u32,
        pump: &mut dyn FnMut(&Self),
    ) -> Result<(), Q6Error> {
        let r = self
            .wait(&self.start_done, delay, timeout_ms, pump, true)
            .await;
        if r.is_err() {
            self.handover_enabled.store(false, Ordering::Release);
        }
        r
    }

    /// Mark the remote stopping and wait for `stop-ack` (the middle of
    /// `qcom_q6v5_request_stop`; the caller sets/clears the SMP2P `stop`
    /// bit around it).
    pub async fn wait_for_stop<D: Delay + ?Sized>(
        &self,
        delay: &D,
        timeout_ms: u32,
        pump: &mut dyn FnMut(&Self),
    ) -> Result<(), Q6Error> {
        self.running.store(false, Ordering::Release);
        self.wait(&self.stop_done, delay, timeout_ms, pump, false)
            .await
    }

    /// Mark stopped without the SMP2P dance (remote not running).
    pub fn mark_stopped(&self) {
        self.running.store(false, Ordering::Release);
    }
}
