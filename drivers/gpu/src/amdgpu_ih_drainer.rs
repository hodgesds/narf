//! Live IH ring drainer for AMD hotplug (HPD) — #1785.
//!
//! The #1712 seam (`AmdGpu::handle_hotplug_event` + `poll_hotplug`,
//! `drivers/gpu/src/amdgpu.rs`) consumes HPD cookies, but no production
//! code drained the IH ring and produced them. This module is that
//! drainer: it reads decoded IH ring entries (`Iv`, the tree's decoded
//! form of a 32-byte ring cookie), extracts the HPD ones, reads the pin
//! level back at drain time, and feeds each cookie into
//! `handle_hotplug_event`.
//!
//! ## What a cookie can and cannot say
//!
//! Every HPD event shares source id `SOURCE_ID_DCN_HPD` (9); the cookie's
//! `src_data[0]` (the context id, 0..=11) names the connector and splits
//! plug events (0..5) from DisplayPort sink IRQs (6..11) — see
//! [`crate::amdgpu_ih::decode_hpd_ctxid`] and `Iv::hpd`. The cookie does
//! NOT say whether a plug event is a connect or a disconnect: the pin
//! level decides that, so the drainer reads it back per cookie with
//! `AmdGpu::hpd_asserted` (the `DC_HPD_SENSE_DELAYED` bit Linux's
//! `dal_hw_hpd_get_value` reports in interrupt mode). A sink IRQ never
//! consults the pin — the level is meaningless for it, since a short
//! pulse leaves the pin where it was.
//!
//! ## Pin index vs connector index
//!
//! The cookie's instance (0..5) is the HPD *pin* index, and that is what
//! `hpd_asserted` indexes: the DCN HPD register blocks are per pin
//! (`HPD_BLOCKS` = 5 on DCN 3.1.4 — pin 5 / HPD6 has no sense register,
//! so a cookie naming it is dropped as pin-unreadable). The KMS
//! connector index is a *different* number: `HpdMachine::bind` maps pin
//! to connector, and only `handle_hotplug_event` knows that mapping.
//!
//! ## Driving it
//!
//! [`serve_ih_hpd`] is the live task: it pulls batches off a Navi22 IH
//! `Subscription` (`try_next`, which drains the ring), feeds them through
//! the legacy controller (`AmdGpu::service_hotplug` — drain + debounce
//! poll in one call), and sleeps [`IH_HPD_POLL_MS`] between passes so
//! debounced connects become `Connected` even when no further cookie
//! arrives. The period is the tree's hotplug floor (`HOTPLUG_MIN_MS` =
//! 50 ms, same value both display paths use): the debounce window is
//! 100 ms, so a 50 ms tick adds at most half a window of latency to a
//! connect while keeping the task a quiet periodic poller.
//!
//! [`start_ih_hpd`] subscribes `source::DCN_HPD` and spawns the task.
//! It fails closed when there is no live legacy controller (a discrete
//! ColdBoot claim gates `with_controller_mut`) or when the source is
//! already owned — the Navi22 native display path's `serve_hpd` holds
//! the exclusive subscription whenever display engines are requested,
//! and two owners of one HPD source would double-handle every plug.
//! Which host should start this task on a given boot (legacy KMS vs
//! native display ownership of HPD, and the Phoenix IH bring-up the
//! APU path still lacks) is the #1785 wiring remainder: the drainer,
//! the service entry point and the task are all here and
//! fixture-validated, but nothing spawns the task yet.
//!
//! ## Timestamp source
//!
//! The task stamps batches with `narf_time::now_cycles()` — the raw
//! TSC on x86_64 (LFENCE;RDTSC), CNTPCT on aarch64 — which is the
//! `tsc` the HPD debounce machine counts in. The default debounce
//! window (`DEBOUNCE_TICKS_DEFAULT`) assumes a ~1 GHz TSC; that
//! calibration is #1712's, not this module's.

extern crate alloc;

use crate::amdgpu_hpd::HpdOutcome;
use crate::amdgpu_ih::HPD_CTXID_RX_PIPE0;
use crate::amdgpu_ih_navi22::{source, Handle, Iv, Subscription};

/// How often the drainer task wakes to drain the ring and sample the
/// HPD debounce timers, in milliseconds. Matches the tree's hotplug
/// floor (`HOTPLUG_MIN_MS`): the debounce window is 100 ms, so a
/// 50 ms tick bounds connect latency while keeping the task quiet.
pub const IH_HPD_POLL_MS: u64 = 50;

/// How many IVs one drain pass feeds. Mirrors the IH engine's batch
/// (`AMDGPU_IH_MAX_NUM_IVS` = 32 in `amdgpu_ih_navi22`).
const DRAIN_BATCH: usize = 32;

/// What one drain pass did. Counts only — the outcomes themselves live
/// in the HPD machine / KMS state the feed updated.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IhHpdDrain {
    /// Cookies accepted by the feed (plugs + sink IRQs).
    pub fed: u32,
    /// Ring entries that are not HPD cookies (vblank, fences, ...).
    pub skipped_non_hpd: u32,
    /// Plug cookies dropped because the pin level could not be read
    /// back (no sense register for this pin, or the device is gone).
    pub skipped_pin_unreadable: u32,
    /// Cookies the feed accepted for a pin with no bound connector.
    pub unmapped: u32,
    /// Sink-IRQ (short-pulse) cookies among `fed`.
    pub short_pulse: u32,
}

/// Rebuild a cookie's context id from its decoded form. `Iv::hpd`
/// splits the context id into `instance` (0..5) and `rx`; the split
/// is reversible: plug ids are 0..5, sink-IRQ ids are 6..11.
pub const fn ctxid_for_hpd(hpd: crate::amdgpu_ih_navi22::Hpd) -> u8 {
    hpd.instance + if hpd.rx { HPD_CTXID_RX_PIPE0 } else { 0 }
}

/// Drain one batch of decoded IH ring entries into the HPD state
/// machine.
///
/// For each entry: non-HPD entries are counted and skipped; HPD plug
/// cookies get their pin level from `pin` (consulted exactly once per
/// plug cookie, in slice order, never for a sink IRQ) and are fed as
/// `(ctxid, asserted, tsc)`; sink-IRQ cookies are fed with
/// `asserted = false`, which the cookie decode ignores. A plug cookie
/// whose pin cannot be read (`pin` returns `None`) is dropped —
/// without a level there is no way to tell a connect from a
/// disconnect, and guessing would invert the event. `feed` returning
/// `None` (a context id the machine rejects) is likewise not counted
/// as fed.
///
/// The caller supplies both closures: in production the pin levels
/// come from `AmdGpu::hpd_asserted`, read once per plug cookie into
/// a staged table by `AmdGpu::drain_ih_hotplug` (the readback needs
/// `&self` while the feed needs `&mut self`), and `feed` is
/// `AmdGpu::handle_hotplug_event`; tests pass a fake pin table and
/// a recording feed.
pub fn drain_ih_hpd_ivs(
    ivs: &[Iv],
    tsc: u64,
    mut pin: impl FnMut(u8) -> Option<bool>,
    mut feed: impl FnMut(u8, bool, u64) -> Option<HpdOutcome>,
) -> IhHpdDrain {
    let mut report = IhHpdDrain::default();
    for iv in ivs {
        let Some(hpd) = iv.hpd() else {
            report.skipped_non_hpd += 1;
            continue;
        };
        let ctxid = ctxid_for_hpd(hpd);
        // A sink IRQ leaves the pin where it was: no readback, and
        // the level the feed receives is ignored by the decode.
        let asserted = if hpd.rx {
            false
        } else {
            let Some(asserted) = pin(hpd.instance) else {
                report.skipped_pin_unreadable += 1;
                continue;
            };
            asserted
        };
        match feed(ctxid, asserted, tsc) {
            Some(HpdOutcome::UnmappedSource) => {
                report.fed += 1;
                report.unmapped += 1;
                if hpd.rx {
                    report.short_pulse += 1;
                }
            }
            Some(_) => {
                report.fed += 1;
                if hpd.rx {
                    report.short_pulse += 1;
                }
            }
            None => {}
        }
    }
    report
}

/// Why [`start_ih_hpd`] refused to start the drainer task.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartError {
    /// `source::DCN_HPD` is already subscribed — the native display
    /// path's `serve_hpd` owns it on this boot.
    AlreadyOwned,
    /// No live legacy controller: probe never ran, or a discrete
    /// ColdBoot claim gated `with_controller_mut`.
    NoController,
    /// The subscription failed for another reason (hub closed, or
    /// the mailbox reservation failed).
    Unavailable,
}

/// Subscribe `source::DCN_HPD` and spawn [`serve_ih_hpd`].
///
/// Fails closed (no task, no subscription held) when there is no
/// legacy controller to feed or the HPD source is already owned.
/// The caller logs the refusal and carries on — polling detection
/// keeps working without the drainer, and the native display path
/// owns HPD on boots where it is armed.
pub fn start_ih_hpd(handle: &Handle) -> Result<(), StartError> {
    // Do not take the exclusive HPD source for nobody: without a
    // live controller the task would drain cookies into the void
    // while blocking the native display path from subscribing.
    if crate::amdgpu::with_controller(|_| ()).is_none() {
        return Err(StartError::NoController);
    }
    let subscription = handle.subscribe(source::DCN_HPD).map_err(|error| {
        if error == crate::amdgpu_ih_navi22::Error::Busy {
            StartError::AlreadyOwned
        } else {
            StartError::Unavailable
        }
    })?;
    narf_scheduler::spawn(serve_ih_hpd(subscription));
    Ok(())
}

/// Live IH HPD drainer task.
///
/// Each pass pulls every queued IV off the subscription (`try_next`
/// drains the ring when the mailbox is empty), feeds the batch
/// through the legacy controller (`AmdGpu::service_hotplug`, which
/// drains and then samples the debounce timers), modesets newly
/// connected connectors with their EDID preferred modes
/// (`AmdGpu::modeset_newly_connected`, #1787 — a connector with
/// no EDID fed yet is logged and left unmodeset, never given an
/// invented mode), and sleeps [`IH_HPD_POLL_MS`]. The sleep —
/// not the IV wait — is the scheduled wakeup the debounce poll
/// needs: a connect only becomes `Connected` in `poll_hotplug`,
/// and no further cookie is guaranteed to arrive after the plug.
///
/// The task exits (dropping the subscription, so the HPD source
/// becomes subscribable again) when the subscription closes or is
/// revoked, or when the legacy controller goes away — a discrete
/// claim after start must not leave the task squatting on the
/// exclusive HPD source.
pub async fn serve_ih_hpd(mut subscription: Subscription) {
    use core::fmt::Write as _;
    loop {
        let mut batch = [Iv::default(); DRAIN_BATCH];
        let mut count = 0;
        loop {
            match subscription.try_next() {
                Ok(Some(iv)) => {
                    if count < DRAIN_BATCH {
                        batch[count] = iv;
                        count += 1;
                    } else {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: IH HPD drainer stopping: subscription closed",
                    );
                    return;
                }
            }
        }
        let tsc = narf_time::now_cycles();
        let connected = match crate::amdgpu::with_controller_mut(|gpu| {
            gpu.service_hotplug(&batch[..count], tsc)
        }) {
            Some((_, connected)) => connected,
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: IH HPD drainer stopping: no legacy controller",
                );
                return;
            }
        };
        // DRM/fb caller (#1787): modeset each connector this tick
        // marked `Connected`, with its stored EDID preferred mode.
        // A second controller lookup (rather than reusing the
        // service borrow) keeps each `with_controller_mut` closure
        // short-lived; a controller gone between the two passes
        // stops the task instead of modesetting into the void.
        let outcomes =
            match crate::amdgpu::with_controller_mut(|gpu| gpu.modeset_newly_connected(&connected))
            {
                Some(outcomes) => outcomes,
                None => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: IH HPD drainer stopping: no legacy controller",
                    );
                    return;
                }
            };
        for (connector_idx, outcome) in outcomes {
            match outcome {
                Ok(true) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: IH HPD connector {connector_idx} modeset to EDID preferred mode",
                    );
                }
                Ok(false) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: IH HPD connector {connector_idx} connected but no EDID preferred mode; leaving unmodeset",
                    );
                }
                Err(error) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: IH HPD connector {connector_idx} modeset failed: {error:?}",
                    );
                }
            }
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(IH_HPD_POLL_MS).as_instant())
            .await;
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// One raw 32-byte ring cookie: `dw[0]` carries client/source,
    /// `dw[4]` carries `src_data[0]` (the HPD context id).
    fn iv(client: u8, src: u8, src_data0: u32) -> Iv {
        Iv::decode([
            u32::from(client) | (u32::from(src) << 8),
            0,
            0,
            0,
            src_data0,
            0,
            0,
            0,
        ])
    }

    /// The core feeds plugs with the pin level read back per cookie,
    /// never consults the pin for a sink IRQ, and counts everything
    /// it skips. Pin levels arrive in ring order: plug 0 high, plug
    /// 1 low, plug 5 unreadable.
    fn drainer_feeds_plugs_and_skips_the_rest() -> TestResult {
        // DCE client (0x04), HPD source (9), vblank pipe 0 (0x3c),
        // GFX client (0x14) EOP (181).
        let ring = [
            iv(0x04, 0x3c, 0), // vblank: not HPD
            iv(0x14, 181, 0),  // GFX EOP: not HPD
            iv(0x04, 9, 0),    // plug, HPD1
            iv(0x04, 9, 1),    // plug, HPD2
            iv(0x04, 9, 8),    // sink IRQ, HPD3
            iv(0x04, 9, 5),    // plug, HPD6: no sense register
            iv(0x04, 9, 12),   // ctxid past 11: not an HPD event
        ];
        let mut pin_calls: Vec<u8> = Vec::new();
        let mut levels = [Some(true), Some(false), None].into_iter();
        let mut pin = |instance: u8| -> Option<bool> {
            pin_calls.push(instance);
            levels.next().flatten()
        };
        let mut fed: Vec<(u8, bool)> = Vec::new();
        let mut feed = |ctxid: u8, asserted: bool, _tsc: u64| -> Option<HpdOutcome> {
            fed.push((ctxid, asserted));
            Some(HpdOutcome::NoChange)
        };
        let report = drain_ih_hpd_ivs(&ring, 1000, &mut pin, &mut feed);
        if report
            != (IhHpdDrain {
                fed: 3,
                skipped_non_hpd: 3,
                skipped_pin_unreadable: 1,
                unmapped: 0,
                short_pulse: 1,
            })
        {
            return TestResult::Fail("drain counts wrong");
        }
        // The pin was consulted once per plug cookie, in ring order,
        // and never for the sink IRQ.
        if pin_calls != alloc::vec![0, 1, 5] {
            return TestResult::Fail("pin consulted for the wrong cookies");
        }
        // Each fed cookie carried its own level; the sink IRQ's level
        // is the ignored placeholder.
        if fed != alloc::vec![(0, true), (1, false), (8, false)] {
            return TestResult::Fail("fed cookies carry the wrong levels");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", drainer_feeds_plugs_and_skips_the_rest);

    /// A plug and an unplug for the same pin in one batch get their
    /// own readbacks, in ring order: the connect reads high, the
    /// disconnect reads low. A once-per-pin staging would feed the
    /// second cookie the first cookie's level and lose the unplug.
    fn drainer_reads_pin_per_cookie_not_per_pin() -> TestResult {
        let ring = [iv(0x04, 9, 0), iv(0x04, 9, 0)];
        let mut levels = [Some(true), Some(false)].into_iter();
        let mut pin = |_: u8| -> Option<bool> { levels.next().flatten() };
        let mut fed: Vec<(u8, bool)> = Vec::new();
        let mut feed = |ctxid: u8, asserted: bool, _tsc: u64| -> Option<HpdOutcome> {
            fed.push((ctxid, asserted));
            Some(HpdOutcome::NoChange)
        };
        let report = drain_ih_hpd_ivs(&ring, 1000, &mut pin, &mut feed);
        if report.fed != 2 || fed != alloc::vec![(0, true), (0, false)] {
            return TestResult::Fail("same-pin batch did not read back per cookie");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", drainer_reads_pin_per_cookie_not_per_pin);

    /// Feed outcomes flow into the counts: an unmapped source is fed
    /// (the machine saw it) and counted as unmapped; a rejected
    /// context id is not fed at all.
    fn drainer_counts_unmapped_and_rejected() -> TestResult {
        let ring = [iv(0x04, 9, 0), iv(0x04, 9, 1)];
        let mut pin = |_: u8| -> Option<bool> { Some(true) };
        let mut feed = |ctxid: u8, _: bool, _: u64| -> Option<HpdOutcome> {
            if ctxid == 0 {
                Some(HpdOutcome::UnmappedSource)
            } else {
                None
            }
        };
        let report = drain_ih_hpd_ivs(&ring, 1000, &mut pin, &mut feed);
        if report.fed != 1 || report.unmapped != 1 || report.skipped_non_hpd != 0 {
            return TestResult::Fail("unmapped/rejected counts wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", drainer_counts_unmapped_and_rejected);

    /// An empty batch drains to all-zero counts.
    fn drainer_empty_batch() -> TestResult {
        let mut pin = |_: u8| -> Option<bool> { Some(true) };
        let mut feed =
            |_: u8, _: bool, _: u64| -> Option<HpdOutcome> { Some(HpdOutcome::NoChange) };
        if drain_ih_hpd_ivs(&[], 0, &mut pin, &mut feed) != IhHpdDrain::default() {
            return TestResult::Fail("empty batch must drain to zero counts");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", drainer_empty_batch);

    /// Context ids round-trip through the decode/rebuild split:
    /// plug ids 0..5 and sink-IRQ ids 6..11.
    fn drainer_ctxid_round_trip() -> TestResult {
        for ctxid in 0..=11u8 {
            let iv = iv(0x04, 9, u32::from(ctxid));
            let Some(hpd) = iv.hpd() else {
                return TestResult::Fail("HPD cookie did not decode");
            };
            if ctxid_for_hpd(hpd) != ctxid {
                return TestResult::Fail("ctxid did not survive the split");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", drainer_ctxid_round_trip);
}
