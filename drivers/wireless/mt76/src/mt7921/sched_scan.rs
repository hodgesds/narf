//! Host scheduled scan on the idle station (NL80211_CMD_START_SCHED_SCAN).
//! Linux mt7921_start_sched_scan / mt7921_stop_sched_scan
//! (mt76_connac_mcu_sched_scan_req + mt76_connac_mcu_sched_scan_enable)
//! and mt7921_scan_work's MCU_EVENT_SCHED_SCAN_DONE, after which mac80211
//! reports the BSSs the firmware's scan cycle received
//! (ieee80211_sched_scan_results). The request is the same CONNAC2
//! network-list offload WoWLAN net-detect programs (`nlo::Plan`), with the
//! same channel and probe-permission checks.
use super::*;
use crate::mt7921::wowlan_nlo;
use narf_wireless::NetDetectConfig;

/// `MCU_EVENT_SCHED_SCAN_DONE`: one scheduled scan cycle finished.
pub(in crate::mt7921::firmware_transport) const SCHED_SCAN_DONE: u8 = 0x23;

/// Bounded work per step, like the one-shot scan collector.
const STEP_FRAMES: usize = 16;
const STEP_EVENTS: usize = 4;

/// A running scheduled scan and the BSSs of its current cycle.
#[derive(Debug)]
pub(in crate::mt7921::firmware_transport) struct Running {
    plan: nlo::Plan,
    info: RadioInfo,
    cycle: ScanReport,
}

fn empty_report() -> ScanReport {
    ScanReport {
        bss: Vec::new(),
        beaconed: Vec::new(),
        received: 0,
        ignored: 0,
        truncated: false,
    }
}

impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) fn sched_scan_running(&self) -> bool {
        self.sched.is_some()
    }

    /// `mt7921_start_sched_scan`: program the request and enable it on the
    /// idle home vif. Nothing is written for a refused request or channel.
    pub(in crate::mt7921::firmware_transport) async fn start_sched_scan(
        &mut self,
        config: &NetDetectConfig,
    ) -> Result<(), Error> {
        if self.sched.is_some() || self.scanning || self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let (info, setup) = match self.state {
            State::RadioReady(info) => (info, true),
            State::ScanReady(info) => (info, false),
            _ => return Err(Error::Busy),
        };
        let plan = nlo::Plan::prepare(&self.backend, info, config, None)?;
        // A cycle completion of an earlier request is not this one's.
        self.events
            .retain(|event| event.get(28) != Some(&SCHED_SCAN_DONE));
        let result = async {
            self.stage(Stage::ScanSetup);
            if setup {
                self.scan_setup(info).await?;
            }
            self.program_wow_nlo(&plan, config).await
        }
        .await;
        match result {
            Ok(()) => {
                self.state = State::ScanReady(info);
                self.sched = Some(Running {
                    plan,
                    info,
                    cycle: empty_report(),
                });
                Ok(())
            }
            Err(error) => {
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::ScanSetup,
                };
                // Best effort only: neither receipt proves the firmware
                // stopped scanning, so the attempt stays terminal.
                let _ = self.disable_sched_scan(info).await;
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }

    /// Collect the running cycle's Beacons and Probe Responses on the
    /// request's channels; at `MCU_EVENT_SCHED_SCAN_DONE` hand the cycle's
    /// results over and start the next. `Cancelled` when none runs (a
    /// verified reset retired it).
    pub(in crate::mt7921::firmware_transport) fn step_sched_scan(
        &mut self,
    ) -> Result<Option<ScanReport>, Error> {
        let Some(running) = self.sched.as_mut() else {
            return Err(Error::Cancelled);
        };
        running.plan.current(&self.backend)?;
        let nss = running.info.capabilities.phy.spatial_streams;
        for _ in 0..STEP_FRAMES {
            let Some(packet) = self.backend.receive_data()? else {
                break;
            };
            let cycle = &mut running.cycle;
            cycle.received = cycle.received.saturating_add(1);
            let Some(bss) = beacon(&packet, nss) else {
                cycle.ignored = cycle.ignored.saturating_add(1);
                continue;
            };
            if scan_id(&bss).is_none_or(|id| !running.plan.scan_ids().contains(&id)) {
                continue;
            }
            cycle.record(&packet, bss);
        }
        let mut done = false;
        if let Some(at) = self
            .events
            .iter()
            .position(|event| event.get(28) == Some(&SCHED_SCAN_DONE))
        {
            self.events.remove(at);
            done = true;
        }
        for _ in 0..STEP_EVENTS {
            let Some(event) = self.backend.receive()? else {
                break;
            };
            if event.len() < 36 {
                return Err(Error::MalformedEvent);
            }
            let len = usize::from(u16::from_le_bytes([event[24], event[25]])) + 24;
            if len < 36 || len > event.len() {
                return Err(Error::MalformedEvent);
            }
            if event[28] == SCHED_SCAN_DONE {
                done = true;
            } else {
                // No command waits while idle; unrelated notifications are
                // counted, not queued.
                running.cycle.ignored = running.cycle.ignored.saturating_add(1);
            }
        }
        Ok(done.then(|| core::mem::replace(&mut running.cycle, empty_report())))
    }

    /// `mt7921_stop_sched_scan`. A failed stop leaves the radio for the
    /// verified reset path.
    pub(in crate::mt7921::firmware_transport) async fn stop_sched_scan(
        &mut self,
    ) -> Result<(), Error> {
        let running = self.sched.take().ok_or(Error::Cancelled)?;
        let result = self.disable_sched_scan(running.info).await;
        self.events
            .retain(|event| event.get(28) != Some(&SCHED_SCAN_DONE));
        if let Err(error) = result {
            self.state = State::Failed {
                stage: Stage::ScanWait,
                error,
            };
        }
        result
    }

    async fn disable_sched_scan(&mut self, info: RadioInfo) -> Result<(), Error> {
        self.notify(
            Command::Ce {
                id: wowlan_nlo::ENABLE,
                query: false,
            },
            &wowlan_nlo::enable(false),
        )
        .await?;
        // Probe permission belonged to the scheduled scan, not the idle
        // VIF: the idle domain is NO_IR again.
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &passive_domain(info),
        )
        .await
    }
}
