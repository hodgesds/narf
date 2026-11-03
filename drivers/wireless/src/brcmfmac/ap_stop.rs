// SPDX-License-Identifier: GPL-2.0-or-later
//! Denial-only stop/cancellation under the original native physical lease.
//! Failed/missing receipts retain the Runtime's mappings; host metadata or a
//! completed-prefix drain never proves firmware MAC/FIFO/DMA quiescence.
use super::{
    ap::Session,
    ap_native::{self, Guard, Phase},
    ap_wire,
};
use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction, runtime::Error, station::Station};
use core::sync::atomic::Ordering;

fn drain<R: Fullmac>(runtime: &mut R) -> Result<bool, Error> {
    for _ in 0..4 {
        let count = runtime.poll()?;
        while runtime.pop_event().is_some() {}
        while runtime.pop_data().is_some() {}
        if count == 0 && runtime.ap_completed_prefix()? {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Session {
    pub(crate) async fn stop<R: Fullmac>(&mut self, station: &mut Station<R>) -> Result<(), Error> {
        // Revoke copied host data/keys/roles before the first native wait,
        // including when START's waiter was dropped or its source revoked.
        self.fail();
        self.cancelled.store(true, Ordering::Release);
        self.phase = Phase::Stopping;
        let native = self.base.native.clone();
        native.current().map_err(|_| Error::Authority)?;
        let guard = Guard::Stop(&native);
        let Some(saved) = self.saved.as_ref() else {
            if self.native_entered {
                return Err(Error::Failed);
            }
            self.phase = Phase::Restored;
            return Ok(());
        };
        // Actual firmware deauthorization/removal. Successful DELETE is
        // still not fabricated here; matching flow/TX terminals follow.
        // Linux primary stop withdraws SET_SSID then DOWN; it does not
        // require a second deauth of a native SCB already removed by loss.
        ap_native::command(
            &mut station.runtime,
            &guard,
            Direction::Set,
            ap_wire::SET_SSID,
            &[0; 52],
            52,
        )
        .await?;
        ap_native::set(&mut station.runtime, &guard, ap_wire::DOWN, 1).await?;
        ap_native::set(&mut station.runtime, &guard, ap_wire::SET_AP, 0).await?;
        if ap_native::get(&mut station.runtime, &guard, ap_wire::GET_AP).await? != 0 {
            return Err(Error::Malformed);
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            native.current().map_err(|_| Error::Authority)?;
            let mut absent = drain(&mut station.runtime)?;
            let reply = ap_native::command(
                &mut station.runtime,
                &guard,
                Direction::Get,
                ap_wire::GET_ASSOCIATIONS,
                &32u32.to_le_bytes(),
                4 + 32 * 6,
            )
            .await?;
            absent &= ap_wire::associations(&reply, 32)?.is_empty();
            for mac in self
                .peers
                .iter()
                .map(|peer| peer.mac)
                .chain(self.rejected.iter().map(|peer| peer.mac))
            {
                absent &= super::ap_station::absent(&mut station.runtime, &guard, mac).await?;
            }
            let terminal = !self.native_entered || station.runtime.ap_leave()?;
            if absent && terminal && drain(&mut station.runtime)? {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        self.native_entered = false;
        saved.restore(&mut station.runtime, &native).await?;
        // Template deletion and saved known radio/offload state are native
        // transactions, not replay of retired credentials/defaults/ports.
        ap_native::vendor(
            &mut station.runtime,
            &guard,
            &self.plan.beacon_vendor,
            &[],
            1,
        )
        .await?;
        ap_native::vendor(
            &mut station.runtime,
            &guard,
            &self.plan.probe_vendor,
            &[],
            2,
        )
        .await?;
        if let Some((beacon, probe)) = &self.pending_template {
            ap_native::vendor(&mut station.runtime, &guard, beacon, &[], 1).await?;
            ap_native::vendor(&mut station.runtime, &guard, probe, &[], 2).await?;
        }
        for index in 1..=3 {
            // Clear all supported GTK slots, including a cancelled install
            // for which the host never obtained an Installed token.
            ap_native::set_var(
                &mut station.runtime,
                &guard,
                "wsec_key",
                &super::ap_key::off_group(index)?,
            )
            .await?;
        }
        if !drain(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        self.group.clear();
        self.peers.clear();
        self.rejected.clear();
        self.received.clear();
        self.early_control.clear();
        self.selected_group = None;
        self.native_group = None;
        self.default_source = None;
        self.busy = false;
        self.phase = Phase::Restored;
        station.ap_forget_station_context();
        Ok(())
    }
}
