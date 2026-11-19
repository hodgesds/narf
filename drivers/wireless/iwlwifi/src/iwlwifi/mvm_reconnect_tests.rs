//! Retained native GTK retirement/reconnect. The same production Owner keeps
//! its ledger while the independent AP starts a new real auth/RSNA exchange.
use super::*;
const FLOOR: u64 = 0x0102_0304_0506;
fn ethernet() -> Vec<u8> {
    udp_ipv4(
        [255; 6],
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        b"retained GTK floor",
    )
}
fn packet(h: &Harness, tid: u8, pn: u64) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut bytes =
        h.actor
            .lock()
            .security
            .encrypted_rx_profile(&ethernet(), pn, true, Some(tid))?;
    bytes[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
    h.actor.lock().inject(0xc1, 0, 0x8000, &bytes);
    Ok(h.device.step(None).into_iter().map(|p| p.0).collect())
}
fn close(h: &Harness) -> Result<(), &'static str> {
    h.actor.lock().closing = true;
    run(h.device.disassociate())?.map_err(|_| "native reconnect close")?;
    if h.device.link_up() || h.retained() != (0, 0, 0) {
        return Err("reconnect before native key/queue/PHY retirement");
    }
    Ok(())
}
fn restart(h: &Harness) -> Result<(), &'static str> {
    let mut a = h.actor.lock();
    if !a.batch.is_empty() || a.held.is_some() {
        return Err("AP restart hid uncertain native packets/control");
    }
    a.security.restart_authenticator(FLOOR)?;
    a.security.ap = ap(true)?;
    a.m1_sent = false;
    a.data_added = false;
    a.closing = false;
    a.tx_dialog = None;
    a.batch.clear();
    a.batch_dma.clear();
    if a.tx_ba_enabled || a.rx_ba.iter().any(Option::is_some) {
        return Err("AP restart hid an active native BA owner");
    }
    a.server = DhcpServer::new(NETWORK);
    Ok(())
}
fn seed(ba: bool) -> Result<Harness, &'static str> {
    let h = if ba {
        Harness::build_profile(true, true, 3, 3, true)?
    } else {
        Harness::profile(true, true)?
    };
    h.join()?;
    if packet(&h, 5, FLOOR)? != [ethernet()] {
        return Err("native GTK seed did not commit actual authenticated frame");
    }
    Ok(h)
}
fn verify_restored(h: &Harness) -> Result<(), &'static str> {
    let a = h.actor.lock();
    let key = &a
        .commands
        .iter()
        .rev()
        .find(|(g, c, b)| *g == 1 && *c == 0x17 && b.len() == 76 && b[..4] == [0, 2, 10, 65])
        .ok_or("native reconnect GTK ADD absent")?
        .2;
    if key[36..44] != [1, 2, 3, 4, 5, 6, 0, 0] || key[44..] != [0; 32] {
        return Err("native GTK install lowered retired PN or initialized a TX group producer");
    }
    drop(a);
    // Firmware's single install RSC uses the maximum committed TID floor,
    // like Linux sta.c. Every host TID stays at least that conservative floor.
    for tid in 0..8 {
        if !packet(h, tid, FLOOR)?.is_empty() {
            return Err("old GTK PN escaped fresh association/other TID");
        }
        if packet(h, tid, FLOOR + 1)? != [ethernet()] {
            return Err("restored GTK cannot accept new authenticated PN");
        }
    }
    Ok(())
}
fn smoke_mvm_gtk_reconnect_same_peer_native_floor_and_real_dhcp() -> TestResult {
    check(|| {
        for ba in [false, true] {
            let h = seed(ba)?;
            close(&h)?;
            restart(&h)?;
            h.join()?;
            verify_restored(&h)?;
            let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                .map_err(|_| "reconnected native kernel DHCP")?;
            if !NETWORK.matches_lease(&lease) {
                return Err("GTK reconnect kernel DHCP mismatch");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_same_peer_native_floor_and_real_dhcp
);

fn smoke_mvm_gtk_reconnect_m4_cancellation_keeps_same_native_work() -> TestResult {
    check(|| {
        let h = seed(true)?;
        close(&h)?;
        restart(&h)?;
        held_join(&h)?;
        if h.device.link_up() {
            return Err("cached GTK history bypassed real M4 receipt");
        }
        h.actor.lock().release();
        h.pump()?;
        if !h.device.link_up() {
            return Err("retained reconnect work failed after actual terminal M4");
        }
        verify_restored(&h)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_m4_cancellation_keeps_same_native_work
);

fn smoke_mvm_gtk_reconnect_current_source_power_policy_still_gate_late_m4() -> TestResult {
    check(|| {
        for fault in 0..3 {
            let h = seed(true)?;
            close(&h)?;
            restart(&h)?;
            held_join(&h)?;
            match fault {
                0 => h.firmware.revoke(),
                1 => h.power.revoke(),
                _ => {
                    h.db.clear();
                }
            }
            h.actor.lock().release();
            h.pump()?;
            h.db.install(domain());
            h.pump()?;
            if h.device.link_up()
                || !h.device.terminal.load(Ordering::Acquire)
                || h.retained().1 != 2
            {
                return Err("retained GTK proof bypassed current source/power/policy or reclaimed uncertain DMA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_current_source_power_policy_still_gate_late_m4
);

fn smoke_mvm_gtk_reconnect_native_retirement_marker_not_waiter_drop_allows_reuse() -> TestResult {
    check(|| {
        let h = seed(true)?;
        {
            let mut a = h.actor.lock();
            a.closing = true;
            a.hold_phy = Some(9);
        }
        {
            let mut future = Box::pin(h.device.disassociate());
            let mut found = false;
            for _ in 0..256 {
                if once(future.as_mut()).is_ready() {
                    return Err("retirement skipped held native RX marker");
                }
                h.actor.lock().serve()?;
                if h.actor.lock().security.holding() {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err("native GTK retirement marker not held");
            }
        }
        if h.device.link_up()
            || h.device.state.try_lock().is_some()
            || h.device.control.try_lock().unwrap().is_none()
            || run(h.device.associate(h.request()))?.is_ok()
        {
            return Err(
                "cancelled retirement exposed reusable GTK/second producer before RX proof",
            );
        }
        h.actor.lock().release();
        h.pump()?;
        if h.retained() != (0, 0, 0) {
            return Err("native retirement failed to finish after marker");
        }
        restart(&h)?;
        h.join()?;
        verify_restored(&h)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_native_retirement_marker_not_waiter_drop_allows_reuse
);

fn smoke_mvm_gtk_reconnect_repeated_associations_never_lower_saved_floor() -> TestResult {
    check(|| {
        let h = seed(false)?;
        for _ in 0..3 {
            close(&h)?;
            restart(&h)?;
            h.join()?;
            if !packet(&h, 5, FLOOR)?.is_empty() {
                return Err("repeated association forgot prior GTK PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_repeated_associations_never_lower_saved_floor
);

fn smoke_mvm_gtk_reconnect_exhausted_retired_pn_needs_actual_new_material() -> TestResult {
    check(|| {
        let h = Harness::profile(true, true)?;
        h.join()?;
        if packet(&h, 5, 0xffff_ffff_ffff)? != [ethernet()] {
            return Err("maximum native GTK PN seed failed");
        }
        close(&h)?;
        restart(&h)?;
        h.scan()?;
        let before = h
            .actor
            .lock()
            .commands
            .iter()
            .filter(|(g, c, b)| *g == 1 && *c == 0x17 && b.len() == 76 && b[..4] == [0, 2, 10, 65])
            .count();
        if run(h.device.associate(h.request()))?.is_ok()
            || h.device.link_up()
            || !h.device.terminal.load(Ordering::Acquire)
            || h.actor
                .lock()
                .commands
                .iter()
                .filter(|(g, c, b)| {
                    *g == 1 && *c == 0x17 && b.len() == 76 && b[..4] == [0, 2, 10, 65]
                })
                .count()
                != before
        {
            return Err("retired GTK48-bit PN exhaustion reset a native key or opened port");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_mvm_gtk_reconnect_exhausted_retired_pn_needs_actual_new_material
);
