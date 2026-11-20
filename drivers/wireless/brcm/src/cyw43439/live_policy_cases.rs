// SPDX-License-Identifier: GPL-2.0-or-later
// Included by each native transport harness. No global policy mutation.
use narf_wireless::reg::{db::Database, RegFlags, RegRule};

fn database() -> Arc<Database> {
    let database = Arc::new(Database::new());
    database.install(firmware::domain());
    database
}
fn packet() -> Vec<u8> {
    let mut bytes = vec![0x4a; 60];
    bytes[..6].copy_from_slice(&AP);
    bytes[6..12].copy_from_slice(&OWN);
    bytes[12..14].copy_from_slice(&[8, 0]);
    bytes
}
fn terminal(harness: &Harness, database: &Database, before: usize) -> Result<(), &'static str> {
    harness.device.drain();
    if harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || harness.device.enqueue(&packet()).is_ok()
        || sent(harness) != before
        || narf_net::iface::lookup(&harness.name)
            .is_none_or(|iface| !iface.link_up || iface.carrier)
    {
        return Err("live policy loss retained peer/carrier or published queued TX");
    }
    {
        let mut state = harness.device.state.try_lock().unwrap();
        if state.pending.is_some() || !matches!(state.tx.try_recv(), Ok(None)) {
            return Err("live policy loss retained pending/queued host transmit");
        }
    }
    database.install(firmware::domain());
    stale_authorization(harness);
    harness.device.drain();
    if harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || harness.device.set_power_save(false) != Err(19)
        || harness
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .poll()
            .is_ok()
    {
        return Err("policy reinstall or stale firmware event reopened terminal lifetime");
    }
    retained(harness)
}
fn tightening() -> Result<(), &'static str> {
    for variant in 0..5 {
        let database = database();
        let harness = live(database.clone())?;
        connect(&harness)?;
        let before = sent(&harness);
        harness
            .device
            .enqueue(&packet())
            .map_err(|_| "policy pre-change TX")?;
        let mut domain = firmware::domain();
        match variant {
            0 => domain.rules[0].max_power_dbm = 10,
            // Overlap with an otherwise permissive rule must still deny TX.
            1 => domain.rules.push(RegRule {
                freq_start_mhz: 2430,
                freq_end_mhz: 2450,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: RegFlags::NO_IR,
            }),
            2 => domain.rules.clear(),
            3 => domain.country_code = *b"CA",
            _ => {}
        }
        if variant == 4 {
            database.clear();
        } else {
            database.install(domain);
        }
        terminal(&harness, &database, before)?;
    }
    Ok(())
}
fn relaxation() -> Result<(), &'static str> {
    let database = database();
    let harness = live(database.clone())?;
    connect(&harness)?;
    let before_power = powers(&harness);
    let mut domain = firmware::domain();
    domain.rules[0].max_power_dbm = 20;
    database.install(domain);
    harness
        .device
        .enqueue(&packet())
        .map_err(|_| "relaxed TX")?;
    let before = sent(&harness);
    for _ in 0..6 {
        harness.device.drain();
    }
    if !harness.device.link_up()
        || harness.device.connected_bssid() != Some(AP)
        || sent(&harness) <= before
        || powers(&harness) != before_power
    {
        return Err("policy relaxation changed acknowledged power or lost authorized data");
    }
    // Even a tighter replacement is admissible while its ceiling still
    // covers the connection's original, acknowledged 17 dBm grant.
    let mut domain = firmware::domain();
    domain.rules[0].max_power_dbm = 18;
    database.install(domain);
    harness.device.drain();
    if !harness.device.link_up() || powers(&harness) != before_power {
        return Err("connection compared policy generations instead of applied TX ceiling");
    }
    retained(&harness)
}
fn between_receipts() -> Result<(), &'static str> {
    // Firmware consumes a real native command and replaces policy before
    // returning its receipt. No subsequent command/event may authorize it.
    for command in [26, 86, 263] {
        let database = database();
        let harness = live(database.clone())?;
        if command == 86 {
            connect(&harness)?;
        } else if command == 26 {
            scan(&harness)?;
        }
        replace_on_command(&harness, command, database.clone());
        if command == 86 {
            harness
                .device
                .set_power_save(true)
                .map_err(|_| "live PS request")?;
            ready(harness.device.apply_power_save())?;
        } else if command == 263 {
            if scan(&harness).is_ok() {
                return Err("native scan receipt used stale policy");
            }
        } else if ready(harness.device.associate(request()))?.is_ok() {
            return Err("native join receipt authorized stale host policy");
        }
        terminal(&harness, &database, sent(&harness))?;
    }
    Ok(())
}
