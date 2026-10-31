//! Actual Qu RFH/RSS descriptors and source-matched public MVM lifecycle.
use super::*;

pub(super) struct Receipt {
    queue: u8,
    dma: [u64; 3],
    write: u32,
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn qword(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
impl Actor {
    pub(super) fn capture_receive_queues(&mut self) -> Result<bool, &'static str> {
        let mut changed = false;
        for receipt in &self.rx_configuration {
            if self.rx_queues.iter().any(|rx| rx.queue == receipt.queue) {
                continue;
            }
            // SAFETY: configuration keeps its local Owner alive; CURRENT
            // retains it after publication. This actor lock serializes native
            // host polls and injection throughout both fixture lifetimes.
            // These views come from the retained allocations, not DMA casts.
            let Some(rx) = (unsafe { self.trace.take_receive_queue(receipt.queue) }) else {
                continue;
            };
            if rx.dma != receipt.dma || rx.free_write != receipt.write {
                return Err("MVM additional RFH addresses differ from actual retained DMA");
            }
            self.rx_queues.push(rx);
            changed = true;
        }
        Ok(changed)
    }
    pub(super) fn receive_command(
        &mut self,
        group: u8,
        cmd: u8,
        sequence: u16,
        body: &[u8],
    ) -> Result<bool, &'static str> {
        match (group, cmd) {
            (5, 0x0d) => {
                if body.len() != 68
                    || body[..4] != [2, 0, 0, 0]
                    || !self.rx_configuration.is_empty()
                {
                    return Err("MVM RFH_CONFIG actual queue count/extent/one-shot");
                }
                for index in 0..2 {
                    let at = 4 + 32 * index;
                    let queue = index as u8 + 1;
                    let dma = [
                        qword(body, at + 4),
                        qword(body, at + 12),
                        qword(body, at + 20),
                    ];
                    if body[at..at + 4] != [queue, 0, 0, 0]
                        || dma.contains(&0)
                        || dword(body, at + 28) != 504
                    {
                        return Err("MVM RFH_CONFIG literal queue/enable/DMA/index");
                    }
                    self.rx_configuration.push(Receipt {
                        queue,
                        dma,
                        write: 504,
                    });
                }
            }
            (0, 0xb3) => {
                self.capture_receive_queues()?;
                if self.rx_queues.len() != 2
                    || body.len() != 176
                    || body[..8] != [1, 0, 0, 0, 0x3f, 0, 0, 0]
                    || body[48..]
                        .iter()
                        .enumerate()
                        .any(|(i, queue)| *queue != 1 + (i % 2) as u8)
                {
                    return Err("MVM RSS actual rings/hash/indirection receipt");
                }
            }
            (5, 2) => {
                let remove = body.get(12) == Some(&1);
                let count = if remove { 12 } else { 8 };
                if body.len() != 12 + count
                    || body[..4] != [0; 4]
                    || body[4..8] != 7u32.to_le_bytes()
                    || body[8..12] != (count as u32).to_le_bytes()
                    || body[12..16] != [u8::from(remove), 0, 1, 0]
                {
                    return Err("MVM all-RFH native sync1 mask/count/type");
                }
                if remove {
                    if self.retiring_baid != Some(body[20]) {
                        return Err("MVM all-RFH DELBA absent native removal");
                    }
                    self.retiring_baid = None;
                }
                self.inject(cmd, group, sequence, &[]);
                let marker = body[8..].to_vec();
                self.inject(0xff, 5, 0x8000, &marker);
                for rx in &mut self.rx_queues {
                    if self.hold_rx_queue == Some(rx.queue) {
                        self.held_markers.push((rx.queue, marker.clone()));
                    } else {
                        rx.inject(0xff, 5, 0x8000, &marker);
                    }
                }
                return Ok(true);
            }
            _ => return Ok(false),
        }
        self.inject(cmd, group, sequence, &[]);
        Ok(true)
    }
    fn inject_receive(
        &mut self,
        queue: u8,
        command: u8,
        group: u8,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        if queue == 0 {
            self.inject(command, group, 0x8000, bytes);
        } else {
            self.rx_queues
                .iter_mut()
                .find(|rx| rx.queue == queue)
                .ok_or("MVM physical RFH fixture absent")?
                .inject(command, group, 0x8000, bytes);
        }
        Ok(())
    }
    fn release_receive_markers(&mut self) -> Result<(), &'static str> {
        self.hold_rx_queue = None;
        for (queue, marker) in core::mem::take(&mut self.held_markers) {
            self.inject_receive(queue, 0xff, 5, &marker)?;
        }
        Ok(())
    }
}

fn setup(protected: bool) -> Result<Harness, &'static str> {
    Harness::build_nvm_receive(protected, true, 3, 3, true, false, 0, 0, 1, false, true)
}
fn ip(marker: u8) -> Vec<u8> {
    udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        1000 + u16::from(marker),
        45000,
        &[marker; 16],
    )
}
fn packet(
    h: &Harness,
    ethernet: &[u8],
    sn: u16,
    pn: u64,
    baid: u8,
    nssn: u16,
) -> Result<Vec<u8>, &'static str> {
    let actor = h.actor.lock();
    let mut bytes = if actor.protected {
        actor
            .security
            .encrypted_rx_profile(ethernet, pn, false, Some(0))?
    } else {
        let mut frame = from_ap(ethernet, sn);
        frame[0] = 0x88;
        frame.splice(24..24, [0, 0]);
        envelope(&frame)
    };
    // Retry frames exercise Open sequence duplicate ownership too; the
    // CCMP AAD masks Retry, and protected flows retain native PN checks.
    bytes[49] |= 8;
    bytes[70..72].copy_from_slice(&(sn << 4).to_le_bytes());
    bytes[16..20].copy_from_slice(
        &((u32::from(baid) << 24) | (u32::from(sn) << 12) | u32::from(nssn)).to_le_bytes(),
    );
    bytes[28..32].copy_from_slice(&actor.rx_rate.to_le_bytes());
    Ok(bytes)
}
fn receive(h: &Harness, queue: u8, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    h.actor.lock().inject_receive(queue, 0xc1, 0, bytes)?;
    Ok(h.device
        .step(None)
        .into_iter()
        .map(|delivery| delivery.0)
        .collect())
}
fn action(h: &Harness, body: &[u8]) -> Result<(), &'static str> {
    let mut frame = vec![0; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    h.actor.lock().inject_receive(0, 0xc1, 0, &envelope(&frame))
}
fn start(h: &Harness, ssn: u16) -> Result<u8, &'static str> {
    let mut body = vec![3, 0, 9, 2, 2, 0, 0, 0, 0]; // immediate, TID0, window8
    if h.actor.lock().nested_downlink {
        body[3] |= 1;
    }
    body[7..9].copy_from_slice(&(ssn << 4).to_le_bytes());
    action(h, &body)?;
    h.pump()?;
    let actor = h.actor.lock();
    if !actor
        .action_responses
        .iter()
        .any(|b| b.len() == 9 && b[..5] == [3, 1, 9, 0, 0])
    {
        return Err("MVM MQ native positive ADDBA response absent");
    }
    actor.rx_ba[0]
        .map(|entry| entry.0)
        .ok_or("MVM MQ native BAID absent")
}
fn held(h: &Harness) -> Result<(), &'static str> {
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        h.device.step(None);
        h.actor.lock().serve()?;
        if !h.actor.lock().held_markers.is_empty() {
            if h.device
                .control
                .try_lock()
                .is_none_or(|control| control.is_none())
                || h.device.state.try_lock().is_some()
            {
                return Err("MVM all-RFH wait lost retained Work or state owner");
            }
            return Ok(());
        }
        if deadline.expired() {
            return Err("MVM held all-RFH native progress bound");
        }
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
}
fn close(h: &Harness) -> Result<(), &'static str> {
    h.actor.lock().closing = true;
    run(h.device.disassociate())?.map_err(|_| "MVM MQ actual native close")?;
    if h.device.link_up() || h.retained() != (0, 0, 0) {
        return Err("MVM MQ native close left queues or carrier");
    }
    Ok(())
}
fn smoke_mvm_rss_native_three_rings_keep_per_queue_pn_and_fallback_port() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = setup(protected)?;
            h.join()?;
            let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                .map_err(|_| "MVM MQ actual kernel DORA")?;
            if !NETWORK.matches_lease(&lease) {
                return Err("MVM MQ DORA lease");
            }
            for (queue, sn, pn, marker, accepted) in [
                (1, 10, 100, 1, true),
                (2, 20, 5, 2, true),
                (2, 20, 5, 3, false),
                (1, 10, 99, 4, false),
                (2, 21, 6, 5, true),
            ] {
                let ethernet = ip(marker);
                let actual = receive(&h, queue, &packet(&h, &ethernet, sn, pn, 127, 0)?)?;
                if actual.contains(&ethernet) != accepted {
                    return Err("MVM MQ independent or duplicate per-ring PN/sequence admission");
                }
            }
            let mut eapol = ip(6);
            eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
            if !receive(&h, 1, &packet(&h, &eapol, 11, 1000, 127, 0)?)?.is_empty() {
                return Err("MVM MQ misplaced EAPOL escaped fallback port");
            }
            let fresh = ip(7);
            if receive(&h, 1, &packet(&h, &fresh, 12, 101, 127, 0)?)? != [fresh] {
                return Err("MVM MQ misplaced EAPOL poisoned native replay");
            }
            close(&h)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/rx_queues",
    smoke_mvm_rss_native_three_rings_keep_per_queue_pn_and_fallback_port
);

fn smoke_mvm_rss_native_per_ring_nssn_nested_bundle_and_all_marker_baid_reuse() -> TestResult {
    check(|| {
        let h = Harness::build_nvm_receive(true, true, 4, 3, true, false, 0, 0, 1, false, true)?;
        h.join()?;
        h.actor.lock().nested_downlink = true;
        let id = start(&h, 100)?;
        let later = ip(21);
        if !receive(&h, 1, &packet(&h, &later, 102, 102, id, 100)?)?.is_empty() {
            return Err("MVM MQ reordered frame skipped its own hole");
        }
        let other = ip(22);
        if receive(&h, 2, &packet(&h, &other, 100, 10, id, 101)?)? != [other] {
            return Err("MVM MQ other physical BA head inherited first ring");
        }
        h.actor
            .lock()
            .inject_receive(1, 0xc3, 0, &[id, 0, 103, 0])?;
        if h.device
            .step(None)
            .into_iter()
            .map(|d| d.0)
            .collect::<Vec<_>>()
            != [later]
        {
            return Err("MVM MQ NSSN released another physical ring");
        }
        let next = ip(23);
        if receive(&h, 2, &packet(&h, &next, 101, 11, id, 102)?)? != [next] {
            return Err("MVM MQ NSSN or PN crossed physical ring ownership");
        }
        // The tag4 owner and the actual ADDBA request both opt in to
        // nested deaggregation; one physical queue cannot supply another's suffix.
        let frames = [ip(24), ip(25)];
        let mut nested = h.actor.lock().security.encrypted_amsdu(&frames, 104, 0)?;
        for bytes in &mut nested {
            bytes[70..72].copy_from_slice(&(103u16 << 4).to_le_bytes());
            bytes[16..20]
                .copy_from_slice(&((u32::from(id) << 24) | (103u32 << 12) | 104).to_le_bytes());
            bytes[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
        }
        if !receive(&h, 1, &nested[0])?.is_empty() || !receive(&h, 2, &nested[1])?.is_empty() {
            return Err("MVM MQ assembled cross-ring native A-MSDU");
        }
        if receive(&h, 1, &nested[1])? != frames {
            return Err("MVM MQ complete same-ring native A-MSDU failed exact ordered publication");
        }
        h.actor.lock().hold_rx_queue = Some(2);
        action(&h, &[3, 2, 0, 8, 39, 0])?;
        held(&h)?;
        if h.actor.lock().rx_ba[0].is_some() {
            return Err("MVM MQ held prefix skipped native BAID removal");
        }
        h.actor.lock().release_receive_markers()?;
        h.pump()?;
        if start(&h, 200)? != id {
            return Err("MVM MQ final physical marker failed bounded BAID reuse");
        }
        let fresh = ip(26);
        if receive(&h, 2, &packet(&h, &fresh, 200, 12, id, 201)?)? != [fresh] {
            return Err("MVM MQ BAID reuse retained old queue head or uncommitted PN");
        }
        close(&h)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/rx_queues",
    smoke_mvm_rss_native_per_ring_nssn_nested_bundle_and_all_marker_baid_reuse
);

fn smoke_mvm_rss_native_dropped_join_waiter_retains_all_markers_and_closed_copies() -> TestResult {
    check(|| {
        let h = setup(true)?;
        h.scan()?;
        h.actor.lock().hold_rx_queue = Some(2);
        let mut waiter = Box::pin(h.device.associate(h.request()));
        if !once(waiter.as_mut()).is_pending() {
            return Err("MVM MQ public join completed before native prefix");
        }
        held(&h)?;
        drop(waiter); // MVM Work, unlike Sc's direct join, owns completion.
        if h.device.link_up() {
            return Err("MVM MQ one-ring marker opened controlled port");
        }
        let closed = ip(31);
        let closed_packet = packet(&h, &closed, 30, 9000, 127, 0)?;
        h.actor.lock().inject_receive(1, 0xc1, 0, &closed_packet)?;
        h.device.step(None);
        h.actor.lock().serve()?;
        h.actor.lock().release_receive_markers()?;
        h.pump()?;
        if !h.device.link_up() {
            return Err("MVM MQ retained join did not finish after all physical markers");
        }
        let fresh = ip(32);
        if receive(&h, 1, &packet(&h, &fresh, 31, 1, 127, 0)?)? != [fresh] {
            return Err("MVM MQ closed copy poisoned new per-ring key epoch");
        }
        while let Ok(Some(frame)) = h.device.rx.lock().as_mut().unwrap().try_recv() {
            if frame.payload() == closed {
                return Err("MVM MQ closed copy escaped after new epoch opened");
            }
        }
        close(&h)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/rx_queues",
    smoke_mvm_rss_native_dropped_join_waiter_retains_all_markers_and_closed_copies
);

fn smoke_mvm_rss_native_source_loss_during_final_marker_pins_every_ring() -> TestResult {
    check(|| {
        let h = setup(true)?;
        h.scan()?;
        h.actor.lock().hold_rx_queue = Some(2);
        let mut waiter = Box::pin(h.device.associate(h.request()));
        if !once(waiter.as_mut()).is_pending() {
            return Err("MVM MQ source fixture skipped native join wait");
        }
        held(&h)?;
        let dma: Vec<_> = h.actor.lock().rx_queues.iter().map(|rx| rx.dma).collect();
        h.firmware.revoke();
        drop(waiter);
        h.pump()?;
        if h.device.link_up() {
            return Err("MVM MQ revoked executable retained carrier");
        }
        let state = h
            .device
            .state
            .try_lock()
            .ok_or("MVM MQ failed retained state")?;
        let owner = state
            .owner
            .as_ref()
            .ok_or("MVM MQ lost retained native owner")?;
        if !owner.station_failed()
            || owner.model_receive_queue_count() != 3
            || owner.model_retained().1 < 2
        {
            return Err("MVM MQ source loss freed uncertain physical rings/TX owners");
        }
        drop(state);
        h.actor.lock().release_receive_markers()?;
        h.pump()?;
        if h.device.link_up()
            || h.actor
                .lock()
                .rx_queues
                .iter()
                .map(|rx| rx.dma)
                .collect::<Vec<_>>()
                != dma
        {
            return Err("MVM MQ late marker resurrected or changed pinned DMA owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/rx_queues",
    smoke_mvm_rss_native_source_loss_during_final_marker_pins_every_ring
);
