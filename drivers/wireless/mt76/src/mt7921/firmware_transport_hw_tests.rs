//! Exercise the production descriptor/doorbell backend on owned memory.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn rig() -> Result<(Vec<u32>, Hardware), Error> {
    let mut words = vec![0u32; 0x100000 / 4];
    let addr = narf_bus::PcieAddr::new(0, 0, 0, 0);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        id: narf_bus::DeviceId {
            vendor: 0x14c3,
            device: 0x0616,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let mmio = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x100000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let storage = Storage {
        wm: Ring::allocate(TX_WM, false)?,
        fwdl: Ring::allocate(TX_FWDL, false)?,
        data: Ring::allocate(TX_DATA, false)?,
        tokens: packet_tx::Tokens::new(),
        pending_events: VecDeque::new(),
        pending_data: VecDeque::new(),
        rx: [
            Ring::allocate(RX_PRE, true)?,
            Ring::allocate(RX_POST, true)?,
            Ring::allocate(RX_DATA, true)?,
        ],
    };
    Ok((
        words,
        Hardware {
            mmio,
            device,
            authority: Cap::bootstrap(),
            owner: super::super::Retained {
                storage: Some(storage),
                published: false,
            },
        },
    ))
}

fn mcu_dma_production_tx_descriptor_completion_and_wrap() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("transport DMA model allocation failed"),
    };
    for turn in 0..DEPTH + 2 {
        let slot = turn % DEPTH;
        let next = (slot + 1) % DEPTH;
        if hw.submit(true, &[0x55; 64]).is_err() || words[(0xd4400 + 8) / 4] != next as u32 {
            return TestResult::Fail("FWDL did not ring hardware queue 16");
        }
        let ring = &hw.owner.storage.as_ref().unwrap().fwdl;
        if ring.word(slot, 1) != ((64 << 16) | LAST)
            || ring.word(slot, 2) != 0
            || ring.word(slot, 3) != (ring.buffers[slot].dma_addr().raw() >> 32) as u32
        {
            return TestResult::Fail("descriptor lengths/segments/address-high layout");
        }
        if hw.tx_complete(true) != Ok(false) {
            return TestResult::Fail("TX completed before DMA");
        }
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .fwdl
            .set_word(slot, 1, (64 << 16) | LAST | DONE);
        words[(0xd4400 + 12) / 4] = next as u32;
        if hw.tx_complete(true) != Ok(true) {
            return TestResult::Fail("TX completion/wrap failed");
        }
    }
    words[(0xd4400 + 12) / 4] = 99;
    if hw.tx_complete(true) != Err(Error::Ring) {
        return TestResult::Fail("corrupt DMA index accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_production_tx_descriptor_completion_and_wrap
);

fn mt76_recycled_storage_clears_tokens_payloads_indices_and_old_rx() -> TestResult {
    let (_words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("recovery DMA fixture allocation"),
    };
    let storage = hw.owner.storage.as_mut().unwrap();
    for ring in [&mut storage.wm, &mut storage.fwdl, &mut storage.data] {
        ring.index = 7;
        ring.pending = true;
        ring.set_word(7, 0, 0x12340000);
        ring.set_word(7, 1, (64 << 16) | LAST);
        ring.buffers[7].as_mut_slice()[..32].fill(0x77);
    }
    storage.tokens.begin(1).unwrap();
    storage.pending_events.push_back(vec![0x66; 36]);
    storage.pending_data.push_back(vec![0x55; 64]);
    storage.rx[0].index = 9;
    storage.rx[0].set_word(9, 1, (36 << 16) | LAST | DONE);
    // All fixture buffers are CPU-owned; there is no device attached to this
    // memory model. Use the exact storage operation called after stop proof.
    storage.recycle();
    if storage.tokens.available() != Ok(1)
        || !storage.pending_events.is_empty()
        || !storage.pending_data.is_empty()
    {
        return TestResult::Fail("old firmware tokens/replies survived DMA generation reset");
    }
    for ring in [&storage.wm, &storage.fwdl, &storage.data] {
        if ring.index != 0 || ring.pending {
            return TestResult::Fail("old TX index/pending state retained");
        }
        for slot in 0..DEPTH {
            if [
                ring.word(slot, 0),
                ring.word(slot, 1),
                ring.word(slot, 2),
                ring.word(slot, 3),
            ] != [0, DONE, 0, 0]
                || ring.buffers[slot].as_slice().iter().any(|byte| *byte != 0)
            {
                return TestResult::Fail("old TX descriptor/key payload remained device visible");
            }
        }
    }
    for ring in &storage.rx {
        if ring.index != 0 || ring.pending {
            return TestResult::Fail("old RX index retained");
        }
        for slot in 0..DEPTH {
            let address = ring.buffers[slot].dma_addr().raw();
            if [
                ring.word(slot, 0),
                ring.word(slot, 1),
                ring.word(slot, 2),
                ring.word(slot, 3),
            ] != [
                address as u32,
                (MAX_FRAME as u32) << 16,
                0,
                (address >> 32) as u32 & 15,
            ] {
                return TestResult::Fail("RX generation was not freshly armed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_recycled_storage_clears_tokens_payloads_indices_and_old_rx
);

fn mt76_wfsys_reset_uses_real_register_bits_and_preserves_neighbors() -> TestResult {
    let (_words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("reset register fixture allocation"),
    };
    if hw.write(0x18000140, 0xaabb0001).is_err()
        || hw.assert_reset().is_err()
        || hw.read(0x18000140) != Ok(0xaabb0000)
        || hw.release_reset().is_err()
        || hw.read(0x18000140) != Ok(0xaabb0001)
        || hw.reset_done() != Ok(false)
        || hw.write(0x18000140, 0xaabb0011).is_err()
        || hw.reset_done() != Ok(true)
    {
        return TestResult::Fail("WFSYS reset/readiness touched wrong address or mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_wfsys_reset_uses_real_register_bits_and_preserves_neighbors
);

fn mcu_dma_production_rx_copies_before_rearm_and_checks_lengths() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("transport DMA model allocation failed"),
    };
    let mut event = vec![0u8; 36];
    event[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    event[24..26].copy_from_slice(&12u16.to_le_bytes());
    event[28] = 4;
    event[29] = 1;
    event[32] = 2;
    {
        let ring = &hw.owner.storage.as_ref().unwrap().rx[0];
        // SAFETY: model acts as the device, writing its owned coherent buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                event.as_ptr(),
                ring.buffers[0].cpu_mut_ptr::<u8>(),
                event.len(),
            )
        };
        ring.set_word(0, 1, (36 << 16) | LAST | DONE);
    }
    words[(RX_PRE + 12) as usize / 4] = 1;
    if hw.receive() != Ok(Some(event)) || words[(RX_PRE + 8) as usize / 4] != 0 {
        return TestResult::Fail("RX response or release doorbell");
    }
    let ring = &hw.owner.storage.as_ref().unwrap().rx[0];
    if ring.index != 1 || ring.word(0, 1) != (MAX_FRAME as u32) << 16 {
        return TestResult::Fail("RX did not rearm consumed descriptor");
    }
    ring.set_word(1, 1, (((MAX_FRAME + 1) as u32) << 16) | LAST | DONE);
    words[(RX_PRE + 12) as usize / 4] = 2;
    if hw.receive() != Err(Error::MalformedEvent) {
        return TestResult::Fail("oversized RX accepted");
    }
    hw.authority.revoke();
    let old = words[(TX_WM + 8) as usize / 4];
    if hw.submit(false, &[1; 64]) != Err(Error::Authority) || words[(TX_WM + 8) as usize / 4] != old
    {
        return TestResult::Fail("revoked authority published a DMA descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_production_rx_copies_before_rearm_and_checks_lengths
);

fn mcu_production_mac_configuration_preserves_unrelated_bits() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    words[0xf004 / 4] = 1 << 31;
    words[0x34230 / 4] = 1 << 20;
    if hw.configure_mac().is_err() || hw.clear_wtbl(19).is_err() || hw.wtbl_idle() != Ok(true) {
        return TestResult::Fail("MAC/WTBL production operations failed");
    }
    if words[0xf004 / 4] != (1 << 31) | (1536 << 3)
        || words[0xf000 / 4] != (1 << 15) | (1 << 19)
        || words[0x210f4 / 4] != 0x6003f
        || words[0xa10f4 / 4] != 0x6003f
        || words[0x21e00 / 4] != 1536 << 3
        || words[0xa1e00 / 4] != 1536 << 3
        || words[0x34230 / 4] != (1 << 20) | (1 << 12) | 19
        || hw.clear_wtbl(20) != Err(Error::Bounds)
    {
        return TestResult::Fail("MAC register fields differ from Linux");
    }
    words[0x34230 / 4] |= 1 << 31;
    if hw.wtbl_idle() != Ok(false) {
        return TestResult::Fail("busy WTBL accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_production_mac_configuration_preserves_unrelated_bits
);

fn mcu_packet_rx_uses_ring_two_and_copies_before_rearming() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    for iteration in 0..DEPTH + 2 {
        let slot = iteration % DEPTH;
        let next = (slot + 1) % DEPTH;
        let mut packet = [0xabu8; 64];
        packet[..4].copy_from_slice(&((2u32 << 27) | 64).to_le_bytes());
        let ring = &hw.owner.storage.as_ref().unwrap().rx[2];
        // SAFETY: model writes only into the owned coherent RX allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(
                packet.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                packet.len(),
            );
        }
        ring.set_word(slot, 1, (64 << 16) | LAST | DONE);
        words[(RX_DATA + 12) as usize / 4] = next as u32;
        if hw.receive() != Ok(None) {
            return TestResult::Fail("data ring consumed by MCU waiter");
        }
        let received = match hw.receive_data() {
            Ok(Some(packet)) => packet,
            _ => return TestResult::Fail("data ring not harvested"),
        };
        let ring = &hw.owner.storage.as_ref().unwrap().rx[2];
        // SAFETY: emulate the device immediately reusing the released buffer.
        unsafe {
            core::ptr::write_bytes(ring.buffers[slot].cpu_mut_ptr::<u8>(), 0, 64);
        }
        if received != packet
            || ring.index != next
            || ring.word(slot, 1) != (4096 << 16)
            || words[(RX_DATA + 8) as usize / 4] != slot as u32
        {
            return TestResult::Fail("data copy/rearm/wrap/doorbell ordering");
        }
    }
    hw.authority.revoke();
    if hw.receive_data() != Err(Error::Authority) {
        return TestResult::Fail("revoked packet RX authority accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_packet_rx_uses_ring_two_and_copies_before_rearming
);

fn management_frame() -> [u8; 30] {
    let mut frame = [0u8; 30];
    frame[0] = 0xb0;
    frame[4..10].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame
}
fn release_event(token: u16, status: u8, pair: bool) -> Vec<u8> {
    let mut packet = vec![0u8; if pair { 16 } else { 12 }];
    let len = packet.len();
    packet[..4].copy_from_slice(&((1u32 << 16) | len as u32).to_le_bytes());
    let mut offset = 8;
    if pair {
        packet[offset..offset + 4].copy_from_slice(&((1u32 << 31) | (19 << 14)).to_le_bytes());
        offset += 4;
    }
    packet[offset..offset + 4]
        .copy_from_slice(&((u32::from(token) << 16) | (u32::from(status) << 13)).to_le_bytes());
    packet
}
fn inject_rx(words: &mut [u32], hw: &Hardware, which: usize, packet: &[u8]) {
    let ring = &hw.owner.storage.as_ref().unwrap().rx[which];
    let slot = ring.index;
    // SAFETY: fake device writes only to the owned descriptor buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            packet.as_ptr(),
            ring.buffers[slot].cpu_mut_ptr::<u8>(),
            packet.len(),
        );
    }
    ring.set_word(slot, 1, ((packet.len() as u32) << 16) | LAST | DONE);
    words[(ring.base + 12) as usize / 4] = ((slot + 1) % DEPTH) as u32;
}
fn mcu_management_tx_matches_linux_cut_through_header() -> TestResult {
    let frame = management_frame();
    let header = packet_tx::management(
        &frame,
        0x12345040,
        0x1234,
        19,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .unwrap();
    let expected = [
        0x2000003eu32,
        0x80026013,
        0x8000200b,
        0x10007800,
        0,
        0,
        4,
        0x000b0000,
    ];
    for (i, word) in expected.iter().enumerate() {
        if header[i * 4..i * 4 + 4] != word.to_le_bytes() {
            return TestResult::Fail("management TXD differs from Linux");
        }
    }
    if header[32..40] != [0x34, 0x92, 0, 0, 0, 0, 0, 0]
        || header[40..48] != [0x40, 0x50, 0x34, 0x12, 30, 0x80, 0, 0]
        || header[48..].iter().any(|b| *b != 0)
        || packet_tx::management(
            &frame,
            1u64 << 32,
            1,
            19,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        ) != Err(Error::DmaAddress)
        || packet_tx::management(
            &frame[..23],
            0,
            1,
            19,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        ) != Err(Error::Bounds)
    {
        return TestResult::Fail("TXP segment/token/last/address geometry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_management_tx_matches_linux_cut_through_header
);
fn mcu_management_buffer_waits_for_dma_and_firmware_release_in_either_order() -> TestResult {
    for dma_first in [false, true] {
        let (mut words, mut hw) = match rig() {
            Ok(rig) => rig,
            Err(_) => return TestResult::Fail("allocation"),
        };
        hw.owner.published = true;
        for turn in 0..DEPTH + 2 {
            let frame = management_frame();
            let slot = turn % DEPTH;
            let next = (slot + 1) % DEPTH;
            if hw
                .submit_management(&frame, 19, crate::mt7921::association::LegacyRate::ONE_MBPS)
                .is_err()
                || words[(TX_DATA + 8) as usize / 4] != next as u32
            {
                return TestResult::Fail("management doorbell or ring wrap");
            }
            let token = turn as u16 + 1;
            let ring = &hw.owner.storage.as_ref().unwrap().data;
            if ring.word(slot, 1) != (64 << 16) | LAST {
                return TestResult::Fail("DMA must publish TXD+TXP, not payload length");
            }
            if hw.submit_management(&frame, 19, crate::mt7921::association::LegacyRate::ONE_MBPS)
                != Err(Error::Busy)
                || !matches!(hw.management_complete(), Ok(None))
            {
                return TestResult::Fail("pending token allowed reuse");
            }
            if dma_first {
                hw.owner
                    .storage
                    .as_ref()
                    .unwrap()
                    .data
                    .set_word(slot, 1, (64 << 16) | LAST | DONE);
                words[(TX_DATA + 12) as usize / 4] = next as u32;
                if !matches!(hw.management_complete(), Ok(None)) {
                    return TestResult::Fail("DDONE freed payload before firmware");
                }
            }
            let packet = release_event(token, 0, true);
            inject_rx(&mut words, &hw, 0, &packet); // notifications may use any RX ring
            if hw.receive() != Ok(None) {
                return TestResult::Fail("TX free reached MCU command waiter");
            }
            if !dma_first {
                if !matches!(hw.management_complete(), Ok(None)) {
                    return TestResult::Fail("firmware release freed descriptor before DMA");
                }
                hw.owner
                    .storage
                    .as_ref()
                    .unwrap()
                    .data
                    .set_word(slot, 1, (64 << 16) | LAST | DONE);
                words[(TX_DATA + 12) as usize / 4] = next as u32;
            }
            if hw.management_complete() != Ok(Some(packet_tx::Completion { token, status: 0 })) {
                return TestResult::Fail("two-phase completion did not retire token");
            }
        }
        hw.owner.published = false; // model has no actual DMA engine
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_management_buffer_waits_for_dma_and_firmware_release_in_either_order
);
fn mcu_tx_release_batch_is_atomic_and_preserves_failure_status() -> TestResult {
    let mut tokens = packet_tx::Tokens::new();
    tokens.begin(1).unwrap();
    tokens.dma_done().unwrap();
    let mut packet = release_event(1, 0, true);
    packet[..4].copy_from_slice(&((2u32 << 16) | 16).to_le_bytes()); // declares a missing second MSDU
    if packet_tx::releases(&packet) != Err(Error::MalformedEvent) || tokens.finish().is_some() {
        return TestResult::Fail("truncated TX release mutated owner");
    }
    let conflicting = [
        packet_tx::Completion {
            token: 1,
            status: 0,
        },
        packet_tx::Completion {
            token: 1,
            status: 2,
        },
    ];
    if tokens.firmware_done(&conflicting) != Err(Error::MalformedEvent) || tokens.finish().is_some()
    {
        return TestResult::Fail("conflicting duplicate release partially committed");
    }
    tokens
        .firmware_done(&[packet_tx::Completion {
            token: 77,
            status: 0,
        }])
        .unwrap();
    if tokens.finish().is_some() {
        return TestResult::Fail("stale token freed current payload");
    }
    let dropped = packet_tx::releases(&release_event(1, 3, false)).unwrap();
    tokens.firmware_done(&dropped).unwrap();
    if tokens.finish()
        != Some(packet_tx::Completion {
            token: 1,
            status: 3,
        })
        || tokens.available() != Ok(2)
    {
        return TestResult::Fail("firmware failure status lost or token reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_tx_release_batch_is_atomic_and_preserves_failure_status
);
fn mcu_packet_router_separates_forwarded_management_from_command_replies() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    let mut normal = vec![0u8; 64];
    normal[..4].copy_from_slice(&((7u32 << 27) | (1 << 16) | 64).to_le_bytes());
    inject_rx(&mut words, &hw, 0, &normal);
    if hw.receive() != Ok(None) || hw.receive_data() != Ok(Some(normal)) {
        return TestResult::Fail("firmware-forwarded MPDU confused with MCU response");
    }
    let mut reply = vec![0u8; 36];
    reply[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    inject_rx(&mut words, &hw, 2, &reply);
    if hw.receive_data() != Ok(None) || hw.receive() != Ok(Some(reply)) {
        return TestResult::Fail("MCU response on data ring was dropped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_packet_router_separates_forwarded_management_from_command_replies
);

fn mcu_receive_router_bounds_both_queues_without_dropping_command_replies() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    for i in 0..33u8 {
        let mut packet = [0u8; 64];
        packet[..4].copy_from_slice(&((2u32 << 27) | 64).to_le_bytes());
        packet[63] = i;
        inject_rx(&mut words, &hw, 0, &packet);
        if hw.receive() != Ok(None) {
            return TestResult::Fail("normal packet reached command waiter");
        }
    }
    let storage = hw.owner.storage.as_ref().unwrap();
    if storage.pending_data.len() != 32 || storage.pending_data.front().unwrap()[63] != 1 {
        return TestResult::Fail("normal RX backlog is unbounded or keeps stale data");
    }
    // Clear the data backlog before exercising event routing on data ring 2.
    hw.owner.storage.as_mut().unwrap().pending_data.clear();
    for _ in 0..32 {
        let mut packet = [0u8; 36];
        packet[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
        inject_rx(&mut words, &hw, 2, &packet);
        if hw.receive_data() != Ok(None) {
            return TestResult::Fail("MCU reply reached packet receiver");
        }
    }
    let mut packet = [0u8; 36];
    packet[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    inject_rx(&mut words, &hw, 2, &packet);
    if hw.receive_data() != Err(Error::EventOverflow)
        || hw.owner.storage.as_ref().unwrap().pending_events.len() != 32
    {
        return TestResult::Fail("command reply overflow silently discarded an older reply");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_receive_router_bounds_both_queues_without_dropping_command_replies
);

fn mcu_tx_completion_pump_preserves_queued_and_fresh_command_replies() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    hw.owner.published = true;
    if hw
        .submit_management(
            &management_frame(),
            1,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        )
        .is_err()
    {
        return TestResult::Fail("publish management TX");
    }
    let mut old = vec![0u8; 36];
    old[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    old[24..26].copy_from_slice(&12u16.to_le_bytes());
    old[28] = 1;
    old[29] = 1;
    let mut fresh = old.clone();
    fresh[29] = 2;
    hw.owner
        .storage
        .as_mut()
        .unwrap()
        .pending_events
        .push_back(old.clone());
    inject_rx(&mut words, &hw, 0, &fresh);
    inject_rx(&mut words, &hw, 1, &release_event(1, 0, false));
    hw.owner
        .storage
        .as_ref()
        .unwrap()
        .data
        .set_word(0, 1, (64 << 16) | LAST | DONE);
    words[(TX_DATA + 12) as usize / 4] = 1;
    let completion = hw.management_complete();
    let first = hw.receive();
    let second = hw.receive();
    hw.owner.published = false; // Fixture owns memory; no device engine exists.
    if completion
        != Ok(Some(packet_tx::Completion {
            token: 1,
            status: 0,
        }))
        || first != Ok(Some(old))
        || second != Ok(Some(fresh))
    {
        return TestResult::Fail(
            "completion pumping consumed MCU response or failed to harvest TX free",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_tx_completion_pump_preserves_queued_and_fresh_command_replies
);
