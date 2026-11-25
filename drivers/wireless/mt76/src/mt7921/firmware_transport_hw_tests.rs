//! Exercise the production descriptor/doorbell backend on owned memory.
use super::*;
#[path = "p2p_management_hw_tests.rs"]
mod p2p_management;
#[path = "p2p_management_tx_hw_tests.rs"]
mod p2p_management_tx;
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "ap_management_hw_tests.rs"]
mod ap_management_hw_tests;
#[path = "ap_packet_hw_tests.rs"]
mod ap_packet_hw_tests;
#[path = "ap_timing_hw_tests.rs"]
mod ap_timing_hw_tests;

#[path = "firmware_transport_hw_iommu_tests.rs"]
mod iommu_tests;
#[path = "firmware_transport_hw_ncdma_tests.rs"]
mod ncdma_tests;
#[path = "tx_pipeline_hw_tests.rs"]
mod tx_pipeline_hw_tests;
#[path = "tx_sequence_hw_tests.rs"]
mod tx_sequence_hw_tests;

fn rig() -> Result<(Vec<u32>, Hardware), Error> {
    rig_with(
        &narf_io::DmaDevice::coherent(),
        narf_bus::PcieAddr::new(0, 0, 0, 0),
        0x0616,
        0x100000,
    )
}

/// [`rig`] for an MT7925 function: PCI id `0x0717` with the real
/// 2 MiB BAR0 (the 7925 L1 selector at `0x155024` needs it).
fn rig_7925() -> Result<(Vec<u32>, Hardware), Error> {
    rig_with(
        &narf_io::DmaDevice::coherent(),
        narf_bus::PcieAddr::new(0, 0, 0, 0),
        0x0717,
        0x200000,
    )
}

/// [`rig`] for the function at `addr` with every ring allocated through
/// `dma` (as `Transport::new` does after `narf_bus::dma::configure`).
fn rig_with(
    dma: &narf_io::DmaDevice,
    addr: narf_bus::PcieAddr,
    did: u16,
    bar_len: u64,
) -> Result<(Vec<u32>, Hardware), Error> {
    let mut words = vec![0u32; bar_len as usize / 4];
    let device = BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        id: narf_bus::DeviceId {
            vendor: 0x14c3,
            device: did,
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
        len: bar_len,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let storage = Storage {
        wm: Ring::allocate_for(dma, TX_WM, false, DEPTH)?,
        fwdl: Ring::allocate_for(dma, TX_FWDL, false, DEPTH)?,
        data: Ring::allocate_for(dma, TX_DATA, false, DEPTH)?,
        data_dma: 0,
        tokens: packet_tx::Tokens::new(),
        // The descriptor fixtures pin exact TXD words and PIDs; the
        // periodic rate sample has its own test (tx_sequence_hw_tests).
        tx_sequence: crate::mt7921::tx_sequence::Owner::without_rate_sampling(),
        pending_events: VecDeque::new(),
        pending_data: VecDeque::new(),
        receive_epoch: 0,
        receive_open: false,
        p2p_capture: super::super::p2p_management_capture::Queue::new(),
        rx: [
            Ring::allocate_for(dma, RX_PRE, true, DEPTH)?,
            Ring::allocate_for(dma, RX_POST, true, DEPTH)?,
            Ring::allocate_for(dma, RX_DATA, true, DEPTH)?,
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
            hw_amsdu: false,
            sequence_reset: SequenceReset::None,
            wake: wake::Wake::default(),
            irq: None,
            pace: crate::mt7921::firmware_transport::Pace::default(),
        },
    ))
}

fn mcu_actual_chip_id_uses_current_native_register_and_never_pci_alias() -> TestResult {
    let (mut words, hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("actual chip native allocation"),
    };
    // The fixture's PCI function is0x0616. Chip identity still comes from
    // MT_HW_CHIPID through the real checked remap transaction.
    for chip in [0x7961u32, 0x7922, 0x7920] {
        words[0x40200 / 4] = chip;
        if hw.chip_id() != Ok(chip as u16) {
            return TestResult::Fail("actual native chip identity was not retained");
        }
    }
    for chip in [0, 0x0608, 0x0616, u32::MAX] {
        words[0x40200 / 4] = chip;
        let expected = if chip == u32::MAX {
            Error::DeviceGone
        } else {
            Error::InvalidIdentity
        };
        if hw.chip_id() != Err(expected) {
            return TestResult::Fail("PCI alias or absent chip register created native identity");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht160",
    mcu_actual_chip_id_uses_current_native_register_and_never_pci_alias
);

fn mcu_dma_production_tx_descriptor_completion_and_wrap() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("transport DMA model allocation failed"),
    };
    // All device-visible addresses, including MCU command and RX payloads,
    // must fit the chip's Linux 32-bit DMA contract in Identity mode too.
    let storage = hw.owner.storage.as_ref().unwrap();
    for ring in [&storage.wm, &storage.fwdl, &storage.data]
        .into_iter()
        .chain(storage.rx.iter())
    {
        for buffer in core::iter::once(&ring.descriptors).chain(ring.buffers.iter()) {
            if buffer
                .dma_addr()
                .raw()
                .checked_add(buffer.len() as u64 - 1)
                .is_none_or(|end| end > u64::from(u32::MAX))
            {
                return TestResult::Fail("MT7921/MT7922 DMA exceeds the 32-bit device mask");
            }
        }
    }
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
    for slot in 0..packet_tx::PIPELINE {
        storage.tokens.begin_at(slot as u16 + 1, slot).unwrap();
    }
    storage.data_dma = 4;
    storage.pending_events.push_back(vec![0x66; 36]);
    storage.pending_data.push_back(CapturedData {
        bytes: vec![0x55; 64],
        epoch: 7,
        port_open: true,
    });
    storage.receive_epoch = 7;
    storage.receive_open = true;
    storage.rx[0].index = 9;
    storage.rx[0].set_word(9, 1, (36 << 16) | LAST | DONE);
    // All fixture buffers are CPU-owned; there is no device attached to this
    // memory model. Use the exact storage operation called after stop proof.
    storage.recycle();
    if storage.tokens.available() != Ok(1)
        || storage.data_dma != 0
        || !storage.pending_events.is_empty()
        || !storage.pending_data.is_empty()
        || storage.receive_epoch != 0
        || storage.receive_open
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

/// Same reset sequence on MT7925: the transport asserts/releases the
/// CONNAC3 register (`0x7c000140`, L1 window `0x130140`), never the
/// CONNAC2 one. Upstream `mt7925/regs.h:92` at torvalds/linux
/// 8d7fe9885c62.
fn mt76_mt7925_wfsys_reset_uses_connac3_register() -> TestResult {
    let (_words, mut hw) = match rig_7925() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("reset register fixture allocation"),
    };
    if hw.write(0x7c000140, 0xaabb0001).is_err()
        || hw.assert_reset().is_err()
        || hw.read(0x7c000140) != Ok(0xaabb0000)
        || hw.release_reset().is_err()
        || hw.read(0x7c000140) != Ok(0xaabb0001)
        || hw.reset_done() != Ok(false)
        || hw.write(0x7c000140, 0xaabb0011).is_err()
        || hw.reset_done() != Ok(true)
    {
        return TestResult::Fail("MT7925 WFSYS reset touched the CONNAC2 address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/recovery",
    mt76_mt7925_wfsys_reset_uses_connac3_register
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
    // RXD0: PKT_TYPE_TXRX_NOTIFY (6), MSDU_CNT 1, byte count.
    packet[..4].copy_from_slice(&((6u32 << 27) | (1 << 16) | len as u32).to_le_bytes());
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
        1,
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
fn mcu_tx_packet_id_distinguishes_ack_from_status_request() -> TestResult {
    // Linux tx.c: NO_ACK=0, NO_SKB=1, reserved HOST status PIDs >=3.
    // A registered global WCID has the same ACK contract as a peer.
    for wcid in [0, 1, 19] {
        for multicast in [false, true] {
            let mut frame = management_frame();
            frame[4] = if multicast { 0xff } else { 0x02 };
            let mut header = packet_tx::management(
                &frame,
                0x12345040,
                7,
                wcid,
                crate::mt7921::association::LegacyRate::ONE_MBPS,
            )
            .unwrap();
            let pid = if multicast { 0 } else { 1 };
            if header[20..24] != [pid, 0, 0, 0] || (header[12] & 1 != 0) != multicast {
                return TestResult::Fail("unrequested management PID disagrees with ACK policy");
            }
            if !multicast
                && (crate::mt7921::tx_sequence::request(&mut header, 3).is_err()
                    || header[20..24] != [3, 4, 0, 0])
            {
                return TestResult::Fail("HOST status did not replace the unrequested PID");
            }
        }
    }
    // An Ethernet multicast destination is still transmitted to the AP's
    // unicast RA; neither it nor a raw ToDS fragment is a no-ACK frame.
    let mut ethernet = [0xff; 14];
    ethernet[12..14].copy_from_slice(&[8, 0]);
    for qos in [false, true] {
        let header = packet_tx::ethernet_qos(&ethernet, 0x1000, 1, 1, true, qos).unwrap();
        if header[20..24] != [1, 0, 0, 0] || header[12] & 1 != 0 {
            return TestResult::Fail("station multicast MSDU lost the AP's ACK policy");
        }
        let mut fragment = [0; 32];
        fragment[0] = if qos { 0x88 } else { 0x08 };
        fragment[1] = 0x05; // ToDS + MoreFrags, first fragment.
        fragment[4] = 0x02;
        let header = packet_tx::fragment(&fragment, 0x1000, 1, 1).unwrap();
        if header[20..24] != [1, 0, 0, 0] || header[12] & 1 != 0 {
            return TestResult::Fail("raw fragment PID disagrees with unicast ACK policy");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_tx_packet_id_distinguishes_ack_from_status_request
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
                .submit_management(
                    crate::mt7921::vif_slots::Vif::HOME,
                    &frame,
                    19,
                    crate::mt7921::association::LegacyRate::ONE_MBPS,
                )
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
            // SAFETY: the fake device has no concurrent writer and this
            // fixture owns the coherent TXD/TXP plus complete auth frame.
            let bytes = unsafe {
                core::slice::from_raw_parts(ring.buffers[slot].cpu_ptr::<u8>(), 64 + frame.len())
            };
            if bytes[8..12] != 0x8000200bu32.to_le_bytes() || bytes[64..] != frame {
                return TestResult::Fail(
                    "published auth TXD lacks fixed-rate HTC_VLD or changed MPDU",
                );
            }
            if hw.submit_management(
                crate::mt7921::vif_slots::Vif::HOME,
                &frame,
                19,
                crate::mt7921::association::LegacyRate::ONE_MBPS,
            ) != Err(Error::Busy)
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

fn mt76_wmm_native_qos_descriptor_publication_and_two_phase_retirement() -> TestResult {
    for protected in [false, true] {
        let (mut words, mut hw) = match rig() {
            Ok(rig) => rig,
            Err(_) => return TestResult::Fail("QoS native fixture allocation"),
        };
        hw.owner.published = true;
        let mut frame = vec![0; 18];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[12..14].copy_from_slice(&[8, 0]);
        if hw
            .submit_data(
                crate::mt7921::vif_slots::Link::HOME,
                &frame,
                protected,
                true,
            )
            .is_err()
            || words[(TX_DATA + 8) as usize / 4] != 1
        {
            return TestResult::Fail("QoS descriptor did not reach hardware doorbell");
        }
        let ring = &hw.owner.storage.as_ref().unwrap().data;
        // SAFETY: fixture owns the stable coherent allocation, with at least
        // HEADER + frame.len bytes; hardware is modeled by owned memory.
        let bytes = unsafe { core::slice::from_raw_parts(ring.buffers[0].cpu_ptr::<u8>(), 82) };
        // Literal Linux CONNAC2 fields: BE LMAC queue 1, EtherType/802.3,
        // TID 0, QoS DATA subtype in TXD2/TXD7, normal retry, PTK bit only.
        // TXD5 carries MT_PACKET_ID_NO_SKB: the AP receiver ACKs the frame
        // and no HOST status is requested (`mt76_tx_status_skb_add`).
        if bytes[..12] != [50, 0, 0, 2, 1, 128, 0, 128, 40, 0, 0, 0]
            || bytes[12..16] != [if protected { 2 } else { 0 }, 120, 0, 16]
            || bytes[16..28] != [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
            || bytes[28..36] != [0, 0, 40, 0, 1, 128, 0, 0]
            || bytes[44..46] != [18, 128]
            || bytes[64..] != frame
            || ring.word(0, 1) != (64 << 16) | LAST
            || hw.submit_data(
                crate::mt7921::vif_slots::Link::HOME,
                &frame,
                protected,
                true,
            ) != Err(Error::Busy)
        {
            return TestResult::Fail("native QoS queue/TID/subtype/security/TXP geometry");
        }
        // A firmware release alone cannot release the Ethernet allocation.
        inject_rx(&mut words, &hw, 0, &release_event(1, 0, true));
        if hw.receive() != Ok(None) || hw.management_complete() != Ok(None) {
            return TestResult::Fail("QoS firmware-only completion freed payload");
        }
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .data
            .set_word(0, 1, (64 << 16) | LAST | DONE);
        words[(TX_DATA + 12) as usize / 4] = 1;
        if hw.management_complete()
            != Ok(Some(packet_tx::Completion {
                token: 1,
                status: 0,
            }))
        {
            return TestResult::Fail("QoS native terminal completion retained token");
        }
        hw.owner.published = false; // fixture proved both modeled owners retired
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_native_qos_descriptor_publication_and_two_phase_retirement
);
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_management_buffer_waits_for_dma_and_firmware_release_in_either_order
);
fn mcu_tx_release_batch_is_atomic_and_preserves_failure_status() -> TestResult {
    let mut tokens = packet_tx::Tokens::new();
    tokens.begin(1).unwrap();
    tokens.dma_done().unwrap();
    let mut packet = release_event(1, 0, true);
    // TXRX_NOTIFY declaring a missing second MSDU.
    packet[..4].copy_from_slice(&((6u32 << 27) | (2 << 16) | 16).to_le_bytes());
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

/// Linux `enum rx_pkt_type` (`mt76_connac.h`) as `mt7921_queue_rx_skb`
/// dispatches it, from literal RXD0 words.
fn mt76_rx_packet_types_follow_linux_rx_pkt_type() -> TestResult {
    use crate::mt7921::txrx::{rx_packet, RxPacket};
    for (rxd0, expected) in [
        (0x0000_0028u32, RxPacket::TxStatus), // PKT_TYPE_TXS
        (0x0800_0028, RxPacket::Other),       // PKT_TYPE_TXRXV
        (0x1000_0040, RxPacket::Normal),      // PKT_TYPE_NORMAL
        (0x1800_0040, RxPacket::Other),       // PKT_TYPE_RX_DUP_RFB
        (0x3001_0010, RxPacket::TxFree),      // PKT_TYPE_TXRX_NOTIFY
        (0x3800_0024, RxPacket::Event),       // PKT_TYPE_RX_EVENT
        (0x3802_0024, RxPacket::Event),       // PKT_TYPE_RX_EVENT, PKT_FLAG 2
        (0x3801_0040, RxPacket::Normal),      // PKT_FLAG 1: PKT_TYPE_NORMAL_MCU
        (0x4000_0040, RxPacket::Normal),      // PKT_TYPE_NORMAL_MCU
        (0x6000_0010, RxPacket::Other),       // PKT_TYPE_RX_FW_MONITOR
        (0xc000_0010, RxPacket::Other),       // PKT_TYPE_TXRX_NOTIFY_V0
    ] {
        if rx_packet(rxd0) != expected {
            return TestResult::Fail("RXD0 PKT_TYPE dispatch differs from mt7921_queue_rx_skb");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mt76_rx_packet_types_follow_linux_rx_pkt_type
);

/// A literal firmware TX-free notification (`mt7921_mac_tx_free`): RXD0
/// 0x30010010 is PKT_TYPE_TXRX_NOTIFY, MSDU_CNT 1, 16 bytes; then the
/// `txd` dword, a WCID-1 pair entry and token 1's MSDU entry (status 0,
/// one transmit count).
const TXRX_NOTIFY_TOKEN_1: [u32; 4] = [0x3001_0010, 0, 0x8000_4000, 0x0001_0001];
/// A literal PKT_TYPE_TXS packet (`mt7921_mac_add_txs`): RXD0 0x00000028,
/// one 8-dword MPDU-format record, acked, WCID 1, PID 1 (NO_SKB).
const TXS_WCID_1_PID_1: [u32; 10] = [0x28, 0, 1 << 15, 0, 1 << 16, 1 << 24, 0, 0, 0, 0];
/// A PKT_TYPE_TXRXV packet whose length is no TXS record multiple.
const TXRXV: [u32; 6] = [0x0800_0018, 0, 0xdead_beef, 0x0001_0001, 0, 0];

fn words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// The native join's management wait (`transmit_management`: submit, then
/// `wait(TIMEOUT_MS, management_complete)`) ends on the firmware's
/// PKT_TYPE_TXRX_NOTIFY release. A TXS (type 0) and a TXRXV (type 1) on the
/// other rings are not releases: before the fix the TXRX_NOTIFY was dropped
/// and the TXS parsed as a release, and the auth wait timed out.
fn mt76_native_txrx_notify_completes_management_wait_and_txs_is_no_release() -> TestResult {
    use core::future::Future;
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("TXRX_NOTIFY fixture allocation"),
    };
    hw.owner.published = true;
    if Backend::submit_management(
        &mut hw,
        crate::mt7921::vif_slots::Vif::HOME,
        &management_frame(),
        1,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .is_err()
    {
        return TestResult::Fail("management frame publication");
    }
    // WFDMA consumed the descriptor (the native boot's `dma=Ok` DIDX).
    hw.owner
        .storage
        .as_ref()
        .unwrap()
        .data
        .set_word(0, 1, (64 << 16) | LAST | DONE);
    words[(TX_DATA + 12) as usize / 4] = 1;
    inject_rx(&mut words, &hw, 0, &words_to_bytes(&TXS_WCID_1_PID_1));
    inject_rx(&mut words, &hw, 2, &words_to_bytes(&TXRXV));
    if hw.management_complete() != Ok(None) {
        return TestResult::Fail("TXS or TXRXV released the management token");
    }
    let storage = hw.owner.storage.as_ref().unwrap();
    if storage.rx[0].index != 1 || storage.rx[2].index != 1 || !storage.pending_data.is_empty() {
        return TestResult::Fail("TXS/TXRXV not consumed by the router, or queued as frames");
    }
    // The firmware's release arrives on the post-download MCU ring.
    inject_rx(&mut words, &hw, 1, &words_to_bytes(&TXRX_NOTIFY_TOKEN_1));
    let mut session = super::super::Session::new_boxed(hw, super::super::tests::firmware(32));
    let result = {
        let mut wait = core::pin::pin!(session.wait(super::super::TIMEOUT_MS, |backend| {
            backend.management_complete()
        }));
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        let mut result = None;
        for _ in 0..16 {
            if let core::task::Poll::Ready(value) = wait.as_mut().poll(&mut cx) {
                result = Some(value);
                break;
            }
        }
        result
    };
    session.backend.owner.published = false; // the model has no DMA engine
    if result
        != Some(Ok(packet_tx::Completion {
            token: 1,
            status: 0,
        }))
    {
        return TestResult::Fail("TXRX_NOTIFY did not complete the management wait");
    }
    if session.backend.owner.storage.as_ref().unwrap().rx[1].index != 1 {
        return TestResult::Fail("TXRX_NOTIFY left on the MCU ring");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mt76_native_txrx_notify_completes_management_wait_and_txs_is_no_release
);

/// A PKT_TYPE_TXS (0) packet reaches the TXS parser and becomes the home
/// station's sampled TX rate; the same record as PKT_TYPE_TXRXV (1) is
/// ignored, as Linux frees it.
fn mt76_native_txs_type_zero_reaches_status_parser() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("TXS fixture allocation"),
    };
    hw.owner.storage.as_mut().unwrap().tx_sequence = crate::mt7921::tx_sequence::Owner::new();
    hw.owner.published = true;
    // The home station's first data frame requests a HOST TXS on PID 3.
    if hw
        .submit_data_txd(
            crate::mt7921::vif_slots::Link::HOME,
            &tx_pipeline_hw_tests::ethernet(0x52),
            true,
            true,
            true,
            false,
            0,
        )
        .is_err()
    {
        return TestResult::Fail("sampled home data frame");
    }
    hw.owner
        .storage
        .as_ref()
        .unwrap()
        .data
        .set_word(0, 1, (64 << 16) | LAST | DONE);
    words[(TX_DATA + 12) as usize / 4] = 1;
    inject_rx(&mut words, &hw, 1, &words_to_bytes(&TXRX_NOTIFY_TOKEN_1));
    if hw.management_complete()
        != Ok(Some(packet_tx::Completion {
            token: 1,
            status: 0,
        }))
    {
        return TestResult::Fail("sampled frame did not retire on TXRX_NOTIFY");
    }
    // PID 3, WCID 1, VHT MCS 7 NSS 2 at 80 MHz. BA_ERROR, TXOP_TIMEOUT and
    // BIP_ERROR are outside MT_TXS0_ACK_ERROR_MASK: still an ACK.
    let rate = 7u32 | 4 << 6 | 1 << 10;
    let mut record = [
        0x28u32,
        0,
        rate | 2 << 29 | 1 << 22 | 1 << 20 | 1 << 19 | 1 << 15,
        0,
        1 << 16,
        3 << 24,
        0,
        0,
        0,
        0,
    ];
    record[0] |= 1 << 27; // PKT_TYPE_TXRXV
    inject_rx(&mut words, &hw, 0, &words_to_bytes(&record));
    if hw.route_rx(None) != Ok(None) || Backend::tx_rate_report(&hw).is_some() {
        return TestResult::Fail("TXRXV was parsed as a TX status");
    }
    record[0] &= !(0x1f << 27); // PKT_TYPE_TXS
    inject_rx(&mut words, &hw, 0, &words_to_bytes(&record));
    if hw.route_rx(None) != Ok(None) {
        return TestResult::Fail("TXS receipt");
    }
    hw.owner.published = false;
    match Backend::tx_rate_report(&hw) {
        Some(report)
            if report.wcid == 1
                && u32::from(report.tx_rate) == rate
                && report.bw == 2
                && report.failures == 0 =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("PKT_TYPE_TXS did not reach the TXS parser"),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mt76_native_txs_type_zero_reaches_status_parser
);

/// A TX-free notification whose MSDU_CNT overruns the packet: Linux
/// `mt7921_mac_tx_free` drops it (WARN_ON_ONCE). With no token owned it
/// cannot concern a NARF payload, so the router drops it and the active
/// wait goes on; while a token is owned it fails closed.
fn mt76_unwalkable_tx_free_drops_unless_a_token_is_owned() -> TestResult {
    // MSDU_CNT 2, 12 bytes: one entry short.
    const SHORT: [u32; 3] = [0x3002_000c, 0, 0x0001_0001];
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("TX-free drop fixture allocation"),
    };
    hw.owner.published = true;
    inject_rx(&mut words, &hw, 1, &words_to_bytes(&SHORT));
    if hw.route_rx(None) != Ok(None) || hw.owner.storage.as_ref().unwrap().rx[1].index != 1 {
        return TestResult::Fail("an unowned unwalkable TX-free aborted the receive");
    }
    if Backend::submit_management(
        &mut hw,
        crate::mt7921::vif_slots::Vif::HOME,
        &management_frame(),
        1,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .is_err()
    {
        return TestResult::Fail("management frame publication");
    }
    inject_rx(&mut words, &hw, 1, &words_to_bytes(&SHORT));
    let result = hw.management_complete();
    hw.owner.published = false; // the model has no DMA engine
    if result != Err(Error::MalformedEvent) {
        return TestResult::Fail("an unwalkable TX-free beside an owned token did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mt76_unwalkable_tx_free_drops_unless_a_token_is_owned
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
    reply[28] = 1; // generic reply
    reply[29] = 1; // to command sequence 1
    inject_rx(&mut words, &hw, 2, &reply);
    if hw.receive_data() != Ok(None) || hw.receive() != Ok(Some(reply)) {
        return TestResult::Fail("MCU response on data ring was dropped");
    }
    TestResult::Pass
}
fn mcu_packet_capture_keeps_closed_and_old_owner_facts_across_native_prefix_open() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("capture native ring allocation"),
    };
    let mut packet = vec![0u8; 64];
    packet[..4].copy_from_slice(&((2u32 << 27) | 64).to_le_bytes());
    hw.close_receive_capture(7);
    for which in 0..3 {
        inject_rx(&mut words, &hw, which, &packet);
    }
    if hw.receive() != Ok(None) || hw.open_receive_capture(7).is_err() {
        return TestResult::Fail("closed DMA copy/native prefix open");
    }
    for _ in 0..3 {
        if hw.receive_data_captured()
            != Ok(Some(CapturedData {
                bytes: packet.clone(),
                epoch: 7,
                port_open: false,
            }))
        {
            return TestResult::Fail("already-copied closed packet gained open admission");
        }
    }
    hw.close_receive_capture(8);
    // This descriptor is complete before opening, but no waiter copied it.
    inject_rx(&mut words, &hw, 2, &packet);
    if hw.open_receive_capture(8).is_err()
        || hw.receive_data_captured()
            != Ok(Some(CapturedData {
                bytes: packet.clone(),
                epoch: 8,
                port_open: false,
            }))
    {
        return TestResult::Fail("completed native prefix inherited a later port open");
    }
    inject_rx(&mut words, &hw, 2, &packet);
    if hw.receive() != Ok(None) {
        return TestResult::Fail("open native capture");
    }
    hw.close_receive_capture(9);
    if hw.open_receive_capture(9).is_err()
        || hw.receive_data_captured()
            != Ok(Some(CapturedData {
                bytes: packet.clone(),
                epoch: 8,
                port_open: true,
            }))
    {
        return TestResult::Fail("old buffered copy inherited the replacement epoch");
    }
    inject_rx(&mut words, &hw, 0, &packet);
    if hw.receive_data_captured()
        != Ok(Some(CapturedData {
            bytes: packet,
            epoch: 9,
            port_open: true,
        }))
    {
        return TestResult::Fail("fresh native capture lost its real open owner");
    }
    hw.close_receive_capture(10);
    words[(RX_DATA + 12) as usize / 4] = DEPTH as u32;
    if hw.open_receive_capture(10) != Err(Error::Ring)
        || hw.owner.storage.as_ref().unwrap().receive_open
    {
        return TestResult::Fail("invalid native cut opened receive admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/receive_epoch",
    mcu_packet_capture_keeps_closed_and_old_owner_facts_across_native_prefix_open
);
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
    if storage.pending_data.len() != 32 || storage.pending_data.front().unwrap().bytes[63] != 1 {
        return TestResult::Fail("normal RX backlog is unbounded or keeps stale data");
    }
    // Clear the data backlog before exercising event routing on data ring 2.
    hw.owner.storage.as_mut().unwrap().pending_data.clear();
    // A command reply (generic event, nonzero sequence) waits for its
    // command; an unread unsolicited event does not (see the next test).
    let mut reply = [0u8; 36];
    reply[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    reply[28] = 1;
    reply[29] = 1;
    for _ in 0..32 {
        inject_rx(&mut words, &hw, 2, &reply);
        if hw.receive_data() != Ok(None) {
            return TestResult::Fail("MCU reply reached packet receiver");
        }
    }
    let packet = reply;
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

/// Linux `mt7921_mcu_rx_event` handles an unsolicited event at RX time and
/// frees it. With packet service running and no command waiting (an idle
/// associated link), LP_INFO, DBG_MSG, RSSI_NOTIFY, TX_DONE, the rate report
/// and sequence-0 generic events are dropped, however many arrive; they
/// never exhaust the 32-entry queue that replies and SCAN_DONE wait in.
fn mcu_unread_unsolicited_events_never_fill_the_event_queue() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    let unsolicited = |eid: u8, option: u8, ext_eid: u8| {
        let mut packet = [0u8; 36];
        packet[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
        packet[28] = eid;
        packet[30] = option;
        packet[32] = ext_eid;
        packet
    };
    let kinds = [
        unsolicited(0x07, 0, 0),    // LP_INFO
        unsolicited(0x27, 0, 0),    // DBG_MSG
        unsolicited(0x96, 0, 0),    // RSSI_NOTIFY
        unsolicited(0x0f, 0, 0),    // TX_DONE
        unsolicited(0xed, 0, 0x87), // ext RATE_REPORT
        unsolicited(0x13, 0, 0),    // BSS_BEACON_LOSS without beacon filter
        unsolicited(0x01, 0, 0),    // sequence-0 generic event
        unsolicited(0x30, 4, 0),    // other unified unsolicited event
    ];
    for _ in 0..40 {
        for packet in &kinds {
            inject_rx(&mut words, &hw, 2, packet);
            if hw.receive_data() != Ok(None) {
                return TestResult::Fail("an unsolicited event failed or reached packet RX");
            }
        }
        if !hw.owner.storage.as_ref().unwrap().pending_events.is_empty() {
            return TestResult::Fail("an unread unsolicited event was queued");
        }
    }
    // SCAN_DONE and the unified ROC grant are read later by their owner.
    for packet in [unsolicited(0x0d, 0, 0), unsolicited(0x27, 4, 0)] {
        inject_rx(&mut words, &hw, 2, &packet);
        if hw.receive_data() != Ok(None) {
            return TestResult::Fail("a kept event reached packet RX");
        }
    }
    if hw.owner.storage.as_ref().unwrap().pending_events.len() != 2 {
        return TestResult::Fail("SCAN_DONE / ROC grant was not kept for its owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_unread_unsolicited_events_never_fill_the_event_queue
);

fn mcu_tx_completion_pump_preserves_queued_and_fresh_command_replies() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    hw.owner.published = true;
    if hw
        .submit_management(
            crate::mt7921::vif_slots::Vif::HOME,
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

fn smoke_mt76_native_revocation_precedes_current_config_bar_and_dma_start() -> TestResult {
    let (mut words, hw) = match rig() {
        Ok(value) => value,
        Err(_) => return TestResult::Fail("native fixture allocation"),
    };
    hw.authority.revoke();
    words[(TX_WM + 8) as usize / 4] = 0x12345678;
    if hw.read(TX_WM + 8) != Err(Error::Authority)
        || hw.write(TX_WM + 8, 0).is_ok()
        || hw.command(narf_bus::pci::cmd::BUS_MASTER, 0).is_ok()
        || words[(TX_WM + 8) as usize / 4] != 0x12345678
    {
        return TestResult::Fail("revoked native MT76 access reached actual BAR/configuration");
    }
    // SAFETY: this revoked-cap negative must reject before the deliberately
    // invalid ECAM and before any attempted BAR sizing or DMA allocation.
    if unsafe { crate::mt7921::pci::bring_up(&hw.device, &hw.authority) }.is_ok() {
        return TestResult::Fail("revoked MT76 probe authority sized a BAR");
    }
    let firmware = super::super::tests::firmware(16);
    // SAFETY: same revoked-cap boundary; native constructor must never reach
    // bogus configuration or allocate/publish queues under stale authority.
    if unsafe { Transport::new(hw.mmio, hw.device, hw.authority, firmware, 1) }.is_ok() {
        return TestResult::Fail("revoked MT76 constructor admitted DMA owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    smoke_mt76_native_revocation_precedes_current_config_bar_and_dma_start
);

fn mt76_native_addba_descriptor_names_actual_tid_and_add_ba_metadata() -> TestResult {
    for tid in 0..8u8 {
        let mut frame = vec![0; 33];
        frame[0] = 0xd0;
        frame[24..26].copy_from_slice(&[3, 0]);
        frame[26] = 1;
        frame[27..29].copy_from_slice(&(0x1003u16 | u16::from(tid) << 2).to_le_bytes());
        let header = packet_tx::management(
            &frame,
            0x12345040,
            7,
            1,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        )
        .unwrap();
        if header[4..8] != (0x8002_6001u32 | u32::from(tid) << 20).to_le_bytes()
            || header[20..24] != [1, 0x40, 0, 0]
            || header[12..16] != (1u32 << 28 | 15 << 11).to_le_bytes()
        {
            return TestResult::Fail("ADDBA management TXD omitted target TID/ADD_BA or changed native sequence ownership");
        }
        frame[25] = 1;
        let response = packet_tx::management(
            &frame,
            0x12345040,
            7,
            1,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        )
        .unwrap();
        if response[20..24] != [1, 0, 0, 0] || response[4..8] != 0x8002_6001u32.to_le_bytes() {
            return TestResult::Fail("ADDBA response inherited originator-only native metadata");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_native_addba_descriptor_names_actual_tid_and_add_ba_metadata
);

/// Linux `mt7921_pci_probe` / `mt792x_dma_enable` sources, then one
/// `mt792x_irq_handler` + `mt792x_irq_tasklet` pass: mask, read the enabled
/// pending sources, acknowledge them (and `MT_MCU_CMD`), and NAPI's unmask.
fn mcu_interrupt_pass_masks_acknowledges_and_unmasks_like_the_tasklet() -> TestResult {
    use crate::mt7921::irq::{HOST_INT_MASK, MT_INT_MCU_CMD, MT_INT_RX_DONE_ALL};
    let (mut words, hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    let word = |addr: u32| addr as usize / 4;
    words[word(MT_MCU2HOST_SW_INT_ENA)] = 0x100;
    if hw.program_host_interrupts().is_err()
        || words[word(MT_PCIE_MAC_INT_ENABLE)] != 0xff
        || words[word(MT_WFDMA0_HOST_INT_ENA)] != HOST_INT_MASK
        || words[word(MT_MCU2HOST_SW_INT_ENA)] != 0x100 | MT_MCU_CMD_WAKE_RX_PCIE
    {
        return TestResult::Fail("interrupt sources differ from mt7921e's");
    }
    // RX data and the MCU software interrupt pend, with a source mt7921e
    // never enables (bit 31): only the enabled ones are acknowledged.
    let pending = (1 << 2) | MT_INT_MCU_CMD | (1 << 31);
    words[word(MT_WFDMA0_HOST_INT_STA)] = pending;
    words[word(MT_MCU_CMD)] = MT_MCU_CMD_WAKE_RX_PCIE;
    match hw.acknowledge_interrupts() {
        Ok(status) if status == pending & HOST_INT_MASK => {}
        _ => return TestResult::Fail("pass did not report the enabled pending sources"),
    }
    if words[word(MT_WFDMA0_HOST_INT_ENA)] != 0
        || words[word(MT_WFDMA0_HOST_INT_STA)] != pending & HOST_INT_MASK
        || words[word(MT_MCU_CMD)] != MT_MCU_CMD_WAKE_RX_PCIE
    {
        return TestResult::Fail("pass did not mask, then write-1-clear STA and MCU_CMD");
    }
    if HOST_INT_MASK & MT_INT_RX_DONE_ALL != MT_INT_RX_DONE_ALL || HOST_INT_MASK != 0x2847_fff5 {
        return TestResult::Fail("mask differs from MT_INT_TX_DONE_ALL | RX_DONE_ALL | MCU_CMD");
    }
    // No vector bound: the polled owner never touches the sources.
    words[word(MT_WFDMA0_HOST_INT_ENA)] = 0x1234;
    if hw.interrupts_begin() != Ok(0)
        || hw.interrupts_end().is_err()
        || words[word(MT_WFDMA0_HOST_INT_ENA)] != 0x1234
    {
        return TestResult::Fail("a polled owner changed the interrupt sources");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx",
    mcu_interrupt_pass_masks_acknowledges_and_unmasks_like_the_tasklet
);

/// The RX rings are sized as Linux `mt7921_dma_init` sizes them for the
/// function: the MCU event ring `MT7921_RX_MCU_RING_SIZE` (8), the MCU WA
/// ring `MT7921_RX_MCU_WA_RING_SIZE` (512) and the data ring
/// `MT7921_RX_RING_SIZE` (1536). Every function this driver binds has
/// `has_mcu_wa` and the 8-entry event ring (only MT7902 differs). Each ring
/// is armed in every slot and programmed with its own descriptor count.
fn mcu_rx_rings_are_sized_as_linux_mt7921_dma_init() -> TestResult {
    for device in [0x0608u16, 0x0616, 0x7920, 0x7922, 0x7961] {
        let layout = dma_layout(device);
        if (layout.rx_event, layout.rx_wa, layout.rx_data) != (8, 512, 1536) {
            return TestResult::Fail("the RX rings are not sized as mt7921_dma_init sizes them");
        }
    }
    let (words, hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("allocation"),
    };
    let storage = match allocate_storage(&narf_io::DmaDevice::coherent(), dma_layout(0x0616)) {
        Ok(storage) => storage,
        Err(_) => return TestResult::Fail("the Linux-sized rings could not be allocated"),
    };
    let slots = [
        storage.rx[0].buffers.len(),
        storage.rx[1].buffers.len(),
        storage.rx[2].buffers.len(),
    ];
    if slots != [8, 512, 1536] {
        return TestResult::Fail("the allocated RX rings do not have the layout's slots");
    }
    for ring in &storage.rx {
        let depth = ring.buffers.len();
        if (0..depth).any(|slot| ring.word(slot, 0) != ring.buffers[slot].dma_addr().raw() as u32) {
            return TestResult::Fail("an RX slot is not armed with its buffer");
        }
        if hw.program(ring, true).is_err() {
            return TestResult::Fail("an RX ring could not be programmed");
        }
        let count = words[(ring.base + 4) as usize / 4] as usize;
        let cpu = words[(ring.base + 8) as usize / 4] as usize;
        if count != depth || cpu != depth - 1 {
            return TestResult::Fail("an RX ring was programmed with another descriptor count");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx-ring-sizes",
    mcu_rx_rings_are_sized_as_linux_mt7921_dma_init
);
