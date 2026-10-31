// SPDX-License-Identifier: GPL-2.0-or-later
//! The production generation supervisor, firmware/LLT/radio/packet owners
//! and real DHCP client. The PCI register and DMA device remain inert.
use super::super::super::super::super::super::{
    interface::{recovery::Rebuild, supervisor::Operation},
    power_runtime,
};
use super::*;

impl Rebuild<PacketIo<BootPort>, Block> for DeviceEnvironment {
    async fn power_down(&self) -> Result<(), StationError> {
        let firmware = self.firmware.lock().clone();
        if firmware.native().powered_off.load(Ordering::Acquire) {
            return Ok(());
        }
        power_runtime::disable(firmware.native(), firmware.status().stage == Stage::Ready)
            .await
            .map_err(Error::Access)?;
        Ok(())
    }
    async fn rebuild(
        &self,
        retained: Arc<Mutex<Option<Prepared<PacketIo<BootPort>, Block>>>>,
        factory: Arc<super::super::super::super::super::super::efuse::Factory>,
        channel: u8,
    ) -> Result<(), StationError> {
        let old = self.firmware.lock().clone();
        let io = old.native().clone();
        if io.packet.model.lock().master {
            return Err(StationError::State);
        }
        self.power_down().await?;
        power_runtime::enable(&io).await.map_err(Error::Access)?;
        let firmware = Arc::new(Firmware::new(io, 0x8179));
        *self.firmware.lock() = firmware.clone();
        let mut image = vec![0; 32 + 4099];
        image[..2].copy_from_slice(&[0xe1, 0x88]);
        image[12..14].copy_from_slice(&4099u16.to_le_bytes());
        for (index, byte) in image[32..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        firmware.initialize(&image).await.map_err(Error::Access)?;
        let mut owner = Prepared::allocate(
            firmware.claim_packet_io().map_err(Error::Access)?,
            4,
            |bytes| Ok(self.packet.allocate(bytes)),
        )?;
        owner.prepare().await?;
        owner
            .configure_radio(radio::Profile::from_factory(&factory).unwrap())
            .await?;
        let calibration = power::calibration_for_channel(&factory, channel);
        let domain = self.domain()?;
        owner
            .configure_channel(calibration.permission(&domain, channel).unwrap())
            .await?;
        owner.configure_mac(&factory)?;
        owner.stage_station_calibration(calibration, &domain)?;
        *retained.lock().await = Some(owner);
        self.beacon.store(false, Ordering::Release);
        Ok(())
    }
}

fn reset(protected: bool, dropped_waiter: bool) -> TestResult {
    let h = Harness::new(protected);
    h.join();
    let old_generation = h.device.generation_for_test();
    let old_ring = h.packet.radio.word(LINUX_RX_BASE);
    let old_cancel = {
        let storage = h.device.prepared.try_lock().unwrap();
        storage.as_ref().unwrap().station_cancellation()
    };
    h.packet.radio.hardware_byte(0x286, 2); // RX DMA independently completes.
    for reg in 0x5f8..=0x5fb {
        h.packet.radio.hardware_byte(reg, 0);
    }
    h.device.fail_for_test();
    if !h.closed() {
        return TestResult::Fail("EE reset did not close carrier first");
    }
    let mut waiter = Box::pin(h.device.schedule(Operation::Recover).unwrap());
    if dropped_waiter {
        h.packet.model.lock().wait = true;
        if waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("EE reset did not retain the held power transition");
        }
        drop(waiter);
        h.packet.model.lock().wait = false;
        for _ in 0..20000 {
            h.device
                .poll_transition(&mut Context::from_waker(Waker::noop()));
            if h.device.prepared.try_lock().is_some_and(|p| {
                p.as_ref().is_some_and(|p| {
                    p.station_phase() == super::super::super::super::super::station::Phase::Passive
                })
            }) {
                break;
            }
        }
    } else if complete(waiter).is_err() {
        return TestResult::Fail("EE actual native owner rebuild failed");
    }
    let current = h.device.environment_for_test().firmware.lock().clone();
    if !h.passive()
        || h.device.generation_for_test() != old_generation + 1
        || h.packet.radio.word(LINUX_RX_BASE) == old_ring
        || Arc::ptr_eq(&current, &h.firmware)
        || current.native().cycles.load(Ordering::Acquire) != 1
        || h.firmware.claim_packet_io().is_ok()
        || h.packet
            .region(u64::from(old_ring))
            .live
            .load(Ordering::Acquire)
    {
        return TestResult::Fail("EE reset reused old generation, firmware claim or DMA");
    }
    old_cancel.store(true, Ordering::Release);
    h.device.drain();
    if !h.passive() {
        return TestResult::Fail("EE old cancellation stopped replacement");
    }
    {
        let mut peer = h.peer.lock();
        let fresh = Peer::new(protected);
        peer.ap = fresh.ap;
        peer.ptk = fresh.ptk;
        peer.replay = fresh.replay;
        peer.pn = fresh.pn;
    }
    h.join();
    let plan = h.peer.lock().plan;
    match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) if plan.matches_lease(&lease) => TestResult::Pass,
        _ => TestResult::Fail("EE fresh post-reset native RSNA/DHCP failed"),
    }
}

fn smoke_rtl8188ee_reset_open_native_dhcp() -> TestResult {
    reset(false, false)
}
fn smoke_rtl8188ee_reset_wpa2_native_dhcp_after_dropped_waiter() -> TestResult {
    reset(true, true)
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/recovery",
    smoke_rtl8188ee_reset_open_native_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/recovery",
    smoke_rtl8188ee_reset_wpa2_native_dhcp_after_dropped_waiter
);

fn smoke_rtl8188ee_reset_missing_dma_receipt_retains_old_owner() -> TestResult {
    let h = Harness::new(false);
    h.join();
    let ring = h.packet.radio.word(LINUX_RX_BASE);
    let drops = h.packet.drops.load(Ordering::Acquire);
    h.packet.radio.hardware_byte(0x286, 0);
    h.device.fail_for_test();
    if complete(h.device.schedule(Operation::Recover).unwrap()).is_ok()
        || !h.closed()
        || h.packet.drops.load(Ordering::Acquire) != drops
        || !h
            .packet
            .region(u64::from(ring))
            .live
            .load(Ordering::Acquire)
        || h.firmware.native().cycles.load(Ordering::Acquire) != 0
        || h.device.prepared.try_lock().is_none_or(|p| p.is_none())
    {
        return TestResult::Fail("EE reset inferred DMA retirement or lost retained owner");
    }
    h.packet.radio.hardware_byte(0x286, 2);
    if complete(h.device.schedule(Operation::Recover).unwrap()).is_err() || !h.passive() {
        return TestResult::Fail("EE reset could not retry after actual DMA idle receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/recovery",
    smoke_rtl8188ee_reset_missing_dma_receipt_retains_old_owner
);

fn smoke_rtl8188ee_reset_fences_old_native_rx_and_late_error() -> TestResult {
    let h = Harness::new(true);
    h.join();
    let plan = h.peer.lock().plan;
    let bytes = udp_ipv4(
        plan.station,
        PEER,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"old-generation-native-rx",
    );
    let frame = h.peer.lock().downlink(&bytes).unwrap();
    h.packet.emit(&frame).unwrap();
    h.packet.radio.hardware_byte(0x286, 2);
    match complete(super::super::super::super::super::super::interface::publication_test::old_copy_and_error_across_rebuild(&h.device)) {
        Ok(()) if h.passive() && h.received().is_empty() => TestResult::Pass,
        Ok(()) => TestResult::Fail("EE replacement retained old copied RX or stayed stopped"),
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/recovery",
    smoke_rtl8188ee_reset_fences_old_native_rx_and_late_error
);
