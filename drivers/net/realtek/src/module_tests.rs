use crate::module_test_support as hw;
use core::sync::atomic::Ordering;
#[test]
fn module_firmware_packet_io_and_failures() {
    {
        let mut m = hw::MODEL.lock().unwrap();
        m.setup_realtek();
        m.fw_missing = true;
    }
    assert_eq!(crate::register(), 0);
    assert_eq!(hw::probe(1), 0);
    let frame = [0xabu8; 60];
    assert_eq!(hw::transmit(1, &frame), -100, "firmware not ready");
    assert_eq!(hw::poll(1), 0);
    assert!(!hw::MODEL.lock().unwrap().carrier);
    {
        let mut m = hw::MODEL.lock().unwrap();
        m.fw_missing = false;
        // > 1 MiB of valid instructions, crossing seventeen broker chunks.
        m.firmware = std::vec![0, 0, 0, 0x10].repeat(262145);
    }
    hw::CLOCK.fetch_add(1_000_000_000, Ordering::Relaxed);
    assert_eq!(hw::poll(1), 0);
    {
        let m = hw::MODEL.lock().unwrap();
        assert!(m.carrier);
        assert_eq!(m.fw_reads.len(), 17);
        assert_eq!(m.closes, 1);
        assert!(m.retain);
    }
    assert_eq!(hw::transmit(1, &frame), 0);
    assert_eq!(hw::MODEL.lock().unwrap().sent[0], frame);
    {
        hw::MODEL.lock().unwrap().inject_rtl(&frame, 0, 0);
    }
    assert_eq!(hw::poll(1), 0);
    assert_eq!(
        hw::MODEL.lock().unwrap().rx[0],
        frame,
        "FCS must not reach stack"
    );
    {
        hw::MODEL.lock().unwrap().inject_rtl(&frame, 1, 1 << 21);
    }
    assert_eq!(hw::poll(1), 0);
    assert_eq!(
        hw::MODEL.lock().unwrap().rx.len(),
        1,
        "bad RX must be dropped"
    );
    // TX ownership timeout must not overwrite the already-submitted packet.
    hw::MODEL.lock().unwrap().auto_tx = false;
    hw::STEP.store(1_000_000, Ordering::Relaxed);
    assert_ne!(hw::transmit(1, &frame), 0);
    // Reset wedge returns promptly without publishing another interface.
    hw::MODEL.lock().unwrap().stuck_reset = true;
    let before = hw::CLOCK.load(Ordering::Relaxed);
    assert_ne!(hw::probe(2), 0);
    assert!(hw::CLOCK.load(Ordering::Relaxed) - before < 200_000_000);
    // The actual reader closes a handle on short/zero reads as well as success.
    hw::MODEL.lock().unwrap().short_read = true;
    assert_eq!(crate::platform::firmware("rtl_nic/rtl8125b-2.fw"), Err(-5));
    assert_eq!(hw::MODEL.lock().unwrap().closes, 2);
    // Valid backward jump with no hardware access must still terminate and
    // restore the page selector after failure.
    hw::STEP.store(100, Ordering::Relaxed);
    let dev = crate::platform::BusDevice::from_token(3).unwrap();
    // SAFETY: the test owns the model and its mapped DMA allocations; pointers and sizes refer to live buffers.
    let mmio = unsafe { crate::platform::map_bar(&dev, 2) }.unwrap();
    let mut phy = crate::phy_access::PhyAccess::new(&mmio);
    phy.mdio_write(0x1f, 0xa43).unwrap();
    assert_eq!(
        phy.run_firmware(&[0x30000000]),
        Err(crate::phy_access::PhyError::FirmwareTimeout)
    );
    assert_eq!(phy.ocp_base(), crate::phy_access::OCP_STD_PHY_BASE);
}
