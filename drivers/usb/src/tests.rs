//! Per-driver smoke tests for `narf-drivers-usb`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under each driver's subsystem path.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── xhci ───────────────────────────────────────────────────────────

fn smoke_xhci_bring_up() -> TestResult {
    use crate::xhci;
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    if !xhci::with_controller(|c| c.is_running()).unwrap_or(false) {
        return TestResult::Fail("xhci not running after bring_up");
    }
    let v = xhci::with_controller(|c| c.version()).unwrap_or(0);
    if v == 0 || v == 0xFFFF {
        return TestResult::Fail("xhci HCIVERSION reads garbage");
    }
    let slots = xhci::with_controller(|c| c.max_slots()).unwrap_or(0);
    if slots == 0 {
        return TestResult::Fail("xhci max_slots = 0");
    }
    let ports = xhci::with_controller(|c| c.max_ports()).unwrap_or(0);
    if ports == 0 {
        return TestResult::Fail("xhci max_ports = 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_bring_up);

/// A full-speed controller starts EP0 at the required safe 8-byte
/// maximum, then must take the real `bMaxPacketSize0` from the first
/// Device Descriptor packet before asking for VID/PID bytes at offsets
/// 8..11. This is the WCN6855 pass-through shape: full-speed transport,
/// 64-byte EP0.
fn smoke_xhci_ep0_mps_from_device_descriptor() -> TestResult {
    use crate::xhci::PortSpeed;

    let cases = [
        (PortSpeed::Low, 8, Some(8)),
        (PortSpeed::Low, 64, None),
        (PortSpeed::Full, 64, Some(64)),
        (PortSpeed::Full, 7, None),
        (PortSpeed::High, 64, Some(64)),
        (PortSpeed::High, 8, None),
        (PortSpeed::Super, 9, Some(512)),
        (PortSpeed::SuperPlus, 13, Some(8192)),
        (PortSpeed::Super, 14, None),
    ];
    for (speed, raw, expected) in cases {
        if speed.ep0_max_packet_from_descriptor(raw) != expected {
            return TestResult::Fail("EP0 bMaxPacketSize0 decode mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_ep0_mps_from_device_descriptor
);

/// Control-transfer completion matching must include the originating
/// TRB pointer. A Data/Status pair shares slot + DCI, so accepting the
/// stale Status completion as the next TD's Data completion zeros the
/// descriptor buffer and makes a full-speed device disappear.
fn smoke_xhci_control_event_matches_originating_trb() -> TestResult {
    use crate::xhci::Xhci;

    const SLOT: u8 = 7;
    const DATA_TRB: u64 = 0x0000_0001_2345_6000;
    const STATUS_TRB: u64 = DATA_TRB + 0x10;
    // Transfer Event = type 32, DCI 1, slot 7. The low address bits
    // carry no pointer data and must be ignored by the matcher.
    let status_event = [
        (STATUS_TRB as u32) | 0xF,
        (STATUS_TRB >> 32) as u32,
        0,
        (32 << 10) | (1 << 16) | ((SLOT as u32) << 24),
    ];
    if Xhci::control_transfer_event_matches(&status_event, SLOT, DATA_TRB) {
        return TestResult::Fail("stale control Status event matched a Data TRB");
    }
    if !Xhci::control_transfer_event_matches(&status_event, SLOT, STATUS_TRB) {
        return TestResult::Fail("control Status event missed its originating TRB");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_event_matches_originating_trb
);

fn smoke_xhci_amd_phoenix_matches() -> TestResult {
    use crate::xhci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    xhci::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (xhci::QEMU_XHCI_VENDOR, xhci::QEMU_XHCI_DEVICE),
        (xhci::AMD_VENDOR, xhci::AMD_PHX_15B9),
        (xhci::AMD_VENDOR, xhci::AMD_PHX_15BA),
        (xhci::AMD_VENDOR, xhci::AMD_PHX_15C0),
        (xhci::AMD_VENDOR, xhci::AMD_PHX_15C1),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d)
        });
        if !found {
            return TestResult::Fail("missing xhci VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x0C,
                mask: 0xFF,
            }
        )
    });
    if !class_match {
        return TestResult::Fail("xhci class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_amd_phoenix_matches);

// ── xhci live (QEMU) ───────────────────────────────────────────────

fn smoke_xhci_enable_slot_command() -> TestResult {
    use crate::xhci;
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    let c = match xhci::controller() {
        Some(c) => c,
        None => return TestResult::Skip("xhci controller missing"),
    };
    let r = narf_scheduler::block_on(async { c.enable_slot().await });
    match r {
        Ok(slot_id) if slot_id >= 1 => TestResult::Pass,
        Ok(_) => TestResult::Fail("Enable Slot returned slot 0"),
        Err(_) => TestResult::Fail("Enable Slot command failed"),
    }
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_enable_slot_command);

/// Enable Slot may return a slot whose old software generation still owns
/// retained DMA. Keep every such hardware reservation allocated while asking
/// for another: disabling it immediately would return the same slot forever.
/// This only observes the production ownership predicate; it never clears it.
async fn reserve_fresh_address_slot(
    controller: &crate::xhci::Xhci,
    held: &mut alloc::vec::Vec<u8>,
) -> Result<(u8, usize), crate::xhci::XhciError> {
    use crate::xhci::XhciError;
    for retired in 0..usize::from(controller.max_slots()) {
        let slot = controller.enable_slot().await?;
        if slot == 0 || slot > controller.max_slots() || held.contains(&slot) {
            return Err(XhciError::CmdFailed(0xFD));
        }
        held.push(slot);
        if controller.test_address_slot_unused(slot) {
            return Ok((slot, retired));
        }
    }
    Err(XhciError::NotReady)
}

/// Clear class metadata before Disable Slot: a sleep-pump must not rearm an
/// interrupt endpoint being retired. The controller retains all DMA mappings.
async fn release_fixture_slots(
    controller: &crate::xhci::Xhci,
    held: &mut alloc::vec::Vec<u8>,
) -> Result<(), crate::xhci::XhciError> {
    use core::fmt::Write as _;
    crate::hid::__reset_keyboards_for_test();
    let mut first_error = None;
    for slot in held.drain(..) {
        if let Err(error) = controller.disable_slot(slot).await {
            let _ = writeln!(
                narf_console::Writer,
                "xhci fixture Disable Slot failed: slot={} error={:?}",
                slot,
                error,
            );
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn smoke_xhci_address_device_qemu() -> TestResult {
    use crate::{hid, xhci};
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    let c = match xhci::controller() {
        Some(c) => c,
        None => return TestResult::Fail("xhci controller missing"),
    };
    let port = match c.connected_ports().first().copied() {
        Some((port, _)) => port,
        None => return TestResult::Skip("no connected port"),
    };
    hid::__reset_keyboards_for_test();
    let stale_slot = c.slot_for_port(port);
    let disable_result =
        stale_slot.map(|slot| narf_scheduler::block_on(async { c.disable_slot(slot).await }));
    if matches!(disable_result, Some(Err(_))) {
        return TestResult::Fail("could not disable earlier port binding");
    }

    // Exercise both orders deterministically. Each cycle addresses and, for a
    // keyboard, runs the real descriptor/configuration/interrupt-IN path. Its
    // successful Disable retires the software generation. Its predicate must
    // stay closed when the next cycle selects a fresh slot, regardless of
    // whether the controller returns the lowest free or a rotating slot ID.
    let mut previous_slot = None;
    for cycle in 0..2 {
        let mut held = alloc::vec::Vec::new();
        let mut addressed_slot = None;
        let result = narf_scheduler::block_on(async {
            let pre_speed = c.port_speed(port);
            let post = match c.port_reset(port).await {
                Ok(post) => post,
                Err(_) => return TestResult::Fail("port_reset failed"),
            };
            let speed = match c.port_speed(port) {
                Some(speed) => speed,
                None => return TestResult::Fail("unknown post-reset port speed"),
            };
            let (slot, retired) = match reserve_fresh_address_slot(&c, &mut held).await {
                Ok(reservation) => reservation,
                Err(_) => return TestResult::Fail("no fresh software slot available"),
            };
            if previous_slot == Some(slot)
                || previous_slot.is_some_and(|old| c.test_address_slot_unused(old))
            {
                return TestResult::Fail("second address cycle reopened retired ownership");
            }
            if let Err(error) = c.address_device(slot, port, speed).await {
                // Failure-only diagnostics preserve the command timing window.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "xhci address smoke: error={:?} cycle={} slot={} retired={} port={} pre_speed={:?} post_speed={:?} portsc={:#x} stale={:?} disable={:?} mapped={:?} generation={:?} retained={:?}",
                    error, cycle, slot, retired, port, pre_speed, c.port_speed(port), post,
                    stale_slot, disable_result, c.slot_for_port(port),
                    c.device_generation(slot), c.device_info(slot),
                );
                return TestResult::Fail("address_device failed");
            }
            addressed_slot = Some(slot);
            match hid::try_bind_kbd_already_addressed(&c, slot, port, speed, None).await {
                Ok(()) | Err(hid::HidError::NotBootKeyboard) => TestResult::Pass,
                Err(_) => TestResult::Fail("HID bind after fresh Address Device failed"),
            }
        });
        // Cleanup is checked even when the address/class path failed. The next
        // cycle starts after a real successful Disable, not a software reset.
        if narf_scheduler::block_on(release_fixture_slots(&c, &mut held)).is_err() {
            return TestResult::Fail("fixture slot cleanup failed");
        }
        if !matches!(result, TestResult::Pass) {
            return result;
        }
        let slot = addressed_slot.expect("passing cycle addressed a real device");
        if c.test_address_slot_unused(slot)
            || c.device_generation(slot).is_some()
            || c.device_info(slot).is_none()
        {
            return TestResult::Fail("successful Disable discarded retained generation ownership");
        }
        previous_slot = Some(slot);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_address_device_qemu);

/// Live USB-HID attach, followed by a bounded interrupt-IN pump. Enumeration
/// uses a fresh software slot and the real post-address class path, so this
/// works before or after the address/retire fixture. A quiet keyboard need not
/// emit a report; this asserts successful configuration and periodic pumping.
fn smoke_xhci_hid_kbd_first_report() -> TestResult {
    use crate::{hid, xhci};
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    let c = match xhci::controller() {
        Some(c) => c,
        None => return TestResult::Fail("xhci controller missing"),
    };
    hid::__reset_keyboards_for_test();
    let port = match c.connected_ports().first().copied() {
        Some((port, _)) => port,
        None => return TestResult::Skip("no connected port"),
    };
    if let Some(stale) = c.slot_for_port(port) {
        if narf_scheduler::block_on(c.disable_slot(stale)).is_err() {
            return TestResult::Fail("could not disable earlier port binding");
        }
    }
    let mut held = alloc::vec::Vec::new();
    let result = narf_scheduler::block_on(async {
        if c.port_reset(port).await.is_err() {
            return TestResult::Fail("HID port_reset failed");
        }
        let speed = match c.port_speed(port) {
            Some(speed) => speed,
            None => return TestResult::Fail("unknown HID post-reset port speed"),
        };
        let (slot, _) = match reserve_fresh_address_slot(&c, &mut held).await {
            Ok(reservation) => reservation,
            Err(_) => return TestResult::Fail("no fresh HID software slot available"),
        };
        if c.address_device(slot, port, speed).await.is_err() {
            return TestResult::Fail("HID Address Device failed");
        }
        match hid::try_bind_kbd_already_addressed(&c, slot, port, speed, None).await {
            Ok(()) => TestResult::Pass,
            Err(hid::HidError::NotBootKeyboard) => TestResult::Skip("port not a HID Boot Keyboard"),
            Err(_) => TestResult::Fail("HID configuration/transport failed"),
        }
    });
    if matches!(result, TestResult::Pass) {
        narf_scheduler::block_on(async {
            let deadline = narf_time::Deadline::after_ms(200);
            while !deadline.expired() {
                if hid::pump_all(&c) > 0 {
                    break;
                }
                // No class/controller guard survives this self-driven wait.
                // block_on drives sleep_pumps after direct HID pumping has
                // returned, so other devices progress without recursive locks.
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
            }
        });
    }
    if narf_scheduler::block_on(release_fixture_slots(&c, &mut held)).is_err() {
        return TestResult::Fail("HID fixture slot cleanup failed");
    }
    result
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_hid_kbd_first_report);

// ── MSC class-driver descriptor parser ─────────────────────────────

fn smoke_msc_config_descriptor_parse() -> TestResult {
    use crate::msc;
    use crate::xhci::EndpointKind;

    // Synthesized blob: Configuration Descriptor (9 B) +
    // Interface Descriptor (9 B, MSC BOT 08:06:50) + 2 ×
    // Endpoint Descriptor (7 B each, bulk-IN @ ep1 / bulk-OUT @ ep2).
    let cfg: [u8; 32] = [
        9, 2, 32, 0, 1, 1, 0, 0xC0, 0, 9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0, 7, 5, 0x81, 0x02, 0x00,
        0x02, 0, 7, 5, 0x02, 0x02, 0x00, 0x02, 0,
    ];
    let (in_ep, out_ep, iface) = match msc::find_bot_endpoints(&cfg) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("find_bot_endpoints rejected MSC blob"),
    };
    if iface != 0 {
        return TestResult::Fail("find_bot_endpoints returned wrong bInterfaceNumber");
    }
    if in_ep.kind != EndpointKind::BulkIn || in_ep.ep_addr != 0x81 || in_ep.max_packet != 0x0200 {
        return TestResult::Fail("bulk-IN endpoint mis-decoded");
    }
    if out_ep.kind != EndpointKind::BulkOut || out_ep.ep_addr != 0x02 || out_ep.max_packet != 0x0200
    {
        return TestResult::Fail("bulk-OUT endpoint mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_config_descriptor_parse);

fn smoke_msc_attach_via_xhci_qemu() -> TestResult {
    use crate::{msc, xhci};
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    msc::__reset_msc_for_test();
    let attached = match xhci::controller() {
        Some(c) => narf_scheduler::block_on(async { msc::enumerate_and_attach_msc(&c).await }),
        None => 0,
    };
    if attached == 0 {
        return TestResult::Skip("no MSC device attached to xhci");
    }
    if msc::attached_msc_count() != attached {
        return TestResult::Fail("registry count diverged from return");
    }
    let cap_ok = msc::with_device(0, |d| d.lba_bytes != 0 && d.last_lba != 0).unwrap_or(false);
    if !cap_ok {
        return TestResult::Fail("READ CAPACITY(10) didn't populate dev");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_attach_via_xhci_qemu);

// ── MSC detach / replug publication ────────────────────────────────

/// Minimal `BlockDeviceSync` standing in for a scanned partition
/// child of a synthetic MSC disk (the real scanner cannot run
/// against a fabricated device — it would issue BOT traffic).
struct DummyPartition;
impl narf_block::BlockDeviceSync for DummyPartition {
    fn lba_size(&self) -> u32 {
        512
    }
    fn capacity(&self) -> u64 {
        1024
    }
    fn read(&self, _lba: u64, _n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        out.fill(0);
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Ok(())
    }
}

/// The publication half of the USB detach lifecycle for MSC:
/// bind publishes `usb-msc{idx}` (+ a partition child), the
/// class-registry unbind dispatch tombstones the device and
/// unregisters disk + partitions, and a replug on the same slot
/// reuses the tombstoned index so the same name republishes.
/// Runs without hardware via `msc::__insert_msc_for_test`.
fn smoke_msc_detach_replug_publication() -> TestResult {
    use crate::{class_registry, msc};
    use alloc::sync::Arc;

    msc::__reset_msc_for_test();
    // Ensure the detach hook is in the class registry. A full boot
    // registers it from the Stage::Subsys initcall; registering
    // here too keeps the smoke independent of initcall order (a
    // duplicate entry would only double-dispatch the detach, which
    // is idempotent).
    msc::register_initcalls();

    // Slot 200: no real enumeration reaches it in the test kernel.
    let idx = msc::__insert_msc_for_test(200);
    let disk = alloc::format!("usb-msc{}", idx);
    if msc::with_device(idx, |d| d.slot_id) != Some(200) {
        return TestResult::Fail("synthetic MSC device not in registry");
    }
    if msc::attached_msc_count() != 1 {
        return TestResult::Fail("attached count wrong after bind");
    }
    if narf_block::find_block_device(&disk).is_none() {
        return TestResult::Fail("usb-msc disk not published after bind");
    }
    let child: &'static str =
        alloc::boxed::Box::leak(alloc::format!("{}p1", disk).into_boxed_str());
    narf_block::register_partition_device(
        child,
        &disk,
        Arc::new(DummyPartition) as Arc<dyn narf_block::BlockDeviceSync>,
        None,
    );
    if narf_block::find_block_device(child).is_none() {
        return TestResult::Fail("partition child not published");
    }

    // Detach through the registry's unbind dispatch — the same
    // entry the supervisor's detach path calls.
    class_registry::dispatch_unbind(200);
    if msc::with_device(idx, |d| d.slot_id).is_some() {
        return TestResult::Fail("MSC entry not tombstoned after detach");
    }
    if msc::attached_msc_count() != 0 {
        return TestResult::Fail("attached count nonzero after detach");
    }
    if narf_block::find_block_device(&disk).is_some() {
        return TestResult::Fail("usb-msc disk still published after detach");
    }
    if narf_block::find_block_device(child).is_some() {
        return TestResult::Fail("partition child still published after detach");
    }
    // Detach is idempotent, including for a never-bound slot.
    msc::detach_msc(200);
    msc::detach_msc(201);

    // Replug: tombstone reuse republishes under the same name.
    let idx2 = msc::__insert_msc_for_test(200);
    if idx2 != idx {
        return TestResult::Fail("replug did not reuse the tombstoned index");
    }
    if narf_block::find_block_device(&disk).is_none() {
        return TestResult::Fail("usb-msc disk not republished after replug");
    }
    if msc::attached_msc_count() != 1 {
        return TestResult::Fail("attached count wrong after replug");
    }

    // Clean up so later smokes see an empty MSC registry.
    msc::detach_msc(200);
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_detach_replug_publication);

/// Finding A pin (queue 16 second-pass review): a held block
/// adapter must never be silently retargeted at the next disk.
/// Filesystems retain the `UsbMscBlockDevice` for the mount's
/// whole life; the adapter re-resolves its target from
/// `MSC_DEVICES[idx]` on every op, and `insert_device` reuses the
/// first tombstone by design — so without a bind-identity check,
/// unplug A / plug B serves A's mounted filesystem from B. The
/// bind-generation gate is that check: stale adapters fail
/// `DeviceRemoved`, including after the *same* disk rebinds (a
/// rebind is a new bind with a new generation).
fn smoke_msc_stale_adapter_generation_gate() -> TestResult {
    use crate::msc::{self, UsbMscBlockDevice};
    use narf_block::{BlockDeviceSync, BlockIoError};

    msc::__reset_msc_for_test();

    // Bind disk A (slot 202) and retain its adapter, the way a
    // mounted filesystem retains it across detach/replug.
    let idx = msc::__insert_msc_for_test(202);
    let Some(stale) = UsbMscBlockDevice::from_index(idx) else {
        return TestResult::Fail("adapter for freshly bound disk missing");
    };
    let mut buf = [0u8; 512];
    let data = [0xA5u8; 512];

    // Unplug A: the tombstone alone already fails the held adapter.
    msc::detach_msc(202);
    if stale.read(0, 1, &mut buf) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("held adapter read not DeviceRemoved while tombstoned");
    }
    if stale.write(0, 1, &data) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("held adapter write not DeviceRemoved while tombstoned");
    }
    if stale.flush() != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("held adapter flush not DeviceRemoved while tombstoned");
    }
    if stale.write_fua(0, 1, &data) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("held adapter FUA write not DeviceRemoved while tombstoned");
    }

    // Plug in a different disk B (slot 203): tombstone reuse lands
    // it on the same index. The held adapter must NOT be served
    // by B — this is the retargeting the generation gate exists
    // to prevent.
    let idx_b = msc::__insert_msc_for_test(203);
    if idx_b != idx {
        return TestResult::Fail("replug did not reuse the tombstoned index");
    }
    let Some(fresh) = UsbMscBlockDevice::from_index(idx) else {
        return TestResult::Fail("adapter for replugged disk missing");
    };
    if stale.read(0, 1, &mut buf) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("stale adapter read silently served by replugged disk");
    }
    if stale.write(0, 1, &data) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("stale adapter write silently served by replugged disk");
    }
    if stale.flush() != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("stale adapter flush silently served by replugged disk");
    }
    if stale.write_fua(0, 1, &data) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("stale adapter FUA write silently served by replugged disk");
    }

    // B's own adapter is generation-current, so it must get PAST
    // the identity gate. With a live controller (the harness's
    // qemu-xhci) its ops fail in the transfer layer against the
    // fabricated slot — DriverError, never DeviceRemoved. Without
    // a controller the environment cannot distinguish the two, so
    // this half is conditioned on one being present.
    if crate::xhci::controller().is_some() {
        if fresh.read(0, 1, &mut buf) != Err(BlockIoError::DriverError) {
            return TestResult::Fail("fresh adapter read did not pass the generation gate");
        }
        if fresh.write(0, 1, &data) != Err(BlockIoError::DriverError) {
            return TestResult::Fail("fresh adapter write did not pass the generation gate");
        }
        if fresh.flush() != Err(BlockIoError::DriverError) {
            return TestResult::Fail("fresh adapter flush did not pass the generation gate");
        }
        if fresh.write_fua(0, 1, &data) != Err(BlockIoError::DriverError) {
            return TestResult::Fail("fresh adapter FUA write did not pass the generation gate");
        }
    }

    // Same disk out and back in (A returns on slot 202): a rebind
    // is a new bind with a new generation, so NEITHER held adapter
    // is resurrected — B's adapter is stale by generation too.
    msc::detach_msc(203);
    let idx_a2 = msc::__insert_msc_for_test(202);
    if idx_a2 != idx {
        return TestResult::Fail("same-disk replug did not reuse the tombstoned index");
    }
    if stale.read(0, 1, &mut buf) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("original adapter resurrected by same-disk rebind");
    }
    if fresh.read(0, 1, &mut buf) != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("previous occupant's adapter not stale after rebind");
    }

    // Clean up so later smokes see an empty MSC registry.
    msc::detach_msc(202);
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_stale_adapter_generation_gate);

// ── Hub idle-suspend PM (issue #840) ─────────────────────────────
//
// The wedge: hub-attached devices were suspended 30 s after hub
// bind because `last_activity_tick` initialised to 0 (the boot
// epoch) and nothing ever stamped it — `mark_port_activity` and
// `resume_port` had no callers — and `MscDevice` recorded no hub
// context, so MSC could not resume its port even in principle.
//
// These fixtures drive the suspend *decision* directly (the
// harness has no wall-clock control): the pure candidate
// selection over hand-built registry snapshots, plus the
// registry-level bind/activity stamping the fix adds. The
// transfer-path half of the fix (MSC funnels resume before the
// CBW and feed on completion) is exercised end-to-end only on
// real hub hardware; QEMU's xtask topology attaches storage to
// root ports, where hub_port is None and the hooks are no-ops.
//
// The fix-round fixtures at the end of this section pin the
// HID half the same way: HID bindings record hub context,
// `hid::hub_ports` collects it across the pumped classes
// (deduplicated), and the wake step's pure selection
// (`suspended_ports_among`) picks out only bound,
// currently-suspended ports to resume before the pumps run.
// The pumps' feed itself calls the same `mark_port_activity`
// the bind-stamps fixture already proves pushes the deadline
// out.

fn fake_hub_binding(slot_id: u8, num_ports: u8) -> crate::attach::HubBinding {
    crate::attach::HubBinding {
        hub: crate::hub::UsbHub {
            slot_id,
            iface_num: 0,
            descriptor: crate::hub::HubDescriptor {
                num_ports,
                characteristics: 0,
                poweron_time_2ms: 0,
                controller_current: 0,
            },
            speed: crate::xhci::PortSpeed::High,
            device_protocol: 1,
        },
        route_string: 0,
        tier: 0,
        root_hub_port: 1,
        bound_downstream: 0,
        suspended_downstream: 0,
        last_activity_tick: [0u64; 64],
    }
}

/// Candidate-selection matrix for `idle_suspend_candidates`,
/// including the exact pre-fix failure shape (bound port, tick
/// still at its initial 0) and the post-fix shape (tick stamped
/// at bind).
fn smoke_hub_idle_suspend_decision() -> TestResult {
    use crate::attach::{idle_suspend_candidates, IDLE_SUSPEND_NS};
    let now: u64 = 100 * 1_000_000_000; // uptime 100 s
    let mut h = fake_hub_binding(7, 4);
    // Port 1: bound, tick never stamped — the pre-#840 initial
    // state (tick = boot epoch). Expired: this is the wedge.
    h.bound_downstream |= 1 << 1;
    h.last_activity_tick[1] = 0;
    // Port 2: bound, stamped at bind 29 s ago of a 30 s window.
    h.bound_downstream |= 1 << 2;
    h.last_activity_tick[2] = now - (IDLE_SUSPEND_NS - 1_000_000_000);
    // Port 3: bound but already suspended → not re-selected.
    h.bound_downstream |= 1 << 3;
    h.suspended_downstream |= 1 << 3;
    h.last_activity_tick[3] = 0;
    // Port 4: never bound, ancient tick → ignored.
    h.last_activity_tick[4] = 0;
    // Port 5 (beyond num_ports = 4): bound bit set spuriously →
    // ignored, the pass only walks real ports.
    h.bound_downstream |= 1 << 5;
    h.last_activity_tick[5] = 0;
    let cands = idle_suspend_candidates(&alloc::vec![h], now);
    if cands != alloc::vec![(7u8, 1u8)] {
        return TestResult::Fail("expected only the unstamped bound port");
    }
    // Exactly at the threshold the port is expired (>=).
    let mut h2 = fake_hub_binding(8, 1);
    h2.bound_downstream |= 1 << 1;
    h2.last_activity_tick[1] = now - IDLE_SUSPEND_NS;
    if idle_suspend_candidates(&alloc::vec![h2], now) != alloc::vec![(8u8, 1u8)] {
        return TestResult::Fail("threshold boundary not expired");
    }
    // The post-resume sentinel never expires.
    let mut h3 = fake_hub_binding(9, 1);
    h3.bound_downstream |= 1 << 1;
    h3.last_activity_tick[1] = u64::MAX;
    if !idle_suspend_candidates(&alloc::vec![h3], now).is_empty() {
        return TestResult::Fail("MAX sentinel selected for suspend");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub_pm", smoke_hub_idle_suspend_decision);

/// Registry-level: `mark_ports_bound` sets the bound bit AND
/// stamps the activity tick (the supervisor's bind path), the
/// stamped port survives until its tick ages past the window,
/// and a `mark_port_activity` feed — what the MSC BOT funnels do
/// on each completed transaction — pushes the deadline out.
/// Pushes one fake binding and truncates it back off afterwards
/// (the registry is append-only; the tail is ours).
fn smoke_hub_bind_stamps_activity() -> TestResult {
    use crate::attach::{
        hub_index_for_slot, idle_suspend_candidates, mark_port_activity, mark_ports_bound, HUBS,
        IDLE_SUSPEND_NS,
    };
    let base = HUBS.lock().len();
    HUBS.lock().push(fake_hub_binding(0xC0, 2));
    let result = (|| {
        let idx = match hub_index_for_slot(0xC0) {
            Some(i) => i,
            None => return TestResult::Fail("hub_index_for_slot missed pushed hub"),
        };
        if idx != base {
            return TestResult::Fail("hub index != append position");
        }
        if hub_index_for_slot(0x3F).is_some() {
            return TestResult::Fail("phantom hub index");
        }
        // Bind port 1 the way the supervisor now does.
        // Hub context is keyed by slot id (#892), so the bind
        // call takes the slot, not the registry index.
        mark_ports_bound(0xC0, 1 << 1);
        let tick = {
            let g = HUBS.lock();
            let h = match g.iter().find(|h| h.hub.slot_id == 0xC0) {
                Some(h) => h,
                None => return TestResult::Fail("pushed hub missing"),
            };
            if h.bound_downstream & (1 << 1) == 0 {
                return TestResult::Fail("mark_ports_bound didn't set bound bit");
            }
            h.last_activity_tick[1]
        };
        if tick == 0 {
            return TestResult::Fail("mark_ports_bound didn't stamp activity");
        }
        // Inside the window: not a candidate. Past it: candidate —
        // the port still suspends when genuinely idle. (Contains-
        // checks: the scan covers the whole live registry.)
        {
            let g = HUBS.lock();
            if idle_suspend_candidates(&g[..], tick + IDLE_SUSPEND_NS - 1_000_000_000)
                .contains(&(0xC0, 1u8))
            {
                return TestResult::Fail("freshly bound port selected for suspend");
            }
            if !idle_suspend_candidates(&g[..], tick + IDLE_SUSPEND_NS + 1_000_000_000)
                .contains(&(0xC0, 1u8))
            {
                return TestResult::Fail("idle-expired bound port not selected");
            }
        }
        // A completed transfer feeds activity: tick moves to the
        // feed instant and the deadline moves with it.
        mark_port_activity(0xC0, 1);
        let tick2 = {
            let g = HUBS.lock();
            match g.iter().find(|h| h.hub.slot_id == 0xC0) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("pushed hub missing"),
            }
        };
        if tick2 < tick {
            return TestResult::Fail("activity feed moved the tick backwards");
        }
        {
            let g = HUBS.lock();
            if idle_suspend_candidates(&g[..], tick2 + IDLE_SUSPEND_NS - 1_000_000_000)
                .contains(&(0xC0, 1u8))
            {
                return TestResult::Fail("activity feed didn't push the deadline out");
            }
        }
        TestResult::Pass
    })();
    HUBS.lock().truncate(base);
    result
}
kernel_test_in!("drivers/usb/hub_pm", smoke_hub_bind_stamps_activity);

/// #892 regression: hub detach must not retarget a surviving
/// device's activity feed. Three hubs (slots 0xC0/0xC1/0xC2);
/// port 1 of the middle hub is bound (tick stamped). Detaching
/// the FIRST hub removes its `HUBS` entry with `retain`, which
/// shifts every later index down by one — under the old
/// index-keyed context, a cached index 1 would then stamp the
/// third hub's tick. With slot-keyed context the feed must
/// still land on the middle hub, and feeding a detached hub's
/// slot must stamp nothing anywhere (no wrong-hub write, no
/// panic on a missing entry).
fn smoke_hub_detach_shift_keeps_activity() -> TestResult {
    use crate::attach::{mark_port_activity, mark_ports_bound, HUBS};
    let base = HUBS.lock().len();
    HUBS.lock().push(fake_hub_binding(0xC0, 2));
    HUBS.lock().push(fake_hub_binding(0xC1, 2));
    HUBS.lock().push(fake_hub_binding(0xC2, 2));
    let result = (|| {
        mark_ports_bound(0xC1, 1 << 1);
        let bound_tick = {
            let g = HUBS.lock();
            match g.iter().find(|h| h.hub.slot_id == 0xC1) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("middle hub missing"),
            }
        };
        if bound_tick == 0 {
            return TestResult::Fail("bind did not stamp middle hub tick");
        }
        // Detach the first hub exactly as `detach_slot` does.
        HUBS.lock().retain(|h| h.hub.slot_id != 0xC0);
        // Feed activity for the middle hub: must land on it even
        // though its registry index moved 1 -> 0, and must not
        // touch the third hub's tick.
        mark_port_activity(0xC1, 1);
        let (mid_tick, third_tick) = {
            let g = HUBS.lock();
            let mid = match g.iter().find(|h| h.hub.slot_id == 0xC1) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("middle hub lost on detach"),
            };
            let third = match g.iter().find(|h| h.hub.slot_id == 0xC2) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("third hub lost on detach"),
            };
            (mid, third)
        };
        if mid_tick < bound_tick {
            return TestResult::Fail("activity feed moved middle hub tick backwards");
        }
        if third_tick != 0 {
            return TestResult::Fail("activity feed stamped the wrong hub after detach shift");
        }
        // Feeding the detached hub's slot must stamp nothing.
        mark_port_activity(0xC0, 1);
        let (mid_tick2, third_tick2) = {
            let g = HUBS.lock();
            let mid = match g.iter().find(|h| h.hub.slot_id == 0xC1) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("middle hub lost on detached feed"),
            };
            let third = match g.iter().find(|h| h.hub.slot_id == 0xC2) {
                Some(h) => h.last_activity_tick[1],
                None => return TestResult::Fail("third hub lost on detached feed"),
            };
            (mid, third)
        };
        if mid_tick2 != mid_tick || third_tick2 != 0 {
            return TestResult::Fail("detached-slot feed wrote to a live hub");
        }
        TestResult::Pass
    })();
    HUBS.lock().truncate(base);
    result
}
kernel_test_in!("drivers/usb/hub_pm", smoke_hub_detach_shift_keeps_activity);

/// Wake-step selection matrix for `suspended_ports_among`, the
/// pure filter behind `hid::resume_suspended_hub_ports`: only
/// bound + currently-suspended ports are selected; duplicate
/// pairs (two classes bound on one port) collapse; unknown
/// hubs and suspended-but-unbound bits are ignored.
fn smoke_hub_hid_wake_selection() -> TestResult {
    use crate::attach::suspended_ports_among;
    let mut h0 = fake_hub_binding(7, 4);
    // Port 1: bound + suspended → selected.
    h0.bound_downstream |= 1 << 1;
    h0.suspended_downstream |= 1 << 1;
    // Port 2: bound, awake → not selected.
    h0.bound_downstream |= 1 << 2;
    // Port 3: suspended bit set but never bound → ignored.
    h0.suspended_downstream |= 1 << 3;
    let mut h1 = fake_hub_binding(8, 2);
    // Hub 1 port 2: bound + suspended → selected.
    h1.bound_downstream |= 1 << 2;
    h1.suspended_downstream |= 1 << 2;
    // Bindings are (parent hub slot id, port) (#892): hub 0 is
    // slot 7, hub 1 is slot 8, slot 9 is unknown.
    let hubs = alloc::vec![h0, h1];
    let bindings = alloc::vec![
        (7u8, 1u8),
        (7u8, 2u8),
        (7u8, 3u8),
        (8u8, 2u8),
        (7u8, 1u8), // duplicate — collapses
        (9u8, 1u8), // unknown hub
    ];
    let got = suspended_ports_among(&hubs, &bindings);
    if got != alloc::vec![(7u8, 1u8), (8u8, 2u8)] {
        return TestResult::Fail("wake selection mismatch");
    }
    // Nothing suspended → nothing woken (the wake step must
    // never touch an awake port).
    let mut h2 = fake_hub_binding(9, 1);
    h2.bound_downstream |= 1 << 1;
    if !suspended_ports_among(&alloc::vec![h2], &alloc::vec![(9u8, 1u8)]).is_empty() {
        return TestResult::Fail("awake bound port selected for wake");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub_pm", smoke_hub_hid_wake_selection);

/// Registry-level: `hid::hub_ports` collects the hub contexts
/// the dispatcher recorded on live HID bindings across the
/// pumped classes, sorted + deduplicated (a composite device
/// binds two classes on one port), and omits root-attached
/// bindings. Seeds the keyboard + consumer registries via
/// their test hooks and resets them afterwards.
fn smoke_hub_hid_context_collection() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    hid::__reset_keyboards_for_test();
    hid::consumer::__reset_consumers_for_test();
    let result = (|| {
        hid::__push_keyboard_for_test(BootKeyboard {
            slot_id: 11,
            interrupt_in_ep: 3,
            interface_num: 0,
            hub_port: Some((7, 1)),
            last_report: KbdReport::default(),
        });
        // A second binding on the same port — must collapse.
        hid::__push_keyboard_for_test(BootKeyboard {
            slot_id: 12,
            interrupt_in_ep: 3,
            interface_num: 0,
            hub_port: Some((7, 1)),
            last_report: KbdReport::default(),
        });
        // Root-attached keyboard — omitted.
        hid::__push_keyboard_for_test(BootKeyboard {
            slot_id: 13,
            interrupt_in_ep: 3,
            interface_num: 0,
            hub_port: None,
            last_report: KbdReport::default(),
        });
        // A second class on a different hub's port.
        hid::consumer::__push_consumer_for_test(14, Some((8, 2)));
        let got = hid::hub_ports();
        if got != alloc::vec![(7u8, 1u8), (8u8, 2u8)] {
            return TestResult::Fail("hub_ports aggregation mismatch");
        }
        TestResult::Pass
    })();
    hid::__reset_keyboards_for_test();
    hid::consumer::__reset_consumers_for_test();
    result
}
kernel_test_in!("drivers/usb/hub_pm", smoke_hub_hid_context_collection);

// ── MSC BBB protocol codec unit tests ──────────────────────────────

/// CBW encode round-trip: encode a READ(10) CBW and verify every
/// field at the byte level (dCBWSignature, dCBWTag,
/// dCBWDataTransferLength, bmCBWFlags direction bit, bCBWCBLength,
/// and CBWCB bytes).
fn smoke_msc_cbw_encode_round_trip() -> TestResult {
    use crate::msc::{encode_cbw, CBW_SIGNATURE};

    // READ(10) on LBA 0x01020304, 3 blocks of 512 bytes each.
    let cb: [u8; 10] = [0x28, 0, 0x01, 0x02, 0x03, 0x04, 0, 0x00, 0x03, 0];
    let tag: u32 = 0xDEAD_BEEF;
    let data_len: u32 = 3 * 512;
    let cbw = encode_cbw(tag, data_len, true, 0, &cb);

    let sig = u32::from_le_bytes([cbw[0], cbw[1], cbw[2], cbw[3]]);
    if sig != CBW_SIGNATURE {
        return TestResult::Fail("dCBWSignature wrong");
    }
    let got_tag = u32::from_le_bytes([cbw[4], cbw[5], cbw[6], cbw[7]]);
    if got_tag != tag {
        return TestResult::Fail("dCBWTag mismatch");
    }
    let got_len = u32::from_le_bytes([cbw[8], cbw[9], cbw[10], cbw[11]]);
    if got_len != data_len {
        return TestResult::Fail("dCBWDataTransferLength mismatch");
    }
    if cbw[12] & 0x80 == 0 {
        return TestResult::Fail("bmCBWFlags IN bit not set");
    }
    if cbw[13] != 0 {
        return TestResult::Fail("bCBWLUN non-zero");
    }
    if cbw[14] != 10 {
        return TestResult::Fail("bCBWCBLength wrong");
    }
    if cbw[15..25] != cb[..] {
        return TestResult::Fail("CBWCB contents wrong");
    }
    if cbw[25..31].iter().any(|b| *b != 0) {
        return TestResult::Fail("CBW trailing bytes non-zero");
    }
    // OUT direction: bmCBWFlags bit 7 must be clear.
    let cbw_out = encode_cbw(1, 512, false, 0, &cb);
    if cbw_out[12] & 0x80 != 0 {
        return TestResult::Fail("bmCBWFlags OUT direction bit set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_cbw_encode_round_trip);

/// CSW decode: good (0), failed (1), and phase-error (2) statuses all
/// decode correctly; a bad signature and a truncated buffer are
/// both rejected.
fn smoke_msc_csw_decode_variants() -> TestResult {
    use crate::msc::{decode_csw, CSW_SIGNATURE};

    let make_csw = |tag: u32, residue: u32, status: u8| -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&tag.to_le_bytes());
        buf[8..12].copy_from_slice(&residue.to_le_bytes());
        buf[12] = status;
        buf
    };

    // Good status
    let csw_ok = make_csw(42, 0, 0);
    let f = match decode_csw(&csw_ok) {
        Some(f) => f,
        None => return TestResult::Fail("decode_csw rejected good CSW"),
    };
    if f.tag != 42 || f.residue != 0 || f.status != 0 {
        return TestResult::Fail("good CSW field mismatch");
    }

    // Failed status with non-zero residue
    let csw_fail = make_csw(99, 512, 1);
    let f = match decode_csw(&csw_fail) {
        Some(f) => f,
        None => return TestResult::Fail("decode_csw rejected fail CSW"),
    };
    if f.status != 1 || f.residue != 512 || f.tag != 99 {
        return TestResult::Fail("failed CSW field mismatch");
    }

    // Phase error status
    let csw_phase = make_csw(7, 0, 2);
    let f = match decode_csw(&csw_phase) {
        Some(f) => f,
        None => return TestResult::Fail("decode_csw rejected phase-error CSW"),
    };
    if f.status != 2 {
        return TestResult::Fail("phase-error status byte wrong");
    }

    // Bad signature must return None
    let mut bad_sig = make_csw(1, 0, 0);
    bad_sig[0] ^= 0xFF;
    if decode_csw(&bad_sig).is_some() {
        return TestResult::Fail("decode_csw accepted bad signature");
    }

    // Truncated buffer must return None
    if decode_csw(&csw_ok[..12]).is_some() {
        return TestResult::Fail("decode_csw accepted 12-byte buffer");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_csw_decode_variants);

/// SYNCHRONIZE CACHE(10) flush conversation against a scripted
/// fake device, at the byte level (the in-tree MSC fixture style):
/// the CDB encoder emits the whole-medium form, the CBW carries it
/// with no data stage, and the CSW replies the scripted device
/// sends back are judged by the transport's own status mapping —
/// Command Passed is Ok, Command Failed / Phase Error come back
/// as `MscError::CswStatus`, never as success (#829: a flush the
/// device refused must surface as a failed flush).
fn smoke_msc_sync_cache_flush_conversation() -> TestResult {
    use crate::msc::{
        check_csw_status, decode_csw, encode_cbw, encode_synchronize_cache10, MscError,
        CBW_SIGNATURE, CSW_SIGNATURE,
    };

    // Whole-medium flush CDB: opcode 0x35, LBA = 0, NUMBER OF
    // BLOCKS = 0 ("all blocks to the end of the medium"), IMD
    // clear so completion means the flush actually finished.
    let cdb = encode_synchronize_cache10();
    if cdb != [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("SYNCHRONIZE CACHE(10) CDB wrong");
    }

    // The CBW for it: no data stage, so dCBWDataTransferLength = 0
    // and the direction bit stays OUT; the CDB rides in CBWCB.
    let tag: u32 = 0x0BAD_F00D;
    let cbw = encode_cbw(tag, 0, false, 0, &cdb);
    if u32::from_le_bytes([cbw[0], cbw[1], cbw[2], cbw[3]]) != CBW_SIGNATURE {
        return TestResult::Fail("flush CBW signature wrong");
    }
    if u32::from_le_bytes([cbw[4], cbw[5], cbw[6], cbw[7]]) != tag {
        return TestResult::Fail("flush CBW tag mismatch");
    }
    if u32::from_le_bytes([cbw[8], cbw[9], cbw[10], cbw[11]]) != 0 {
        return TestResult::Fail("flush CBW data length non-zero");
    }
    if cbw[12] & 0x80 != 0 {
        return TestResult::Fail("flush CBW direction bit set (no data stage expected)");
    }
    if cbw[13] != 0 {
        return TestResult::Fail("flush CBW LUN non-zero");
    }
    if cbw[14] != 10 || cbw[15..25] != cdb[..] {
        return TestResult::Fail("flush CBW does not embed the SYNCHRONIZE CACHE CDB");
    }
    if cbw[25..31].iter().any(|b| *b != 0) {
        return TestResult::Fail("flush CBW trailing bytes non-zero");
    }

    // Scripted replies: build the CSW the fake device returns for
    // each outcome and run it through decode + status mapping,
    // exactly as the transport does.
    let scripted_csw = |status: u8| -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        buf[4..8].copy_from_slice(&tag.to_le_bytes());
        buf[12] = status;
        buf
    };
    for (status, expect_ok) in [(0u8, true), (1u8, false), (2u8, false)] {
        let fields = match decode_csw(&scripted_csw(status)) {
            Some(f) => f,
            None => return TestResult::Fail("decode_csw rejected scripted flush CSW"),
        };
        if fields.tag != tag || fields.status != status {
            return TestResult::Fail("scripted flush CSW fields mismatch");
        }
        match check_csw_status(fields.status) {
            Ok(()) if expect_ok => {}
            Err(MscError::CswStatus(s)) if !expect_ok && s == status => {}
            _ => return TestResult::Fail("flush CSW status mapped to the wrong result"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_sync_cache_flush_conversation);

/// WRITE(10) FUA encoding: the FUA form differs from the plain
/// form in exactly one bit (byte 1 bit 3); the plain encoder must
/// stay flag-free so non-FUA writes are unchanged (#829).
fn smoke_msc_write10_fua_encode() -> TestResult {
    use crate::msc::{encode_write10, encode_write10_fua};

    let plain = encode_write10(0x0102_0304, 3);
    let fua = encode_write10_fua(0x0102_0304, 3);
    if fua[0] != 0x2A {
        return TestResult::Fail("FUA WRITE(10) opcode wrong");
    }
    if fua[1] != 0x08 {
        return TestResult::Fail("FUA WRITE(10) missing the FUA bit (byte 1 bit 3)");
    }
    if plain[1] != 0 {
        return TestResult::Fail("plain WRITE(10) gained CDB flags");
    }
    if fua[2..10] != plain[2..10] {
        return TestResult::Fail("FUA WRITE(10) changed fields beyond the FUA bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_write10_fua_encode);

/// Live flush conversation: on a QEMU-attached stick the block
/// adapter must advertise the Flush/FUA it performs, `flush()`
/// must complete a real SYNCHRONIZE CACHE(10), and a FUA write
/// must round-trip. Skips (like the attach smoke) when no xHCI /
/// no MSC device is present. The FUA probe uses the last block
/// and restores its original contents, leaving the scratch
/// image as it found it.
fn smoke_msc_flush_via_xhci_qemu() -> TestResult {
    use crate::{msc, xhci};
    use narf_block::BlockDeviceSync;

    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    msc::__reset_msc_for_test();
    let attached = match xhci::controller() {
        Some(c) => narf_scheduler::block_on(async { msc::enumerate_and_attach_msc(&c).await }),
        None => 0,
    };
    if attached == 0 {
        return TestResult::Skip("no MSC device attached to xhci");
    }
    let dev = match msc::UsbMscBlockDevice::from_index(0) {
        Some(d) => d,
        None => return TestResult::Fail("block adapter refused attached device"),
    };
    let caps = dev.capabilities();
    if !caps.volatile_cache || !caps.fua {
        return TestResult::Fail("adapter does not advertise the Flush/FUA it performs");
    }
    if dev.flush().is_err() {
        return TestResult::Fail("SYNCHRONIZE CACHE(10) flush failed on live device");
    }
    let lba_size = dev.lba_size() as usize;
    let last = dev.capacity() - 1;
    let mut original = alloc::vec![0u8; lba_size];
    if dev.read(last, 1, &mut original).is_err() {
        return TestResult::Fail("read of last block failed");
    }
    let mut pattern = alloc::vec![0u8; lba_size];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xA5;
    }
    if dev.write_fua(last, 1, &pattern).is_err() {
        return TestResult::Fail("FUA write failed on live device");
    }
    let mut back = alloc::vec![0u8; lba_size];
    if dev.read(last, 1, &mut back).is_err() || back != pattern {
        return TestResult::Fail("FUA-written block did not read back");
    }
    if dev.write_fua(last, 1, &original).is_err() || dev.flush().is_err() {
        return TestResult::Fail("restore/flush failed on live device");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_flush_via_xhci_qemu);

/// INQUIRY response decoder: space-padded vendor/product/revision
/// fields are trimmed; peripheral type and removable bit are correct.
fn smoke_msc_inquiry_response_decode() -> TestResult {
    use crate::msc::InquiryData;

    let mut buf = [0x20u8; 36]; // fill with spaces (ASCII)
    buf[0] = 0x00; // direct-access peripheral type, non-removable flag
    buf[1] = 0x80; // RMB = 1 (removable)
    buf[2] = 0x06; // VERSION
    buf[3] = 0x02; // response data format
    buf[4] = 0x1F; // additional length
    buf[8..16].copy_from_slice(b"SanDisk ");
    buf[16..32].copy_from_slice(b"Ultra USB 3.0   ");
    buf[32..36].copy_from_slice(b"1.00");

    let d = match InquiryData::from_bytes(&buf) {
        Some(d) => d,
        None => return TestResult::Fail("InquiryData::from_bytes returned None"),
    };
    if d.peripheral_type != 0 {
        return TestResult::Fail("peripheral_type wrong");
    }
    if !d.removable {
        return TestResult::Fail("removable bit not set");
    }
    if d.vendor != "SanDisk" {
        return TestResult::Fail("vendor string mismatch");
    }
    if d.product != "Ultra USB 3.0" {
        return TestResult::Fail("product string mismatch");
    }
    if d.revision != "1.00" {
        return TestResult::Fail("revision string mismatch");
    }
    // Short buffer must return None
    if InquiryData::from_bytes(&buf[..35]).is_some() {
        return TestResult::Fail("InquiryData accepted 35-byte buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_inquiry_response_decode);

/// READ CAPACITY(10) decoder: big-endian last_lba and block_size are
/// decoded correctly; short buffers are rejected.
fn smoke_msc_read_capacity10_decode() -> TestResult {
    use crate::msc::decode_read_capacity10;

    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    buf[4..8].copy_from_slice(&512u32.to_be_bytes());
    let (block_size, last_lba) = match decode_read_capacity10(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode_read_capacity10 returned None"),
    };
    if block_size != 512 {
        return TestResult::Fail("block_size wrong");
    }
    if last_lba != 0x00FF_FFFF {
        return TestResult::Fail("last_lba wrong");
    }

    // 4096-byte blocks
    let mut buf2 = [0u8; 8];
    buf2[0..4].copy_from_slice(&0x001F_FFFFu32.to_be_bytes());
    buf2[4..8].copy_from_slice(&4096u32.to_be_bytes());
    let (bs2, lba2) = match decode_read_capacity10(&buf2) {
        Some(v) => v,
        None => return TestResult::Fail("decode_read_capacity10 failed 4K case"),
    };
    if bs2 != 4096 || lba2 != 0x001F_FFFF {
        return TestResult::Fail("4K block-size decode wrong");
    }

    // Short buffer must return None
    if decode_read_capacity10(&buf[..7]).is_some() {
        return TestResult::Fail("decode_read_capacity10 accepted 7-byte buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_read_capacity10_decode);

/// READ(10) and WRITE(10) CDB encoder: opcode, big-endian LBA, and
/// big-endian transfer-length are in the correct CDB byte positions.
fn smoke_msc_read_write10_encoder() -> TestResult {
    use crate::msc::{encode_read10, encode_write10};

    // READ(10) on LBA 0x0102_0304, 7 blocks.
    let r = encode_read10(0x0102_0304, 7);
    if r[0] != 0x28 {
        return TestResult::Fail("READ(10) opcode wrong");
    }
    if r[2..6] != [0x01, 0x02, 0x03, 0x04] {
        return TestResult::Fail("READ(10) LBA bytes wrong");
    }
    if r[7..9] != [0x00, 0x07] {
        return TestResult::Fail("READ(10) nblocks bytes wrong");
    }

    // WRITE(10) on LBA 0xDEAD_BEEF, 1 block.
    let w = encode_write10(0xDEAD_BEEF, 1);
    if w[0] != 0x2A {
        return TestResult::Fail("WRITE(10) opcode wrong");
    }
    if w[2..6] != [0xDE, 0xAD, 0xBE, 0xEF] {
        return TestResult::Fail("WRITE(10) LBA bytes wrong");
    }
    if w[7..9] != [0x00, 0x01] {
        return TestResult::Fail("WRITE(10) nblocks bytes wrong");
    }

    // Maximum transfer length 0xFFFF must not overflow.
    let r_max = encode_read10(0, 0xFFFF);
    if r_max[7..9] != [0xFF, 0xFF] {
        return TestResult::Fail("READ(10) max nblocks overflow");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_read_write10_encoder);

// ── HID class-driver descriptor parser + report decode ─────────────

fn smoke_hid_boot_keyboard_parse() -> TestResult {
    use crate::hid;
    use crate::xhci::EndpointKind;

    let cfg: [u8; 25] = [
        9, 2, 25, 0, 1, 1, 0, 0xA0, 0, 9, 4, 0, 0, 1, 0x03, 0x01, 0x01, 0, 7, 5, 0x81, 0x03, 0x08,
        0x00, 10,
    ];
    let (iface, ep) = match hid::find_boot_keyboard(&cfg) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("find_boot_keyboard rejected HID blob"),
    };
    if iface != 0
        || ep.kind != EndpointKind::InterruptIn
        || ep.ep_addr != 0x81
        || ep.max_packet != 8
    {
        return TestResult::Fail("HID kbd endpoint mis-decoded");
    }
    let report = hid::KbdReport::from_bytes([
        hid::kbd_mod::LCTRL | hid::kbd_mod::LSHIFT,
        0,
        0x04,
        0x05,
        0,
        0,
        0,
        0,
    ]);
    if !report.pressed(0x04) || !report.pressed(0x05) {
        return TestResult::Fail("KbdReport::pressed missed key");
    }
    if report.modifiers != (hid::kbd_mod::LCTRL | hid::kbd_mod::LSHIFT) {
        return TestResult::Fail("KbdReport modifier byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_boot_keyboard_parse);

// ── HID Usage → KeyCode coverage ───────────────────────────────────

fn smoke_hid_usage_to_keycode_table() -> TestResult {
    use crate::hid::usage_to_keycode;
    use narf_input::KeyCode;
    // Spot-check the rows people care most about: letters, digits,
    // navigation cluster, function-row, numpad, modifier escapes.
    let cases: &[(u8, KeyCode)] = &[
        (0x04, KeyCode::A),
        (0x1D, KeyCode::Z),
        (0x1E, KeyCode::Key1),
        (0x27, KeyCode::Key0),
        (0x28, KeyCode::Enter),
        (0x29, KeyCode::Escape),
        (0x2A, KeyCode::Backspace),
        (0x2B, KeyCode::Tab),
        (0x2C, KeyCode::Space),
        (0x39, KeyCode::CapsLock),
        (0x3A, KeyCode::F1),
        (0x45, KeyCode::F12),
        (0x46, KeyCode::SysRq),
        (0x48, KeyCode::Pause),
        (0x49, KeyCode::Insert),
        (0x4C, KeyCode::Delete),
        (0x4A, KeyCode::Home),
        (0x4D, KeyCode::End),
        (0x4B, KeyCode::PageUp),
        (0x4E, KeyCode::PageDown),
        (0x4F, KeyCode::Right),
        (0x50, KeyCode::Left),
        (0x51, KeyCode::Down),
        (0x52, KeyCode::Up),
        (0x53, KeyCode::NumLock),
        (0x54, KeyCode::KpSlash),
        (0x55, KeyCode::KpAsterisk),
        (0x56, KeyCode::KpMinus),
        (0x57, KeyCode::KpPlus),
        (0x58, KeyCode::KpEnter),
        (0x59, KeyCode::Kp1),
        (0x62, KeyCode::Kp0),
        (0x63, KeyCode::KpDot),
        (0x65, KeyCode::Menu),
        (0xE0, KeyCode::LeftCtrl),
        (0xE7, KeyCode::RightMeta),
    ];
    for &(u, want) in cases {
        let got = usage_to_keycode(u);
        if got != want {
            return TestResult::Fail("usage_to_keycode mismatch");
        }
    }
    if usage_to_keycode(0x00) != KeyCode::Unknown || usage_to_keycode(0xFF) != KeyCode::Unknown {
        return TestResult::Fail("Unknown sentinel mis-set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_usage_to_keycode_table);

fn smoke_hid_modifier_byte_to_modifiers() -> TestResult {
    use crate::hid;
    use narf_input::Modifiers;
    let m = hid::modifier_byte_to_modifiers(
        hid::kbd_mod::LCTRL | hid::kbd_mod::RSHIFT | hid::kbd_mod::LALT | hid::kbd_mod::RGUI,
    );
    if !m.contains(Modifiers::CTRL) {
        return TestResult::Fail("CTRL");
    }
    if !m.contains(Modifiers::SHIFT) {
        return TestResult::Fail("SHIFT");
    }
    if !m.contains(Modifiers::ALT) {
        return TestResult::Fail("ALT");
    }
    if !m.contains(Modifiers::META) {
        return TestResult::Fail("META");
    }
    let none = hid::modifier_byte_to_modifiers(0);
    if none.bits() != 0 {
        return TestResult::Fail("zero byte → non-zero mods");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_modifier_byte_to_modifiers);

fn smoke_hid_diff_press_release_repeat() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode,
    };

    init_global_ring(64);
    __reset_global_ring_for_test();
    hid::__reset_keyboards_for_test();

    // Fabricate a keyboard binding without going through the
    // controller — we only exercise translate_report here.
    let mut kbd = BootKeyboard {
        slot_id: 1,
        interrupt_in_ep: 3,
        interface_num: 0,
        hub_port: None,
        last_report: KbdReport::default(),
    };

    // First report: A pressed (with LShift held) — should fire two
    // events: LeftShift press, then A press.
    let r1 = KbdReport::from_bytes([hid::kbd_mod::LSHIFT, 0, 0x04, 0, 0, 0, 0, 0]);
    let n1 = kbd.translate_report(r1);
    if n1 != 2 {
        return TestResult::Fail("expected 2 events on first press");
    }

    let e1 = pop_global();
    let e2 = pop_global();
    let (k1, p1) = match e1 {
        Some(InputEvent::Key(k)) => (k.code, k.pressed),
        _ => return TestResult::Fail("e1 missing"),
    };
    let (k2, p2) = match e2 {
        Some(InputEvent::Key(k)) => (k.code, k.pressed),
        _ => return TestResult::Fail("e2 missing"),
    };
    if !(p1 && k1 == KeyCode::LeftShift) {
        return TestResult::Fail("expected LShift press first");
    }
    if !(p2 && k2 == KeyCode::A) {
        return TestResult::Fail("expected A press second");
    }

    // Second report: same keys still held → no events.
    let n2 = kbd.translate_report(r1);
    if n2 != 0 {
        return TestResult::Fail("repeat report emitted events");
    }
    if pop_global().is_some() {
        return TestResult::Fail("ring non-empty after repeat");
    }

    // Third report: A released, B pressed (still LShift held) →
    // one release (A) + one press (B), no LShift transition.
    let r3 = KbdReport::from_bytes([hid::kbd_mod::LSHIFT, 0, 0x05, 0, 0, 0, 0, 0]);
    let n3 = kbd.translate_report(r3);
    if n3 != 2 {
        return TestResult::Fail("expected 2 events on swap");
    }

    let mut got_a_release = false;
    let mut got_b_press = false;
    for _ in 0..2 {
        match pop_global() {
            Some(InputEvent::Key(k)) => {
                if k.code == KeyCode::A && !k.pressed {
                    got_a_release = true;
                }
                if k.code == KeyCode::B && k.pressed {
                    got_b_press = true;
                }
            }
            _ => return TestResult::Fail("missing event after swap"),
        }
    }
    if !got_a_release {
        return TestResult::Fail("A release missing");
    }
    if !got_b_press {
        return TestResult::Fail("B press missing");
    }

    // Fourth report: empty (everything released) → LShift release
    // and B release.
    let r4 = KbdReport::from_bytes([0; 8]);
    let n4 = kbd.translate_report(r4);
    if n4 != 2 {
        return TestResult::Fail("expected 2 releases on clear");
    }

    let mut got_shift_release = false;
    let mut got_b_release = false;
    for _ in 0..2 {
        match pop_global() {
            Some(InputEvent::Key(k)) => {
                if k.code == KeyCode::LeftShift && !k.pressed {
                    got_shift_release = true;
                }
                if k.code == KeyCode::B && !k.pressed {
                    got_b_release = true;
                }
            }
            _ => return TestResult::Fail("missing release event"),
        }
    }
    if !got_shift_release {
        return TestResult::Fail("LShift release missing");
    }
    if !got_b_release {
        return TestResult::Fail("B release missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_diff_press_release_repeat);

fn smoke_hid_rollover_suppressed() -> TestResult {
    use crate::hid::{BootKeyboard, KbdReport};
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global};

    init_global_ring(64);
    __reset_global_ring_for_test();
    let mut kbd = BootKeyboard {
        slot_id: 1,
        interrupt_in_ep: 3,
        interface_num: 0,
        hub_port: None,
        last_report: KbdReport::default(),
    };
    // The HID error roll-over: all six positions = 0x01 with no
    // modifier bits set. Should produce zero events.
    let roll = KbdReport::from_bytes([0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
    let n = kbd.translate_report(roll);
    if n != 0 {
        return TestResult::Fail("rollover emitted events");
    }
    if pop_global().is_some() {
        return TestResult::Fail("rollover wrote to ring");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_rollover_suppressed);

fn smoke_hid_modifier_only_transition() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode, Modifiers,
    };

    init_global_ring(64);
    __reset_global_ring_for_test();
    let mut kbd = BootKeyboard {
        slot_id: 1,
        interrupt_in_ep: 3,
        interface_num: 0,
        hub_port: None,
        last_report: KbdReport::default(),
    };
    // Press LCtrl alone → one event with CTRL set.
    let r1 = KbdReport::from_bytes([hid::kbd_mod::LCTRL, 0, 0, 0, 0, 0, 0, 0]);
    let n1 = kbd.translate_report(r1);
    if n1 != 1 {
        return TestResult::Fail("expected 1 event for ctrl press");
    }
    match pop_global() {
        Some(InputEvent::Key(k)) => {
            if !(k.pressed && k.code == KeyCode::LeftCtrl && k.modifiers.contains(Modifiers::CTRL))
            {
                return TestResult::Fail("ctrl press shape wrong");
            }
        }
        _ => return TestResult::Fail("ctrl press missing"),
    }
    // Add RAlt on top of LCtrl → one event (RAlt press) carrying
    // both CTRL and ALT.
    let r2 = KbdReport::from_bytes([
        hid::kbd_mod::LCTRL | hid::kbd_mod::RALT,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    let n2 = kbd.translate_report(r2);
    if n2 != 1 {
        return TestResult::Fail("expected 1 event for ralt add");
    }
    match pop_global() {
        Some(InputEvent::Key(k)) => {
            if !(k.pressed
                && k.code == KeyCode::RightAlt
                && k.modifiers.contains(Modifiers::CTRL)
                && k.modifiers.contains(Modifiers::ALT))
            {
                return TestResult::Fail("ralt-add shape wrong");
            }
        }
        _ => return TestResult::Fail("ralt-add missing"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_modifier_only_transition);

// ── UAC1 descriptor parser smokes ──────────────────────────────────

fn smoke_uac_class_triple_constants() -> TestResult {
    use crate::uac;
    if uac::USB_CLASS_AUDIO != 0x01 {
        return TestResult::Fail("Audio class code = 0x01");
    }
    if uac::USB_AUDIO_SUBCLASS_AUDIOCONTROL != 0x01 {
        return TestResult::Fail("AC subclass = 0x01");
    }
    if uac::USB_AUDIO_SUBCLASS_AUDIOSTREAMING != 0x02 {
        return TestResult::Fail("AS subclass = 0x02");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_class_triple_constants);

fn smoke_uac_ac_header_decodes_collection() -> TestResult {
    use crate::uac::AcHeader;
    // bLength=10, CS_INTERFACE, HEADER, bcdADC=0x0100,
    // wTotalLength=0x0040, bInCollection=2, [iface_a, iface_b]
    let buf = [10, 0x24, 0x01, 0x00, 0x01, 0x40, 0x00, 2, 0x01, 0x02];
    let h = AcHeader::parse(&buf).expect("parse");
    if h.bcd_adc != 0x0100 {
        return TestResult::Fail("bcdADC should decode to 0x0100");
    }
    if h.total_length != 0x40 {
        return TestResult::Fail("wTotalLength mismatch");
    }
    if h.in_collection != alloc::vec![1u8, 2u8] {
        return TestResult::Fail("collection list mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_ac_header_decodes_collection);

fn smoke_uac_input_terminal_microphone() -> TestResult {
    use crate::uac::{InputTerminal, TERMINAL_MICROPHONE};
    // 12 bytes: bLength=12, CS_INTERFACE, INPUT_TERMINAL,
    // bTerminalID=1, wTerminalType=0x0201 (microphone),
    // bAssocTerminal=0, bNrChannels=2, wChannelConfig=0x0003 (FL+FR),
    // iChannelNames=0, iTerminal=0
    let buf = [12, 0x24, 0x02, 1, 0x01, 0x02, 0, 2, 0x03, 0x00, 0, 0];
    let t = InputTerminal::parse(&buf).expect("parse");
    if t.terminal_type != TERMINAL_MICROPHONE {
        return TestResult::Fail("microphone terminal type = 0x0201");
    }
    if t.nr_channels != 2 {
        return TestResult::Fail("channel count mismatch");
    }
    if t.channel_config != 0x0003 {
        return TestResult::Fail("channel config mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_input_terminal_microphone);

fn smoke_uac_output_terminal_speaker() -> TestResult {
    use crate::uac::{OutputTerminal, TERMINAL_SPEAKER};
    // 9 bytes: bLength=9, CS_INTERFACE, OUTPUT_TERMINAL,
    // bTerminalID=2, wTerminalType=0x0301, bAssocTerminal=0,
    // bSourceID=3, iTerminal=0
    let buf = [9, 0x24, 0x03, 2, 0x01, 0x03, 0, 3, 0];
    let t = OutputTerminal::parse(&buf).expect("parse");
    if t.terminal_type != TERMINAL_SPEAKER {
        return TestResult::Fail("speaker terminal type = 0x0301");
    }
    if t.source_id != 3 {
        return TestResult::Fail("source id mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_output_terminal_speaker);

fn smoke_uac_feature_unit_decodes_per_channel_controls() -> TestResult {
    use crate::uac::{FeatureUnit, FEATURE_MUTE, FEATURE_VOLUME};
    // bLength=10, CS_INTERFACE, FEATURE_UNIT, bUnitID=4,
    // bSourceID=1, bControlSize=1, master ctrl = MUTE|VOLUME,
    // ch1 = VOLUME, ch2 = VOLUME, iFeature=0
    let buf = [
        10,
        0x24,
        0x06,
        4,
        1,
        1,
        (FEATURE_MUTE | FEATURE_VOLUME) as u8,
        FEATURE_VOLUME as u8,
        FEATURE_VOLUME as u8,
        0,
    ];
    let f = FeatureUnit::parse(&buf).expect("parse");
    if f.unit_id != 4 {
        return TestResult::Fail("unit id mismatch");
    }
    if f.controls.len() != 3 {
        return TestResult::Fail("expected master + 2 channel control bitmaps");
    }
    if f.controls[0] != (FEATURE_MUTE | FEATURE_VOLUME) {
        return TestResult::Fail("master control bitmap mismatch");
    }
    if f.controls[1] != FEATURE_VOLUME {
        return TestResult::Fail("ch1 control bitmap mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_uac_feature_unit_decodes_per_channel_controls
);

#[allow(clippy::erasing_op)]
fn smoke_uac_format_type_i_pcm_44k_48k() -> TestResult {
    use crate::uac::{FormatTypeI, FORMAT_TYPE_I};
    // bLength=14, CS_INTERFACE, FORMAT_TYPE, bFormatType=1,
    // bNrChannels=2, bSubframeSize=2, bBitResolution=16, bSamFreqType=2,
    // tSamFreq[0] = 44100 (LE 24-bit), tSamFreq[1] = 48000
    let mut buf = alloc::vec![14, 0x24, 0x02, FORMAT_TYPE_I, 2, 2, 16, 2];
    buf.extend_from_slice(&[
        (44100u32 & 0xFF) as u8,
        ((44100u32 >> 8) & 0xFF) as u8,
        ((44100u32 >> 16) & 0xFF) as u8,
    ]);
    buf.extend_from_slice(&[
        (48000u32 & 0xFF) as u8,
        ((48000u32 >> 8) & 0xFF) as u8,
        ((48000u32 >> 16) & 0xFF) as u8,
    ]);
    let f = FormatTypeI::parse(&buf).expect("parse");
    if f.nr_channels != 2 || f.subframe_size != 2 || f.bit_resolution != 16 {
        return TestResult::Fail("format Type-I header mismatch");
    }
    if f.sample_rates != alloc::vec![44100u32, 48000u32] {
        return TestResult::Fail("sample-rate list mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_format_type_i_pcm_44k_48k);

fn smoke_uac_format_type_i_continuous_range() -> TestResult {
    use crate::uac::{FormatTypeI, FORMAT_TYPE_I};
    // bSamFreqType=0 → continuous: 6 bytes = lower + upper LE 24-bit.
    let mut buf = alloc::vec![14, 0x24, 0x02, FORMAT_TYPE_I, 2, 2, 16, 0];
    // 8000 .. 96000
    buf.extend_from_slice(&[(8000u32 & 0xFF) as u8, ((8000u32 >> 8) & 0xFF) as u8, 0]);
    buf.extend_from_slice(&[
        (96000u32 & 0xFF) as u8,
        ((96000u32 >> 8) & 0xFF) as u8,
        ((96000u32 >> 16) & 0xFF) as u8,
    ]);
    let f = FormatTypeI::parse(&buf).expect("parse");
    if f.range_lower_hz != Some(8000) || f.range_upper_hz != Some(96000) {
        return TestResult::Fail("continuous-range Hz decode wrong");
    }
    if !f.sample_rates.is_empty() {
        return TestResult::Fail("continuous range should leave discrete list empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_format_type_i_continuous_range);

// ── UVC descriptor parser smokes ───────────────────────────────────

fn smoke_uvc_class_triple_constants() -> TestResult {
    use crate::uvc;
    if uvc::USB_CLASS_VIDEO != 0x0E {
        return TestResult::Fail("Video class code = 0x0E");
    }
    if uvc::USB_VIDEO_SUBCLASS_VIDEOSTREAMING != 0x02 {
        return TestResult::Fail("VS subclass = 0x02");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_class_triple_constants);

fn smoke_uvc_yuy2_guid_bytes() -> TestResult {
    use crate::uvc::GUID_FORMAT_YUY2;
    // The first four ASCII bytes of the GUID are "YUY2".
    if &GUID_FORMAT_YUY2[..4] != b"YUY2" {
        return TestResult::Fail("YUY2 GUID prefix should be ASCII 'YUY2'");
    }
    // The trailing fixed suffix is the FOURCC namespace.
    if GUID_FORMAT_YUY2[8..16] != [0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71] {
        return TestResult::Fail("YUY2 GUID trailer mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_yuy2_guid_bytes);

fn smoke_uvc_vc_header_parses() -> TestResult {
    use crate::uvc::VcHeader;
    // bLength=13, CS_INTERFACE, VC_HEADER, bcdUVC=0x0150 (UVC 1.5),
    // wTotalLength=0x80, dwClockFrequency=15_000_000 LE,
    // bInCollection=1, baInterfaceNr[0]=2
    let mut buf = alloc::vec![13, 0x24, 0x01, 0x50, 0x01, 0x80, 0x00];
    buf.extend_from_slice(&15_000_000u32.to_le_bytes());
    buf.push(1);
    buf.push(2);
    let h = VcHeader::parse(&buf).expect("parse");
    if h.bcd_uvc != 0x0150 {
        return TestResult::Fail("bcdUVC should decode to 0x0150");
    }
    if h.clock_frequency != 15_000_000 {
        return TestResult::Fail("clock frequency mismatch");
    }
    if h.in_collection != alloc::vec![2u8] {
        return TestResult::Fail("collection list mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_vc_header_parses);

fn smoke_uvc_camera_input_terminal_carries_focal_length() -> TestResult {
    use crate::uvc::{InputTerminal, ITT_CAMERA};
    // bLength=18, CS_INTERFACE, INPUT_TERMINAL, bTerminalID=1,
    // wTerminalType=0x0201 (Camera), bAssocTerminal=0, iTerminal=0,
    // wObjectiveFocalLengthMin=10, Max=100, wOcularFocalLength=50,
    // bControlSize=3, bmControls=0x00_0007 (auto-exposure mode + AE
    // priority + exposure time absolute), trailing iTerminal handled
    // implicitly by remaining bytes.
    let mut buf = alloc::vec![18u8, 0x24, 0x02, 1, 0x01, 0x02, 0, 0];
    buf.extend_from_slice(&10u16.to_le_bytes());
    buf.extend_from_slice(&100u16.to_le_bytes());
    buf.extend_from_slice(&50u16.to_le_bytes());
    buf.push(3);
    buf.push(0x07);
    buf.push(0x00);
    buf.push(0x00);
    let t = InputTerminal::parse(&buf).expect("parse");
    if t.terminal_type != ITT_CAMERA {
        return TestResult::Fail("camera terminal type 0x0201 expected");
    }
    let cam = t.camera.expect("camera-specific block must populate");
    if cam.objective_focal_length_min != 10 || cam.objective_focal_length_max != 100 {
        return TestResult::Fail("focal length range mismatch");
    }
    if cam.controls != 0x07 {
        return TestResult::Fail("camera controls bitmap mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_uvc_camera_input_terminal_carries_focal_length
);

fn smoke_uvc_format_uncompressed_yuy2() -> TestResult {
    use crate::uvc::{FormatUncompressed, GUID_FORMAT_YUY2};
    // 27 bytes: bLength=27, CS_INTERFACE, FORMAT_UNCOMPRESSED,
    // bFormatIndex=1, bNumFrameDescriptors=2, GUID=YUY2, bBitsPerPixel=16,
    // bDefaultFrameIndex=1, aspect 16:9, interlace 0, copy_protect 0
    let mut buf = alloc::vec![27, 0x24, 0x04, 1, 2];
    buf.extend_from_slice(&GUID_FORMAT_YUY2);
    buf.push(16);
    buf.push(1);
    buf.push(16);
    buf.push(9);
    buf.push(0);
    buf.push(0);
    let f = FormatUncompressed::parse(&buf).expect("parse");
    if f.guid != GUID_FORMAT_YUY2 {
        return TestResult::Fail("GUID round-trip");
    }
    if f.bits_per_pixel != 16 {
        return TestResult::Fail("YUY2 should declare 16 bpp");
    }
    if f.aspect_ratio_x != 16 || f.aspect_ratio_y != 9 {
        return TestResult::Fail("aspect ratio mismatch");
    }
    if f.num_frame_descriptors != 2 {
        return TestResult::Fail("num_frame_descriptors lost");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_format_uncompressed_yuy2);

fn smoke_uvc_frame_uncompressed_1080p30() -> TestResult {
    use crate::uvc::FrameUncompressed;
    // bLength=30, CS_INTERFACE, FRAME_UNCOMPRESSED, bFrameIndex=1,
    // capabilities=0, wWidth=1920, wHeight=1080, dwMin/MaxBitrate,
    // dwMaxVideoFrameBufferSize, dwDefaultFrameInterval=333_333 (30 fps),
    // bFrameIntervalType=1, dwFrameInterval[0]=333_333
    let mut buf = alloc::vec![30u8, 0x24, 0x05, 1, 0];
    buf.extend_from_slice(&1920u16.to_le_bytes());
    buf.extend_from_slice(&1080u16.to_le_bytes());
    buf.extend_from_slice(&100_000_000u32.to_le_bytes()); // min bitrate 100 Mbps
    buf.extend_from_slice(&100_000_000u32.to_le_bytes()); // max bitrate
    buf.extend_from_slice(&(1920u32 * 1080 * 2).to_le_bytes()); // YUY2 buffer
    buf.extend_from_slice(&333_333u32.to_le_bytes()); // default interval
    buf.push(1); // discrete, 1 entry
    buf.extend_from_slice(&333_333u32.to_le_bytes());
    let f = FrameUncompressed::parse(&buf).expect("parse");
    if f.width != 1920 || f.height != 1080 {
        return TestResult::Fail("1080p resolution lost");
    }
    if f.frame_intervals != alloc::vec![333_333u32] {
        return TestResult::Fail("frame interval list mismatch");
    }
    let fps = FrameUncompressed::fps_from_interval(f.frame_intervals[0]);
    if fps != 30 {
        return TestResult::Fail("100 ns interval should convert to 30 fps");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_frame_uncompressed_1080p30);

fn smoke_uvc_format_mjpeg_decodes_default_frame_index() -> TestResult {
    use crate::uvc::FormatMjpeg;
    // 11 bytes: bLength=11, CS_INTERFACE, FORMAT_MJPEG, bFormatIndex=2,
    // bNumFrameDescriptors=3, bmFlags=0x01, bDefaultFrameIndex=2,
    // aspect 4:3, interlace 0, copy_protect 0
    let buf = [11u8, 0x24, 0x06, 2, 3, 0x01, 2, 4, 3, 0, 0];
    let f = FormatMjpeg::parse(&buf).expect("parse");
    if f.format_index != 2 {
        return TestResult::Fail("format index lost");
    }
    if f.default_frame_index != 2 {
        return TestResult::Fail("default frame index lost");
    }
    if f.aspect_ratio_x != 4 || f.aspect_ratio_y != 3 {
        return TestResult::Fail("aspect ratio lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_uvc_format_mjpeg_decodes_default_frame_index
);

fn smoke_uvc_frame_mjpeg_720p30_discrete() -> TestResult {
    use crate::uvc::FrameMjpeg;
    // VS_FRAME_MJPEG with 1 discrete interval (30 fps).
    // bLength=30, CS_INTERFACE(0x24), subtype=0x07(VS_FRAME_MJPEG),
    // bFrameIndex=1, capabilities=0, wWidth=1280 LE, wHeight=720 LE,
    // dwMinBitRate, dwMaxBitRate, dwMaxVideoFrameBufferSize (MJPEG
    // frames are compressed, size estimate = W*H),
    // dwDefaultFrameInterval=333333 (30 fps, 100 ns units),
    // bFrameIntervalType=1 (1 discrete entry),
    // dwFrameInterval[0]=333333.
    let mut buf = alloc::vec![30u8, 0x24, 0x07, 1, 0];
    buf.extend_from_slice(&1280u16.to_le_bytes());
    buf.extend_from_slice(&720u16.to_le_bytes());
    buf.extend_from_slice(&40_000_000u32.to_le_bytes()); // min bitrate
    buf.extend_from_slice(&40_000_000u32.to_le_bytes()); // max bitrate
    buf.extend_from_slice(&(1280u32 * 720).to_le_bytes()); // max frame buf (MJPEG compressed)
    buf.extend_from_slice(&333_333u32.to_le_bytes()); // default interval
    buf.push(1); // 1 discrete interval
    buf.extend_from_slice(&333_333u32.to_le_bytes());

    let f = FrameMjpeg::parse(&buf).expect("parse FrameMjpeg");
    if f.width != 1280 || f.height != 720 {
        return TestResult::Fail("720p resolution lost");
    }
    if f.frame_index != 1 {
        return TestResult::Fail("frame_index lost");
    }
    if f.frame_intervals != alloc::vec![333_333u32] {
        return TestResult::Fail("frame interval list wrong");
    }
    if FrameMjpeg::fps_from_interval(f.frame_intervals[0]) != 30 {
        return TestResult::Fail("fps_from_interval should yield 30");
    }
    if f.continuous_min.is_some() || f.continuous_max.is_some() {
        return TestResult::Fail("continuous range must be None for discrete type");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_frame_mjpeg_720p30_discrete);

fn smoke_uvc_frame_mjpeg_continuous_range() -> TestResult {
    use crate::uvc::FrameMjpeg;
    // VS_FRAME_MJPEG with continuous range (type = 0, 12 bytes after hdr).
    // bLength=38, CS_INTERFACE(0x24), subtype=0x07, bFrameIndex=2,
    // capabilities=0, wWidth=640, wHeight=480,
    // min/max bitrate, max frame size, default=333333,
    // bFrameIntervalType=0 (continuous),
    // min=166667 (60 fps), max=1000000 (10 fps), step=166667.
    let mut buf = alloc::vec![38u8, 0x24, 0x07, 2, 0];
    buf.extend_from_slice(&640u16.to_le_bytes());
    buf.extend_from_slice(&480u16.to_le_bytes());
    buf.extend_from_slice(&10_000_000u32.to_le_bytes());
    buf.extend_from_slice(&10_000_000u32.to_le_bytes());
    buf.extend_from_slice(&(640u32 * 480).to_le_bytes());
    buf.extend_from_slice(&333_333u32.to_le_bytes()); // default
    buf.push(0); // continuous
    buf.extend_from_slice(&166_667u32.to_le_bytes()); // min (60 fps)
    buf.extend_from_slice(&1_000_000u32.to_le_bytes()); // max (10 fps)
    buf.extend_from_slice(&166_667u32.to_le_bytes()); // step

    let f = FrameMjpeg::parse(&buf).expect("parse continuous FrameMjpeg");
    if f.continuous_min != Some(166_667) {
        return TestResult::Fail("continuous_min lost");
    }
    if f.continuous_max != Some(1_000_000) {
        return TestResult::Fail("continuous_max lost");
    }
    if f.continuous_step != Some(166_667) {
        return TestResult::Fail("continuous_step lost");
    }
    if !f.frame_intervals.is_empty() {
        return TestResult::Fail("discrete intervals must be empty for continuous type");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_frame_mjpeg_continuous_range);

// ── HID Boot Mouse — descriptor parser + diff ──────────────────────

fn smoke_hid_boot_mouse_parse() -> TestResult {
    use crate::hid::mouse;
    use crate::xhci::EndpointKind;

    // Same shape as the keyboard cfg blob, but bInterfaceProtocol = 2
    // (mouse) and the interrupt-IN endpoint sized for the 3-byte
    // boot report.
    let cfg: [u8; 25] = [
        // CONFIG: 9, 2, wTotalLen=25, numIface=1, cfgVal=1, iCfg=0,
        // bmAttr=0xA0, MaxPwr=0
        9, 2, 25, 0, 1, 1, 0, 0xA0, 0,
        // INTERFACE: 9, 4, iface=0, alt=0, numEP=1,
        // class=0x03 (HID), sub=0x01 (Boot), proto=0x02 (Mouse), iIface=0
        9, 4, 0, 0, 1, 0x03, 0x01, 0x02, 0,
        // ENDPOINT: 7, 5, addr=0x82 (IN ep2), attr=0x03 (interrupt),
        // wMaxPacketSize=4, bInterval=10
        7, 5, 0x82, 0x03, 4, 0x00, 10,
    ];
    let (iface, ep) = match mouse::find_boot_mouse(&cfg) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("find_boot_mouse rejected HID blob"),
    };
    if iface != 0
        || ep.kind != EndpointKind::InterruptIn
        || ep.ep_addr != 0x82
        || ep.max_packet != 4
    {
        return TestResult::Fail("HID mouse endpoint mis-decoded");
    }
    // Decode a 3-byte report: left button + (-2, +5).
    let r = mouse::MouseReport::from_bytes(&[mouse::btn::LEFT, (-2i8) as u8, 5]);
    if r.buttons != mouse::btn::LEFT || r.dx != -2 || r.dy != 5 {
        return TestResult::Fail("MouseReport::from_bytes mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_boot_mouse_parse);

fn smoke_hid_boot_mouse_translate_diff() -> TestResult {
    use crate::hid::mouse::{self, boot_mouse_evdev_caps, BootMouse, MouseReport};
    use narf_input::{
        __reset_global_ring_for_test, evdev::ROUTER, init_global_ring, pop_global, InputEvent,
        PointerButtons,
    };

    init_global_ring(64);
    __reset_global_ring_for_test();
    let (evdev_id, evdev_node) = ROUTER.register_device(boot_mouse_evdev_caps());
    let mut m = BootMouse {
        slot_id: 1,
        interrupt_in_ep: 3,
        interface_num: 0,
        hub_port: None,
        last_buttons: 0,
        evdev_id,
        evdev_node,
    };

    // Idle report → no event.
    if m.translate_report(MouseReport::default()) != 0 {
        return TestResult::Fail("idle report should not emit");
    }

    // Movement only → one PointerEvent with no buttons.
    let n = m.translate_report(MouseReport {
        buttons: 0,
        dx: 7,
        dy: -3,
    });
    if n != 1 {
        return TestResult::Fail("movement should emit one event");
    }
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 7 || p.dy != -3 || p.buttons != PointerButtons::EMPTY {
                return TestResult::Fail("movement event shape wrong");
            }
        }
        _ => return TestResult::Fail("expected Pointer event for movement"),
    }

    // Button press only → one event, buttons=LEFT.
    let n = m.translate_report(MouseReport {
        buttons: mouse::btn::LEFT,
        dx: 0,
        dy: 0,
    });
    if n != 1 {
        return TestResult::Fail("button press should emit");
    }
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if !(p.buttons.contains(PointerButtons::LEFT) && p.dx == 0 && p.dy == 0) {
                return TestResult::Fail("press event shape wrong");
            }
        }
        _ => return TestResult::Fail("expected Pointer event for press"),
    }

    // Same buttons + zero delta → no event (held).
    if m.translate_report(MouseReport {
        buttons: mouse::btn::LEFT,
        dx: 0,
        dy: 0,
    }) != 0
    {
        return TestResult::Fail("held button + no delta must be silent");
    }

    // Release → one event, buttons cleared.
    let n = m.translate_report(MouseReport::default());
    if n != 1 {
        return TestResult::Fail("button release should emit");
    }
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.buttons != PointerButtons::EMPTY {
                return TestResult::Fail("release event must clear buttons");
            }
        }
        _ => return TestResult::Fail("expected Pointer event for release"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_boot_mouse_translate_diff);

// ── EHCI / OHCI / UHCI codec smokes ───────────────────────────────

fn smoke_ehci_capability_block_decodes() -> TestResult {
    use crate::ehci::{synth_cap_block, CapabilityRegs, HccParams, HcsParams};
    // 6 ports, ppc=1, no PPC routing rules, 0 companion controllers,
    // version 1.0; 64-bit cap, programmable framelist, EECP at 0x68.
    let hcs = HcsParams(0x0000_0016); // n_ports=6, ppc bit set
    let hcc = HccParams(0x0000_6803); // 64-bit + progframelist + EECP=0x68
    let blob = synth_cap_block(0x20, 0x0100, hcs, hcc);
    let cap = CapabilityRegs::decode(&blob).expect("decode");
    if cap.cap_length != 0x20 || cap.hci_version != 0x0100 {
        return TestResult::Fail("cap header wrong");
    }
    if cap.hcs_params.n_ports() != 6 || !cap.hcs_params.ppc() {
        return TestResult::Fail("HCSPARAMS wrong");
    }
    if !cap.hcc_params.addr64()
        || !cap.hcc_params.programmable_framelist()
        || cap.hcc_params.eecp() != 0x68
    {
        return TestResult::Fail("HCCPARAMS wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ehci", smoke_ehci_capability_block_decodes);

fn smoke_ehci_qtd_pack_unpack_round_trip() -> TestResult {
    use crate::ehci::{qtd_status, Qtd, QtdPid};
    let q = Qtd {
        next: 0x1000_2000,
        next_terminate: false,
        alt_next: 0,
        alt_next_terminate: true,
        status: qtd_status::ACTIVE,
        pid: QtdPid::In,
        err_count: 3,
        page_index: 0,
        ioc: true,
        total_bytes: 64,
        data_toggle: true,
        buffer_pages: [0xAAAA_0000, 0xBBBB_0000, 0, 0, 0],
    };
    let packed = q.pack();
    let r = Qtd::unpack(&packed);
    if r != q {
        return TestResult::Fail("Qtd round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ehci", smoke_ehci_qtd_pack_unpack_round_trip);

fn smoke_ehci_qh_endpoint_info_round_trip() -> TestResult {
    use crate::ehci::{QhEndpointInfo, Speed};
    let info = QhEndpointInfo {
        device_addr: 0x05,
        inactivate: false,
        endpoint: 1,
        speed: Speed::High,
        data_toggle_ctrl: false,
        head_of_list: true,
        max_packet: 512,
        control_ep: false,
        nak_count_reload: 4,
    };
    let v = info.pack();
    let r = QhEndpointInfo::unpack(v);
    if r != info {
        return TestResult::Fail("QhEndpointInfo round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ehci", smoke_ehci_qh_endpoint_info_round_trip);

fn smoke_ehci_qtd_halt_reason_decoded() -> TestResult {
    use crate::ehci::{qtd_halt_reason, qtd_status};
    if qtd_halt_reason(qtd_status::ACTIVE).is_some() {
        return TestResult::Fail("active qtd shouldn't have a halt reason");
    }
    let reason = qtd_halt_reason(qtd_status::HALTED | qtd_status::DATA_BUFFER_ERROR);
    if reason != Some("data buffer error") {
        return TestResult::Fail("halt reason mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ehci", smoke_ehci_qtd_halt_reason_decoded);

fn smoke_ehci_portsc_low_speed_release_to_companion() -> TestResult {
    use crate::ehci::PortSc;
    // Line status K-state means a low-speed device just connected
    // and the EHCI driver should hand off to the companion.
    let p = PortSc(PortSc::CURRENT_CONNECT_STATUS | (0b01 << 10));
    if !p.is_low_speed_at_reset() {
        return TestResult::Fail("low-speed line state not detected");
    }
    let q = PortSc(PortSc::CURRENT_CONNECT_STATUS | (0b10 << 10));
    if q.is_low_speed_at_reset() {
        return TestResult::Fail("J-state mis-classified as low-speed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/ehci",
    smoke_ehci_portsc_low_speed_release_to_companion
);

// ── OHCI ──────────────────────────────────────────────────────────

fn smoke_ohci_hccontrol_state_round_trip() -> TestResult {
    use crate::ohci::{HcControl, Hcfs};
    let c = HcControl(0).with_hcfs(Hcfs::Operational);
    if c.hcfs() != Hcfs::Operational {
        return TestResult::Fail("HCFS round-trip failed");
    }
    let c = c.with_hcfs(Hcfs::Suspend);
    if c.hcfs() != Hcfs::Suspend {
        return TestResult::Fail("HCFS suspend round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ohci", smoke_ohci_hccontrol_state_round_trip);

fn smoke_ohci_ed_round_trip() -> TestResult {
    use crate::ohci::{Ed, EdDir, EdSpeed};
    let e = Ed {
        fa: 5,
        en: 2,
        dir: EdDir::In,
        speed: EdSpeed::Full,
        skip: false,
        format_iso: false,
        max_packet: 64,
        tail_pointer: 0x1000_0000,
        head_pointer: 0x2000_0000,
        head_halted: true,
        head_toggle_carry: false,
        next_ed: 0x3000_0000,
    };
    let r = Ed::unpack(&e.pack());
    if r != e {
        return TestResult::Fail("Ed round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ohci", smoke_ohci_ed_round_trip);

fn smoke_ohci_general_td_completion_code_decodes() -> TestResult {
    use crate::ohci::{CompletionCode, GeneralTd, TdPid};
    let t = GeneralTd {
        buffer_rounding: true,
        pid: TdPid::Setup,
        delay_interrupt: 7,
        data_toggle: 0b10,
        error_count: 0,
        condition_code: CompletionCode::Stall,
        current_buffer_pointer: 0x4000_0000,
        next_td: 0x5000_0010,
        buffer_end: 0x4000_0040,
    };
    let r = GeneralTd::unpack(&t.pack());
    if r != t {
        return TestResult::Fail("GeneralTd round-trip failed");
    }
    if r.condition_code != CompletionCode::Stall {
        return TestResult::Fail("Stall completion code lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/ohci",
    smoke_ohci_general_td_completion_code_decodes
);

fn smoke_ohci_hcca_status_extracted() -> TestResult {
    use crate::ohci::{hcca, read_hcca_status, HCCA_SIZE};
    let mut blob = alloc::vec![0u8; HCCA_SIZE];
    blob[hcca::FRAME_NUMBER_OFFSET] = 0x34;
    blob[hcca::FRAME_NUMBER_OFFSET + 1] = 0x12;
    let done = 0xCAFE_C0D0u32;
    blob[hcca::DONE_HEAD_OFFSET..hcca::DONE_HEAD_OFFSET + 4].copy_from_slice(&done.to_le_bytes());
    let (frame, dh) = read_hcca_status(&blob).expect("read");
    if frame != 0x1234 || dh != (done & 0xFFFF_FFF0) {
        return TestResult::Fail("HCCA status decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ohci", smoke_ohci_hcca_status_extracted);

// ── UHCI ──────────────────────────────────────────────────────────

fn smoke_uhci_frame_list_pointer_flags() -> TestResult {
    use crate::uhci::FrameListPtr;
    let p = FrameListPtr::make(0xDEAD_BEE0, true);
    if !p.is_qh() || p.terminate() || p.ptr() != 0xDEAD_BEE0 {
        return TestResult::Fail("QH frame-list pointer mis-encoded");
    }
    let t = FrameListPtr::make_terminate();
    if !t.terminate() {
        return TestResult::Fail("terminate pointer should set bit 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uhci", smoke_uhci_frame_list_pointer_flags);

fn smoke_uhci_td_round_trip() -> TestResult {
    use crate::uhci::{td_status, FrameListPtr, Td, TdPid};
    let t = Td {
        link: FrameListPtr::make(0x1000_0000, true),
        actual_length: 0x12,
        status: td_status::ACTIVE,
        interrupt_on_completion: true,
        iso: false,
        low_speed: true,
        error_count: 3,
        short_packet_detect: true,
        pid: TdPid::Setup,
        device_addr: 0x12,
        endpoint: 4,
        data_toggle: true,
        max_len: 7,
        buffer: 0xCAFE_BABE,
    };
    let r = Td::unpack(&t.pack());
    if r != t {
        return TestResult::Fail("UHCI Td round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uhci", smoke_uhci_td_round_trip);

fn smoke_uhci_qh_round_trip() -> TestResult {
    use crate::uhci::{FrameListPtr, Qh};
    let q = Qh {
        link: FrameListPtr::make(0xAABB_CCD0, true),
        element: FrameListPtr::make_terminate(),
    };
    let r = Qh::unpack(&q.pack());
    if r != q {
        return TestResult::Fail("UHCI Qh round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uhci", smoke_uhci_qh_round_trip);

fn smoke_uhci_frame_list_full_population() -> TestResult {
    use crate::uhci::{make_frame_list_pointing_to, FrameListPtr};
    let list = make_frame_list_pointing_to(0xCAFE_C0D0);
    if list.len() != 1024 {
        return TestResult::Fail("Frame list must have 1024 entries");
    }
    let p = FrameListPtr(list[0]);
    if p.ptr() != 0xCAFE_C0D0 || !p.is_qh() || p.terminate() {
        return TestResult::Fail("Frame list entry shape wrong");
    }
    if list.iter().any(|&v| v != list[0]) {
        return TestResult::Fail("Frame list should be uniform");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uhci", smoke_uhci_frame_list_full_population);

fn smoke_hid_boot_mouse_button_mask() -> TestResult {
    use crate::hid::mouse;
    use narf_input::PointerButtons;
    let m = mouse::button_byte_to_buttons(mouse::btn::LEFT | mouse::btn::MIDDLE);
    if !(m.contains(PointerButtons::LEFT)
        && m.contains(PointerButtons::MIDDLE)
        && !m.contains(PointerButtons::RIGHT))
    {
        return TestResult::Fail("button byte → buttons mapping wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_boot_mouse_button_mask);

// ── xhci sibling-port pairing (USB2 ↔ USB3) ──────────────────────

fn smoke_xhci_sibling_port_pairs_within_overlap() -> TestResult {
    // Two synthetic Supported Protocol caps: USB2 covers ports 1..=4,
    // USB3 covers ports 5..=8. Range-relative index pairs them so
    // sibling_port(1) == 5, sibling_port(2) == 6, etc., and
    // sibling_port(5) == 1, sibling_port(6) == 2, etc.
    use crate::xhci;
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    // We can't construct a synthetic controller easily; just confirm
    // that on the live controller every USB3 port with a non-zero
    // sibling has a sibling that's marked USB2 (and vice versa),
    // proving the table is self-consistent.
    let max = xhci::with_controller(|c| {
        c.connected_ports()
            .iter()
            .map(|(p, _)| *p)
            .max()
            .unwrap_or(0)
    })
    .unwrap_or(0);
    if max == 0 {
        return TestResult::Skip("no connected port to walk");
    }
    let consistent = xhci::with_controller(|c| {
        for p in 1..=max {
            let sib = c.sibling_port(p);
            if sib == 0 {
                continue;
            }
            let p_proto = c.port_protocol(p);
            let s_proto = c.port_protocol(sib);
            if !((p_proto == 2 && s_proto == 3) || (p_proto == 3 && s_proto == 2)) {
                return false;
            }
            // Symmetry: sibling of sibling is self.
            if c.sibling_port(sib) != p {
                return false;
            }
        }
        true
    })
    .unwrap_or(false);
    if consistent {
        TestResult::Pass
    } else {
        TestResult::Fail("sibling table not USB2↔USB3 symmetric")
    }
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_sibling_port_pairs_within_overlap
);

fn smoke_xhci_sibling_port_zero_when_no_sibling() -> TestResult {
    // sibling_port for port 0 (sentinel) and port > max_ports is 0.
    use crate::xhci;
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    let result = xhci::with_controller(|c| c.sibling_port(0) == 0 && c.sibling_port(255) == 0)
        .unwrap_or(false);
    if result {
        TestResult::Pass
    } else {
        TestResult::Fail("out-of-range sibling_port returned non-zero")
    }
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_sibling_port_zero_when_no_sibling
);

// ── drivers/usb/class-detection ────────────────────────────────────
//
// Build a minimal config descriptor with a single interface
// descriptor carrying the target class triple, then verify each
// class's finder picks it up. Doesn't run the full bind path
// (that needs an Xhci instance) — just the descriptor walker.

/// Build a 9-byte config header + a 9-byte interface descriptor
/// with the given class triple.
fn build_cfg_with_class(
    class: u8,
    subclass: u8,
    protocol: u8,
    iface_num: u8,
) -> alloc::vec::Vec<u8> {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    // CONFIG descriptor: 9 bytes.
    v.extend_from_slice(&[
        9, 0x02, // bLength, bDescriptorType=CONFIG
        18, 0, // wTotalLength = 18 (9 cfg + 9 iface)
        1, // bNumInterfaces
        1, // bConfigurationValue
        0, 0xC0, 50,
    ]);
    // INTERFACE descriptor: 9 bytes.
    v.extend_from_slice(&[
        9, 0x04, // bLength, bDescriptorType=INTERFACE
        iface_num, 0, // bAlternateSetting
        0, // bNumEndpoints
        class, subclass, protocol, 0, // iInterface
    ]);
    v
}

/// Class-only registry entries must inspect interface descriptors. In
/// particular, the WCN6855's Wireless/RF/Bluetooth interface must never
/// fall through and be claimed as a wildcard USB-audio device when a
/// descriptor read did not produce a VID/PID.
fn smoke_usb_class_registry_checks_interface_triples() -> TestResult {
    use crate::class_registry::{match_entry, UsbClassMatch};

    let audio = UsbClassMatch::class_only(0x01);
    let qca_bt = build_cfg_with_class(0xE0, 0x01, 0x01, 0);
    if match_entry(&audio, 0, 0, &qca_bt) {
        return TestResult::Fail("USB-audio wildcard matched Bluetooth interface");
    }

    let audio_cfg = build_cfg_with_class(0x01, 0x01, 0x00, 3);
    if !match_entry(&audio, 0x1234, 0x5678, &audio_cfg) {
        return TestResult::Fail("USB-audio class match missed AudioControl interface");
    }

    let qca = UsbClassMatch::vid_pid(0x10ab, 0x9309);
    if !match_entry(&qca, 0x10ab, 0x9309, &qca_bt) {
        return TestResult::Fail("exact WCN6855 VID/PID match missed");
    }
    if match_entry(&qca, 0, 0, &qca_bt) {
        return TestResult::Fail("exact WCN6855 VID/PID match became wildcard");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/class-registry",
    smoke_usb_class_registry_checks_interface_triples
);

// ── drivers/usb/class-registry unbind dispatch ────────────────────
//
// The disconnect lifecycle (attach::detach_slot) reaches registered
// class drivers through dispatch_unbind. The hook is broadcast:
// every registered hook sees the slot and self-filters. This test
// registers a hook for an unmatchable VID/PID (its probe can never
// fire for a real device) and deliberately leaves it registered —
// resetting the global registry would wipe drivers registered by
// the boot initcalls for later smokes.

static UNBIND_HOOK_LAST_SLOT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static UNBIND_HOOK_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static UNBIND_TEST_MATCHES: [crate::class_registry::UsbClassMatch; 1] =
    [crate::class_registry::UsbClassMatch::vid_pid(
        0xFFFE, 0xFFFE,
    )];

fn unbind_hook_record(slot: u8) -> Result<(), ()> {
    UNBIND_HOOK_LAST_SLOT.store(slot, core::sync::atomic::Ordering::SeqCst);
    UNBIND_HOOK_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

fn unbind_test_probe(
    _dev: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    Err(crate::class_registry::UsbProbeError::UnsupportedVariant)
}

fn smoke_usb_class_registry_unbind_dispatch() -> TestResult {
    use crate::class_registry::{dispatch_unbind, register_class_driver_with_unbind};
    if register_class_driver_with_unbind(
        "test-unbind-hook",
        &UNBIND_TEST_MATCHES,
        unbind_test_probe,
        unbind_hook_record,
    )
    .is_err()
    {
        return TestResult::Fail("hooked driver registration failed");
    }
    let before = UNBIND_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst);
    let report = dispatch_unbind(9);
    if report.invoked == 0 {
        return TestResult::Fail("dispatch_unbind invoked no hooks");
    }
    if UNBIND_HOOK_LAST_SLOT.load(core::sync::atomic::Ordering::SeqCst) != 9 {
        return TestResult::Fail("unbind hook did not receive the detached slot");
    }
    if UNBIND_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst) != before + 1 {
        return TestResult::Fail("unbind hook was not called exactly once per dispatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/class-registry",
    smoke_usb_class_registry_unbind_dispatch
);

static UNBIND_FAIL_HOOK_CALLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static UNBIND_OK_HOOK_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Failing hook for the isolation test: fails ONLY for the
/// sentinel slot 0xEE, so other dispatches (and other tests'
/// hooks) are unaffected and the failure count is exact.
fn unbind_hook_fail_sentinel(slot: u8) -> Result<(), ()> {
    UNBIND_FAIL_HOOK_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if slot == 0xEE {
        Err(())
    } else {
        Ok(())
    }
}

fn unbind_hook_ok_record(slot: u8) -> Result<(), ()> {
    let _ = slot;
    UNBIND_OK_HOOK_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// #893 regression: one failing unbind hook must not abort
/// dispatch for the remaining hooks. The failing hook is
/// registered BEFORE the ok hook; after `dispatch_unbind(0xEE)`
/// both must have run exactly once more and the report must
/// count exactly one failure. (A panicking hook cannot be
/// tested this way — panic is fatal by kernel policy, see
/// `UsbUnbindFn` — so the contract under test is the
/// reported-failure path.)
fn smoke_usb_class_registry_unbind_isolation() -> TestResult {
    use crate::class_registry::{dispatch_unbind, register_class_driver_with_unbind};
    if register_class_driver_with_unbind(
        "test-unbind-fail",
        &UNBIND_TEST_MATCHES,
        unbind_test_probe,
        unbind_hook_fail_sentinel,
    )
    .is_err()
    {
        return TestResult::Fail("failing-hook registration failed");
    }
    if register_class_driver_with_unbind(
        "test-unbind-ok",
        &UNBIND_TEST_MATCHES,
        unbind_test_probe,
        unbind_hook_ok_record,
    )
    .is_err()
    {
        return TestResult::Fail("ok-hook registration failed");
    }
    let fail_before = UNBIND_FAIL_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst);
    let ok_before = UNBIND_OK_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst);
    let report = dispatch_unbind(0xEE);
    if UNBIND_FAIL_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst) != fail_before + 1 {
        return TestResult::Fail("failing hook was not called exactly once");
    }
    if UNBIND_OK_HOOK_CALLS.load(core::sync::atomic::Ordering::SeqCst) != ok_before + 1 {
        return TestResult::Fail("dispatch stopped after the failing hook");
    }
    if report.failed != 1 {
        return TestResult::Fail("dispatch did not count exactly one failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/class-registry",
    smoke_usb_class_registry_unbind_isolation
);

fn smoke_usb_uac_finder_picks_audiocontrol_interface() -> TestResult {
    use crate::uac::{
        find_audio_control_interface, USB_AUDIO_SUBCLASS_AUDIOCONTROL, USB_CLASS_AUDIO,
    };
    // Audio / AudioControl on interface number 7.
    let cfg = build_cfg_with_class(USB_CLASS_AUDIO, USB_AUDIO_SUBCLASS_AUDIOCONTROL, 0, 7);
    if find_audio_control_interface(&cfg) != Some(7) {
        return TestResult::Fail("AC interface not found at expected iface_num");
    }
    // Non-audio device → None.
    let cfg2 = build_cfg_with_class(0x08, 0x06, 0x50, 0); // MSC
    if find_audio_control_interface(&cfg2).is_some() {
        return TestResult::Fail("MSC config must NOT match AC finder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_usb_uac_finder_picks_audiocontrol_interface
);

fn smoke_usb_uvc_finder_picks_videocontrol_interface() -> TestResult {
    use crate::uvc::{
        find_video_control_interface, USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOCONTROL,
    };
    let cfg = build_cfg_with_class(USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOCONTROL, 0, 3);
    if find_video_control_interface(&cfg) != Some(3) {
        return TestResult::Fail("VC interface not found at expected iface_num");
    }
    // Audio config should NOT match.
    let cfg2 = build_cfg_with_class(0x01, 0x01, 0, 0);
    if find_video_control_interface(&cfg2).is_some() {
        return TestResult::Fail("audio config must NOT match VC finder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_finder_picks_videocontrol_interface
);

fn smoke_usb_cdc_ncm_finder_picks_comm_ncm_interface() -> TestResult {
    use crate::cdc::{CDC_SUBCLASS_NCM, USB_CLASS_CDC_COMM};
    use crate::cdc_ncm::find_ncm_comm_interface;
    let cfg = build_cfg_with_class(USB_CLASS_CDC_COMM, CDC_SUBCLASS_NCM, 0, 11);
    if find_ncm_comm_interface(&cfg) != Some(11) {
        return TestResult::Fail("NCM Comm interface not found");
    }
    // CDC-ACM (subclass 0x02) on CDC-Comm class must NOT match NCM finder.
    let cfg2 = build_cfg_with_class(USB_CLASS_CDC_COMM, 0x02, 0x01, 0);
    if find_ncm_comm_interface(&cfg2).is_some() {
        return TestResult::Fail("CDC-ACM config must NOT match NCM finder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/cdc_ncm",
    smoke_usb_cdc_ncm_finder_picks_comm_ncm_interface
);

// ── drivers/usb/hub (port suspend constants) ───────────────────────

fn smoke_usb_hub_port_suspend_constants_distinct() -> TestResult {
    use crate::hub::{
        C_PORT_CONNECTION, C_PORT_RESET, C_PORT_SUSPEND, PORT_RESET, PORT_SUSPEND, PSTAT_SUSPEND,
    };
    // Distinct feature codes — silent collision would suspend
    // when we meant to reset.
    if PORT_SUSPEND == PORT_RESET {
        return TestResult::Fail("PORT_SUSPEND must differ from PORT_RESET");
    }
    if C_PORT_SUSPEND == C_PORT_CONNECTION || C_PORT_SUSPEND == C_PORT_RESET {
        return TestResult::Fail("C_PORT_SUSPEND must be distinct change-code");
    }
    // PSTAT_SUSPEND is bit 2 per USB 2.0 §11.24.2.7.1 table 11-15.
    if PSTAT_SUSPEND != 1 << 2 {
        return TestResult::Fail("PSTAT_SUSPEND must be bit 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_usb_hub_port_suspend_constants_distinct
);

fn smoke_usb_attach_idle_suspend_threshold_is_30s() -> TestResult {
    use crate::attach::IDLE_SUSPEND_NS;
    if IDLE_SUSPEND_NS != 30 * 1_000_000_000 {
        return TestResult::Fail("IDLE_SUSPEND_NS drifted from 30 s");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/attach",
    smoke_usb_attach_idle_suspend_threshold_is_30s
);

// ── drivers/usb/cdc_ncm (Data interface + bulk endpoints) ──────────

fn smoke_usb_cdc_ncm_finder_picks_bulk_pair_under_data_iface() -> TestResult {
    use crate::cdc::{CDC_SUBCLASS_NCM, USB_CLASS_CDC_COMM, USB_CLASS_CDC_DATA};
    use crate::cdc_ncm::find_ncm_bulk_endpoints;
    use crate::xhci::EndpointKind;
    // Compose:
    //   CONFIG (9 bytes)
    //   COMM iface (class 0x02 sub 0x0D) — interface 0, 0 endpoints
    //   DATA iface (class 0x0A)          — interface 1
    //   ENDPOINT bulk OUT (ep 0x01, MPS 512)
    //   ENDPOINT bulk IN  (ep 0x82, MPS 512)
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    v.extend_from_slice(&[9, 0x02, 23 + 9 + 9 + 7 + 7 - 36, 0, 2, 1, 0, 0xC0, 50]);
    // Adjust wTotalLength to actual computed bytes.
    let total = 9 + 9 + 9 + 7 + 7;
    v[2] = (total & 0xFF) as u8;
    v[3] = (total >> 8) as u8;
    // COMM interface.
    v.extend_from_slice(&[9, 0x04, 0, 0, 0, USB_CLASS_CDC_COMM, CDC_SUBCLASS_NCM, 0, 0]);
    // DATA interface.
    v.extend_from_slice(&[9, 0x04, 1, 0, 2, USB_CLASS_CDC_DATA, 0, 0, 0]);
    // Bulk OUT endpoint, ep_addr=0x01, attrs=0x02 (bulk), MPS=512.
    v.extend_from_slice(&[7, 0x05, 0x01, 0x02, 0x00, 0x02, 0]);
    // Bulk IN endpoint, ep_addr=0x82.
    v.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x00, 0x02, 0]);

    let (iface, bulk_in, bulk_out) = match find_ncm_bulk_endpoints(&v) {
        Some(t) => t,
        None => return TestResult::Fail("bulk pair not found"),
    };
    if iface != 1 {
        return TestResult::Fail("Data iface number wrong");
    }
    if bulk_in.ep_addr != 0x82 || !matches!(bulk_in.kind, EndpointKind::BulkIn) {
        return TestResult::Fail("bulk_in not detected");
    }
    if bulk_out.ep_addr != 0x01 || !matches!(bulk_out.kind, EndpointKind::BulkOut) {
        return TestResult::Fail("bulk_out not detected");
    }
    if bulk_in.max_packet != 512 || bulk_out.max_packet != 512 {
        return TestResult::Fail("MPS not preserved");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/cdc_ncm",
    smoke_usb_cdc_ncm_finder_picks_bulk_pair_under_data_iface
);

// ── drivers/usb/uvc (payload header + Probe/Commit + reassembler) ──

fn smoke_usb_uvc_payload_header_decodes_pts_and_eof() -> TestResult {
    use crate::uvc::{bfh, UvcPayloadHeader};
    // 6-byte header: length=6, BFH = EOH|EOF|PTS, PTS=0x12345678.
    let buf = [
        6,
        bfh::EOH | bfh::EOF | bfh::PTS,
        0x78,
        0x56,
        0x34,
        0x12,
        // payload bytes follow — not in the header itself
        0xAA,
        0xBB,
    ];
    let h = match UvcPayloadHeader::parse(&buf) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("parse rejected valid header"),
    };
    if h.length != 6 {
        return TestResult::Fail("length not preserved");
    }
    if !h.is_eof() {
        return TestResult::Fail("EOF bit not detected");
    }
    if h.is_error() {
        return TestResult::Fail("ERR falsely detected");
    }
    if h.pts != Some(0x1234_5678) {
        return TestResult::Fail("PTS decode wrong");
    }
    if h.scr.is_some() {
        return TestResult::Fail("SCR must be None when bit clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_payload_header_decodes_pts_and_eof
);

fn smoke_usb_uvc_payload_header_rejects_truncated() -> TestResult {
    use crate::uvc::{bfh, UvcError, UvcPayloadHeader};
    // BFH says PTS|SCR (4+6 bytes follow) but length=2 means none of
    // those bytes are inside the declared header → Truncated.
    let buf = [2, bfh::EOH | bfh::PTS | bfh::SCR];
    match UvcPayloadHeader::parse(&buf) {
        Err(UvcError::Truncated) => TestResult::Pass,
        Ok(_) => TestResult::Fail("PTS+SCR with length=2 must reject"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_payload_header_rejects_truncated
);

fn smoke_usb_uvc_probe_commit_round_trip() -> TestResult {
    use crate::uvc::VsProbeCommit;
    let src = VsProbeCommit {
        hint: 0x0001,
        format_index: 1,
        frame_index: 3,
        frame_interval: 333_333, // 30 fps
        max_video_frame_size: 1280 * 720 * 2,
        max_payload_transfer_size: 1024,
        ..Default::default()
    };
    let bytes = src.encode_v10();
    if bytes.len() != VsProbeCommit::LEN_V10 {
        return TestResult::Fail("encoded length wrong");
    }
    let back = VsProbeCommit::decode(&bytes).expect("decode");
    if back != src {
        return TestResult::Fail("round-trip lost fields");
    }
    // 30 fps confirmation: 100ns units, so 333333 ≈ 30 fps.
    if back.frame_interval != 333_333 {
        return TestResult::Fail("frame_interval lost");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_usb_uvc_probe_commit_round_trip);

fn smoke_usb_uvc_probe_commit_v15_wire_frame() -> TestResult {
    use crate::uvc::VsProbeCommit;
    let src = VsProbeCommit {
        hint: 0x0001,
        format_index: 1,
        frame_index: 1,
        frame_interval: 333_333,
        key_frame_rate: 30,
        max_video_frame_size: 614_400,
        max_payload_transfer_size: 1024,
        clock_frequency: 48_000_000,
        framing_info: 0,
        preferred_version: 0x10,
        min_version: 0x10,
        max_version: 0x10,
        ..Default::default()
    };
    let bytes = src.encode_v15();
    // Pinned byte-for-byte: the 26-byte 1.0 block, then the clock LE
    // at [26..30] (48_000_000 = 0x02DC6C00), then framing/versions.
    let mut expect = [0u8; 34];
    expect[0..2].copy_from_slice(&0x0001u16.to_le_bytes());
    expect[2] = 1;
    expect[3] = 1;
    expect[4..8].copy_from_slice(&333_333u32.to_le_bytes());
    expect[8..10].copy_from_slice(&30u16.to_le_bytes());
    expect[18..22].copy_from_slice(&614_400u32.to_le_bytes());
    expect[22..26].copy_from_slice(&1024u32.to_le_bytes());
    expect[26..30].copy_from_slice(&48_000_000u32.to_le_bytes());
    expect[30] = 0;
    expect[31] = 0x10;
    expect[32] = 0x10;
    expect[33] = 0x10;
    if bytes != expect {
        return TestResult::Fail("34-byte wire frame mismatch");
    }
    let back = VsProbeCommit::decode(&bytes).expect("decode");
    if back != src {
        return TestResult::Fail("34-byte round-trip lost fields");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_usb_uvc_probe_commit_v15_wire_frame);

fn smoke_usb_uvc_probe_commit_v10_decode_zeroes_v15() -> TestResult {
    use crate::uvc::VsProbeCommit;
    let src = VsProbeCommit {
        hint: 1,
        format_index: 1,
        frame_index: 1,
        frame_interval: 333_333,
        ..Default::default()
    };
    let back = VsProbeCommit::decode(&src.encode_v10()).expect("decode");
    if back.clock_frequency != 0
        || back.framing_info != 0
        || back.preferred_version != 0
        || back.min_version != 0
        || back.max_version != 0
    {
        return TestResult::Fail("26-byte decode must zero the 1.1+ fields");
    }
    if back != src {
        return TestResult::Fail("26-byte round-trip lost fields");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_probe_commit_v10_decode_zeroes_v15
);

fn smoke_usb_uvc_probe_commit_len_for() -> TestResult {
    use crate::uvc::VsProbeCommit;
    if VsProbeCommit::len_for(0x0100) != 26
        || VsProbeCommit::len_for(0x0109) != 26
        || VsProbeCommit::len_for(0x0110) != 34
        || VsProbeCommit::len_for(0x0150) != 34
    {
        return TestResult::Fail("len_for gate wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_usb_uvc_probe_commit_len_for);

fn smoke_uvc_streamon_v15_negotiation() -> TestResult {
    narf_drivers_video::devfs_bridge::__reset_for_test();
    crate::uvc::__reset_uvc_for_test();
    let transport = Arc::new(FixtureTransport::new(
        false,
        false,
        uvc_fixture_frame_packets(),
    ));
    // The modelled 1.5 device's VC HEADER clock (48 MHz) deliberately
    // differs from the 1.0 fixture's 4.68 MHz: the PROBE clock must
    // come from the bound device's header, not a constant.
    transport.set_clock(48_000_000);
    let blob = uvc_fixture_config_blob_versioned(0x0150, 48_000_000);
    let idx = match narf_scheduler::block_on(crate::uvc::try_bind_video_with_transport(
        &*transport,
        7,
        &blob,
    )) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("bind against the modelled 1.5 camera failed"),
    };
    // Drive the production desired-construction path, not a
    // hand-built payload.
    let desired = {
        let devices = crate::uvc::UVC_DEVICES.lock();
        let device = match devices.get(idx) {
            Some(d) => d,
            None => return TestResult::Fail("bound device missing"),
        };
        if device.uvc_version != 0x0150 || device.clock_frequency != 48_000_000 {
            return TestResult::Fail("bind should record bcdUVC + VC clock");
        }
        let format = narf_drivers_video::v4l2_ioctl::PixFormat {
            width: 640,
            height: 480,
            fourcc: u32::from_le_bytes(*b"YUYV"),
        };
        match crate::uvc::desired_probe_commit(device, format) {
            Some(d) => d,
            None => return TestResult::Fail("desired_probe_commit failed"),
        }
    };
    let negotiated = match narf_scheduler::block_on(
        crate::uvc::negotiate_and_activate_video_stream_with(&*transport, idx, desired),
    ) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("1.5 negotiation failed"),
    };
    let log = transport.log();
    let probe = match log.iter().find_map(|x| match x {
        FixtureXfer::SetCurProbe { payload } => Some(payload.clone()),
        _ => None,
    }) {
        Some(p) => p,
        None => return TestResult::Fail("no SET_CUR(PROBE) logged"),
    };
    if probe.len() != 34 {
        return TestResult::Fail("SET_CUR(PROBE) to a 1.5 device must be 34 bytes");
    }
    if u32::from_le_bytes(probe[26..30].try_into().unwrap()) != 48_000_000 {
        return TestResult::Fail("PROBE clock must be the VC HEADER clock");
    }
    if probe[31] != 0x10 || probe[32] != 0x10 || probe[33] != 0x10 {
        return TestResult::Fail("PROBE must declare 1.0 payload versions");
    }
    let commit = match log.iter().find_map(|x| match x {
        FixtureXfer::SetCurCommit { payload } => Some(payload.clone()),
        _ => None,
    }) {
        Some(p) => p,
        None => return TestResult::Fail("no SET_CUR(COMMIT) logged"),
    };
    if commit.len() != 34 {
        return TestResult::Fail("SET_CUR(COMMIT) to a 1.5 device must be 34 bytes");
    }
    if u32::from_le_bytes(commit[18..22].try_into().unwrap()) != 614_400
        || u32::from_le_bytes(commit[22..26].try_into().unwrap()) != 1024
    {
        return TestResult::Fail("COMMIT must carry the device-accepted sizes");
    }
    if u32::from_le_bytes(commit[26..30].try_into().unwrap()) != 48_000_000
        || commit[31] != 0x10
        || commit[32] != 0x10
        || commit[33] != 0x10
    {
        return TestResult::Fail("COMMIT must carry the device clock + versions");
    }
    if negotiated.control.clock_frequency != 48_000_000
        || negotiated.control.max_payload_transfer_size != 1024
    {
        return TestResult::Fail("negotiated control must carry the device values");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_streamon_v15_negotiation);

fn smoke_usb_uvc_reassembler_completes_two_packet_frame() -> TestResult {
    use crate::uvc::{bfh, ReassemblerOutcome, UvcFrameReassembler};
    let mut r = UvcFrameReassembler::new();
    // Packet 1: header (length=2, BFH=EOH|FID), payload = [0xAA, 0xBB].
    let p1 = [2, bfh::EOH | bfh::FID, 0xAA, 0xBB];
    if r.push(&p1) != ReassemblerOutcome::Appended {
        return TestResult::Fail("first packet must Append");
    }
    // Packet 2: header (length=2, BFH=EOH|FID|EOF), payload = [0xCC, 0xDD].
    let p2 = [2, bfh::EOH | bfh::FID | bfh::EOF, 0xCC, 0xDD];
    if r.push(&p2) != ReassemblerOutcome::FrameComplete {
        return TestResult::Fail("second packet (EOF) must complete frame");
    }
    let frame = r.take_frame();
    if frame != alloc::vec![0xAA, 0xBB, 0xCC, 0xDD] {
        return TestResult::Fail("reassembled frame bytes wrong");
    }
    if r.frames_completed != 1 {
        return TestResult::Fail("frames_completed must be 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_reassembler_completes_two_packet_frame
);

fn smoke_usb_uvc_reassembler_drops_errored_frame() -> TestResult {
    use crate::uvc::{bfh, ReassemblerOutcome, UvcFrameReassembler};
    let mut r = UvcFrameReassembler::new();
    let p1 = [2, bfh::EOH | bfh::FID, 0xAA];
    r.push(&p1);
    // ERR set on EOF packet → reassembler must yield Errored + empty buf.
    let p2 = [2, bfh::EOH | bfh::FID | bfh::EOF | bfh::ERR, 0xBB];
    if r.push(&p2) != ReassemblerOutcome::Errored {
        return TestResult::Fail("ERR on EOF must yield Errored");
    }
    if !r.buffer.is_empty() {
        return TestResult::Fail("errored frame must clear buffer");
    }
    if r.frames_completed != 0 {
        return TestResult::Fail("errored frame must NOT increment counter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_reassembler_drops_errored_frame
);

// ── drivers/usb/uac (sample rate + PCM ring) ───────────────────────

fn smoke_usb_uac_encode_sampling_freq_48k() -> TestResult {
    use crate::uac::{decode_sampling_freq, encode_sampling_freq};
    // 48 kHz = 0x00BB80 little-endian = [0x80, 0xBB, 0x00].
    let b = encode_sampling_freq(48_000);
    if b != [0x80, 0xBB, 0x00] {
        return TestResult::Fail("48k LE bytes wrong");
    }
    // 44.1 kHz = 0x00AC44.
    let b = encode_sampling_freq(44_100);
    if b != [0x44, 0xAC, 0x00] {
        return TestResult::Fail("44.1k LE bytes wrong");
    }
    // Round-trip.
    if decode_sampling_freq(&encode_sampling_freq(96_000)) != Some(96_000) {
        return TestResult::Fail("96k round-trip wrong");
    }
    // Truncated buf.
    if decode_sampling_freq(&[0u8; 2]).is_some() {
        return TestResult::Fail("2-byte buf must yield None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_usb_uac_encode_sampling_freq_48k);

fn smoke_usb_uac_pcm_format_audio_frame_bytes() -> TestResult {
    use crate::uac::PcmFormat;
    let stereo_16 = PcmFormat {
        channels: 2,
        bytes_per_sample: 2,
        bit_depth: 16,
    };
    if stereo_16.audio_frame_bytes() != 4 {
        return TestResult::Fail("stereo/16: 2 ch * 2 bytes = 4");
    }
    if stereo_16.iso_packet_bytes(48) != 4 * 48 {
        return TestResult::Fail("iso_packet_bytes(48) wrong");
    }
    let five_one_24 = PcmFormat {
        channels: 6,
        bytes_per_sample: 4,
        bit_depth: 24,
    };
    if five_one_24.audio_frame_bytes() != 24 {
        return TestResult::Fail("5.1/24-in-32: 6 ch * 4 = 24");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_usb_uac_pcm_format_audio_frame_bytes
);

fn smoke_usb_uac_pcm_ring_push_pop_round_trip() -> TestResult {
    use crate::uac::{PcmFormat, PcmRing};
    let fmt = PcmFormat {
        channels: 2,
        bytes_per_sample: 2,
        bit_depth: 16,
    };
    let mut ring = PcmRing::new(fmt, 128);
    // Push 16 bytes (4 audio frames).
    let in_bytes: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x10,
    ];
    ring.push(&in_bytes).expect("push");
    if ring.filled() != 16 {
        return TestResult::Fail("filled mismatch after push");
    }
    let mut out = [0u8; 16];
    let n = ring.pop(&mut out).expect("pop");
    if n != 16 || out != in_bytes {
        return TestResult::Fail("pop bytes mismatch");
    }
    if ring.filled() != 0 {
        return TestResult::Fail("filled must be 0 after full drain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_usb_uac_pcm_ring_push_pop_round_trip
);

fn smoke_usb_uac_pcm_ring_misaligned_rejected() -> TestResult {
    use crate::uac::{PcmError, PcmFormat, PcmRing};
    let fmt = PcmFormat {
        channels: 2,
        bytes_per_sample: 2,
        bit_depth: 16,
    };
    let mut ring = PcmRing::new(fmt, 64);
    // 5 bytes — not a multiple of 4 (audio_frame_bytes).
    match ring.push(&[0u8; 5]) {
        Err(PcmError::Misaligned) => {}
        _ => return TestResult::Fail("misaligned push must reject"),
    }
    let mut out = [0u8; 3];
    match ring.pop(&mut out) {
        Err(PcmError::Misaligned) => TestResult::Pass,
        _ => TestResult::Fail("misaligned pop must reject"),
    }
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_usb_uac_pcm_ring_misaligned_rejected
);

fn smoke_usb_uac_pcm_ring_wraps_around() -> TestResult {
    use crate::uac::{PcmFormat, PcmRing};
    let fmt = PcmFormat {
        channels: 1,
        bytes_per_sample: 2,
        bit_depth: 16,
    };
    let mut ring = PcmRing::new(fmt, 8); // capacity = 8 bytes
                                         // Fill the ring, drain it, fill again — forces head+tail wrap.
    ring.push(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
        .expect("push 1");
    let mut tmp = [0u8; 8];
    ring.pop(&mut tmp).expect("pop 1");
    ring.push(&[0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])
        .expect("push 2 (after wrap)");
    ring.pop(&mut tmp).expect("pop 2");
    if tmp != [0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA] {
        return TestResult::Fail("wrap-around bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_usb_uac_pcm_ring_wraps_around);

// ── UAC1 required smokes (5 per spec) ─────────────────────────────
//
// These five tests directly exercise the five coverage points mandated
// by the USB Audio Class 1.0 driver spec:
//   1. AC_HEADER decode         (smoke_uac_ac_header_decodes_collection above)
//   2. INPUT_TERMINAL headphone terminal type
//   3. FEATURE_UNIT control bitmap (smoke_uac_feature_unit_decodes_per_channel_controls above)
//   4. FORMAT_TYPE_I 24-bit / 48 kHz / 2-channel
//   5. Volume SET_CUR / GET_CUR encoder (Feature Unit volume request encoding)

fn smoke_uac_input_terminal_headphone() -> TestResult {
    use crate::uac::{InputTerminal, TERMINAL_HEADPHONES};
    // 12 bytes: bLength=12, CS_INTERFACE, INPUT_TERMINAL,
    // bTerminalID=3, wTerminalType=0x0302 (headphones),
    // bAssocTerminal=0, bNrChannels=2, wChannelConfig=0x0003,
    // iChannelNames=0, iTerminal=0
    let buf = [12u8, 0x24, 0x02, 3, 0x02, 0x03, 0, 2, 0x03, 0x00, 0, 0];
    let t = InputTerminal::parse(&buf).expect("parse");
    if t.terminal_type != TERMINAL_HEADPHONES {
        return TestResult::Fail("headphone terminal type should be 0x0302");
    }
    if t.terminal_id != 3 {
        return TestResult::Fail("terminal_id mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_input_terminal_headphone);

fn smoke_uac_format_type_i_24bit_48k_stereo() -> TestResult {
    use crate::uac::{FormatTypeI, FORMAT_TYPE_I};
    // 24-bit / 48 kHz / 2-channel — a typical USB DAC or headset.
    // bLength=11, CS_INTERFACE, FORMAT_TYPE, bFormatType=TYPE_I,
    // bNrChannels=2, bSubframeSize=3 (24-bit packed in 3 bytes),
    // bBitResolution=24, bSamFreqType=1 (discrete),
    // tSamFreq[0] = 48000 Hz LE 24-bit.
    let mut buf = alloc::vec![11u8, 0x24, 0x02, FORMAT_TYPE_I, 2, 3, 24, 1];
    let hz: u32 = 48_000;
    buf.push((hz & 0xFF) as u8);
    buf.push(((hz >> 8) & 0xFF) as u8);
    buf.push(((hz >> 16) & 0xFF) as u8);
    let f = FormatTypeI::parse(&buf).expect("parse");
    if f.nr_channels != 2 {
        return TestResult::Fail("nr_channels should be 2");
    }
    if f.subframe_size != 3 {
        return TestResult::Fail("subframe_size should be 3 (24-bit packed)");
    }
    if f.bit_resolution != 24 {
        return TestResult::Fail("bit_resolution should be 24");
    }
    if f.sample_rates != alloc::vec![48_000u32] {
        return TestResult::Fail("sample_rate should be [48000]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_format_type_i_24bit_48k_stereo);

fn smoke_uac_volume_set_cur_get_cur_encode_decode() -> TestResult {
    use crate::uac::{
        decode_mute, decode_volume, encode_mute, encode_volume, fu_windex, fu_wvalue,
        CHANNEL_MASTER, FU_CS_MUTE, FU_CS_VOLUME, REQ_GET_CUR, REQ_SET_CUR,
    };

    // ── request-code round-trip ──────────────────────────────────────
    if REQ_SET_CUR != 0x01 {
        return TestResult::Fail("SET_CUR must be 0x01 (UAC1 §A.9)");
    }
    if REQ_GET_CUR != 0x81 {
        return TestResult::Fail("GET_CUR must be 0x81 (UAC1 §A.9)");
    }

    // ── wValue / wIndex helpers ──────────────────────────────────────
    // Feature unit 4, iface 0, volume master channel.
    let wv = fu_wvalue(FU_CS_VOLUME, CHANNEL_MASTER);
    if wv != ((FU_CS_VOLUME as u16) << 8) {
        return TestResult::Fail("fu_wvalue encoding wrong");
    }
    let wi = fu_windex(4, 0);
    if wi != (4u16 << 8) {
        return TestResult::Fail("fu_windex encoding wrong");
    }

    // ── volume SET_CUR payload: −6 dB = −1536 in 1/256 dB units ────
    let vol_bytes = encode_volume(-1536i16);
    // −1536 = 0xFA00 LE → [0x00, 0xFA]
    if vol_bytes != [0x00, 0xFA] {
        return TestResult::Fail("encode_volume(-1536) LE bytes wrong");
    }
    // round-trip
    match decode_volume(&vol_bytes) {
        Some(-1536) => {}
        _ => return TestResult::Fail("decode_volume round-trip for -6 dB failed"),
    }

    // ── 0 dB = 0 ────────────────────────────────────────────────────
    let unity = encode_volume(0);
    if unity != [0x00, 0x00] {
        return TestResult::Fail("0 dB should encode to [0x00, 0x00]");
    }

    // ── mute encode/decode ───────────────────────────────────────────
    let _ = fu_wvalue(FU_CS_MUTE, CHANNEL_MASTER); // reachability
    if encode_mute(true) != [1u8] {
        return TestResult::Fail("mute=true must encode to [1]");
    }
    if encode_mute(false) != [0u8] {
        return TestResult::Fail("mute=false must encode to [0]");
    }
    if decode_mute(&[1u8]) != Some(true) {
        return TestResult::Fail("decode_mute([1]) should be Some(true)");
    }
    if decode_mute(&[0u8]) != Some(false) {
        return TestResult::Fail("decode_mute([0]) should be Some(false)");
    }
    if decode_mute(&[]).is_some() {
        return TestResult::Fail("decode_mute([]) must be None");
    }
    // truncated volume
    if decode_volume(&[0u8]).is_some() {
        return TestResult::Fail("decode_volume([0]) 1-byte buf must be None");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_uac_volume_set_cur_get_cur_encode_decode
);

// ── drivers/usb/xhci (iso EP discovery + iso TRB constants) ────────
//
// xHCI iso TRB submission can't be unit-tested without a live
// controller (the bulk_in / bulk_out smokes are skip-only too on
// QEMU). The protocol-level pieces — TRB type, SIA bit, iso-EP
// finder in the config descriptor — are testable on synthetic data.

fn smoke_usb_uac_finder_picks_iso_endpoints_from_as_iface() -> TestResult {
    use crate::uac::{
        find_audio_streaming_iso_eps, USB_AUDIO_SUBCLASS_AUDIOSTREAMING, USB_CLASS_AUDIO,
    };
    // Compose a config with an AC iface (no iso EPs) + AS iface
    // (one iso OUT for playback) + AS iface alt-1 (iso IN for mic).
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    // CONFIG
    v.extend_from_slice(&[9, 0x02, 0, 0, 3, 1, 0, 0xC0, 50]);
    // AC iface
    v.extend_from_slice(&[9, 0x04, 0, 0, 0, USB_CLASS_AUDIO, 0x01, 0, 0]);
    // AS iface 1
    v.extend_from_slice(&[
        9,
        0x04,
        1,
        0,
        1,
        USB_CLASS_AUDIO,
        USB_AUDIO_SUBCLASS_AUDIOSTREAMING,
        0,
        0,
    ]);
    // iso OUT endpoint 0x03, attrs=0x01 (iso, asynch).
    v.extend_from_slice(&[7, 0x05, 0x03, 0x01, 0x00, 0x01, 1]);
    // AS iface 2 (capture)
    v.extend_from_slice(&[
        9,
        0x04,
        2,
        0,
        1,
        USB_CLASS_AUDIO,
        USB_AUDIO_SUBCLASS_AUDIOSTREAMING,
        0,
        0,
    ]);
    // iso IN endpoint 0x82, attrs=0x01.
    v.extend_from_slice(&[7, 0x05, 0x82, 0x01, 0x00, 0x01, 1]);
    let total = v.len() as u16;
    v[2] = (total & 0xFF) as u8;
    v[3] = (total >> 8) as u8;

    let (iso_out, iso_in) = find_audio_streaming_iso_eps(&v);
    // OUT ep 0x03 → DCI = 3*2 + 0 = 6.
    if iso_out != 6 {
        return TestResult::Fail("iso OUT DCI not 6");
    }
    // IN ep 0x82 → DCI = 2*2 + 1 = 5.
    if iso_in != 5 {
        return TestResult::Fail("iso IN DCI not 5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_usb_uac_finder_picks_iso_endpoints_from_as_iface
);

fn smoke_usb_uvc_finder_picks_iso_in_endpoint_from_vs_iface() -> TestResult {
    use crate::uvc::{
        find_video_streaming_iso_in_ep, USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
    };
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    v.extend_from_slice(&[9, 0x02, 0, 0, 2, 1, 0, 0xC0, 50]);
    // VC iface
    v.extend_from_slice(&[9, 0x04, 0, 0, 0, USB_CLASS_VIDEO, 0x01, 0, 0]);
    // VS iface
    v.extend_from_slice(&[
        9,
        0x04,
        1,
        0,
        1,
        USB_CLASS_VIDEO,
        USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
        0,
        0,
    ]);
    // iso IN endpoint 0x81.
    v.extend_from_slice(&[7, 0x05, 0x81, 0x01, 0x00, 0x04, 1]);
    let total = v.len() as u16;
    v[2] = (total & 0xFF) as u8;
    v[3] = (total >> 8) as u8;

    let iso_in = find_video_streaming_iso_in_ep(&v);
    // ep 0x81 → DCI = 1*2 + 1 = 3.
    if iso_in != 3 {
        return TestResult::Fail("iso IN DCI not 3");
    }
    // A config without a VS iface → 0.
    let mut nope: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    nope.extend_from_slice(&[9, 0x02, 18, 0, 1, 1, 0, 0xC0, 50]);
    nope.extend_from_slice(&[9, 0x04, 0, 0, 0, 0x08, 0x06, 0x50, 0]); // MSC
    if find_video_streaming_iso_in_ep(&nope) != 0 {
        return TestResult::Fail("non-UVC config must yield 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_finder_picks_iso_in_endpoint_from_vs_iface
);

fn smoke_usb_uvc_retains_streaming_alternates_and_selects_bandwidth() -> TestResult {
    use crate::uvc::{
        find_video_streaming_endpoints, select_video_streaming_iso_endpoint, UvcStreamingTransport,
        USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
    };

    let mut cfg = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 2, 1, 0, 0x80, 50]);
    // VideoControl plus an interrupt endpoint: it must not be mistaken for video data.
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, USB_CLASS_VIDEO, 0x01, 0, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x84, 0x03, 0x10, 0x00, 8]);
    // VideoStreaming alt 0 is the zero-bandwidth idle setting.
    cfg.extend_from_slice(&[
        9,
        0x04,
        2,
        0,
        0,
        USB_CLASS_VIDEO,
        USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
        0,
        0,
    ]);
    // Alt 1: one 1024-byte transaction per microframe.
    cfg.extend_from_slice(&[
        9,
        0x04,
        2,
        1,
        1,
        USB_CLASS_VIDEO,
        USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
        0,
        0,
    ]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x01, 0x00, 0x04, 1]);
    // Alt 2: two 1024-byte transactions (wMaxPacketSize[12:11] = 1).
    cfg.extend_from_slice(&[
        9,
        0x04,
        2,
        2,
        1,
        USB_CLASS_VIDEO,
        USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
        0,
        0,
    ]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x01, 0x00, 0x0c, 1]);
    // Alt 3: three 1024-byte transactions (wMaxPacketSize[12:11] = 2).
    cfg.extend_from_slice(&[
        9,
        0x04,
        2,
        3,
        1,
        USB_CLASS_VIDEO,
        USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
        0,
        0,
    ]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x01, 0x00, 0x14, 1]);
    let total = cfg.len() as u16;
    cfg[2..4].copy_from_slice(&total.to_le_bytes());

    let endpoints = find_video_streaming_endpoints(&cfg);
    if endpoints.len() != 3 {
        return TestResult::Fail("UVC streaming alternate count wrong");
    }
    let high = endpoints[2];
    if high.interface_number != 2
        || high.alternate_setting != 3
        || high.endpoint_address != 0x81
        || high.dci != 3
        || high.transport != UvcStreamingTransport::Isochronous
        || high.max_packet_size != 1024
        || high.transactions_per_interval != 3
        || high.max_payload_size != 3072
        || high.interval != 1
    {
        return TestResult::Fail("UVC high-bandwidth endpoint metadata wrong");
    }
    if select_video_streaming_iso_endpoint(&endpoints, 1500)
        .map(|endpoint| endpoint.alternate_setting)
        != Some(2)
    {
        return TestResult::Fail("UVC selector did not choose smallest fitting alternate");
    }
    if select_video_streaming_iso_endpoint(&endpoints, 2500)
        .map(|endpoint| endpoint.alternate_setting)
        != Some(3)
    {
        return TestResult::Fail("UVC selector did not choose high-bandwidth alternate");
    }
    if select_video_streaming_iso_endpoint(&endpoints, 3073).is_some() {
        return TestResult::Fail("UVC selector accepted an undersized alternate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_usb_uvc_retains_streaming_alternates_and_selects_bandwidth
);

fn smoke_xhci_translates_usb2_periodic_endpoint_schedule() -> TestResult {
    use crate::xhci::{endpoint_context_params, EndpointConfig, EndpointKind, PortSpeed};

    let high_bandwidth = EndpointConfig {
        ep_addr: 0x81,
        max_packet: 0x1400,
        kind: EndpointKind::IsochIn,
        interval: 1,
    };
    let Some(params) = endpoint_context_params(PortSpeed::High, high_bandwidth) else {
        return TestResult::Fail("valid HS isoch endpoint was rejected");
    };
    if params.max_packet != 1024
        || params.max_burst != 2
        || params.interval != 0
        || params.max_esit_payload != 3072
        || params.error_count != 0
    {
        return TestResult::Fail("HS isoch endpoint context translation wrong");
    }

    let full_speed_interrupt = EndpointConfig {
        ep_addr: 0x82,
        max_packet: 8,
        kind: EndpointKind::InterruptIn,
        interval: 10,
    };
    let Some(params) = endpoint_context_params(PortSpeed::Full, full_speed_interrupt) else {
        return TestResult::Fail("valid FS interrupt endpoint was rejected");
    };
    // 10 ms = 80 microframes; xHCI requires rounding down to 64 = 2^6.
    if params.interval != 6 || params.max_burst != 0 || params.max_esit_payload != 8 {
        return TestResult::Fail("FS interrupt interval translation wrong");
    }

    let reserved_burst = EndpointConfig {
        max_packet: 0x1c00,
        ..high_bandwidth
    };
    if endpoint_context_params(PortSpeed::High, reserved_burst).is_some() {
        return TestResult::Fail("reserved USB2 high-bandwidth encoding accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_translates_usb2_periodic_endpoint_schedule
);

// ── Bring-up replication: input chain failure modes ───────────────
//
// These tests reproduce the failure modes we've hit on real
// silicon ("kbd attached but no reports flowing") without needing
// real hardware. Each isolates one signal we'd observe on the
// status panel + verifies it behaves as documented.

/// pump_all on an empty keyboard list returns 0 events without
/// hanging or erroring. The supervisor task calls this every
/// wake — if no kbd bound, must be a fast no-op.
#[cfg(target_arch = "x86_64")]
fn smoke_hid_pump_all_with_no_keyboards_is_noop() -> TestResult {
    use crate::{hid, xhci};
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    hid::__reset_keyboards_for_test();
    let before_pumps = hid::PUMP_ALL_CALLS.load(core::sync::atomic::Ordering::Relaxed);
    let before_reports = hid::REPORTS_READ.load(core::sync::atomic::Ordering::Relaxed);
    let n = xhci::with_controller(hid::pump_all).unwrap_or(0);
    if n != 0 {
        return TestResult::Fail("pump_all with no kbds returned non-zero events");
    }
    let after_pumps = hid::PUMP_ALL_CALLS.load(core::sync::atomic::Ordering::Relaxed);
    let after_reports = hid::REPORTS_READ.load(core::sync::atomic::Ordering::Relaxed);
    if after_pumps != before_pumps + 1 {
        return TestResult::Fail("PUMP_ALL_CALLS didn't increment on pump_all");
    }
    if after_reports != before_reports {
        return TestResult::Fail("REPORTS_READ incremented with no kbds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid",
    smoke_hid_pump_all_with_no_keyboards_is_noop
);

/// On-screen diagnostic contract: `PUMP_ALL_CALLS` advances on
/// every supervisor wake; `REPORTS_READ` advances on every
/// non-empty interrupt-IN read. These two counters are what the
/// status panel exposes for real-HW bring-up diagnosis. This
/// test pins their semantics so a refactor that drops one of
/// the bumps fails loudly.
#[cfg(target_arch = "x86_64")]
fn smoke_hid_pump_counters_monotonic() -> TestResult {
    use crate::{hid, xhci};
    use core::sync::atomic::Ordering;
    if !xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    hid::__reset_keyboards_for_test();
    let baseline_pumps = hid::PUMP_ALL_CALLS.load(Ordering::Relaxed);
    // Drive several pumps; each must advance the counter by 1.
    for i in 1..=5u32 {
        let _ = xhci::with_controller(hid::pump_all);
        let now = hid::PUMP_ALL_CALLS.load(Ordering::Relaxed);
        if now != baseline_pumps + i {
            return TestResult::Fail("PUMP_ALL_CALLS didn't advance monotonically");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_pump_counters_monotonic);

/// find_boot_keyboard handles a config descriptor with NO
/// HID-class interface (e.g., a kbd-shaped device that doesn't
/// expose Boot subclass). Returns NoInterruptIn / NotBoot, never
/// loops indefinitely. Catches a regression where the parser
/// fails to advance past an unrecognised descriptor type.
fn smoke_hid_find_boot_keyboard_no_hid_iface_terminates() -> TestResult {
    use crate::hid::find_boot_keyboard;
    // Config descriptor with a non-HID interface (class=0xFF
    // Vendor-Specific). No interrupt-IN should be found.
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    // Config descriptor header (9 bytes).
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    // Interface descriptor (9 bytes) — vendor-specific class.
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0]);
    // Endpoint descriptor (7 bytes) — bulk-IN.
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x40, 0x00, 0]);
    // Patch total length in header.
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_boot_keyboard(&cfg) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("non-HID config matched as boot keyboard"),
    }
}
kernel_test_in!(
    "drivers/usb/hid",
    smoke_hid_find_boot_keyboard_no_hid_iface_terminates
);

/// find_boot_keyboard handles a truncated descriptor without
/// reading past the buffer. Catches a regression where a length
/// field of 0 would cause an infinite loop.
fn smoke_hid_find_boot_keyboard_truncated_descriptor_terminates() -> TestResult {
    use crate::hid::find_boot_keyboard;
    // Header with length saying "more bytes" but buffer too short.
    let cfg: alloc::vec::Vec<u8> = alloc::vec![9, 0x02, 64, 0, 1, 1, 0, 0xC0, 50];
    let _ = find_boot_keyboard(&cfg);
    // Reaching here without an infinite loop / panic is the test.
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid",
    smoke_hid_find_boot_keyboard_truncated_descriptor_terminates
);

/// find_boot_keyboard returns NoInterruptIn for a kbd config
/// that's missing an interrupt-IN endpoint. Reproduces the
/// `port=6 step=find_boot_kbd err=NoInterruptIn` message from
/// the user's real-HW boot — same root path.
fn smoke_hid_find_boot_keyboard_returns_no_interrupt_in_when_missing() -> TestResult {
    use crate::hid::{find_boot_keyboard, HidError};
    // HID Boot Keyboard interface BUT no interrupt-IN endpoint.
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    // Interface descriptor: HID class (0x03), Boot subclass (0x01),
    // Keyboard protocol (0x01).
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 0, 0x03, 0x01, 0x01, 0]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_boot_keyboard(&cfg) {
        Err(HidError::NoInterruptIn) => TestResult::Pass,
        Ok(_) => TestResult::Fail("matched as keyboard without an int-IN endpoint"),
        Err(_) => TestResult::Fail("wrong error variant for missing int-IN"),
    }
}
kernel_test_in!(
    "drivers/usb/hid",
    smoke_hid_find_boot_keyboard_returns_no_interrupt_in_when_missing
);

// ── btusb ──────────────────────────────────────────────────────────

/// The USB-IF Wireless Controllers class triple for a Bluetooth
/// programming interface (Vol 4 Part B + USB-IF v1.0).
fn smoke_btusb_class_triple_constants() -> TestResult {
    use crate::btusb::{USB_CLASS_WIRELESS, USB_PROTOCOL_BLUETOOTH, USB_SUBCLASS_RF};
    if USB_CLASS_WIRELESS != 0xE0 || USB_SUBCLASS_RF != 0x01 || USB_PROTOCOL_BLUETOOTH != 0x01 {
        return TestResult::Fail("btusb class triple drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_class_triple_constants);

/// Build a synthetic Configuration Descriptor declaring a
/// 0xE0/0x01/0x01 interface with the three required endpoints —
/// interrupt-IN, bulk-IN, bulk-OUT — and check that `find_bt_endpoints`
/// extracts them in the right order. Wire layout per USB 2.0
/// §9.6.3 / §9.6.5 / §9.6.6 — the same shape btusb sees on attach.
fn smoke_btusb_find_endpoints_minimal_descriptor() -> TestResult {
    use crate::btusb::find_bt_endpoints;
    use crate::xhci::EndpointKind;

    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xE0, 0x01, 0x01, 0]);
    // EP1 IN, interrupt — event endpoint (mps=16, bInterval=1).
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    // EP2 IN, bulk — ACL-IN (mps=64).
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    // EP2 OUT, bulk — ACL-OUT (mps=64).
    cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;

    let eps = match find_bt_endpoints(&cfg) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("find_bt_endpoints did not match"),
    };
    if eps.interface != 0 || eps.config_value != 1 {
        return TestResult::Fail("interface / configValue mismatch");
    }
    if eps.event_in.ep_addr != 0x81 || !matches!(eps.event_in.kind, EndpointKind::InterruptIn) {
        return TestResult::Fail("event-IN mis-identified");
    }
    if eps.acl_in.ep_addr != 0x82 || !matches!(eps.acl_in.kind, EndpointKind::BulkIn) {
        return TestResult::Fail("ACL-IN mis-identified");
    }
    if eps.acl_out.ep_addr != 0x02 || !matches!(eps.acl_out.kind, EndpointKind::BulkOut) {
        return TestResult::Fail("ACL-OUT mis-identified");
    }
    if eps.event_in.max_packet != 16 || eps.acl_in.max_packet != 64 {
        return TestResult::Fail("max-packet sizes did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_minimal_descriptor
);

/// A configuration descriptor with a non-Bluetooth interface (e.g.
/// HID 0x03/0x01/0x01) must NOT match — returns `NotBluetooth`.
fn smoke_btusb_find_endpoints_rejects_non_bluetooth_interface() -> TestResult {
    use crate::btusb::{find_bt_endpoints, BtUsbError};
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, 0x03, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0A]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_bt_endpoints(&cfg) {
        Err(BtUsbError::NotBluetooth) => TestResult::Pass,
        Ok(_) => TestResult::Fail("matched a non-Bluetooth interface"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_rejects_non_bluetooth_interface
);

/// A Bluetooth interface missing its bulk-OUT endpoint must be
/// rejected — Stage 0 requires all three (event-IN + bulk-IN +
/// bulk-OUT) to build a usable transport.
fn smoke_btusb_find_endpoints_rejects_missing_bulk_out() -> TestResult {
    use crate::btusb::{find_bt_endpoints, BtUsbError};
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    cfg.extend_from_slice(&[9, 0x02, 0, 0, 1, 1, 0, 0xC0, 50]);
    cfg.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xE0, 0x01, 0x01, 0]);
    cfg.extend_from_slice(&[7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01]);
    cfg.extend_from_slice(&[7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00]);
    let total = cfg.len() as u16;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    match find_bt_endpoints(&cfg) {
        Err(BtUsbError::NotBluetooth) => TestResult::Pass,
        Ok(_) => TestResult::Fail("matched without bulk-OUT"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/usb/btusb",
    smoke_btusb_find_endpoints_rejects_missing_bulk_out
);

/// On QEMU's default TCG x86_64 there's no USB Bluetooth controller,
/// so `attached_count` should be 0 after the supervisor's enumeration
/// passes.
fn smoke_btusb_no_bluetooth_on_qemu() -> TestResult {
    if crate::btusb::attached_count() != 0 {
        return TestResult::Fail("btusb registry should be empty on QEMU TCG");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_no_bluetooth_on_qemu);

/// WCN6855 vendor version data is a fixed 20-byte little-endian record. The
/// multi-NVM flag combines chip/platform bytes into the board-specific suffix.
fn smoke_btusb_qca_version_and_board_id() -> TestResult {
    use crate::btusb_qca::QcaVersion;

    let mut raw = [0u8; 20];
    raw[0..4].copy_from_slice(&0x0013_0201u32.to_le_bytes());
    raw[4..8].copy_from_slice(&7u32.to_le_bytes());
    raw[8..12].copy_from_slice(&0x400C_1211u32.to_le_bytes());
    raw[12] = 0x01;
    raw[13] = 0x0A;
    raw[14..16].copy_from_slice(&0x8000u16.to_le_bytes());
    let Some(version) = QcaVersion::decode(&raw) else {
        return TestResult::Fail("WCN6855 version record did not decode");
    };
    if version.rom_version != 0x0013_0201 || version.board_id() != 0x010A {
        return TestResult::Fail("WCN6855 version or board ID decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_version_and_board_id);

/// Runtime NVM selection includes both the GlobalFoundries variant and the
/// board ID, while the rampatch is selected only by ROM version.
fn smoke_btusb_qca_firmware_names() -> TestResult {
    use crate::btusb_qca::{firmware_names, QcaVersion};

    let names = firmware_names(QcaVersion {
        rom_version: 0x0013_0201,
        ram_version: 0x400C_1211,
        chip_id: 0x01,
        platform_id: 0x0A,
        flag: 0x8000,
        ..QcaVersion::default()
    });
    if names.rampatch != "qca/rampatch_usb_00130201.bin" {
        return TestResult::Fail("WCN6855 rampatch name is wrong");
    }
    if names.nvm != "qca/nvm_usb_00130201_gf_010a.bin" {
        return TestResult::Fail("WCN6855 NVM name is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_firmware_names);

/// The rampatch header embeds high/low ROM halves followed by the patch
/// revision. Reject a stale patch even when its ROM identity matches.
fn smoke_btusb_qca_rampatch_validation() -> TestResult {
    use crate::btusb_qca::{validate_rampatch_image, QcaError, QcaVersion};

    let version = QcaVersion {
        rom_version: 0x0013_0201,
        patch_version: 6,
        ..QcaVersion::default()
    };
    let mut image = [0u8; 40];
    image[16..18].copy_from_slice(&0x0013u16.to_le_bytes());
    image[18..20].copy_from_slice(&0x0201u16.to_le_bytes());
    image[20..22].copy_from_slice(&7u16.to_le_bytes());
    if validate_rampatch_image(&image, version).is_err() {
        return TestResult::Fail("valid WCN6855 rampatch header rejected");
    }
    image[20..22].copy_from_slice(&6u16.to_le_bytes());
    if validate_rampatch_image(&image, version) != Err(QcaError::FirmwareInvalid) {
        return TestResult::Fail("stale WCN6855 rampatch accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_qca_rampatch_validation);

/// HCI Command Complete retains its leading Status byte. Keep the USB
/// Stage-0 parser aligned with the shared Bluetooth controller parser.
fn smoke_btusb_local_version_skips_status() -> TestResult {
    use crate::btusb::{
        apply_bd_addr_return, apply_buffer_size_return, controller_info_from_version_return,
    };

    let ret = [
        0x00, // Status
        0x0C, // HCI version 5.3
        0x10, 0x00, // HCI revision 0x0010
        0x0C, // LMP version
        0xD7, 0x00, // Qualcomm company ID 0x00d7
        0x34, 0x12, // LMP subversion 0x1234
    ];
    let info = match controller_info_from_version_return(&ret) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("valid Read Local Version response rejected"),
    };
    if info.hci_version != 0x0C
        || info.hci_revision != 0x0010
        || info.manufacturer != 0x00D7
        || info.lmp_subversion != 0x1234
    {
        return TestResult::Fail("Read Local Version response shifted by status byte");
    }
    let mut info = info;
    if apply_bd_addr_return(&mut info, &[0, 1, 2, 3, 4, 5, 6]).is_err()
        || info.bd_addr != [1, 2, 3, 4, 5, 6]
    {
        return TestResult::Fail("Read BD_ADDR response decoded incorrectly");
    }
    if apply_buffer_size_return(&mut info, &[0, 0x40, 0x01, 0x20, 0x10, 0, 8, 0]).is_err()
        || info.acl_data_mtu != 0x0140
        || info.sco_data_mtu != 0x20
        || info.acl_total_num != 16
        || info.sco_total_num != 8
    {
        return TestResult::Fail("Read Buffer Size response decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/btusb", smoke_btusb_local_version_skips_status);

// ── fingerprint ────────────────────────────────────────────────────

/// USB-ID table matches: all 16 VID/PID entries resolve to a vendor.
fn smoke_fp_usb_id_table_match() -> TestResult {
    use crate::fingerprint::{classify_vid_pid, FpVendor};
    let cases: &[(u16, u16, FpVendor)] = &[
        // Synaptics
        (0x06CB, 0x00BD, FpVendor::Synaptics),
        (0x06CB, 0x00FF, FpVendor::Synaptics),
        // Goodix
        (0x27C6, 0x5110, FpVendor::Goodix),
        (0x27C6, 0x55B4, FpVendor::Goodix),
        (0x27C6, 0x6594, FpVendor::Goodix),
        // ELAN
        (0x04F3, 0x0903, FpVendor::Elan),
        (0x04F3, 0x0C03, FpVendor::Elan),
    ];
    for &(vid, pid, expected) in cases {
        match classify_vid_pid(vid, pid) {
            Some(v) if v == expected => {}
            Some(_) => {
                return TestResult::Fail("vendor mismatch");
            }
            None => {
                return TestResult::Fail("VID/PID not found in table");
            }
        }
    }
    // Unknown device should return None.
    if classify_vid_pid(0x1234, 0x5678).is_some() {
        return TestResult::Fail("unknown VID/PID should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_usb_id_table_match);

/// Vendor classifier: each VID maps to the correct FpVendor.
fn smoke_fp_vendor_classifier() -> TestResult {
    use crate::fingerprint::{classify_vid_pid, FpVendor};
    // All Synaptics PIDs
    for pid in [0x00BD, 0x00C2, 0x00C6, 0x00C9, 0x00DC, 0x00FF] {
        if !matches!(classify_vid_pid(0x06CB, pid), Some(FpVendor::Synaptics)) {
            return TestResult::Fail("Synaptics PID not classified");
        }
    }
    // All Goodix PIDs
    for pid in [0x5110, 0x5117, 0x530C, 0x533C, 0x5395, 0x55B4, 0x6594] {
        if !matches!(classify_vid_pid(0x27C6, pid), Some(FpVendor::Goodix)) {
            return TestResult::Fail("Goodix PID not classified");
        }
    }
    // All ELAN PIDs
    for pid in [0x0903, 0x0907, 0x0C00, 0x0C03] {
        if !matches!(classify_vid_pid(0x04F3, pid), Some(FpVendor::Elan)) {
            return TestResult::Fail("ELAN PID not classified");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_vendor_classifier);

/// Endpoint discovery on synthetic config blobs.
fn smoke_fp_endpoint_discovery() -> TestResult {
    use crate::fingerprint::{find_fp_endpoints, FpEndpoints, FpVendor};
    use crate::xhci::EndpointKind;

    // Build a vendor-class (0xFF) config with bulk-IN @ 0x81 +
    // bulk-OUT @ 0x01.
    let mut cfg: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
    cfg[0] = 9;
    cfg[1] = 0x02;
    cfg[2] = 32;
    cfg[4] = 1;
    cfg[5] = 1;
    cfg[9] = 9;
    cfg[10] = 0x04;
    cfg[11] = 0;
    cfg[13] = 2;
    cfg[14] = 0xFF;
    cfg[18] = 7;
    cfg[19] = 0x05;
    cfg[20] = 0x81;
    cfg[21] = 0x02;
    cfg[22] = 0x00;
    cfg[23] = 0x02;
    cfg[25] = 7;
    cfg[26] = 0x05;
    cfg[27] = 0x01;
    cfg[28] = 0x02;
    cfg[29] = 0x00;
    cfg[30] = 0x02;
    match find_fp_endpoints(&cfg, FpVendor::Goodix) {
        Ok(FpEndpoints::Bulk {
            bulk_in, bulk_out, ..
        }) => {
            if bulk_in.ep_addr != 0x81 || bulk_in.kind != EndpointKind::BulkIn {
                return TestResult::Fail("bulk-IN mis-decoded");
            }
            if bulk_out.ep_addr != 0x01 || bulk_out.kind != EndpointKind::BulkOut {
                return TestResult::Fail("bulk-OUT mis-decoded");
            }
        }
        _ => return TestResult::Fail("bulk endpoint discovery failed"),
    }
    // ELAN: interrupt-IN @ 0x81 (bmAttributes=3).
    let mut cfg2: alloc::vec::Vec<u8> = alloc::vec![0u8; 25];
    cfg2[0] = 9;
    cfg2[1] = 0x02;
    cfg2[2] = 25;
    cfg2[4] = 1;
    cfg2[5] = 1;
    cfg2[9] = 9;
    cfg2[10] = 0x04;
    cfg2[11] = 0;
    cfg2[13] = 1;
    cfg2[14] = 0xFF;
    cfg2[18] = 7;
    cfg2[19] = 0x05;
    cfg2[20] = 0x81;
    cfg2[21] = 0x03;
    cfg2[22] = 0x40;
    cfg2[23] = 0x00;
    match find_fp_endpoints(&cfg2, FpVendor::Elan) {
        Ok(FpEndpoints::InterruptIn { intr_in, .. }) => {
            if intr_in.ep_addr != 0x81 || intr_in.kind != EndpointKind::InterruptIn {
                return TestResult::Fail("interrupt-IN mis-decoded");
            }
        }
        _ => return TestResult::Fail("ELAN interrupt-IN discovery failed"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_endpoint_discovery);

/// Bind-path: no fingerprint reader on QEMU (registry stays empty).
fn smoke_fp_no_reader_on_qemu() -> TestResult {
    // The QEMU TCG environment has no fingerprint USB device.
    // After supervisor enumeration the registry must be empty.
    if crate::fingerprint::attached_fp_count() != 0 {
        return TestResult::Fail("fingerprint registry should be empty on QEMU TCG");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_no_reader_on_qemu);

/// Provider publication (#920): every bound reader resolves as
/// `/dev/fp<N>` by registry index — the second reader is fp1, not
/// unpublished — and enumeration agrees with lookup exactly.
fn smoke_fp_provider_publishes_every_reader() -> TestResult {
    use crate::fingerprint::{
        __reset_fp_for_test, __test_register_device, enumerate_fp, lookup_fp, FpVendor,
    };
    use narf_filesystem::{FileOps, FileType};
    __reset_fp_for_test();
    let mut fail: Option<&str> = None;
    __test_register_device(3, FpVendor::Synaptics, 3, 2);
    __test_register_device(5, FpVendor::Elan, 3, 0);
    if crate::fingerprint::attached_fp_count() != 2 {
        fail = Some("registry should hold two test readers");
    }
    // First device is still fp0; the second is fp1 (was: unpublished).
    if fail.is_none() && lookup_fp("fp0").is_none() {
        fail = Some("fp0 should resolve for the first reader");
    }
    if fail.is_none() && lookup_fp("fp1").is_none() {
        fail = Some("fp1 should resolve for the second reader");
    }
    // Masking defeats: unknown index and malformed names are not nodes.
    if fail.is_none() && lookup_fp("fp2").is_some() {
        fail = Some("fp2 must not resolve with two readers bound");
    }
    if fail.is_none() && (lookup_fp("fp").is_some() || lookup_fp("fpx").is_some()) {
        fail = Some("malformed fp names must not resolve");
    }
    if fail.is_none() {
        let names = enumerate_fp();
        let expected = [
            (alloc::format!("fp0"), FileType::Special),
            (alloc::format!("fp1"), FileType::Special),
        ];
        if names != expected {
            fail = Some("enumerate must list exactly fp0, fp1");
        }
    }
    if fail.is_none() {
        // The published node keeps the 0o660 special mode.
        if let Some(node) = lookup_fp("fp1") {
            if node.stat().mode.perms != 0o660 {
                fail = Some("fp1 node must keep mode 0o660");
            }
        } else {
            fail = Some("fp1 should resolve for the mode check");
        }
    }
    __reset_fp_for_test();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
kernel_test_in!(
    "drivers/usb/fingerprint",
    smoke_fp_provider_publishes_every_reader
);

/// Capability gate (#920): opening a `/dev/fp<N>` node requires
/// `CAP_SYS_RAWIO`, for reads as well as writes. The hook is
/// swapped explicitly both ways (never assumed), and restored
/// before returning, so the global hook state cannot leak into
/// other smokes.
fn smoke_fp_open_requires_rawio_cap() -> TestResult {
    use crate::fingerprint::{__reset_fp_for_test, __test_register_device, lookup_fp, FpVendor};
    use narf_filesystem::{FileOps, FsError};
    fn deny(_cap: u32) -> bool {
        false
    }
    fn allow(_cap: u32) -> bool {
        true
    }
    __reset_fp_for_test();
    __test_register_device(3, FpVendor::Synaptics, 3, 2);
    let node = match lookup_fp("fp0") {
        Some(n) => n,
        None => {
            __reset_fp_for_test();
            return TestResult::Fail("fp0 should resolve for the gate smoke");
        }
    };
    let orig = narf_filesystem::__test_swap_caller_capable_hook(Some(deny));
    let mut fail: Option<&str> = None;
    if !matches!(
        node.open_instance_checked(false),
        Err(FsError::PermissionDenied)
    ) {
        fail = Some("read open without the cap must be refused");
    }
    if fail.is_none()
        && !matches!(
            node.open_instance_checked(true),
            Err(FsError::PermissionDenied)
        )
    {
        fail = Some("write open without the cap must be refused");
    }
    let _ = narf_filesystem::__test_swap_caller_capable_hook(Some(allow));
    if fail.is_none() && !matches!(node.open_instance_checked(false), Ok(None)) {
        fail = Some("read open with the cap must succeed");
    }
    if fail.is_none() && !matches!(node.open_instance_checked(true), Ok(None)) {
        fail = Some("write open with the cap must succeed");
    }
    let _ = narf_filesystem::__test_swap_caller_capable_hook(orig);
    __reset_fp_for_test();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_open_requires_rawio_cap);

/// Modelled control-transfer device for the ioctl smoke: records
/// the SETUP fields of every OUT transfer and answers IN transfers
/// from a fixed byte string.
struct FakeFpTransport {
    in_bytes: alloc::vec::Vec<u8>,
    last_out: narf_lib::sync::IrqSafeSpinLock<Option<(u8, u8, u16, u16, alloc::vec::Vec<u8>)>>,
}

impl crate::fingerprint::FpTransport for FakeFpTransport {
    fn control_in<'a>(
        &'a self,
        _slot_id: u8,
        _bm_request_type: u8,
        _b_request: u8,
        _w_value: u16,
        _w_index: u16,
        out: &'a mut [u8],
    ) -> crate::fingerprint::FpFuture<'a, Result<usize, crate::fingerprint::FpError>> {
        let bytes = self.in_bytes.clone();
        alloc::boxed::Box::pin(async move {
            let n = bytes.len().min(out.len());
            out[..n].copy_from_slice(&bytes[..n]);
            Ok(n)
        })
    }

    fn control_out<'a>(
        &'a self,
        _slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &'a [u8],
    ) -> crate::fingerprint::FpFuture<'a, Result<usize, crate::fingerprint::FpError>> {
        let data = data.to_vec();
        let mut g = self.last_out.lock();
        *g = Some((bm_request_type, b_request, w_value, w_index, data.clone()));
        alloc::boxed::Box::pin(async move { Ok(data.len()) })
    }
}

/// Userspace-memory stand-in for the ioctl smoke: one flat buffer
/// at base 0x1000; out-of-range accesses fail `BadAddress`, like a
/// real userspace pointer fault.
struct MemCtx {
    mem: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>,
}

impl MemCtx {
    fn new() -> Self {
        Self {
            mem: narf_lib::sync::IrqSafeSpinLock::new(alloc::vec![0u8; 0x4000]),
        }
    }

    fn offset(&self, address: u64, len: usize) -> Result<usize, narf_filesystem::FsError> {
        let base = address
            .checked_sub(0x1000)
            .ok_or(narf_filesystem::FsError::BadAddress)?;
        let off = base as usize;
        if off.checked_add(len).is_none_or(|end| end > 0x4000) {
            return Err(narf_filesystem::FsError::BadAddress);
        }
        Ok(off)
    }
}

impl narf_filesystem::IoctlContext for MemCtx {
    fn read(&self, address: u64, dest: &mut [u8]) -> Result<(), narf_filesystem::FsError> {
        let off = self.offset(address, dest.len())?;
        dest.copy_from_slice(&self.mem.lock()[off..off + dest.len()]);
        Ok(())
    }

    fn write(&self, address: u64, src: &[u8]) -> Result<(), narf_filesystem::FsError> {
        let off = self.offset(address, src.len())?;
        self.mem.lock()[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }

    fn nonblocking(&self) -> bool {
        true
    }
}

/// Build a 24-byte `FP_IOC_CTRL_TRANSFER` argument (see the layout
/// comment on the ioctl constant).
fn fp_ctrl_arg(bm: u8, req: u8, val: u16, idx: u16, len: u32, ptr: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[0] = bm;
    a[1] = req;
    a[2..4].copy_from_slice(&val.to_le_bytes());
    a[4..6].copy_from_slice(&idx.to_le_bytes());
    a[8..12].copy_from_slice(&len.to_le_bytes());
    a[16..24].copy_from_slice(&ptr.to_le_bytes());
    a
}

/// Control-transfer ioctl (#920): an OUT vendor request reaches
/// the transport with its SETUP fields intact, an IN vendor
/// request copies the response back and writes back the actual
/// length, and malformed requests never reach the transport.
/// The data plane is untouched by this change (diff proof); the
/// read step below only pins that the read path still resolves
/// through the controller and fails without a device.
fn smoke_fp_ctrl_transfer_ioctl() -> TestResult {
    use crate::fingerprint::{
        FpVendor, __reset_fp_for_test, __test_fp_node, __test_register_device, FP_DEVICES,
        FP_IOC_CTRL_TRANSFER, FP_IOC_GET_INFO,
    };
    use narf_filesystem::{FileOps, FsError};
    __reset_fp_for_test();
    let idx = __test_register_device(7, FpVendor::Goodix, 3, 2);
    let dev = match FP_DEVICES.lock().get(idx).cloned() {
        Some(d) => d,
        None => {
            __reset_fp_for_test();
            return TestResult::Fail("test device should be in the registry");
        }
    };
    let transport = alloc::sync::Arc::new(FakeFpTransport {
        in_bytes: alloc::vec![0xAA, 0xBB],
        last_out: narf_lib::sync::IrqSafeSpinLock::new(None),
    });
    let node = __test_fp_node(dev, transport.clone());
    let ctx = MemCtx::new();
    let mut fail: Option<&str> = None;
    // OUT vendor request: SETUP fields + payload reach the transport.
    let arg_addr = 0x1000u64;
    let data_addr = 0x2000u64;
    {
        let mut mem = ctx.mem.lock();
        mem[0x0000..0x0018].copy_from_slice(&fp_ctrl_arg(0x40, 0x01, 0x0203, 0x0004, 3, data_addr));
        mem[0x1000..0x1003].copy_from_slice(&[0x11, 0x22, 0x33]);
    }
    let out = narf_scheduler::block_on(node.ioctl_user(FP_IOC_CTRL_TRANSFER, arg_addr, &ctx));
    if fail.is_none() && out != Ok(3) {
        fail = Some("OUT vendor transfer should report 3 bytes");
    }
    if fail.is_none() {
        match transport.last_out.lock().as_ref() {
            Some((bm, req, val, widx, data))
                if *bm == 0x40
                    && *req == 0x01
                    && *val == 0x0203
                    && *widx == 0x0004
                    && data.as_slice() == [0x11, 0x22, 0x33] => {}
            _ => fail = Some("OUT transfer SETUP fields or payload mismatch"),
        }
    }
    // IN vendor request: response copied back, actual length written back.
    if fail.is_none() {
        let resp_addr = 0x3000u64;
        {
            let mut mem = ctx.mem.lock();
            mem[0x0000..0x0018]
                .copy_from_slice(&fp_ctrl_arg(0xC0, 0x02, 0x0000, 0x0000, 2, resp_addr));
        }
        let r = narf_scheduler::block_on(node.ioctl_user(FP_IOC_CTRL_TRANSFER, arg_addr, &ctx));
        if r != Ok(2) {
            fail = Some("IN vendor transfer should report 2 bytes");
        } else {
            let mem = ctx.mem.lock();
            if mem[0x2000..0x2002] != [0xAA, 0xBB] {
                fail = Some("IN response bytes not copied back");
            } else if mem[0x0008..0x000C] != 2u32.to_le_bytes() {
                fail = Some("IN actual length not written back into data_len");
            }
        }
    }
    // Validation defeats: none of these may reach the transport.
    if fail.is_none() {
        let bad = [
            (0x00, "standard OUT request must be rejected"),
            (0x80, "standard IN request must be rejected"),
            (0x20, "class request must be rejected"),
            (
                0x41,
                "vendor request to a non-device recipient must be rejected",
            ),
        ];
        for (bm, msg) in bad {
            let mut mem = ctx.mem.lock();
            mem[0x0000..0x0018].copy_from_slice(&fp_ctrl_arg(bm, 0x01, 0, 0, 0, 0x2000));
            drop(mem);
            let r = narf_scheduler::block_on(node.ioctl_user(FP_IOC_CTRL_TRANSFER, arg_addr, &ctx));
            if !matches!(r, Err(FsError::Unsupported)) {
                fail = Some(msg);
                break;
            }
        }
    }
    if fail.is_none() {
        let mut mem = ctx.mem.lock();
        mem[0x0000..0x0018].copy_from_slice(&fp_ctrl_arg(0x40, 0x01, 0, 0, 4097, 0x2000));
        drop(mem);
        let r = narf_scheduler::block_on(node.ioctl_user(FP_IOC_CTRL_TRANSFER, arg_addr, &ctx));
        if !matches!(r, Err(FsError::InvalidData)) {
            fail = Some("oversize data_len must be rejected with InvalidData");
        }
    }
    if fail.is_none() {
        let r = narf_scheduler::block_on(node.ioctl_user(0xdead, arg_addr, &ctx));
        if !matches!(r, Err(FsError::Unsupported)) {
            fail = Some("unknown ioctl must be rejected");
        }
    }
    // GET_INFO packing: slot 7, Goodix = 1, IN DCI 3, OUT DCI 2.
    if fail.is_none() {
        let r = narf_scheduler::block_on(node.ioctl_user(FP_IOC_GET_INFO, 0, &ctx));
        let expected: u64 = 7 | (1 << 8) | (3 << 16) | (2 << 24);
        if r != Ok(expected) {
            fail = Some("GET_INFO packing mismatch");
        }
    }
    // Data plane intact: a read still resolves through the
    // controller and fails without a bound device on this slot.
    if fail.is_none() {
        let mut buf = [0u8; 64];
        let r = narf_scheduler::block_on(node.read(0, &mut buf));
        if r.is_ok() {
            fail = Some("data-plane read must fail without a device");
        }
    }
    __reset_fp_for_test();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
kernel_test_in!("drivers/usb/fingerprint", smoke_fp_ctrl_transfer_ioctl);

/// xHCI control helpers reject a method/SETUP direction mismatch. This is
/// load-bearing for payload-carrying host-to-device requests such as HID
/// SET_REPORT: routing one through `control_in` would otherwise DMA in the
/// wrong direction and silently discard the keyboard LED report.
fn smoke_xhci_control_direction_contract() -> TestResult {
    use crate::xhci::control_request_is_in;

    if control_request_is_in(0x00) || control_request_is_in(0x21) {
        return TestResult::Fail("host-to-device request classified as control-IN");
    }
    if !control_request_is_in(0x80) || !control_request_is_in(0xA1) {
        return TestResult::Fail("device-to-host request classified as control-OUT");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_control_direction_contract);

// ── ccid ────────────────────────────────────────────────────────────

/// Class constants for CCID (USB-IF CCID spec rev 1.1 §4.3 Table 5-1).
fn smoke_ccid_class_triple_constants() -> TestResult {
    use crate::ccid::{CCID_INTERFACE_CLASS, CCID_INTERFACE_PROTOCOL, CCID_INTERFACE_SUBCLASS};
    if CCID_INTERFACE_CLASS != 0x0B
        || CCID_INTERFACE_SUBCLASS != 0x00
        || CCID_INTERFACE_PROTOCOL != 0x00
    {
        return TestResult::Fail("CCID class triple drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_class_triple_constants);

/// Build a minimal 54-byte CCID class descriptor with T=0 + T=1 bits
/// set in dwProtocols, and verify `CcidDescriptor::from_bytes` decodes
/// them (CCID spec §5.1 Table 5-1).
fn smoke_ccid_descriptor_t0_t1() -> TestResult {
    use crate::ccid::{CcidDescriptor, CCID_DESC_TYPE, CCID_HDR_LEN, CCID_PROTO_T0, CCID_PROTO_T1};
    let _ = CCID_HDR_LEN; // used indirectly through the protocol
    let mut buf = [0u8; 54];
    buf[0] = 54;
    buf[1] = CCID_DESC_TYPE;
    buf[2] = 0x10; // bcdCCID = 0x0110
    buf[3] = 0x01;
    buf[4] = 0; // bMaxSlotIndex
    buf[5] = 0x07; // bVoltageSupport
    buf[6..10].copy_from_slice(&(CCID_PROTO_T0 | CCID_PROTO_T1).to_le_bytes());
    buf[28..32].copy_from_slice(&254u32.to_le_bytes()); // dwMaxIFSD
    buf[44..48].copy_from_slice(&271u32.to_le_bytes()); // dwMaxCCIDMessageLength

    let d = match CcidDescriptor::from_bytes(&buf) {
        Some(d) => d,
        None => return TestResult::Fail("CcidDescriptor::from_bytes returned None"),
    };
    if d.bcd_ccid != 0x0110 {
        return TestResult::Fail("bcdCCID mismatch");
    }
    if d.protocols & CCID_PROTO_T0 == 0 {
        return TestResult::Fail("T=0 bit not set in dwProtocols");
    }
    if d.protocols & CCID_PROTO_T1 == 0 {
        return TestResult::Fail("T=1 bit not set in dwProtocols");
    }
    if d.max_ifsd != 254 {
        return TestResult::Fail("dwMaxIFSD did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_descriptor_t0_t1);

/// PC_to_RDR_IccPowerOn (0x62) header encodes correctly (§6.1.1
/// Table 6-1): bMessageType, dwLength=0, bSlot, bSeq (CCID rev 1.1).
fn smoke_ccid_power_on_header_encode() -> TestResult {
    use crate::ccid::{CcidReader, PC_TO_RDR_ICC_POWER_ON};
    let hdr = CcidReader::build_header(PC_TO_RDR_ICC_POWER_ON, 0, 0, 0x07);
    if hdr[0] != PC_TO_RDR_ICC_POWER_ON {
        return TestResult::Fail("bMessageType != 0x62");
    }
    if hdr[1..5] != 0u32.to_le_bytes() {
        return TestResult::Fail("dwLength != 0 for power-on (no payload)");
    }
    if hdr[5] != 0 {
        return TestResult::Fail("bSlot != 0");
    }
    if hdr[6] != 0x07 {
        return TestResult::Fail("bSeq did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_power_on_header_encode);

/// RDR_to_PC_DataBlock (0x80) decode extracts all header fields
/// correctly from a synthetic 14-byte response (CCID spec §6.2.1).
fn smoke_ccid_data_block_decode() -> TestResult {
    use crate::ccid::{CcidReader, CCID_HDR_LEN, RDR_TO_PC_DATA_BLOCK, STATUS_SUCCESS};
    let atr: [u8; 4] = [0x3B, 0x90, 0x11, 0x00];
    let mut buf = alloc::vec![0u8; CCID_HDR_LEN + atr.len()];
    buf[0] = RDR_TO_PC_DATA_BLOCK;
    buf[1..5].copy_from_slice(&(atr.len() as u32).to_le_bytes());
    buf[5] = 0; // bSlot
    buf[6] = 0x05; // bSeq
    buf[7] = STATUS_SUCCESS;
    buf[8] = 0x00;
    buf[9] = 0x00; // bChainParameter
    buf[10..14].copy_from_slice(&atr);
    let (msg_type, payload_len, slot, seq, b_status, b_error) =
        match CcidReader::decode_response_header(&buf) {
            Ok(t) => t,
            Err(_) => return TestResult::Fail("decode_response_header failed"),
        };
    if msg_type != RDR_TO_PC_DATA_BLOCK {
        return TestResult::Fail("bMessageType mismatch");
    }
    if payload_len != 4 {
        return TestResult::Fail("dwLength != 4");
    }
    if slot != 0 || seq != 0x05 {
        return TestResult::Fail("bSlot/bSeq mismatch");
    }
    if b_status & 0x03 != STATUS_SUCCESS {
        return TestResult::Fail("bStatus not success");
    }
    if b_error != 0 {
        return TestResult::Fail("bError != 0");
    }
    let payload = &buf[CCID_HDR_LEN..CCID_HDR_LEN + payload_len as usize];
    if payload != &atr[..] {
        return TestResult::Fail("ATR payload did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_data_block_decode);

/// Bind path: `find_ccid_interface` + `find_ccid_class_descriptor` +
/// `find_ccid_endpoints` all succeed on a fully synthetic configuration
/// descriptor with a CCID 0x0B/0x00/0x00 interface (§4.3 Table 5-1).
fn smoke_ccid_bind_fake_xhci() -> TestResult {
    use crate::ccid::{
        find_ccid_class_descriptor, find_ccid_endpoints, find_ccid_interface, CcidError,
        CCID_DESC_TYPE, CCID_INTERFACE_CLASS, CCID_INTERFACE_PROTOCOL, CCID_INTERFACE_SUBCLASS,
        CCID_PROTO_T0, CCID_PROTO_T1,
    };
    use crate::xhci::EndpointKind;

    // Config (9) + Interface (9) + CCID descriptor (54) + 3 endpoints (21) = 93.
    let total: u16 = 93;
    let mut cfg = alloc::vec![0u8; total as usize];
    cfg[0] = 9;
    cfg[1] = 0x02;
    cfg[2] = (total & 0xFF) as u8;
    cfg[3] = (total >> 8) as u8;
    cfg[4] = 1;
    cfg[5] = 1; // bConfigurationValue
    cfg[7] = 0xC0;
    cfg[8] = 50;
    // Interface at 9
    cfg[9] = 9;
    cfg[10] = 0x04;
    cfg[11] = 0;
    cfg[13] = 3;
    cfg[14] = CCID_INTERFACE_CLASS;
    cfg[15] = CCID_INTERFACE_SUBCLASS;
    cfg[16] = CCID_INTERFACE_PROTOCOL;
    // CCID class descriptor at 18
    cfg[18] = 54;
    cfg[19] = CCID_DESC_TYPE;
    cfg[20] = 0x10;
    cfg[21] = 0x01; // bcdCCID = 0x0110
    cfg[24..28].copy_from_slice(&(CCID_PROTO_T0 | CCID_PROTO_T1).to_le_bytes());
    cfg[46..50].copy_from_slice(&254u32.to_le_bytes()); // dwMaxIFSD
    cfg[62..66].copy_from_slice(&271u32.to_le_bytes()); // dwMaxCCIDMessageLength
                                                        // Bulk-IN (EP1 IN) at 72
    cfg[72] = 7;
    cfg[73] = 0x05;
    cfg[74] = 0x81;
    cfg[75] = 0x02;
    cfg[76] = 64;
    // Bulk-OUT (EP1 OUT) at 79
    cfg[79] = 7;
    cfg[80] = 0x05;
    cfg[81] = 0x01;
    cfg[82] = 0x02;
    cfg[83] = 64;
    // Interrupt-IN (EP2 IN) at 86
    cfg[86] = 7;
    cfg[87] = 0x05;
    cfg[88] = 0x82;
    cfg[89] = 0x03;
    cfg[90] = 8;

    let (iface, iface_off) = match find_ccid_interface(&cfg) {
        Some(p) => p,
        None => return TestResult::Fail("find_ccid_interface returned None"),
    };
    if iface != 0 || iface_off != 9 {
        return TestResult::Fail("interface number or offset mismatch");
    }
    let desc = match find_ccid_class_descriptor(&cfg, iface_off) {
        Some(d) => d,
        None => return TestResult::Fail("find_ccid_class_descriptor returned None"),
    };
    if desc.protocols & CCID_PROTO_T0 == 0 || desc.protocols & CCID_PROTO_T1 == 0 {
        return TestResult::Fail("T=0/T=1 bits absent in decoded descriptor");
    }
    let eps = match find_ccid_endpoints(&cfg, iface_off) {
        Ok(e) => e,
        Err(CcidError::EndpointsMissing) => return TestResult::Fail("endpoints missing"),
        Err(_) => return TestResult::Fail("find_ccid_endpoints error"),
    };
    if eps.bulk_in.ep_addr != 0x81 || !matches!(eps.bulk_in.kind, EndpointKind::BulkIn) {
        return TestResult::Fail("bulk-IN addr/kind mismatch");
    }
    if eps.bulk_out.ep_addr != 0x01 || !matches!(eps.bulk_out.kind, EndpointKind::BulkOut) {
        return TestResult::Fail("bulk-OUT addr/kind mismatch");
    }
    if eps.intr_in.is_none() {
        return TestResult::Fail("intr-IN absent");
    }
    let intr = eps.intr_in.unwrap();
    if intr.ep_addr != 0x82 || !matches!(intr.kind, EndpointKind::InterruptIn) {
        return TestResult::Fail("intr-IN addr/kind mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_bind_fake_xhci);

/// After supervisor enumeration on QEMU TCG there are no smart-card
/// readers, so the registry must be empty.
fn smoke_ccid_no_reader_on_qemu() -> TestResult {
    if crate::ccid::attached_count() != 0 {
        return TestResult::Fail("ccid registry should be empty on QEMU TCG");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid", smoke_ccid_no_reader_on_qemu);

// ── ccid/t0 — T=0 framing ────────────────────────────────────────────

/// T=0 Case 1 APDU encodes to exactly 4 bytes (CLA INS P1 P2).
/// ISO 7816-4 §5.3.1.
fn smoke_ccid_t0_case1_encode() -> TestResult {
    use crate::ccid::t0::T0Apdu;
    let apdu = T0Apdu::build_case1(0x00, 0xA4, 0x04, 0x00);
    let b = apdu.as_bytes();
    if b != [0x00, 0xA4, 0x04, 0x00] {
        return TestResult::Fail("T=0 Case 1 byte sequence mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t0", smoke_ccid_t0_case1_encode);

/// T=0 Case 2 APDU encodes to 5 bytes (CLA INS P1 P2 Le).
/// ISO 7816-4 §5.3.2.
fn smoke_ccid_t0_case2_encode() -> TestResult {
    use crate::ccid::t0::T0Apdu;
    let apdu = T0Apdu::build_case2(0x00, 0xCA, 0x00, 0x6E, 0xFF);
    let b = apdu.as_bytes();
    if b.len() != 5 || b[4] != 0xFF {
        return TestResult::Fail("T=0 Case 2 encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t0", smoke_ccid_t0_case2_encode);

/// T=0 Case 3 APDU encodes to 5 + Lc bytes (CLA INS P1 P2 Lc DATA).
/// ISO 7816-4 §5.3.3.
fn smoke_ccid_t0_case3_encode() -> TestResult {
    use crate::ccid::t0::T0Apdu;
    let data = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let apdu = match T0Apdu::build_case3(0x00, 0xA4, 0x04, 0x00, &data) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("build_case3 failed"),
    };
    let b = apdu.as_bytes();
    if b.len() != 5 + data.len() {
        return TestResult::Fail("T=0 Case 3 wrong length");
    }
    if b[4] != data.len() as u8 {
        return TestResult::Fail("Lc field mismatch");
    }
    if b[5..] != data[..] {
        return TestResult::Fail("DATA field mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t0", smoke_ccid_t0_case3_encode);

/// T=0 Case 4 APDU encodes to 6 + Lc bytes (CLA INS P1 P2 Lc DATA Le).
/// ISO 7816-4 §5.3.4.
fn smoke_ccid_t0_case4_encode() -> TestResult {
    use crate::ccid::t0::T0Apdu;
    let data = [0x01, 0x02];
    let apdu = match T0Apdu::build_case4(0x80, 0xE0, 0x00, 0x00, &data, 0x08) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("build_case4 failed"),
    };
    let b = apdu.as_bytes();
    let want: &[u8] = &[0x80, 0xE0, 0x00, 0x00, 0x02, 0x01, 0x02, 0x08];
    if b != want {
        return TestResult::Fail("T=0 Case 4 byte sequence mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t0", smoke_ccid_t0_case4_encode);

/// T=0 GET_RESPONSE chaining: SW1=0x61, SW2=0x08 → GET_RESPONSE APDU
/// = CLA(echo) 0xC0 0x00 0x00 Le=0x08. ISO 7816-3 §10.3.3.
fn smoke_ccid_t0_get_response_chaining() -> TestResult {
    use crate::ccid::t0::{build_get_response, decode_response, SW1_GET_RESPONSE};
    let card_resp = [0x61u8, 0x08];
    let (data, sw1, sw2) = match decode_response(&card_resp) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("decode_response failed"),
    };
    if !data.is_empty() {
        return TestResult::Fail("no data bytes before SW");
    }
    if sw1 != SW1_GET_RESPONSE {
        return TestResult::Fail("SW1 != 0x61");
    }
    let gr = build_get_response(0x00, sw2);
    let b = gr.as_bytes();
    if b != [0x00, 0xC0, 0x00, 0x00, 0x08] {
        return TestResult::Fail("GET_RESPONSE APDU bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t0", smoke_ccid_t0_get_response_chaining);

// ── ccid/t1 — T=1 framing ────────────────────────────────────────────

/// T=1 I-block with N(S)=0: PCB=0x00, LRC covers NAD+PCB+LEN+INF.
/// ISO 7816-3 §11.3.2 / §11.3.3.
fn smoke_ccid_t1_iblock_lrc() -> TestResult {
    use crate::ccid::t1::{lrc_check, T1Block};
    let block = T1Block::i_block(0, &[0xDE, 0xAD]);
    let wire = match block.encode() {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("encode failed"),
    };
    if wire[0] != 0x00 {
        return TestResult::Fail("NAD != 0x00");
    }
    if wire[1] != 0x00 {
        return TestResult::Fail("PCB for I(NS=0) != 0x00");
    }
    if wire[2] != 2 {
        return TestResult::Fail("LEN != 2");
    }
    if lrc_check(&wire) != 0x00 {
        return TestResult::Fail("LRC of whole block != 0x00");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t1", smoke_ccid_t1_iblock_lrc);

/// T=1 R-block ACK (N(R)=0) encodes to PCB=0x80, no INF.
/// ISO 7816-3 §11.6.2.2 / Table 16.
fn smoke_ccid_t1_rblock_ack_nak() -> TestResult {
    use crate::ccid::t1::{lrc_check, T1Block};
    let ack = T1Block::r_block_ack(0);
    if !ack.is_rblock() {
        return TestResult::Fail("r_block_ack should be an R-block");
    }
    if ack.r_error() {
        return TestResult::Fail("ACK must not have error bit set");
    }
    let w = match ack.encode() {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("encode ack failed"),
    };
    if w[1] != 0x80 {
        return TestResult::Fail("ACK PCB != 0x80");
    }
    if lrc_check(&w) != 0x00 {
        return TestResult::Fail("ACK LRC invalid");
    }
    let nak = T1Block::r_block_nak(1);
    if !nak.r_error() {
        return TestResult::Fail("NAK must have error bit set");
    }
    let wn = match nak.encode() {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("encode nak failed"),
    };
    if wn[1] != 0x91 {
        return TestResult::Fail("NAK PCB != 0x91");
    }
    if lrc_check(&wn) != 0x00 {
        return TestResult::Fail("NAK LRC invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t1", smoke_ccid_t1_rblock_ack_nak);

/// T=1 S(IFS request) encodes to PCB=0xC1 with one-byte INF=ifsd.
/// ISO 7816-3 §11.6.3.1.
fn smoke_ccid_t1_sblock_ifs_request() -> TestResult {
    use crate::ccid::t1::{lrc_check, T1Block, PCB_SBLOCK_IFS_REQ};
    let block = T1Block::s_ifs_request(0xFE);
    if !block.is_sblock() {
        return TestResult::Fail("IFS block should be S-block");
    }
    if block.pcb != PCB_SBLOCK_IFS_REQ {
        return TestResult::Fail("IFS request PCB != 0xC1");
    }
    let wire = match block.encode() {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("encode failed"),
    };
    if wire[1] != 0xC1 {
        return TestResult::Fail("wire PCB != 0xC1");
    }
    if wire[2] != 1 {
        return TestResult::Fail("LEN must be 1");
    }
    if wire[3] != 0xFE {
        return TestResult::Fail("IFSD value mismatch");
    }
    if lrc_check(&wire) != 0x00 {
        return TestResult::Fail("LRC invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t1", smoke_ccid_t1_sblock_ifs_request);

/// T=1 I-block sequence numbers wrap: 0 → 1 → 0.
/// ISO 7816-3 §11.6.1 — N(S) alternates between 0 and 1.
fn smoke_ccid_t1_sequence_number_wrap() -> TestResult {
    use crate::ccid::t1::T1SeqState;
    let mut state = T1SeqState::default();
    if state.next_ns() != 0 {
        return TestResult::Fail("first N(S) must be 0");
    }
    if state.next_ns() != 1 {
        return TestResult::Fail("second N(S) must be 1");
    }
    if state.next_ns() != 0 {
        return TestResult::Fail("third N(S) must wrap to 0");
    }
    if state.current_nr() != 0 {
        return TestResult::Fail("N(R) must start at 0");
    }
    state.advance_nr();
    if state.current_nr() != 1 {
        return TestResult::Fail("N(R) after advance must be 1");
    }
    state.advance_nr();
    if state.current_nr() != 0 {
        return TestResult::Fail("N(R) must wrap to 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/ccid/t1", smoke_ccid_t1_sequence_number_wrap);

// ── xhci spec-encode smokes ────────────────────────────────────────
//
// Verify the spec-aligned TRB / register / DCBAA / ERST / Slot+EP
// Context encoders against the xHCI 1.2 specification field layouts.
// These tests are pure encode/decode against hand-computed bit
// patterns; they don't touch any controller MMIO so they pass on
// hardware-less boots (Stage-1 verification).

/// xHCI capability-register decode — confirm HCSPARAMS1 / HCSPARAMS2
/// / HCCPARAMS1 unpack the fields the bring-up path needs.
fn smoke_xhci_cap_decode_hcsparams1_hccparams1() -> TestResult {
    use crate::xhci::cap::{
        decode_hccparams1, decode_hcsparams1, HccParams1, HcsParams1, HcsParams2,
    };
    // HCSPARAMS1 fields: MaxSlots[7:0]=0x40, MaxIntrs[18:8]=0x20,
    // MaxPorts[31:24]=0x14. Build: 0x14_00_20_40 (BE-style).
    // 0x14 << 24 | 0x20 << 8 | 0x40 = 0x14002040.
    let v = (0x14u32 << 24) | (0x20u32 << 8) | 0x40u32;
    let h = decode_hcsparams1(v);
    if h != (HcsParams1 {
        max_slots: 0x40,
        max_intrs: 0x20,
        max_ports: 0x14,
    }) {
        return TestResult::Fail("HCSPARAMS1 decode mismatch");
    }
    // HCCPARAMS1: AC64=1, CSZ=0, xECP=0x100 dwords.
    let h = decode_hccparams1(0x0100_0001);
    let want = HccParams1 {
        ac64: true,
        bnc: false,
        csz_64byte: false,
        ppc: false,
        pind: false,
        lhrc: false,
        ltc: false,
        nss: false,
        max_psa_size: 0,
        xecp_dwords: 0x100,
    };
    if h != want {
        return TestResult::Fail("HCCPARAMS1 decode mismatch");
    }
    // HCSPARAMS2: MAXSCRATCHPAD_BUFS spans bits[25:21] (high) +
    // bits[31:27] (low). Want bufs=4: low=4 in bits[31:27].
    let p2 = HcsParams2::decode(4u32 << 27);
    if p2.max_scratchpad_bufs != 4 {
        return TestResult::Fail("MAXSCRATCHPAD_BUFS low-only decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_cap_decode_hcsparams1_hccparams1
);

/// PORTSC decode — the port-reset state machine reads CCS/PED/PR/PLS
/// + the change bits. Verify [`PortStatus::decode`] surfaces them.
fn smoke_xhci_portsc_decode_state_machine() -> TestResult {
    use crate::xhci::op::{
        PortLinkState, PortStatus, PORTSC_CCS, PORTSC_CSC, PORTSC_PR, PORTSC_PRC,
    };
    // Connected, reset-in-progress: CCS=1, PR=1, CSC=1 (a hot-plug
    // event), PLS=Polling (7). PORTSC_PLS at bits[8:5].
    let v = PORTSC_CCS | PORTSC_PR | PORTSC_CSC | (7u32 << 5);
    let st = PortStatus::decode(v);
    if !st.connected || !st.reset_in_progress || !st.csc {
        return TestResult::Fail("expected CCS+PR+CSC set");
    }
    if st.link_state != Some(PortLinkState::Polling) {
        return TestResult::Fail("PLS should decode to Polling");
    }
    // After reset: clear PRC + CSC via RW1C writeback. The compose
    // helper should NOT carry PR back (only the change bits).
    let wb = PortStatus::clear_changes_value(v, PORTSC_PRC | PORTSC_CSC);
    if (wb & PORTSC_PR) != 0 {
        return TestResult::Fail("clear_changes_value must drop PR");
    }
    if (wb & PORTSC_PRC) == 0 || (wb & PORTSC_CSC) == 0 {
        return TestResult::Fail("clear_changes_value must keep change-clear bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_portsc_decode_state_machine);

/// Command TRB encode — Enable Slot / Address Device / Configure
/// Endpoint each carry well-known bit patterns.
fn smoke_xhci_cmd_trb_encode_address_configure_enable() -> TestResult {
    use crate::xhci::cmd_ring::{
        encode_address_device, encode_configure_endpoint, encode_enable_slot,
        TRB_TYPE_ADDRESS_DEVICE_CMD, TRB_TYPE_CONFIGURE_ENDPOINT_CMD, TRB_TYPE_ENABLE_SLOT_CMD,
        TRB_TYPE_MASK, TRB_TYPE_SHIFT,
    };
    let trb = encode_enable_slot(0, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_ENABLE_SLOT_CMD {
        return TestResult::Fail("Enable Slot wrong TRB type");
    }
    if (trb.control & 1) != 1 {
        return TestResult::Fail("Cycle bit not preserved");
    }
    let trb = encode_address_device(0x12_3456_0000, 5, /*bsr*/ false, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_ADDRESS_DEVICE_CMD {
        return TestResult::Fail("Address Device wrong TRB type");
    }
    if ((trb.control >> 24) & 0xFF) != 5 {
        return TestResult::Fail("Address Device slot_id not in bits[31:24]");
    }
    if (trb.parameter & 0xF) != 0 {
        return TestResult::Fail("Address Device parameter must be 16-byte aligned");
    }
    let trb = encode_configure_endpoint(0x40_0000_0000, 7, /*dc*/ false, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_CONFIGURE_ENDPOINT_CMD {
        return TestResult::Fail("Configure Endpoint wrong TRB type");
    }
    if ((trb.control >> 24) & 0xFF) != 7 {
        return TestResult::Fail("Configure Endpoint slot_id not in bits[31:24]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_cmd_trb_encode_address_configure_enable
);

/// Event TRB decode — Transfer Event, Command Completion, Port Status
/// Change. Each fields its slot/EP/completion-code per §6.4.2.
fn smoke_xhci_event_trb_decode_transfer_cmd_psc() -> TestResult {
    use crate::xhci::cmd_ring::TRB_TYPE_SHIFT;
    use crate::xhci::event_ring::{
        DecodedEvent, EVT_CMD_COMPLETION, EVT_PORT_STATUS_CHANGE, EVT_TRANSFER,
    };
    // Transfer Event: slot=3, EP=DCI=2 (bulk-OUT EP1), completion=1 (Success),
    // transfer_length residue=4. Pack into 4 dwords.
    let xfer_d3 = (EVT_TRANSFER << TRB_TYPE_SHIFT) | (3u32 << 24) | (2u32 << 16);
    let xfer_d2 = (1u32 << 24) | 4;
    let ev = DecodedEvent::from_dwords([0xCAFE0000, 0, xfer_d2, xfer_d3]);
    match ev {
        DecodedEvent::Transfer(t) => {
            if t.slot_id != 3
                || t.endpoint_id != 2
                || t.completion_code != 1
                || t.transfer_length != 4
            {
                return TestResult::Fail("Transfer Event fields mismatch");
            }
        }
        _ => return TestResult::Fail("expected Transfer Event"),
    }
    // Command Completion: slot=5, completion=9 (TRB Error).
    let cmd_d3 = (EVT_CMD_COMPLETION << TRB_TYPE_SHIFT) | (5u32 << 24);
    let cmd_d2 = 9u32 << 24;
    let ev = DecodedEvent::from_dwords([0xABCD_0010, 0, cmd_d2, cmd_d3]);
    match ev {
        DecodedEvent::CmdCompletion(c) => {
            if c.slot_id != 5 || c.completion_code != 9 {
                return TestResult::Fail("CmdCompletion fields mismatch");
            }
        }
        _ => return TestResult::Fail("expected CmdCompletion"),
    }
    // Port Status Change: port_id=4 lives in parameter bits[31:24],
    // which is the LOWER 32-bit dword (d0) high byte.
    let psc_d0 = 4u32 << 24;
    let psc_d3 = EVT_PORT_STATUS_CHANGE << TRB_TYPE_SHIFT;
    let ev = DecodedEvent::from_dwords([psc_d0, 0, 0, psc_d3]);
    match ev {
        DecodedEvent::PortStatusChange(p) => {
            if p.port_id != 4 {
                return TestResult::Fail("PortStatusChange port_id mismatch");
            }
        }
        _ => return TestResult::Fail("expected PortStatusChange"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_event_trb_decode_transfer_cmd_psc
);

/// Normal TRB encode — bulk-OUT data buffer + IOC flag.
fn smoke_xhci_normal_trb_encode_bulk_out() -> TestResult {
    use crate::xhci::cmd_ring::{TRB_IOC, TRB_TYPE_MASK, TRB_TYPE_NORMAL, TRB_TYPE_SHIFT};
    use crate::xhci::transfer_ring::encode_normal;
    let buf_pa: u64 = 0x1000_0000;
    let trb = encode_normal(buf_pa, 1500, /*ioc*/ true, /*chain*/ false, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_NORMAL {
        return TestResult::Fail("Normal TRB wrong type");
    }
    if (trb.status & 0x1_FFFF) != 1500 {
        return TestResult::Fail("Normal TRB length not in status[16:0]");
    }
    if (trb.control & TRB_IOC) == 0 {
        return TestResult::Fail("IOC must be set");
    }
    if trb.parameter != buf_pa {
        return TestResult::Fail("Normal TRB parameter must hold buf_pa");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_normal_trb_encode_bulk_out);

/// Setup / Data / Status Stage TRB encode for a control IN transfer.
fn smoke_xhci_setup_data_status_stage_encode() -> TestResult {
    use crate::xhci::cmd_ring::{
        TRB_IDT, TRB_IOC, TRB_TYPE_DATA_STAGE, TRB_TYPE_MASK, TRB_TYPE_SETUP_STAGE, TRB_TYPE_SHIFT,
        TRB_TYPE_STATUS_STAGE,
    };
    use crate::xhci::transfer_ring::{
        encode_data_stage, encode_setup_stage, encode_status_stage, TRB_DIR_IN, TRT_IN_DATA,
    };
    // GET_DESCRIPTOR DEVICE: bmRT=0x80, bReq=6, wValue=(1<<8), wIndex=0,
    // wLength=18.
    let setup: [u8; 8] = [0x80, 6, 0, 1, 0, 0, 18, 0];
    let trb = encode_setup_stage(setup, TRT_IN_DATA, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_SETUP_STAGE {
        return TestResult::Fail("Setup TRB wrong type");
    }
    if (trb.control & TRB_IDT) == 0 {
        return TestResult::Fail("IDT must be set on Setup Stage");
    }
    if ((trb.control >> 16) & 0x3) != TRT_IN_DATA {
        return TestResult::Fail("TRT must be IN_DATA");
    }
    if trb.status != 8 {
        return TestResult::Fail("Setup Stage status length must be 8");
    }
    if trb.parameter != u64::from_le_bytes(setup) {
        return TestResult::Fail("Setup packet not packed into parameter");
    }
    // Data Stage IN with IOC. A real control-TD completion path must
    // identify this event by TRB pointer, then drain the separately
    // requested Status Stage event before issuing its next transfer.
    let trb = encode_data_stage(0x2000_0000, 18, /*dir_in*/ true, /*ioc*/ true, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_DATA_STAGE {
        return TestResult::Fail("Data Stage wrong type");
    }
    if (trb.control & TRB_DIR_IN) == 0 {
        return TestResult::Fail("Data Stage DIR=IN missing");
    }
    if (trb.control & TRB_IOC) == 0 {
        return TestResult::Fail("Data Stage IOC missing");
    }
    if (trb.status & 0x1_FFFF) != 18 {
        return TestResult::Fail("Data Stage length mismatch");
    }
    // Status Stage OUT (opposite of IN data stage), IOC=1.
    let trb = encode_status_stage(/*dir_in*/ false, true, 1);
    if ((trb.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT) != TRB_TYPE_STATUS_STAGE {
        return TestResult::Fail("Status Stage wrong type");
    }
    if (trb.control & TRB_DIR_IN) != 0 {
        return TestResult::Fail("Status Stage after IN data must be OUT");
    }
    if (trb.control & TRB_IOC) == 0 {
        return TestResult::Fail("Status Stage IOC missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_setup_data_status_stage_encode
);

/// Input Context layout — Add Context Flag bitmap addresses Slot
/// (bit 0), EP0 (bit 1), then DCI N (bit N). Drop Flag rejects DCI <
/// 2.
fn smoke_xhci_input_ctx_layout_add_drop_flags() -> TestResult {
    use crate::xhci::slot::{
        encode_slot_ctx_dword0, encode_slot_ctx_dword2, input_context_size, input_ctx_add_flag,
        input_ctx_drop_flag,
    };
    // Add Slot Context: bit 0.
    if input_ctx_add_flag(0) != 1 {
        return TestResult::Fail("Slot add flag must be bit 0");
    }
    // Add EP0: bit 1.
    if input_ctx_add_flag(1) != 2 {
        return TestResult::Fail("EP0 add flag must be bit 1");
    }
    // Add a bulk-OUT EP at DCI 4: bit 4.
    if input_ctx_add_flag(4) != 0x10 {
        return TestResult::Fail("DCI 4 add flag must be bit 4");
    }
    // Drop flag for DCI 0/1 = 0 (illegal to drop slot/EP0).
    if input_ctx_drop_flag(0) != 0 || input_ctx_drop_flag(1) != 0 {
        return TestResult::Fail("Drop slot/EP0 must be no-op");
    }
    if input_ctx_drop_flag(3) != 0x8 {
        return TestResult::Fail("DCI 3 drop flag must be bit 3");
    }
    // Slot Context dword0: route_string + speed + hub + ctx_entries.
    let d0 = encode_slot_ctx_dword0(0x12345, 3, true, true, 5);
    if (d0 & 0xFFFFF) != 0x12345 {
        return TestResult::Fail("route_string not in bits[19:0]");
    }
    if ((d0 >> 20) & 0xF) != 3 {
        return TestResult::Fail("speed not in bits[23:20]");
    }
    if (d0 & (1 << 26)) == 0 {
        return TestResult::Fail("HUB bit not set");
    }
    if (d0 & (1 << 25)) == 0 {
        return TestResult::Fail("MTT bit not set");
    }
    if ((d0 >> 27) & 0x1F) != 5 {
        return TestResult::Fail("ctx_entries not in bits[31:27]");
    }
    let d2 = encode_slot_ctx_dword2(7, 1, 3);
    if d2 & 0xFF != 7 || (d2 >> 8) & 0xFF != 1 || (d2 >> 16) & 0x3 != 3 {
        return TestResult::Fail("parent TT slot context encoding mismatch");
    }
    // Input Context size — 32-byte and 64-byte variants.
    if input_context_size(false) != 32 + 32 + 31 * 32 {
        return TestResult::Fail("32-byte input context size wrong");
    }
    if input_context_size(true) != 64 + 64 + 31 * 64 {
        return TestResult::Fail("64-byte input context size wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_input_ctx_layout_add_drop_flags
);

/// DCBAA entry encode — phys must be 64-byte aligned per §6.1.
fn smoke_xhci_dcbaa_entry_encode() -> TestResult {
    use crate::xhci::dcbaa::{encode_entry, is_aligned, DCBAA_BYTES, DCBAA_ENTRIES};
    if DCBAA_ENTRIES != 256 {
        return TestResult::Fail("DCBAA must be 256 entries");
    }
    if DCBAA_BYTES != 256 * 8 {
        return TestResult::Fail("DCBAA byte count must be 2048");
    }
    // Entry must mask the low 6 bits.
    if encode_entry(0x1234_5678) != 0x1234_5640 {
        return TestResult::Fail("entry must mask bits[5:0]");
    }
    if !is_aligned(0x1000) {
        return TestResult::Fail("0x1000 is 64-byte aligned");
    }
    if is_aligned(0x1020) {
        return TestResult::Fail("0x1020 is NOT 64-byte aligned");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_dcbaa_entry_encode);

/// ERST entry encode — 64-byte aligned ring base, low 16 bits of size.
fn smoke_xhci_erst_entry_encode() -> TestResult {
    use crate::xhci::event_ring::{ErstEntry, ER_SEG_TRBS};
    let e = ErstEntry::encode(0x2000_0000, ER_SEG_TRBS as u16);
    if e.ring_seg_base != 0x2000_0000 {
        return TestResult::Fail("ring_seg_base mismatch");
    }
    if e.ring_seg_size != ER_SEG_TRBS as u32 {
        return TestResult::Fail("ring_seg_size mismatch");
    }
    // Encoding must mask off the bottom 6 bits of the base.
    let e2 = ErstEntry::encode(0x2000_0033, 64);
    if e2.ring_seg_base != 0x2000_0000 {
        return TestResult::Fail("base must mask bits[5:0]");
    }
    let raw = e2.to_le_bytes();
    if raw.len() != 16 {
        return TestResult::Fail("ERST entry must be 16 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_erst_entry_encode);

/// Slot Context state-machine values match Table 4-7.
fn smoke_xhci_slot_state_machine_decode() -> TestResult {
    use crate::xhci::slot::{SlotState, SLOT_CTX_STATE_SHIFT};
    let d3_default = 1u32 << SLOT_CTX_STATE_SHIFT;
    let d3_addressed = 2u32 << SLOT_CTX_STATE_SHIFT;
    let d3_configured = 3u32 << SLOT_CTX_STATE_SHIFT;
    let d3_disabled = 0u32 << SLOT_CTX_STATE_SHIFT;
    if SlotState::from_dword3(d3_disabled) != Some(SlotState::DisabledOrEnabled) {
        return TestResult::Fail("encoding 0 must decode to DisabledOrEnabled");
    }
    if SlotState::from_dword3(d3_default) != Some(SlotState::Default) {
        return TestResult::Fail("encoding 1 must decode to Default");
    }
    if SlotState::from_dword3(d3_addressed) != Some(SlotState::Addressed) {
        return TestResult::Fail("encoding 2 must decode to Addressed");
    }
    if SlotState::from_dword3(d3_configured) != Some(SlotState::Configured) {
        return TestResult::Fail("encoding 3 must decode to Configured");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_slot_state_machine_decode);

/// Endpoint Context encode covers IN / OUT / Bulk / Interrupt / Iso.
fn smoke_xhci_endpoint_context_encode_all_kinds() -> TestResult {
    use crate::xhci::slot::{
        encode_ep_ctx_dword1, encode_ep_ctx_dword2_tr_lo, encode_ep_ctx_dword4, EP_TYPE_BULK_IN,
        EP_TYPE_BULK_OUT, EP_TYPE_CONTROL, EP_TYPE_INT_IN, EP_TYPE_INT_OUT, EP_TYPE_ISOCH_IN,
        EP_TYPE_ISOCH_OUT,
    };
    // Bulk OUT, CErr=3, MaxBurst=0, MPS=512.
    let d1 = encode_ep_ctx_dword1(3, EP_TYPE_BULK_OUT, 0, 512);
    if ((d1 >> 3) & 0x7) != EP_TYPE_BULK_OUT {
        return TestResult::Fail("Bulk-OUT EP type mismatch");
    }
    if (d1 >> 16) != 512 {
        return TestResult::Fail("MPS not in bits[31:16]");
    }
    if ((d1 >> 1) & 0x3) != 3 {
        return TestResult::Fail("CErr not in bits[2:1]");
    }
    // Bulk-IN, IsochIn, IsochOut, IntIn, IntOut, Control all distinct.
    let mut seen = [false; 8];
    for k in [
        EP_TYPE_BULK_IN,
        EP_TYPE_INT_IN,
        EP_TYPE_INT_OUT,
        EP_TYPE_ISOCH_IN,
        EP_TYPE_ISOCH_OUT,
        EP_TYPE_CONTROL,
    ] {
        if seen[k as usize] {
            return TestResult::Fail("EP type values must be distinct");
        }
        seen[k as usize] = true;
    }
    // TR Dequeue Pointer low: 16-byte alignment + DCS bit. Input
    // address has the low 4 bits zero (TRBs are 16-byte aligned per
    // §6.2.3); the encoder preserves the upper bits and ORs in DCS.
    let tr_lo = encode_ep_ctx_dword2_tr_lo(0x4000_0010, 1);
    if (tr_lo & 0xF) != 1 {
        return TestResult::Fail("DCS bit not in bit 0");
    }
    if (tr_lo & 0xFFFF_FFF0) != 0x4000_0010 {
        return TestResult::Fail("TR Dequeue Pointer bits[31:4] not preserved");
    }
    // Encoder must mask off bits[3:1] of the input address (per spec
    // bits[3:1] MBZ; only bit 0 is DCS).
    let tr_lo2 = encode_ep_ctx_dword2_tr_lo(0x4000_001F, 0);
    if (tr_lo2 & 0xF) != 0 {
        return TestResult::Fail("DCS=0 should clear low 4 bits");
    }
    let d4 = encode_ep_ctx_dword4(64, 0xAA);
    if (d4 & 0xFFFF) != 64 {
        return TestResult::Fail("avg_trb_len not in bits[15:0]");
    }
    if (d4 >> 16) != 0xAA {
        return TestResult::Fail("max_esit_payload_lo not in bits[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_endpoint_context_encode_all_kinds
);

/// PCI class triple match for an xHCI controller (0x0c0330).
fn smoke_xhci_pci_class_match_triple() -> TestResult {
    use crate::xhci::probe::{
        is_xhci_class, PCI_CLASS_SERIAL_BUS, PCI_CLASS_TRIPLE_XHCI, PCI_PROGIF_XHCI,
        PCI_SUBCLASS_USB,
    };
    if PCI_CLASS_SERIAL_BUS != 0x0C || PCI_SUBCLASS_USB != 0x03 || PCI_PROGIF_XHCI != 0x30 {
        return TestResult::Fail("PCI class constants wrong");
    }
    if PCI_CLASS_TRIPLE_XHCI != 0x000C_0330 {
        return TestResult::Fail("PCI triple must equal 0x0C0330");
    }
    if !is_xhci_class(0x000C_0330) {
        return TestResult::Fail("must match 0x0C0330");
    }
    if is_xhci_class(0x000C_0310) {
        // 0x0C/03/10 = EHCI, should NOT match.
        return TestResult::Fail("must not match EHCI 0x0C0310");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_pci_class_match_triple);

/// Scratchpad-array entry encode + alignment guards.
fn smoke_xhci_scratchpad_entry_encode() -> TestResult {
    use crate::xhci::scratchpad::{
        encode_entry, is_array_aligned, is_page_aligned, scratchpad_array_bytes,
        SCRATCH_ARRAY_ALIGN, SCRATCH_PAGE_SIZE,
    };
    if SCRATCH_PAGE_SIZE != 4096 {
        return TestResult::Fail("page size must be 4096");
    }
    if SCRATCH_ARRAY_ALIGN != 64 {
        return TestResult::Fail("array alignment must be 64");
    }
    if scratchpad_array_bytes(8) != 64 {
        return TestResult::Fail("8 entries × 8 bytes = 64");
    }
    if encode_entry(0x10_0FFF) != 0x10_0000 {
        return TestResult::Fail("encode_entry must mask low 12 bits");
    }
    if !is_page_aligned(0x10000) {
        return TestResult::Fail("0x10000 is 4K-aligned");
    }
    if is_page_aligned(0x10001) {
        return TestResult::Fail("0x10001 is NOT 4K-aligned");
    }
    if !is_array_aligned(0x40) {
        return TestResult::Fail("0x40 is 64-aligned");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_scratchpad_entry_encode);

// ── narf-usb device-model + rtl8xxxu bridge smokes ─────────────────

/// USB device-model — UsbError translation from XhciError.
fn smoke_usb_error_translates_completion_codes() -> TestResult {
    use crate::device::UsbError;
    use crate::xhci::XhciError;
    if UsbError::from_xhci(XhciError::CmdFailed(6)) != UsbError::Stall {
        return TestResult::Fail("ccode 6 must map to Stall");
    }
    if UsbError::from_xhci(XhciError::CmdFailed(4)) != UsbError::TransactionError {
        return TestResult::Fail("ccode 4 must map to TransactionError");
    }
    if UsbError::from_xhci(XhciError::CmdFailed(7)) != UsbError::Babble {
        return TestResult::Fail("ccode 7 must map to Babble");
    }
    if UsbError::from_xhci(XhciError::CmdTimeout) != UsbError::Timeout {
        return TestResult::Fail("CmdTimeout must map to Timeout");
    }
    if UsbError::from_xhci(XhciError::PortResetTimeout) != UsbError::Timeout {
        return TestResult::Fail("PortResetTimeout must map to Timeout");
    }
    if UsbError::from_xhci(XhciError::CmdFailed(99)) != UsbError::HardwareError(99) {
        return TestResult::Fail("unknown ccode must pass through");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/device",
    smoke_usb_error_translates_completion_codes
);

/// dci_for() — bEndpointAddress → DCI math per xHCI §4.8.1.
fn smoke_usb_dci_for_endpoint_address() -> TestResult {
    use crate::bulk::dci_for;
    // EP1 OUT → DCI 2; EP1 IN → DCI 3; EP2 OUT → DCI 4; EP2 IN → DCI 5.
    if dci_for(0x01) != 2 {
        return TestResult::Fail("EP1 OUT must map to DCI 2");
    }
    if dci_for(0x81) != 3 {
        return TestResult::Fail("EP1 IN must map to DCI 3");
    }
    if dci_for(0x02) != 4 {
        return TestResult::Fail("EP2 OUT must map to DCI 4");
    }
    if dci_for(0x82) != 5 {
        return TestResult::Fail("EP2 IN must map to DCI 5");
    }
    if dci_for(0x0F) != 30 {
        return TestResult::Fail("EP15 OUT must map to DCI 30");
    }
    if dci_for(0x8F) != 31 {
        return TestResult::Fail("EP15 IN must map to DCI 31");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/device", smoke_usb_dci_for_endpoint_address);

/// SETUP packet builder — vendor read + standard GET_DESCRIPTOR
/// encode the right bmRT / bReq / wValue layout.
fn smoke_usb_setup_packet_encode_vendor_and_get_descriptor() -> TestResult {
    use crate::control::{get_descriptor, vendor_read, vendor_write, Setup};
    // GET_DESCRIPTOR DEVICE: bmRT=0x80, bReq=6, wValue=(type<<8)|index.
    let s = get_descriptor(1, 0, 0, 18);
    if s.bm_request_type != 0x80 {
        return TestResult::Fail("GET_DESCRIPTOR bmRT must be 0x80");
    }
    if s.b_request != 6 {
        return TestResult::Fail("GET_DESCRIPTOR bReq must be 6");
    }
    if s.w_value != (1u16 << 8) {
        return TestResult::Fail("GET_DESCRIPTOR wValue must be type<<8");
    }
    if s.w_length != 18 {
        return TestResult::Fail("GET_DESCRIPTOR wLength mismatch");
    }
    if !s.is_in() {
        return TestResult::Fail("GET_DESCRIPTOR must be IN");
    }
    // Vendor read: REALTEK_USB_READ pattern (0xC0/0x05/addr/0/len).
    let s = vendor_read(0x05, 0x1234, 0, 4);
    if s.bm_request_type != 0xC0 {
        return TestResult::Fail("vendor_read bmRT must be 0xC0");
    }
    if !s.is_in() {
        return TestResult::Fail("vendor_read must be IN");
    }
    // Vendor write: 0x40/0x05/addr/0/len.
    let s = vendor_write(0x05, 0xABCD, 0, 4);
    if s.bm_request_type != 0x40 {
        return TestResult::Fail("vendor_write bmRT must be 0x40");
    }
    if s.is_in() {
        return TestResult::Fail("vendor_write must NOT be IN");
    }
    // Round-trip to_bytes / from_bytes.
    let s = Setup::new(0xC0, 5, 0xBABE, 0xCAFE, 2);
    let bytes = s.to_bytes();
    let back = Setup::from_bytes(bytes);
    if back != s {
        return TestResult::Fail("Setup encode/decode round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/control",
    smoke_usb_setup_packet_encode_vendor_and_get_descriptor
);

/// CLEAR_FEATURE(ENDPOINT_HALT) — the device half of halted-endpoint
/// recovery (`USBDevice::clear_endpoint_halt`) must encode exactly
/// the USB 2.0 §9.4.1 packet: host-to-device / standard / endpoint
/// recipient, bRequest 1, wValue = feature selector 0, wIndex =
/// endpoint address, no data stage.
fn smoke_usb_clear_feature_endpoint_halt_packet() -> TestResult {
    use crate::control::{clear_feature, FEATURE_ENDPOINT_HALT, RT_RECIP_ENDPOINT};
    let s = clear_feature(RT_RECIP_ENDPOINT, FEATURE_ENDPOINT_HALT, 0x83);
    if s.bm_request_type != 0x02 {
        return TestResult::Fail("CLEAR_FEATURE bmRT must be 0x02 (OUT/std/endpoint)");
    }
    if s.b_request != 1 {
        return TestResult::Fail("CLEAR_FEATURE bReq must be 1");
    }
    if s.w_value != 0 {
        return TestResult::Fail("ENDPOINT_HALT feature selector must be 0");
    }
    if s.w_index != 0x83 {
        return TestResult::Fail("CLEAR_FEATURE wIndex must be the endpoint address");
    }
    if s.w_length != 0 || s.is_in() {
        return TestResult::Fail("CLEAR_FEATURE has no data stage and is OUT");
    }
    let expected: [u8; 8] = [0x02, 0x01, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00];
    if s.to_bytes() != expected {
        return TestResult::Fail("CLEAR_FEATURE wire bytes mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/control",
    smoke_usb_clear_feature_endpoint_halt_packet
);

/// rtl8xxxu integration — read MAC EFUSE byte via control-transfer
/// SETUP-packet encoding matches the per-chip Realtek read layout.
///
/// Realtek uses bmRT=0xC0 / bReq=0x05 / wValue=addr / wIndex=0 /
/// wLength=width (1 / 2 / 4 bytes). The narf-usb control builder must
/// produce a byte-identical SETUP packet for the bridge to forward —
/// the rtl8xxxu USB transport (`drivers/wireless/src/rtl8xxxu/usb.rs`)
/// uses the same encoding, sourced from `core.c::rtl8xxxu_read8` ~L621.
fn smoke_rtl8xxxu_efuse_read_setup_via_narf_usb() -> TestResult {
    use crate::control::Setup;
    // Read 1 byte at EFUSE address 0x008C — `REG_EFUSE_CTRL+0` on
    // 8188EU. Realtek reads here when assembling the per-chip MAC.
    let addr: u16 = 0x008C;
    let s = Setup::new(0xC0, 0x05, addr, 0x0000, 1);
    let bytes = s.to_bytes();
    // Hand-computed expected SETUP packet (USB 2.0 §9.3):
    //   [0]=0xC0 bmRT, [1]=0x05 bReq, [2..3]=wValue LE,
    //   [4..5]=wIndex LE, [6..7]=wLength LE.
    let expected: [u8; 8] = [0xC0, 0x05, 0x8C, 0x00, 0x00, 0x00, 0x01, 0x00];
    if bytes != expected {
        return TestResult::Fail("narf-usb SETUP byte layout wrong for Realtek read");
    }
    // Sanity-check the IN direction bit + standard wValue/wLength.
    if !s.is_in() {
        return TestResult::Fail("0xC0 bmRT must be IN");
    }
    if u16::from_le_bytes([bytes[2], bytes[3]]) != addr {
        return TestResult::Fail("wValue not little-endian addr");
    }
    if u16::from_le_bytes([bytes[6], bytes[7]]) != 1 {
        return TestResult::Fail("wLength must be 1");
    }
    // The matching write SETUP (host → device): bmRT=0x40 with same
    // bReq / wValue / wIndex.
    let w = Setup::new(0x40, 0x05, 0x008C, 0, 1);
    let w_bytes = w.to_bytes();
    let w_expected: [u8; 8] = [0x40, 0x05, 0x8C, 0x00, 0x00, 0x00, 0x01, 0x00];
    if w_bytes != w_expected {
        return TestResult::Fail("Realtek write SETUP layout wrong");
    }
    if w.is_in() {
        return TestResult::Fail("0x40 bmRT must NOT be IN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/control",
    smoke_rtl8xxxu_efuse_read_setup_via_narf_usb
);

// ── Wacom tablet driver ─────────────────────────────────────────────

fn smoke_wacom_device_table_size() -> TestResult {
    use crate::hid::wacom_features::WACOM_DEVICES;
    if WACOM_DEVICES.len() < 40 {
        return TestResult::Fail("wacom device table has fewer than 40 entries");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/wacom", smoke_wacom_device_table_size);

fn smoke_wacom_intuos_pro_s_in_table() -> TestResult {
    use crate::hid::wacom_features::{lookup, WacomType};
    let f = match lookup(0x0314) {
        Some(f) => f,
        None => return TestResult::Fail("Intuos Pro S (PTH-460, PID=0x0314) not found"),
    };
    if f.device_type != WacomType::IntuosProS {
        return TestResult::Fail("Intuos Pro S device_type mismatch");
    }
    if f.pressure_max < 2047 {
        return TestResult::Fail("Intuos Pro S pressure_max too low");
    }
    if f.touch_max != 16 {
        return TestResult::Fail("Intuos Pro S touch_max should be 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/wacom", smoke_wacom_intuos_pro_s_in_table);

fn smoke_wacom_mode_select_feature_report() -> TestResult {
    use crate::hid::wacom_features::{
        encode_pen_mode_report, WACOM_FEATURE_REPORT_ID, WACOM_PEN_MODE_VALUE,
    };
    let mut buf = [0u8; 8];
    let n = encode_pen_mode_report(&mut buf);
    if n != 2 {
        return TestResult::Fail("encode_pen_mode_report returned wrong byte count");
    }
    if buf[0] != WACOM_FEATURE_REPORT_ID {
        return TestResult::Fail("pen mode report ID must be 2");
    }
    if buf[1] != WACOM_PEN_MODE_VALUE {
        return TestResult::Fail("pen mode value must be 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid/wacom",
    smoke_wacom_mode_select_feature_report
);

fn smoke_wacom_intuos_pro_pen_tip_and_pressure() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_PENABLED};
    use narf_input::{abs, init_global_ring, pop_absolute};

    init_global_ring(256);

    let mut state = match WacomState::new(0x0315) {
        Some(s) => s,
        None => return TestResult::Fail("Intuos Pro M not in device table"),
    };

    // Enter proximity (status byte 0xC0).
    let mut enter = [0u8; 10];
    enter[0] = REPORT_PENABLED;
    enter[1] = 0xC0;
    state.handle_report(&enter);

    // Pen data: pressure ~2000 out of 2047 (near full scale).
    // Pressure decode: t = (data[6]<<3)|((data[7]&0xC0)>>5)|(data[1]&1)
    // For p_raw=2000: data[6] = 2000>>3 = 250, data[7] upper = (2000&7)<<5 = 0.
    let p_raw: u32 = 2000;
    let mut data = [0u8; 10];
    data[0] = REPORT_PENABLED;
    data[1] = 0x01; // tip bit set
    data[2] = 0x01; // X high
    data[3] = 0xF4; // X low
    data[4] = 0x02; // Y high
    data[5] = 0x58; // Y low
    data[6] = (p_raw >> 3) as u8; // = 250
    data[7] = ((p_raw & 7) << 5) as u8;
    data[8] = 64u8; // tilt Y = 0 (offset by 64)

    let n = state.handle_report(&data);
    if n == 0 {
        return TestResult::Fail("pen data report emitted no events");
    }

    // Drain and find ABS_PRESSURE.
    let mut found_pressure = false;
    let mut p_val = 0i32;
    while let Some(e) = pop_absolute() {
        if e.axis == abs::ABS_PRESSURE {
            found_pressure = true;
            p_val = e.value;
        }
    }
    if !found_pressure {
        return TestResult::Fail("no ABS_PRESSURE event from Intuos Pro pen report");
    }
    if p_val < 500 {
        return TestResult::Fail("pressure value too low for near-full-scale input");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid/wacom",
    smoke_wacom_intuos_pro_pen_tip_and_pressure
);

fn smoke_wacom_intuos_pro_barrel_button() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_PENABLED};
    use narf_input::{btn, init_global_ring, pop_button};

    init_global_ring(256);
    let mut state = match WacomState::new(0x0315) {
        Some(s) => s,
        None => return TestResult::Fail("Intuos Pro M not in device table"),
    };

    let mut enter = [0u8; 10];
    enter[0] = REPORT_PENABLED;
    enter[1] = 0xC0;
    state.handle_report(&enter);

    // Barrel button 1: status bit1 = 0x02.
    let mut data = [0u8; 10];
    data[0] = REPORT_PENABLED;
    data[1] = 0x02; // barrel1 bit
    data[8] = 64; // tilt Y neutral
    state.handle_report(&data);

    while let Some(e) = pop_button() {
        if e.code == btn::BTN_STYLUS && e.pressed {
            return TestResult::Pass;
        }
    }
    TestResult::Fail("BTN_STYLUS (barrel1) not emitted from Intuos Pro pen report")
}
kernel_test_in!(
    "drivers/usb/hid/wacom",
    smoke_wacom_intuos_pro_barrel_button
);

fn smoke_wacom_intuos_pro_eraser_in_range() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_PENABLED};
    use narf_input::btn;

    let mut state = match WacomState::new(0x0315) {
        Some(s) => s,
        None => return TestResult::Fail("Intuos Pro M not in device table"),
    };

    // Enter proximity with eraser tool ID (data[3] bit3 → tool_id bit3 → eraser).
    // tool_id = (data[2]<<4)|(data[3]>>4) — so data[3]=0x80 gives lower nibble 0x08.
    let mut enter = [0u8; 10];
    enter[0] = REPORT_PENABLED;
    enter[1] = 0xC0;
    enter[3] = 0x80; // eraser marker
    state.handle_report(&enter);

    if state.pen[0].tool != btn::BTN_TOOL_RUBBER {
        return TestResult::Fail("eraser tool ID did not set BTN_TOOL_RUBBER");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid/wacom",
    smoke_wacom_intuos_pro_eraser_in_range
);

fn smoke_wacom_intuos_pro_tilt_signed() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_PENABLED};
    use narf_input::{abs, init_global_ring, pop_absolute};

    init_global_ring(256);
    let mut state = match WacomState::new(0x0315) {
        Some(s) => s,
        None => return TestResult::Fail("Intuos Pro M not in device table"),
    };

    let mut enter = [0u8; 10];
    enter[0] = REPORT_PENABLED;
    enter[1] = 0xC0;
    state.handle_report(&enter);

    // Tilt X = +32: packed into data[7] bits [6:1].
    // tilt_x = (((data[7] << 1) & 0x7E) | (data[8] >> 7)) - 64
    // For tilt_x_raw = 32+64 = 96: data[7] = (96 << 0) & 0x7E = 96 & 0x7E = 96
    // Simpler: set tilt_x bits so decoded value > 0 (positive tilt).
    let mut data = [0u8; 10];
    data[0] = REPORT_PENABLED;
    data[1] = 0x00;
    // data[7]: tilt_x = ((data[7]<<1)&0x7E | ...) - 64
    // Set to give +45: raw = 45+64=109; (109>>0)&0x7E=108, data[7]=54.
    data[7] = 54; // encodes tilt_x ≈ +44
                  // data[8]: tilt_y = (data[8] & 0x7F) - 64. For -20: 44 → data[8]=44.
    data[8] = 44; // encodes tilt_y ≈ -20

    state.handle_report(&data);

    let mut tilt_x = None;
    let mut tilt_y = None;
    while let Some(e) = pop_absolute() {
        if e.axis == abs::ABS_TILT_X {
            tilt_x = Some(e.value);
        }
        if e.axis == abs::ABS_TILT_Y {
            tilt_y = Some(e.value);
        }
    }

    if let Some(tx) = tilt_x {
        if tx <= 0 {
            return TestResult::Fail("ABS_TILT_X should be positive");
        }
    }
    if let Some(ty) = tilt_y {
        if ty >= 0 {
            return TestResult::Fail("ABS_TILT_Y should be negative");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/wacom", smoke_wacom_intuos_pro_tilt_signed);

fn smoke_wacom_bamboo_one_pen_decode() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_PENABLED};
    use narf_input::{abs, init_global_ring, pop_absolute};

    init_global_ring(256);
    let mut state = match WacomState::new(0x037A) {
        Some(s) => s,
        None => return TestResult::Fail("One by Wacom S not in device table"),
    };

    // Bamboo pen report: bit5 = in_prox, bit0 = tip.
    let mut pkt = [0u8; 10];
    pkt[0] = REPORT_PENABLED;
    pkt[1] = 0x21; // in_prox | tip
    pkt[2] = 0xD2; // X low byte = 210
    pkt[3] = 0x04; // X high byte
    pkt[4] = 0xE2; // Y low byte = 226
    pkt[5] = 0x15; // Y high byte → Y = 5602
    pkt[6] = 0xFF; // pressure low
    pkt[7] = 0x03; // pressure high bits

    let n = state.handle_report(&pkt);
    if n == 0 {
        return TestResult::Fail("One by Wacom pen report emitted no events");
    }

    let mut found_x = false;
    while let Some(e) = pop_absolute() {
        if e.axis == abs::ABS_X && e.value > 0 {
            found_x = true;
        }
    }
    if !found_x {
        return TestResult::Fail("no positive ABS_X from One by Wacom pen report");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/wacom", smoke_wacom_bamboo_one_pen_decode);

fn smoke_wacom_cintiq_pad_expresskeys() -> TestResult {
    use crate::hid::wacom::{WacomState, REPORT_INTUOSPAD};
    use narf_input::{init_global_ring, pop_button};

    init_global_ring(256);
    let mut state = match WacomState::new(0x00FA) {
        Some(s) => s,
        None => return TestResult::Fail("Cintiq 22HD not in device table"),
    };

    // Cintiq 22HD pad: buttons = (data[8]<<10)|(data[7]&0x01)<<9|data[6]<<1|data[5]&0x01
    // Press button 0 (data[5] |= 0x01).
    let mut pkt = [0u8; 16];
    pkt[0] = REPORT_INTUOSPAD;
    pkt[5] = 0x01; // button 0

    let n = state.handle_report(&pkt);
    if n == 0 {
        return TestResult::Fail("Cintiq pad report emitted no events");
    }

    while let Some(e) = pop_button() {
        if e.code == 0x100 && e.pressed {
            // BTN_0
            return TestResult::Pass;
        }
    }
    TestResult::Fail("BTN_0 not pressed in Cintiq ExpressKey report")
}
kernel_test_in!("drivers/usb/hid/wacom", smoke_wacom_cintiq_pad_expresskeys);

// ── drivers/usb/hub — protocol-level smokes ────────────────────────
// Required by the hwmon/serial/hub task spec.

/// Hub descriptor decode: `bNbrPorts` and `wHubCharacteristics`
/// are parsed correctly from a synthetic 9-byte descriptor buffer.
///
/// Reference: USB 2.0 §11.23.2.1 (Hub Descriptor), Table 11-13.
/// Linux hub.c `usb_hub_descriptor` / `hub_configure` ~L3200.
fn smoke_usb_hub_descriptor_decode() -> TestResult {
    use crate::hub::{HubDescriptor, HUB_DESC_TYPE};
    // Synthetic 9-byte USB 2.0 hub descriptor:
    //   bLength=9, bDescriptorType=0x29, bNbrPorts=4,
    //   wHubCharacteristics=0x0000 (ganged power, no OC),
    //   bPwrOn2PwrGood=50 (100ms), bHubContrCurrent=100mA,
    //   DeviceRemovable=0x00, PortPwrCtrlMask=0xFF
    let buf: [u8; 9] = [0x09, HUB_DESC_TYPE, 4, 0x00, 0x00, 50, 100, 0x00, 0xFF];
    let desc = match HubDescriptor::decode(&buf) {
        Some(d) => d,
        None => return TestResult::Fail("HubDescriptor::decode returned None for valid buffer"),
    };
    if desc.num_ports != 4 {
        return TestResult::Fail("bNbrPorts decode wrong (expected 4)");
    }
    if desc.characteristics != 0x0000 {
        return TestResult::Fail("wHubCharacteristics decode wrong (expected 0x0000)");
    }
    if desc.poweron_time_2ms != 50 {
        return TestResult::Fail("bPwrOn2PwrGood decode wrong (expected 50)");
    }
    if desc.controller_current != 100 {
        return TestResult::Fail("bHubContrCurrent decode wrong (expected 100)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub", smoke_usb_hub_descriptor_decode);

/// The target 05e3:0610 Genesys hub advertises protocol 2 (one TT per
/// port). A full-speed child such as 10ab:9309 must carry the parent
/// slot, downstream port, and Hub Descriptor think time into its xHCI
/// Slot Context; otherwise split transactions are scheduled against
/// the wrong TT.
fn smoke_usb_hub_multi_tt_child_topology() -> TestResult {
    use crate::attach::route_tier;
    use crate::hub::{HubDescriptor, UsbHub, HUB_PROTOCOL_MULTI_TT};
    use crate::xhci::PortSpeed;

    let hub = UsbHub {
        slot_id: 7,
        iface_num: 0,
        descriptor: HubDescriptor {
            num_ports: 4,
            // TT think-time encoding 3 = 32 full-speed bit times.
            characteristics: 3 << 5,
            poweron_time_2ms: 50,
            controller_current: 100,
        },
        speed: PortSpeed::High,
        device_protocol: HUB_PROTOCOL_MULTI_TT,
    };
    if !hub.is_multi_tt() {
        return TestResult::Fail("protocol 2 hub was not classified multi-TT");
    }
    if route_tier(0) != 0
        || route_tier(0x0000F) != 1
        || route_tier(0x00021) != 2
        || route_tier(0xFEDCB) != 5
    {
        return TestResult::Fail("xHCI route tier decode mismatch");
    }
    let topology = hub.child_topology(0, 0, 1, PortSpeed::Full);
    if topology.route_string != 1 {
        return TestResult::Fail("downstream route string mismatch");
    }
    if topology.parent_hub_slot_id != 7 || topology.parent_hub_port != 1 {
        return TestResult::Fail("parent TT slot/port missing");
    }
    if topology.tt_think_time != 3 {
        return TestResult::Fail("hub TT think time not propagated");
    }

    let high_speed = hub.child_topology(0, 0, 2, PortSpeed::High);
    if high_speed.parent_hub_slot_id != 0
        || high_speed.parent_hub_port != 0
        || high_speed.tt_think_time != 0
    {
        return TestResult::Fail("high-speed child incorrectly received TT metadata");
    }

    let full_speed_hub = UsbHub {
        speed: PortSpeed::Full,
        ..hub
    };
    if full_speed_hub.is_multi_tt() {
        return TestResult::Fail("full-speed hub incorrectly classified multi-TT");
    }
    let no_translator = full_speed_hub.child_topology(0, 0, 1, PortSpeed::Low);
    if no_translator.parent_hub_slot_id != 0
        || no_translator.parent_hub_port != 0
        || no_translator.tt_think_time != 0
    {
        return TestResult::Fail("full-speed hub incorrectly supplied TT metadata");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub", smoke_usb_hub_multi_tt_child_topology);

/// Hub Port Status decode: connection-change, over-current, and reset
/// bits are at the correct positions in the 32-bit GET_STATUS word.
///
/// Reference: USB 2.0 §11.24.2.7 (GetPortStatus), Table 11-15 (wPortStatus),
/// Table 11-16 (wPortChange). Linux hub.c `hub_port_status` ~L665.
fn smoke_usb_hub_port_status_decode() -> TestResult {
    use crate::hub::{
        C_PORT_CONNECTION, C_PORT_OVER_CURRENT, C_PORT_RESET, PSTAT_CONNECTION, PSTAT_ENABLE,
        PSTAT_OVER_CURRENT, PSTAT_RESET,
    };
    // wPortStatus: bit 0 = connection, 1 = enable, 3 = over-current, 4 = reset.
    if PSTAT_CONNECTION != 1 << 0 {
        return TestResult::Fail("PSTAT_CONNECTION must be bit 0");
    }
    if PSTAT_ENABLE != 1 << 1 {
        return TestResult::Fail("PSTAT_ENABLE must be bit 1");
    }
    if PSTAT_OVER_CURRENT != 1 << 3 {
        return TestResult::Fail("PSTAT_OVER_CURRENT must be bit 3");
    }
    if PSTAT_RESET != 1 << 4 {
        return TestResult::Fail("PSTAT_RESET must be bit 4");
    }
    // wPortChange change-bits map to feature codes (C_PORT_*):
    // C_PORT_CONNECTION = 16, C_PORT_OVER_CURRENT = 19, C_PORT_RESET = 20.
    // These are feature selector values for CLEAR_FEATURE, not bit indices.
    if C_PORT_CONNECTION != 16 {
        return TestResult::Fail("C_PORT_CONNECTION feature selector should be 16");
    }
    if C_PORT_OVER_CURRENT != 19 {
        return TestResult::Fail("C_PORT_OVER_CURRENT feature selector should be 19");
    }
    if C_PORT_RESET != 20 {
        return TestResult::Fail("C_PORT_RESET feature selector should be 20");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hub", smoke_usb_hub_port_status_decode);

/// SET_FEATURE PORT_POWER encodes the correct bmRequestType + bRequest
/// + wValue triple. This test verifies that the constants used in
///   `UsbHub::attach` (which issues SET_FEATURE PORT_POWER for each port)
///   match the USB 2.0 Class-Specific Request table.
///
/// Reference: USB 2.0 §11.24.2.7 Table 11-17 (Port Feature Selectors).
/// Linux hub.c `hub_power_on` ~L487.
fn smoke_usb_hub_set_feature_port_power_encode() -> TestResult {
    use crate::hub::{PORT_POWER, REQ_SET_FEATURE, RT_HOST_TO_DEV_CLASS_OTHER};
    // bmRequestType = 0x23: Host-to-Device, Class, Other (port).
    if RT_HOST_TO_DEV_CLASS_OTHER != 0x23 {
        return TestResult::Fail("bmRequestType for SET_FEATURE(port) should be 0x23");
    }
    // bRequest = 0x03 (SET_FEATURE per USB §9.4.9).
    if REQ_SET_FEATURE != 0x03 {
        return TestResult::Fail("bRequest SET_FEATURE should be 0x03");
    }
    // wValue = PORT_POWER = 8 (USB 2.0 §11.24.2.7.2 Table 11-17).
    if PORT_POWER != 8 {
        return TestResult::Fail("PORT_POWER feature selector should be 8");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hub",
    smoke_usb_hub_set_feature_port_power_encode
);

// ── UAC topology / bind / card fixtures (queue 29, #777) ───────────
//
// Modelled devices: a UAC1 headset (playback + capture) and a
// UAC2 playback DAC with a programmable clock source. The blobs
// are hand-assembled configuration descriptors; the assertions
// pin the topology walk, the bind conversation ORDER, card
// publication, the pump, and detach.

/// UAC1 headset: AC iface 0 (IT 1 USB-streaming → FU 2 → OT 3
/// speaker; IT 4 mic → FU 5 → OT 6 USB-streaming), AS iface 1
/// playback (alt 1: stereo 16-bit 44.1/48 kHz, OUT ep 0x01,
/// 192 B packets), AS iface 2 capture (alt 1: mono 16-bit
/// 48 kHz, IN ep 0x82, 96 B packets).
fn uac1_headset_config() -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    let mut add = |d: &[u8]| v.extend_from_slice(d);
    add(&[9, 0x02, 0, 0, 3, 1, 0, 0x80, 50]); // CONFIGURATION
    add(&[9, 0x04, 0, 0, 0, 0x01, 0x01, 0x00, 0]); // iface 0 AC (UAC1)
    add(&[10, 0x24, 0x01, 0x00, 0x01, 62, 0, 2, 1, 2]); // AC HEADER
    add(&[12, 0x24, 0x02, 1, 0x01, 0x01, 0, 2, 0x03, 0x00, 0, 0]); // IT 1
    add(&[
        13, 0x24, 0x06, 2, 1, 2, 0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0,
    ]); // FU 2
    add(&[9, 0x24, 0x03, 3, 0x01, 0x03, 0, 2, 0]); // OT 3 speaker
    add(&[12, 0x24, 0x02, 4, 0x01, 0x02, 0, 1, 0x01, 0x00, 0, 0]); // IT 4 mic
    add(&[11, 0x24, 0x06, 5, 4, 2, 0x03, 0x00, 0x02, 0x00, 0]); // FU 5
    add(&[9, 0x24, 0x03, 6, 0x01, 0x01, 0, 5, 0]); // OT 6 streaming
    add(&[9, 0x04, 1, 0, 0, 0x01, 0x02, 0x00, 0]); // AS 1 alt 0
    add(&[7, 0x24, 0x01, 1, 0, 0x01, 0x00]); // AS_GENERAL link 1 PCM
    add(&[9, 0x04, 1, 1, 1, 0x01, 0x02, 0x00, 0]); // AS 1 alt 1
    add(&[7, 0x24, 0x01, 1, 0, 0x01, 0x00]);
    // FORMAT_TYPE_I: stereo, subframe 2, 16-bit, {44100, 48000}
    add(&[
        14, 0x24, 0x02, 0x01, 2, 2, 16, 2, 0x44, 0xAC, 0x00, 0x80, 0xBB, 0x00,
    ]);
    add(&[9, 0x05, 0x01, 0x05, 0xC0, 0x00, 1, 0, 0]); // EP OUT 192 B
    add(&[7, 0x25, 0x01, 0x01, 0, 0x00, 0x00]); // CS_ENDPOINT freq ctl
    add(&[9, 0x04, 2, 0, 0, 0x01, 0x02, 0x00, 0]); // AS 2 alt 0
    add(&[7, 0x24, 0x01, 6, 0, 0x01, 0x00]); // AS_GENERAL link 6 PCM
    add(&[9, 0x04, 2, 1, 1, 0x01, 0x02, 0x00, 0]); // AS 2 alt 1
    add(&[7, 0x24, 0x01, 6, 0, 0x01, 0x00]);
    // FORMAT_TYPE_I: mono, subframe 2, 16-bit, {48000}
    add(&[11, 0x24, 0x02, 0x01, 1, 2, 16, 1, 0x80, 0xBB, 0x00]);
    add(&[9, 0x05, 0x82, 0x05, 96, 0x00, 1, 0, 0]); // EP IN 96 B
    v
}

/// UAC2 playback DAC: AC iface 0 (clock source 9 → IT 1
/// USB-streaming → FU 2 → OT 3 speaker), AS iface 1 (alt 1:
/// stereo 24-in-32, OUT ep 0x01, 768 B packets).
fn uac2_dac_config() -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    let mut add = |d: &[u8]| v.extend_from_slice(d);
    add(&[9, 0x02, 0, 0, 2, 1, 0, 0x80, 50]); // CONFIGURATION
    add(&[9, 0x04, 0, 0, 0, 0x01, 0x01, 0x20, 0]); // iface 0 AC (UAC2)
    add(&[9, 0x24, 0x01, 0x00, 0x02, 0x09, 55, 0, 0]); // HEADER v2
    add(&[8, 0x24, 0x0A, 9, 2, 0x03, 1, 0]); // CLOCK_SOURCE 9, programmable
    add(&[
        18, 0x24, 0x02, 1, 0x01, 0x01, 0, 2, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]); // IT 1
    add(&[
        18, 0x24, 0x06, 2, 1, 0x0F, 0, 0, 0, 0x0C, 0, 0, 0, 0x0C, 0, 0, 0, 0,
    ]); // FU 2
    add(&[12, 0x24, 0x03, 3, 0x01, 0x03, 0, 2, 0, 0, 0, 0]); // OT 3 speaker
    add(&[9, 0x04, 1, 0, 0, 0x01, 0x02, 0x20, 0]); // AS 1 alt 0
    add(&[16, 0x24, 0x01, 1, 0, 1, 1, 0, 0, 0, 2, 3, 0, 0, 0, 0]); // AS_GENERAL v2
    add(&[9, 0x04, 1, 1, 1, 0x01, 0x02, 0x20, 0]); // AS 1 alt 1
    add(&[16, 0x24, 0x01, 1, 0, 1, 1, 0, 0, 0, 2, 3, 0, 0, 0, 0]);
    add(&[6, 0x24, 0x02, 0x01, 4, 24]); // FORMAT_TYPE_I v2: 24-in-32
    add(&[9, 0x05, 0x01, 0x05, 0x00, 0x03, 1, 0, 0]); // EP OUT 768 B
    v
}

fn smoke_uac_topology_walk_uac1_headset() -> TestResult {
    use crate::uac::{UacTopology, UacVersion};
    let cfg = uac1_headset_config();
    let topo = match UacTopology::parse(&cfg) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("UAC1 topology parse"),
    };
    if topo.version != UacVersion::V1 || topo.ac_iface != 0 {
        return TestResult::Fail("UAC1 version / AC iface");
    }
    if topo.terminals.len() != 4 || topo.feature_units.len() != 2 {
        return TestResult::Fail("UAC1 terminal / FU counts");
    }
    if topo.streams.len() != 2 {
        return TestResult::Fail("UAC1 stream count");
    }
    let pb = &topo.streams[0];
    let cap = &topo.streams[1];
    if pb.iface != 1 || pb.terminal_link != 1 || pb.is_capture() != Some(false) {
        return TestResult::Fail("UAC1 playback stream shape");
    }
    if cap.iface != 2 || cap.terminal_link != 6 || cap.is_capture() != Some(true) {
        return TestResult::Fail("UAC1 capture stream shape");
    }
    if pb.alts.len() != 2 || pb.alts[1].ep_addr != 0x01 || pb.alts[1].ep_max_packet != 192 {
        return TestResult::Fail("UAC1 playback alts");
    }
    let choice = match crate::uac::choose_stream_default(pb, topo.version) {
        Some(c) => c,
        None => return TestResult::Fail("UAC1 playback default choice"),
    };
    if choice.alt_setting != 1 || choice.rate_hz != 48_000 || choice.channels != 2 {
        return TestResult::Fail("UAC1 playback choice = alt 1, 48 kHz stereo");
    }
    let fu = match topo.feature_unit_for(1) {
        Some(f) => f,
        None => return TestResult::Fail("UAC1 FU on playback path"),
    };
    if fu.id != 2 || fu.master_controls & crate::uac::FEATURE_VOLUME == 0 {
        return TestResult::Fail("UAC1 playback FU id / volume bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_topology_walk_uac1_headset);

fn smoke_uac_topology_walk_uac2_clock() -> TestResult {
    use crate::uac::{UacTopology, UacVersion};
    let cfg = uac2_dac_config();
    let topo = match UacTopology::parse(&cfg) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("UAC2 topology parse"),
    };
    if topo.version != UacVersion::V2 {
        return TestResult::Fail("UAC2 version");
    }
    if topo.terminals.len() != 2 || topo.feature_units.len() != 1 {
        return TestResult::Fail("UAC2 terminal / FU counts");
    }
    if topo.clocks.len() != 1 {
        return TestResult::Fail("UAC2 clock count");
    }
    let clock = match topo.clock_for_terminal(1) {
        Some(c) => c,
        None => return TestResult::Fail("UAC2 clock resolution for terminal 1"),
    };
    if clock.id != 9 || !clock.freq_programmable {
        return TestResult::Fail("UAC2 clock id / programmable");
    }
    let stream = &topo.streams[0];
    let choice = match crate::uac::choose_stream_default(stream, topo.version) {
        Some(c) => c,
        None => return TestResult::Fail("UAC2 default choice"),
    };
    if choice.rate_hz != 48_000 || choice.channels != 2 || choice.subframe_size != 4 {
        return TestResult::Fail("UAC2 choice = 48 kHz, 24-in-32 stereo");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_topology_walk_uac2_clock);

fn smoke_uac_clock_rate_choice() -> TestResult {
    use crate::uac::{choose_clock_rate, ClockSubrange};
    let r = |min_hz, max_hz, res_hz| ClockSubrange {
        min_hz,
        max_hz,
        res_hz,
    };
    if choose_clock_rate(&[r(44_100, 48_000, 100)]) != Some(48_000) {
        return TestResult::Fail("clock choice prefers 48k in range");
    }
    if choose_clock_rate(&[r(96_000, 192_000, 0)]) != Some(96_000) {
        return TestResult::Fail("clock choice falls to lowest subrange min");
    }
    if choose_clock_rate(&[r(44_100, 44_100, 0), r(48_000, 48_000, 0)]) != Some(48_000) {
        return TestResult::Fail("clock choice scans all subranges");
    }
    if choose_clock_rate(&[]).is_some() {
        return TestResult::Fail("clock choice empty = None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_clock_rate_choice);

fn smoke_uac_bind_plan_uac1_order() -> TestResult {
    use crate::uac::{build_bind_plan, StepData, UacTopology};
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    choices.sort_by_key(|c| c.capture);
    let plan = build_bind_plan(&topo, 1, &choices);
    // SET_CONFIGURATION + per direction (SET_INTERFACE, SET_CUR
    // freq, GET_MIN, GET_MAX, GET_RES, SET_CUR vol, SET_CUR mute).
    if plan.len() != 15 {
        return TestResult::Fail("UAC1 plan length = 15");
    }
    let s0 = &plan[0];
    if s0.request_type != 0x00 || s0.request != 0x09 || s0.value != 1 || !s0.fatal {
        return TestResult::Fail("plan[0] = SET_CONFIGURATION");
    }
    let s1 = &plan[1];
    if s1.request != crate::control::REQ_SET_INTERFACE || s1.value != 1 || s1.index != 1 {
        return TestResult::Fail("plan[1] = SET_INTERFACE playback alt 1");
    }
    let s2 = &plan[2];
    if s2.request_type != 0x22 || s2.request != crate::uac::REQ_SET_CUR || s2.index != 0x01 {
        return TestResult::Fail("plan[2] = SET_CUR freq on OUT ep");
    }
    match &s2.data {
        StepData::Out(b) if b.as_slice() == [0x80, 0xBB, 0x00] => {}
        _ => return TestResult::Fail("plan[2] payload = 48000 24-bit LE"),
    }
    let s3 = &plan[3];
    if s3.request != crate::uac::REQ_GET_MIN || s3.fatal {
        return TestResult::Fail("plan[3] = non-fatal GET_MIN");
    }
    if s3.index != crate::uac::fu_windex(2, 0) {
        return TestResult::Fail("plan[3] targets playback FU 2");
    }
    let s6 = &plan[6];
    if s6.request != crate::uac::REQ_SET_CUR
        || s6.value != crate::uac::fu_wvalue(crate::uac::FU_CS_VOLUME, 0)
    {
        return TestResult::Fail("plan[6] = SET_CUR volume");
    }
    let s7 = &plan[7];
    if s7.value != crate::uac::fu_wvalue(crate::uac::FU_CS_MUTE, 0) {
        return TestResult::Fail("plan[7] = SET_CUR mute");
    }
    let s8 = &plan[8];
    if s8.request != crate::control::REQ_SET_INTERFACE || s8.index != 2 {
        return TestResult::Fail("plan[8] = SET_INTERFACE capture");
    }
    let last = &plan[14];
    if last.index != crate::uac::fu_windex(5, 0) {
        return TestResult::Fail("plan[14] targets capture FU 5");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_bind_plan_uac1_order);

fn smoke_uac_bind_plan_uac2_clock() -> TestResult {
    use crate::uac::{build_bind_plan, ResponseSlot, StepData, UacTopology};
    let cfg = uac2_dac_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let choice = crate::uac::choose_stream_default(&topo.streams[0], topo.version).expect("choice");
    let plan = build_bind_plan(&topo, 1, &[choice]);
    // SET_CONFIGURATION, SET_INTERFACE, GET_RANGE, SET_CUR clock,
    // GET_MIN, GET_MAX, GET_RES, SET_CUR vol, SET_CUR mute.
    if plan.len() != 9 {
        return TestResult::Fail("UAC2 plan length = 9");
    }
    let rng = &plan[2];
    if rng.request != crate::uac::REQ_RANGE || rng.request_type != 0xA1 || rng.fatal {
        return TestResult::Fail("plan[2] = non-fatal GET_RANGE");
    }
    if rng.index != (9 << 8) || rng.slot != (ResponseSlot::ClockRange { capture: false }) {
        return TestResult::Fail("plan[2] addresses clock 9, range slot");
    }
    let set = &plan[3];
    if set.request != crate::uac::REQ_CUR || set.index != (9 << 8) {
        return TestResult::Fail("plan[3] = SET_CUR on clock 9");
    }
    if set.resolve_rate_from_range != Some(false) {
        return TestResult::Fail("plan[3] resolves rate from RANGE");
    }
    match &set.data {
        StepData::Out(b) if b.as_slice() == 48_000u32.to_le_bytes() => {}
        _ => return TestResult::Fail("plan[3] payload = 48000 u32 LE"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_bind_plan_uac2_clock);

fn smoke_uac_card_publication() -> TestResult {
    use crate::uac::{BindOutcome, UacTopology};
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state =
        crate::uac_card::UacCardState::from_bind(7, &topo, &choices, &BindOutcome::default());
    let idx = match crate::uac_card::register_card(&state) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("register_card"),
    };
    let pb = match narf_drivers_sound::default_hw_params(idx, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("card visible in sound registry (playback)"),
    };
    if pb.rate != narf_drivers_sound::SampleRate::R48000
        || pb.channels != narf_drivers_sound::ChannelCount::Stereo
        || pb.format != narf_drivers_sound::format::SampleFormat::S16LE
    {
        return TestResult::Fail("playback default params = 48k stereo S16LE");
    }
    let cap = match narf_drivers_sound::default_hw_params(idx, true) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("card visible in sound registry (capture)"),
    };
    if cap.channels != narf_drivers_sound::ChannelCount::Mono {
        return TestResult::Fail("capture default params = mono");
    }
    state.detach();
    if narf_drivers_sound::default_hw_params(idx, false).is_ok() {
        return TestResult::Fail("card gone after detach");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_card_publication);

#[derive(Clone)]
struct FakeIsoState {
    out_log: alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>>,
    in_queue: alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>>,
}

impl FakeIsoState {
    fn new() -> Self {
        Self {
            out_log: alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                alloc::vec::Vec::new(),
            )),
            in_queue: alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                alloc::vec::Vec::new(),
            )),
        }
    }
}

#[derive(Clone)]
struct FakeIso(FakeIsoState);

impl core::fmt::Debug for FakeIso {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FakeIso")
    }
}

impl crate::uac_card::IsoTransfer for FakeIso {
    fn isoch_out(&self, data: &[u8]) -> Result<usize, narf_drivers_sound::SoundError> {
        self.0.out_log.lock().extend_from_slice(data);
        Ok(data.len())
    }
    fn isoch_in(&self, out: &mut [u8]) -> Result<usize, narf_drivers_sound::SoundError> {
        let mut q = self.0.in_queue.lock();
        let n = out.len().min(q.len());
        out[..n].copy_from_slice(&q[..n]);
        q.drain(..n);
        Ok(n)
    }
}

fn smoke_uac_pump_moves_frames() -> TestResult {
    use crate::uac::{BindOutcome, UacTopology};
    use narf_drivers_sound::hardware::PcmHardware;
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state =
        crate::uac_card::UacCardState::from_bind(7, &topo, &choices, &BindOutcome::default());

    // Playback: 48 frames of pattern → one packet out; an empty
    // ring still clocks a full silence packet.
    let pb_iso = FakeIso(FakeIsoState::new());
    let mut pb = match crate::uac_card::UacStream::with_iso(
        state.clone(),
        false,
        alloc::boxed::Box::new(pb_iso.clone()),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("playback lease"),
    };
    let dev: &dyn narf_drivers_sound::hardware::PcmDevice =
        &crate::uac_card::UsbAudioCard(state.clone());
    let params = dev.default_params(false);
    if pb.configure(params).is_err() || pb.prepare().is_err() || pb.start().is_err() {
        return TestResult::Fail("playback configure/prepare/start");
    }
    let pattern: alloc::vec::Vec<u8> = (0..192u32).map(|i| (i % 251) as u8).collect();
    if pb.write(&pattern) != Ok(192) {
        return TestResult::Fail("playback write accepts 192 B");
    }
    if pb.pump_once().is_err() {
        return TestResult::Fail("playback pump step");
    }
    {
        let log = pb_iso.0.out_log.lock();
        if log.as_slice() != pattern.as_slice() {
            return TestResult::Fail("pump moved the exact queued bytes");
        }
    }
    if pb.pointer() != 48 {
        return TestResult::Fail("pointer advanced 48 frames");
    }
    if pb.pump_once().is_err() {
        return TestResult::Fail("playback underrun pump step");
    }
    {
        let log = pb_iso.0.out_log.lock();
        if log.len() != 384 || log[192..].iter().any(|b| *b != 0) {
            return TestResult::Fail("underrun clocks silence");
        }
    }
    if pb.stop().is_err() {
        return TestResult::Fail("playback stop");
    }

    // Capture: a queued device packet lands in the ring and
    // read() returns it verbatim.
    let cap_iso = FakeIso(FakeIsoState::new());
    let mic: alloc::vec::Vec<u8> = (0..96u32).map(|i| (200 - i) as u8).collect();
    cap_iso.0.in_queue.lock().extend_from_slice(&mic);
    let mut cap = match crate::uac_card::UacStream::with_iso(
        state.clone(),
        true,
        alloc::boxed::Box::new(cap_iso),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("capture lease"),
    };
    let cparams = dev.default_params(true);
    if cap.configure(cparams).is_err() || cap.prepare().is_err() || cap.start().is_err() {
        return TestResult::Fail("capture configure/prepare/start");
    }
    if cap.pump_once().is_err() {
        return TestResult::Fail("capture pump step");
    }
    let mut out = [0u8; 96];
    match cap.read(&mut out) {
        Ok(96) if out == mic.as_slice() => {}
        _ => return TestResult::Fail("capture read returns the device packet"),
    }
    if cap.pointer() != 48 {
        return TestResult::Fail("capture pointer advanced 48 frames");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_pump_moves_frames);

fn smoke_uac_detach_removes_registry_and_card() -> TestResult {
    use crate::uac::{BindOutcome, UacTopology};
    crate::uac::__reset_uac_for_test();
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state =
        crate::uac_card::UacCardState::from_bind(9, &topo, &choices, &BindOutcome::default());
    let idx = match crate::uac_card::register_card(&state) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("register card for detach fixture"),
    };
    let (out_dci, in_dci) = crate::uac::find_audio_streaming_iso_eps(&cfg);
    crate::uac::__push_uac_for_test(crate::uac::UacDevice {
        slot_id: 9,
        ac_iface: 0,
        iso_out_dci: out_dci,
        iso_in_dci: in_dci,
        card: Some(state),
        card_error: None,
    });
    if crate::uac::attached_uac_count() != 1 {
        return TestResult::Fail("registry holds the bound device");
    }
    if crate::uac::unbind_all_uac() != 1 {
        return TestResult::Fail("unbind removes one entry");
    }
    if crate::uac::attached_uac_count() != 0 {
        return TestResult::Fail("registry empty after unbind");
    }
    if narf_drivers_sound::default_hw_params(idx, false).is_ok() {
        return TestResult::Fail("card unregistered after unbind");
    }
    TestResult::Pass
}

// ── UVC streaming composition: end-to-end fixture (#803 + #812) ──────
//
// A modelled UVC camera (descriptor set + probe/commit state machine
// + isochronous packet source) behind the `UvcTransport` seam, driven
// through the REAL V4L2 ioctl dispatch: S_FMT → REQBUFS → QBUF →
// STREAMON must run the probe/commit negotiation, configure the
// endpoint, and select the streaming alternate before any frame can
// land; DQBUF must return the modelled payload bytes; STREAMOFF must
// stop the pump and release the alternate. The transfer log asserts
// the conversation order, not just the outcomes. The composition code
// under test is the production code — only the transport differs.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use narf_lib::sync::IrqSafeSpinLock;

/// One recorded transfer in the modelled device conversation.
/// Probe/commit payloads are variable-length: 26 bytes for a 1.0
/// device, 34 for a 1.1+ device.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FixtureXfer {
    SetConfiguration,
    SetCurProbe { payload: Vec<u8> },
    GetCurProbe,
    SetCurCommit { payload: Vec<u8> },
    ConfigureEndpoints { ep_addr: u8 },
    SetInterface { interface: u16, alt: u16 },
    IsochIn,
    OtherControlOut { request: u8, value: u16 },
    OtherControlIn { request: u8, value: u16 },
}

struct FixtureState {
    log: Vec<FixtureXfer>,
    /// Last SET_CUR(PROBE) payload; GET_CUR(PROBE) answers from it.
    probe: Option<Vec<u8>>,
    /// The modelled device's clock (its VC HEADER clock), answered in
    /// the 1.1+ extension block of GET_CUR(PROBE).
    clock_frequency: u32,
    fail_probe: bool,
    fail_set_interface: bool,
    packets: VecDeque<Vec<u8>>,
}

/// Modelled UVC device behind the [`crate::uvc::UvcTransport`] seam.
/// Its GET_CUR(PROBE) behaves like a real device: it accepts the
/// host's format/frame/interval and fills in its own
/// `dwMaxVideoFrameSize` (640×480 YUYV) and
/// `dwMaxPayloadTransferSize` (1024, matching the alt-1 endpoint);
/// for a 34-byte probe it additionally answers its clock and the
/// 1.0 payload versions it accepts.
struct FixtureTransport {
    state: IrqSafeSpinLock<FixtureState>,
}

impl FixtureTransport {
    fn new(fail_probe: bool, fail_set_interface: bool, packets: Vec<Vec<u8>>) -> Self {
        Self {
            state: IrqSafeSpinLock::new(FixtureState {
                log: Vec::new(),
                probe: None,
                clock_frequency: 0,
                fail_probe,
                fail_set_interface,
                packets: packets.into(),
            }),
        }
    }

    fn log(&self) -> Vec<FixtureXfer> {
        self.state.lock().log.clone()
    }

    /// Set the modelled device's VC HEADER clock, answered in the
    /// 1.1+ extension block of GET_CUR(PROBE).
    fn set_clock(&self, hz: u32) {
        self.state.lock().clock_frequency = hz;
    }

    /// Stage a packet for the modelled device to source, as if it
    /// arrived after the fixture was set up — including while a pump
    /// is parked waiting for one.
    fn stage_packet(&self, packet: Vec<u8>) {
        self.state.lock().packets.push_back(packet);
    }

    /// Packets currently staged (consumed one per `isoch_in`).
    fn pending_packets(&self) -> usize {
        self.state.lock().packets.len()
    }
}

/// A future that pends until the modelled device has a packet staged.
///
/// Real isochronous transfers complete only when the device sources a
/// packet; on the silent alternate setting 0 a parked transfer may
/// not resolve until the *next* stream starts. Modelling the park
/// faithfully (rather than returning empty reads) is what lets the
/// generation-toggle smoke hold a pump mid-await across
/// STREAMOFF/STREAMON — the interleave the stream-generation
/// protocol exists for. The fixture re-polls manually in place of the
/// transfer-event wake.
struct PacketStaged<'a> {
    state: &'a IrqSafeSpinLock<FixtureState>,
}

impl Future for PacketStaged<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.state.lock().packets.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

impl crate::uvc::UvcTransport for FixtureTransport {
    async fn control_out(
        &self,
        _slot_id: u8,
        _bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<usize, crate::xhci::XhciError> {
        use crate::xhci::XhciError;
        let mut state = self.state.lock();
        if b_request == crate::hid::STD_REQ_SET_CONFIGURATION {
            state.log.push(FixtureXfer::SetConfiguration);
            return Ok(data.len());
        }
        if b_request == crate::control::REQ_SET_INTERFACE {
            state.log.push(FixtureXfer::SetInterface {
                interface: w_index,
                alt: w_value,
            });
            if state.fail_set_interface && w_value != 0 {
                return Err(XhciError::CmdFailed(0xE1));
            }
            return Ok(data.len());
        }
        if b_request == crate::uvc::VS_REQ_SET_CUR && w_value == crate::uvc::VS_PROBE_CONTROL {
            let payload = data.to_vec();
            state.log.push(FixtureXfer::SetCurProbe {
                payload: payload.clone(),
            });
            if state.fail_probe {
                return Err(XhciError::CmdFailed(0xE2));
            }
            state.probe = Some(payload);
            return Ok(data.len());
        }
        if b_request == crate::uvc::VS_REQ_SET_CUR && w_value == crate::uvc::VS_COMMIT_CONTROL {
            state.log.push(FixtureXfer::SetCurCommit {
                payload: data.to_vec(),
            });
            return Ok(data.len());
        }
        state.log.push(FixtureXfer::OtherControlOut {
            request: b_request,
            value: w_value,
        });
        Ok(data.len())
    }

    async fn control_in(
        &self,
        _slot_id: u8,
        _bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        _w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, crate::xhci::XhciError> {
        let mut state = self.state.lock();
        if b_request == crate::uvc::VS_REQ_GET_CUR && w_value == crate::uvc::VS_PROBE_CONTROL {
            state.log.push(FixtureXfer::GetCurProbe);
            let mut accepted = state.probe.clone().unwrap_or_default();
            // The device fills in its own frame size + payload size.
            if accepted.len() >= 26 {
                accepted[18..22].copy_from_slice(&614_400u32.to_le_bytes());
                accepted[22..26].copy_from_slice(&1024u32.to_le_bytes());
            }
            // A 1.1+ device answers the extension block: its clock and
            // the 1.0 payload versions it accepts.
            if accepted.len() >= 34 {
                accepted[26..30].copy_from_slice(&state.clock_frequency.to_le_bytes());
                accepted[30] = 0;
                accepted[31] = 0x10;
                accepted[32] = 0x10;
                accepted[33] = 0x10;
            }
            let n = out.len().min(accepted.len());
            out[..n].copy_from_slice(&accepted[..n]);
            return Ok(n);
        }
        state.log.push(FixtureXfer::OtherControlIn {
            request: b_request,
            value: w_value,
        });
        Ok(0)
    }

    async fn configure_endpoints(
        &self,
        _slot_id: u8,
        endpoints: &[crate::xhci::EndpointConfig],
    ) -> Result<(), crate::xhci::XhciError> {
        let mut state = self.state.lock();
        for endpoint in endpoints {
            state.log.push(FixtureXfer::ConfigureEndpoints {
                ep_addr: endpoint.ep_addr,
            });
        }
        Ok(())
    }

    async fn isoch_in(
        &self,
        _slot_id: u8,
        _dci: u8,
        out: &mut [u8],
    ) -> Result<usize, crate::xhci::XhciError> {
        // Park until the device sources a packet, like the real
        // transfer: never an empty read.
        PacketStaged { state: &self.state }.await;
        let mut state = self.state.lock();
        state.log.push(FixtureXfer::IsochIn);
        let packet = state.packets.pop_front().unwrap_or_default();
        let n = packet.len().min(out.len());
        out[..n].copy_from_slice(&packet[..n]);
        Ok(n)
    }
}

/// The modelled camera currently installed for the fixture stream
/// hooks (fn pointers cannot capture, so the hooks resolve it here).
static UVC_FIXTURE_TRANSPORT: IrqSafeSpinLock<Option<Arc<FixtureTransport>>> =
    IrqSafeSpinLock::new(None);

fn uvc_fixture_stream_start(
    node: usize,
    format: narf_drivers_video::v4l2_ioctl::PixFormat,
) -> narf_drivers_video::v4l2_ioctl::StreamHookFuture {
    Box::pin(async move {
        let transport = UVC_FIXTURE_TRANSPORT.lock().clone().ok_or(19)?;
        // Same composition as production, minus the pump spawn: the
        // fixture drives `pump_video_frames_with` itself, interleaved
        // with DQBUF, because a smoke cannot rely on executor
        // scheduling (block_on does not drive the executor).
        crate::uvc::stream_start_with(&*transport, node, format).await
    })
}

fn uvc_fixture_stream_stop(node: usize) -> narf_drivers_video::v4l2_ioctl::StreamHookFuture {
    Box::pin(async move {
        let transport = UVC_FIXTURE_TRANSPORT.lock().clone().ok_or(19)?;
        crate::uvc::stream_stop_with(&*transport, node).await
    })
}

fn uvc_fixture_stream_ops() -> narf_drivers_video::v4l2_ioctl::StreamOps {
    narf_drivers_video::v4l2_ioctl::StreamOps {
        start: uvc_fixture_stream_start,
        stop: uvc_fixture_stream_stop,
    }
}

/// Configuration descriptor set for the modelled camera: VC interface
/// 0, VS interface 1 with one uncompressed YUYV 640×480 @30 fps format
/// and an isochronous alt-1 endpoint (0x81, 1024-byte packets).
fn uvc_fixture_config_blob() -> Vec<u8> {
    uvc_fixture_config_blob_versioned(0x0100, 0x0047_9C40)
}

/// Modelled camera config blob with a chosen VC HEADER version/clock.
/// The 1.0 form keeps the original bytes: bcdUVC 1.00, 4.68 MHz clock.
fn uvc_fixture_config_blob_versioned(bcd_uvc: u16, clock_hz: u32) -> Vec<u8> {
    let mut cfg = alloc::vec::Vec::new();
    // Configuration header (wTotalLength patched at the end).
    cfg.extend_from_slice(&[9, 2, 0, 0, 2, 1, 0, 0x80, 50]);
    // Interface 0: VideoControl.
    cfg.extend_from_slice(&[9, 4, 0, 0, 0, 0x0E, 0x01, 0x00, 0]);
    // VC_HEADER (13 bytes): bcdUVC, wTotalLength 13,
    // dwClockFrequency (4 bytes), one streaming interface (1).
    let mut vc_header = [13u8, 0x24, 0x01, 0, 0, 13, 0, 0, 0, 0, 0, 1, 1];
    vc_header[3..5].copy_from_slice(&bcd_uvc.to_le_bytes());
    vc_header[7..11].copy_from_slice(&clock_hz.to_le_bytes());
    cfg.extend_from_slice(&vc_header);
    // Interface 1 alt 0: VideoStreaming, zero bandwidth.
    cfg.extend_from_slice(&[9, 4, 1, 0, 0, 0x0E, 0x02, 0x00, 0]);
    // VS_INPUT_HEADER: 1 format, CS total 71, endpoint 0x81, terminal 1.
    cfg.extend_from_slice(&[14, 0x24, 0x01, 1, 71, 0, 0x81, 0, 1, 0, 0, 0, 1, 0]);
    // VS_FORMAT_UNCOMPRESSED: index 1, 1 frame, YUY2 GUID, 16 bpp.
    cfg.extend_from_slice(&[27, 0x24, 0x04, 1, 1]);
    cfg.extend_from_slice(&crate::uvc::GUID_FORMAT_YUY2);
    cfg.extend_from_slice(&[16, 1, 0, 0, 0, 0]);
    // VS_FRAME_UNCOMPRESSED: index 1, 640×480, default + only interval
    // 333333 (30 fps), max frame buffer 614400 bytes.
    cfg.extend_from_slice(&[30, 0x24, 0x05, 1, 0]);
    cfg.extend_from_slice(&640u16.to_le_bytes());
    cfg.extend_from_slice(&480u16.to_le_bytes());
    cfg.extend_from_slice(&0u32.to_le_bytes()); // dwMinBitRate
    cfg.extend_from_slice(&0u32.to_le_bytes()); // dwMaxBitRate
    cfg.extend_from_slice(&614_400u32.to_le_bytes());
    cfg.extend_from_slice(&333_333u32.to_le_bytes()); // default interval
    cfg.push(1); // one discrete interval
    cfg.extend_from_slice(&333_333u32.to_le_bytes());
    // Interface 1 alt 1: VideoStreaming, one isochronous IN endpoint.
    cfg.extend_from_slice(&[9, 4, 1, 1, 1, 0x0E, 0x02, 0x00, 0]);
    cfg.extend_from_slice(&[7, 5, 0x81, 0x01, 0x00, 0x04, 1]);
    let total = cfg.len() as u16;
    cfg[2..4].copy_from_slice(&total.to_le_bytes());
    cfg
}

/// The frame the modelled camera emits: two payload packets carrying
/// `UVC-E2E-FRAME!` (FID set on both, EOF on the second).
fn uvc_fixture_frame_packets() -> Vec<Vec<u8>> {
    let mut first = alloc::vec![2u8, 0x81];
    first.extend_from_slice(b"UVC-E2E-");
    let mut second = alloc::vec![2u8, 0x83];
    second.extend_from_slice(b"FRAME!");
    alloc::vec![first, second]
}

// ── Fixture ioctl plumbing (mirrors the video crate's v4l2 mock) ────

const FIXTURE_ARG: u64 = 512;

fn fixture_eno(e: i64) -> u64 {
    (-e) as u64
}

fn fixture_ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((b'V' as u32) << 8) | nr
}

struct FixtureCtx {
    mem: IrqSafeSpinLock<Vec<u8>>,
}

impl FixtureCtx {
    fn new() -> Self {
        Self {
            mem: IrqSafeSpinLock::new(alloc::vec![0u8; 8192]),
        }
    }
    fn put_u32(&self, off: usize, v: u32) {
        self.mem.lock()[FIXTURE_ARG as usize + off..FIXTURE_ARG as usize + off + 4]
            .copy_from_slice(&v.to_ne_bytes());
    }
    fn get_u32(&self, off: usize) -> u32 {
        let m = self.mem.lock();
        let a = FIXTURE_ARG as usize + off;
        u32::from_ne_bytes([m[a], m[a + 1], m[a + 2], m[a + 3]])
    }
}

impl narf_filesystem::IoctlContext for FixtureCtx {
    fn read(&self, a: u64, b: &mut [u8]) -> Result<(), narf_filesystem::FsError> {
        let m = self.mem.lock();
        let a = a as usize;
        b.copy_from_slice(
            m.get(a..a + b.len())
                .ok_or(narf_filesystem::FsError::BadAddress)?,
        );
        Ok(())
    }
    fn write(&self, a: u64, b: &[u8]) -> Result<(), narf_filesystem::FsError> {
        let mut m = self.mem.lock();
        let a = a as usize;
        m.get_mut(a..a + b.len())
            .ok_or(narf_filesystem::FsError::BadAddress)?
            .copy_from_slice(b);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        true
    }
}

/// Poll a future once with a no-op waker.
fn fixture_poll<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fn raw() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        unsafe fn noop(_: *const ()) {}
        const V: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(core::ptr::null(), &V)
    }
    // SAFETY: the vtable's clone returns an equivalent waker and
    // wake/drop are no-ops over a null data pointer that is never read.
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    fut.poll(&mut cx)
}

/// Drive a future that must complete without external wakes (every
/// modelled transfer is immediately ready). `None` = still pending
/// after the poll budget — a fixture failure, never a hang.
fn fixture_drive<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = Box::pin(fut);
    for _ in 0..100_000 {
        if let Poll::Ready(v) = fixture_poll(fut.as_mut()) {
            return Some(v);
        }
    }
    None
}

type FixtureDevice = Arc<IrqSafeSpinLock<narf_drivers_video::devfs_bridge::VideoDevice>>;
type FixtureEvents = Arc<IrqSafeSpinLock<narf_drivers_video::v4l2_ioctl::FdEvents>>;

fn fixture_ioctl(
    dev: &FixtureDevice,
    events: &FixtureEvents,
    ctx: &FixtureCtx,
    cmd: u32,
) -> Result<u64, &'static str> {
    fixture_drive(narf_drivers_video::v4l2_ioctl::dispatch(
        dev.clone(),
        cmd,
        FIXTURE_ARG,
        ctx,
        events.clone(),
    ))
    .ok_or("ioctl future pended")?
    .map_err(|_| "ioctl faulted")
}

/// Reset all streaming state, bind the modelled camera, install the
/// fixture stream hooks, and run S_FMT + REQBUFS(2) + QBUF×2 — the
/// state from which STREAMON is meaningful.
fn uvc_fixture_bound(
    fail_probe: bool,
    fail_set_interface: bool,
) -> Result<
    (
        Arc<FixtureTransport>,
        usize,
        FixtureDevice,
        FixtureCtx,
        FixtureEvents,
    ),
    &'static str,
> {
    uvc_fixture_bound_with_blob(fail_probe, fail_set_interface, &uvc_fixture_config_blob())
}

/// Bind against a modelled camera described by `blob` (same flow as
/// [`uvc_fixture_bound`], so the 1.5 test shares the S_FMT/REQBUFS
/// setup and only the VC HEADER version/clock differ).
fn uvc_fixture_bound_with_blob(
    fail_probe: bool,
    fail_set_interface: bool,
    blob: &[u8],
) -> Result<
    (
        Arc<FixtureTransport>,
        usize,
        FixtureDevice,
        FixtureCtx,
        FixtureEvents,
    ),
    &'static str,
> {
    narf_drivers_video::devfs_bridge::__reset_for_test();
    crate::uvc::__reset_uvc_for_test();
    let transport = Arc::new(FixtureTransport::new(
        fail_probe,
        fail_set_interface,
        uvc_fixture_frame_packets(),
    ));
    *UVC_FIXTURE_TRANSPORT.lock() = Some(transport.clone());

    let idx = narf_scheduler::block_on(crate::uvc::try_bind_video_with_transport(
        &*transport,
        7,
        blob,
    ))
    .map_err(|_| "bind against the modelled camera failed")?;
    let (node, format_count) = {
        let devices = crate::uvc::UVC_DEVICES.lock();
        let device = devices.get(idx).ok_or("bound device missing")?;
        (device.video_node, device.formats.len())
    };
    if format_count != 1 {
        return Err("bind should retain the parsed format table");
    }
    if !narf_drivers_video::devfs_bridge::set_stream_ops(node, uvc_fixture_stream_ops()) {
        return Err("installing fixture stream hooks failed");
    }
    let dev = narf_drivers_video::devfs_bridge::get_device(node)
        .ok_or("registered video device missing")?;
    let events: FixtureEvents = Arc::new(IrqSafeSpinLock::new(
        narf_drivers_video::v4l2_ioctl::FdEvents::new(),
    ));
    let ctx = FixtureCtx::new();

    // S_FMT: YUYV 640×480 (v4l2_format pix fields at offset 8).
    let yuyv = u32::from_le_bytes(*b"YUYV");
    ctx.put_u32(0, 1);
    ctx.put_u32(8, 640);
    ctx.put_u32(12, 480);
    ctx.put_u32(16, yuyv);
    if fixture_ioctl(&dev, &events, &ctx, fixture_ioc(1, 5, 208))? != 0 {
        return Err("S_FMT should succeed");
    }
    // REQBUFS: 2 MMAP buffers.
    ctx.put_u32(0, 2);
    ctx.put_u32(4, 1);
    ctx.put_u32(8, 1);
    if fixture_ioctl(&dev, &events, &ctx, fixture_ioc(3, 8, 20))? != 0 {
        return Err("REQBUFS should succeed");
    }
    // QBUF both buffers.
    for index in 0..2u32 {
        ctx.put_u32(0, index);
        ctx.put_u32(4, 1);
        ctx.put_u32(60, 1);
        if fixture_ioctl(&dev, &events, &ctx, fixture_ioc(3, 15, 88))? != 0 {
            return Err("QBUF should succeed");
        }
    }
    Ok((transport, idx, dev, ctx, events))
}

fn fixture_streamon(
    dev: &FixtureDevice,
    events: &FixtureEvents,
    ctx: &FixtureCtx,
) -> Result<u64, &'static str> {
    ctx.put_u32(0, 1);
    fixture_ioctl(dev, events, ctx, fixture_ioc(1, 18, 4))
}

fn fixture_streamoff(
    dev: &FixtureDevice,
    events: &FixtureEvents,
    ctx: &FixtureCtx,
) -> Result<u64, &'static str> {
    ctx.put_u32(0, 1);
    fixture_ioctl(dev, events, ctx, fixture_ioc(1, 19, 4))
}

/// Position of the first occurrence of `needle` in the transfer log.
fn fixture_log_pos(log: &[FixtureXfer], needle: &FixtureXfer) -> Option<usize> {
    log.iter().position(|x| x == needle)
}

fn smoke_uvc_streamon_composition_e2e() -> TestResult {
    let (transport, idx, dev, ctx, events) = match uvc_fixture_bound(false, false) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // STREAMON must run the hardware composition, not just flip state.
    match fixture_streamon(&dev, &events, &ctx) {
        Ok(0) => {}
        Ok(_) => return TestResult::Fail("STREAMON should succeed"),
        Err(e) => return TestResult::Fail(e),
    }
    if !dev.lock().streaming {
        return TestResult::Fail("device should be streaming after STREAMON");
    }
    {
        let devices = crate::uvc::UVC_DEVICES.lock();
        match devices[idx].active_stream {
            Some(ep) if ep.alternate_setting == 1 && ep.dci == 3 => {}
            _ => return TestResult::Fail("STREAMON should activate alt 1 (DCI 3)"),
        }
    }
    // Drive the capture pump, interleaved with nonblocking DQBUF, until
    // the modelled frame lands in a queued buffer.
    let generation = crate::uvc::UVC_DEVICES.lock()[idx].stream_generation;
    let mut pump = Box::pin(crate::uvc::pump_video_frames_with(
        idx,
        &*transport,
        generation,
    ));
    let mut dequeued = false;
    for _ in 0..10_000 {
        let _ = fixture_poll(pump.as_mut());
        ctx.put_u32(4, 1);
        ctx.put_u32(60, 1);
        match fixture_ioctl(&dev, &events, &ctx, fixture_ioc(3, 17, 88)) {
            Ok(0) => {
                dequeued = true;
                break;
            }
            Ok(r) if r == fixture_eno(11) => continue,
            Ok(_) => return TestResult::Fail("DQBUF should succeed or EAGAIN"),
            Err(e) => return TestResult::Fail(e),
        }
    }
    if !dequeued {
        return TestResult::Fail("DQBUF never returned the modelled frame");
    }
    if ctx.get_u32(0) != 0 {
        return TestResult::Fail("dequeued buffer should be index 0");
    }
    if ctx.get_u32(8) as usize != b"UVC-E2E-FRAME!".len() {
        return TestResult::Fail("bytesused should equal the modelled frame length");
    }
    let bytes_ok = {
        let g = dev.lock();
        let f0 = g.buffers[0].frames[0];
        let p = f0.start_address().kernel_ptr::<u8>();
        let mut buf = [0u8; 14];
        // SAFETY: f0 is an allocated frame owned by buffer 0; its
        // direct-map pointer is valid for the 14 delivered bytes.
        unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), 14) };
        &buf == b"UVC-E2E-FRAME!"
    };
    if !bytes_ok {
        return TestResult::Fail("buffer should contain the modelled frame bytes");
    }
    // STREAMOFF reverses the composition.
    match fixture_streamoff(&dev, &events, &ctx) {
        Ok(0) => {}
        Ok(_) => return TestResult::Fail("STREAMOFF should succeed"),
        Err(e) => return TestResult::Fail(e),
    }
    if dev.lock().streaming {
        return TestResult::Fail("STREAMOFF should clear streaming");
    }
    // The pump is parked in `isoch_in` (the modelled device sources
    // nothing on alt 0), so stage one packet to wake it — the same
    // wake the next stream's traffic would give it on hardware. The
    // frame it completes belongs to the stopped stream: the pump
    // must drop it at the pre-delivery lifecycle check, not deliver
    // it into the reset queues, and exit cleanly.
    transport.stage_packet(alloc::vec![2u8, 0x83, b'W', b'A', b'K', b'E', b'!']);
    // The pump observes the stop request and exits cleanly.
    let mut pump_done = None;
    for _ in 0..10_000 {
        if let Poll::Ready(r) = fixture_poll(pump.as_mut()) {
            pump_done = Some(r);
            break;
        }
    }
    if !matches!(pump_done, Some(Ok(()))) {
        return TestResult::Fail("pump should exit Ok after STREAMOFF");
    }
    {
        let devices = crate::uvc::UVC_DEVICES.lock();
        if devices[idx].active_stream.is_some() {
            return TestResult::Fail("STREAMOFF should clear the active stream");
        }
    }
    // The transfer conversation: probe before commit, commit carries
    // the device-accepted values, SET_INTERFACE after commit, isoc
    // only after activation, alt 0 released at teardown.
    let log = transport.log();
    let desired = crate::uvc::VsProbeCommit {
        hint: 1,
        format_index: 1,
        frame_index: 1,
        frame_interval: 333_333,
        ..Default::default()
    };
    let mut accepted = desired;
    accepted.max_video_frame_size = 614_400;
    accepted.max_payload_transfer_size = 1024;
    let probe_payload = log.iter().find_map(|x| match x {
        FixtureXfer::SetCurProbe { payload } => Some(payload.clone()),
        _ => None,
    });
    // The 1.0 fixture device (bcdUVC 0x0100) must receive exactly the
    // 26-byte form — a 34-byte probe here would be the truncation bug
    // in reverse.
    if probe_payload.as_ref().map(|p| p.len()) != Some(26) {
        return TestResult::Fail("SET_CUR(PROBE) to a 1.0 device must be 26 bytes");
    }
    if probe_payload != Some(desired.encode_for(0x0100)) {
        return TestResult::Fail("SET_CUR(PROBE) should carry the desired stream parameters");
    }
    let commit_payload = log.iter().find_map(|x| match x {
        FixtureXfer::SetCurCommit { payload } => Some(payload.clone()),
        _ => None,
    });
    if commit_payload.as_ref().map(|p| p.len()) != Some(26) {
        return TestResult::Fail("SET_CUR(COMMIT) to a 1.0 device must be 26 bytes");
    }
    if commit_payload != Some(accepted.encode_for(0x0100)) {
        return TestResult::Fail("SET_CUR(COMMIT) should carry the device-accepted parameters");
    }
    let pos = |needle: &FixtureXfer| fixture_log_pos(&log, needle);
    let positions = [
        pos(&FixtureXfer::SetConfiguration),
        log.iter()
            .position(|x| matches!(x, FixtureXfer::SetCurProbe { .. })),
        pos(&FixtureXfer::GetCurProbe),
        log.iter()
            .position(|x| matches!(x, FixtureXfer::SetCurCommit { .. })),
        pos(&FixtureXfer::ConfigureEndpoints { ep_addr: 0x81 }),
        pos(&FixtureXfer::SetInterface {
            interface: 1,
            alt: 1,
        }),
        pos(&FixtureXfer::IsochIn),
    ];
    let mut order = Vec::new();
    for position in positions {
        match position {
            Some(p) => order.push(p),
            None => return TestResult::Fail("conversation is missing a required transfer"),
        }
    }
    if !order.windows(2).all(|w| w[0] < w[1]) {
        return TestResult::Fail("transfer conversation is out of order");
    }
    let last_set_interface = log.iter().rev().find_map(|x| match x {
        FixtureXfer::SetInterface { alt, .. } => Some(*alt),
        _ => None,
    });
    if last_set_interface != Some(0) {
        return TestResult::Fail("teardown should end with SET_INTERFACE alt 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_streamon_composition_e2e);

fn smoke_uvc_streamon_probe_failure_fails_ioctl() -> TestResult {
    let (transport, idx, dev, ctx, events) = match uvc_fixture_bound(true, false) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // A failed PROBE negotiation must fail STREAMON — the pre-#803
    // behaviour (silent local-state success) is the black-stream bug.
    match fixture_streamon(&dev, &events, &ctx) {
        Ok(r) if r == fixture_eno(5) => {}
        Ok(_) => return TestResult::Fail("STREAMON should fail with EIO when PROBE fails"),
        Err(e) => return TestResult::Fail(e),
    }
    if dev.lock().streaming {
        return TestResult::Fail("device must not be streaming after a failed STREAMON");
    }
    let log = transport.log();
    if !log
        .iter()
        .any(|x| matches!(x, FixtureXfer::SetCurProbe { .. }))
    {
        return TestResult::Fail("the failed PROBE attempt should be in the log");
    }
    if log
        .iter()
        .any(|x| matches!(x, FixtureXfer::SetCurCommit { .. }))
    {
        return TestResult::Fail("COMMIT must not follow a failed PROBE");
    }
    if log
        .iter()
        .any(|x| matches!(x, FixtureXfer::ConfigureEndpoints { .. }))
    {
        return TestResult::Fail("no endpoint may be configured after a failed PROBE");
    }
    if crate::uvc::UVC_DEVICES.lock()[idx].active_stream.is_some() {
        return TestResult::Fail("no stream may be active after a failed STREAMON");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uac",
    smoke_uac_detach_removes_registry_and_card
);

fn smoke_uac_pump_generation_stop_start() -> TestResult {
    use crate::uac::{BindOutcome, UacTopology};
    use narf_drivers_sound::hardware::PcmHardware;
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state =
        crate::uac_card::UacCardState::from_bind(7, &topo, &choices, &BindOutcome::default());
    let pb_iso = FakeIso(FakeIsoState::new());
    let mut pb = match crate::uac_card::UacStream::with_iso(
        state.clone(),
        false,
        alloc::boxed::Box::new(pb_iso.clone()),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("playback lease"),
    };
    let dev: &dyn narf_drivers_sound::hardware::PcmDevice =
        &crate::uac_card::UsbAudioCard(state.clone());
    let params = dev.default_params(false);
    if pb.configure(params).is_err() || pb.prepare().is_err() || pb.start().is_err() {
        return TestResult::Fail("configure/prepare/start");
    }
    let shared = match state.stream(false).and_then(|d| d.live.lock().clone()) {
        Some(s) => s,
        None => return TestResult::Fail("live pump shared"),
    };
    let gen1 = shared.generation();
    if gen1 == 0 || !shared.is_current(gen1) {
        return TestResult::Fail("start establishes the current generation");
    }
    // Queue distinctive frames, then park a gen1 cycle
    // mid-transfer: the packet is built (begin) but its
    // transfer has not committed.
    let pattern: alloc::vec::Vec<u8> = (0..192u32).map(|i| (i % 251) as u8).collect();
    if pb.write(&pattern) != Ok(192) {
        return TestResult::Fail("write accepts 192 B");
    }
    let (packet, frames) = match shared.begin_playback(gen1, 48_000, 4) {
        Some(p) => p,
        None => return TestResult::Fail("gen1 begins a cycle"),
    };
    if packet != pattern || frames != 48 {
        return TestResult::Fail("gen1 packet = the queued pattern, 48 frames");
    }
    // The standard ALSA recovery sequence lands while the gen1
    // transfer is still in flight: stop -> prepare -> start.
    if pb.stop().is_err() || pb.prepare().is_err() || pb.start().is_err() {
        return TestResult::Fail("stop/prepare/start cycle");
    }
    let gen2 = shared.generation();
    if gen2 == gen1 || !shared.is_current(gen2) || shared.is_current(gen1) {
        return TestResult::Fail("start supersedes gen1 with a fresh generation");
    }
    // Double-start while running: no new generation, no second
    // owner of the ring.
    if pb.start().is_err() || shared.generation() != gen2 {
        return TestResult::Fail("double-start keeps the running generation");
    }
    // The parked gen1 transfer resolves now: its commit is
    // refused, it cannot begin again, and the pointer has not
    // moved. Its packet is dropped, never delivered.
    if shared.commit_playback(gen1, frames) {
        return TestResult::Fail("stale generation commit refused");
    }
    if shared.begin_playback(gen1, 48_000, 4).is_some() {
        return TestResult::Fail("stale generation cannot begin");
    }
    if pb.pointer() != 0 {
        return TestResult::Fail("pointer unmoved by the superseded pump");
    }
    if !pb_iso.0.out_log.lock().is_empty() {
        return TestResult::Fail("superseded packet never delivered");
    }
    // The successor generation owns the ring: one cycle clocks
    // a full (silence) packet and moves the pointer by itself.
    if pb.pump_once().is_err() {
        return TestResult::Fail("gen2 pump cycle");
    }
    if pb.pointer() != 48 {
        return TestResult::Fail("pointer advanced by gen2 alone");
    }
    {
        let log = pb_iso.0.out_log.lock();
        if log.len() != 192 || log.iter().any(|b| *b != 0) {
            return TestResult::Fail("gen2 clocks silence (pattern died with gen1)");
        }
    }
    if pb.stop().is_err() {
        return TestResult::Fail("final stop");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_pump_generation_stop_start);

fn smoke_uac_pump_detach_while_running() -> TestResult {
    use crate::uac::{BindOutcome, UacTopology};
    use narf_drivers_sound::hardware::PcmHardware;
    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state =
        crate::uac_card::UacCardState::from_bind(9, &topo, &choices, &BindOutcome::default());

    // Playback: a cycle parked mid-transfer when detach lands.
    let mut pb = match crate::uac_card::UacStream::with_iso(
        state.clone(),
        false,
        alloc::boxed::Box::new(FakeIso(FakeIsoState::new())),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("playback lease"),
    };
    let dev: &dyn narf_drivers_sound::hardware::PcmDevice =
        &crate::uac_card::UsbAudioCard(state.clone());
    let pb_params = dev.default_params(false);
    if pb.configure(pb_params).is_err() || pb.prepare().is_err() || pb.start().is_err() {
        return TestResult::Fail("playback configure/prepare/start");
    }
    let pb_shared = match state.stream(false).and_then(|d| d.live.lock().clone()) {
        Some(s) => s,
        None => return TestResult::Fail("playback live shared"),
    };
    let pb_gen = pb_shared.generation();
    let (_packet, frames) = match pb_shared.begin_playback(pb_gen, 48_000, 4) {
        Some(p) => p,
        None => return TestResult::Fail("playback cycle begins"),
    };

    // Capture: a cycle begun, its packet not yet committed.
    let mut cap = match crate::uac_card::UacStream::with_iso(
        state.clone(),
        true,
        alloc::boxed::Box::new(FakeIso(FakeIsoState::new())),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("capture lease"),
    };
    let cap_params = dev.default_params(true);
    if cap.configure(cap_params).is_err() || cap.prepare().is_err() || cap.start().is_err() {
        return TestResult::Fail("capture configure/prepare/start");
    }
    let cap_shared = match state.stream(true).and_then(|d| d.live.lock().clone()) {
        Some(s) => s,
        None => return TestResult::Fail("capture live shared"),
    };
    let cap_gen = cap_shared.generation();
    if cap_shared.begin_capture(cap_gen, 48_000) != Some(48) {
        return TestResult::Fail("capture cycle begins (48 frames)");
    }

    state.detach();

    // Both in-flight cycles are disowned: commits refused,
    // no new cycle begins, pointers frozen.
    if pb_shared.commit_playback(pb_gen, frames) {
        return TestResult::Fail("detached playback commit refused");
    }
    if cap_shared.commit_capture(cap_gen, &[0xABu8; 192], 2) {
        return TestResult::Fail("detached capture commit refused");
    }
    if pb_shared.begin_playback(pb_gen, 48_000, 4).is_some()
        || cap_shared.begin_capture(cap_gen, 48_000).is_some()
    {
        return TestResult::Fail("no cycle begins after detach");
    }
    if pb.pointer() != 0 || cap.pointer() != 0 {
        return TestResult::Fail("pointers frozen by detach");
    }
    // And the detached card refuses new leases.
    match dev.open(false, 0) {
        Err(narf_drivers_sound::SoundError::NoSuchCard) => {}
        _ => return TestResult::Fail("open after detach = NoSuchCard"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_pump_detach_while_running);

fn smoke_uac_clock_rate_snap() -> TestResult {
    use crate::uac::{clock_rate_admitted, snap_clock_rate, ClockSubrange};
    let r = |min_hz, max_hz, res_hz| ClockSubrange {
        min_hz,
        max_hz,
        res_hz,
    };
    let grid = [r(44_100, 48_000, 100)];
    if !clock_rate_admitted(&grid, 44_100) || !clock_rate_admitted(&grid, 48_000) {
        return TestResult::Fail("grid admits its endpoints");
    }
    if clock_rate_admitted(&grid, 44_150) || clock_rate_admitted(&grid, 96_000) {
        return TestResult::Fail("grid refuses off-grid and out-of-range");
    }
    if snap_clock_rate(&grid, 48_000) != Some(48_000) {
        return TestResult::Fail("admitted rate passes unchanged");
    }
    if snap_clock_rate(&grid, 44_140) != Some(44_100)
        || snap_clock_rate(&grid, 44_160) != Some(44_200)
    {
        return TestResult::Fail("covered off-grid rate snaps to the nearest grid point");
    }
    if snap_clock_rate(&grid, 47_999) != Some(48_000) {
        return TestResult::Fail("snap may land on the subrange max");
    }
    if snap_clock_rate(&grid, 96_000).is_some() || snap_clock_rate(&grid, 32_000).is_some() {
        return TestResult::Fail("uncovered rate has no snap (prepare must fail)");
    }
    let continuous = [r(32_000, 192_000, 0)];
    if snap_clock_rate(&continuous, 123_457) != Some(123_457) {
        return TestResult::Fail("zero-resolution subrange admits its whole interval");
    }
    let discrete = [r(44_100, 44_100, 0), r(96_000, 96_000, 0)];
    if snap_clock_rate(&discrete, 96_000) != Some(96_000)
        || snap_clock_rate(&discrete, 48_000).is_some()
    {
        return TestResult::Fail("disjoint subranges snap independently");
    }
    if snap_clock_rate(&[], 48_000).is_some() || clock_rate_admitted(&[], 48_000) {
        return TestResult::Fail("no subranges admit nothing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_clock_rate_snap);

fn smoke_uac_bind_outcome_reaches_card() -> TestResult {
    use crate::uac::{record_response, BindOutcome, ClockSubrange, ResponseSlot, UacTopology};
    use narf_drivers_sound::mixer::{ControlId, ControlKind};

    // Feed synthetic bind-conversation responses through the
    // executor's own record path: FU range reads with
    // non-default values in both directions.
    let mut outcome = BindOutcome::default();
    let feed = |outcome: &mut BindOutcome, slot, v: i16| {
        record_response(outcome, slot, &v.to_le_bytes());
    };
    feed(
        &mut outcome,
        ResponseSlot::FuVolumeMin { capture: false },
        -25_600,
    );
    feed(
        &mut outcome,
        ResponseSlot::FuVolumeMax { capture: false },
        3_072,
    );
    feed(
        &mut outcome,
        ResponseSlot::FuVolumeRes { capture: false },
        128,
    );
    feed(
        &mut outcome,
        ResponseSlot::FuVolumeMin { capture: true },
        -5_120,
    );
    feed(&mut outcome, ResponseSlot::FuVolumeMax { capture: true }, 0);
    feed(
        &mut outcome,
        ResponseSlot::FuVolumeRes { capture: true },
        64,
    );

    let cfg = uac1_headset_config();
    let topo = UacTopology::parse(&cfg).expect("topo");
    let mut choices = alloc::vec::Vec::new();
    for s in &topo.streams {
        choices.push(crate::uac::choose_stream_default(s, topo.version).expect("choice"));
    }
    let state = crate::uac_card::UacCardState::from_bind(7, &topo, &choices, &outcome);
    let dev: &dyn narf_drivers_sound::hardware::PcmDevice =
        &crate::uac_card::UsbAudioCard(state.clone());
    let vol = |kind| dev.control_info(ControlId { index: 0, kind });
    match vol(ControlKind::MasterVolume) {
        Ok(info) if (info.value_min, info.value_max, info.step) == (-25_600, 3_072, 128) => {}
        _ => return TestResult::Fail("playback dB range reaches control_info (not the default)"),
    }
    match vol(ControlKind::CaptureVolume) {
        Ok(info) if (info.value_min, info.value_max, info.step) == (-5_120, 0, 64) => {}
        _ => return TestResult::Fail("capture dB range reaches control_info"),
    }

    // UAC2: a RANGE response and a clock GET_CUR readback land
    // on the stream state — ranges retained for the runtime
    // discipline, rate recorded, capabilities intersected.
    let mut outcome2 = BindOutcome::default();
    let mut range_bytes = alloc::vec![1u8, 0];
    range_bytes.extend_from_slice(&44_100u32.to_le_bytes());
    range_bytes.extend_from_slice(&48_000u32.to_le_bytes());
    range_bytes.extend_from_slice(&100u32.to_le_bytes());
    record_response(
        &mut outcome2,
        ResponseSlot::ClockRange { capture: false },
        &range_bytes,
    );
    record_response(
        &mut outcome2,
        ResponseSlot::ClockCur { capture: false },
        &44_100u32.to_le_bytes(),
    );
    let cfg2 = uac2_dac_config();
    let topo2 = UacTopology::parse(&cfg2).expect("topo2");
    let mut choices2 = alloc::vec::Vec::new();
    for s in &topo2.streams {
        choices2.push(crate::uac::choose_stream_default(s, topo2.version).expect("choice2"));
    }
    let state2 = crate::uac_card::UacCardState::from_bind(7, &topo2, &choices2, &outcome2);
    let dir = match state2.stream(false) {
        Some(d) => d,
        None => return TestResult::Fail("UAC2 playback stream state"),
    };
    if dir.clock_ranges
        != [ClockSubrange {
            min_hz: 44_100,
            max_hz: 48_000,
            res_hz: 100,
        }]
    {
        return TestResult::Fail("clock ranges retained on the stream state");
    }
    let dev2: &dyn narf_drivers_sound::hardware::PcmDevice =
        &crate::uac_card::UsbAudioCard(state2.clone());
    if dev2.default_params(false).rate != narf_drivers_sound::SampleRate::R44100 {
        return TestResult::Fail("read-back clock rate recorded on the card");
    }
    let caps = dev2.capabilities(false);
    if caps.rates
        != [
            narf_drivers_sound::SampleRate::R44100,
            narf_drivers_sound::SampleRate::R48000,
        ]
    {
        return TestResult::Fail("capabilities = descriptor rates intersected with clock ranges");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uac", smoke_uac_bind_outcome_reaches_card);
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_uvc_streamon_probe_failure_fails_ioctl
);

fn smoke_uvc_streamon_activation_failure_unwinds() -> TestResult {
    let (transport, idx, dev, ctx, events) = match uvc_fixture_bound(false, true) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // SET_INTERFACE(alt 1) stalls after a successful COMMIT: STREAMON
    // fails, and the composition unwinds the commit by returning the
    // interface to its zero-bandwidth alternate.
    match fixture_streamon(&dev, &events, &ctx) {
        Ok(r) if r == fixture_eno(5) => {}
        Ok(_) => return TestResult::Fail("STREAMON should fail with EIO when activation fails"),
        Err(e) => return TestResult::Fail(e),
    }
    if dev.lock().streaming {
        return TestResult::Fail("device must not be streaming after a failed STREAMON");
    }
    if crate::uvc::UVC_DEVICES.lock()[idx].active_stream.is_some() {
        return TestResult::Fail("no stream may be active after a failed STREAMON");
    }
    let log = transport.log();
    if !log
        .iter()
        .any(|x| matches!(x, FixtureXfer::SetCurCommit { .. }))
    {
        return TestResult::Fail("COMMIT should have succeeded before activation");
    }
    let alt1 = fixture_log_pos(
        &log,
        &FixtureXfer::SetInterface {
            interface: 1,
            alt: 1,
        },
    );
    let alt0 = fixture_log_pos(
        &log,
        &FixtureXfer::SetInterface {
            interface: 1,
            alt: 0,
        },
    );
    match (alt1, alt0) {
        (Some(a1), Some(a0)) if a0 > a1 => {}
        _ => {
            return TestResult::Fail("failed activation should be unwound with SET_INTERFACE alt 0")
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/uvc",
    smoke_uvc_streamon_activation_failure_unwinds
);

// ── Generation-toggle fixture helpers ─────────────────────────────

/// Poll a hand-driven future until it completes; `None` = still
/// pending after the poll budget (a fixture failure, never a hang).
fn fixture_poll_until_ready<F: Future>(mut fut: Pin<&mut F>) -> Option<F::Output> {
    for _ in 0..10_000 {
        if let Poll::Ready(v) = fixture_poll(fut.as_mut()) {
            return Some(v);
        }
    }
    None
}

/// QBUF both capture buffers (STREAMOFF returns them to the
/// dequeued state, so a fresh stream needs them re-queued).
fn fixture_qbuf_all(
    dev: &FixtureDevice,
    events: &FixtureEvents,
    ctx: &FixtureCtx,
) -> Result<(), &'static str> {
    for index in 0..2u32 {
        ctx.put_u32(0, index);
        ctx.put_u32(4, 1);
        ctx.put_u32(60, 1);
        if fixture_ioctl(dev, events, ctx, fixture_ioc(3, 15, 88))? != 0 {
            return Err("QBUF should succeed");
        }
    }
    Ok(())
}

/// Outcome of one nonblocking DQBUF against the fixture device.
enum FixtureDqbuf {
    Frame(Vec<u8>),
    Again,
    Failed(&'static str),
}

fn fixture_dqbuf(dev: &FixtureDevice, events: &FixtureEvents, ctx: &FixtureCtx) -> FixtureDqbuf {
    ctx.put_u32(4, 1);
    ctx.put_u32(60, 1);
    match fixture_ioctl(dev, events, ctx, fixture_ioc(3, 17, 88)) {
        Ok(0) => {}
        Ok(r) if r == fixture_eno(11) => return FixtureDqbuf::Again,
        Ok(_) => return FixtureDqbuf::Failed("DQBUF should succeed or EAGAIN"),
        Err(e) => return FixtureDqbuf::Failed(e),
    }
    let index = ctx.get_u32(0) as usize;
    let used = ctx.get_u32(8) as usize;
    if used > 4096 {
        return FixtureDqbuf::Failed("DQBUF reported an implausible bytesused");
    }
    let bytes = {
        let g = dev.lock();
        let f0 = g.buffers[index].frames[0];
        let p = f0.start_address().kernel_ptr::<u8>();
        let mut buf = alloc::vec![0u8; used];
        // SAFETY: f0 is an allocated frame owned by the dequeued
        // buffer; its direct-map pointer is valid for the `used`
        // bytes the V4L2 layer recorded from the delivered frame.
        unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), used) };
        buf
    };
    FixtureDqbuf::Frame(bytes)
}

/// One UVC payload packet: 2-byte header (length, `flags`) + payload.
fn uvc_fixture_packet(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = alloc::vec![2u8, flags];
    packet.extend_from_slice(payload);
    packet
}

/// The stream-generation protocol under a STREAMOFF → STREAMON
/// toggle, driven at the state-machine level with faithfully parked
/// pumps. This is the interleave the composition e2e cannot see: its
/// modelled transport used to answer empty reads immediately, so its
/// pump always observed teardown at a loop top before STREAMOFF
/// returned. Here `isoch_in` parks like hardware, so a pump can be
/// held mid-await across the whole toggle.
///
/// Phase A (stale delivery): a frame in flight across STREAMOFF
/// completes only after the buffer reset; the pump must drop it at
/// the pre-delivery check, and it must not surface in the next
/// stream's queue.
///
/// Phase B (the wedge): STREAMON for generation 2, park its pump,
/// STREAMOFF, STREAMON for generation 3. The pump claim must succeed
/// for generation 3 despite the generation-2 pump still being marked
/// (the old boolean protocol declined the spawn here and left the
/// device streaming with no pump — a silent black stream). The
/// parked pump then wakes on the new stream's packets, exits without
/// delivering and without consuming generation-3 state, and its
/// exit bookkeeping must not clear the generation-3 pump's mark.
fn smoke_uvc_streamon_generation_toggle() -> TestResult {
    let (transport, idx, dev, ctx, events) = match uvc_fixture_bound(false, false) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let stream_generation = |idx: usize| crate::uvc::UVC_DEVICES.lock()[idx].stream_generation;
    let pump_mark = |idx: usize| crate::uvc::UVC_DEVICES.lock()[idx].capture_pump_generation;

    // ── Phase A: in-flight frame across STREAMOFF is dropped ─────
    if fixture_streamon(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("STREAMON (gen 1) should succeed");
    }
    if stream_generation(idx) != 1 {
        return TestResult::Fail("first activation should bump the stream generation to 1");
    }
    // Mirror the production spawn wrapper: claim, then drive the
    // pump by hand.
    if crate::uvc::claim_capture_pump(idx) != Some(1) {
        return TestResult::Fail("pump claim for generation 1 should succeed");
    }
    let mut pump1 = Box::pin(crate::uvc::pump_video_frames_with(idx, &*transport, 1));
    // The bind staged one frame (UVC-E2E-FRAME!): pump it to DQBUF.
    let mut frame_a = None;
    for _ in 0..10_000 {
        let _ = fixture_poll(pump1.as_mut());
        match fixture_dqbuf(&dev, &events, &ctx) {
            FixtureDqbuf::Frame(bytes) => {
                frame_a = Some(bytes);
                break;
            }
            FixtureDqbuf::Again => continue,
            FixtureDqbuf::Failed(e) => return TestResult::Fail(e),
        }
    }
    if frame_a.as_deref() != Some(b"UVC-E2E-FRAME!".as_slice()) {
        return TestResult::Fail("gen-1 pump should deliver the staged frame");
    }
    // Start a second gen-1 frame (FID flips to 0) but stage only its
    // first packet: the frame is in flight, straddling the STREAMOFF.
    transport.stage_packet(uvc_fixture_packet(0x80, b"STALE-"));
    for _ in 0..1_000 {
        if transport.pending_packets() == 0 {
            break;
        }
        let _ = fixture_poll(pump1.as_mut());
    }
    if transport.pending_packets() != 0 {
        return TestResult::Fail("gen-1 pump should consume the in-flight packet");
    }
    if !matches!(fixture_dqbuf(&dev, &events, &ctx), FixtureDqbuf::Again) {
        return TestResult::Fail("the in-flight frame must not be delivered before EOF");
    }
    // STREAMOFF: stop requested for gen 1, buffers reset. The pump
    // is parked in `isoch_in`, waiting for the frame's second packet.
    if fixture_streamoff(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("STREAMOFF (gen 1) should succeed");
    }
    // The frame completes *after* the reset. The pump wakes, hits the
    // pre-delivery lifecycle check, drops it, and exits.
    transport.stage_packet(uvc_fixture_packet(0x82, b"FRAME"));
    match fixture_poll_until_ready(pump1.as_mut()) {
        Some(Ok(())) => {}
        _ => {
            return TestResult::Fail("gen-1 pump should exit Ok once its in-flight frame resolves")
        }
    }
    // Mirror the wrapper's exit bookkeeping.
    crate::uvc::release_capture_pump(idx, 1);
    if pump_mark(idx) != 0 {
        return TestResult::Fail("a current-generation pump's exit should clear the pump mark");
    }

    // ── Phase B: the toggle must not wedge ───────────────────────
    if fixture_qbuf_all(&dev, &events, &ctx).is_err() {
        return TestResult::Fail("QBUF before gen-2 STREAMON should succeed");
    }
    if fixture_streamon(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("STREAMON (gen 2) should succeed");
    }
    if stream_generation(idx) != 2 {
        return TestResult::Fail("second activation should bump the stream generation to 2");
    }
    // The stale gen-1 frame was dropped, not left for this stream:
    // DQBUF on the fresh stream must find nothing.
    if !matches!(fixture_dqbuf(&dev, &events, &ctx), FixtureDqbuf::Again) {
        return TestResult::Fail("the stale gen-1 frame must not surface in the gen-2 stream");
    }
    if crate::uvc::claim_capture_pump(idx) != Some(2) {
        return TestResult::Fail("pump claim for generation 2 should succeed");
    }
    let mut pump2 = Box::pin(crate::uvc::pump_video_frames_with(idx, &*transport, 2));
    // Park the gen-2 pump mid-await: no packets staged, every poll
    // pends inside `isoch_in`.
    let mut parked = true;
    for _ in 0..16 {
        if !matches!(fixture_poll(pump2.as_mut()), Poll::Pending) {
            parked = false;
        }
    }
    if !parked {
        return TestResult::Fail("gen-2 pump should be parked in isoch_in with nothing staged");
    }
    // The format-change toggle: STREAMOFF, then STREAMON again —
    // while the gen-2 pump is still parked and still marked.
    if fixture_streamoff(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("STREAMOFF (gen 2) should succeed");
    }
    if pump_mark(idx) != 2 {
        return TestResult::Fail("the parked gen-2 pump should still be marked before gen 3");
    }
    if fixture_qbuf_all(&dev, &events, &ctx).is_err() {
        return TestResult::Fail("QBUF before gen-3 STREAMON should succeed");
    }
    if fixture_streamon(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("STREAMON (gen 3) should succeed");
    }
    if stream_generation(idx) != 3 {
        return TestResult::Fail("third activation should bump the stream generation to 3");
    }
    // THE wedge pin: a pump for the new generation must be claimable
    // even though the gen-2 pump never exited.
    if crate::uvc::claim_capture_pump(idx) != Some(3) {
        return TestResult::Fail(
            "pump claim for generation 3 must not be declined for a stale pump",
        );
    }
    let mut pump3 = Box::pin(crate::uvc::pump_video_frames_with(idx, &*transport, 3));
    // The new stream's first traffic wakes the parked gen-2 pump (a
    // sacrificial errored packet stands in for it). It must exit on
    // the generation check — delivering nothing, consuming nothing
    // of generation 3's lifecycle state.
    transport.stage_packet(uvc_fixture_packet(0xC1, b"X"));
    match fixture_poll_until_ready(pump2.as_mut()) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("gen-2 pump should exit Ok when woken by gen-3 traffic"),
    }
    if !matches!(fixture_dqbuf(&dev, &events, &ctx), FixtureDqbuf::Again) {
        return TestResult::Fail("the stale gen-2 pump must not deliver into the gen-3 stream");
    }
    // Its exit bookkeeping (wrapper mirror) must not clear the
    // generation-3 pump's mark.
    crate::uvc::release_capture_pump(idx, 2);
    if pump_mark(idx) != 3 {
        return TestResult::Fail("a stale pump's exit must not clear its successor's mark");
    }
    // The gen-3 pump delivers the gen-3 frame.
    transport.stage_packet(uvc_fixture_packet(0x81, b"GEN3-"));
    transport.stage_packet(uvc_fixture_packet(0x83, b"FRAME"));
    let mut frame_3 = None;
    for _ in 0..10_000 {
        let _ = fixture_poll(pump3.as_mut());
        match fixture_dqbuf(&dev, &events, &ctx) {
            FixtureDqbuf::Frame(bytes) => {
                frame_3 = Some(bytes);
                break;
            }
            FixtureDqbuf::Again => continue,
            FixtureDqbuf::Failed(e) => return TestResult::Fail(e),
        }
    }
    if frame_3.as_deref() != Some(b"GEN3-FRAME".as_slice()) {
        return TestResult::Fail("gen-3 pump should deliver the gen-3 frame");
    }
    // Final state: streaming, generation 3, exactly the gen-3 pump
    // marked alive.
    if !dev.lock().streaming {
        return TestResult::Fail("device should still be streaming after the toggle");
    }
    if stream_generation(idx) != 3 || pump_mark(idx) != 3 {
        return TestResult::Fail("exactly the gen-3 pump should be marked after the toggle");
    }
    // Cleanup: STREAMOFF + a wake packet retires the gen-3 pump.
    if fixture_streamoff(&dev, &events, &ctx) != Ok(0) {
        return TestResult::Fail("final STREAMOFF should succeed");
    }
    transport.stage_packet(uvc_fixture_packet(0x83, b"DONE!"));
    match fixture_poll_until_ready(pump3.as_mut()) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("gen-3 pump should exit Ok after the final STREAMOFF"),
    }
    crate::uvc::release_capture_pump(idx, 3);
    if pump_mark(idx) != 0 {
        return TestResult::Fail("pump mark should be clear after the final exit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/uvc", smoke_uvc_streamon_generation_toggle);

// ── MSC BOT conversation fixtures (#828/#830/#831/#832) ───────────
//
// `FakeBot` plays the device side of the Bulk-Only Transport +
// embedded SCSI conversation. It is written from the BOT 1.0 and
// SBC-3/SPC-4 texts — CBW/CSW layouts parsed and built by hand
// here, sense in the SPC-4 fixed format — and never calls the
// production encoders, so a constant or framing the driver and
// the fake might share wrongly cannot pass silently: the happy
// path test pins the first CBW on the wire byte-for-byte against
// §5.1, and the fake enforces the protocol's awkward corners
// (data-phase stalls on refused commands, halt state that only
// the host+device clear pairing lifts, sense that drains exactly
// once) the way real bridges behave.

use crate::msc::{BotTransport, MscError};
use crate::xhci::XhciError;
use alloc::collections::BTreeMap;

/// Fixed-format sense data (SPC-4 §4.5): response code 0x70 in
/// byte 0, sense key in the low nibble of byte 2, additional
/// length 10 (for the 18-byte form) in byte 7, ASC / ASCQ in
/// bytes 12 / 13.
fn fake_sense(key: u8, asc: u8, ascq: u8) -> [u8; 18] {
    let mut s = [0u8; 18];
    s[0] = 0x70;
    s[2] = key & 0x0F;
    s[7] = 10;
    s[12] = asc;
    s[13] = ascq;
    s
}

/// The fixture's data model for a never-written block: the LBA's
/// big-endian bytes cycling, salted per LUN and per offset. The
/// high LBA bytes land inside the block, so a read that truncated
/// the LBA to 32 bits returns visibly different bytes; the LUN
/// salt makes two slots of one reader distinguishable.
fn fake_block_pattern(lun: u8, lba: u64, block_size: u32) -> Vec<u8> {
    let tag = lba.to_be_bytes();
    let salt = lun.wrapping_mul(0x3D);
    (0..block_size as usize)
        .map(|i| tag[i % 8] ^ salt ^ (i as u8))
        .collect()
}

struct FakeLun {
    block_size: u32,
    block_count: u64,
    present: bool,
    ua_pending: bool,
    sense: [u8; 18],
    written: BTreeMap<u64, Vec<u8>>,
}

impl FakeLun {
    fn new(block_count: u64, block_size: u32) -> Self {
        FakeLun {
            block_size,
            block_count,
            present: true,
            ua_pending: false,
            sense: fake_sense(0, 0, 0),
            written: BTreeMap::new(),
        }
    }
    fn absent(block_count: u64, block_size: u32) -> Self {
        let mut l = Self::new(block_count, block_size);
        l.present = false;
        l
    }
    fn with_ua(mut self) -> Self {
        self.ua_pending = true;
        self
    }
    fn block(&self, lun: u8, lba: u64) -> Vec<u8> {
        if let Some(b) = self.written.get(&lba) {
            return b.clone();
        }
        fake_block_pattern(lun, lba, self.block_size)
    }
}

/// The in-flight command, between its CBW and its CSW.
struct FakePending {
    lun: usize,
    is_in: bool,
    data_len: u32,
    csw: [u8; 13],
    staged_in: Option<Vec<u8>>,
    write_need: Option<(u64, u64)>,
    /// Refuse the data phase with a STALL (failed commands and
    /// the injected data stall both present this way).
    data_stall: bool,
    /// The data stall was injected into a command that would
    /// otherwise pass: when it fires, the CSW turns to Command
    /// Failed and `stall_sense` becomes the pending sense.
    stall_patch: bool,
    phase_data_done: bool,
}

struct FakeState {
    luns: Vec<FakeLun>,
    support_max_lun: bool,
    pending: Option<FakePending>,
    halt_in_dev: bool,
    halt_in_host: bool,
    halt_out_dev: bool,
    halt_out_host: bool,
    stall_data_in_once: bool,
    phase_error_once: bool,
    corrupt_csw_once: bool,
    stall_sense: [u8; 18],
    cbws: Vec<[u8; 31]>,
    bot_resets: usize,
    host_resets: usize,
    clear_features: usize,
    max_data_stage: u32,
}

struct FakeBot {
    state: IrqSafeSpinLock<FakeState>,
}

#[derive(Default)]
struct FakeStats {
    cbws: Vec<[u8; 31]>,
    bot_resets: usize,
    host_resets: usize,
    clear_features: usize,
    max_data_stage: u32,
}

impl FakeStats {
    fn cbw_opcode_count(&self, opcode: u8) -> usize {
        self.cbws.iter().filter(|c| c[15] == opcode).count()
    }
}

fn fake_stall() -> MscError {
    // xHCI completion code 6 (Stall Error), as the production
    // bulk path reports a device STALL.
    MscError::Xhci(XhciError::CmdFailed(6))
}

impl FakeBot {
    fn new(luns: Vec<FakeLun>) -> Self {
        Self::build(luns, true)
    }
    fn without_max_lun(luns: Vec<FakeLun>) -> Self {
        Self::build(luns, false)
    }
    fn build(luns: Vec<FakeLun>, support_max_lun: bool) -> Self {
        FakeBot {
            state: IrqSafeSpinLock::new(FakeState {
                luns,
                support_max_lun,
                pending: None,
                halt_in_dev: false,
                halt_in_host: false,
                halt_out_dev: false,
                halt_out_host: false,
                stall_data_in_once: false,
                phase_error_once: false,
                corrupt_csw_once: false,
                stall_sense: fake_sense(6, 0x29, 0x00),
                cbws: Vec::new(),
                bot_resets: 0,
                host_resets: 0,
                clear_features: 0,
                max_data_stage: 0,
            }),
        }
    }
    fn stats(&self) -> FakeStats {
        let st = self.state.lock();
        FakeStats {
            cbws: st.cbws.clone(),
            bot_resets: st.bot_resets,
            host_resets: st.host_resets,
            clear_features: st.clear_features,
            max_data_stage: st.max_data_stage,
        }
    }
    fn set_stall_data_in_once(&self) {
        self.state.lock().stall_data_in_once = true;
    }
    fn set_phase_error_once(&self) {
        self.state.lock().phase_error_once = true;
    }
    fn set_corrupt_csw_once(&self) {
        self.state.lock().corrupt_csw_once = true;
    }
    fn set_stall_sense(&self, sense: [u8; 18]) {
        self.state.lock().stall_sense = sense;
    }

    /// Execute one parsed CBW against the LUN model: decide the
    /// CSW status, stage any IN data, or arm the write sink.
    /// Mirrors the spec behaviours production must survive —
    /// UNIT ATTENTION reported once on the first command after
    /// power-on (and bypassed by INQUIRY / REQUEST SENSE, per
    /// SPC), absent media as NOT READY / 0x3A, and a refused
    /// command stalling its data phase rather than consuming it.
    fn execute(st: &mut FakeState, tag: u32, data_len: u32, is_in: bool, lun: usize, cdb: &[u8]) {
        st.max_data_stage = st.max_data_stage.max(data_len);
        let opcode = cdb[0];
        let mut status = 0u8;
        let mut staged: Option<Vec<u8>> = None;
        let mut write_need: Option<(u64, u64)> = None;
        let mut data_stall = false;
        if lun >= st.luns.len() {
            status = 1;
            data_stall = data_len > 0;
        } else if opcode == 0x03 {
            // REQUEST SENSE: report the pending sense, then the
            // condition is cleared (that is the drain).
            staged = Some(st.luns[lun].sense.to_vec());
            st.luns[lun].sense = fake_sense(0, 0, 0);
        } else if opcode == 0x12 {
            // INQUIRY (SPC-4 §6.5): standard 36-byte response.
            let mut buf = [0u8; 36];
            buf[0] = 0x00; // direct-access block device
            buf[1] = 0x80; // removable
            buf[2] = 0x05; // SPC-3
            buf[3] = 0x02; // response data format
            buf[4] = 31; // additional length
            buf[8..16].copy_from_slice(b"NARF    ");
            buf[16..32].copy_from_slice(b"FAKE BOT DISK   ");
            buf[32..36].copy_from_slice(b"1.00");
            staged = Some(buf.to_vec());
        } else if st.luns[lun].ua_pending {
            st.luns[lun].ua_pending = false;
            st.luns[lun].sense = fake_sense(6, 0x29, 0x00);
            status = 1;
            data_stall = data_len > 0;
        } else if !st.luns[lun].present {
            st.luns[lun].sense = fake_sense(2, 0x3A, 0x00);
            status = 1;
            data_stall = data_len > 0;
        } else {
            match opcode {
                0x00 | 0x1B | 0x35 => {}
                0x25 => {
                    let l = &st.luns[lun];
                    let last10 = if l.block_count - 1 > u64::from(u32::MAX) {
                        u32::MAX
                    } else {
                        (l.block_count - 1) as u32
                    };
                    let mut buf = [0u8; 8];
                    buf[0..4].copy_from_slice(&last10.to_be_bytes());
                    buf[4..8].copy_from_slice(&l.block_size.to_be_bytes());
                    staged = Some(buf.to_vec());
                }
                0x9E => {
                    if cdb[1] & 0x1F == 0x10 {
                        let l = &st.luns[lun];
                        let mut buf = [0u8; 32];
                        buf[0..8].copy_from_slice(&(l.block_count - 1).to_be_bytes());
                        buf[8..12].copy_from_slice(&l.block_size.to_be_bytes());
                        staged = Some(buf.to_vec());
                    } else {
                        st.luns[lun].sense = fake_sense(5, 0x20, 0x00);
                        status = 1;
                        data_stall = data_len > 0;
                    }
                }
                0x28 | 0x88 => {
                    let (lba, count) = if opcode == 0x28 {
                        (
                            u64::from(u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]])),
                            u64::from(u16::from_be_bytes([cdb[7], cdb[8]])),
                        )
                    } else {
                        (
                            u64::from_be_bytes([
                                cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
                            ]),
                            u64::from(u32::from_be_bytes([cdb[10], cdb[11], cdb[12], cdb[13]])),
                        )
                    };
                    if lba + count > st.luns[lun].block_count {
                        st.luns[lun].sense = fake_sense(5, 0x21, 0x00);
                        status = 1;
                        data_stall = data_len > 0;
                    } else {
                        let mut buf = Vec::new();
                        for i in 0..count {
                            buf.extend_from_slice(&st.luns[lun].block(lun as u8, lba + i));
                        }
                        staged = Some(buf);
                    }
                }
                0x2A | 0x8A => {
                    let (lba, count) = if opcode == 0x2A {
                        (
                            u64::from(u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]])),
                            u64::from(u16::from_be_bytes([cdb[7], cdb[8]])),
                        )
                    } else {
                        (
                            u64::from_be_bytes([
                                cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
                            ]),
                            u64::from(u32::from_be_bytes([cdb[10], cdb[11], cdb[12], cdb[13]])),
                        )
                    };
                    if lba + count > st.luns[lun].block_count {
                        st.luns[lun].sense = fake_sense(5, 0x21, 0x00);
                        status = 1;
                        data_stall = data_len > 0;
                    } else {
                        write_need = Some((lba, count));
                    }
                }
                _ => {
                    st.luns[lun].sense = fake_sense(5, 0x20, 0x00);
                    status = 1;
                    data_stall = data_len > 0;
                }
            }
        }
        let mut stall_patch = false;
        if status == 0 && is_in && staged.is_some() && st.stall_data_in_once {
            st.stall_data_in_once = false;
            data_stall = true;
            stall_patch = true;
        }
        if status == 0 && st.phase_error_once {
            st.phase_error_once = false;
            status = 2;
            staged = None;
            write_need = None;
            stall_patch = false;
            data_stall = data_len > 0;
        }
        let residue = if is_in && status != 0 {
            data_len
        } else if is_in {
            data_len - staged.as_ref().map_or(0, |v| v.len() as u32)
        } else {
            0
        };
        // CSW (§5.2): 'USBS', tag echo, residue, status.
        let mut csw = [0u8; 13];
        csw[0..4].copy_from_slice(&0x5342_5355u32.to_le_bytes());
        if st.corrupt_csw_once {
            st.corrupt_csw_once = false;
            csw[0] ^= 0xFF;
        }
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        csw[8..12].copy_from_slice(&residue.to_le_bytes());
        csw[12] = status;
        st.pending = Some(FakePending {
            lun,
            is_in,
            data_len,
            csw,
            staged_in: staged,
            write_need,
            data_stall,
            stall_patch,
            phase_data_done: false,
        });
    }
}

impl BotTransport for FakeBot {
    async fn bulk_in(&self, _slot_id: u8, _dci: u8, out: &mut [u8]) -> Result<usize, MscError> {
        let mut st = self.state.lock();
        if st.halt_in_dev || st.halt_in_host {
            st.halt_in_host = true;
            return Err(fake_stall());
        }
        // Data phase first, if the pending command has one.
        let data_phase = match &st.pending {
            Some(p) => p.is_in && p.data_len > 0 && !p.phase_data_done,
            None => false,
        };
        if data_phase {
            let (data_stall, stall_patch, lun) = {
                let p = st.pending.as_ref().unwrap();
                (p.data_stall, p.stall_patch, p.lun)
            };
            if data_stall {
                st.halt_in_dev = true;
                st.halt_in_host = true;
                if stall_patch {
                    let sense = st.stall_sense;
                    st.luns[lun].sense = sense;
                    if let Some(p) = &mut st.pending {
                        p.csw[12] = 1; // Command Failed
                    }
                }
                if let Some(p) = &mut st.pending {
                    p.phase_data_done = true;
                }
                return Err(fake_stall());
            }
            let staged = {
                let p = st.pending.as_mut().unwrap();
                let v = p.staged_in.take().unwrap_or_default();
                p.phase_data_done = true;
                v
            };
            let n = staged.len().min(out.len());
            out[..n].copy_from_slice(&staged[..n]);
            return Ok(n);
        }
        // Status phase: serve the CSW and close the command.
        match st.pending.take() {
            Some(p) => {
                let n = 13usize.min(out.len());
                out[..n].copy_from_slice(&p.csw[..n]);
                Ok(n)
            }
            None => Err(MscError::Xhci(XhciError::CmdTimeout)),
        }
    }

    async fn bulk_out(&self, _slot_id: u8, _dci: u8, data: &[u8]) -> Result<usize, MscError> {
        let mut st = self.state.lock();
        if st.halt_out_dev || st.halt_out_host {
            st.halt_out_host = true;
            return Err(fake_stall());
        }
        // A pending command expecting OUT data consumes this
        // transfer as its data phase (or stalls it, if refused).
        let expecting = match &st.pending {
            Some(p) => !p.is_in && p.data_len > 0 && !p.phase_data_done,
            None => false,
        };
        if expecting {
            let (data_stall, write_need, lun) = {
                let p = st.pending.as_ref().unwrap();
                (p.data_stall, p.write_need, p.lun)
            };
            if data_stall {
                st.halt_out_dev = true;
                st.halt_out_host = true;
                if let Some(p) = &mut st.pending {
                    p.phase_data_done = true;
                }
                return Err(fake_stall());
            }
            if let Some((lba, count)) = write_need {
                let bs = st.luns[lun].block_size as usize;
                let mut stored = 0u64;
                while stored < count && (stored as usize + 1) * bs <= data.len() {
                    let chunk = data[(stored as usize) * bs..(stored as usize + 1) * bs].to_vec();
                    st.luns[lun].written.insert(lba + stored, chunk);
                    stored += 1;
                }
            }
            if let Some(p) = &mut st.pending {
                p.phase_data_done = true;
            }
            return Ok(data.len());
        }
        if st.pending.is_some() {
            // Data nobody is waiting for (e.g. the payload of a
            // command whose data phase was already refused and
            // stalled once): the device sinks it.
            return Ok(data.len());
        }
        // CBW (§5.1): 31 bytes, 'USBC' signature little-endian.
        if data.len() != 31 {
            return Err(fake_stall());
        }
        let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if sig != 0x4342_5355 {
            return Err(fake_stall());
        }
        let mut raw = [0u8; 31];
        raw.copy_from_slice(data);
        st.cbws.push(raw);
        let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let data_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let is_in = data[12] & 0x80 != 0;
        let lun = data[13] as usize;
        let cb_len = ((data[14] & 0x1F) as usize).min(16);
        if cb_len == 0 {
            return Err(fake_stall());
        }
        let cdb = &data[15..15 + cb_len];
        Self::execute(&mut st, tag, data_len, is_in, lun, cdb);
        Ok(data.len())
    }

    async fn control_in(
        &self,
        _slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        _w_value: u16,
        _w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, MscError> {
        let st = self.state.lock();
        // GET MAX LUN (BOT §3.3): class/interface IN, 0xFE.
        if bm_request_type == 0xA1 && b_request == 0xFE {
            if !st.support_max_lun || out.is_empty() {
                return Err(fake_stall());
            }
            out[0] = (st.luns.len() - 1) as u8;
            return Ok(1);
        }
        Err(fake_stall())
    }

    async fn control_out(
        &self,
        _slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        _data: &[u8],
    ) -> Result<usize, MscError> {
        let mut st = self.state.lock();
        // Mass Storage Reset (BOT §5.3): class/interface OUT, 0xFF.
        if bm_request_type == 0x21 && b_request == 0xFF {
            st.bot_resets += 1;
            st.pending = None;
            st.halt_in_dev = false;
            st.halt_out_dev = false;
            for l in st.luns.iter_mut() {
                l.ua_pending = false;
            }
            return Ok(0);
        }
        // CLEAR_FEATURE(ENDPOINT_HALT) (USB 2.0 §9.4.1): standard
        // endpoint request, selector 0, wIndex = endpoint address.
        if bm_request_type == 0x02 && b_request == 0x01 && w_value == 0 {
            st.clear_features += 1;
            if w_index & 0x80 != 0 {
                st.halt_in_dev = false;
            } else {
                st.halt_out_dev = false;
            }
            return Ok(0);
        }
        // SET_CONFIGURATION and anything else class drivers issue
        // during bind: accept.
        Ok(0)
    }

    async fn reset_halted_endpoint(&self, _slot_id: u8, dci: u8) -> Result<(), MscError> {
        let mut st = self.state.lock();
        st.host_resets += 1;
        // DCI parity: odd = IN endpoint, even = OUT endpoint.
        if dci % 2 == 1 {
            st.halt_in_host = false;
        } else {
            st.halt_out_host = false;
        }
        Ok(())
    }
}

/// Fixture slot/DCIs for the conversation tests: slot 1, bulk-IN
/// on DCI 3 (endpoint 0x81), bulk-OUT on DCI 4 (endpoint 0x02) —
/// the same pairing the canned config blob in
/// `smoke_msc_config_descriptor_parse` describes.
const FAKE_SLOT: u8 = 1;
const FAKE_DCI_IN: u8 = 3;
const FAKE_DCI_OUT: u8 = 4;

async fn fake_attach(fake: &FakeBot) -> Result<Vec<crate::msc::MscDevice>, MscError> {
    crate::msc::attach_all_luns(fake, FAKE_SLOT, FAKE_DCI_IN, FAKE_DCI_OUT, 0).await
}

/// Happy path end to end against the fixture — attach, INQUIRY,
/// write, read back, pattern read — with the first CBW on the
/// wire pinned byte-for-byte against BOT §5.1: 'USBC', tag 1,
/// 8-byte data stage, IN flag set, LUN 0, CB length 10, and the
/// READ CAPACITY(10) CDB (0x25 followed by zeros).
async fn msc_fixture_happy_path(fake: &FakeBot) -> Result<(), &'static str> {
    let mut devs = fake_attach(fake)
        .await
        .map_err(|_| "attach_all_luns failed")?;
    if devs.len() != 1 {
        return Err("expected exactly one LUN device");
    }
    let dev = devs.remove(0);
    if dev.lun != 0 || dev.lba_bytes != 512 || dev.last_lba != 2047 || dev.cmd16 {
        return Err("attach capacity fields wrong");
    }
    let stats = fake.stats();
    let pin: [u8; 31] = [
        0x55, 0x53, 0x42, 0x43, // 'USBC'
        1, 0, 0, 0, // tag 1
        8, 0, 0, 0,    // data length 8
        0x80, // IN
        0,    // LUN 0
        10,   // CB length
        0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, // READ CAPACITY(10)
        0, 0, 0, 0, 0, 0, // CBWCB padding
    ];
    if stats.cbws.first() != Some(&pin) {
        return Err("first CBW differs from the BOT §5.1 byte pin");
    }
    let inq = dev.inquiry(fake).await.map_err(|_| "INQUIRY failed")?;
    if &inq[8..12] != b"NARF" {
        return Err("INQUIRY vendor string wrong");
    }
    let mut data = alloc::vec![0u8; 4 * 512];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xA5;
    }
    dev.write_blocks(fake, 100, 4, &data)
        .await
        .map_err(|_| "write_blocks failed")?;
    let back = dev
        .read_blocks(fake, 100, 4)
        .await
        .map_err(|_| "read_blocks failed")?;
    if back != data {
        return Err("written data did not round-trip");
    }
    let pat = dev
        .read_blocks(fake, 7, 1)
        .await
        .map_err(|_| "pattern read failed")?;
    if pat != fake_block_pattern(0, 7, 512) {
        return Err("unwritten block is not the fixture pattern");
    }
    Ok(())
}

fn smoke_msc_fixture_happy_path() -> TestResult {
    let fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512)]);
    match narf_scheduler::block_on(msc_fixture_happy_path(&fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_happy_path);

/// #828: a 100-block request (12.5 per-command chunks) reads and
/// writes correctly through the driver API, every individual BOT
/// data stage stays within the single DMA page, and the wire
/// shows exactly 13 READ(10) and 13 WRITE(10) CBWs.
async fn msc_fixture_chunked_io(fake: &FakeBot) -> Result<(), &'static str> {
    let mut devs = fake_attach(fake).await.map_err(|_| "attach failed")?;
    let dev = devs.remove(0);
    let got = dev
        .read_blocks(fake, 10, 100)
        .await
        .map_err(|_| "100-block read failed")?;
    let mut expect = Vec::new();
    for lba in 10..110 {
        expect.extend_from_slice(&fake_block_pattern(0, lba, 512));
    }
    if got != expect {
        return Err("100-block read returned wrong bytes");
    }
    let mut data = alloc::vec![0u8; 100 * 512];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7) ^ 0x3C;
    }
    dev.write_blocks(fake, 2000, 100, &data)
        .await
        .map_err(|_| "100-block write failed")?;
    let back = dev
        .read_blocks(fake, 2000, 100)
        .await
        .map_err(|_| "read-back of the 100-block write failed")?;
    if back != data {
        return Err("100-block write did not round-trip");
    }
    let stats = fake.stats();
    if stats.max_data_stage > 4096 {
        return Err("a BOT data stage exceeded the xHCI DMA page");
    }
    if stats.cbw_opcode_count(0x28) != 26 || stats.cbw_opcode_count(0x2A) != 13 {
        return Err("chunked I/O did not split into 13-command sequences");
    }
    Ok(())
}

fn smoke_msc_fixture_chunked_io() -> TestResult {
    let fake = FakeBot::new(alloc::vec![FakeLun::new(8192, 512)]);
    match narf_scheduler::block_on(msc_fixture_chunked_io(&fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_chunked_io);

/// #831: a two-slot reader binds both LUNs with their own
/// capacities, a read on LUN 1 returns LUN 1's data (the pattern
/// salts differ, so a LUN mix-up changes the bytes), some CBW on
/// the wire carries bCBWLUN = 1, and a device that stalls
/// GET MAX LUN still binds as single-LUN.
async fn msc_fixture_multi_lun(fake: &FakeBot) -> Result<(), &'static str> {
    let devs = fake_attach(fake).await.map_err(|_| "attach failed")?;
    if devs.len() != 2 {
        return Err("multi-LUN device did not bind both LUNs");
    }
    if devs[0].lun != 0 || devs[0].last_lba != 2047 {
        return Err("LUN 0 capacity wrong");
    }
    if devs[1].lun != 1 || devs[1].last_lba != 4095 {
        return Err("LUN 1 capacity wrong (slots share a capacity?)");
    }
    let a = devs[0]
        .read_blocks(fake, 5, 1)
        .await
        .map_err(|_| "LUN 0 read failed")?;
    let b = devs[1]
        .read_blocks(fake, 5, 1)
        .await
        .map_err(|_| "LUN 1 read failed")?;
    if a != fake_block_pattern(0, 5, 512) || b != fake_block_pattern(1, 5, 512) || a == b {
        return Err("reads crossed between LUNs");
    }
    if !fake.stats().cbws.iter().any(|c| c[13] == 1) {
        return Err("no CBW on the wire carried bCBWLUN=1");
    }
    Ok(())
}

fn smoke_msc_fixture_multi_lun() -> TestResult {
    let fake = FakeBot::new(alloc::vec![
        FakeLun::new(2048, 512),
        FakeLun::new(4096, 512)
    ]);
    if let Err(m) = narf_scheduler::block_on(msc_fixture_multi_lun(&fake)) {
        return TestResult::Fail(m);
    }
    let stubborn = FakeBot::without_max_lun(alloc::vec![FakeLun::new(64, 512)]);
    let outcome = narf_scheduler::block_on(async {
        match fake_attach(&stubborn).await {
            Ok(devs) if devs.len() == 1 && devs[0].lun == 0 => Ok(()),
            Ok(_) => Err("GET MAX LUN-refusing device bound the wrong LUN set"),
            Err(_) => Err("GET MAX LUN-refusing device failed to bind at all"),
        }
    });
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_multi_lun);

/// #831 edge: an empty second slot is skipped, not fatal; a
/// reader whose only slot is empty binds nothing and errors.
async fn msc_fixture_absent_lun(fake: &FakeBot, empty: &FakeBot) -> Result<(), &'static str> {
    let devs = fake_attach(fake)
        .await
        .map_err(|_| "bind with an empty second slot failed")?;
    if devs.len() != 1 || devs[0].lun != 0 {
        return Err("empty slot was bound (or the populated slot was lost)");
    }
    if fake_attach(empty).await.is_ok() {
        return Err("an all-empty reader bound successfully");
    }
    Ok(())
}

fn smoke_msc_fixture_absent_lun() -> TestResult {
    let fake = FakeBot::new(alloc::vec![
        FakeLun::new(2048, 512),
        FakeLun::absent(4096, 512),
    ]);
    let empty = FakeBot::new(alloc::vec![FakeLun::absent(2048, 512)]);
    match narf_scheduler::block_on(msc_fixture_absent_lun(&fake, &empty)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_absent_lun);

/// #832: a > 2 TiB LUN escalates to READ CAPACITY(16), reports
/// its full 64-bit capacity, and reads past the 32-bit boundary
/// with a READ(16) CDB carrying the untruncated LBA — while a
/// LUN of exactly 2^32 blocks (whose RC(10) also saturates)
/// correctly stays on the 10-byte forms.
async fn msc_fixture_capacity16(fake: &FakeBot) -> Result<(), &'static str> {
    let devs = fake_attach(fake).await.map_err(|_| "attach failed")?;
    if devs.len() != 2 {
        return Err("expected both capacity LUNs to bind");
    }
    let huge: u64 = (1 << 32) + 0x1000;
    if !devs[0].cmd16 || devs[0].last_lba != huge - 1 {
        return Err(">2 TiB LUN did not escalate to the 16-byte forms");
    }
    if devs[1].cmd16 || devs[1].last_lba != u64::from(u32::MAX) {
        return Err("exactly-2 TiB LUN was misclassified as 16-byte");
    }
    let hi: u64 = 1 << 32;
    let got = devs[0]
        .read_blocks(fake, hi, 2)
        .await
        .map_err(|_| "read past the 32-bit boundary failed")?;
    let mut expect = fake_block_pattern(0, hi, 512);
    expect.extend_from_slice(&fake_block_pattern(0, hi + 1, 512));
    if got != expect {
        return Err("read past the 32-bit boundary returned low-LBA bytes");
    }
    let stats = fake.stats();
    let read16 = stats
        .cbws
        .iter()
        .find(|c| c[15] == 0x88)
        .ok_or("no READ(16) CBW on the wire")?;
    if read16[17..25] != hi.to_be_bytes() {
        return Err("READ(16) CDB LBA field truncated");
    }
    if stats.cbw_opcode_count(0x9E) != 2 {
        return Err("READ CAPACITY(16) was not issued for both saturating LUNs");
    }
    let top = devs[1]
        .read_block(fake, u64::from(u32::MAX))
        .await
        .map_err(|_| "top-block read on the boundary LUN failed")?;
    if top != fake_block_pattern(1, u64::from(u32::MAX), 512) {
        return Err("boundary LUN top block wrong");
    }
    if fake.stats().cbws.last().map(|c| c[15]) != Some(0x28) {
        return Err("boundary LUN read did not use READ(10)");
    }
    Ok(())
}

fn smoke_msc_fixture_capacity16() -> TestResult {
    let huge: u64 = (1 << 32) + 0x1000;
    let exact: u64 = 1 << 32;
    let fake = FakeBot::new(alloc::vec![
        FakeLun::new(huge, 512),
        FakeLun::new(exact, 512),
    ]);
    match narf_scheduler::block_on(msc_fixture_capacity16(&fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_capacity16);

/// #830, first access: the device raises UNIT ATTENTION on the
/// very first READ CAPACITY (the classic powered-on bridge).
/// Attach must survive it — sense drained (a REQUEST SENSE on
/// the wire), capacity retried, correct values bound.
async fn msc_fixture_unit_attention(fake: &FakeBot) -> Result<(), &'static str> {
    let devs = fake_attach(fake)
        .await
        .map_err(|_| "attach did not survive first-access UNIT ATTENTION")?;
    if devs.len() != 1 || devs[0].last_lba != 2047 {
        return Err("capacity after UNIT ATTENTION recovery wrong");
    }
    let stats = fake.stats();
    if stats.cbw_opcode_count(0x03) < 1 {
        return Err("no REQUEST SENSE drained the UNIT ATTENTION");
    }
    if stats.cbw_opcode_count(0x25) < 2 {
        return Err("READ CAPACITY was not retried after the sense drain");
    }
    Ok(())
}

fn smoke_msc_fixture_unit_attention() -> TestResult {
    let fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512).with_ua()]);
    match narf_scheduler::block_on(msc_fixture_unit_attention(&fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_unit_attention);

/// #830, data-phase STALL: the read stalls mid-conversation;
/// production must clear the halt on both sides (a host
/// Reset Endpoint AND a device CLEAR_FEATURE are both visible),
/// drain the sense the stall carried, retry, and return the
/// right bytes.
async fn msc_fixture_stall_recovery(fake: &FakeBot) -> Result<(), &'static str> {
    let mut devs = fake_attach(fake).await.map_err(|_| "attach failed")?;
    let dev = devs.remove(0);
    fake.set_stall_data_in_once();
    let got = dev
        .read_blocks(fake, 3, 2)
        .await
        .map_err(|_| "read did not recover from a data-phase stall")?;
    let mut expect = fake_block_pattern(0, 3, 512);
    expect.extend_from_slice(&fake_block_pattern(0, 4, 512));
    if got != expect {
        return Err("post-stall read returned wrong bytes");
    }
    let stats = fake.stats();
    if stats.host_resets < 1 || stats.clear_features < 1 {
        return Err("stall recovery skipped one half of the halt clear");
    }
    if stats.cbw_opcode_count(0x28) != 2 {
        return Err("stalled read was not retried exactly once");
    }
    Ok(())
}

fn smoke_msc_fixture_stall_recovery() -> TestResult {
    let fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512)]);
    match narf_scheduler::block_on(msc_fixture_stall_recovery(&fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_stall_recovery);

/// #830, honest failure: a stall whose sense says MEDIUM ERROR
/// must NOT be retried, and the error must carry the sense data
/// (key 3, ASC 0x11) instead of a bare status.
async fn msc_fixture_medium_error(fake: &FakeBot) -> Result<(), &'static str> {
    let mut devs = fake_attach(fake).await.map_err(|_| "attach failed")?;
    let dev = devs.remove(0);
    fake.set_stall_sense(fake_sense(3, 0x11, 0x00));
    fake.set_stall_data_in_once();
    match dev.read_blocks(fake, 3, 2).await {
        Err(MscError::Sense(sense))
            if sense.sense_key == 3 && sense.additional_sense_code == 0x11 =>
        {
            Ok(())
        }
        Err(_) => Err("medium error surfaced without its sense data"),
        Ok(_) => Err("medium error read reported success"),
    }
}

fn smoke_msc_fixture_medium_error() -> TestResult {
    let fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512)]);
    let outcome = narf_scheduler::block_on(msc_fixture_medium_error(&fake));
    // The no-retry half of the verdict: exactly one READ CBW.
    let reads = fake.stats().cbw_opcode_count(0x28);
    match outcome {
        Ok(()) if reads == 1 => TestResult::Pass,
        Ok(()) => TestResult::Fail("a durable medium error was retried"),
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_medium_error);

/// #830, Reset Recovery: a Phase Error CSW and (separately) a
/// CSW with a corrupted signature must each trigger exactly one
/// BOT Mass Storage Reset and a successful retry.
async fn msc_fixture_reset_recovery(
    phase_fake: &FakeBot,
    csw_fake: &FakeBot,
) -> Result<(), &'static str> {
    let mut devs = fake_attach(phase_fake)
        .await
        .map_err(|_| "attach (phase) failed")?;
    let dev = devs.remove(0);
    phase_fake.set_phase_error_once();
    dev.test_unit_ready(phase_fake)
        .await
        .map_err(|_| "TEST UNIT READY did not recover from a Phase Error")?;
    if phase_fake.stats().bot_resets != 1 {
        return Err("Phase Error did not trigger exactly one Reset Recovery");
    }
    let mut devs = fake_attach(csw_fake)
        .await
        .map_err(|_| "attach (csw) failed")?;
    let dev = devs.remove(0);
    csw_fake.set_corrupt_csw_once();
    dev.test_unit_ready(csw_fake)
        .await
        .map_err(|_| "TEST UNIT READY did not recover from a bad CSW")?;
    if csw_fake.stats().bot_resets != 1 {
        return Err("bad CSW did not trigger exactly one Reset Recovery");
    }
    Ok(())
}

fn smoke_msc_fixture_reset_recovery() -> TestResult {
    let phase_fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512)]);
    let csw_fake = FakeBot::new(alloc::vec![FakeLun::new(2048, 512)]);
    match narf_scheduler::block_on(msc_fixture_reset_recovery(&phase_fake, &csw_fake)) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/usb/msc", smoke_msc_fixture_reset_recovery);
