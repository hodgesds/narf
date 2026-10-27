//! One task and one control channel per PCI NHI function.
use super::{control::Control, nhi::Nhi, ring::Ring};
use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

struct Pending {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    nhi: Nhi,
}
static PENDING: IrqSafeSpinLock<Vec<Pending>> = IrqSafeSpinLock::new(Vec::new());
pub(crate) fn retain(device: BusDevice, cap: Cap<BusDeviceCap, Write>, nhi: Nhi) {
    PENDING.lock().push(Pending { device, cap, nhi });
}
pub(crate) fn start() -> narf_init::InitResult {
    let pending = core::mem::take(&mut *PENDING.lock());
    if pending.is_empty() {
        return narf_init::InitResult::NotPresent;
    }
    // Legacy ICM gate (see `super::icm`): on firmware-CM hosts the
    // fabric already has a connection manager, and starting ring 0
    // would fight it for the routers. Classify every controller
    // from its firmware status before any native-CM act — including
    // the `_OSC` request below, which is not made at all when no
    // controller is native. Standing down is a first-class
    // outcome, logged and recorded per domain, not an error.
    let mut native = Vec::new();
    for (domain, pending) in pending.into_iter().enumerate() {
        let verdict = super::icm::detect(&pending.cap, &pending.nhi);
        super::icm::record(domain as u32, verdict);
        match verdict.mode {
            super::icm::CmMode::Native => native.push((domain, pending)),
            super::icm::CmMode::FirmwareManaged => {
                let _ = writeln!(
                    narf_console::Writer,
                    "usb4: domain {domain} is firmware-managed (legacy ICM, FW_STS={:#010x}); \
                     native CM standing down",
                    verdict.fw_sts.unwrap_or(0),
                );
            }
            mode => {
                let _ = writeln!(
                    narf_console::Writer,
                    "usb4: domain {domain} firmware state {mode:?} (FW_STS={:#010x}); \
                     native CM standing down",
                    verdict.fw_sts.unwrap_or(0),
                );
            }
        }
    }
    if native.is_empty() {
        let _ = writeln!(
            narf_console::Writer,
            "usb4: no natively managed controllers; native CM not started"
        );
        return narf_init::InitResult::NotPresent;
    }
    let Some(control) = super::firmware::native_control() else {
        let _ = writeln!(
            narf_console::Writer,
            "usb4: firmware did not grant native USB4 control"
        );
        return narf_init::InitResult::NotPresent;
    };
    // Name the per-protocol grant explicitly: a protocol firmware
    // did not grant is never programmed, and the boot log is where
    // that state is visible instead of being inferred later from
    // missing tunnels.
    let _ = writeln!(
        narf_console::Writer,
        "usb4: firmware granted native control: USB3 {}, DisplayPort {}, PCIe {}, XDomain {}",
        if control & super::firmware::CONTROL_USB3 != 0 {
            "yes"
        } else {
            "no"
        },
        if control & super::firmware::CONTROL_DP != 0 {
            "yes"
        } else {
            "no"
        },
        if control & super::firmware::CONTROL_PCIE != 0 {
            "yes"
        } else {
            "no"
        },
        if control & super::firmware::CONTROL_XDOMAIN != 0 {
            "yes"
        } else {
            "no"
        },
    );
    // Join the device-PM fan-out with the state-checked handlers in
    // `pm.rs`: system sleep is refused only while tunnels are live
    // or a fault left path writes unrolled-back — an idle or stopped
    // CM never vetoes suspend (#1028).
    super::pm::register();
    for (domain, pending) in native {
        narf_scheduler::spawn(async move {
            let Pending { device, cap, nhi } = pending;
            // SAFETY: probe owns this PCI function; platform granted native CM.
            let mut ring =
                match unsafe { Ring::new(nhi.bar0, nhi.hop_count, device.id.vendor == 0x8086) } {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "usb4: domain {domain} ring allocation: {e:?}"
                        );
                        return;
                    }
                };
            ring.bind_authority(cap);
            if !ring.stop() {
                let _ = writeln!(
                    narf_console::Writer,
                    "usb4: domain {domain} did not stop its old rings"
                );
                return;
            }
            if nhi.nhi_version < 0x40 {
                // SAFETY: native ownership and validated NHI aperture. v1
                // interfaces require tHIReset before rings can be reused.
                if cap
                    .invoke(super::ring::IoOp(|| {
                        // SAFETY: invoked under current ownership of this PCI function.
                        unsafe { nhi.bar0.write32(0x39858, 1) }
                    }))
                    .is_err()
                {
                    return;
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(20).as_instant()).await;
            }
            if let Ok(Err(e)) = cap.invoke(super::ring::IoOp(|| ring.install_irq(&device, &cap))) {
                let _ = writeln!(
                    narf_console::Writer,
                    "usb4: domain {domain} MSI-X unavailable ({e:?}), using timed polling"
                );
            }
            if cap.invoke(super::ring::IoOp(|| ring.start())).is_err() {
                return;
            }
            if narf_bus::pci::set_command(
                &cap,
                &device,
                narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
            )
            .is_err()
            {
                return;
            }
            let mut ctl = Control::new(ring);
            let result = super::topology::run(domain as u32, control, &mut ctl).await;
            // Stop interrupt generation even if subsequent capability-checked
            // PCI bus-master revocation fails and DMA must stay quarantined.
            ctl.ring.stop();
            // Revoke bus mastering before dropping DMA memory on every exit.
            let disabled =
                narf_bus::pci::clear_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER).is_ok();
            if !disabled {
                core::mem::forget(ctl);
            }
            let _ = writeln!(
                narf_console::Writer,
                "usb4: domain {domain} stopped: {result:?}"
            );
        });
    }
    narf_init::InitResult::Ok
}
