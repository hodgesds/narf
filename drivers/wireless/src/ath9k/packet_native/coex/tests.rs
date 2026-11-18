//! Only the real Native boundary is exercised. Config/BAR addresses are
//! deliberately invalid: current record/PCI refusal must precede access.
//! The RAM record markers are format fixtures, not measured qualifications.
use super::*;
use crate::ath9k::{
    ar9003::{self, btcoex::concurrent},
    calibration::Permission,
};
use alloc::{boxed::Box, sync::Arc};
use narf_bus::{BarKind, BusAddr, BusKind, DeviceId, PcieAddr};
use narf_kernel_test::{kernel_test_in, TestResult};

fn refusal() -> Result<(), &'static str> {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for device_id in [0x0034, 0x0036] {
        for pci_lost in [false, true] {
            let fixture = concurrent::tests::fixture(device_id, 2412)?;
            let chip = if device_id == 0x0034 {
                ar9003::Chip::Ar9462
            } else {
                ar9003::Chip::Ar9565
            };
            let address = PcieAddr::new(0, 0, 7, 0);
            let device = BusDevice {
                addr: BusAddr::Pcie(address),
                id: DeviceId {
                    vendor: 0x168c,
                    device: device_id,
                    class: 0x028000,
                    subsystem_vendor: 0,
                    subsystem_id: 0,
                },
                kind: BusKind::Pcie {
                    addr: address,
                    cfg_phys: narf_memory::PhysAddr::new(0),
                },
            };
            let pci = Cap::<BusDeviceCap, Write>::bootstrap();
            let bar = MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: 0,
                len: crate::ath9k::phy::REQUIRED_BAR,
                kind: BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            let report = ar9003::calib::Report {
                frequency_mhz: 2412,
                five_ghz: false,
                rx_chainmask: fixture.base.tx_chainmask,
                tx_chainmask: fixture.base.tx_chainmask,
                peak_caldac: [None; 3],
                carrier_leak: None,
                default_nf: [-95; 3],
                tx_iq_cal: None,
                tx_iq_cal_enabled: false,
                tx_clcal: None,
            };
            let revision = ar9003::Revision {
                chip,
                mac_rev: 2,
                pcie: true,
            };
            let domain = narf_wireless::reg::db::snapshot().ok_or("native coex policy")?;
            let permission = Permission::from_domain_dual(&domain, 2412)
                .map_err(|_| "native coex permission")?;
            // Explicit test-only construction of the private Native shape;
            // no preparation/calibration or physical ownership is claimed.
            let mut native = Native::assemble(
                device,
                pci,
                bar,
                Calibrated::Ar9300 {
                    report: Box::new(report),
                    grant: fixture.grant.clone(),
                    permission,
                    clock: crate::ath9k::mac::Clock::Ofdm2g,
                    tx_chainmask: report.tx_chainmask,
                    apm: false,
                    rf_kill: None,
                    periodic: narf_lib::mutex::Mutex::new(ar9003::calib::Periodic::new(
                        &revision,
                        &report,
                        ar9003::calib::IqTotals::default(),
                        0,
                    )),
                    totals: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                        ar9003::calib::IqTotals::default(),
                    )),
                    antenna_profile: None,
                },
                1,
                Some(InstalledPower::Rates(
                    ar9003::power::rate_words(&fixture.base.targets).to_vec(),
                )),
                None,
            );
            native.mci_power = Some(narf_lib::sync::IrqSafeSpinLock::new(fixture.power));
            if pci_lost {
                pci.revoke();
            } else {
                fixture.cap.revoke();
            }
            let before = native.mci_power.as_ref().unwrap().lock().words();
            let mut entered = false;
            if native
                .coex_access(false, || {
                    entered = true;
                    Ok(())
                })
                .is_ok()
                || entered
                || native.mci_concurrent(true).is_ok()
                || native.ar9300_reset_coex_power(&fixture.base).is_ok()
                || native.mci_power.as_ref().unwrap().lock().words() != before
            {
                return Err(
                    "revoked real Native coex source reached invalid transport or changed history",
                );
            }
        }
    }
    Ok(())
}
fn smoke_ath9k_mci_real_native_revocation_precedes_config_mmio_and_power_history() -> TestResult {
    refusal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_real_native_revocation_precedes_config_mmio_and_power_history
);
