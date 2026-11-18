// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual Native + scoped RAM ECAM/BAR, with real current record CapOps.
//! Synthetic EEPROM/calibration/sleep metadata is seeded explicitly; this
//! proves the refusal boundary, not physical preparation or RF acceptance.
use super::*;
use crate::ath9k::{
    admission::{Facts, Source},
    ar9003::{self, board, eeprom, phy, power, serdes, templates::AR9300_DEFAULT},
    calibration::Permission,
    ps,
};
use alloc::{boxed::Box, sync::Arc, vec};
use narf_bus::{BarKind, BusAddr, BusKind, DeviceId, PcieAddr};
use narf_capabilities::Read;
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};

const WA: u32 = 0x0040_4000;
struct Sources {
    calibrated: Calibrated,
    sleep: Arc<ps::Grant>,
    original_cap: Cap<FirmwareBlob, Read>,
    sleep_cap: Cap<FirmwareBlob, Read>,
}
fn sources(id: &DeviceId, gpio: u8, polarity: bool) -> Result<Sources, &'static str> {
    let mut image = AR9300_DEFAULT;
    image[eeprom::field::TXRX_MASK] = 0x33;
    image[ar9003::mac::RF_SILENT] = 1 | (u8::from(polarity) << 1) | (gpio << 2);
    let kill = ar9003::mac::rf_silent(&image).map_err(|_| "N46S EEPROM RFkill")?;
    let identity = eeprom::Identity {
        mac: [2, 1, 2, 3, 4, 5],
        eeprom_version: image[0],
        template_version: image[1],
        regulatory_domains: [0x3a, 0],
        op_flags: 3,
        rx_chainmask: 3,
        tx_chainmask: 3,
        tx_gain: 0,
        rx_gain: 0,
    };
    let revision = ar9003::Revision {
        chip: ar9003::Chip::Ar9462,
        mac_rev: 2,
        pcie: true,
    };
    let prepared = phy::expected_with_board(
        &revision,
        &identity,
        serdes::PllPwrsave::resolve(revision.chip, 0, 0),
        &image,
        2412,
        0x12,
        0,
        board::Config::for_pci(id),
    )
    .map_err(|_| "N46S RFkill preparation facts")?;
    let facts = Facts::new_ar9003(id, &revision, &identity, &prepared, &image, 2412, 0x12)
        .map_err(|_| "N46A RFkill original facts")?;
    let request = facts.request();
    let mut record = vec![0u8; 128];
    record[..12].copy_from_slice(b"N46A\x01\0\x80\0\x80\0\0\0");
    record[12..16].copy_from_slice(&[0x8c, 0x16, 0x34, 0]);
    record[16..48].copy_from_slice(&request.identity);
    record[48..54].copy_from_slice(&request.mac);
    let antenna = image[eeprom::modal_base(false) + eeprom::modal::ANTENNA_GAIN] as i8;
    record[54..60].copy_from_slice(&[1, 20, 3, 3, antenna.max(0) as u8, 40]);
    let original_cap = Cap::bootstrap();
    let grant = Source::Verified {
        bytes: record,
        signer: Some([0x46; 32]),
        cap: original_cap,
    }
    .load(facts)
    .map_err(|_| "N46A RFkill original source")?;
    let plan = power::plan(&image, 2412, 0x12, grant.ceiling(40), 3)
        .map_err(|_| "N46S RFkill power plan")?;
    let domain = narf_wireless::reg::db::snapshot().ok_or("N46S RFkill host policy")?;
    let permission = Permission::from_domain_dual(&domain, 2412)
        .map_err(|_| "N46S RFkill permission")?
        .with_ceiling(grant.ceiling(40));
    let report = ar9003::calib::Report {
        frequency_mhz: 2412,
        five_ghz: false,
        rx_chainmask: 3,
        tx_chainmask: 3,
        peak_caldac: [None; 3],
        carrier_leak: None,
        default_nf: [-95; 3],
        tx_iq_cal: None,
        tx_iq_cal_enabled: false,
        tx_clcal: None,
    };
    let base = ar9003::ps::Base::new(0x0034, grant.clone(), permission, &report, &plan, WA, true)
        .map_err(|_| "N46S RFkill calibration binding")?
        .ok_or("N46S RFkill missing base")?;
    let request = base.request();
    let mut record = vec![0; 128];
    record[..8].copy_from_slice(b"N46S\x01\0\x80\0");
    record[8..12].copy_from_slice(&128u32.to_le_bytes());
    record[12..16].copy_from_slice(&[0x8c, 0x16, 0x34, 0]);
    record[16..48].copy_from_slice(&request.identity);
    record[48..54].copy_from_slice(&request.mac);
    record[54..58].copy_from_slice(&base.body());
    record[58..60].copy_from_slice(&base.limits().0.to_le_bytes());
    record[60..62].copy_from_slice(&12i16.to_le_bytes());
    record[62..64].copy_from_slice(&40i16.to_le_bytes());
    record[64..80].copy_from_slice(&[1, 0, 0, 4, 255, 8, 0xd0, 7, 0, 4, 1, 1, 0, 0, 0, 0]);
    record[80..112].copy_from_slice(&base.digest());
    let sleep_cap = Cap::bootstrap();
    let sleep = ps::Source::Verified {
        bytes: record,
        signer: Some([0x53; 32]),
        cap: sleep_cap,
    }
    .load_ar9003(base)
    .map_err(|_| "N46S RFkill sleep source")?;
    Ok(Sources {
        calibrated: Calibrated::Ar9300 {
            report: Box::new(report),
            grant,
            permission,
            clock: crate::ath9k::mac::Clock::Ofdm2g,
            tx_chainmask: 3,
            apm: false,
            rf_kill: kill,
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
        sleep,
        original_cap,
        sleep_cap,
    })
}

fn refusal() -> Result<(), &'static str> {
    use ps::hardware::Raw;
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for (gpio, polarity) in [(1, false), (6, true)] {
        for loss in 0..7 {
            let address = PcieAddr::new(0x7f46, 0, 0, 0);
            let id = DeviceId {
                vendor: 0x168c,
                device: 0x0034,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            };
            let source = sources(&id, gpio, polarity)?;
            let mut config = vec![0u32; 1024].into_boxed_slice();
            config[1] = u32::from(
                narf_bus::pci::cmd::MEM_SPACE
                    | narf_bus::pci::cmd::INTX_DISABLE
                    | narf_bus::pci::cmd::BUS_MASTER,
            );
            let physical = narf_memory::PhysAddr::new(0x7f46_0000);
            // SAFETY: this private RAM config page outlives the scoped ECAM
            // guard and Native; it is never a registered physical endpoint.
            let _ecam = unsafe {
                narf_bus::ecam::__test_windows(&[(physical, config.as_mut_ptr().cast(), 4096)])
            };
            let device = BusDevice {
                addr: BusAddr::Pcie(address),
                id,
                kind: BusKind::Pcie {
                    addr: address,
                    cfg_phys: physical,
                },
            };
            let pci = Cap::<BusDeviceCap, Write>::bootstrap();
            let mut registers =
                vec![0u32; crate::ath9k::phy::REQUIRED_BAR as usize / 4].into_boxed_slice();
            registers[0x7044 / 4] = 4;
            registers[0x704c / 4] = 2;
            registers[0x4004 / 4] = WA & !0x4000;
            registers[0x8004 / 4] = 0x40000;
            registers[0x404c / 4] = if polarity { 0 } else { 1 << gpio };
            let bar = MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: registers.as_mut_ptr() as u64,
                len: crate::ath9k::phy::REQUIRED_BAR,
                kind: BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            let mut native = Native::assemble(device, pci, bar, source.calibrated, 1, None, None);
            *native.ps.lock() = Some(source.sleep.clone());
            native.active.store(true, Ordering::Release);
            native.ps_bound.store(true, Ordering::Release);
            // Initial successful doze metadata is intentionally synthetic;
            // all subsequent source/config/GPIO/awake effects are Native.
            native.ps_sleeping.store(true, Ordering::Release);
            if loss == 1 {
                let raw = PowerRaw {
                    native: &native,
                    source: &source.sleep,
                };
                if Raw::read(&raw, 0x7044) != Ok(4) {
                    return Err("inactive configured RFkill denied raw RTC proof");
                }
            }
            if loss < 4 {
                registers[0x404c / 4] = match loss {
                    0 | 1 => {
                        if polarity {
                            1 << gpio
                        } else {
                            0
                        }
                    }
                    2 => u32::MAX,
                    _ => 0xdead_beef,
                };
            } else {
                match loss {
                    4 => source.original_cap.revoke(),
                    5 => source.sleep_cap.revoke(),
                    _ => pci.revoke(),
                }
                // An unauthorized GPIO/read/write would fault, not merely
                // return a convenient value from the inert register file.
                native.bar.virt = 0;
            }
            let before = registers.to_vec();
            let result = if loss == 1 {
                let raw = PowerRaw {
                    native: &native,
                    source: &source.sleep,
                };
                Raw::write(&raw, 0x4004, WA)
            } else {
                native.read(0x7044).map(|_| ())
            };
            if result != Err(Error::Access)
                || registers.as_ref() != before.as_slice()
                || !native.ps_sleeping.load(Ordering::Acquire)
                || !native.active.load(Ordering::Acquire)
            {
                return Err(
                    "N46S RFkill/source loss wrote wake state or fabricated awake/retirement",
                );
            }
            if loss < 4 {
                if !native.ps_failed.load(Ordering::Acquire) {
                    return Err("asserted RFkill failed to latch terminal sleep uncertainty");
                }
                registers[0x404c / 4] = if polarity { 0 } else { 1 << gpio };
                let before = registers.to_vec();
                if native.read(0x7044) != Err(Error::Access)
                    || registers.as_ref() != before.as_slice()
                {
                    return Err("released RFkill revived uncertain N46S sleep owner");
                }
            }
        }
    }
    Ok(())
}
fn smoke_ath9k_ar9462_native_rfkill_precedes_raw_wake_and_sleep_effects() -> TestResult {
    refusal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_native_rfkill_precedes_raw_wake_and_sleep_effects
);
