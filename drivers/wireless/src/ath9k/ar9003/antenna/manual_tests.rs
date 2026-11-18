//! Synthetic source/record/register actors; no measured RF or DMA claim.
use super::*;
use alloc::{collections::BTreeMap, vec};
use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn base() -> Result<(Base, Cap<FirmwareBlob, Read>), &'static str> {
    let id = narf_bus::DeviceId {
        subsystem_vendor: 0x168c,
        subsystem_id: 0x3119,
        ..super::super::tests::device()
    };
    let (profile, grant, original) =
        super::super::tests::fixture(id, 0xc0).map_err(|_| "manual original fixture")?;
    let (image, _) = super::super::tests::factory(0xc0);
    let domain = narf_wireless::reg::db::snapshot().ok_or("manual host policy")?;
    let permission = Permission::from_domain_dual(&domain, 2412)
        .map_err(|_| "manual permission")?
        .with_ceiling(0);
    let plan = super::super::super::power::plan(&image, 2412, 0x12, 0, 1)
        .map_err(|_| "manual actual plan")?;
    let report = super::super::super::calib::Report {
        frequency_mhz: 2412,
        five_ghz: false,
        rx_chainmask: 1,
        tx_chainmask: 1,
        peak_caldac: [None; 3],
        carrier_leak: None,
        default_nf: [-95; 3],
        tx_iq_cal: None,
        tx_iq_cal_enabled: false,
        tx_clcal: None,
    };
    Ok((
        Base::new(
            grant,
            permission,
            &report,
            &plan,
            profile,
            &image,
            super::super::super::board::Config::for_pci(&id),
        )
        .map_err(|_| "manual exact source facts")?,
        original,
    ))
}
fn record(base: &Base) -> Vec<u8> {
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(&base.kind.magic());
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, base.kind.device() as u8, 0]);
    b[16..48].copy_from_slice(&base.request.identity);
    b[48..54].copy_from_slice(&base.request.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 1]);
    b[58..60].copy_from_slice(&128i16.to_le_bytes());
    b[60..62].copy_from_slice(&(-256i16).to_le_bytes());
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    b
}
type SourceFixture = (Arc<Grant>, Cap<FirmwareBlob, Read>, Cap<FirmwareBlob, Read>);
fn fixture_source() -> Result<SourceFixture, &'static str> {
    let (base, original) = base()?;
    let b = record(&base);
    let cap = Cap::bootstrap();
    Ok((
        Arc::new(
            Grant::decode(base, &b, Some([0x48; 32]), cap)
                .map_err(|_| "manual N48D format fixture")?,
        ),
        cap,
        original,
    ))
}
fn install(latch: &Latch, source: Arc<Grant>) -> Result<(), &'static str> {
    let mut f = core::pin::pin!(latch.replace(source));
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(())) => Ok(()),
        _ => Err("manual installation unexpectedly pending/refused"),
    }
}
#[derive(Default)]
struct RegistersModel {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    bad_off: bool,
    fault: Option<(u64, u32)>,
}
impl RegisterIo for RegistersModel {
    fn read32(&mut self, r: u64) -> u32 {
        if let Some((bad, value)) = self.fault {
            if bad == r {
                return value;
            }
        }
        if self.bad_off && r == 0x817c {
            1
        } else {
            self.regs.get(&r).copied().unwrap_or(0)
        }
    }
    fn write32(&mut self, r: u64, v: u32) {
        self.writes.push((r, v));
        self.regs.insert(r, v);
    }
    fn delay_us(&mut self, _: u64) {}
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}

fn smoke_ath9k_ar9485_manual_off_receipts_and_original_disable_fields() -> TestResult {
    check(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        let (source, _, _) = fixture_source()?;
        let ordinary = source.base.inputs.ordinary & 0x00ff_ffff;
        let sharing = source.base.inputs.sharing & 0x00ff_ffff;
        let latch = Latch::new();
        install(&latch, source)?;
        let mut io = RegistersModel::default();
        io.regs.insert(0x9e28, 0x13ef0200);
        io.regs.insert(0xa28c, 0xa5000000);
        for (enabled, switch) in [(true, sharing), (false, ordinary)] {
            latch
                .program(&mut io, enabled)
                .map_err(|_| "source3WIRE/manual program")?;
            latch
                .ready(enabled)
                .map_err(|_| "manual readiness receipt")?;
            if io.regs.get(&0xa28c) != Some(&(0xa5000000 | switch))
                || io.regs.get(&0x8170) != Some(&0x1c00)
                || io.regs.get(&0x817c) != Some(&0)
                || io.regs.get(&0x9e28) != Some(&0x13ef0200)
                || io.regs.get(&0x9fc0).copied().unwrap_or(0) & 0x2000 == 0
                || !latch.bound()
                || latch.desired() != enabled
            {
                return Err("manual source masks/disable restoration/lease retention differ");
            }
            latch
                .readback(|r| Ok(io.read32(r)))
                .map_err(|_| "manual complete readback")?;
        }
        let first_manual = io
            .writes
            .iter()
            .position(|(r, _)| *r == 0xa28c)
            .ok_or("missing source switch write")?;
        if !io.writes[..first_manual].contains(&(0x83b8, 0)) {
            return Err("manual switch preceded actual last coex-off receipt");
        }
        io.regs.insert(0xa28c, 0);
        if latch.readback(|r| Ok(io.read32(r))).is_ok() {
            return Err("manual switch corruption escaped expected physical profile");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_manual_off_receipts_and_original_disable_fields
);

fn smoke_ath9k_ar9485_manual_old_tokens_reentrant_and_revocation_after_disable() -> TestResult {
    check(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        for original_loss in [false, true] {
            let latch = Latch::new();
            let captured_before = latch.clone();
            let (source, cap, original) = fixture_source()?;
            install(&latch, source)?;
            let mut io = RegistersModel::default();
            latch
                .program(&mut io, false)
                .map_err(|_| "manual disabled receipt")?;
            latch.ready(false).map_err(|_| "manual disabled ready")?;
            let effects = Cell::new(0);
            captured_before
                .current(true, || {
                    latch.current(true, || {
                        effects.set(effects.get() + 1);
                        Ok(())
                    })
                })
                .map_err(|_| "manual callback reentry")?;
            if original_loss {
                original.revoke();
            } else {
                cap.revoke();
            }
            if captured_before
                .current(true, || {
                    effects.set(99);
                    Ok(())
                })
                .is_ok()
                || effects.get() != 1
                || !latch.bound()
            {
                return Err("captured old token or explicit disable bypassed current joint source");
            }
            let writes = io.writes.len();
            if latch.program(&mut io, true).is_ok() || io.writes.len() != writes {
                return Err("revoked original/companion reached first hardware write");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_manual_old_tokens_reentrant_and_revocation_after_disable
);

fn smoke_ath9k_ar9485_manual_pending_install_cancel_and_off_uncertainty_are_terminal() -> TestResult
{
    check(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        let second = Latch::new();
        let (source, _, _) = fixture_source()?;
        let mut pending = alloc::boxed::Box::pin(second.replace(source));
        second
            .current(true, || {
                if pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return Err(Error::State);
                }
                Ok(())
            })
            .map_err(|_| "manual pending close")?;
        drop(pending);
        if second.current(true, || Ok(())).is_ok() {
            return Err("canceled manual installation reopened an old token");
        }
        let (source, _, _) = fixture_source()?;
        let off = Latch::new();
        install(&off, source)?;
        let mut io = RegistersModel {
            bad_off: true,
            ..Default::default()
        };
        if off.program(&mut io, true).is_ok()
            || io.writes.iter().any(|(r, _)| *r == 0xa28c)
            || off.current(true, || Ok(())).is_ok()
        {
            return Err("unproven coex-off receipt reached manual switch or reopened publication");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_manual_pending_install_cancel_and_off_uncertainty_are_terminal
);

type MciFixture = (
    Arc<Grant>,
    Cap<FirmwareBlob, Read>,
    super::super::super::btcoex::MciLink,
    super::super::super::btcoex::ManualMciFacts,
);
fn mci_source() -> Result<MciFixture, &'static str> {
    let id = narf_bus::DeviceId {
        device: 0x0036,
        ..super::super::tests::device()
    };
    let (profile, grant, _) = super::super::tests::fixture(id, 0).map_err(|_| "N65A fixture")?;
    let (image, _) = super::super::tests::factory(0);
    let domain = narf_wireless::reg::db::snapshot().ok_or("N65D policy")?;
    let permission = Permission::from_domain_dual(&domain, 2412)
        .map_err(|_| "N65D permission")?
        .with_ceiling(0);
    let plan =
        super::super::super::power::plan(&image, 2412, 0x12, 0, 1).map_err(|_| "N65D plan")?;
    let report = super::super::super::calib::Report {
        frequency_mhz: 2412,
        five_ghz: false,
        rx_chainmask: 1,
        tx_chainmask: 1,
        peak_caldac: [None; 3],
        carrier_leak: None,
        default_nf: [-95; 3],
        tx_iq_cal: None,
        tx_iq_cal_enabled: false,
        tx_clcal: None,
    };
    let (link, facts) = super::super::super::btcoex::synthetic_manual_mci()
        .map_err(|_| "N65D synthetic retained ring")?;
    let base = Base::new_mci(
        grant,
        permission,
        &report,
        &plan,
        profile,
        &image,
        super::super::super::board::Config::for_pci(&id),
        facts,
    )
    .map_err(|_| "N65D completed-source binding")?;
    let b = record(&base);
    let cap = Cap::bootstrap();
    let source =
        Grant::decode(base, &b, Some([0x65; 32]), cap).map_err(|_| "N65D distinct record")?;
    Ok((Arc::new(source), cap, link, facts))
}
fn live_mci_registers(facts: super::super::super::btcoex::ManualMciFacts) -> RegistersModel {
    let bytes = facts.bytes();
    let word = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    let mut io = RegistersModel::default();
    for (r, v) in [
        (0x18ac, 4),
        (0x1820, word(4)),
        (0x1824, word(8)),
        (0x1818, word(12)),
        (0x9e28, 0x126f0600),
        (0x9fc0, 0x2000),
    ] {
        io.regs.insert(r, v);
    }
    io
}
fn smoke_ath9k_ar9565_n65d_actual_local_stop_retains_owner_and_distinct_manual_fields() -> TestResult
{
    check(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        let (source, cap, mut link, facts) = mci_source()?;
        let ring = link.dma.clone().ok_or("N65D original ring")?;
        let latch = Latch::new();
        let old = latch.clone();
        install(&latch, source)?;
        let mut io = live_mci_registers(facts);
        latch
            .current(false, || {
                link.stop_for_manual(&mut io, facts)
                    .map_err(|_| Error::Access)
            })
            .map_err(|_| "actual MCI source stop/cleanup")?;
        if link.can_reset()
            || link.mci_enabled()
            || link.dma.as_ref().is_none_or(|d| !Arc::ptr_eq(d, &ring))
            || link.manual_facts().ok() != Some(facts)
        {
            return Err("manual stop reopened/freed original MCI owner");
        }
        link.btcoex.mci.ready = true;
        if link.reset_ready().is_ok() {
            return Err("future reset_ready bypassed permanent MCI producer retirement");
        }
        link.btcoex.mci.ready = false;
        for (enabled, mc, fast, restart, force) in [
            (true, 0x13ef0600, 0x2000, 0x200000, 0x8000),
            (false, 0x126f0600, 0, 0, 0),
        ] {
            latch
                .program(&mut io, enabled)
                .map_err(|_| "source AR9565 manual program")?;
            latch.ready(enabled).map_err(|_| "N65D actual receipts")?;
            if io.regs.get(&0x9e28) != Some(&mc)
                || io.regs.get(&0x9fc0).copied().unwrap_or(0) & 0x2000 != fast
                || io.regs.get(&0x9e24).copied().unwrap_or(0) & 0x200000 != restart
                || io.regs.get(&0x1a64).copied().unwrap_or(0) & 0x8000 != force
                || io
                    .writes
                    .iter()
                    .any(|(r, _)| matches!(*r, 0xa28c | 0x4050 | 0x4068 | 0x8174))
            {
                return Err("AR9565 used AR9485 switch/GPIO program or wrong source bits");
            }
            latch
                .readback(|r| Ok(io.read32(r)))
                .map_err(|_| "N65D local off/manual readback")?;
        }
        cap.revoke();
        if old.current(true, || Ok(())).is_ok() || !latch.bound() || link.dma.is_none() {
            return Err("disabled N65D or captured token lost mandatory source/ring retention");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_n65d_actual_local_stop_retains_owner_and_distinct_manual_fields
);

fn smoke_ath9k_ar9565_n65d_live_pointer_and_mode_receipt_failure_keep_mci_retired() -> TestResult {
    check(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        for fault in [(0x1820, 0), (0x18ac, 4)] {
            let (source, _, mut link, facts) = mci_source()?;
            let retained = link.dma.clone().ok_or("uncertain original ring")?;
            let latch = Latch::new();
            install(&latch, source)?;
            let mut io = live_mci_registers(facts);
            io.fault = Some(fault);
            if latch
                .current(false, || {
                    link.stop_for_manual(&mut io, facts)
                        .map_err(|_| Error::Access)
                })
                .is_ok()
                || link.can_reset()
                || link.mci_enabled()
                || link.dma.as_ref().is_none_or(|d| !Arc::ptr_eq(d, &retained))
                || latch.current(true, || Ok(())).is_ok()
                || io
                    .writes
                    .iter()
                    .any(|(r, _)| matches!(*r, 0x9e28 | 0x9fc0 | 0x9e24 | 0x1a64))
            {
                return Err(
                    "unproven live pointer/local off reached antenna or reclaimed/reopened MCI",
                );
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_n65d_live_pointer_and_mode_receipt_failure_keep_mci_retired
);
