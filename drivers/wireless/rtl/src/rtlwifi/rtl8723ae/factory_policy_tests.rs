// SPDX-License-Identifier: GPL-2.0-or-later
//! Native Rust tests over the actual checked factory owner; execution deferred.
use super::*;
use alloc::{sync::Arc, vec::Vec};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Read(u8, u16),
    Write(u8, u16, u32),
    Settle,
}
struct Model {
    regs: [u8; 0x100],
    raw: [u8; 512],
    events: Vec<Event>,
    active: bool,
    address: usize,
    ready_reads: usize,
    pa_ready_after: usize,
    revoke_on: Option<Event>,
    ignore_close: bool,
    data_error: bool,
    lost_status: bool,
}
#[derive(Clone)]
pub(in crate::rtlwifi::rtl8723ae) struct Port {
    model: Arc<IrqSafeSpinLock<Model>>,
    cap: Cap<BusDeviceCap, Write>,
}
impl Port {
    pub(in crate::rtlwifi::rtl8723ae) fn new(expected: &Factory, pa: u8) -> Self {
        // Encode a real physical EFUSE program map, not logical-address
        // aliasing. All32 blocks fit304 bytes; protected PA506 is separate.
        let mut raw = [0xff; 512];
        let mut at = 0;
        for (section, block) in expected.logical[..256].chunks_exact(8).enumerate() {
            if section < 16 {
                raw[at] = (section << 4) as u8;
                at += 1;
            } else {
                raw[at] = (((section & 7) << 5) | 0x0f) as u8;
                raw[at + 1] = ((section & 0x78) << 1) as u8;
                at += 2;
            }
            raw[at..at + 8].copy_from_slice(block);
            at += 8;
        }
        raw[506] = pa;
        let mut regs = [0; 0x100];
        regs[0xf2] = 1; // BT_FUNC, normal8723 series.
        regs[0x0a] = 0x20;
        regs[0x34..0x38].copy_from_slice(&0x1234_0300u32.to_le_bytes());
        Self {
            model: Arc::new(IrqSafeSpinLock::new(Model {
                regs,
                raw,
                events: Vec::new(),
                active: false,
                address: 0,
                ready_reads: 0,
                pa_ready_after: 1,
                revoke_on: None,
                ignore_close: false,
                data_error: false,
                lost_status: false,
            })),
            cap: Cap::bootstrap(),
        }
    }
    fn operation<T>(
        &self,
        event: Event,
        f: impl FnOnce(&mut Model) -> Result<T, AccessError>,
    ) -> Result<T, AccessError> {
        narf_drivers_wireless_rtw::rtw88::pci_park::invoke(&self.cap, || {
            let (result, revoke) = {
                let mut m = self.model.lock();
                m.events.push(event);
                (f(&mut m), m.revoke_on == Some(event))
            };
            if revoke {
                self.cap.revoke();
            }
            result
        })
        .map_err(|_| AccessError::Access)?
    }
    fn writes(&self) -> Vec<Event> {
        self.model
            .lock()
            .events
            .iter()
            .filter(|e| matches!(e, Event::Write(..)))
            .copied()
            .collect()
    }
    fn set32(&self, r: u16, v: u32) {
        self.model.lock().regs[usize::from(r)..usize::from(r) + 4]
            .copy_from_slice(&v.to_le_bytes());
    }
}
fn ready(m: &mut Model) {
    if m.active {
        m.ready_reads += 1;
        let bound = if m.address == 506 {
            m.pa_ready_after
        } else {
            1
        };
        if m.ready_reads >= bound {
            m.regs[0x33] |= 0x80;
            m.active = false;
        }
    }
}
impl Regs for Port {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        self.operation(Event::Read(1, r), |m| {
            if r == 0x33 {
                if m.active && m.lost_status {
                    return Ok(0xff);
                }
                ready(m);
            }
            if r == 0x30 {
                if m.data_error {
                    return Err(AccessError::Access);
                }
                return Ok(m.raw[m.address]);
            }
            Ok(m.regs[usize::from(r)])
        })
    }
    fn read16(&self, r: u16) -> Result<u16, AccessError> {
        self.operation(Event::Read(2, r), |m| {
            Ok(u16::from_le_bytes(
                m.regs[usize::from(r)..usize::from(r) + 2]
                    .try_into()
                    .unwrap(),
            ))
        })
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        self.operation(Event::Read(4, r), |m| {
            if r == 0x30 {
                if m.active && m.lost_status {
                    return Ok(u32::MAX);
                }
                ready(m);
                if m.data_error {
                    return Err(AccessError::Access);
                }
                m.regs[0x30] = m.raw[m.address];
            }
            Ok(u32::from_le_bytes(
                m.regs[usize::from(r)..usize::from(r) + 4]
                    .try_into()
                    .unwrap(),
            ))
        })
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        self.operation(Event::Write(1, r, u32::from(v)), |m| {
            if r == 0xcf && v == 0 && m.ignore_close {
                return Ok(());
            }
            m.regs[usize::from(r)] = v;
            if r == 0x33 && v & 0x80 == 0 {
                m.address = usize::from(m.regs[0x31]) | (usize::from(m.regs[0x32] & 3) << 8);
                m.active = true;
                m.ready_reads = 0;
            }
            Ok(())
        })
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        self.operation(Event::Write(2, r, u32::from(v)), |m| {
            m.regs[usize::from(r)..usize::from(r) + 2].copy_from_slice(&v.to_le_bytes());
            Ok(())
        })
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        self.operation(Event::Write(4, r, v), |m| {
            m.regs[usize::from(r)..usize::from(r) + 4].copy_from_slice(&v.to_le_bytes());
            Ok(())
        })
    }
    fn settle_map_data(&self) {
        self.model.lock().events.push(Event::Settle);
    }
}

/// Actual Io default read16 must refuse, rather than silently widen/split.
struct NoWords(Port);
#[async_trait::async_trait]
impl crate::rtlwifi::firmware_transport::Io for NoWords {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        Regs::read8(&self.0, r)
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        Regs::read32(&self.0, r)
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        Regs::write8(&self.0, r, v)
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        Regs::write16(&self.0, r, v)
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        Regs::write32(&self.0, r, v)
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Access)
    }
}

pub(crate) fn expected() -> Arc<Factory> {
    let mut logical = [0xff; 512];
    logical[..256].copy_from_slice(&super::super::tests::provisioned());
    logical[0x10..=0x12].fill(10);
    logical[0x16..=0x18].fill(10);
    logical[0x1c..=0x27].fill(0);
    logical[0x2b] = 2;
    Arc::new(Factory {
        mac: logical[0x67..0x6d].try_into().unwrap(),
        logical,
    })
}
fn acquire(owner: &mut Owner, port: &Port, f: Arc<Factory>) -> Result<Arc<Inputs>, Failure> {
    // SAFETY: inert private physical-map/register model, no device or DMA.
    unsafe { owner.acquire(port, f) }
}
pub(crate) fn inputs() -> Arc<Inputs> {
    inputs_for(expected(), 0xff)
}
pub(crate) fn inputs_for(f: Arc<Factory>, pa: u8) -> Arc<Inputs> {
    let p = Port::new(&f, pa);
    acquire(&mut Owner::default(), &p, f).expect("inert checked AE factory fixture")
}

fn smoke_rtl8723ae_factory_physical_widths_and_ff_data() -> TestResult {
    let f = expected();
    let p = Port::new(&f, 0xff);
    let mut owner = Owner::default();
    let input = match acquire(&mut owner, &p, f.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("checked physical factory"),
    };
    kt_assert_eq!(owner.state(), State::Ready);
    kt_assert_eq!(owner.gate(), Gate::Closed);
    kt_assert!(owner.cleanup_receipt().is_some());
    kt_assert_eq!(input.pa(), 0xff);
    kt_assert_eq!(input.adapter().hwinfo[0x2a], 0xff); // unused thermal stays exact
    kt_assert_eq!(input.factory().logical, f.logical);
    let m = p.model.lock();
    kt_assert_eq!(
        m.events.iter().filter(|e| **e == Event::Settle).count(),
        497
    );
    kt_assert!(m.events.contains(&Event::Read(2, 2)));
    kt_assert!(m.events.contains(&Event::Read(2, 8)));
    kt_assert!(m.events.contains(&Event::Write(2, 2, 0x1000)));
    kt_assert!(m.events.contains(&Event::Write(2, 8, 0x22)));
    kt_assert!(m.events.contains(&Event::Write(1, 0x31, 0xfa)));
    kt_assert!(m.events.contains(&Event::Write(1, 0x32, 1)));
    kt_assert_eq!(
        &m.events[m.events.len() - 2..],
        &[Event::Write(1, 0xcf, 0), Event::Read(1, 0xcf)]
    );
    kt_assert_eq!(m.regs[0xcf], 0);
    drop(m);
    let count = p.model.lock().events.len();
    kt_assert_eq!(
        acquire(&mut owner, &p, f).err().unwrap().operation,
        Some(Error::Terminal)
    );
    kt_assert_eq!(p.model.lock().events.len(), count);
    TestResult::Pass
}

fn smoke_rtl8723ae_physical_ready_boundary_and_lost_data_distinction() -> TestResult {
    for after in [1, 1001, 1002] {
        let p = Port::new(&expected(), 0xff);
        p.model.lock().pa_ready_after = after;
        kt_assert!(p.write8(ACCESS, 0x69).is_ok());
        let result = physical(&p, PA_ADDRESS);
        if after <= 1001 {
            kt_assert_eq!(result, Ok(0xff));
        } else {
            kt_assert_eq!(result, Err(Error::Timeout));
        }
        kt_assert_eq!(p.model.lock().ready_reads, after.min(1001));
        kt_assert_eq!(
            p.model
                .lock()
                .events
                .iter()
                .filter(|e| **e == Event::Read(1, 0x30))
                .count(),
            usize::from(after <= 1001)
        );
    }
    let p = Port::new(&expected(), 0xff);
    p.model.lock().lost_status = true;
    kt_assert_eq!(physical(&p, PA_ADDRESS), Err(Error::Gone));
    kt_assert!(p
        .model
        .lock()
        .events
        .iter()
        .all(|e| *e != Event::Read(1, 0x30)));
    TestResult::Pass
}

fn smoke_rtl8723ae_factory_refusals_and_revoked_cleanup() -> TestResult {
    for register in [0xf0, 0xf4, 0x68] {
        let f = expected();
        let p = Port::new(&f, 0xff);
        p.set32(register, u32::MAX);
        let mut owner = Owner::default();
        kt_assert_eq!(
            acquire(&mut owner, &p, f).err().unwrap().operation,
            Some(Error::Gone)
        );
        kt_assert!(p.writes().is_empty());
    }
    for autoload in [0, 0x30] {
        let f = expected();
        let p = Port::new(&f, 0xff);
        p.model.lock().regs[0x0a] = autoload;
        let mut owner = Owner::default();
        kt_assert_eq!(
            acquire(&mut owner, &p, f).err().unwrap().operation,
            Some(Error::Unprovisioned)
        );
        kt_assert!(p.writes().is_empty());
    }
    let mut erased = (*expected()).clone();
    erased.logical[0x10] = 0xff;
    let v = super::super::tests::version(version::BT_FUNC).unwrap();
    let a = adapter::Adapter::from_hardware(v, 0x20, 0, &erased.logical).unwrap();
    let pg = super::super::phy::PgStore::from_pg(&super::super::tables::PHY_REG_PG).unwrap();
    let source = txpower::Plan::for_channel(
        &txpower::Efuse::from_adapter(&a),
        &pg,
        1,
        false,
        false,
        txpower::DynamicPower::Normal,
    )
    .unwrap();
    kt_assert_eq!(source.indices()[0][0], 63); // clamp cannot validate raw0xff
    let erased = Arc::new(erased);
    let p = Port::new(&erased, 0xff);
    let mut o = Owner::default();
    kt_assert_eq!(
        acquire(&mut o, &p, erased).err().unwrap().operation,
        Some(Error::RawPower)
    );
    kt_assert_eq!(o.gate(), Gate::Closed);
    kt_assert!(matches!(
        o.state(),
        State::Failed(Failure {
            operation: Some(Error::RawPower),
            cleanup: None
        })
    ));
    kt_assert!(o.cleanup_receipt().is_some());
    for (address, value) in [(0x10, 64), (0x1c, 0xff), (0x2b, 0xff)] {
        let mut raw = (*expected()).clone();
        raw.logical[address] = value;
        let raw = Arc::new(raw);
        let p = Port::new(&raw, 0xff);
        let mut owner = Owner::default();
        kt_assert_eq!(
            acquire(&mut owner, &p, raw).err().unwrap().operation,
            Some(Error::RawPower)
        );
        kt_assert!(owner.inputs().is_none());
        kt_assert!(owner.cleanup_receipt().is_some());
        kt_assert_eq!(p.model.lock().address, 496); // refused before physical PA506
    }
    let f = expected();
    let p = Port::new(&f, 0xff);
    let no_words = NoWords(p.clone());
    let mut o = Owner::default();
    // SAFETY: same private inert function, with a deliberately unavailable
    // exact-width adapter operation; cleanup remains currently authorized.
    let failure = unsafe { o.acquire(&no_words, f) }.err().unwrap();
    kt_assert_eq!(failure.operation, Some(Error::Access(AccessError::Access)));
    kt_assert!(o.cleanup_receipt().is_some());
    kt_assert!(!p.model.lock().events.contains(&Event::Read(2, 2)));
    for event in [
        Event::Write(1, 0xcf, 0x69),
        Event::Read(4, 0x30),
        Event::Write(1, 0xcf, 0),
    ] {
        let f = expected();
        let p = Port::new(&f, 0xff);
        p.model.lock().revoke_on = Some(event);
        let mut owner = Owner::default();
        let error = acquire(&mut owner, &p, f).err().unwrap();
        kt_assert!(matches!(owner.state(), State::Quarantined(_)));
        kt_assert_eq!(owner.gate(), Gate::MayBeOn);
        kt_assert!(error.cleanup.is_some());
        kt_assert!(owner.inputs().is_none());
        kt_assert!(owner.cleanup_receipt().is_none());
        let writes = p.writes();
        let count = p.model.lock().events.len();
        kt_assert_eq!(
            acquire(&mut owner, &p, expected()).err().unwrap().operation,
            Some(Error::Terminal)
        );
        kt_assert_eq!(p.model.lock().events.len(), count);
        kt_assert_eq!(p.writes(), writes);
        if event == Event::Write(1, 0xcf, 0x69) {
            kt_assert_eq!(writes.last(), Some(&event));
        }
    }
    let f = expected();
    let p = Port::new(&f, 0xff);
    p.model.lock().data_error = true;
    let mut o = Owner::default();
    let failure = acquire(&mut o, &p, f).err().unwrap();
    kt_assert_eq!(failure.operation, Some(Error::Access(AccessError::Access)));
    kt_assert_eq!(failure.cleanup, None);
    kt_assert_eq!(o.gate(), Gate::Closed);
    kt_assert_eq!(o.state(), State::Failed(failure));
    kt_assert!(o.cleanup_receipt().is_some());
    // The returned Err is only a copy; dropping the waiter/error cannot
    // erase the historical confirmed cleanup held by the actual owner.
    let before = p.model.lock().events.len();
    kt_assert!(acquire(&mut o, &p, expected()).is_err());
    kt_assert_eq!(o.state(), State::Failed(failure));
    kt_assert!(o.cleanup_receipt().is_some());
    kt_assert_eq!(p.model.lock().events.len(), before);
    let f = expected();
    let p = Port::new(&f, 0xff);
    p.model.lock().ignore_close = true;
    let mut o = Owner::default();
    let failure = acquire(&mut o, &p, f).err().unwrap();
    kt_assert_eq!(failure.operation, None);
    kt_assert_eq!(failure.cleanup, Some(Error::Cleanup));
    kt_assert!(matches!(o.state(), State::Quarantined(_)));
    kt_assert!(o.cleanup_receipt().is_none());
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_factory_physical_widths_and_ff_data
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_physical_ready_boundary_and_lost_data_distinction
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_factory_refusals_and_revoked_cleanup
);
