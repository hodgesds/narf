// SPDX-License-Identifier: GPL-2.0-or-later
//! Full native coexistence continuation over the existing inert DMA model.
//! No physical PCI, firmware download, measured RF output or over-air join
//! is claimed. Real revocable capabilities enclose the RAM effects. C2H is
//! produced into the ORIGINAL ring only after the actual H2C box's last byte.
//! Authored only: execution and test-feature compilation are deferred.
use super::*;
use crate::rtlwifi::{
    firmware_transport::Identity,
    prepare::packet::{Publication, TerminalPark},
    rtl8821ae::{
        coex,
        coex_dispatch::Dispatch,
        coex_program::{BtIdentity, Program},
        coex_runtime::Notify,
        phy,
    },
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Read, Write};
use narf_firmware::FirmwareBlob;
use narf_lib::sync::OnceLock;

const VERSION: [u8; 8] = [0x0b, 0, 1, 0, 0xe0, 0x34, 0x12, 7];
const CHANGED: [u8; 8] = [0x0b, 0, 1, 0, 0xe0, 0x35, 0x12, 7];
static POLICY: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

fn require(value: bool, why: &'static str) -> Result<(), &'static str> {
    if value {
        Ok(())
    } else {
        Err(why)
    }
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    // The register model never waits for an IRQ or executor task. No
    // block_on/interrupt-taking bridge is called while this fixture lock lives.
    let _serial = POLICY.lock();
    struct Restore(Option<narf_wireless::reg::RegulatoryDomain>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(old) = self.0.take() {
                narf_wireless::reg::db::set_domain(old);
            } else {
                narf_wireless::reg::db::clear_domain();
            }
        }
    }
    let _restore = Restore(narf_wireless::reg::db::get_domain());
    narf_wireless::reg::db::set_domain(domain(20));
    match f() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn drive<F: Future>(future: F) -> Result<F::Output, &'static str> {
    let mut future = core::pin::pin!(future);
    for _ in 0..1024 {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending => {}
        }
    }
    Err("8821 RAM continuation did not finish within its fixture bound")
}

#[derive(Clone, Copy)]
enum Reply {
    Complete,
    Missing,
    Short,
    Zero,
    WrongSequence,
}
struct Ring {
    descriptor: Block,
    buffers: Vec<Block>,
    producer: usize,
}
struct State {
    ring: Option<Ring>,
    commands: Vec<(u8, [u8; 7])>,
    reply: Reply,
    missing_record: bool,
    changed_ack: bool,
    ordinary_before_version: bool,
    rf: [u32; 256],
}
struct Sources {
    pci: Cap<BusDeviceCap, Write>,
    image: Cap<FirmwareBlob, Read>,
    napc: Cap<FirmwareBlob, Read>,
    joint: Cap<FirmwareBlob, Read>,
    identity: Identity,
    base: Arc<envelope::Calibration>,
    program: OnceLock<Arc<Program>>,
    retired: AtomicBool,
    scalar: IrqSafeSpinLock<()>,
    hold_delay: AtomicBool,
    holding: AtomicBool,
    queries: AtomicUsize,
    bindings: AtomicUsize,
    parks: AtomicUsize,
    irq: AtomicBool,
    state: IrqSafeSpinLock<State>,
}
#[derive(Clone)]
struct CoexPort {
    original: AePort,
    source: Arc<Sources>,
}
impl CoexPort {
    fn current<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if self.source.retired.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        self.source.base.with_current(|| {
            self.source.identity.invoke(|| {
                let original = || {
                    crate::rtw88::pci_park::invoke(&self.source.pci, operation)
                        .map_err(|_| Error::State)?
                };
                if let Some(program) = self.source.program.get() {
                    program.invoke(original)
                } else {
                    original()
                }
            })
        })
    }
    fn scalar<T>(
        &self,
        operation: impl FnOnce() -> Result<T, AccessError>,
    ) -> Result<T, AccessError> {
        let _effect = self.source.scalar.lock();
        self.current(|| operation().map_err(Error::Access))
            .map_err(|_| AccessError::Gate)
    }
    /// Device-side production into the same allocated descriptor/buffer
    /// extents. No host authority or second ring is fabricated by this model.
    fn inject(&self, bytes: &[u8], c2h: bool) -> Result<(), Error> {
        let mut state = self.source.state.lock();
        let ring = state.ring.as_mut().ok_or(Error::State)?;
        let slot = ring.producer;
        let offset = slot * 32;
        if ring.descriptor.read32(offset)? & OWN == 0 {
            return Err(Error::Descriptor);
        }
        let start = if c2h { 0 } else { 8 };
        if !c2h {
            // Real drvinfo/PHYST and OFDM6 descriptor fields. PWDB byte4
            // encodes -40dBm, which the native parser retains as60 percent.
            ring.buffers[slot].write_bytes(0, &[0, 0, 0, 0, 140, 0, 0, 0])?;
        }
        ring.buffers[slot].write_bytes(start, bytes)?;
        for word in 1..6 {
            ring.descriptor.write32(offset + word * 4, 0)?;
        }
        ring.descriptor
            .write32(offset + 8, if c2h { 1 << 28 } else { 0 })?;
        if !c2h {
            ring.descriptor.write32(offset + 12, 4)?;
        }
        let end = if slot + 1 == ring.buffers.len() {
            1 << 30
        } else {
            0
        };
        ring.descriptor.write32(
            offset,
            bytes.len() as u32 | end | if c2h { 0 } else { (1 << 16) | (1 << 26) },
        )?;
        ring.producer = (slot + 1) % ring.buffers.len();
        Ok(())
    }
    fn completed_box(&self, reg: u16) -> Result<(), AccessError> {
        if !(0x1d0..0x1e0).contains(&reg) || reg & 3 != 3 {
            return Ok(());
        }
        let base = reg - 3;
        let ext = 0x1f0 + (base - 0x1d0);
        let id = self.original.reg8(base);
        let mut payload = [0; 7];
        for (i, byte) in payload[..3].iter_mut().enumerate() {
            *byte = self.original.reg8(base + 1 + i as u16);
        }
        for (i, byte) in payload[3..].iter_mut().enumerate() {
            *byte = self.original.reg8(ext + i as u16);
        }
        self.source.state.lock().commands.push((id, payload));
        if id != 0x67 {
            return Ok(());
        }
        let response = match payload[1] {
            0 => {
                self.source.queries.fetch_add(1, Ordering::AcqRel);
                let state = self.source.state.lock();
                let reply = state.reply;
                let data = state.ordinary_before_version;
                drop(state);
                if data {
                    self.inject(&ordinary(), false)
                        .map_err(|_| AccessError::Gate)?;
                }
                match reply {
                    Reply::Complete => Some(VERSION.to_vec()),
                    Reply::Missing => None,
                    Reply::Short => Some(VERSION[..6].to_vec()),
                    Reply::Zero => Some(vec![0x0b, 0, 1, 0, 0xe0, 0, 0, 7]),
                    Reply::WrongSequence => Some(vec![0x0b, 0, 1, 0, 0xd0, 0x34, 0x12, 7]),
                }
            }
            12 | 13 => Some(if self.source.state.lock().changed_ack {
                CHANGED.to_vec()
            } else {
                vec![0x0b, 0, 1, 0, 0, 0]
            }),
            _ => None,
        };
        if let Some(bytes) = response {
            self.inject(&bytes, true).map_err(|_| AccessError::Gate)?;
        }
        Ok(())
    }
    fn command(&self, id: u8, bytes: &[u8]) -> bool {
        self.source
            .state
            .lock()
            .commands
            .iter()
            .any(|(got, p)| *got == id && p[..bytes.len()] == *bytes)
    }
    fn parked(&self) -> bool {
        self.source.retired.load(Ordering::Acquire)
            && !self.original.0.lock().master
            && !self.source.irq.load(Ordering::Acquire)
            && self.original.reg32(0xb0) == 0
            && self.original.reg32(0xb8) == 0
            && self.original.reg8(0x522) == 0xff
            && self.original.reg8(0x301) == 0xff
            && self.original.reg8(0x100) & 0xcf == 0
    }
}
#[async_trait::async_trait]
impl Io for CoexPort {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        self.scalar(|| self.original.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, AccessError> {
        self.scalar(|| self.original.read16(r))
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        self.scalar(|| self.original.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        self.scalar(|| {
            self.original.write8(r, v)?;
            self.completed_box(r)
        })
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        self.scalar(|| self.original.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        self.scalar(|| {
            self.original.write32(r, v)?;
            if r == phy::RA_LSSIWRITE {
                self.source.state.lock().rf[((v >> 20) & 0xff) as usize] = v & 0xfffff;
            }
            if r == phy::RHSSIREAD {
                let readback = self.source.state.lock().rf[(v & 0xff) as usize];
                self.original.set32(phy::RA_SIREAD, readback);
                self.original.set32(phy::RA_PIREAD, readback);
            }
            Ok(())
        })
    }
    fn write_bytes(&self, r: u16, bytes: &[u8]) -> Result<(), AccessError> {
        for (i, b) in bytes.iter().enumerate() {
            self.write8(r + i as u16, *b)?;
        }
        Ok(())
    }
    async fn delay_us(&self, _: u64) {
        core::future::poll_fn(|cx| {
            if self.source.hold_delay.load(Ordering::Acquire) {
                self.source.holding.store(true, Ordering::Release);
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await
    }
}
/// Restrictive cleanup has ONLY the CURRENT ORIGINAL PCI authority. It
/// cannot bypass a revoked PCI cap, reopen firmware, or reclaim any extent.
struct PciOnly(CoexPort);
impl PciOnly {
    fn current<T>(&self, op: impl FnOnce() -> Result<T, AccessError>) -> Result<T, AccessError> {
        crate::rtw88::pci_park::invoke(&self.0.source.pci, op).map_err(|_| AccessError::Gate)?
    }
}
#[async_trait::async_trait]
impl Io for PciOnly {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        self.current(|| self.0.original.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, AccessError> {
        self.current(|| self.0.original.read16(r))
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        self.current(|| self.0.original.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        self.current(|| self.0.original.write8(r, v))
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        self.current(|| self.0.original.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        self.current(|| self.0.original.write32(r, v))
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Access)
    }
}
impl Port for CoexPort {
    type Buffer = Block;
    fn authority<T>(
        &self,
        _: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        // Outer descriptor/poll scopes are deliberately reentrant; only
        // individual scalar effects serialize against terminal park.
        self.current(operation)
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        self.current(|| Ok(self.original.block(bytes)))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.scalar(|| {
            self.original.0.lock().master = enabled;
            Ok(())
        })
        .map_err(Error::Access)
    }
    fn kick(&self, queue_bit: u16) -> Result<(), Error> {
        self.scalar(|| {
            self.original.0.lock().kicks.push(queue_bit);
            Ok(())
        })
        .map_err(Error::Access)
    }
    fn bind_rtl8821ae_coex(
        &self,
        base: Arc<envelope::Calibration>,
        factory: &Factory,
        p: envelope::Permission,
        bt: BtIdentity,
    ) -> Result<Option<Arc<Program>>, Error> {
        self.source.bindings.fetch_add(1, Ordering::AcqRel);
        if self.source.state.lock().missing_record {
            return Ok(None);
        }
        if !Arc::ptr_eq(&base, &self.source.base) {
            return Err(Error::State);
        }
        let bytes = Program::fixture_record(&base, self.source.identity, factory, p, bt)?;
        let program = Arc::new(Program::parse_fixture(
            base,
            self.source.identity,
            factory,
            p,
            bt,
            &bytes,
            Some([7; 32]),
            self.source.joint,
        )?);
        self.source
            .program
            .set(program.clone())
            .map_err(|_| Error::State)?;
        Ok(Some(program))
    }
    fn terminal_park(&self) -> Option<TerminalPark> {
        let this = self.clone();
        Some(TerminalPark::new(Arc::new(move || {
            this.source.retired.store(true, Ordering::Release);
            let _scalar = this.source.scalar.lock();
            this.source.parks.fetch_add(1, Ordering::AcqRel);
            let pci = PciOnly(this.clone());
            let gates = crate::rtlwifi::rtl8821ae::park::close(&pci, || {
                pci.current(|| {
                    this.original.0.lock().master = false;
                    Ok(())
                })
            });
            let irq = pci.current(|| {
                this.source.irq.store(false, Ordering::Release);
                Ok(())
            });
            gates.and(irq).map_err(Error::Access)
        })))
    }
    fn publication(&self) -> Result<Publication, Error> {
        let this = self.clone();
        Ok(Publication::guarded(Arc::new(move |effect| {
            this.current(effect)
        })))
    }
}

struct Fixture {
    owner: Prepared<CoexPort, Block>,
    port: CoexPort,
    base: Arc<envelope::Calibration>,
    factory: Factory,
}
fn fixture(raw_c3: u8, reply: Reply, missing_record: bool) -> Result<Fixture, &'static str> {
    fixture_with_widths(raw_c3, reply, missing_record, false)
}
fn fixture_with_widths(
    raw_c3: u8,
    reply: Reply,
    missing_record: bool,
    wide: bool,
) -> Result<Fixture, &'static str> {
    let original = AePort::new();
    let mut factory = Factory {
        mac: MAC,
        logical: ae::powered_logical(0xf2, 2),
    };
    factory.logical[0xc3] = raw_c3;
    let napc = Cap::bootstrap();
    let record = if wide {
        ae::napc_v2(
            &factory,
            &[(1, 0, 20, 0), (2, 0, 20, 0), (1, 0, 40, 1)],
            30,
            false,
        )
    } else {
        ae::napc(&factory, &[1], 30)
    };
    let base = Arc::new(
        envelope::Calibration::from_verified(&record, Some([1; 32]), &factory)
            .map_err(|_| "8821 NAPC fixture")?
            .with_fixture_source(napc),
    );
    let image = Cap::bootstrap();
    // Inert selected-image header metadata only; no downloaded binary.
    let mut header = [0; 32];
    header[..2].copy_from_slice(&[1, 0x21]);
    header[4..7].copy_from_slice(&[0x18, 0, 1]);
    let mut rf = [0; 256];
    rf[0x1e] = 0x54321;
    let port = CoexPort {
        original: original.clone(),
        source: Arc::new(Sources {
            pci: Cap::bootstrap(),
            image,
            napc,
            joint: Cap::bootstrap(),
            identity: Identity::fixture_with_source(&header, image),
            base: base.clone(),
            program: OnceLock::new(),
            retired: AtomicBool::new(false),
            scalar: IrqSafeSpinLock::new(()),
            hold_delay: AtomicBool::new(false),
            holding: AtomicBool::new(false),
            queries: AtomicUsize::new(0),
            bindings: AtomicUsize::new(0),
            parks: AtomicUsize::new(0),
            irq: AtomicBool::new(true),
            state: IrqSafeSpinLock::new(State {
                ring: None,
                commands: Vec::new(),
                reply,
                missing_record,
                changed_ack: false,
                ordinary_before_version: false,
                rf,
            }),
        }),
    };
    let mut owner = Prepared::allocate_for(Chip::Rtl8821ae, port.clone(), 4, |bytes| {
        Ok(original.block(bytes))
    })
    .map_err(|_| "8821 actual Prepared allocation")?;
    for (reg, ring) in TX_BASES.iter().zip(&owner.tx) {
        original.set32(*reg, ring.address() as u32);
    }
    let ring = owner
        .receive
        .as_ref()
        .ok_or("8821 original RX ring")?
        .clone();
    original.set32(crate::rtlwifi::prepare::RX_BASE, ring.address() as u32);
    original.set32(mac::REG_RCR, 0xf400_2a0e);
    original.set32(0x68, 1 << 18);
    original.set32(0x430, 0x11223344);
    original.set32(0x434, 0x55667788);
    owner.rtl8821ae_power = Some(
        base.permission(&domain(20), 1)
            .map_err(|_| "8821 permission")?,
    );
    owner.rtl8821ae_coex = Some(Box::new(coex::Owner::bind_factory(&factory)));
    owner.packet.local = Some(MAC);
    owner.published = true;
    owner.phase = Phase::MacConfigured;
    port.source.state.lock().ring = Some(Ring {
        descriptor: ring,
        buffers: owner.buffers.clone(),
        producer: 0,
    });
    owner.start_packets().map_err(|_| "8821 native start")?;
    Ok(Fixture {
        owner,
        port,
        base,
        factory,
    })
}
fn ordinary() -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[0] = 8;
    bytes[4..10].copy_from_slice(&MAC);
    bytes[10..16].copy_from_slice(&PEER);
    bytes[24..32].copy_from_slice(b"original");
    bytes
}
fn retained(f: &Fixture, ring: u64, buffers: &[u64]) -> bool {
    f.owner
        .receive
        .as_ref()
        .is_some_and(|r| r.address() == ring)
        && f.owner
            .buffers
            .iter()
            .map(Memory::address)
            .eq(buffers.iter().copied())
        && f.owner.published
        && f.owner.rtl8821ae_coex.as_ref().is_some_and(|c| c.probed)
}
fn prepared(f: &mut Fixture) -> Result<Arc<Program>, &'static str> {
    drive(f.owner.ae_prepare_coex(f.base.clone()))?
        .map_err(|_| "8821 native full coex prepare")?
        .ok_or("8821 genuine query and separate record did not qualify")
}

struct NativeEnv;
impl crate::rtlwifi::prepare::station::Environment for NativeEnv {
    fn allow_channel(
        &self,
        _: &Factory,
        channel: u8,
    ) -> Result<(), crate::rtlwifi::prepare::station::Error> {
        if matches!(channel, 1 | 2) {
            Ok(())
        } else {
            Err(crate::rtlwifi::prepare::station::Error::Profile)
        }
    }
    fn now_ms(&self) -> u64 {
        20_000
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        None
    }
    fn domain(
        &self,
    ) -> Result<narf_wireless::reg::RegulatoryDomain, crate::rtlwifi::prepare::station::Error> {
        narf_wireless::reg::db::snapshot()
            .map(|domain| domain.as_ref().clone())
            .ok_or(crate::rtlwifi::prepare::station::Error::Profile)
    }
    async fn pause(&self) {
        core::future::poll_fn(|cx| {
            cx.waker().wake_by_ref();
            Poll::<()>::Pending
        })
        .await
    }
}

fn passive_scan(channels: Vec<u32>) -> narf_wireless::ScanRequest {
    narf_wireless::ScanRequest {
        ssids: Vec::new(),
        frequencies_mhz: Vec::new(),
        channels,
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}

fn smoke_8821_full_native_ready_cache_reports_only_bound_ht20() -> TestResult {
    check(|| {
        use narf_wireless::WirelessNetIface;
        let mut f = fixture_with_widths(1, Reply::Complete, false, true)?;
        let mut policy = domain(20);
        policy.rules[0].max_bandwidth_mhz = 40;
        narf_wireless::reg::db::set_domain(policy.clone());
        require(
            crate::rtlwifi::rtl8821ae::vht::host_capabilities(&f.base, &policy)
                & crate::rtlwifi::rtl8821ae::vht::HOST_HT40_2G
                != 0,
            "8821 ready regression lacks a prior admitted HT40 point",
        )?;
        // Re-enter only the RAM fixture's pre-start phase. No physical
        // firmware or radio bring-up is bypassed outside this test model.
        f.owner.phase = Phase::MacConfigured;
        f.owner
            .fixture_8821_stage_base(f.base.clone())
            .map_err(|_| "8821 shared original staged NAPC")?;
        let Fixture {
            owner,
            port,
            factory,
            ..
        } = f;
        let device = crate::rtlwifi::interface::Device::new(
            "narf-8821-native-ready-fixture",
            Arc::new(narf_lib::mutex::Mutex::new(Some(owner))),
            Arc::new(factory),
            NativeEnv,
            1,
        );
        let phy =
            drive(crate::rtlwifi::interface::publication_test::ready_8821_capabilities(&device))??;
        require(
            u16::from_le_bytes([phy.ht[0], phy.ht[1]]) & 2 == 0 && phy.vht.is_none(),
            "8821 Native ready cached pre-N21C HT40/VHT capability",
        )?;
        let info = device.get_wireless_info();
        require(
            info.bands
                .iter()
                .flat_map(|band| &band.channels)
                .copied()
                .collect::<Vec<_>>()
                == [1],
            "8821 public channel list escaped its exact N21C operating point",
        )?;
        let before = port.original.0.lock().writes.len();
        let request = passive_scan(vec![2]);
        require(
            matches!(
                drive(device.scan(request))?,
                Err(narf_wireless::WirelessError::NotSupported)
            ) && port.original.0.lock().writes.len() == before
                && !port.source.retired.load(Ordering::Acquire),
            "8821 other-channel explicit scan affected a live fixed-point owner",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_ready_cache_reports_only_bound_ht20
);

fn smoke_8821_full_native_cancel_scan_between_notifications_parks() -> TestResult {
    check(|| {
        let mut f = fixture(1, Reply::Complete, false)?;
        f.owner.phase = Phase::MacConfigured;
        f.owner
            .fixture_8821_stage_base(f.base.clone())
            .map_err(|_| "8821 scan shared base")?;
        let Fixture {
            owner,
            port,
            factory,
            ..
        } = f;
        let device = crate::rtlwifi::interface::Device::new(
            "narf-8821-native-scan-cancel-fixture",
            Arc::new(narf_lib::mutex::Mutex::new(Some(owner))),
            Arc::new(factory),
            NativeEnv,
            1,
        );
        drive(crate::rtlwifi::interface::publication_test::ready_8821_capabilities(&device))??;
        let publication = port.publication().map_err(|_| "8821 scan publication")?;
        drive(
            crate::rtlwifi::interface::publication_test::cancel_8821_scan_waiting_for_control(
                &device,
                passive_scan(vec![1]),
            ),
        )??;
        let before = port.original.0.lock().writes.len();
        require(
            port.parked()
                && port.write8(0x790, 1).is_err()
                && publication.invoke(|| Ok(())).is_err()
                && port.original.0.lock().writes.len() == before,
            "8821 scan drop between notifications retained original scalar/publication admission",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_cancel_scan_between_notifications_parks
);

fn smoke_8821_full_native_reusable_leave_notifies_lps_and_media_without_halt() -> TestResult {
    check(|| {
        for raw in [0, 1] {
            let mut f = fixture(raw, Reply::Complete, false)?;
            let program = prepared(&mut f)?;
            drive(f.owner.ae_coex_notify(Notify::Media(true)))?
                .map_err(|_| "8821 RAM fixture media notification")?;
            // Actual link and idle watchdog qualification are not simulated:
            // seed only this existing fixture's LPS permission, as in the
            // original native LPS case, then run the real enter/leave path.
            f.owner
                .rtl8821ae_coex
                .as_mut()
                .unwrap()
                .full
                .as_mut()
                .unwrap()
                .lps_gate()
                .enter_allowed = true;
            drive(f.owner.enter_leisure())?.map_err(|_| "8821 actual reusable-leave LPS enter")?;
            require(
                f.owner.packet.leisure,
                "8821 reusable-leave fixture remained awake",
            )?;
            drive(f.owner.leave_station_peer())?.map_err(|_| "8821 actual reusable peer leave")?;
            let coex = f
                .owner
                .rtl8821ae_coex
                .as_mut()
                .ok_or("8821 retained reusable coex")?;
            let gate = *coex
                .full
                .as_mut()
                .ok_or("8821 retained reusable algorithm")?
                .lps_gate();
            require(
                !coex.btc.wifi.station_linked
                    && !coex.btc.stop_coex_dm
                    && !gate.linked
                    && !gate.report_linked
                    && gate.active
                    && !f.owner.packet.leisure
                    && f.owner.phase == Phase::Running
                    && coex
                        .program
                        .as_ref()
                        .is_some_and(|p| Arc::ptr_eq(p, &program))
                    && !f.port.source.retired.load(Ordering::Acquire),
                "8821 reusable disassociation kept old link/LPS state or halted its algorithm",
            )?;
            drive(f.owner.ae_coex_notify(Notify::Scan(true)))?
                .map_err(|_| "8821 retained algorithm could not scan after reusable leave")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_reusable_leave_notifies_lps_and_media_without_halt
);

fn smoke_8821_full_native_iqk_cancel_closes_original_owner() -> TestResult {
    check(|| {
        let mut f = fixture(0, Reply::Complete, false)?;
        let program = prepared(&mut f)?;
        let ring = f
            .owner
            .receive
            .as_ref()
            .ok_or("8821 IQK original ring")?
            .address();
        let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
        f.owner.fixture_8821_linked_iqk_due(
            program,
            crate::rtlwifi::prepare::station::Candidate {
                bss: narf_wireless::association::Bss {
                    bssid: PEER,
                    ssid: b"iqk-ram-fixture".to_vec(),
                    channel: 1,
                    band: None,
                    signal_dbm: None,
                    capability: 1,
                    beacon_interval: 100,
                    information_elements: Vec::new(),
                },
                rsne: None,
                rsnxe: None,
            },
        );
        let publication = f.port.publication().map_err(|_| "8821 IQK publication")?;
        f.port.source.hold_delay.store(true, Ordering::Release);
        {
            let mut future = core::pin::pin!(f.owner.refresh_station_rate_mask(&NativeEnv));
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
                    && f.port.source.holding.load(Ordering::Acquire),
                "8821 actual IQK did not reach its original RF-read delay",
            )?;
        }
        let before = f.port.original.0.lock().writes.len();
        require(
            f.owner.station_phase() == crate::rtlwifi::prepare::station::Phase::Failed
                && f.port.parked()
                && retained(&f, ring, &buffers)
                && f.port.write8(0x790, 1).is_err()
                && publication.invoke(|| Ok(())).is_err()
                && f.port.original.0.lock().writes.len() == before,
            "8821 cancelled IQK retained live RF admission or replaced original resources",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_iqk_cancel_closes_original_owner
);

fn smoke_8821_full_native_original_mailbox_rx_and_c3_dispatch() -> TestResult {
    check(|| {
        for raw in [0, 1] {
            let mut f = fixture(raw, Reply::Complete, false)?;
            let ring = f.owner.receive.as_ref().unwrap().address();
            let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
            let program = prepared(&mut f)?;
            let coex = f
                .owner
                .rtl8821ae_coex
                .as_ref()
                .ok_or("8821 retained coex")?;
            require(
                matches!(
                    (raw, coex.full.as_ref()),
                    (0, Some(Dispatch::Two(_))) | (1, Some(Dispatch::One(_)))
                ),
                "8821 actual C3 algorithm dispatch",
            )?;
            require(
                coex.btc.initialized
                    && coex.btc.statistics.cnt_init_hw_config == 1
                    && coex.btc.statistics.cnt_init_coex_dm == 1,
                "8821 source init not composed",
            )?;
            require(
                f.port.source.queries.load(Ordering::Acquire) == 1
                    && f.port.source.bindings.load(Ordering::Acquire) == 1
                    && f.owner.packet.receive != 0,
                "8821 qualification did not follow actual query/ring receive",
            )?;
            require(
                f.port.command(0x67, &[0xe0, 0, 0, 0]) && f.port.command(0x65, &[1, 1]),
                "8821 source H2C mailbox bytes",
            )?;
            require(
                f.port.original.0.lock().writes.windows(8).any(|window| {
                    window
                        == [
                            (1, 0x1f0, 0),
                            (1, 0x1f1, 0),
                            (1, 0x1f2, 0),
                            (1, 0x1f3, 0),
                            (1, 0x1d0, 0x67),
                            (1, 0x1d1, 0xe0),
                            (1, 0x1d2, 0),
                            (1, 0x1d3, 0),
                        ]
                }),
                "8821 query response did not follow extension-first original byte mailbox",
            )?;
            require(
                f.port.original.reg8(0x76e) == if raw == 1 { 0x0c } else { 4 },
                "8821 source antenna-specific counter register",
            )?;
            if raw == 0 {
                require(
                    matches!(coex.full.as_ref(), Some(Dispatch::Two(r)) if r.algo.dm.bt_rf0x1e_backup == 0x54321),
                    "8821 native HSSI RF backup",
                )?;
                require(
                    f.port.command(0x60, &[0, 0, 0, 0x48, 0]),
                    "8821 two-antenna source initial TDMA bytes",
                )?;
            } else {
                require(
                    matches!(coex.full.as_ref(), Some(Dispatch::One(r)) if r.algo.dm.backup_arfr_cnt1 == 0x11223344 && r.algo.dm.backup_arfr_cnt2 == 0x55667788),
                    "8821 original source backups",
                )?;
                // One-antenna init does not issue TDMA. Its actual idle
                // BT-info handler selects the source disconnected row8.
                drive(
                    f.owner
                        .ae_coex_notify(Notify::BtInfo(&[1, 0x49, 0x40, 25, 0])),
                )?
                .map_err(|_| "8821 one-antenna actual BT-info dispatch")?;
                require(
                    f.port.command(0x60, &[8, 0, 0, 0, 0]),
                    "8821 one-antenna disconnected TDMA row8",
                )?;
            }
            require(
                retained(&f, ring, &buffers) && f.owner.phase == Phase::Running && !f.port.parked(),
                "8821 successful continuation replaced/retired original owner",
            )?;
            let again = prepared(&mut f)?;
            require(
                Arc::ptr_eq(&program, &again) && f.port.source.queries.load(Ordering::Acquire) == 1,
                "8821 second probe replaced program/history",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_original_mailbox_rx_and_c3_dispatch
);

fn smoke_8821_full_native_missing_short_version_and_normal_napc_never_promote() -> TestResult {
    check(|| {
        for reply in [
            Reply::Missing,
            Reply::Short,
            Reply::Zero,
            Reply::WrongSequence,
        ] {
            let mut f = fixture(0, reply, false)?;
            let result = drive(f.owner.ae_prepare_coex(f.base.clone()))?;
            require(
                if matches!(reply, Reply::Short) {
                    result.is_err()
                } else {
                    matches!(result, Ok(None))
                },
                "8821 absent/short/non-version observation qualified",
            )?;
            require(
                f.port.source.bindings.load(Ordering::Acquire) == 0
                    && f.port.source.program.get().is_none()
                    && f.owner.rtl8821ae_coex.as_ref().unwrap().full.is_none(),
                "8821 cached/zero-filled version promoted NAPC",
            )?;
            require(
                !f.port.command(0x65, &[1, 1])
                    && f.port.original.wrote(4, 0x6c0, 0x55555555).is_none(),
                "8821 unqualified probe emitted full RF program",
            )?;
            if matches!(reply, Reply::Short) {
                require(
                    f.port.parked() && f.owner.phase == Phase::Failed,
                    "8821 malformed actual response did not terminally park",
                )?;
            }
        }
        let mut f = fixture(1, Reply::Complete, true)?;
        require(
            matches!(drive(f.owner.ae_prepare_coex(f.base.clone()))?, Ok(None))
                && f.port.source.bindings.load(Ordering::Acquire) == 1
                && f.owner.phase == Phase::Running
                && f.owner.rtl8821ae_coex.as_ref().unwrap().full.is_none(),
            "8821 normal NAPC substituted for missing N21C",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_missing_short_version_and_normal_napc_never_promote
);

fn smoke_8821_full_native_query_preserves_original_deferred_data() -> TestResult {
    check(|| {
        let mut f = fixture(0, Reply::Complete, false)?;
        f.port.source.state.lock().ordinary_before_version = true;
        prepared(&mut f)?;
        let expected = ordinary();
        let step = f
            .owner
            .poll_receive_step()
            .map_err(|_| "8821 deferred ordinary RX")?;
        require(
            step.consumed
                && step.packet.as_ref().is_some_and(|p| {
                    p.bytes == expected[..32] && p.channel == 1 && !p.ht && p.pwdb == Some(60)
                }),
            "8821 MP query changed ordinary bytes/rate/PHY admission",
        )?;
        let step = f
            .owner
            .poll_receive_step()
            .map_err(|_| "8821 drained original RX")?;
        require(
            !step.consumed && step.packet.is_none(),
            "8821 deferred RX was replayed twice",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_query_preserves_original_deferred_data
);

fn smoke_8821_full_native_original_rx_rejects_runt_mac_before_delivery() -> TestResult {
    check(|| {
        let mut f = fixture(0, Reply::Complete, false)?;
        prepared(&mut f)?;
        let ring = f
            .owner
            .receive
            .as_ref()
            .ok_or("8821 original RX ring")?
            .address();
        let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
        let bytes = ordinary();
        for length in 24..=28 {
            let slot = f.owner.packet.receive;
            f.port
                .inject(&bytes[..length], false)
                .map_err(|_| "8821 original runt RX injection")?;
            let step = f
                .owner
                .poll_receive_step()
                .map_err(|_| "8821 original runt RX read/rearm")?;
            require(
                step.consumed
                    && if length < 28 {
                        step.packet.is_none()
                    } else {
                        step.packet.as_ref().is_some_and(|packet| {
                            packet.bytes == bytes[..24] && packet.pwdb == Some(60)
                        })
                    },
                "8821 runt MAC reached delivery or complete minimum MAC was dropped",
            )?;
            require(
                f.owner.phase == Phase::Running
                    && f.owner.packet.receive == (slot + 1) % f.owner.depth
                    && f.owner
                        .receive
                        .as_ref()
                        .unwrap()
                        .read32(slot * 32)
                        .map_err(|_| "8821 original runt RX rearm")?
                        & OWN
                        != 0
                    && retained(&f, ring, &buffers)
                    && !f.port.source.retired.load(Ordering::Acquire),
                "8821 runt RX changed original owner or failed to rearm its descriptor",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_original_rx_rejects_runt_mac_before_delivery
);

fn smoke_8821_full_native_n21c_exact_framing_and_nested_source_refusal() -> TestResult {
    check(|| {
        let f = fixture(0, Reply::Complete, false)?;
        let p = f.owner.rtl8821ae_power.ok_or("8821 permission")?;
        let bt = BtIdentity::observed(0x1234, 7).map_err(|_| "8821 fixture identity")?;
        let bytes = Program::fixture_record(&f.base, f.port.source.identity, &f.factory, p, bt)
            .map_err(|_| "8821 current source recipe")?;
        let parse = |bytes: &[u8], signer| {
            Program::parse_fixture(
                f.base.clone(),
                f.port.source.identity,
                &f.factory,
                p,
                bt,
                bytes,
                signer,
                f.port.source.joint,
            )
        };
        require(
            parse(&bytes, Some([7; 32])).is_ok(),
            "8821 exact N21C framing refused",
        )?;
        for offset in [
            0, 4, 8, 12, 16, 48, 80, 112, 144, 176, 208, 214, 215, 216, 217, 218, 219, 220, 222,
            223, 230, 255,
        ] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            require(
                parse(&changed, Some([7; 32])).is_err(),
                "8821 N21C changed binding/reserved byte admitted",
            )?;
        }
        let mut unknown = bytes;
        unknown[228..230].copy_from_slice(&i16::MAX.to_le_bytes());
        require(
            parse(&unknown, Some([7; 32])).is_err()
                && parse(&bytes[..255], Some([7; 32])).is_err()
                && parse(&bytes, None).is_err()
                && parse(&ae::napc(&f.factory, &[1], 30), Some([7; 32])).is_err(),
            "8821 unsigned/truncated/unknown/NAPC source admitted as joint program",
        )?;
        // A malformed report supplies no contradictory full identity. A
        // later COMPLETE version OR build contradiction permanently poisons
        // this program, including a subsequent report of the original value.
        let mut changed_build = VERSION;
        changed_build[7] += 1;
        for changed in [CHANGED, changed_build] {
            let program = parse(&bytes, Some([7; 32])).map_err(|_| "8821 fresh poison parser")?;
            let effects = AtomicUsize::new(0);
            require(
                program.check_bt_report(&VERSION[..6]).is_err()
                    && program.check_bt_report(&VERSION).is_ok()
                    && program.check_bt_report(&changed).is_err()
                    && program.check_bt_report(&VERSION).is_err()
                    && program
                        .invoke(|| {
                            effects.fetch_add(1, Ordering::AcqRel);
                            Ok(())
                        })
                        .is_err()
                    && effects.load(Ordering::Acquire) == 0,
                "8821 full version/build contradiction was not terminal",
            )?;
        }
        for source in 0..4 {
            let mut live = fixture(0, Reply::Complete, false)?;
            let program = prepared(&mut live)?;
            let publication = live
                .port
                .publication()
                .map_err(|_| "8821 guarded publication")?;
            let effects = AtomicUsize::new(0);
            match source {
                0 => live.port.source.napc.revoke(),
                1 => live.port.source.image.revoke(),
                2 => live.port.source.joint.revoke(),
                _ => live.port.source.pci.revoke(),
            }
            let before = live.port.original.0.lock().writes.len();
            // Program owns the three RF sources; the actual Port operation
            // additionally owns PCI. This counter is inert CPU work only.
            let source_result = program.invoke(|| {
                effects.fetch_add(1, Ordering::AcqRel);
                Ok(())
            });
            require(
                source_result.is_ok() == (source == 3),
                "8821 dead source reached joint grant operation",
            )?;
            require(
                publication
                    .invoke(|| {
                        effects.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                    .is_err()
                    && live.port.write8(0x790, 0xaa).is_err()
                    && live.port.original.0.lock().writes.len() == before
                    && effects.load(Ordering::Acquire) == usize::from(source == 3),
                "8821 publication/scalar escaped current original source/PCI",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_n21c_exact_framing_and_nested_source_refusal
);

fn smoke_8821_full_native_changed_version_during_real_mp_wait_poison_parks() -> TestResult {
    check(|| {
        let mut f = fixture(0, Reply::Complete, false)?;
        // Capture BEFORE program installation, matching retained station
        // publication tokens: the shared latch must still observe poisoning.
        let publication = f
            .port
            .publication()
            .map_err(|_| "8821 pre-installation publication")?;
        let program = prepared(&mut f)?;
        let ring = f.owner.receive.as_ref().unwrap().address();
        let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
        // The actual source BT-info mask bit requests RF register3c repair,
        // through H2C WRITE_REG_VALUE then WRITE_REG_ADDR. Replace the first
        // device acknowledgement with a genuine complete changed version.
        f.port.source.state.lock().changed_ack = true;
        let before = f.port.source.state.lock().commands.len();
        require(
            drive(
                f.owner
                    .ae_coex_notify(Notify::BtInfo(&[1, 0x49, 0x40, 25, 0])),
            )?
            .is_err(),
            "8821 changed GET_VERSION inside MP wait accepted",
        )?;
        let state = f.port.source.state.lock();
        let commands = &state.commands[before..];
        require(
            commands.len() == 1 && commands[0].0 == 0x67 && commands[0].1[1] == 13,
            "8821 effects continued after contradictory real BT version",
        )?;
        drop(state);
        require(
            f.port.parked() && f.owner.phase == Phase::Failed && retained(&f, ring, &buffers),
            "8821 poison lost original state or failed restrictive park",
        )?;
        require(
            matches!(f.owner.rtl8821ae_coex.as_ref().unwrap().full.as_ref(), Some(Dispatch::Two(r)) if r.failed() && r.algo.dm.bt_rf0x1e_backup == 0x54321 && r.algo.sta.bt_tx_rx_mask),
            "8821 failed source history/backups rolled back",
        )?;
        let effects = AtomicUsize::new(0);
        require(
            program
                .invoke(|| {
                    effects.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                })
                .is_err()
                && publication
                    .invoke(|| {
                        effects.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                    .is_err()
                && effects.load(Ordering::Acquire) == 0,
            "8821 poisoned program/retained publication reached effect",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_changed_version_during_real_mp_wait_poison_parks
);

fn smoke_8821_full_native_cancelled_or_revoked_init_retains_history_and_park() -> TestResult {
    check(|| {
        // Two-antenna init reaches real RF1e HSSI selection then delay20us.
        // It is already inside Runtime.failed, the N21C poll scope and the
        // owned terminal guard; dropping or revoking cannot undo that effect.
        for lost in 0..5 {
            let mut f = fixture(0, Reply::Complete, false)?;
            let ring = f.owner.receive.as_ref().unwrap().address();
            let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
            f.port.source.hold_delay.store(true, Ordering::Release);
            let mut future = Box::pin(f.owner.ae_prepare_coex(f.base.clone()));
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
                    && f.port.source.holding.load(Ordering::Acquire)
                    && f.port.source.program.get().is_some(),
                "8821 fixture did not hold real qualified RF init wait",
            )?;
            let before = f.port.original.0.lock().writes.len();
            match lost {
                0 => {} // Actual future cancellation at that boundary.
                1 => f.port.source.image.revoke(),
                2 => f.port.source.napc.revoke(),
                3 => f.port.source.joint.revoke(),
                _ => f.port.source.pci.revoke(),
            }
            if lost != 0 {
                f.port.source.hold_delay.store(false, Ordering::Release);
                require(
                    drive(future.as_mut())?.is_err(),
                    "8821 lost source resumed native RF init",
                )?;
            }
            drop(future);
            require(
                f.owner.phase == Phase::Failed
                    && retained(&f, ring, &buffers)
                    && matches!(f.owner.rtl8821ae_coex.as_ref().unwrap().full.as_ref(), Some(Dispatch::Two(r)) if r.failed()),
                "8821 partial/cancelled init replaced owner or cleared failed source history",
            )?;
            if lost != 4 {
                require(
                    f.port.parked(),
                    "8821 original PCI did not close after cancellation/source loss",
                )?;
            } else {
                require(
                    f.port.original.0.lock().writes.len() == before
                        && f.port.original.0.lock().master
                        && !f.port.parked(),
                    "8821 revoked PCI fabricated terminal stop receipt",
                )?;
            }
            let after = f.port.original.0.lock().writes.len();
            require(
                f.port.write8(0x790, 0xaa).is_err()
                    && f.port.original.0.lock().writes.len() == after,
                "8821 cancelled/failed owner admitted later scalar effect",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_cancelled_or_revoked_init_retains_history_and_park
);

fn smoke_8821_full_native_cancelled_unqualified_query_keeps_original_owner() -> TestResult {
    check(|| {
        let mut f = fixture(1, Reply::Missing, false)?;
        let ring = f.owner.receive.as_ref().unwrap().address();
        let buffers: Vec<_> = f.owner.buffers.iter().map(Memory::address).collect();
        f.port.source.hold_delay.store(true, Ordering::Release);
        let mut future = Box::pin(f.owner.ae_prepare_coex(f.base.clone()));
        require(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
                && f.port.source.holding.load(Ordering::Acquire)
                && f.port.source.queries.load(Ordering::Acquire) == 1
                && f.port.source.bindings.load(Ordering::Acquire) == 0,
            "8821 missing-version future did not wait on actual mailbox/RX dependency",
        )?;
        drop(future);
        require(
            f.owner.phase == Phase::Failed
                && retained(&f, ring, &buffers)
                && f.port.parked()
                && f.port.source.program.get().is_none()
                && f.owner.rtl8821ae_coex.as_ref().unwrap().full.is_none(),
            "8821 cancelled original query fabricated program, rollback or reclamation",
        )?;
        require(
            f.port.write8(0x790, 0xaa).is_err(),
            "8821 cancelled query admitted later RF source effects",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_cancelled_unqualified_query_keeps_original_owner
);

fn smoke_8821_full_native_current_policy_loss_closes_before_new_notification() -> TestResult {
    check(|| {
        for absent in [false, true] {
            narf_wireless::reg::db::set_domain(domain(20));
            let mut f = fixture(0, Reply::Complete, false)?;
            let program = prepared(&mut f)?;
            let before = f.port.source.state.lock().commands.len();
            if absent {
                narf_wireless::reg::db::clear_domain();
            } else {
                narf_wireless::reg::db::set_domain(domain(1));
            }
            require(
                drive(f.owner.ae_coex_notify(Notify::Media(true)))?.is_err()
                    && f.owner.phase == Phase::Failed
                    && f.port.parked()
                    && f.port.source.state.lock().commands.len() == before,
                "8821 changed/absent current policy admitted notification before park",
            )?;
            let effects = AtomicUsize::new(0);
            require(
                program
                    .invoke(|| {
                        effects.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                    .is_err()
                    && effects.load(Ordering::Acquire) == 0,
                "8821 stale immutable policy snapshot admitted source operation",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_current_policy_loss_closes_before_new_notification
);

fn smoke_8821_full_native_lps_uses_original_shared_box_and_current_joint_source() -> TestResult {
    check(|| {
        for raw in [0, 1] {
            let mut f = fixture(raw, Reply::Complete, false)?;
            prepared(&mut f)?;
            // Explicit lifecycle fixture bypass: no over-air join is claimed.
            // The station watchdog normally establishes these exact booleans;
            // here they isolate qualified native LPS payload/box/retirement.
            let coex = f.owner.rtl8821ae_coex.as_mut().ok_or("8821 coex")?;
            let gate = coex.full.as_mut().ok_or("8821 dispatch")?.lps_gate();
            gate.linked = true;
            gate.report_linked = true;
            gate.enter_allowed = true;
            coex.btc.bt_info.bt_ctrl_lps = true;
            coex.btc.bt_info.bt_lps_on = true;
            coex.btc.bt_info.lps_val = 0x50;
            coex.btc.bt_info.rpwm_val = 4;
            drive(f.owner.ae_enter_leisure())?.map_err(|_| "8821 qualified native LPS enter")?;
            require(
                f.owner.packet.leisure && f.port.command(0x20, &[1, 0, 2, 0, 4, 0x50, 0]),
                "8821 actual BT-controlled power-mode payload",
            )?;
            let before = f.port.original.0.lock().writes.len();
            f.port.source.joint.revoke();
            require(
                drive(f.owner.ae_leave_leisure())?.is_err()
                    && f.port.parked()
                    && f.owner.phase == Phase::Failed,
                "8821 dead joint source admitted LPS wake instead of park",
            )?;
            require(
                f.port.original.0.lock().writes[before..]
                    .iter()
                    .all(|(_, r, _)| !((0x1d0..0x200).contains(r) || *r == 0x361)),
                "8821 revoked source published power-mode/RPWM",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_full_native_lps_uses_original_shared_box_and_current_joint_source
);
