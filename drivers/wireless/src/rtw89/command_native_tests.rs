use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_bus::{BusAddr, BusKind, DeviceId, PcieAddr};
use narf_capabilities::{object_table, CapKind, CapSlot, Rights};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("radio_init/header_golden.rs");

fn cap() -> Cap<BusDeviceCap, Write> {
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: fresh model object, exact BusDevice/Write rights and generation.
    unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    }
}
fn device(chip: ChipId) -> BusDevice {
    let address = PcieAddr::new(0, 0, 7, 0);
    BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: 0x10ec,
            device: match chip {
                ChipId::Rtl8852A => 0x8852,
                ChipId::Rtl8852B => 0xb852,
                ChipId::Rtl8852C => 0xc852,
                ChipId::Rtl8851B => 0xb851,
                ChipId::Rtl8922A => 0x8922,
            },
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    }
}
struct Fixture {
    native: Native,
    words: Vec<u32>,
}
impl Fixture {
    fn new(chip: ChipId) -> Result<Self, Error> {
        Self::aperture(chip, 65536)
    }
    fn aperture(chip: ChipId, extent: usize) -> Result<Self, Error> {
        let mut words = vec![0u32; extent / 4];
        let authority = cap();
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: words.as_mut_ptr() as u64,
            len: extent as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: private aligned register RAM, no real device or other owner.
        let io = unsafe { NativeIo::new(region, authority, chip, 0) }.map_err(|_| Error::Access)?;
        let ring = alloc_coherent_masked(32, DomainId::DRIVER_0, (1u64 << 40) - 1)
            .map_err(|_| Error::NoMemory)?;
        // SAFETY: fresh private32-byte descriptor storage.
        unsafe {
            core::ptr::write_bytes(ring.as_mut_ptr(), 0, 32);
        }
        let native = Native {
            io,
            bdram: super::super::bdram::Bdram::default(),
            pcie: super::super::pcie::Pcie::default(),
            basic: super::super::pci_basic::Basic::default(),
            factory: None,
            fifo: super::super::fifo::Fifo::default(),
            cut: 0,
            device: device(chip),
            authority,
            chip,
            regs: addr_set_for_chip(chip).tx[12],
            ring: Some(ring),
            queue: CommandQueue::new(4)?,
            depth: 4,
            armed: false,
            state: State::Configuring,
            receive: super::super::rx_dma::Rx::default(),
            radio: super::super::rf_access::Rf::default(),
            runtime_sequence: 0,
            station_runtime: station::Runtime::default(),
            calibration: None,
            coex_ready: false,
            nctl_ready: false,
            calibrating: None,
            scheduler: Some(super::super::scheduler_mailbox::Mailbox::default()),
            gain_bases: None,
            radio_started: false,
            radio_shutdown: super::super::radio_shutdown::Shutdown::default(),
            ordinary: None,
            full_qualification: None,
            operating: Some(super::super::phy_operating::Operating::default()),
            phycap: None,
            phycap_attempted: false,
        };
        Ok(Self { native, words })
    }
    fn activate(&mut self) -> Result<(), Error> {
        // Test only replaces PCI command reads; register programming, current
        // authority, DMA allocation, codecs and publication are actual paths.
        self.native.configure_registers()?;
        self.native.state = State::Terminal;
        self.native.activate_registers()
    }
    fn words_after_fenced_drop(mut self) -> Vec<u32> {
        // SAFETY: exclusively owned inert RAM has never had hardware DMA,
        // prefetch or another producer; all fixture calls have completed.
        unsafe {
            self.native.reclaim_fenced();
        }
        // Keep this same MMIO allocation alive across Fixture/Native Drop.
        // Vec moves preserve its heap pointer; the returned owner holds it.
        core::mem::take(&mut self.words)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: every address belongs to this inert RAM-only fixture; there
        // has never been any device, DMA/prefetch or concurrent IRQ producer.
        unsafe {
            self.native.reclaim_fenced();
        }
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_native_station_cannot_convert_basic_or_dma_into_ordinary_rf() -> TestResult {
    let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x40020).unwrap();
    f.activate().unwrap();
    let before = f.words.clone();
    if f.native.ordinary_current() != Err(super::super::power::Error::Unsupported)
        || f.native.prepare_packets([2, 4, 6, 8, 10, 12], 0)
            != Err(super::super::packet_core::Error::Access)
        || f.words != before
        || f.native.station_runtime.core.is_some()
    {
        return TestResult::Fail(
            "native DMA readiness manufactured ordinary RF/response authority",
        );
    }
    let admission = super::super::station_control::Admission::new();
    if ready(
        f.native
            .send_permit(Kind::Header, &[1; 16], station::Permit::Station(&admission)),
    ) != Some(Err(Error::Access))
        || f.native.queue.pending() != 0
        || f.words != before
    {
        return TestResult::Fail("station command reached DMA without the sealed ordinary grant");
    }
    f.native.authority.revoke();
    let mut access = f.native.station_access();
    let mut called = false;
    let result = super::super::station_control::Interface::with_current(&mut access, |_| {
        called = true;
        Ok(())
    });
    if result != Err(super::super::power::Error::Access) || called || f.words != before {
        return TestResult::Fail("revoked actual station authority reached a register closure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_station_cannot_convert_basic_or_dma_into_ordinary_rf
);
fn smoke_rtw89_native_ch12_program_publish_and_revocation() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut fixture = Fixture::new(chip).unwrap();
        if fixture.activate().is_err() || !fixture.native.firmware_prepared() {
            return TestResult::Fail("actual native ring publication/readback");
        }
        let mut body = [0u8; 72];
        for (index, byte) in body.iter_mut().enumerate() {
            *byte = index as u8;
        }
        if ready(fixture.native.send(Kind::Section, &body)) != Some(Ok(()))
            || fixture.native.queue.pending() != 1
            || fixture.native.firmware_prepared()
        {
            return TestResult::Fail("actual native firmware-command receipt");
        }
        let idx = fixture.native.regs.idx as usize / 4;
        if fixture.words[idx] != 1 {
            return TestResult::Fail("host WP not in low16-bit half");
        }
        let packet = fixture.native.queue.model_resource(0).unwrap();
        let header = command_queue::descriptor(chip, Kind::Section, 72).unwrap();
        // SAFETY: actual retained packet allocation covers descriptor+72 bytes.
        let copied =
            unsafe { core::slice::from_raw_parts(packet.cpu_ptr::<u8>(), header.len() + 72) };
        if copied[..header.len()] != *header || copied[header.len()..] != body {
            return TestResult::Fail("native packet DMA contains wrong descriptor/payload");
        }
        // SAFETY: model owns the complete descriptor-ring allocation.
        let bd = unsafe {
            core::slice::from_raw_parts(fixture.native.ring.as_ref().unwrap().cpu_ptr::<u8>(), 8)
        };
        if bd != command_queue::txbd(packet.dma_addr().raw(), header.len() + 72).unwrap() {
            return TestResult::Fail("TXBD omitted command descriptor bytes/address");
        }
        fixture.words[idx] = 0x0001_0001;
        if fixture.native.poll() != Ok(0)
            || fixture.native.queue.pending() != 0
            || fixture.native.firmware_prepared()
        {
            return TestResult::Fail("HW upper-half consumption / multi-tag retention");
        }
        fixture.native.authority.revoke();
        let wp = fixture.native.queue.write_pointer();
        if ready(fixture.native.send(Kind::Header, &body)) != Some(Err(Error::Access))
            || fixture.native.queue.write_pointer() != wp
            || fixture.words[idx] != 0x0001_0001
        {
            return TestResult::Fail("revoked native command published DMA/registers");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_ch12_program_publish_and_revocation
);
fn smoke_rtw89_native_ch12_failed_configuration_is_retained() -> TestResult {
    let mut fixture = Fixture::new(ChipId::Rtl8852B).unwrap();
    fixture.native.authority.revoke();
    if fixture.native.configure_registers() != Err(Error::Access)
        || !fixture.native.armed
        || fixture.words.iter().any(|word| *word != 0)
    {
        return TestResult::Fail("revoked ring setup touched registers or lost DMA pin");
    }
    // The complete public entry must reject before deliberately unmapped PCI
    // configuration, and before allocating any ring on that path.
    let mut words = vec![0u32; 16384];
    let authority = cap();
    authority.revoke();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 65536,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: private complete RAM mapping; revoked authority must stop before
    // any actual configuration access on the deliberately unmapped device.
    let result = unsafe {
        Native::new(
            device(ChipId::Rtl8852B),
            region,
            authority,
            ChipId::Rtl8852B,
            0,
            4,
        )
    };
    if !matches!(result, Err(Error::Access)) || words.iter().any(|word| *word != 0) {
        return TestResult::Fail("revoked constructor entered PCI/DMA configuration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_ch12_failed_configuration_is_retained
);

fn smoke_rtw89_ring_host_doorbells_preserve_hardware_half() -> TestResult {
    let mut words = vec![0u32; 16384];
    let tx = addr_set_for_chip(ChipId::Rtl8852B).tx[12];
    let rx = addr_set_for_chip(ChipId::Rtl8852B).rx[0];
    words[tx.idx as usize / 4] = 0x0ab0_fedc;
    words[rx.idx as usize / 4] = 0x0123_abcd;
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 65536,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: owned aligned RAM model of complete host-index registers; no DMA
    // producer exists and the test pointers fit the modelled ring depth.
    unsafe {
        crate::rtw89::datapath::ring_doorbell_tx(&region, &tx, 3);
        crate::rtw89::datapath::ring_doorbell_rx(&region, &rx, 4);
    }
    if words[tx.idx as usize / 4] != 0x0ab0_0003 || words[rx.idx as usize / 4] != 0x0123_0004 {
        return TestResult::Fail("doorbell overwrote HW read pointer half");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ring_host_doorbells_preserve_hardware_half
);

fn smoke_rtw89_native_bdram_requires_preparation_and_current_authority() -> TestResult {
    let mut fixture = Fixture::new(ChipId::Rtl8852B).unwrap();
    fixture.native.state = State::Unpublished;
    let before = fixture.words.clone();
    // The safe activation entry rejects missing cold factory/configuration
    // receipts before even consulting deliberately unmapped PCI configuration.
    fixture.native.state = State::Configured;
    if fixture.native.enable_download() != Err(Error::Terminal) || fixture.words != before {
        return TestResult::Fail("CH12 activation accepted an unqualified cold owner");
    }
    fixture.native.state = State::Unpublished;
    // SAFETY: exclusively owned inert model has no DMA or other producer.
    // The deliberately unmapped PCI configuration must not be accessed here:
    // a missing owned BDRAM receipt rejects before base publication/config I/O.
    if unsafe { fixture.native.configure() } != Err(Error::Terminal)
        || fixture.native.state != State::Unpublished
        || fixture.words != before
    {
        return TestResult::Fail("CH12 published a ring without its BDRAM preparation receipt");
    }
    fixture.native.authority.revoke();
    // SAFETY: no actual device exists; revocation must stop the exact native
    // entry before it can access the deliberately unmapped PCI configuration.
    if ready(unsafe { fixture.native.prepare_bdram(false) }) != Some(Err(Error::Access))
        || fixture.native.state != State::Terminal
        || fixture.native.bdram.state() != super::super::bdram::State::Preparing
        || fixture.words != before
        // SAFETY: the same exclusive inert model remains revoked and terminal;
        // this retry must reject before its unmapped PCI configuration access.
        || ready(unsafe { fixture.native.prepare_bdram(false) }) != Some(Err(Error::Terminal))
    {
        return TestResult::Fail("revoked native BDRAM entry accessed PCI/MMIO or reopened");
    }
    // Exercise actual NativeIo authority checks on the register path as well,
    // independently of the PCI command preflight above.
    let mut owner = super::super::bdram::Bdram::default();
    // SAFETY: NativeIo maps the fixture's exclusive inert RAM, with no device
    // or DMA producer; revoked authority must reject before any BAR access.
    if ready(unsafe { owner.prepare(&mut fixture.native.io, ChipId::Rtl8852B) })
        != Some(Err(super::super::power::Error::Access))
        || owner.state() != super::super::bdram::State::Preparing
        || fixture.words != before
    {
        return TestResult::Fail("revoked BDRAM register operation touched actual NativeIo BAR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_bdram_requires_preparation_and_current_authority
);

fn smoke_rtw89_cancelled_startup_closes_mmio_and_retains_published_command_dma() -> TestResult {
    let mut fixture = Fixture::new(ChipId::Rtl8852B).unwrap();
    if fixture.activate().is_err()
        || ready(fixture.native.send(Kind::Header, &[0x5a; 32])) != Some(Ok(()))
    {
        return TestResult::Fail("startup cancellation native command baseline");
    }
    let ring = fixture.native.ring.as_ref().unwrap().dma_addr().raw();
    fixture.words[0xc000 / 4] = 1 << 29;
    let retained = fixture.native.queue.pending();
    let packet = fixture
        .native
        .queue
        .model_resource(0)
        .unwrap()
        .dma_addr()
        .raw();
    {
        let future = async {
            let _attempt = super::super::startup::Attempt::new(&mut fixture.native);
            core::future::pending::<()>().await;
        };
        if ready(future).is_some() {
            return TestResult::Fail("startup cancellation did not retain waiter");
        }
    }
    if fixture.native.state != State::Terminal
        || retained != 1
        || fixture.native.queue.pending() != retained
        || fixture
            .native
            .queue
            .model_resource(0)
            .is_none_or(|memory| memory.dma_addr().raw() != packet)
        || fixture.native.ring.as_ref().unwrap().dma_addr().raw() != ring
        || fixture.words[0x1010 / 4] & 0xF0F00 != 0xF0F00
        || fixture.words[0xc000 / 4] & (1 << 29) != 0
        || ready(fixture.native.send(Kind::Header, &[1; 32])) != Some(Err(Error::Terminal))
    {
        return TestResult::Fail("cancelled startup reused or freed uncertain native DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_cancelled_startup_closes_mmio_and_retains_published_command_dma
);

fn smoke_rtw89_native_runtime_rf_headers_match_original_linux_c() -> TestResult {
    let mut f = Fixture::new(ChipId::Rtl8852B).unwrap();
    for &(sequence, path, page, length, expected) in HEADERS {
        f.native.runtime_sequence = u16::from(sequence);
        let body = vec![0x5a; length as usize];
        let packet = f.native.radio_page_packet(path, page, &body).unwrap();
        if packet[..8] != expected
            || packet[8..] != body
            || f.native.runtime_sequence != u16::from(sequence) + 1
        {
            return TestResult::Fail(
                "runtime RF page header/automatic ACK/sequence differs from original C",
            );
        }
    }
    f.native.runtime_sequence = 256;
    if f.native.radio_page_packet(0, 0, &[0; 4]) != Err(super::super::radio_init::Error::Profile) {
        return TestResult::Fail("initial RF runtime command sequence was reused after wrap");
    }
    f.native.runtime_sequence = 0;
    if ready(f.native.upload_radio_page(0, 0, &[0; 4]))
        != Some(Err(super::super::radio_init::Error::Register(
            super::super::power::Error::Terminal,
        )))
        || f.native.runtime_sequence != 0
        || f.native.armed
    {
        return TestResult::Fail("unqualified RF owner reached runtime sequence/DMA publication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_runtime_rf_headers_match_original_linux_c
);

fn smoke_rtw89_native_rf_page_observes_actual_descriptor_body_and_cancel_retention() -> TestResult {
    let mut f = Fixture::new(ChipId::Rtl8852B).unwrap();
    if f.activate().is_err() {
        return TestResult::Fail("RF native command model activation");
    }
    let body: Vec<u8> = (0..2000).map(|v| v as u8).collect();
    // This established private RAM backend seam replaces only cold/PCI
    // qualification, as Fixture::activate does for firmware-download smokes.
    // The actual runtime sender, capability, DMA allocations/descriptor and
    // outer cancellation guard are all production paths.
    let result = {
        let future = async {
            let mut attempt = super::super::startup::Attempt::new(&mut f.native);
            attempt.owner_mut().transmit_radio_page(1, 2, &body).await
        };
        ready(future)
    };
    if result.is_some()
        || f.native.state != State::Terminal
        || f.native.queue.pending() != 1
        || f.native.runtime_sequence != 1
    {
        return TestResult::Fail("RF command cancellation lost retained native owner");
    }
    let packet = f.native.queue.model_resource(0).unwrap();
    let bytes = packet.as_slice();
    let ring = f.native.ring.as_ref().unwrap();
    let bd = &ring.as_slice()[..8];
    let length = u16::from_le_bytes(bd[..2].try_into().unwrap()) as usize;
    let option = u16::from_le_bytes(bd[2..4].try_into().unwrap());
    let address = u32::from_le_bytes(bd[4..8].try_into().unwrap()) as u64
        | (((option >> 6) & 255) as u64) << 32;
    if length != 24 + 8 + 2000
        || address != packet.dma_addr().raw()
        || address + length as u64 - 1 > DEVICE_DMA_MASK
        || bytes[24..32] != [0x26, 2, 0, 0, 0xd8, 0x47, 0, 0]
        || bytes[32..32 + body.len()] != body
        || f.words[f.native.regs.idx as usize / 4] != 1
    {
        return TestResult::Fail(
            "RF upload fixture did not observe actual retained TXBD/H2C/body/host WP",
        );
    }
    let retained = packet.dma_addr().raw();
    f.native.authority.revoke();
    if ready(f.native.send(Kind::Header, &[0; 8])) != Some(Err(Error::Terminal))
        || f.native.queue.model_resource(0).unwrap().dma_addr().raw() != retained
    {
        return TestResult::Fail("cancelled/revoked RF upload reopened or released DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_rf_page_observes_actual_descriptor_body_and_cancel_retention
);

fn smoke_rtw89_native_revoked_calibration_blocks_register_and_command_publication() -> TestResult {
    let mut f = Fixture::new(ChipId::Rtl8852B).unwrap();
    if f.activate().is_err() {
        return TestResult::Fail("calibration revocation native baseline");
    }
    let (calibration, authority) = super::super::calibration_policy::tests::revocable_model();
    f.native.calibration = Some(calibration);
    f.native.coex_ready = true;
    f.native.nctl_ready = true;
    authority.revoke();
    let words = f.words.clone();
    let ring = f.native.ring.as_ref().unwrap().dma_addr().raw();
    let command = ready(f.native.coex_command(3, &[0; 26], true));
    if command
        != Some(Err(super::super::coex_native::Error::Register(
            super::super::power::Error::Access,
        )))
        || super::super::rfk::Interface::admit(&mut f.native)
            != Err(super::super::rfk::Error::Register(
                super::super::power::Error::Access,
            ))
        || Io::write32(&mut f.native, 0x8000, 4) != Err(super::super::power::Error::Access)
        || f.words != words
        || f.native.runtime_sequence != 0
        || f.native.queue.pending() != 0
        || f.native.ring.as_ref().unwrap().dma_addr().raw() != ring
    {
        return TestResult::Fail(
            "revoked actual calibration capability reached Native registers/sequence/DMA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_revoked_calibration_blocks_register_and_command_publication
);

fn smoke_rtw89_native_queued_command_rechecks_qualification_after_wait() -> TestResult {
    let mut f = Fixture::new(ChipId::Rtl8852B).unwrap();
    if f.activate().is_err() {
        return TestResult::Fail("queued qualification native baseline");
    }
    let (calibration, authority) = super::super::calibration_policy::tests::revocable_model();
    f.native.calibration = Some(calibration);
    // Existing explicit RAM transport boundary: actual capability, queue,
    // allocations, TXBD bytes and doorbell; no real device/attach is admitted.
    for _ in 0..f.native.depth {
        if f.native.queue.is_full() {
            break;
        }
        if ready(f.native.send(Kind::Header, &[3; 16])) != Some(Ok(())) {
            return TestResult::Fail("retained native queue fill");
        }
    }
    if !f.native.queue.is_full() {
        return TestResult::Fail("finite actual command ring never filled");
    }
    let retained = f.native.queue.pending();
    let index = f.native.regs.idx as usize / 4;
    let wp = f.words[index] & 65535;
    let descriptors = f.native.ring.as_ref().unwrap().as_slice().to_vec();
    let result = {
        let native = &mut f.native;
        let words = &mut f.words;
        let future = async {
            let mut attempt = super::super::startup::Attempt::new(native);
            attempt.owner_mut().send(Kind::Header, &[7; 16]).await
        };
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        if !matches!(future.as_mut().poll(&mut context), Poll::Pending) {
            return TestResult::Fail("full actual command queue did not wait");
        }
        authority.revoke();
        // The device frees a real TXBD while the sending future waits. It must
        // recheck the now-revoked qualification before even retiring/reusing it.
        words[index] = (words[index] & !0x0fff0000) | (1 << 16);
        // Use the shared finite time primitive solely to expire this real50us
        // future; no test-local hardware loop or executor bridge is involved.
        narf_time::busy_wait_cycles(narf_time::wall::ns_to_cycles(100_000));
        future.as_mut().poll(&mut context)
    };
    if result != Poll::Ready(Err(Error::Access))
        || f.native.state != State::Terminal
        || f.native.queue.pending() != retained
        || f.words[index] & 65535 != wp
        || f.native.ring.as_ref().unwrap().as_slice() != descriptors.as_slice()
    {
        return TestResult::Fail(
            "paused native command published/reused DMA after qualification revocation",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_queued_command_rechecks_qualification_after_wait
);

fn smoke_rtw89_native_terminal_radio_closure_uses_current_cap_and_retains_dma() -> TestResult {
    for revoked in [false, true] {
        let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
        if f.activate().is_err() || ready(f.native.send(Kind::Header, &[0x5a; 16])) != Some(Ok(()))
        {
            return TestResult::Fail("native radio closure baseline");
        }
        let ring = f.native.ring.as_ref().unwrap().dma_addr().raw();
        let packet = f.native.queue.model_resource(0).unwrap().dma_addr().raw();
        let pending = f.native.queue.pending();
        // Established inert RAM-only qualification boundary. Actual native MMIO,
        // capability, real retained command DMA and outer cancellation guard run.
        f.native.radio_started = true;
        for (address, mask) in [
            (0x109c4, 0x11),
            (0x10980, 0x10001),
            (0x15864, 0x20000000),
            (0x18010, 255),
            (0x18088, 0x12345678),
            (0x2f0, 0x20000),
            (0, 3 << 16),
        ] {
            f.words[address / 4] |= mask;
        }
        let before = f.words.clone();
        if revoked {
            f.native.authority.revoke();
        }
        {
            let _attempt = super::super::startup::Attempt::new(&mut f.native);
        }
        if f.native.state != State::Terminal
            || f.native.queue.pending() != pending
            || f.native.ring.as_ref().unwrap().dma_addr().raw() != ring
            || f.native.queue.model_resource(0).unwrap().dma_addr().raw() != packet
        {
            return TestResult::Fail("radio closure discarded uncertain command DMA");
        }
        if revoked {
            if f.words != before {
                return TestResult::Fail("revoked radio stop touched Native BAR");
            }
        } else if f.words[0x109c4 / 4] & 0x11 != 0
            || f.words[0x10980 / 4] & 0x10001 != 0
            || f.words[0x15864 / 4] & 0x20000000 != 0
            || f.words[0x18010 / 4] & 255 != 0
            || f.words[0x18088 / 4] != 0x80000000
            || f.words[0x2f0 / 4] & 0x20000 != 0
            || f.words[0] & 0x30000 != 0
        {
            return TestResult::Fail(
                "actual terminal Native left PMAC/NCTL/BB clock/reset controls open",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_terminal_radio_closure_uses_current_cap_and_retains_dma
);

fn smoke_rtw89_native_dma_fence_does_not_suppress_radio_drop_closure() -> TestResult {
    let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
    if f.activate().is_err() {
        return TestResult::Fail("radio Drop fence baseline");
    }
    f.native.radio_started = true;
    for (address, mask) in [
        (0x109c4, 0x11),
        (0x15864, 0x20000000),
        (0x18010, 255),
        (0x2f0, 0x20000),
        (0, 0x30000),
    ] {
        f.words[address / 4] |= mask;
    }
    let words = f.words_after_fenced_drop();
    if words[0x109c4 / 4] & 0x11 != 0
        || words[0x15864 / 4] & 0x20000000 != 0
        || words[0x18010 / 4] & 255 != 0
        || words[0x2f0 / 4] & 0x20000 != 0
        || words[0] & 0x30000 != 0
    {
        return TestResult::Fail("reclaimed command DMA hid independently started radio from Drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_dma_fence_does_not_suppress_radio_drop_closure
);

fn smoke_rtw89_native_xtal_shutdown_observes_actual_commands_and_keeps_dma() -> TestResult {
    for revoked in [false, true] {
        let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
        if f.activate().is_err() || ready(f.native.send(Kind::Header, &[9; 16])) != Some(Ok(())) {
            return TestResult::Fail("native XTAL shutdown baseline");
        }
        f.native.radio_started = true;
        f.native.fail();
        let pending = f.native.queue.pending();
        let packet = f.native.queue.model_resource(0).unwrap().dma_addr().raw();
        let before = f.words.clone();
        if revoked {
            f.native.authority.revoke();
        }
        let mut result = None;
        let mut xtal = [0xa5u8, 0x5a];
        let mut commands = 0;
        {
            let native = &mut f.native;
            let words = &mut f.words;
            let mut future = pin!(native.finish_radio_shutdown());
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..8 {
                match future.as_mut().poll(&mut context) {
                    Poll::Ready(value) => {
                        result = Some(value);
                        break;
                    }
                    Poll::Pending => {}
                }
                // Device model reads the *actual issued* native register command and
                // completes exactly that address/mode/mask against its independent RF
                // bytes. No pre-publication source or DMA-address-to-VA cast is used.
                let command = words[0x270 / 4];
                if command & (1 << 31) == 0 || !matches!(command as u8, 0x80 | 0x81) {
                    return TestResult::Fail(
                        "native shutdown did not publish a real bounded XTAL command",
                    );
                }
                let path = usize::from((command as u8) - 0x80);
                let data = if command & (1 << 24) != 0 {
                    xtal[path]
                } else {
                    if command >> 16 & 255 != 255 {
                        return TestResult::Fail(
                            "native RF shutdown write mask differs from source",
                        );
                    }
                    xtal[path] = (command >> 8) as u8;
                    xtal[path]
                };
                words[0x270 / 4] = (command & !(1 << 31) & !0xff00) | (u32::from(data) << 8);
                commands += 1;
                narf_time::busy_wait_cycles(narf_time::wall::ns_to_cycles(100_000));
            }
        }
        if f.native.queue.pending() != pending
            || f.native.queue.model_resource(0).unwrap().dma_addr().raw() != packet
            || f.native.state != State::Terminal
        {
            return TestResult::Fail("RF shutdown released uncertain actual native command DMA");
        }
        if revoked {
            if result != Some(Err(super::super::power::Error::Access))
                || commands != 0
                || f.words != before
            {
                return TestResult::Fail("revoked actual shutdown accessed native MMIO");
            }
        } else if result != Some(Ok(()))
            || commands != 6
            || xtal.iter().any(|v| v & 7 != 0)
            || f.native.radio_shutdown.state()
                != super::super::radio_shutdown::State::ShutdownAcknowledged
        {
            return TestResult::Fail("actual native XTAL disable/verify did not complete");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_xtal_shutdown_observes_actual_commands_and_keeps_dma
);

struct MetadataFiles;
impl super::super::prepared::Files for MetadataFiles {
    fn load(&mut self, _: &'static str) -> Result<Vec<u8>, super::super::fw::FwError> {
        let mut bytes = vec![0; 52];
        bytes[4..8].copy_from_slice(&[0, 29, 29, 18]);
        bytes[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x8000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&4u32.to_le_bytes());
        Ok(bytes)
    }
}
fn smoke_rtw89_native_qualification_requests_are_exact_current_and_read_only() -> TestResult {
    let Ok(mut f) = Fixture::aperture(ChipId::Rtl8852B, 0x20000) else {
        return TestResult::Fail("qualification metadata fixture");
    };
    let image = super::super::prepared::load(&mut MetadataFiles, ChipId::Rtl8852B, 0).unwrap();
    let assets = super::super::radio_assets::Assets::from_prepared(&image).unwrap();
    f.native.factory = Some(super::super::station_control::tests::factory_with_profile(
        0, 0x33, 5, false,
    ));
    f.native.phycap =
        Some(super::super::firmware_phycap::Receipt::decode([0x403, 0, 0, 0]).unwrap());
    f.native.state = State::Active;
    let before = f.words.clone();
    let basic = f.native.qualification_request(&assets, false).unwrap();
    let full = f.native.qualification_request(&assets, true).unwrap();
    let mac = f.native.factory.as_ref().unwrap().identity().unwrap().mac();
    let suffix = alloc::format!(
        "-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    if basic.version() != 1
        || full.version() != 2
        || basic.mac() != mac
        || full.mac() != mac
        || basic.digest() == full.digest()
        || !basic.name().starts_with("rtw89/rtw8852b-cal-v1-")
        || !full.name().starts_with("rtw89/rtw8852b-radio-v2-")
        || !basic.name().ends_with(&suffix)
        || !full.name().ends_with(&suffix)
        || f.words != before
        || f.native.radio_started
        || f.native.calibration.is_some()
        || f.native.full_qualification.is_some()
        || f.native.ordinary.is_some()
        || f.native.operating.as_ref().unwrap().state() != super::super::phy_operating::State::New
    {
        return TestResult::Fail("qualification metadata granted or changed hardware state");
    }
    f.native.authority.revoke();
    if f.native.qualification_request(&assets, false).is_ok()
        || f.native.qualification_request(&assets, true).is_ok()
        || f.words != before
    {
        return TestResult::Fail("revoked native metadata request touched registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_qualification_requests_are_exact_current_and_read_only
);
