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
        let mut words = vec![0u32; 16384];
        let authority = cap();
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: words.as_mut_ptr() as u64,
            len: 65536,
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
