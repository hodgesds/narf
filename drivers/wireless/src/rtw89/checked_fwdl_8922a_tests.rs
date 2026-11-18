// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked BE ring/RP/doorbell retention over literal native registers.
use super::*;
use crate::rtw89::cold_8922a::Regs;
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    W16(u32, u16),
    W32(u32, u32),
}
struct Map {
    address: u64,
    bytes: Box<[u8]>,
    drops: Arc<AtomicUsize>,
    revoke_on_write:
        Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
    revoke_on_read:
        Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
}
impl Drop for Map {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: private inert model owns stable byte storage and unique modeled DMA
// addresses; writes enforce extent and sync is a model-only no-hardware action.
unsafe impl Memory for Map {
    fn address(&self) -> u64 {
        self.address
    }
    fn length(&self) -> usize {
        self.bytes.len()
    }
    fn write(&mut self, o: usize, b: &[u8]) -> Result<(), Error> {
        let end = o.checked_add(b.len()).ok_or(Error::Memory)?;
        self.bytes
            .get_mut(o..end)
            .ok_or(Error::Memory)?
            .copy_from_slice(b);
        if let Some(cap) = self.revoke_on_write.take() {
            cap.revoke();
        }
        Ok(())
    }
    fn sync(&self, _o: usize, _n: usize) {}
    fn read(&self, o: usize, b: &mut [u8]) -> Result<(), Error> {
        let end = o.checked_add(b.len()).ok_or(Error::Memory)?;
        b.copy_from_slice(self.bytes.get(o..end).ok_or(Error::Memory)?);
        if let Some(cap) = self.revoke_on_read {
            cap.revoke();
        }
        Ok(())
    }
}
fn memory(address: u64, len: usize, drops: &Arc<AtomicUsize>) -> Map {
    Map {
        address,
        bytes: vec![0; len].into_boxed_slice(),
        drops: drops.clone(),
        revoke_on_write: None,
        revoke_on_read: None,
    }
}
fn owned(depth: u16, drops: &Arc<AtomicUsize>) -> Owner<Map> {
    let mut address = 0x100000;
    let mut next = |length| {
        let m = memory(address, length, drops);
        address += 0x1000;
        m
    };
    let tx = core::array::from_fn(|_| next(usize::from(depth) * 8));
    let rx = core::array::from_fn(|_| next(usize::from(depth) * 8));
    let receive = core::array::from_fn(|_| (0..depth).map(|_| next(128)).collect());
    let legacy = (0..3).map(|_| next(32)).collect();
    // SAFETY: one inert controller exclusively owns every modeled referenced map.
    unsafe { Owner::adopt(Storage { tx, rx, receive }, legacy, depth, depth) }
}
struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<Op>,
    binding: cold::Binding,
    accesses: usize,
    fail_at: Option<usize>,
    failed: bool,
    drop_bdram: bool,
    fast_bdram: bool,
    stuck_bdram: bool,
    drop_num: bool,
    drop_doorbell: bool,
    consume: bool,
    gone: Option<u32>,
}
impl Model {
    fn new() -> Self {
        let words = [
            (0x24, 0x1f00_0000),
            (0x84, 0x0201_0002),
            (0x88, 0x802),
            (0x10000, 0xc050_01ff),
            (0xb000, 0x30),
            (0xb010, 0),
            (0xb01c, 0),
        ]
        .into_iter()
        .collect();
        let cap =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        Self {
            words,
            writes: Vec::new(),
            binding: cold::Binding::observe(&region, &cap),
            accesses: 0,
            fail_at: None,
            failed: false,
            drop_bdram: false,
            fast_bdram: false,
            stuck_bdram: false,
            drop_num: false,
            drop_doorbell: false,
            consume: false,
            gone: None,
        }
    }
    fn word(&self, a: u32) -> u32 {
        self.words.get(&a).copied().unwrap_or(0)
    }
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.accesses += 1;
        if self.fail_at == Some(self.accesses) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
}
impl cold::Regs for Model {
    fn binding(&self) -> cold::Binding {
        self.binding
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn read8(&mut self, _a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn write8(&mut self, _a: u32, _v: u8) -> Result<(), power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        Ok(self.word(a) as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(if self.gone == Some(a) {
            u32::MAX
        } else {
            self.word(a)
        })
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push(Op::W16(a, v));
        if self.drop_num && a == 0xb030 {
            return Ok(());
        }
        let idx = BE_DMA_ADDR_SET.tx[12].idx as u32;
        if self.drop_doorbell && (a == idx || a == 0xb160) {
            return Ok(());
        }
        let high = if a == idx && self.consume {
            u32::from(v) << 16
        } else {
            self.word(a) & 0xffff_0000
        };
        self.words.insert(a, high | u32::from(v));
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push(Op::W32(a, v));
        if a == 0xb014 && v == 0x7fff {
            for ring in &BE_DMA_ADDR_SET.tx {
                self.words.insert(ring.idx as u32, 0);
            }
        }
        if a == 0xb018 && v == 3 {
            for ring in &BE_DMA_ADDR_SET.rx {
                self.words.insert(ring.idx as u32, 0);
            }
        }
        if a == 0xb000 && v & 0x10000 != 0 {
            if self.drop_bdram {
                return Ok(());
            }
            if self.fast_bdram {
                self.words.insert(a, v & !0x10000);
                return Ok(());
            }
        }
        self.words.insert(a, v);
        Ok(())
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, _us: u64) -> Result<(), power::Error> {
        self.access()?;
        if a == 0xb000 && m == 0x10000 && self.word(a) & m != 0 && !self.stuck_bdram {
            self.words.insert(a, self.word(a) & !m);
        }
        if self.word(a) & m == v {
            Ok(())
        } else {
            Err(power::Error::Timeout)
        }
    }
    fn delay_us(&mut self, _us: u64) -> Result<(), power::Error> {
        self.access()
    }
}
fn enabled(depth: u16) -> Result<(Owner<Map>, Model, Arc<AtomicUsize>), Error> {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = owned(depth, &drops);
    let mut model = Model::new();
    owner.reset_program(&mut model)?;
    // SAFETY: inert model represents completed source DLE/HFC/PCI prerequisites;
    // this is not a native callback, grant or firmware/readiness receipt.
    unsafe { owner.enable_ch12(&mut model) }?;
    Ok((owner, model, drops))
}
fn smoke_rtw8922a_checked_reset_ring_and_terminal_retention() -> TestResult {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = owned(4, &drops);
    let mut model = Model::new();
    kt_assert_eq!(owner.reset_program(&mut model), Ok(()));
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    kt_assert_eq!(owner.state(), State::ProgrammedStopped);
    kt_assert_eq!(
        &model.writes[..9],
        &[
            Op::W32(0x88, 0x800),
            Op::W32(0x88, 0x800),
            Op::W32(0x88, 0x802),
            Op::W32(0xb010, 0x8000_7fff),
            Op::W32(0xb000, 0x80),
            Op::W32(0xb014, 0x7fff),
            Op::W32(0xb018, 3),
            Op::W16(0xb160, 3),
            Op::W16(0xb164, 3)
        ]
    );
    let tx0 = model
        .writes
        .iter()
        .position(|op| *op == Op::W16(0xb030, 4))
        .unwrap();
    kt_assert_eq!(
        &model.writes[tx0..tx0 + 3],
        &[
            Op::W16(0xb030, 4),
            Op::W32(0xb200, 0x100000),
            Op::W32(0xb204, 0)
        ]
    );
    let attempts = model.accesses;
    let stop = owner.stop_release(&mut model).unwrap();
    drop(stop);
    kt_assert_eq!(owner.state(), State::Released);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 26);
    let writes = model.writes.len();
    kt_assert_eq!(
        // SAFETY: deliberately terminal inert owner refuses before any I/O.
        unsafe { owner.enable_ch12(&mut model) },
        Err(Error::State)
    );
    kt_assert_eq!(model.writes.len(), writes);
    for at in 1..=attempts {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut held = owned(4, &counter);
        let mut fault = Model::new();
        fault.fail_at = Some(at);
        kt_assert!(held.reset_program(&mut fault).is_err());
        kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
        kt_assert!(matches!(held.state(), State::Failed(_)));
        drop(held);
        kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_reset_ring_and_terminal_retention
);
fn smoke_rtw8922a_checked_bdram_clear_never_retires_and_dropped_ring_refuses() -> TestResult {
    for kind in 0..4 {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut owner = owned(4, &counter);
        let mut model = Model::new();
        model.drop_bdram = kind == 0;
        model.fast_bdram = kind == 1;
        model.drop_num = kind == 2;
        model.stuck_bdram = kind == 3;
        let result = owner.reset_program(&mut model);
        if kind < 2 {
            // Default-clear and an unobservable short self-clear pulse are
            // configuration only. Neither can retire the original mappings.
            kt_assert_eq!(result, Ok(()));
            kt_assert_eq!(owner.state(), State::ProgrammedStopped);
        } else {
            kt_assert!(result.is_err());
            kt_assert!(matches!(owner.state(), State::Failed(_)));
        }
        kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
        kt_assert_eq!(owner.held(), (3, 0, 0));
        // A fresh denial-only stop never needs to sample the BDRAM pulse. It
        // permanently releases this owner and cannot turn it into TX readiness.
        model.drop_bdram = false;
        model.fast_bdram = false;
        model.drop_num = false;
        model.stuck_bdram = false;
        let storage = owner.stop_release(&mut model).unwrap();
        drop(storage);
        kt_assert_eq!(owner.state(), State::Released);
        kt_assert_eq!(counter.load(Ordering::Relaxed), 26);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_bdram_clear_never_retires_and_dropped_ring_refuses
);
fn smoke_rtw8922a_checked_ch12_multitag_and_uncertain_kick_keep_original_mappings() -> TestResult {
    let (mut owner, mut model, drops) = enabled(16).unwrap();
    model.consume = true;
    for n in 0..20 {
        kt_assert!(owner
            .submit(&mut model, memory(0x900000 + n * 0x1000, 32, &drops))
            .is_ok());
    }
    kt_assert_eq!(owner.held(), (3, 1, 19));
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    let kept = drops.load(Ordering::Relaxed);
    drop(owner);
    kt_assert_eq!(drops.load(Ordering::Relaxed), kept);
    for kind in 0..3 {
        let (mut held, mut io, counter) = enabled(8).unwrap();
        if kind == 0 {
            io.drop_doorbell = true;
            kt_assert!(held
                .submit(&mut io, memory(0xa00000, 32, &counter))
                .is_err());
        } else {
            kt_assert!(held.submit(&mut io, memory(0xa00000, 32, &counter)).is_ok());
            let idx = BE_DMA_ADDR_SET.tx[12].idx as u32;
            if kind == 1 {
                io.words.insert(idx, (7 << 16) | 1);
            } else {
                io.gone = Some(idx);
            }
            kt_assert!(held.reclaim(&mut io).is_err());
        }
        kt_assert_eq!(held.held(), (3, 1, 0));
        kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
        kt_assert!(matches!(held.state(), State::Failed(_)));
        drop(held);
        kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_ch12_multitag_and_uncertain_kick_keep_original_mappings
);
fn smoke_rtw8922a_checked_native_dma_authority_and_bounds() -> TestResult {
    let mut words = vec![0u32; 0x40000 / 4];
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let cap =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    for (address, value) in [
        (0x10000, 0x3000_0000),
        (0x84, 3),
        (0x14000, 0),
        (0xb010, 0),
        (0xb201, 0),
    ] {
        // SAFETY: private aligned RAM mapping, no device or competing writer.
        let mut io = unsafe { Native::new(&region, &cap) };
        kt_assert_eq!(io.write32(address, value), Err(power::Error::Access));
        kt_assert_eq!(io.write32(0xb010, 0x8000_7fff), Err(power::Error::Access));
    }
    // SAFETY: private aligned RAM mapping, exclusive current checked port.
    let mut io = unsafe { Native::new(&region, &cap) };
    kt_assert_eq!(io.write32(0xb010, 0x8000_6fff), Ok(()));
    cap.revoke();
    kt_assert_eq!(io.write32(0xb010, 0x8000_7fff), Err(power::Error::Access));
    kt_assert_eq!(words[0xb010 / 4], 0x8000_6fff);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_native_dma_authority_and_bounds
);

fn smoke_rtw8922a_post_download_rp_stop_and_ch12_restore_never_retire_maps() -> TestResult {
    let (mut owner, mut io, drops) = enabled(8).unwrap();
    io.words.insert(0x88, 2); // Fresh WCPU running after the separate FWDL owner.
    io.words.insert(0x84, 0x0201_0003); // Closed System releases BB0 platform.
    io.consume = true;
    kt_assert!(owner.submit(&mut io, memory(0xb00000, 32, &drops)).is_ok());
    kt_assert_eq!(owner.stop_for_trx(&mut io), Ok(()));
    kt_assert_eq!(owner.state(), State::FirmwareStopped);
    kt_assert_eq!(owner.held(), (3, 0, 1));
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    kt_assert_eq!(io.word(0xb010) & 0x8000_7fff, 0x8000_7fff);
    kt_assert_eq!(io.word(0xb000) & 0xb0, 0x80);
    // SAFETY: inert model of the checked closed SCC/TRX completion. The
    // separate TRX tests exercise that real producer; this grants no hardware.
    let restored = unsafe { owner.resume_ch12_after_trx(&mut io) };
    kt_assert_eq!(restored, Ok(()));
    kt_assert_eq!(io.word(0xb010) & 0x8000_7fff, 0x8000_6fff);
    kt_assert_eq!(io.word(0xb000) & 0xb0, 0x30);
    kt_assert_eq!(owner.held(), (3, 0, 1));
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    let storage = owner.stop_release(&mut io).unwrap();
    drop(storage);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 35);
    kt_assert_eq!(owner.state(), State::Released);
    let (mut held, mut io, counter) = enabled(8).unwrap();
    kt_assert!(held.submit(&mut io, memory(0xc00000, 32, &counter)).is_ok());
    io.fail_at = Some(io.accesses + 1);
    kt_assert!(held.stop_for_trx(&mut io).is_err());
    kt_assert_eq!(held.held(), (3, 1, 0));
    drop(held);
    kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_post_download_rp_stop_and_ch12_restore_never_retire_maps
);
fn rx_packet(owner: &mut Owner<Map>, slot: usize, packet_type: u8, payload: &[u8]) {
    let packet = &mut owner.storage.as_mut().unwrap().receive[0][slot];
    let length = 4 + 24 + payload.len();
    packet.bytes.fill(0);
    packet.bytes[..4].copy_from_slice(&(0xc000 | length as u32).to_le_bytes());
    packet.bytes[4..8]
        .copy_from_slice(&((u32::from(packet_type) << 24) | payload.len() as u32).to_le_bytes());
    packet.bytes[28..length].copy_from_slice(payload);
}
fn smoke_rtw8922a_checked_firmware_rx_literal_doorbell_closed_packet_path() -> TestResult {
    let (mut owner, mut io, drops) = enabled(8).unwrap();
    // Source OUTSRC/RFK_REPORT/STATE envelope; no RFK command is outstanding
    // here, so this is only retained firmware data, never a calibration proof.
    rx_packet(&mut owner, 0, 10, &[0x26, 0, 0, 0, 10, 0, 0, 0, 1, 7]);
    rx_packet(&mut owner, 1, 0, &[0; 28]); // Actual well-formed ordinary Wifi MPDU.
    io.words.insert(0xb160, 0x0002_0007);
    let before = io.writes.len();
    let outcome = owner.receive_firmware(&mut io, 256).unwrap();
    kt_assert_eq!(
        (outcome.work, outcome.dropped, outcome.c2h.len()),
        (2, 1, 1)
    );
    kt_assert_eq!(
        outcome.c2h[0].route,
        super::super::completion_8922a::Route::OutsrcPhy { class: 9, func: 0 }
    );
    kt_assert_eq!(
        &io.writes[before..],
        &[Op::W16(0xb160, 0), Op::W16(0xb160, 1)]
    );
    kt_assert_eq!(io.word(0xb160), 0x0002_0001);
    for slot in 0..2 {
        kt_assert_eq!(
            &owner.storage.as_ref().unwrap().receive[0][slot].bytes[..4],
            &[0; 4]
        );
    }
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    kt_assert_eq!(owner.receive_firmware(&mut io, 1).unwrap().work, 0);
    // An inherited/full index mismatch fails closed; no cursor guessing or
    // descriptor replay can return a C2H or free its original maps.
    let (mut bad, mut io, counter) = enabled(8).unwrap();
    io.words.insert(0xb160, 0x0001_0000); // Host WP must still be7.
    kt_assert!(matches!(bad.receive_firmware(&mut io, 1), Err(Error::Ring)));
    drop(bad);
    kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    let (mut dropped, mut io, counter) = enabled(8).unwrap();
    rx_packet(&mut dropped, 0, 10, &[0x26, 0, 0, 0, 10, 0, 0, 0, 1, 7]);
    io.words.insert(0xb160, 0x0001_0007);
    io.drop_doorbell = true;
    kt_assert!(matches!(
        dropped.receive_firmware(&mut io, 1),
        Err(Error::Readback(0xb160))
    ));
    kt_assert_eq!(dropped.rx_wp, 0);
    kt_assert!(matches!(
        dropped.receive_firmware(&mut io, 1),
        Err(Error::State)
    ));
    drop(dropped);
    kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_firmware_rx_literal_doorbell_closed_packet_path
);
fn smoke_rtw8922a_checked_firmware_rx_native_revoke_retains_original_maps() -> TestResult {
    let (mut owner, _, drops) = enabled(8).unwrap();
    let cap =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    let mut ram = vec![0u32; 0x40000 / 4];
    ram[0xb160 / 4] = 0x0001_0007;
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: ram.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    cap.revoke();
    // SAFETY: private aligned RAM mapping and inert exclusively owned maps;
    // revoked capability must reject before any memory/MMIO effect.
    let mut port = unsafe { Native::new(&region, &cap) };
    kt_assert!(matches!(
        port.receive_firmware(&mut owner, 1),
        Err(Error::Io(power::Error::Access))
    ));
    kt_assert_eq!(ram[0xb160 / 4], 0x0001_0007);
    kt_assert_eq!(owner.rx_wp, 7);
    drop(owner);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_firmware_rx_native_revoke_retains_original_maps
);
fn smoke_rtw8922a_checked_native_command_revoke_drops_only_unpublished_packet() -> TestResult {
    let (mut owner, _, drops) = enabled(8).unwrap();
    let cap =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    let mut ram = vec![0u32; 0x40000 / 4];
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: ram.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let packet = memory(0xd00000, 64, &drops);
    let before = owner.storage.as_ref().unwrap().tx[12].bytes.clone();
    cap.revoke();
    // SAFETY: aligned private RAM and inert exclusive modeled DMA owner;
    // current-capability refusal must occur before descriptor publication.
    let mut port = unsafe { Native::new(&region, &cap) };
    kt_assert_eq!(
        port.submit_command(&mut owner, packet),
        Err(Error::Io(power::Error::Access))
    );
    kt_assert_eq!(&owner.storage.as_ref().unwrap().tx[12].bytes, &before);
    kt_assert_eq!(owner.held(), (3, 0, 0));
    kt_assert!(matches!(owner.state(), State::Failed(_)));
    kt_assert_eq!(drops.load(Ordering::Relaxed), 1); // only fresh unreferenced packet
    drop(owner);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 1); // all original maps pinned
    TestResult::Pass
}
fn native_enabled(
    region: &narf_bus::MmioRegion,
    cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ram: &mut [u32],
) -> (Owner<Map>, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = owned(8, &drops);
    let mut model = Model::new();
    // Establish the original model binding BEFORE any configuration. Native
    // later observes this same exact source controller/BAR/capability tuple.
    model.binding = cold::Binding::observe(region, cap);
    owner.reset_program(&mut model).unwrap();
    // SAFETY: inert same original source-program model; no hardware/DMA grant.
    unsafe { owner.enable_ch12(&mut model) }.unwrap();
    for (address, value) in &model.words {
        ram[*address as usize / 4] = *value;
    }
    (owner, drops)
}
fn smoke_rtw8922a_qualified_native_revocation_during_descriptor_write_retains_command() -> TestResult
{
    let bus =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    let mut ram = vec![0u32; 0x40000 / 4];
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: ram.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let (mut owner, drops) = native_enabled(&region, &bus, &mut ram);
    let (grant, signer) = super::super::be_qualification::tests::revocable();
    owner.storage.as_mut().unwrap().tx[12].revoke_on_write = Some(signer);
    // SAFETY: actual Native access to inert aligned same-binding BAR RAM and
    // exclusively owned model maps; grant is a current inert N22P fixture.
    let mut io = unsafe { Native::new(&region, &bus) }.qualify(&grant);
    let packet = memory(0xd00000, 64, &drops);
    kt_assert_eq!(
        io.submit_command(&mut owner, packet),
        Err(Error::Io(power::Error::Access))
    );
    kt_assert_eq!(ram[BE_DMA_ADDR_SET.tx[12].idx as usize / 4] & 0xfff, 0);
    kt_assert_eq!(owner.ring.wp, 0);
    kt_assert_eq!(owner.held(), (3, 1, 0));
    kt_assert!(matches!(owner.state(), State::Failed(_)));
    drop(owner);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_qualified_native_revocation_during_descriptor_write_retains_command
);

struct ReportPort<'a, 'b> {
    owner: &'a mut Owner<Map>,
    io: Native<'b>,
}
impl super::super::be_control::Interface for ReportPort<'_, '_> {
    fn active(&mut self) -> Result<(), power::Error> {
        self.owner
            .dma_current(&mut self.io)
            .map_err(|_| power::Error::Access)
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<(), power::Error> {
        let drops = self.owner.storage.as_ref().unwrap().tx[0].drops.clone();
        let mut packet = memory(0xd00000, bytes.len(), &drops);
        packet.bytes.copy_from_slice(bytes);
        self.io
            .submit_command(self.owner, packet)
            .map(|_| ())
            .map_err(|_| power::Error::Access)
    }
    fn consumed(&mut self) -> Result<bool, power::Error> {
        self.owner
            .reclaim(&mut self.io)
            .map_err(|_| power::Error::Access)?;
        Ok(self.owner.held().1 == 0)
    }
    fn receive(&mut self) -> Result<FirmwareRx, power::Error> {
        self.io
            .receive_firmware(self.owner, 256)
            .map_err(|_| power::Error::Access)
    }
}
fn smoke_rtw8922a_qualified_native_report_wait_revocation_never_publishes_report_or_rx_credit(
) -> TestResult {
    for revoke_on_clear in [false, true] {
        let bus =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let mut ram = vec![0u32; 0x40000 / 4];
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: ram.as_mut_ptr() as u64,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let (mut owner, drops) = native_enabled(&region, &bus, &mut ram);
        let (grant, signer) = super::super::be_qualification::tests::revocable();
        // SAFETY: inert source-bound actual Native/retained DMA model.
        let native = unsafe { Native::new(&region, &bus) }.qualify(&grant);
        let mut control = super::super::be_control::Control::default();
        {
            let mut port = ReportPort {
                owner: &mut owner,
                io: native,
            };
            let command = super::super::fwcmd_8922a::H2cCmd {
                cat: 2,
                class: 11,
                func: 8,
            };
            let kind = super::super::rfk::be_rfk::ReportKind::PreNtfy;
            // SAFETY: actual current inert N22P command-semantic fixture; no radio.
            kt_assert!(unsafe { control.send(&mut port, command, &[0; 4], Some(kind)) }.is_ok());
            // Same original hardware source now consumes CH12 and supplies a
            // literal valid report. Revocation occurs INSIDE the actual pending
            // wait's RX snapshot/clear effect, while its outer invoke is active.
            ram[BE_DMA_ADDR_SET.tx[12].idx as usize / 4] = 0x00010001;
            rx_packet(port.owner, 0, 10, &[0x26, 0, 0, 0, 10, 0, 0, 0, 1, 7]);
            let packet = &mut port.owner.storage.as_mut().unwrap().receive[0][0];
            if revoke_on_clear {
                packet.revoke_on_write = Some(signer);
            } else {
                packet.revoke_on_read = Some(signer);
            }
            ram[0xb160 / 4] = 0x00010007;
            kt_assert!(control.await_report(&mut port, kind, 5).is_err());
            kt_assert_eq!(control.state(), super::super::be_control::State::Failed);
            kt_assert_eq!(ram[0xb160 / 4], 0x00010007);
            kt_assert_eq!(port.owner.rx_wp, 7);
            let header = &port.owner.storage.as_ref().unwrap().receive[0][0].bytes[..4];
            kt_assert_eq!(header == [0; 4], revoke_on_clear);
            kt_assert!(matches!(port.owner.state(), State::Failed(_)));
        }
        drop(owner);
        kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_qualified_native_report_wait_revocation_never_publishes_report_or_rx_credit
);

struct DoneNativePort<'a, 'b> {
    port: ReportPort<'a, 'b>,
    ram: &'a mut [u32],
    revoke: Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
}
impl super::super::be_control::Interface for DoneNativePort<'_, '_> {
    fn active(&mut self) -> Result<(), power::Error> {
        super::super::be_control::Interface::active(&mut self.port)
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<(), power::Error> {
        super::super::be_control::Interface::submit(&mut self.port, bytes)?;
        // Inert hardware side: only after actual CH12 publication, supply a
        // literal DONE tuple and distinct RP advancement in the same old BAR.
        let header = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let tuple = (header & 0xffff) | (header & 0xff000000);
        let mut ack = [0u8; 12];
        ack[..4].copy_from_slice(&0x101u32.to_le_bytes());
        ack[4..8].copy_from_slice(&12u32.to_le_bytes());
        ack[8..12].copy_from_slice(&tuple.to_le_bytes());
        rx_packet(self.port.owner, 0, 10, &ack);
        self.port.owner.storage.as_mut().unwrap().receive[0][0].revoke_on_read = self.revoke;
        self.ram[BE_DMA_ADDR_SET.tx[12].idx as usize / 4] = 0x00010001;
        self.ram[0xb160 / 4] = 0x00010007;
        Ok(())
    }
    fn consumed(&mut self) -> Result<bool, power::Error> {
        super::super::be_control::Interface::consumed(&mut self.port)
    }
    fn receive(&mut self) -> Result<FirmwareRx, power::Error> {
        super::super::be_control::Interface::receive(&mut self.port)
    }
}
fn smoke_rtw8922a_wlan_native_done_ticket_owns_original_dma_and_rechecks_rx_source() -> TestResult {
    for revoke in [false, true] {
        let bus =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let mut ram = vec![0u32; 0x40000 / 4];
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: ram.as_mut_ptr() as u64,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let (mut owner, drops) = native_enabled(&region, &bus, &mut ram);
        let (grant, signer) = super::super::be_wlan_qualification::tests::revocable();
        // SAFETY: original actual Native/CH12/maps over inert source-bound
        // BAR, with a distinct current N22W fixture; no physical firmware.
        let io = unsafe { Native::new(&region, &bus) }
            .qualify_scope(super::super::be_qualification::Grant::Wlan(&grant));
        let mut control = super::super::be_control::Control::default();
        {
            let mut port = DoneNativePort {
                port: ReportPort {
                    owner: &mut owner,
                    io,
                },
                ram: &mut ram,
                revoke: revoke.then_some(signer),
            };
            let command = super::super::fwcmd_8922a::H2cCmd {
                cat: 2,
                class: 0x10,
                func: 3,
            };
            // SAFETY: this sole retained native CH12 owner and its original
            // DMA mappings stay alive through the command and any failure.
            // The inert port invokes current N22W/PCI at each effect and
            // supplies only the exact requested DONE tuple plus separate RP;
            // source revocation must fail without releasing those mappings.
            let result = unsafe { control.send_done(&mut port, command, &[0; 4], 5) };
            if revoke {
                kt_assert!(result.is_err());
                kt_assert_eq!(control.state(), super::super::be_control::State::Failed);
                kt_assert_eq!(port.ram[0xb160 / 4], 0x00010007);
                kt_assert_eq!(port.port.owner.rx_wp, 7);
                kt_assert!(matches!(port.port.owner.state(), State::Failed(_)));
                kt_assert_eq!(port.port.owner.held(), (3, 1, 0));
            } else {
                kt_assert!(result.is_ok());
                kt_assert_eq!(control.state(), super::super::be_control::State::Idle);
                kt_assert_eq!(port.port.owner.held(), (3, 0, 1));
                kt_assert_eq!(port.port.owner.rx_wp, 0);
            }
        }
        drop(owner);
        kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_wlan_native_done_ticket_owns_original_dma_and_rechecks_rx_source
);
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_native_command_revoke_drops_only_unpublished_packet
);

fn smoke_rtw8922a_original_packet_native_preflight_is_inactive_one_shot_and_no_reset() -> TestResult
{
    for fault in 0..4 {
        let bus =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let mut ram = vec![0u32; 0x40000 / 4];
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: ram.as_mut_ptr() as u64,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let (mut owner, drops) = native_enabled(&region, &bus, &mut ram);
        // Literal inert WLAN-only source model, not a physical RFK receipt.
        ram[0xe348 / 4] = 0xd57ddf;
        ram[0xac / 4] = 0x81004003;
        ram[0x1087c / 4] = 0x111;
        let (grant, signer) = super::super::be_packet_qualification::tests::revocable();
        let cancel = core::sync::atomic::AtomicBool::new(false);
        match fault {
            1 => ram[BE_DMA_ADDR_SET.tx[0].idx as usize / 4] = 0x00010000,
            2 => signer.revoke(),
            3 => cancel.store(true, Ordering::Release),
            _ => (),
        }
        let before = ram.clone();
        // SAFETY: same original native map owner over inert RAM; distinct
        // current N22O fixture, never a physical radio/MLME readiness proof.
        let mut io = unsafe {
            super::super::native_packet_be::fixture_preflight(&region, &bus, &cancel, &grant)
        };
        let result = owner.packet_preflight(&mut io, [2, 1, 2, 3, 4, 5]);
        kt_assert_eq!(result.is_ok(), fault == 0);
        kt_assert_eq!(ram, before);
        if fault == 0 {
            kt_assert_eq!(owner.packet_phase(), Some(packet::Phase::Inactive));
            // Even a valid full record + original-ring metadata cannot make
            // this concrete read-only adapter open traffic without BE MLME.
            // SAFETY: this negative call retains the same original inert
            // owner/maps; the concrete adapter unconditionally refuses start
            // and every register write. It cannot fabricate the missing MLME
            // receipt or activate real DMA, even with valid preflight metadata.
            kt_assert!(unsafe { owner.packet_start(&mut io) }.is_err());
            kt_assert_eq!(owner.packet_phase(), Some(packet::Phase::Failed));
        }
        kt_assert!(owner.packet_preflight(&mut io, [2, 1, 2, 3, 4, 5]).is_err());
        kt_assert_eq!(ram, before);
        drop(owner);
        kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_original_packet_native_preflight_is_inactive_one_shot_and_no_reset
);

fn smoke_rtw8922a_native_packet_header_uses_source_v2_not_v3_and_bounds_dma() -> TestResult {
    let mut frame = vec![0u8; 24];
    frame[0] = 0xb0;
    frame[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    let bytes = packet::header(&frame, 1, 7, 0x123456780).unwrap();
    kt_assert_eq!(bytes.len(), 78);
    let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    kt_assert_eq!(word(0), 0x00480080);
    kt_assert_eq!(word(4), 1 << 26);
    kt_assert_eq!(word(8), 24 | (0x12 << 17) | (1 << 24));
    kt_assert_eq!(word(12), 0x123 | (1 << 13));
    kt_assert_eq!(word(28), 1 << 31);
    kt_assert_eq!(word(32), (1 << 10) | (1 << 22) | (7 << 16));
    kt_assert_eq!(word(40), 1 << 30);
    kt_assert_eq!(word(48), 0); // no automatic RTS/protection rates
    kt_assert_eq!(&bytes[64..72], &[7, 128, 0, 0, 0, 0, 0, 0]);
    kt_assert!(packet::header(&frame, 32, 7, 0x123456780).is_err());
    kt_assert!(packet::header(&frame, 1, 7, (1 << 36) - 16).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_native_packet_header_uses_source_v2_not_v3_and_bounds_dma
);

// SAFETY: source-only inert register/ownership fixture, never a production
// grant/MLME receipt. Actual joint native authority is covered above.
unsafe impl packet::Port for Model {
    fn packet_current(&mut self, phase: packet::Phase) -> Result<(), power::Error> {
        self.current()?;
        let (gates, stop) = match phase {
            packet::Phase::Inactive => (0, 0x80006fff),
            packet::Phase::Active => (0x30000000, 0x6efe),
            _ => return Err(power::Error::Access),
        };
        if self.word(0x24) & 0x1f00001f != 0x1f000000
            || self.word(0x84) & 0x03030300 != 0x02010000
            || self.word(0x10000) & 0x30000000 != gates
            || self.word(0xb010) & 0x80007fff != stop
        {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn peer_current(&mut self, frame: &[u8], macid: u8) -> Result<(), power::Error> {
        self.current()?;
        if macid > 1 || frame.get(10..16) != Some(&[2u8, 1, 2, 3, 4, 5][..]) {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn start_packets(&mut self) -> Result<(), power::Error> {
        self.current()?;
        self.write32(0x10000, self.word(0x10000) | 0x30000000)?;
        self.write32(0xb010, 0x6efe)
    }
    fn stop_packets(&mut self) -> Result<(), power::Error> {
        self.current()?;
        self.write32(0xb010, 0x80006fff)?;
        self.write32(0x10000, self.word(0x10000) & !0x30000000)
    }
}
fn rpp_packet(owner: &mut Owner<Map>, slot: usize, record: u32) {
    let map = &mut owner.storage.as_mut().unwrap().receive[1][slot];
    map.bytes.fill(0);
    map.bytes[..4].copy_from_slice(&0xc020u32.to_le_bytes()); // FS/LS, write-size32
    map.bytes[4..8].copy_from_slice(&4u32.to_le_bytes()); // short BE RXD, 4-byte record
    map.bytes[28..32].copy_from_slice(&record.to_le_bytes());
}
fn smoke_rtw8922a_original_packet_source_needs_independent_rp_and_rpq_and_pins_terminal(
) -> TestResult {
    let (mut owner, mut io, drops) = enabled(8).unwrap();
    let original = io.writes.len();
    kt_assert_eq!(owner.packet_preflight(&mut io, [2, 1, 2, 3, 4, 5]), Ok(()));
    kt_assert_eq!(io.writes.len(), original);
    // SAFETY: inert source state/queues only; this never exercises the
    // production inactive-only adapter or claims a physical MLME receipt.
    kt_assert!(unsafe { owner.packet_start(&mut io) }.is_ok());
    let mut frame = vec![0u8; 32];
    frame[0] = 8;
    frame[1] = 1;
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    let body = memory(0xe00000, frame.len(), &drops);
    let header = memory(0xe01000, 78, &drops);
    let id = owner
        .packet_submit(&mut io, &frame, 1, body, header)
        .unwrap();
    let idx = BE_DMA_ADDR_SET.tx[0].idx as u32;
    kt_assert_eq!(io.word(idx) & 0xfff, 1);
    // Firmware release arrives first. Actual BD RP is still0; no receipt.
    rpp_packet(&mut owner, 0, 1); // seq0, BE0 QSEL0, MACID1, TX_DONE0
    io.words
        .insert(BE_DMA_ADDR_SET.rx[1].idx as u32, 0x00010007);
    let first = owner.packet_poll(&mut io, 8).unwrap();
    kt_assert!(first.receipts.is_empty());
    io.words.insert(idx, 0x00010001);
    let second = owner.packet_poll(&mut io, 8).unwrap();
    kt_assert_eq!(second.receipts.len(), 1);
    kt_assert_eq!(second.receipts[0].id, id);
    kt_assert_eq!(second.receipts[0].status, 0);
    kt_assert_eq!(second.receipts[0].bytes, frame);
    // Delayed duplicate cannot complete any newer/no outstanding identity.
    rpp_packet(&mut owner, 1, 1);
    io.words
        .insert(BE_DMA_ADDR_SET.rx[1].idx as u32, 0x00020000);
    kt_assert!(owner.packet_poll(&mut io, 8).is_err());
    kt_assert_eq!(owner.packet_phase(), Some(packet::Phase::Failed));
    kt_assert!(matches!(owner.state(), State::Failed(_)));
    drop(owner);
    kt_assert_eq!(drops.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_original_packet_source_needs_independent_rp_and_rpq_and_pins_terminal
);
