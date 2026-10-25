use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    seed: u32,
    values: RefCell<BTreeMap<u64, u32>>,
    trace: RefCell<Vec<(u64, u32)>>,
    accesses: Cell<usize>,
    fail: Cell<Option<usize>>,
}
impl Model {
    fn new(seed: u32) -> Self {
        Self {
            seed,
            values: RefCell::new(BTreeMap::new()),
            trace: RefCell::new(Vec::new()),
            accesses: Cell::new(0),
            fail: Cell::new(None),
        }
    }
    fn raw(&self, reg: u64) -> u32 {
        *self
            .values
            .borrow()
            .get(&reg)
            .unwrap_or(&if self.seed == 0 {
                0
            } else {
                self.seed ^ reg as u32
            })
    }
    fn access(&self) -> Result<(), Error> {
        let n = self.accesses.get();
        self.accesses.set(n + 1);
        if self.fail.get() == Some(n) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn parked(&self) {
        for (reg, value) in [
            (8, 0),
            (0x840, 0),
            (0x24, 0),
            (0x8048, 0x0200_0020),
            (0x981c, 1),
        ] {
            self.values.borrow_mut().insert(reg, value);
        }
    }
    fn hash(&self) -> u64 {
        self.trace
            .borrow()
            .iter()
            .fold(0xcbf29ce484222325, |mut hash, &(reg, value)| {
                for byte in (reg as u32)
                    .to_le_bytes()
                    .into_iter()
                    .chain(value.to_le_bytes())
                {
                    hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
                }
                hash
            })
    }
}
impl Port for Model {
    fn transmit_allowed(&self) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn access<T>(&self, _: bool, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.access()?;
        operation()
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.access()?;
        Ok(self.raw(reg))
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.borrow_mut().push((reg, value));
        self.values.borrow_mut().insert(reg, value);
        Ok(())
    }
    fn allocate(&self, _: usize) -> Result<narf_io::DmaBuffer, Error> {
        Err(Error::Memory)
    }
    fn master(&self, _: bool) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn now_us(&self) -> u64 {
        0
    }
}
const LOCAL: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn image() -> [u8; EEPROM_4K_BYTES] {
    let mut image = [0; EEPROM_4K_BYTES];
    image[12..18].copy_from_slice(&LOCAL);
    image[18..20].copy_from_slice(&[1, 1]);
    image
}
fn check_oracles() -> Result<(), &'static str> {
    for &(kind, seed, count, hash) in MAC_CASES {
        let io = Model::new(seed);
        match kind {
            0 => queue0(&io),
            1 => qos(&io),
            2 => dma(&io),
            3 => opmode(&io),
            4 => mfp(&io),
            _ => return Err("unknown C case"),
        }
        .map_err(|_| "native register trace")?;
        if io.trace.borrow().len() != count as usize || io.hash() != hash {
            return Err("MAC/queue/DMA differs from frozen reference data");
        }
    }
    Ok(())
}
fn check_preparation() -> Result<(), &'static str> {
    let mut factory = image();
    factory[20] = 1 | (3 << 2); // actual factory RF-silent input3.
    let io = Model::new(0x5a93a5c3);
    io.parked();
    prepare(&io, &factory, LOCAL).map_err(|_| "MAC prepare")?;
    if io.raw(8) & 4 != 0
        || io.raw(0x840) & 0x3ff != 0
        || io.raw(0x24) & 1 != 0
        || io.raw(0x8048) & 0x0200_0020 != 0x0200_0020
    {
        return Err("MAC preparation activated packet gate");
    }
    if io
        .trace
        .borrow()
        .iter()
        .any(|&(reg, _)| reg == 0xc || (0x800..0x828).contains(&reg))
    {
        return Err("MAC preparation published DMA address");
    }
    for entry in 0..128u64 {
        for field in 0..8u64 {
            if io.raw(0x8800 + entry * 32 + field * 4) != if field == 5 { 7 } else { 0 } {
                return Err("stale hardware key retained");
            }
        }
    }
    if io.raw(0x404c) & (3 << 6) != 0
        || io.raw(0x8340) != 0x380
        || io.raw(0x8114) != 0x200
        || io.raw(0x1070) != 20 * 44
    {
        return Err("native FIFO/GPIO/timing setup differs");
    }
    let bssid = [2, 0, 0, 0, 0, 1];
    peer(&io, Some((bssid, 7)), 9).map_err(|_| "peer")?;
    if io.raw(0x8008) != 2 || io.raw(0x800c) != (0x100 | 7 << 16) || io.raw(0x1070) != 9 * 44 {
        return Err("actual BSSID/AID/slot not programmed");
    }
    Ok(())
}
fn check_failures() -> Result<(), &'static str> {
    let io = Model::new(0);
    io.parked();
    prepare(&io, &image(), LOCAL).map_err(|_| "baseline")?;
    for point in 0..io.accesses.get() {
        let io = Model::new(0);
        io.parked();
        io.fail.set(Some(point));
        if prepare(&io, &image(), LOCAL) != Err(Error::Access) || io.accesses.get() != point + 1 {
            return Err("lost access continued MAC writes");
        }
        if io.raw(8) & 4 != 0 || io.raw(0x840) & 0x3ff != 0 || io.raw(0x24) & 1 != 0 {
            return Err("failed MAC prepare enabled DMA/IRQ");
        }
    }
    for reg in [8, 0x840, 0x24, 0x981c] {
        let io = Model::new(0);
        io.parked();
        io.values
            .borrow_mut()
            .insert(reg, if reg == 0x981c { 0 } else { u32::MAX });
        if prepare(&io, &image(), LOCAL) != Err(Error::State) || !io.trace.borrow().is_empty() {
            return Err("bad calibrated/parked state mutated hardware");
        }
    }
    Ok(())
}
fn smoke_ar9285_mac_queue_dma_matches_frozen_reference() -> TestResult {
    match check_oracles() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_mac_clears_keys_preserves_parking_and_binds_real_peer() -> TestResult {
    match check_preparation() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_mac_every_access_failure_stops_before_packet_activation() -> TestResult {
    match check_failures() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/mac",
    smoke_ar9285_mac_queue_dma_matches_frozen_reference
);
kernel_test_in!(
    "drivers/wireless/ath9k/mac",
    smoke_ar9285_mac_clears_keys_preserves_parking_and_binds_real_peer
);
kernel_test_in!(
    "drivers/wireless/ath9k/mac",
    smoke_ar9285_mac_every_access_failure_stops_before_packet_activation
);
