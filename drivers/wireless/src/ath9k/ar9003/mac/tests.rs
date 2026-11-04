use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::RefCell;
use narf_io::DmaBuffer;
use narf_kernel_test::{kernel_test_in, TestResult};

const MAC: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];

/// Read-back register file of a parked, PHY-active AR9300.
struct Regs(RefCell<BTreeMap<u64, u32>>, RefCell<Vec<u64>>);

impl Port for &Regs {
    fn transmit_allowed(&self) -> Result<(), Error> {
        Ok(())
    }
    fn access<T>(&self, _: bool, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        operation()
    }
    fn read(&self, register: u64) -> Result<u32, Error> {
        Ok(self.0.borrow().get(&register).copied().unwrap_or(0))
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.1.borrow_mut().push(register);
        self.0.borrow_mut().insert(register, value);
        Ok(())
    }
    fn allocate(&self, _: usize) -> Result<DmaBuffer, Error> {
        Err(Error::Memory)
    }
    fn master(&self, _: bool) -> Result<(), Error> {
        Err(Error::State)
    }
    fn now_us(&self) -> u64 {
        0
    }
}

fn identity(op_flags: u8) -> Identity {
    Identity {
        mac: MAC,
        eeprom_version: 2,
        template_version: 2,
        regulatory_domains: [0, 0],
        op_flags,
        rx_chainmask: 7,
        tx_chainmask: 7,
        tx_gain: 0,
        rx_gain: 0,
    }
}

fn regs() -> Regs {
    Regs(
        RefCell::new(BTreeMap::from([
            (AR_DIAG_SW, AR_DIAG_RX_PARK),
            (AR_PHY_ACTIVE, 1),
            (AR_TXCFG, 0x0000_0213),
            (AR_RXBP_THRESH, 0x0000_0505),
            (0x801c, 0x2c),
            (AR_GPIO_OE_OUT, 0xffff),
            (AR_GPIO_IN, 1 << 3),
        ])),
        RefCell::new(Vec::new()),
    )
}

fn check() -> Result<(), &'static str> {
    let mut image = vec![0u8; 64];
    // RF-silent enabled on GPIO 3, active high.
    image[RF_SILENT] = 1 | 2 | (3 << 2);
    let r = regs();
    let kill = prepare(&&r, &identity(3), &image, MAC, true).map_err(|_| "prepare fault")?;
    let reg = |a: u64| r.0.borrow().get(&a).copied().unwrap_or(0);
    if kill
        != Some(RfKill {
            gpio: 3,
            polarity: true,
        })
        || reg(AR_GPIO_OE_OUT) != 0xffff & !(3 << 6)
        || !matches!(
            rf_kill_asserted(
                &&r,
                kill.unwrap_or(RfKill {
                    gpio: 0,
                    polarity: false
                })
            ),
            Ok(true)
        )
    {
        return Err("AR9300 RF-silent GPIO decode/input differs");
    }
    // 5 GHz fast clock: SIFS 16, slot 9, ACK/CTS 25 us at 44 MHz.
    if reg(0x1030) != 14 * 44
        || reg(0x1070) != 9 * 44
        || reg(0x8014) != (25 * 44) | ((25 * 44) << 16)
        || reg(0x801c) & 0x7f != 43
    {
        return Err("AR9300 fast-clock IFS/USEC differs");
    }
    if reg(AR_TXCFG) != 0x0000_0215
        || reg(AR_RXCFG) & 7 != 5
        || reg(AR_RXFIFO_CFG) != 0x200
        || reg(AR_RXBP_THRESH) != 0x0000_0101
        || reg(AR_PCU_TXBUF_CTRL) != 0x700
        || reg(AR_Q_DESC_CRCCHK) != 1
        || r.1.borrow().contains(&0x4024)
    {
        return Err("EDMA ath9k_hw_set_dma / queue programming differs");
    }
    let r = regs();
    if prepare(&&r, &identity(1), &image, MAC, false).is_ok() {
        return Err("2 GHz prepared on a 5 GHz-only map");
    }
    r.0.borrow_mut().insert(AR_PHY_ACTIVE, 0);
    if !matches!(
        prepare(&&r, &identity(3), &image, MAC, false),
        Err(Error::State)
    ) {
        return Err("inactive PHY accepted");
    }
    image[RF_SILENT] = 0x21;
    if rf_silent(&image).is_ok() {
        return Err("reserved RF-silent bits accepted");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_mac_profile_dma_clock_and_rf_silent() -> TestResult {
    match check() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_mac_profile_dma_clock_and_rf_silent
);
