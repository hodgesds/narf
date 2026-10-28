// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CE/RTL8822CE PCI DMA-stop proof (Linux v7.2 rtw88 `pci.c`
//! `rtw_pci_stop` → `rtw_pci_disable_interrupt` + `rtw_pci_dma_release`,
//! `wow.c::rtw_wow_rx_dma_stop`, `util.c::check_hw_ready`).
//!
//! Linux frees its ring skbs after `rtw_pci_stop` because the HIMRs are
//! zero and `rtw_hci_stop` ran after `rtw_mac_power_off`. NARF keeps the
//! controller powered, so instead it proves every DMA engine idle under
//! closed bus mastering before any published mapping may be released.
use super::firmware_transport::Error;
use alloc::boxed::Box;

/// TX buffer-descriptor index registers (`rtw_pci_tx_queue_idx_addr`):
/// H2C, BK, BE, VO, VI, MGMT, HI0. Host WP is bits 0..11, hardware RP
/// bits 16..27 (`__pci_get_hw_tx_ring_rp`).
pub(super) const TX_INDEX: [u16; 7] = [0x132c, 0x3ac, 0x3a8, 0x3a0, 0x3a4, 0x3b0, 0x3b8];
/// `RTK_PCI_HIMR0`, `RTK_PCI_HIMR1`, `RTK_PCI_HIMR3`.
pub(super) const HIMR: [u16; 3] = [0xb0, 0xb8, 0x10b8];
/// `REG_RXPKT_NUM` with `BIT_RW_RELEASE` (18) and `BIT_RXDMA_IDLE` (17).
pub(super) const RXPKT_NUM: u16 = 0x284;
pub(super) const RW_RELEASE: u32 = 1 << 18;
pub(super) const RXDMA_IDLE: u32 = 1 << 17;
/// `check_hw_ready`: 1000 polls 10 us apart.
const POLLS: usize = 1000;

/// Teardown register view. It needs only the exact device's current PCI
/// authority and memory decode: it is valid after bus mastering closed.
#[async_trait::async_trait]
pub(super) trait Quiesce: Send {
    /// A fresh PCI command read: bus mastering clear and INTx disabled.
    fn bus_master_closed(&mut self) -> Result<bool, Error>;
    fn read8(&mut self, reg: u16) -> Result<u8, Error>;
    fn read32(&mut self, reg: u16) -> Result<u32, Error>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error>;
    async fn delay_us(&mut self, us: u64);
}

fn read(io: &mut impl Quiesce, reg: u16) -> Result<u32, Error> {
    match io.read32(reg)? {
        u32::MAX => Err(Error::Gone),
        value => Ok(value),
    }
}

/// Prove the stopped controller idle. Every failure keeps the caller's
/// published rings and buffers retained; success is the only release proof.
pub(super) async fn prove(io: &mut impl Quiesce) -> Result<(), Error> {
    // rtw_pci_stop already ran: BME off, INTx off, HIMRs zero.
    if !io.bus_master_closed()? {
        return Err(Error::Prerequisite);
    }
    for reg in HIMR {
        if read(io, reg)? != 0 {
            return Err(Error::Prerequisite);
        }
    }
    // TXPAUSE all queues; CR HCI_TXDMA/HCI_RXDMA/TXDMA/RXDMA/... closed.
    let pause = io.read8(0x522)?;
    let cr = io.read8(0x100)?;
    if pause != 0xff || cr & 0xcf != 0 {
        return Err(Error::Prerequisite);
    }
    // TX: each ring's hardware read pointer reached the host write pointer
    // (`rtw_pci_dma_check`/`rtw_pci_tx_isr` treat rp == wp as drained).
    for reg in TX_INDEX {
        let mut drained = false;
        for _ in 0..POLLS {
            let value = read(io, reg)?;
            if value & 0xfff == (value >> 16) & 0xfff {
                drained = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !drained {
            return Err(Error::Timeout);
        }
    }
    // RX: rtw_wow_rx_dma_stop sets RW_RELEASE and waits for RXDMA_IDLE.
    let rx = read(io, RXPKT_NUM)?;
    io.write32(RXPKT_NUM, rx | RW_RELEASE)?;
    let mut idle = false;
    for _ in 0..POLLS {
        if read(io, RXPKT_NUM)? & RXDMA_IDLE != 0 {
            idle = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !idle {
        return Err(Error::Timeout);
    }
    // Nothing reopened bus mastering while the engines drained.
    if !io.bus_master_closed()? {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
pub(super) mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Byte register file plus PCI command model.
    pub(in crate::rtw88) struct Regs {
        pub(in crate::rtw88) bytes: Vec<u8>,
        pub(in crate::rtw88) bme: bool,
        /// TX ring index register whose RP never catches up.
        pub(in crate::rtw88) stuck_tx: Option<u16>,
        pub(in crate::rtw88) rx_busy: bool,
        pub(in crate::rtw88) gone: bool,
        /// Reopen BME after this many delays.
        pub(in crate::rtw88) reopen_after: Option<usize>,
        pub(in crate::rtw88) delays: usize,
    }
    impl Regs {
        /// A stopped controller as `rtw_pci_stop` leaves it.
        pub(in crate::rtw88) fn stopped() -> Self {
            let mut bytes = vec![0; 0x1400];
            bytes[0x522] = 0xff;
            Self {
                bytes,
                bme: false,
                stuck_tx: None,
                rx_busy: false,
                gone: false,
                reopen_after: None,
                delays: 0,
            }
        }
        pub(in crate::rtw88) fn set32(&mut self, reg: u16, value: u32) {
            let at = usize::from(reg);
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn get32(&self, reg: u16) -> u32 {
            let at = usize::from(reg);
            u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
        }
    }
    #[async_trait::async_trait]
    impl Quiesce for Regs {
        fn bus_master_closed(&mut self) -> Result<bool, Error> {
            Ok(!self.bme)
        }
        fn read8(&mut self, reg: u16) -> Result<u8, Error> {
            Ok(if self.gone {
                0xff
            } else {
                self.bytes[usize::from(reg)]
            })
        }
        fn read32(&mut self, reg: u16) -> Result<u32, Error> {
            if self.gone {
                return Ok(u32::MAX);
            }
            let mut value = self.get32(reg);
            if reg == RXPKT_NUM && value & RW_RELEASE != 0 && !self.rx_busy {
                value |= RXDMA_IDLE;
            }
            Ok(value)
        }
        fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
            self.set32(reg, value);
            Ok(())
        }
        async fn delay_us(&mut self, _: u64) {
            self.delays += 1;
            if self.reopen_after == Some(self.delays) {
                self.bme = true;
            }
            // A ring still draining catches up unless held stuck.
            for reg in TX_INDEX {
                if Some(reg) != self.stuck_tx {
                    let value = self.get32(reg);
                    self.set32(reg, value & 0xfff | (value & 0xfff) << 16);
                }
            }
        }
    }
    fn run(regs: &mut Regs) -> Result<(), Error> {
        narf_scheduler::block_on(prove(regs))
    }

    /// `rtw_pci_stop` + DMA idle proof: success, every unmet stop condition,
    /// TX/RX engines that never drain, surprise removal and a BME reopen.
    fn smoke_rtw88_pci_dma_stop_proof_requires_stopped_idle_engines() -> TestResult {
        let mut regs = Regs::stopped();
        // A BE frame still in flight drains within the poll budget.
        regs.set32(0x3a8, 5 | 4 << 16);
        if run(&mut regs).is_err() || regs.get32(RXPKT_NUM) & RW_RELEASE == 0 {
            return TestResult::Fail("stopped idle controller was not proven");
        }
        let cases: [(fn(&mut Regs), Error, &str); 7] = [
            (|r| r.bme = true, Error::Prerequisite, "BME open"),
            (|r| r.set32(0xb8, 1), Error::Prerequisite, "HIMR1 armed"),
            (|r| r.bytes[0x522] = 0, Error::Prerequisite, "TX unpaused"),
            (|r| r.bytes[0x100] = 0x04, Error::Prerequisite, "TXDMA on"),
            (
                |r| {
                    r.stuck_tx = Some(0x132c);
                    r.set32(0x132c, 3);
                },
                Error::Timeout,
                "H2C not drained",
            ),
            (|r| r.rx_busy = true, Error::Timeout, "RXDMA busy"),
            (|r| r.gone = true, Error::Gone, "surprise removal"),
        ];
        for (mutate, expected, name) in cases {
            let mut regs = Regs::stopped();
            mutate(&mut regs);
            if run(&mut regs) != Err(expected) {
                let _ = name;
                return TestResult::Fail("unmet DMA-stop condition was accepted");
            }
        }
        let mut regs = Regs::stopped();
        regs.set32(0x3b0, 1);
        regs.reopen_after = Some(1);
        if run(&mut regs) != Err(Error::Prerequisite) {
            return TestResult::Fail("BME reopened during drain was accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw88/dma_stop",
        smoke_rtw88_pci_dma_stop_proof_requires_stopped_idle_engines
    );
}
