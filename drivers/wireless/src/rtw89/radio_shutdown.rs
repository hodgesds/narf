// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained B/C asynchronous XTAL shutdown after immediate engine/clock closure.
//! Completion acknowledges the source RF00S/RF10S (B) or RF00/RF10 (C) disable
//! fields, not RF/DMA idle, an old-DMA fence, reset readiness or permission to
//! free memory.
use super::power::{Error, Io};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Stopping,
    ShutdownAcknowledged,
}
#[derive(Default)]
pub(super) struct Shutdown {
    state: State,
}
struct Access<'a, I>(&'a mut I);
impl<I: Io> Access<'_, I> {
    fn read(&mut self) -> Result<u32, Error> {
        let v = self.0.read32(0x270)?;
        if matches!(v, u32::MAX | 0xeaeaeaea | 0xdeadbeef) {
            Err(Error::Gone)
        } else {
            Ok(v)
        }
    }
    async fn idle(&mut self) -> Result<u32, Error> {
        let start = self.0.now_us();
        loop {
            let v = self.read()?;
            if v & (1 << 31) == 0 {
                return Ok(v);
            }
            if self.0.now_us().saturating_sub(start) >= 50_000 {
                return Err(Error::Timeout);
            }
            self.0.delay_us(50).await;
        }
    }
    /// One AX masked XTAL-SI write (mac.c `rtw89_mac_write_xtal_si`): only the
    /// address echo is checked; the final field state is proven by a read.
    async fn masked_write(&mut self, address: u8, value: u8, mask: u8) -> Result<(), Error> {
        self.idle().await?;
        let command =
            (1 << 31) | u32::from(address) | (u32::from(mask) << 16) | (u32::from(value) << 8);
        self.0.write32(0x270, command)?;
        let reply = self.idle().await?;
        if reply as u8 != address {
            return Err(Error::Access);
        }
        Ok(())
    }
    async fn transaction(&mut self, address: u8, value: Option<(u8, u8)>) -> Result<u8, Error> {
        // A cancelled earlier power/BB XTAL operation may still own the controller.
        // Wait for real idle before issuing the next serialized shutdown command.
        self.idle().await?;
        let command = (1 << 31)
            | u32::from(address)
            | match value {
                Some((v, mask)) => (u32::from(mask) << 16) | (u32::from(v) << 8),
                None => 1 << 24,
            };
        self.0.write32(0x270, command)?;
        let reply = self.idle().await?;
        if reply as u8 != address {
            return Err(Error::Access);
        }
        let data = (reply >> 8) as u8;
        if value.is_some_and(|(v, _)| v != data) {
            return Err(Error::Access);
        }
        Ok(data)
    }
}
/// # Safety
/// Serialized actual current B XTAL owner; caller retains uncertain controller
/// state on cancellation. Emission-related use also supplies current measured
/// authority through Io; shutdown may use raw current-device closing access.
pub(super) async unsafe fn xtal_read(io: &mut impl Io, address: u8) -> Result<u8, Error> {
    Access(io).transaction(address, None).await
}
/// # Safety
/// Same exclusive controller/current-authority contract as xtal_read. This is
/// the actual AX mask byte, not a software replacement of the masked register.
pub(super) async unsafe fn xtal_write(
    io: &mut impl Io,
    address: u8,
    value: u8,
    mask: u8,
) -> Result<(), Error> {
    if mask == 0 || value & !mask != 0 {
        return Err(Error::Unsupported);
    }
    Access(io).transaction(address, Some((value, mask))).await?;
    Ok(())
}
impl Shutdown {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Same retained exclusively owned B function and actual current-device Io;
    /// no independent power/PHY/XTAL/BT producer. All packet producers are closed
    /// and all uncertain DMA remains retained. Closing needs no new RF emission
    /// permission and does not establish reset/reclamation authority.
    pub async unsafe fn finish(
        &mut self,
        io: &mut impl Io,
        radio_started: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Stopping;
        let engine = if radio_started {
            super::radio_stop::engines(io)
        } else {
            Ok(())
        };
        let clock = super::radio_stop::clocks(io);
        let mut error = engine.err().or(clock.err());
        let mut a = Access(io);
        for address in [0x80u8, 0x81] {
            let result = async {
                let old = a.transaction(address, None).await?;
                a.transaction(address, Some((old & !7, 255))).await?;
                Ok::<(), Error>(())
            }
            .await;
            if error.is_none() {
                error = result.err();
            }
        }
        // Successful command echoes alone never supply the final disable proof.
        for address in [0x80u8, 0x81] {
            let result = a.transaction(address, None).await.and_then(|v| {
                if v & 7 == 0 {
                    Ok(())
                } else {
                    Err(Error::Access)
                }
            });
            if error.is_none() {
                error = result.err();
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        self.state = State::ShutdownAcknowledged;
        Ok(())
    }
}
impl Shutdown {
    /// RTL8852C terminal analog closure. rtw8852c.c `rtw8852c_mac_disable_bb_rf`
    /// is only the AFE-digital clock and BB reset clear (no XTAL step, unlike
    /// B's `__rtw8852bx_mac_disable_bb_rf`); the C RF00/RF10 disable lives in
    /// `rtw8852c_pwr_off_func` as masked `XTAL_SI_WL_RFC_S0`/`S1` writes of
    /// `XTAL_SI_RF00`/`XTAL_SI_RF10` (BIT 0) to zero, which this performs
    /// right after the clocks and then proves by reading both bytes back.
    /// The rest of `rtw8852c_pwr_off_func` (ANAPAR_WL, pads, APFM off) stays
    /// with the power owner's `power_off`.
    ///
    /// # Safety
    /// Same contract as `finish`, for the retained exclusively owned C function.
    pub async unsafe fn finish_c(
        &mut self,
        io: &mut impl Io,
        radio_started: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Stopping;
        let engine = if radio_started {
            super::radio_stop::engines(io)
        } else {
            Ok(())
        };
        let clock = super::radio_stop::clocks(io);
        let mut error = engine.err().or(clock.err());
        let mut a = Access(io);
        for address in [0x80u8, 0x81] {
            let result = a.masked_write(address, 0, 1).await;
            if error.is_none() {
                error = result.err();
            }
        }
        for address in [0x80u8, 0x81] {
            let result = a.transaction(address, None).await.and_then(|v| {
                if v & 1 == 0 {
                    Ok(())
                } else {
                    Err(Error::Access)
                }
            });
            if error.is_none() {
                error = result.err();
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        self.state = State::ShutdownAcknowledged;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_shutdown/tests.rs"]
mod tests;
