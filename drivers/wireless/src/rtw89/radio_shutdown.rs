// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained B asynchronous XTAL shutdown after immediate engine/clock closure.
//! Completion acknowledges the source RF00S/RF10S disable fields, not RF/DMA
//! idle, an old-DMA fence, reset readiness or permission to free memory.
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
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_shutdown/tests.rs"]
mod tests;
