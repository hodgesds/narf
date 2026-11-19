// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-scoped station TXBUF upload through the retained original beacon
//! mapping. Firmware-only page0 upload remains a separate one-shot path.
use super::*;
use crate::rtw88::{runtime_ps_scope::Bound, station_control::Admission};

fn run<T>(
    source: &Bound,
    admission: &Admission,
    op: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    admission.run(|| source.invoke(op))
}
impl<R: Registers, M: Memory> Backend<R, M> {
    pub(super) async fn station_page(
        &mut self,
        data: &[u8],
        boundary: u16,
        source: &Bound,
        admission: &Admission,
    ) -> Result<(), Error> {
        // A real successful firmware->radio handoff disarmed this exact
        // original mapping. Neither a failed firmware transfer nor a merely
        // allocated/continued owner may mint a new station DMA submission.
        if self.state != PageState::Terminal || !self.disarmed || !self.completed {
            return Err(Error::State);
        }
        let expected = match source.did() {
            0xc821 => 460,
            0xc822 => 1938,
            _ => return Err(Error::Unsupported),
        };
        if boundary != expected || data.len() != 464 || data[..80].iter().any(|b| *b != 0) {
            return Err(Error::Image);
        }
        let gate = run(source, admission, || self.io.station_gate())?;
        if !source.matches(&gate) {
            return Err(Error::Access);
        }
        if !run(source, admission, || self.io.station_ps_rx_quiet())? {
            return Err(Error::State);
        }
        let ring = self.ring.as_mut().ok_or(Error::State)?;
        let frame = self.frame.as_mut().ok_or(Error::State)?;
        let ring_base = address(ring, 16, 256)?;
        let frame_base = address(frame, DESC + data.len(), 4)?;
        let beacon = run(source, admission, || self.io.read8(0x550))?;
        let work = run(source, admission, || self.io.read8(0x383))?;
        if beacon & 8 != 0
            || work & 0x10 != 0
            || run(source, admission, || self.io.read32(0x308))? != ring_base
            || run(source, admission, || self.io.read16(0x204))? & 0xfff != boundary
        {
            return Err(Error::Prerequisite);
        }
        // Poison before descriptor or MMIO changes. Cancellation/source loss
        // pins mappings; only the exact fresh BCN_VALID completes this attempt.
        self.disarmed = false;
        self.completed = false;
        self.published = true;
        run(source, admission, || {
            self.io.write16(0x204, boundary | 1 << 15)
        })?;
        if run(source, admission, || self.io.read16(0x204))? & 1 << 15 != 0 {
            return Err(Error::Prerequisite);
        }
        let cr = run(source, admission, || self.io.read8(0x101))?;
        let queue = run(source, admission, || self.io.read8(0x422))?;
        run(source, admission, || self.io.write8(0x101, cr | 1))?;
        run(source, admission, || {
            self.io.write8(0x550, beacon & !8 | 16)
        })?;
        run(source, admission, || self.io.write8(0x422, queue & !0x40))?;
        run(source, admission, || {
            frame.write(0, &[0; DESC])?;
            frame.write(DESC, data)?;
            // Source dummy/beacon download, CCK1, no protected RF payload.
            // Actual BCN_FUNC and BCNQ_DL are disabled before publication.
            Self::word(frame, 0, data.len() as u32 | 48 << 16 | 1 << 26 | 1 << 31)?;
            Self::word(frame, 4, 16 << 8 | 8 << 16)?;
            Self::word(frame, 12, 1 << 8 | 1 << 10)?;
            Self::word(frame, 32, 1 << 15)?;
            frame.sync();
            Self::word(ring, 0, 48)?;
            Self::word(ring, 4, frame_base)?;
            Self::word(ring, 8, data.len() as u32)?;
            Self::word(ring, 12, frame_base + 48)?;
            ring.sync();
            Ok(())
        })?;
        run(source, admission, || {
            Self::word(
                ring,
                0,
                48 | (((DESC + data.len()).div_ceil(128) as u32) | 0x8000) << 16,
            )?;
            ring.sync();
            Ok(())
        })?;
        // Reinvoke exact original source/UP/epoch/PCI after OWN, immediately
        // around the physical doorbell. No preceding bool authorizes this.
        run(source, admission, || {
            if self.io.read8(0x550)? & 8 != 0 || self.io.read8(0x422)? & 0x40 != 0 {
                return Err(Error::Prerequisite);
            }
            self.io.write8(0x383, work | 0x10)
        })?;
        let mut complete = false;
        for _ in 0..1000 {
            let actual = run(source, admission, || self.io.read32(0x204))?;
            if actual == u32::MAX {
                return Err(Error::Gone);
            }
            if actual & 1 << 15 != 0 {
                complete = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        if !complete {
            return Err(Error::Timeout);
        }
        run(source, admission, || {
            ring.acquire();
            frame.acquire();
            Ok(())
        })?;
        self.completed = true;
        run(source, admission, || self.io.write8(0x383, work))?;
        if run(source, admission, || self.io.read8(0x383))? & 0x10 != 0 {
            return Err(Error::Prerequisite);
        }
        run(source, admission, || {
            ring.write(0, &[0; 16])?;
            ring.sync();
            Ok(())
        })?;
        run(source, admission, || {
            self.io.write16(0x204, boundary | 1 << 15)
        })?;
        run(source, admission, || self.io.write8(0x550, beacon))?;
        run(source, admission, || self.io.write8(0x422, queue))?;
        run(source, admission, || self.io.write8(0x101, cr))?;
        if run(source, admission, || self.io.read8(0x550))? != beacon
            || run(source, admission, || self.io.read8(0x422))? != queue
            || run(source, admission, || self.io.read8(0x101))? != cr
        {
            return Err(Error::Prerequisite);
        }
        self.disarmed = true;
        Ok(())
    }
}
