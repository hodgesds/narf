// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked native BE GET_FEATURE register mailbox, separate from AX receipts.
//! Primary source: mac.c::read_phycap/setup_phycap_part{0,1}, fw.c::msg_reg,
//! fw_feat_tbl, rtw8922a.c h2c/c2h_regs/counter_reg and efuse_be.c cnv_state.
use super::{cold_8922a::Regs, power, rfk::be_features::Features};

pub(super) trait Interface: Regs {
    /// Original completed FW/System/closed-TRX and CH12-only DMA owner.
    fn active(&mut self) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Pending,
    Complete,
}
#[derive(Default)]
pub(super) struct Mailbox {
    state: State,
    h2c: u8,
    c2h: u8,
}
/// Actual complete firmware replies, source-declared chip defaults and part1
/// feature selection. No RF, channel or station authority follows from this.
pub(super) struct Receipt {
    part0: [u32; 4],
    part1: Option<[u32; 4]>,
    version: [u8; 4],
    device: u16,
    tx_nss: u8,
    rx_nss: u8,
    tx_paths: u8,
    rx_paths: u8,
    tx_diversity: bool,
    no_eht: bool,
    no_mcs_12_13: bool,
}
impl Receipt {
    pub(super) fn matches_source(&self, features: Features, device: u16) -> bool {
        self.version == features.version() && self.device == device
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture(
        features: Features,
        device: u16,
        p0: [u32; 4],
        p1: Option<[u32; 4]>,
    ) -> Self {
        Self::decode(p0, p1, features, device).expect("literal BE GET_FEATURE fixture")
    }
    fn decode(
        p0: [u32; 4],
        p1: Option<[u32; 4]>,
        features: Features,
        device: u16,
    ) -> Result<Self, power::Error> {
        if p0[0] & 0x7f != 3
            || (p0[0] >> 8) & 15 != 4
            || !features.supports_device(device)
            || features.phycap_part1() != p1.is_some()
            || p1.is_some_and(|v| v[0] & 0x7f != 12 || (v[0] >> 8) & 15 != 4)
        {
            return Err(power::Error::Access);
        }
        let tx = p0[1] as u8;
        let rx = (p0[0] >> 16) as u8;
        let tx_ant = (p0[3] >> 8) as u8;
        let rx_ant = (p0[3] >> 16) as u8;
        let diversity = tx == 1 && tx_ant == 2 && rx_ant == 2;
        // Source zero NSS/antenna counts preserve RTL8922A's2T2R/RF_AB
        // chip defaults. They do not select a guessed physical board path.
        let qam = p1.map(|words| words[2] as u8);
        Ok(Self {
            part0: p0,
            part1: p1,
            version: features.version(),
            device,
            tx_nss: if tx == 0 { 2 } else { tx.min(2) },
            rx_nss: if rx == 0 { 2 } else { rx.min(2) },
            tx_paths: if tx_ant == 1 || diversity { 2 } else { 3 },
            rx_paths: if rx_ant == 1 { 2 } else { 3 },
            tx_diversity: diversity,
            no_eht: ((p0[1] >> 8) & 255) < 4,
            // setup_phycap_part1 maps an unknown QAM to the chip's4096QAM
            // default. Actual892b is the source VS variant and always limits
            // MCS12/13; its minimum firmware version guarantees part1 exists.
            no_mcs_12_13: device == 0x892b || matches!(qam, Some(1 | 2)),
        })
    }
    pub(super) fn words(&self) -> ([u32; 4], Option<[u32; 4]>) {
        (self.part0, self.part1)
    }
    pub(super) fn topology(&self) -> (u8, u8, u8, u8, bool) {
        (
            self.tx_nss,
            self.rx_nss,
            self.tx_paths,
            self.rx_paths,
            self.tx_diversity,
        )
    }
    pub(super) fn no_eht(&self) -> bool {
        self.no_eht
    }
    pub(super) fn no_mcs_12_13(&self) -> bool {
        self.no_mcs_12_13
    }
    pub(super) fn bind(&self, hash: &mut narf_crypto::sha256::Sha256) {
        hash.update(b"RTL8922A actual firmware GET_FEATURE part0/part1 v1\0");
        hash.update(&self.version);
        hash.update(&self.device.to_le_bytes());
        for words in core::iter::once(&self.part0).chain(self.part1.iter()) {
            for (i, word) in words.iter().enumerate() {
                // ACK/sequence are transaction fields; function/length and
                // every actual capability bit remain in the bound receipt.
                hash.update(&(if i == 0 { word & !0xf080 } else { *word }).to_le_bytes());
            }
        }
        hash.update(&[
            u8::from(self.part1.is_some()),
            self.tx_nss,
            self.rx_nss,
            self.tx_paths,
            self.rx_paths,
            u8::from(self.tx_diversity),
            u8::from(self.no_eht),
            u8::from(self.no_mcs_12_13),
        ]);
    }
}
impl Mailbox {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn query(
        &mut self,
        io: &mut impl Interface,
        features: Features,
        device: u16,
    ) -> Result<Receipt, power::Error> {
        if self.state != State::New {
            return Err(power::Error::Terminal);
        }
        if !features.supports_device(device) {
            return Err(power::Error::Unsupported);
        }
        self.state = State::Pending;
        io.active()?;
        let p0 = self.part(io, 0)?;
        let p1 = if features.phycap_part1() {
            Some(self.part(io, 1)?)
        } else {
            None
        };
        let receipt = Receipt::decode(p0, p1, features, device)?;
        io.active()?;
        self.state = State::Complete;
        Ok(receipt)
    }
    fn part(&mut self, io: &mut impl Interface, part: u8) -> Result<[u32; 4], power::Error> {
        convert(io, false)?;
        // Refuse an inherited/stale reply before any command effect. The
        // source has no sequence echo for GET_FEATURE; an empty exclusive
        // mailbox plus new trigger/consumption binds this one-shot operation.
        if byte(io, 0x7164)? != 0 {
            return Err(power::Error::Access);
        }
        poll(io, 0x7160, 0, 5000)?;
        if byte(io, 0x7164)? != 0 {
            return Err(power::Error::Access);
        }
        for (index, word) in [0x103 | (u32::from(part) << 16), 0, 0, 0]
            .into_iter()
            .enumerate()
        {
            let address = 0x7140 + index as u32 * 4;
            put(io, address, word)?;
            // Native safety readback before the source trigger: an ignored
            // DATA write cannot turn a previous part/body into this request.
            if word32(io, address)? != word {
                return Err(power::Error::Access);
            }
        }
        self.h2c = self.h2c.wrapping_add(1);
        counter(io, 0x0f, self.h2c)?;
        if byte(io, 0x7164)? != 0 {
            return Err(power::Error::Access);
        }
        put8(io, 0x7160, 1)?;
        poll(io, 0x7164, 1, 1_000_000)?;
        let mut words = [0; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = word32(io, 0x7150 + index as u32 * 4)?;
        }
        put8(io, 0x7164, 0)?;
        self.c2h = self.c2h.wrapping_add(1);
        counter(io, 0xf0, self.c2h)?;
        if byte(io, 0x7164)? != 0 || byte(io, 0x7160)? != 0 {
            return Err(power::Error::Access);
        }
        if words[0] & 0x7f != if part == 0 { 3 } else { 12 } || (words[0] >> 8) & 15 != 4 {
            return Err(power::Error::Access);
        }
        convert(io, true)?;
        Ok(words)
    }
}
fn byte(io: &mut impl Interface, a: u32) -> Result<u8, power::Error> {
    io.active()?;
    let value = io.read8(a)?;
    // The counter byte can legitimately contain15/15. Its current native
    // active/common-gate checks remain required; trigger all-ones is Gone.
    if value == 255 && a != 0x1f5 {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn word32(io: &mut impl Interface, a: u32) -> Result<u32, power::Error> {
    io.active()?;
    let value = io.read32(a)?;
    if value == u32::MAX {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn put(io: &mut impl Interface, a: u32, v: u32) -> Result<(), power::Error> {
    io.active()?;
    io.write32(a, v)
}
fn put8(io: &mut impl Interface, a: u32, v: u8) -> Result<(), power::Error> {
    io.active()?;
    io.write8(a, v)
}
fn counter(io: &mut impl Interface, mask: u8, count: u8) -> Result<(), power::Error> {
    let old = byte(io, 0x1f5)?;
    let value = (old & !mask) | ((count << mask.trailing_zeros()) & mask);
    put8(io, 0x1f5, value)?;
    if byte(io, 0x1f5)? & mask != value & mask {
        return Err(power::Error::Access);
    }
    Ok(())
}
fn poll(io: &mut impl Interface, a: u32, value: u8, us: u64) -> Result<(), power::Error> {
    let mut error = None;
    let done = narf_scheduler::responsive_spin_until(
        || match byte(io, a) {
            Ok(v) => v == value,
            Err(e) => {
                error = Some(e);
                true
            }
        },
        narf_time::Deadline::after_us(us),
    );
    if let Some(e) = error {
        Err(e)
    } else if done {
        Ok(())
    } else {
        Err(power::Error::Timeout)
    }
}
fn convert(io: &mut impl Interface, idle: bool) -> Result<(), power::Error> {
    let original = word32(io, 0x68)?;
    put(
        io,
        0x68,
        if idle {
            original | 0x10000
        } else {
            original & !0x10000
        },
    )?;
    if !idle {
        let mut error = None;
        // cnv_efuse_state_be warns/continues on a responsive power-state
        // timeout. An actual failed access is terminal and forbids cleanup.
        let _ = narf_scheduler::responsive_spin_until(
            || match word32(io, 0x3f0) {
                Ok(v) => v & 0x03ff0000 == 0x02200000,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(5000),
        );
        if let Some(error) = error {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_mailbox_tests.rs"]
mod tests;
