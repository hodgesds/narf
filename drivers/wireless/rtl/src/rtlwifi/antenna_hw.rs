// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2009-2013 Realtek Corporation.
//! Actual source antenna MMIO, PHY-derived statistics and2s SMART training.
use super::*;
use alloc::vec::Vec;
const PERIOD_MS: u64 = 2000;
// Only these masks belong to the continuation. In particular antenna E08.16
// must never overwrite actual CCK TXAGC8..15, or A00.15 the HT40 primary bit4.
const FIELDS: &[(u16, u32)] = &[
    (0x4c, (1 << 23) | (1 << 25)),
    (0x870, 0x300),
    (0x864, 0x5ff),
    (0xb2c, (1 << 22) | (1 << 31)),
    (0xca4, u32::MAX),
    (0xa74, 1 << 7),
    (0xa0c, 1 << 4),
    (0x80c, 1 << 21),
    (0x914, 0xffff),
    (0x860, 0x7000),
    (0x6d8, 0xc0),
    (0xc50, 1 << 7),
    (0xa00, 1 << 15),
    (0x7b0, u32::MAX),
    (0x7b4, 0x3ffff),
    (0xe08, 1 << 16),
];
#[derive(Clone, Copy)]
enum Action {
    Hardware,
    Start,
    Finish,
    Unlink,
}
#[derive(Clone, Copy)]
pub(in crate::rtlwifi) struct Plan {
    action: Action,
    linked: bool,
    rx: u8,
    tx: u8,
    matched: bool,
    next: u64,
}
pub(in crate::rtlwifi) struct State {
    pub grant: Arc<Grant>,
    saved: Vec<(u16, u32, u32)>,
    expected: Vec<(u16, u32, u32)>,
    kind: u8,
    rx: u8,
    tx: u8,
    linked: bool,
    training: bool,
    next: u64,
    sum: [u64; 2],
    count: [u64; 2],
}
fn read(io: &impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Access(super::super::firmware_transport::Error::Gone))
    } else {
        Ok(value)
    }
}
fn write(io: &impl Io, reg: u16, mask: u32, value: u32) -> Result<(), Error> {
    if value & !mask != 0 {
        return Err(Error::State);
    }
    let prior = read(io, reg)?;
    io.write32(reg, (prior & !mask) | value)?;
    if read(io, reg)? & mask != value {
        return Err(Error::Readback);
    }
    Ok(())
}
impl State {
    pub(in crate::rtlwifi) fn initialize(io: &impl Io, grant: Arc<Grant>) -> Result<Self, Error> {
        let kind = grant.kind();
        let mut saved = Vec::new();
        saved
            .try_reserve_exact(FIELDS.len())
            .map_err(|_| Error::Memory)?;
        for &(reg, mask) in FIELDS {
            saved.push((reg, mask, read(io, reg)? & mask));
        }
        let mut state = Self {
            grant,
            expected: saved.clone(),
            saved,
            kind,
            rx: if kind == 1 { 1 } else { 0 },
            tx: 0,
            linked: false,
            training: false,
            next: 0,
            sum: [0; 2],
            count: [0; 2],
        };
        state.set(io, 0x4c, (1 << 23) | (1 << 25), (1 << 23) | (1 << 25))?;
        state.set(io, 0x870, 0x300, 0)?;
        state.set(io, 0x864, 1 << 10, 0)?;
        state.set(io, 0xb2c, 1 << 22, if kind == 2 { 1 << 22 } else { 0 })?;
        state.set(io, 0xb2c, 1 << 31, 1 << 31)?;
        state.set(io, 0xca4, u32::MAX, 0xa0)?;
        state.set(io, 0xa74, 1 << 7, 1 << 7)?;
        state.set(io, 0xa0c, 1 << 4, 1 << 4)?;
        state.set(io, 0x914, 0xffff, 0x0201)?;
        state.set(io, 0xc50, 1 << 7, 0)?;
        state.set(io, 0xa00, 1 << 15, 0)?;
        state.set(io, 0xe08, 1 << 16, 0)?;
        if kind == 4 {
            state.set(io, 0x7b4, 0x3ffff, 0x30000)?;
            state.set(io, 0x7b0, u32::MAX, 0)?;
            state.set(io, 0x80c, 1 << 21, 1 << 21)?;
            state.set(io, 0x864, 0x1ff, 1 | (1 << 6))?; // actual ant_combination2; default0,optional1.
        } else {
            if kind == 1 {
                state.set(io, 0x80c, 1 << 21, 0)?;
            }
            state.idle(io, state.rx)?;
        }
        state.readback(io)?;
        Ok(state)
    }
    fn set(&mut self, io: &impl Io, reg: u16, mask: u32, value: u32) -> Result<(), Error> {
        let entry = self
            .expected
            .iter_mut()
            .find(|(r, m, _)| *r == reg && mask & !*m == 0)
            .ok_or(Error::State)?;
        write(io, reg, mask, value)?;
        entry.2 = (entry.2 & !mask) | value;
        Ok(())
    }
    fn idle(&mut self, io: &impl Io, rx: u8) -> Result<(), Error> {
        if rx > 1 {
            return Err(Error::State);
        }
        // Explicit hardware selector codes from factory type. Linux's prior
        // logical rx_idle_ant == CG_TRX_HW_ANTDIV alias is deliberately absent.
        self.set(
            io,
            0x864,
            0x1f8,
            (u32::from(rx) << 3) | (u32::from(rx ^ 1) << 6),
        )?;
        if self.kind == 1 {
            self.set(io, 0x860, 0x7000, u32::from(rx) << 12)?;
            self.set(io, 0x6d8, 0xc0, u32::from(rx) << 6)?;
        }
        Ok(())
    }
    pub(in crate::rtlwifi) fn readback(&self, io: &impl Io) -> Result<(), Error> {
        for &(reg, mask, value) in &self.expected {
            if read(io, reg)? & mask != value {
                return Err(Error::Readback);
            }
        }
        Ok(())
    }
    pub(in crate::rtlwifi) fn descriptor(&self) -> Option<u8> {
        if self.kind == 2 {
            None
        } else {
            Some(self.tx)
        }
    }
    pub(in crate::rtlwifi) fn sample(
        &mut self,
        bytes: &[u8],
        own: [u8; 6],
        peer: [u8; 6],
        mux: u8,
        pwdb: u8,
    ) {
        if !self.linked
            || mux > 1
            || pwdb > 100
            || !super::super::rate_adaptive::matches_bssid(bytes, peer)
        {
            return;
        }
        if self.kind == 4 && (!self.training || bytes.get(4..10) != Some(own.as_slice())) {
            return;
        }
        self.sum[usize::from(mux)] = self.sum[usize::from(mux)].saturating_add(u64::from(pwdb));
        self.count[usize::from(mux)] = self.count[usize::from(mux)].saturating_add(1);
    }
    pub(in crate::rtlwifi) fn plan(&self, now: u64, linked: bool) -> Result<Option<Plan>, Error> {
        if !linked {
            return if self.linked {
                Ok(Some(Plan {
                    action: Action::Unlink,
                    linked: false,
                    rx: self.rx,
                    tx: self.tx,
                    matched: false,
                    next: now.checked_add(PERIOD_MS).ok_or(Error::State)?,
                }))
            } else {
                Ok(None)
            };
        }
        if self.linked && now < self.next {
            return Ok(None);
        }
        let next = now.checked_add(PERIOD_MS).ok_or(Error::State)?;
        if self.kind == 4 && !self.training {
            return Ok(Some(Plan {
                action: Action::Start,
                linked: true,
                rx: self.rx,
                tx: self.tx,
                matched: false,
                next,
            }));
        }
        let avg = core::array::from_fn::<u64, 2, _>(|i| {
            if self.count[i] == 0 {
                0
            } else {
                self.sum[i] / self.count[i]
            }
        });
        let target = if avg[0] == avg[1] {
            self.rx
        } else {
            u8::from(avg[1] > avg[0])
        };
        Ok(Some(Plan {
            action: if self.kind == 4 {
                Action::Finish
            } else {
                Action::Hardware
            },
            linked: true,
            rx: target,
            tx: if self.kind == 2 { self.tx } else { target },
            matched: self.count.iter().any(|c| *c != 0),
            next,
        }))
    }
    pub(in crate::rtlwifi) fn apply(
        &mut self,
        io: &impl Io,
        plan: Plan,
        own: [u8; 6],
    ) -> Result<(), Error> {
        match plan.action {
            Action::Unlink => {
                self.set(io, 0xc50, 1 << 7, 0)?;
                self.set(io, 0xa00, 1 << 15, 0)?;
                if self.kind == 1 {
                    self.set(io, 0x80c, 1 << 21, 0)?;
                }
                self.set(io, 0xe08, 1 << 16, 0)?;
                self.training = false;
            }
            Action::Hardware => {
                self.set(io, 0xc50, 1 << 7, 1 << 7)?;
                self.set(io, 0xa00, 1 << 15, 1 << 15)?;
                if self.kind == 1 {
                    self.set(io, 0x80c, 1 << 21, 1 << 21)?;
                }
                self.idle(io, plan.rx)?;
            }
            Action::Start => {
                self.set(
                    io,
                    0x7b0,
                    u32::MAX,
                    u32::from_le_bytes(own[..4].try_into().unwrap()),
                )?;
                self.set(
                    io,
                    0x7b4,
                    0x3ffff,
                    0x30000 | u32::from(u16::from_le_bytes(own[4..].try_into().unwrap())),
                )?;
                self.set(io, 0xa00, 1 << 15, 1 << 15)?;
                self.set(io, 0xe08, 1 << 16, 1 << 16)?;
                self.set(io, 0xc50, 1 << 7, 1 << 7)?;
                self.training = true;
            }
            Action::Finish => {
                self.set(io, 0xe08, 1 << 16, 0)?;
                if plan.matched {
                    self.set(io, 0x864, 0x1c0, u32::from(plan.rx) << 6)?;
                    self.set(io, 0x80c, 1 << 21, 1 << 21)?;
                    self.set(io, 0xc50, 1 << 7, if plan.tx == 0 { 0 } else { 1 << 7 })?;
                } else {
                    self.set(io, 0xc50, 1 << 7, 0)?;
                }
                self.training = false;
            }
        }
        self.readback(io)?;
        if !matches!(plan.action, Action::Finish) || plan.matched {
            self.rx = plan.rx;
            self.tx = plan.tx;
        }
        self.linked = plan.linked;
        self.next = plan.next;
        self.sum = [0; 2];
        self.count = [0; 2];
        Ok(())
    }
    pub(in crate::rtlwifi) fn restore(&self, io: &impl Io) -> Result<(), Error> {
        // First withdraw autonomous switching/training, then restore the
        // exact preceding masked program. No raw-gain/width field is replaced.
        write(io, 0xc50, 1 << 7, 0)?;
        write(io, 0xa00, 1 << 15, 0)?;
        write(io, 0xe08, 1 << 16, 0)?;
        for &(reg, mask, value) in &self.saved {
            write(io, reg, mask, value)?;
        }
        for &(reg, mask, value) in &self.saved {
            if read(io, reg)? & mask != value {
                return Err(Error::Readback);
            }
        }
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture_state(&self) -> (u8, u8, bool, [u64; 2]) {
        (self.rx, self.tx, self.training, self.count)
    }
}
impl State {
    pub(in crate::rtlwifi) fn restored_readback(&self, io: &impl Io) -> Result<(), Error> {
        for &(reg, mask, value) in &self.saved {
            if read(io, reg)? & mask != value {
                return Err(Error::Readback);
            }
        }
        Ok(())
    }
}
