// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! `mci.c::ath9k_mci_{update_rssi,set_txpower}` and
//! `ar9003_eeprom.c::ar9003_hw_set_power_per_rate_table` at the Linux
//! revision in `btcoex.rs`. This is a legacy20 owner: HT20 power-table
//! slots are capped, but no HT packet format or HT40 program is admitted.
use crate::ath9k::{
    admission::Grant,
    ar9003::{power, Chip},
    identity::RegisterIo,
    packet::Error,
};

/// Part of the N46A/N65A identity, requiring a freshly qualified record.
/// The existing measured ceiling must cover both programs and transitions.
pub(in crate::ath9k) const RECIPE: &[u8] = b"MCI native concurrentTX legacy20 v1: actual associated beacon Linux RSSI LPF/marker127, five consecutive period samples >=40 on/<40 off with sign reset and timer history retained; 2G only config CONCUR_TX bits0..1; full original calibrated factory/CTL/host/signed ceiling power plan and min(HT20 targets8..22,20half-dBm) plan; legacy targets0..8 and zero HT40 slots unchanged, no HT promotion; Grant CapOp encloses each current PCI read/write plus entire checked power transition, original current policy/RFkill and physical plan admission first, actual RTC ON2 required; write/readback before concurrent flag or new priorities, failed mutation terminal until fully qualified reset, saved original plan restored on disable/reset; complete measured antenna/BT/temperature/supply/posture static and transition envelope includes concurrent state and automatic legacy responses; no invented calibration, no NETWORK_SLEEP or FTP authority";

#[derive(Default)]
pub(super) struct Rssi {
    count: i8,
}
impl Rssi {
    /// Linux resets the opposite sign before counting this period. A fifth
    /// period requests the state even if it is already installed.
    pub(super) fn period(&mut self, rssi: u8) -> Option<bool> {
        if rssi >= 40 {
            self.count = self.count.max(0) + 1;
            if self.count == 5 {
                self.count = 0;
                return Some(true);
            }
        } else {
            self.count = self.count.min(0) - 1;
            if self.count == -5 {
                self.count = 0;
                return Some(false);
            }
        }
        None
    }
}

/// Linux applies `ar9003_mci_get_max_txpower(CTL_2GHT20)` after CTL and
/// scaled-power limiting. The fourteen HT20 entries have source indices
/// 8..22. The HT40 entries stay zero in this exact legacy/20 MHz program.
pub(in crate::ath9k) fn plan(base: &power::Plan, enabled: bool) -> power::Plan {
    let mut result = *base;
    if enabled && base.frequency < 4000 {
        for value in &mut result.targets[8..22] {
            *value = (*value).min(0x14);
        }
        result.max_power_level = result.targets.iter().copied().max().unwrap_or(0);
    }
    result
}

/// This deliberately bypasses the ordinary fixed-power readback during a
/// transition. Implementations must check the retained PCI capability and
/// original current transport/policy on *every* access. Only this module's
/// record-qualified adapter can hand it to the power programmer.
pub(in crate::ath9k) trait Raw {
    fn read(&self, register: u64) -> Result<u32, Error>;
    fn write(&self, register: u64, value: u32) -> Result<(), Error>;
}

fn under<T>(grant: &Grant, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    grant
        .invoke(|| Ok(operation()))
        .map_err(|_| Error::Access)?
}

struct Qualified<'a, P> {
    raw: &'a P,
    grant: &'a Grant,
    error: Option<Error>,
}
impl<P: Raw> RegisterIo for Qualified<'_, P> {
    fn authorized(&self) -> bool {
        self.error.is_none() && under(self.grant, || Ok(())).is_ok()
    }
    fn read32(&mut self, register: u64) -> u32 {
        if self.error.is_some() {
            return u32::MAX;
        }
        under(self.grant, || self.raw.read(register)).unwrap_or_else(|error| {
            self.error = Some(error);
            u32::MAX
        })
    }
    fn write32(&mut self, register: u64, value: u32) {
        if self.error.is_some() {
            return;
        }
        let result = under(self.grant, || {
            self.raw.write(register, value)?;
            // A second real invocation prevents a revoked source or ignored
            // posted write from becoming a completed power transition.
            under(self.grant, || {
                if self.raw.read(register)? == value {
                    Ok(())
                } else {
                    Err(Error::Descriptor)
                }
            })
        });
        if let Err(error) = result {
            self.error = Some(error);
        }
    }
}

fn check(io: &mut impl RegisterIo, chip: Chip, plan: &power::Plan) -> Result<(), Error> {
    if io.read32(0x7044) & 15 != 2 {
        return Err(Error::State);
    }
    for (register, value) in power::rate_words(&plan.targets) {
        if io.read32(register) != value {
            return Err(Error::Descriptor);
        }
    }
    let ack = u32::from(if plan.frequency < 4000 {
        plan.targets[4]
    } else {
        plan.targets[0]
    }) & 0x3f;
    if io.read32(0xa458) != 0
        || io.read32(0xa3f0) != 0
        || io.read32(0x80e8) != ack | (ack << 8) | 0x3f3f_0000
        || io.read32(0xa440) & 0xff != plan.temp_slope as u32 & 0xff
        || io.read32(0xa43c) & 0xff != plan.temperature[0] as u32 & 0xff
        || chip == Chip::Ar9462 && io.read32(0xb440) & 0xff != plan.temp_slope as u32 & 0xff
    {
        return Err(Error::Descriptor);
    }
    for (chain, (gain, error)) in [(0xa420, 0xa40c), (0xb420, 0xb40c), (0xc420, 0xc40c)]
        .into_iter()
        .enumerate()
    {
        if (chain == 0 || plan.tx_chainmask & (1 << chain) != 0)
            && (io.read32(gain) & 0x00ff_0000
                != (plan.correction[chain] << 16) as u32 & 0x00ff_0000
                || io.read32(error) & 0x0300_0000 != 0x0300_0000)
        {
            return Err(Error::Descriptor);
        }
    }
    if !io.authorized() {
        return Err(Error::Access);
    }
    Ok(())
}

/// Mutable expected physical program of one calibrated native generation.
/// The station serializes it with DMA, calibration, reset and suspend.
pub(in crate::ath9k) struct Power {
    chip: Chip,
    identity: [u8; 32],
    base: power::Plan,
    enabled: bool,
    uncertain: bool,
}
impl Power {
    pub(in crate::ath9k) fn new(device: u16, grant: &Grant, base: power::Plan) -> Option<Self> {
        let chip = match device {
            0x0034 => Chip::Ar9462,
            0x0036 => Chip::Ar9565,
            _ => return None,
        };
        let request = grant.request();
        if request.device != device || request.frequency_mhz != base.frequency {
            return None;
        }
        Some(Self {
            chip,
            identity: request.identity,
            base,
            enabled: false,
            uncertain: false,
        })
    }
    fn bound(&self, grant: &Grant) -> bool {
        let request = grant.request();
        request.identity == self.identity
            && request.frequency_mhz == self.base.frequency
            && request.device
                == if self.chip == Chip::Ar9462 {
                    0x0034
                } else {
                    0x0036
                }
    }
    pub(in crate::ath9k) fn words(&self) -> Result<[(u64, u32); 12], Error> {
        if self.uncertain {
            return Err(Error::Access);
        }
        Ok(power::rate_words(&plan(&self.base, self.enabled).targets))
    }
    /// Ordinary I/O has already re-proved the original physical/policy
    /// fences. Every raw access below adds the actual record+PCI boundary.
    pub(in crate::ath9k) fn transition(
        &mut self,
        raw: &impl Raw,
        grant: &Grant,
        enabled: bool,
    ) -> Result<(), Error> {
        if self.base.frequency >= 4000 || self.uncertain || !self.bound(grant) {
            return Err(Error::Access);
        }
        under(grant, || {
            let mut io = Qualified {
                raw,
                grant,
                error: None,
            };
            check(&mut io, self.chip, &plan(&self.base, self.enabled))?;
            if let Some(error) = io.error {
                return Err(error);
            }
            if self.enabled == enabled {
                return Ok(());
            }
            let target = plan(&self.base, enabled);
            // Set before the first potentially posted write. Failed readback
            // keeps the original history and rejects all later ordinary I/O.
            self.uncertain = true;
            let programmed = power::program(&mut io, self.chip, &target);
            let checked = check(&mut io, self.chip, &target);
            if let Some(error) = io.error {
                return Err(error);
            }
            programmed.map_err(|_| Error::Descriptor)?;
            checked?;
            self.enabled = enabled;
            self.uncertain = false;
            Ok(())
        })
    }
    /// Called only after the actual same-channel reset/calibration with
    /// DMA parked. It cannot clear uncertainty by changing a software flag.
    pub(in crate::ath9k) fn reset(
        &mut self,
        raw: &impl Raw,
        grant: &Grant,
        base: &power::Plan,
    ) -> Result<(), Error> {
        if *base != self.base || !self.bound(grant) {
            return Err(Error::State);
        }
        under(grant, || {
            let mut io = Qualified {
                raw,
                grant,
                error: None,
            };
            let result = check(&mut io, self.chip, base);
            if let Some(error) = io.error {
                return Err(error);
            }
            result?;
            self.enabled = false;
            self.uncertain = false;
            Ok(())
        })
    }
}

#[cfg(feature = "kernel-test")]
pub(in crate::ath9k) mod tests;
