// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2009 Atheros Communications Inc.
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
//! Shared immutable Atheros EEPROM regulatory identity from Linux ath/regd.c.
//! A country hint or CTL identifier alone never grants host transmit rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactoryError {
    Unsupported,
}
mod table;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    /// Linux's sanitized current_rd, retaining its roaming bit.
    pub eeprom: u16,
    pub country: u16,
    pub pair: u16,
    pub ctl_5ghz: u16,
    pub ctl_2ghz: u16,
    pub alpha2: [u8; 2],
}
impl Factory {
    pub fn from_eeprom(value: u32) -> Result<Self, FactoryError> {
        let raw = u16::try_from(value).map_err(|_| FactoryError::Unsupported)?;
        // Linux sanitizes exactly 0x8000 before stripping the roaming bit.
        let eeprom = if raw == 0x8000 { 0x64 } else { raw };
        let domain = eeprom & !0x4000;
        let explicit = if domain & 0x8000 != 0 {
            Some(
                table::COUNTRIES
                    .iter()
                    .find(|c| c.0 == domain & !0x8000)
                    .ok_or(FactoryError::Unsupported)?,
            )
        } else {
            if !table::PAIRS.iter().any(|p| p.0 == domain) {
                return Err(FactoryError::Unsupported);
            }
            None
        };
        let country = explicit.map_or(0, |c| c.0);
        let country = if country == 0 && domain == 0 {
            840
        } else {
            country
        };
        let selected = if country == 0 {
            None
        } else {
            Some(
                table::COUNTRIES
                    .iter()
                    .find(|c| c.0 == country)
                    .ok_or(FactoryError::Unsupported)?,
            )
        };
        let pair = selected.map_or(domain, |c| c.1);
        if pair == 0 {
            return Err(FactoryError::Unsupported);
        }
        let &(_, ctl_5ghz, ctl_2ghz) = table::PAIRS
            .iter()
            .find(|p| p.0 == pair)
            .ok_or(FactoryError::Unsupported)?;
        let alpha2 = selected
            .or_else(|| table::COUNTRIES.iter().find(|c| c.1 == pair))
            .map_or(*b"00", |c| c.2);
        Ok(Self {
            eeprom,
            country,
            pair,
            ctl_5ghz,
            ctl_2ghz,
            alpha2,
        })
    }
}
