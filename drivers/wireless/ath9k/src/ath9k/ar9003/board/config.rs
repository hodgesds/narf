// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux `pci.c::ath_pci_id_table` CUS198/CUS230 and
//! `init.c::ath9k_init_pcoem_platform`. Inputs are the current PCI identity,
//! never a guessed platform/GPIO property. The admitted AR9485 preparation
//! models CONFIG_ATH9K_PCOEM, including exact AR9565 WB335 combining
//! suppression. Manual BT antenna sharing remains disabled.
use super::super::Chip;
use crate::ath9k::identity::BringUpError;
#[cfg(feature = "module")]
use crate::ath9k::platform::compat::narf_bus;
use narf_bus::DeviceId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Config {
    pub(super) xlna_gpio: u8,
    pub(super) xatten_margin: bool,
    pub(super) alt_mingainidx: bool,
    suppress_9565_combining: bool,
    // This source platform value is retained in the preparation identity.
    // It is not applied while the separate manual BT-sharing gate is closed.
    ant_ctrl_comm2g_switch_enable: u32,
}

impl Config {
    pub(in crate::ath9k) fn for_pci(id: &DeviceId) -> Self {
        let pcoem = id.vendor == 0x168c
            && id.device == 0x0032
            && matches!(
                (id.subsystem_vendor, id.subsystem_id),
                (0x1a3b, 0x2086 | 0x1237 | 0x2126 | 0x126a | 0x2152) | (0x105b, 0xe075)
            );
        if id.vendor == 0x168c && id.device == 0x0036 {
            // pci.c WB335 1-ANT rows without ATH9K_PCI_BT_ANT_DIV.
            // The generic 0036 row has BT_ANT_DIV, so only these exact
            // source exceptions suppress the hardcoded 0xc9 capability.
            return Self {
                suppress_9565_combining: matches!(
                    (id.subsystem_vendor, id.subsystem_id),
                    (0x105b, 0xe068)
                        | (0x185f, 0xa119)
                        | (0x11ad, 0x0632 | 0x06b2 | 0x0842 | 0x1842 | 0x6671)
                        | (0x1b9a, 0x2811 | 0x2812 | 0x28a1 | 0x28a3)
                        | (0x1a3b, 0x218a | 0x2f8a)
                ),
                ..Self::default()
            };
        }
        if pcoem {
            Self {
                xlna_gpio: 9,
                xatten_margin: true,
                alt_mingainidx: true,
                suppress_9565_combining: false,
                ant_ctrl_comm2g_switch_enable: 0x000b_bb88,
            }
        } else {
            Self::default()
        }
    }

    pub(in crate::ath9k) fn check_chip(self, chip: Chip) -> Result<(), BringUpError> {
        let ordinary = Self {
            suppress_9565_combining: false,
            ..self
        };
        if chip != Chip::Ar9485 && ordinary != Self::default()
            || self.suppress_9565_combining && chip != Chip::Ar9565
        {
            return Err(BringUpError::BadIdentity);
        }
        Ok(())
    }
    pub(in crate::ath9k) fn suppress_9565_combining(self) -> bool {
        self.suppress_9565_combining
    }
    pub(in crate::ath9k) fn manual_switch(self) -> u32 {
        self.ant_ctrl_comm2g_switch_enable
    }

    /// Canonical source inputs, including the currently inactive BT switch
    /// mask. No C layout padding or mutable platform data enters N48A.
    pub(in crate::ath9k) fn identity_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0] = self.xlna_gpio;
        bytes[1] = u8::from(self.xatten_margin);
        bytes[2] = u8::from(self.alt_mingainidx);
        bytes[3] = u8::from(self.suppress_9565_combining);
        bytes[4..].copy_from_slice(&self.ant_ctrl_comm2g_switch_enable.to_le_bytes());
        bytes
    }
}
