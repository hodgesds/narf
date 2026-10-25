// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Firmware GET_FEATURE capabilities, distinct from factory EFUSE PHY data.
//! Linux mac.c::setup_phycap_part0 and fw.c register-message transport.
use super::power::Error;

/// Immutable receipt earned only by the serialized register mailbox. The
/// enclosing native retains it; it supplies no RF/calibration/TX authority.
#[derive(Debug)]
pub(super) struct Receipt {
    words: [u32; 4],
    tx_nss: u8,
    rx_nss: u8,
    tx_paths: u8,
    rx_paths: u8,
    tx_diversity: bool,
}
impl Receipt {
    pub(in crate::rtw89) fn decode(words: [u32; 4]) -> Result<Self, Error> {
        if words[0] & 0x7f != 3 || (words[0] >> 8) & 15 != 4 || words == [u32::MAX; 4] {
            return Err(Error::Access);
        }
        let tx = words[1] as u8;
        let rx = (words[0] >> 16) as u8;
        let tx_ant = (words[3] >> 8) as u8;
        let rx_ant = (words[3] >> 16) as u8;
        // Linux zero NSS means the actual B chip's two-stream default. Zero
        // antenna count preserves B's default RF-AB selection, not RF-B-only.
        let tx_nss = if tx == 0 { 2 } else { tx.min(2) };
        let rx_nss = if rx == 0 { 2 } else { rx.min(2) };
        let tx_diversity = tx == 1 && tx_ant == 2 && rx_ant == 2;
        Ok(Self {
            words,
            tx_nss,
            rx_nss,
            tx_paths: if tx_ant == 1 || tx_diversity { 2 } else { 3 },
            rx_paths: if rx_ant == 1 { 2 } else { 3 },
            tx_diversity,
        })
    }
    pub(super) fn words(&self) -> [u32; 4] {
        self.words
    }
    pub(super) fn tx_nss(&self) -> u8 {
        self.tx_nss
    }
    pub(super) fn rx_nss(&self) -> u8 {
        self.rx_nss
    }
    pub(super) fn tx_paths(&self) -> u8 {
        self.tx_paths
    }
    pub(super) fn rx_paths(&self) -> u8 {
        self.rx_paths
    }
    pub(super) fn tx_diversity(&self) -> bool {
        self.tx_diversity
    }
    /// Deliberately narrower than Linux's dynamic topology adaptation: this
    /// initial measured recipe calibrates both paths, transmits on A and
    /// receives on AB. Other firmware topologies require their own recipe.
    pub(super) fn initial_profile(&self) -> Result<(), Error> {
        if !matches!(self.words[1] as u8, 0 | 2)
            || !matches!((self.words[0] >> 16) as u8, 0 | 2)
            || !matches!((self.words[3] >> 8) as u8, 0 | 2)
            || !matches!((self.words[3] >> 16) as u8, 0 | 2)
            || self.tx_nss != 2
            || self.rx_nss != 2
            || self.tx_paths & 1 == 0
            || self.rx_paths != 3
            || self.tx_diversity
        {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B firmware GET_FEATURE part0 2T2R TXA RXAB v1");
        // Counter/ACK nibbles describe the transaction rather than RF facts.
        for (index, value) in self.words.iter().enumerate() {
            hash.update(&(if index == 0 { value & !0xf080 } else { *value }).to_le_bytes());
        }
        hash.update(&[
            self.tx_nss,
            self.rx_nss,
            self.tx_paths,
            self.rx_paths,
            u8::from(self.tx_diversity),
        ]);
        hash.finalize()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_phycap/tests.rs"]
mod tests;
