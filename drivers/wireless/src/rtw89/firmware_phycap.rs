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
    /// Earned through the RTL8852C V1 register block (0x7140..0x7164).
    c: bool,
    /// Decoded for RTL8852A (`chip->tx_nss`/`rx_nss` 2, `rf_path_num` 2)
    /// through the B 0x8140 register block (`rtw8852a_h2c_regs` is
    /// `R_AX_H2CREG_DATA0`, the B block).
    a: bool,
    /// Decoded for RTL8851B (`chip->tx_nss`/`rx_nss` 1, `rf_path_num` 1)
    /// through the B 0x8140 register block.
    n51: bool,
}
impl Receipt {
    pub(in crate::rtw89) fn decode(words: [u32; 4]) -> Result<Self, Error> {
        Self::decode_for(false, words)
    }
    /// mac.c `rtw89_mac_setup_phycap_part0` is chip-independent for AX; the
    /// RTL8852C `chip->tx_nss`/`rx_nss` (2) and `rf_path_num` (2) equal B's,
    /// so the decode is shared. `c` only binds the receipt to the V1 block.
    pub(in crate::rtw89) fn decode_for(c: bool, words: [u32; 4]) -> Result<Self, Error> {
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
            c,
            a: false,
            n51: false,
        })
    }
    /// mac.c `rtw89_mac_setup_phycap_part0` for RTL8852A (rtw8852a.c
    /// `tx_nss`/`rx_nss` 2, `rf_path_num` 2): the same AX part0 decode as
    /// B, marked A so only the A register block binds it.
    pub(in crate::rtw89) fn decode_a(words: [u32; 4]) -> Result<Self, Error> {
        let mut receipt = Self::decode_for(false, words)?;
        receipt.a = true;
        Ok(receipt)
    }
    /// mac.c `rtw89_mac_setup_phycap_part0` for RTL8851B (rtw8851b.c
    /// `tx_nss`/`rx_nss` 1, `rf_path_num` 1): NSS is clamped to 1 (zero
    /// means the chip default 1), and the one-path branch forces
    /// `antenna_tx`/`antenna_rx` to RF_A regardless of the antenna counts.
    /// Linux still records `tx_path_diversity` for `tx_nss == 1 && tx_ant ==
    /// 2 && rx_ant == 2`; that is kept here and refused by
    /// [`Self::initial_profile_51`]. The fuse antenna-diversity bit
    /// (`rfe_type % 3 == 2`) is a factory fact, not part of this receipt.
    pub(in crate::rtw89) fn decode_51(words: [u32; 4]) -> Result<Self, Error> {
        if words[0] & 0x7f != 3 || (words[0] >> 8) & 15 != 4 || words == [u32::MAX; 4] {
            return Err(Error::Access);
        }
        let tx = words[1] as u8;
        let tx_ant = (words[3] >> 8) as u8;
        let rx_ant = (words[3] >> 16) as u8;
        Ok(Self {
            words,
            tx_nss: 1,
            rx_nss: 1,
            tx_paths: 1,
            rx_paths: 1,
            tx_diversity: tx == 1 && tx_ant == 2 && rx_ant == 2,
            c: false,
            a: false,
            n51: true,
        })
    }
    pub(super) fn is_a(&self) -> bool {
        self.a
    }
    pub(super) fn is_c(&self) -> bool {
        self.c
    }
    pub(super) fn is_51(&self) -> bool {
        self.n51
    }
    /// The RTL8851B initial recipe: an RTL8851B receipt, 1T1R on RF_A, no
    /// TX path diversity (meaningless on one path; refused).
    pub(super) fn initial_profile_51(&self) -> Result<(), Error> {
        if !self.n51
            || self.tx_nss != 1
            || self.rx_nss != 1
            || self.tx_paths != 1
            || self.rx_paths != 1
            || self.tx_diversity
        {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
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
        if self.n51 {
            return Err(Error::Unsupported);
        }
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
        hash.update(if self.n51 {
            &b"NARF RTL8851B firmware GET_FEATURE part0 1T1R TXA RXA v1"[..]
        } else if self.c {
            b"NARF RTL8852C firmware GET_FEATURE part0 2T2R TXA RXAB v1"
        } else if self.a {
            b"NARF RTL8852A firmware GET_FEATURE part0 2T2R TXA RXAB v1"
        } else {
            b"NARF RTL8852B firmware GET_FEATURE part0 2T2R TXA RXAB v1"
        });
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
