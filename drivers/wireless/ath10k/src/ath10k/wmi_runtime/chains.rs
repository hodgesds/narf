//! Native chain selection from calibrated firmware SERVICE_READY and the
//! actual INIT resource masks. Linux wmi.c5582..5590/mac.c5036..5070.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Chains(u8);
impl Chains {
    pub(super) fn new(mask: u8) -> Result<Self, Error> {
        if !matches!(mask, 1 | 3 | 7 | 15) {
            return Err(Error::Unsupported);
        }
        Ok(Self(mask))
    }
    pub(super) fn count(self) -> u8 {
        self.0.count_ones() as u8
    }
    pub(super) fn multiple(self) -> bool {
        self.count() > 1
    }
    pub(super) fn mcs(self) -> [u8; 10] {
        let mut result = [0; 10];
        result[..usize::from(self.count())].fill(255);
        result
    }
    pub(super) fn vht_map(self) -> u16 {
        let mut result = 0xffffu16;
        for stream in 0..self.count() {
            result = (result & !(3u16 << (2 * stream))) | (2u16 << (2 * stream));
        }
        result
    }
    pub(super) fn commands(self, dialect: Dialect) -> Result<[Vec<u8>; 2], Error> {
        let id = match dialect {
            Dialect::Main | Dialect::Tlv => 0x4003,
            Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 0x9006,
            Dialect::TenFour => 0x9008,
        };
        let command = |parameter| -> Result<Vec<u8>, Error> {
            let mut out = wire::packet(id, if dialect == Dialect::Tlv { 16 } else { 8 })?;
            let at = if dialect == Dialect::Tlv {
                wire::put(&mut out, 4, (82 << 16) | 12);
                12
            } else {
                4
            };
            wire::put(&mut out, at, parameter);
            wire::put(&mut out, at + 4, u32::from(self.0));
            Ok(out)
        };
        Ok([command(1)?, command(2)?])
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn vdev_nss(self, dialect: Dialect) -> Result<Vec<u8>, Error> {
        self.vdev_nss_for(dialect, 0)
    }
    /// `WMI_VDEV_SET_PARAM(nss)` for `vdev` (`mac.c::ath10k_add_interface`).
    pub(super) fn vdev_nss_for(self, dialect: Dialect, vdev: u8) -> Result<Vec<u8>, Error> {
        let (id, parameter) = match dialect {
            Dialect::Main | Dialect::Tlv => (0x5008, 0x22),
            Dialect::TenOne => (0x901a, 0x20),
            Dialect::TenTwo | Dialect::TenTwoFour => (0x9019, 0x20),
            Dialect::TenFour => (0x901c, 0x22),
        };
        let mut out = wire::packet(id, if dialect == Dialect::Tlv { 16 } else { 12 })?;
        let at = if dialect == Dialect::Tlv {
            wire::put(&mut out, 4, (95 << 16) | 12);
            8
        } else {
            4
        };
        wire::put(&mut out, at, u32::from(vdev));
        wire::put(&mut out, at + 4, parameter);
        wire::put(&mut out, at + 8, u32::from(self.count()));
        Ok(out)
    }
}
