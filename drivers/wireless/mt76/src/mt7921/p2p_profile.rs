//! Immutable WM feature observation attached to the actual retained radio.
//! This receipt supplies no grant, started BSS or CNM/RF completion.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P2pProfile {
    cnm: bool,
}
impl P2pProfile {
    pub(crate) fn cnm(self) -> bool {
        self.cnm
    }
}
impl Firmware {
    pub(crate) fn p2p_profile(&self) -> Result<P2pProfile, Error> {
        Ok(P2pProfile {
            cnm: self.cnm_capability()?,
        })
    }
}
