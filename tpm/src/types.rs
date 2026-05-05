#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmError {
    NotPresent,
    LocalityTimeout,
    BusyTimeout,
    NoCommandBuffer,
    BadResponse,
    InvalidArgs,
    Denied,
    HardwareError,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcrSet(pub u32); // Bitmask of PCRs 0-31

impl PcrSet {
    pub const ALL: Self = Self(u32::MAX);
    pub const NONE: Self = Self(0);

    pub fn contains(self, pcr: u32) -> bool {
        if pcr >= 32 { return false; }
        (self.0 & (1 << pcr)) != 0
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PolicyHash(pub [u8; 32]);
