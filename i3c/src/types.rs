#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum I3cError {
    NoDevice,
    BusBusy,
    Timeout,
    Nack,
    CrcError,
    Denied,
    InvalidArgs,
    HardwareError,
}

pub enum I3cOp<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

pub struct IbiPayload {
    pub addr: u8,
    pub data: alloc::vec::Vec<u8>,
}
