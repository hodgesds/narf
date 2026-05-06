#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PmBusError {
    NotPresent,
    Timeout,
    Nack,
    CrcError,
    InvalidArgs,
    Denied,
    HardwareError,
}

#[derive(Copy, Clone, Debug)]
pub struct PowerReading {
    pub voltage_mv: u32,
    pub current_ma: u32,
    pub power_mw: u32,
    pub temp_mc: i32, // millicelsius
}
