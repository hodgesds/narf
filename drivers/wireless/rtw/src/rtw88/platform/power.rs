//! `narf_power` for the module: the device-PM error type. Runtime and
//! system PM are not carried by the module build (no PM KABI exists).

pub mod device_pm {
    /// Why a device PM transition was refused (the built-in variants the
    /// driver names).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DevicePmError {
        Busy,
        DriverError,
        NotImplemented,
    }
}
