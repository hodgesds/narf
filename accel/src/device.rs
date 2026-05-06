use bitflags::bitflags;

pub struct AccelId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelKind {
    Npu,
    Tpu,
    Fpga,
    Dsp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelError {
    NotSupported,
    Busy,
    Timeout,
    InvalidArgs,
    HardwareError,
    Denied,
    OutOfMemory,
}

pub struct AccelInfo {
    pub id: AccelId,
    pub kind: AccelKind,
    pub memory_size: u64,
    pub compute_units: u32,
    pub features: AccelFeatures,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccelFeatures: u32 {
        const BFLOAT16   = 1 << 0;
        const INT8       = 1 << 1;
        const ASYNC_QUEUE = 1 << 2;
        const P2P_DMA    = 1 << 3;
    }
}

pub struct JobId(pub u64);

pub struct ComputeJob {
    pub graph_blob: narf_capabilities::Cap<narf_io::DmaBuffer, narf_capabilities::Read>,
    pub inputs:
        alloc::vec::Vec<narf_capabilities::Cap<narf_io::DmaBuffer, narf_capabilities::Read>>,
    pub outputs:
        alloc::vec::Vec<narf_capabilities::Cap<narf_io::DmaBuffer, narf_capabilities::Write>>,
}

pub type AccelDevice = dyn crate::AccelDeviceTrait;
