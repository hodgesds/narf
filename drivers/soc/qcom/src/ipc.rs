//! Outgoing inter-processor interrupts ("kicks").
//!
//! SMP2P and GLINK notify the remote by raising an IPC interrupt. Two
//! send paths cover the supported SoCs:
//!
//! - [`ApcsIpc`] — `qcom,ipq6018-apcs-apps-global` /
//!   `qcom,ipq8074-apcs-apps-global` (`qcom-apcs-ipc-mailbox.c`): write
//!   `BIT(channel)` to the IPC register at offset 8. IPQ5018 uses the
//!   same block.
//! - [`Ipcc`] — `qcom,ipcc` on SC7280 (`qcom-ipcc.c`): write
//!   `client << 16 | signal` to `IPCC_REG_SEND_ID` (0x0c).

use crate::io::RegIo;

/// Raise the remote's interrupt.
pub trait Kick {
    fn kick(&self);
}

/// `qcom_apcs_ipc_send_data`.
#[derive(Debug)]
pub struct ApcsIpc<R: RegIo> {
    regs: R,
    offset: u32,
    channel: u32,
}

/// IPC register offset of the IPQ6018/IPQ8074/IPQ5018 APCS global block.
pub const APCS_IPQ_IPC_OFFSET: u32 = 8;

impl<R: RegIo> ApcsIpc<R> {
    pub fn new(regs: R, offset: u32, channel: u32) -> Self {
        Self {
            regs,
            offset,
            channel: channel & 31,
        }
    }
}

impl<R: RegIo> Kick for ApcsIpc<R> {
    fn kick(&self) {
        self.regs.write32(self.offset, 1 << self.channel);
    }
}

/// `IPCC_REG_SEND_ID`.
pub const IPCC_REG_SEND_ID: u32 = 0x0c;

/// `qcom_ipcc_mbox_send_data`.
#[derive(Debug)]
pub struct Ipcc<R: RegIo> {
    regs: R,
    client: u16,
    signal: u16,
}

impl<R: RegIo> Ipcc<R> {
    pub fn new(regs: R, client: u16, signal: u16) -> Self {
        Self {
            regs,
            client,
            signal,
        }
    }
}

impl<R: RegIo> Kick for Ipcc<R> {
    fn kick(&self) {
        self.regs.write32(
            IPCC_REG_SEND_ID,
            ((self.client as u32) << 16) | self.signal as u32,
        );
    }
}

/// The kick a DT `mboxes` / `qcom,ipc` entry names
/// (`platform::KickDt`), over its mapped window.
#[derive(Debug)]
pub enum DtKick<R: RegIo> {
    Apcs(ApcsIpc<R>),
    Ipcc(Ipcc<R>),
}

impl<R: RegIo> Kick for DtKick<R> {
    fn kick(&self) {
        match self {
            DtKick::Apcs(k) => k.kick(),
            DtKick::Ipcc(k) => k.kick(),
        }
    }
}
