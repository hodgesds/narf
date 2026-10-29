//! QRTR endpoint over a GLINK channel — the AHB counterpart of the MHI
//! `IPCR` pipe in [`super::qmi_client`].
//!
//! Linux `net/qrtr/smd.c` binds the rpmsg device named `IPCRTR` on the
//! remoteproc's `glink-edge` (`label = "rtr"` on IPQ8074/IPQ6018,
//! `"wpss"` on SC7280) and moves one QRTR packet per rpmsg message:
//! `qcom_smd_qrtr_callback` → `qrtr_endpoint_post`, `qcom_smd_qrtr_send`
//! → `rpmsg_send`. The framing, name service and flow control above it
//! are the same [`super::qrtr::QrtrLink`] the MHI path uses, so
//! [`GlinkQrtr`] only has to implement [`QrtrPipe`] on top of
//! [`narf_drivers_qcom_soc::glink::Glink`].
//!
//! The channel is remote-initiated: the Q6 opens `IPCRTR` once its
//! firmware runs, the endpoint claims it ([`Glink::accept`]) with the
//! default `qcom,intents` (none of the upstream DTs set the property,
//! so 5 × 1 KiB), and QRTR frames flow once the open handshake is done.
//! Frames sent before then fail with `-ENOTCONN` — in Linux the QRTR
//! endpoint does not exist before `qcom_smd_qrtr_probe`.
//!
//! Interrupts: the edge's GIC SPI (`qcom_glink_smem_intr`) wakes
//! [`GlinkBus::wait_irq`]; every wake runs `Glink::process_rx`.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use narf_drivers_qcom_soc::glink::{
    Glink, GlinkError, GlinkEvent, GlinkPipe, GLINK_DEFAULT_INTENTS,
};

use super::qmi_client::QrtrPipe;

/// `qcom_smd_qrtr_smd_match`.
pub const QRTR_GLINK_CHANNEL: &str = "IPCRTR";
pub const ENOTCONN: i32 = 107;
pub const EMSGSIZE: i32 = 90;

/// The edge interrupt and clock the pipe waits on.
pub trait GlinkBus {
    /// Wait up to `ms` for the edge interrupt.
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send;
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// One console line.
    fn log(&self, _args: fmt::Arguments<'_>) {}
}

/// The edge interrupt bound from the `glink-edge` node's
/// `interrupts = <GIC_SPI n IRQ_TYPE_EDGE_RISING>`
/// (`qcom_glink_smem_intr`), with a millisecond clock.
#[allow(missing_debug_implementations)]
pub struct GicGlinkBus<C: Fn() -> u64 + Send + Sync> {
    pub line: narf_drivers_qcom_soc::irq::GicSpi,
    pub clock: C,
}

impl<C: Fn() -> u64 + Send + Sync> GlinkBus for GicGlinkBus<C> {
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send {
        use narf_drivers_qcom_soc::irq::IrqLine;
        let w = self.line.wait(ms);
        async move {
            let _ = w.await;
        }
    }
    fn now_ms(&self) -> u64 {
        (self.clock)()
    }
}

/// `struct qrtr_smd_dev`.
#[allow(missing_debug_implementations)]
pub struct GlinkQrtr<P: GlinkPipe, B: GlinkBus> {
    pub glink: Glink<P>,
    pub bus: B,
    lcid: Option<u32>,
    rx: VecDeque<Vec<u8>>,
    /// The remote closed `IPCRTR` (firmware went down) since the last
    /// [`Self::take_closed`].
    closed: bool,
    pub send_failures: u32,
}

impl<P: GlinkPipe, B: GlinkBus> GlinkQrtr<P, B> {
    /// Register the rpmsg driver: claim `IPCRTR` on `glink`.
    pub fn new(mut glink: Glink<P>, bus: B) -> Self {
        // A static name shorter than GLINK_NAME_SIZE cannot be refused.
        let _ = glink.accept(QRTR_GLINK_CHANNEL, &GLINK_DEFAULT_INTENTS);
        let mut s = Self {
            glink,
            bus,
            lcid: None,
            rx: VecDeque::new(),
            closed: false,
            send_failures: 0,
        };
        s.drain_events();
        s
    }

    /// The channel's local id once open.
    pub fn lcid(&self) -> Option<u32> {
        self.lcid
    }
    pub fn is_open(&self) -> bool {
        self.lcid.is_some()
    }
    /// `true` once after the remote closed the channel.
    pub fn take_closed(&mut self) -> bool {
        core::mem::take(&mut self.closed)
    }

    fn drain_events(&mut self) {
        while let Some(ev) = self.glink.take_event() {
            match ev {
                GlinkEvent::Open { lcid, name } if name == QRTR_GLINK_CHANNEL => {
                    self.lcid = Some(lcid);
                }
                GlinkEvent::Data { lcid, data } if Some(lcid) == self.lcid => {
                    // `qcom_smd_qrtr_callback`: one QRTR packet.
                    self.rx.push_back(data);
                }
                GlinkEvent::Closed { lcid, .. } if Some(lcid) == self.lcid => {
                    // `qcom_smd_qrtr_remove` → `qrtr_endpoint_unregister`.
                    self.lcid = None;
                    self.rx.clear();
                    self.closed = true;
                }
                GlinkEvent::SendFailed { lcid, .. } if Some(lcid) == self.lcid => {
                    self.send_failures += 1;
                }
                _ => {}
            }
        }
    }
}

fn errno(e: GlinkError) -> i32 {
    match e {
        GlinkError::TooBig(_) => EMSGSIZE,
        _ => ENOTCONN,
    }
}

impl<P: GlinkPipe + Send, B: GlinkBus + Send + Sync> QrtrPipe for GlinkQrtr<P, B> {
    fn send(&mut self, frame: &[u8]) -> Result<(), i32> {
        let lcid = self.lcid.ok_or(ENOTCONN)?;
        self.glink.send(lcid, frame).map_err(errno)
    }
    fn poll(&mut self) {
        self.glink.process_rx();
        self.drain_events();
    }
    fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }
    async fn wait(&mut self, ms: u32) {
        self.bus.wait_irq(ms).await;
        self.poll();
    }
    fn now_ms(&self) -> u64 {
        self.bus.now_ms()
    }
    fn log(&self, args: fmt::Arguments<'_>) {
        self.bus.log(args)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "qrtr_glink_tests.rs"]
mod tests;
