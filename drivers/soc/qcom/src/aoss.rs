//! AOSS QMP: the message channel to the always-on subsystem.
//!
//! Linux counterpart: `drivers/soc/qcom/qcom_aoss.c` (`qmp_open`,
//! `qmp_send`, `qmp_kick`) plus the `load_state` message sent by
//! `drivers/remoteproc/qcom_q6v5.c` (`q6v5_load_state_toggle`).
//!
//! The channel is a shared-memory descriptor (`msgram`) plus a mailbox
//! kick. The kick is the crate's [`Kick`](crate::ipc::Kick) trait — on
//! SC7280-class SoCs that is an IPCC doorbell (`qcom-ipcc.c`), which
//! is also how the WCN6750 GLINK edge is kicked. The descriptor layout
//! and handshake below are transcribed from `qcom_aoss.c`:
//!
//! ```text
//! descriptor offsets:
//!   MAGIC 0x00, VERSION 0x04, FEATURES 0x08,
//!   UCORE_LINK_STATE 0x0c, UCORE_LINK_STATE_ACK 0x10,
//!   UCORE_CH_STATE 0x14, UCORE_CH_STATE_ACK 0x18,
//!   UCORE_MBOX_SIZE 0x1c, UCORE_MBOX_OFFSET 0x20,
//!   MCORE_LINK_STATE 0x24, MCORE_LINK_STATE_ACK 0x28,
//!   MCORE_CH_STATE 0x2c, MCORE_CH_STATE_ACK 0x30,
//!   MCORE_MBOX_SIZE 0x34, MCORE_MBOX_OFFSET 0x38
//! open:  MAGIC == 0x4d41494c ("MAIL"), VERSION == 1,
//!        mbox offset/size from the MCORE fields (size != 0),
//!        ack the remote link state, set local link UP, kick,
//!        wait for the link ack, set local channel UP, kick,
//!        wait for the remote channel UP, ack it, kick,
//!        wait for the channel ack (each wait bounded; a timeout
//!        unwinds the channel/link state to DOWN, as Linux does)
//! send:  64-byte zero-padded message, 32-bit copies at mbox+4,
//!        length word 64 at mbox, read-back, kick, wait for the
//!        length word to clear (AOSS consumed it); on timeout clear
//!        the length word and fail
//! ```
//!
//! `QMP_STATE_UP` is bits 15..0 (`GENMASK(15, 0)`), `QMP_STATE_DOWN`
//! bits 31..16. Waits sleep through [`Delay`](crate::io::Delay) via
//! `io::poll_reg`, never spin.
//!
//! Nothing here has run on Qualcomm silicon.

use crate::io::{poll_reg, write_bytes, Delay, RegIo};
use crate::ipc::Kick;

/// `QMP_MAGIC` (`0x4d41494c`, "MAIL" as a u32 constant).
const QMP_MAGIC: u32 = 0x4d41_494c;
/// `QMP_VERSION`.
const QMP_VERSION: u32 = 1;
/// `QMP_MSG_LEN`: every message is a 64-byte zero-padded buffer.
const QMP_MSG_LEN: usize = 64;
/// `QMP_STATE_UP` (`GENMASK(15, 0)`).
const STATE_UP: u32 = 0x0000_ffff;
/// `QMP_STATE_DOWN` (`GENMASK(31, 16)`).
const STATE_DOWN: u32 = 0xffff_0000;

/// Descriptor offsets (`QMP_DESC_*`).
const DESC_MAGIC: u32 = 0x00;
const DESC_VERSION: u32 = 0x04;
const DESC_UCORE_LINK_STATE: u32 = 0x0c;
const DESC_UCORE_LINK_STATE_ACK: u32 = 0x10;
const DESC_UCORE_CH_STATE: u32 = 0x14;
const DESC_UCORE_CH_STATE_ACK: u32 = 0x18;
const DESC_MCORE_LINK_STATE: u32 = 0x24;
const DESC_MCORE_LINK_STATE_ACK: u32 = 0x28;
const DESC_MCORE_CH_STATE: u32 = 0x2c;
const DESC_MCORE_CH_STATE_ACK: u32 = 0x30;
const DESC_MCORE_MBOX_SIZE: u32 = 0x34;
const DESC_MCORE_MBOX_OFFSET: u32 = 0x38;

/// Poll sleep between ack reads (NARF policy; Linux waits on the
/// mailbox IRQ / waitqueue instead).
const POLL_SLEEP_US: u32 = 100;
/// Poll timeout per handshake step and per send (NARF policy; Linux
/// waits `HZ`, i.e. 1 s, on each).
const POLL_TIMEOUT_US: u32 = 1_000_000;

/// QMP failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QmpError {
    /// The descriptor magic does not match [`QMP_MAGIC`].
    BadMagic,
    /// The descriptor version is not [`QMP_VERSION`].
    BadVersion,
    /// The MCORE mailbox size reads 0.
    BadMbox,
    /// A handshake step or a send was not acked in time.
    Timeout,
    /// The message does not fit in [`QMP_MSG_LEN`] bytes.
    TooLong,
}

/// An open AOSS QMP channel: the msgram window, the kick, and the
/// negotiated mailbox offset/size.
#[derive(Debug)]
pub struct Qmp<R: RegIo, K: Kick> {
    msgram: R,
    kick: K,
    offset: u32,
    size: u32,
}

impl<R: RegIo, K: Kick> Qmp<R, K> {
    /// `qmp_open`: run the link/channel handshake over `msgram`,
    /// kicking after every state change. On a timeout the channel and
    /// link states are unwound to DOWN, as Linux does.
    pub async fn open<D: Delay + ?Sized>(msgram: R, kick: K, delay: &D) -> Result<Self, QmpError> {
        if msgram.read32(DESC_MAGIC) != QMP_MAGIC {
            return Err(QmpError::BadMagic);
        }
        if msgram.read32(DESC_VERSION) != QMP_VERSION {
            return Err(QmpError::BadVersion);
        }
        let offset = msgram.read32(DESC_MCORE_MBOX_OFFSET);
        let size = msgram.read32(DESC_MCORE_MBOX_SIZE);
        if size == 0 {
            return Err(QmpError::BadMbox);
        }
        let qmp = Self {
            msgram,
            kick,
            offset,
            size,
        };
        // Ack the remote core's link state.
        let link = qmp.msgram.read32(DESC_UCORE_LINK_STATE);
        qmp.msgram.write32(DESC_UCORE_LINK_STATE_ACK, link);
        // Set the local link UP and wait for the ack.
        qmp.msgram.write32(DESC_MCORE_LINK_STATE, STATE_UP);
        qmp.kick.kick();
        if qmp
            .wait_ack(delay, DESC_MCORE_LINK_STATE_ACK)
            .await
            .is_err()
        {
            qmp.close_link();
            return Err(QmpError::Timeout);
        }
        // Set the local channel UP and wait for the remote channel.
        qmp.msgram.write32(DESC_MCORE_CH_STATE, STATE_UP);
        qmp.kick.kick();
        if qmp.wait_ack(delay, DESC_UCORE_CH_STATE).await.is_err() {
            qmp.close_channel();
            qmp.close_link();
            return Err(QmpError::Timeout);
        }
        // Ack the remote channel and wait for our channel ack.
        qmp.msgram.write32(DESC_UCORE_CH_STATE_ACK, STATE_UP);
        qmp.kick.kick();
        if qmp.wait_ack(delay, DESC_MCORE_CH_STATE_ACK).await.is_err() {
            qmp.close_channel();
            qmp.close_link();
            return Err(QmpError::Timeout);
        }
        Ok(qmp)
    }

    async fn wait_ack<D: Delay + ?Sized>(&self, delay: &D, off: u32) -> Result<u32, u32> {
        poll_reg(
            &self.msgram,
            delay,
            off,
            |v| v == STATE_UP,
            POLL_SLEEP_US,
            POLL_TIMEOUT_US,
        )
        .await
    }

    fn close_channel(&self) {
        self.msgram.write32(DESC_MCORE_CH_STATE, STATE_DOWN);
    }

    fn close_link(&self) {
        self.msgram.write32(DESC_MCORE_LINK_STATE, STATE_DOWN);
        self.kick.kick();
    }

    /// `qmp_close`: drop the channel state (the link close kicks, as
    /// Linux does on the timeout unwind path).
    pub fn close(&self) {
        self.close_channel();
        self.close_link();
    }

    /// `qmp_send`: transmit one zero-padded 64-byte message and wait
    /// for AOSS to consume it (length word cleared). On timeout the
    /// length word is cleared and the send fails.
    pub async fn send<D: Delay + ?Sized>(&self, delay: &D, msg: &str) -> Result<(), QmpError> {
        if msg.len() >= QMP_MSG_LEN {
            return Err(QmpError::TooLong);
        }
        let mut buf = [0u8; QMP_MSG_LEN];
        buf[..msg.len()].copy_from_slice(msg.as_bytes());
        // The message RAM only implements 32-bit accesses.
        write_bytes(&self.msgram, self.offset + 4, &buf);
        self.msgram.write32(self.offset, QMP_MSG_LEN as u32);
        // Read back the length to confirm the data landed.
        let _ = self.msgram.read32(self.offset);
        self.kick.kick();
        let consumed = poll_reg(
            &self.msgram,
            delay,
            self.offset,
            |v| v == 0,
            POLL_SLEEP_US,
            POLL_TIMEOUT_US,
        )
        .await;
        if consumed.is_err() {
            self.msgram.write32(self.offset, 0);
            return Err(QmpError::Timeout);
        }
        Ok(())
    }

    /// `q6v5_load_state_toggle`: the AOSS image load-state message for
    /// a remote (`{class: image, res: load_state, name: %s, val: %s}`
    /// with `val` `on`/`off`). Built on the stack; no allocation.
    pub async fn load_state<D: Delay + ?Sized>(
        &self,
        delay: &D,
        name: &str,
        on: bool,
    ) -> Result<(), QmpError> {
        const PREFIX: &[u8] = b"{class: image, res: load_state, name: ";
        const MID: &[u8] = b", val: ";
        const SUFFIX: &[u8] = b"}";
        let val: &[u8] = if on { b"on" } else { b"off" };
        let total = PREFIX.len() + name.len() + MID.len() + val.len() + SUFFIX.len();
        if total >= QMP_MSG_LEN {
            return Err(QmpError::TooLong);
        }
        let mut buf = [0u8; QMP_MSG_LEN];
        let mut at = 0;
        for part in [PREFIX, name.as_bytes(), MID, val, SUFFIX] {
            buf[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        // The buffer is NUL-padded past `at`; send() re-pads, so pass
        // the message as a str slice of exactly the written bytes.
        let msg = core::str::from_utf8(&buf[..at]).map_err(|_| QmpError::TooLong)?;
        self.send(delay, msg).await
    }

    /// The negotiated mailbox size (from the MCORE descriptor field).
    pub fn mbox_size(&self) -> u32 {
        self.size
    }
}
