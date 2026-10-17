//! Owned DCN inbox1/outbox1 transport. ABI: Linux dmub_cmd.h and dmub_srv.c.
//! The enclosing controller supplies generation-specific reset/coherency.
use super::*;

const SIZE: u32 = 8192; // linux: DMUB_RB_SIZE
const SLOT: u32 = 64; // linux: DMUB_RB_CMD_SIZE
                      // linux-ctx: hdr=dcn seg=2
const IN_W: u32 = 0x1d6; // linux: mmDMCUB_INBOX1_WPTR
const IN_R: u32 = 0x1d7; // linux: mmDMCUB_INBOX1_RPTR
const OUT_W: u32 = 0x1de; // linux: mmDMCUB_OUTBOX1_WPTR
const OUT_R: u32 = 0x1df; // linux: mmDMCUB_OUTBOX1_RPTR
                          // linux-ctx: reset

/// Firmware's packed dmub_feature_caps bytes. Informational only: no feature
/// is enabled from these flags. Older firmware leaves the zeroed tail intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureCaps(pub [u8; 14]); // linux-lit: 14=sizeof(struct dmub_feature_caps)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxState {
    Dormant,
    Ready,
    /// Also retained when a future is dropped; further commands are refused.
    InFlight,
    Failed,
}

#[derive(Debug)]
pub(super) struct Mailbox {
    pub(super) state: MailboxState,
    write: u32,
    read: u32,
    notifications: bool,
    // Preserve unrelated notifications while waiting for AUX, without heap
    // allocation or unbounded processing of firmware-controlled traffic.
    events: [[u8; 64]; 16], // linux-lit: 64=DMUB_RB_CMD_SIZE
    head: usize,
    len: usize,
}
impl Mailbox {
    pub(super) const fn new() -> Self {
        Self {
            state: MailboxState::Dormant,
            write: 0,
            read: 0,
            notifications: false,
            events: [[0; 64]; 16],
            head: 0,
            len: 0,
        }
    }
    fn save(&mut self, event: [u8; 64]) -> Result<(), Error> {
        if self.len == self.events.len() {
            return Err(Error::NotificationOverflow);
        }
        self.events[(self.head + self.len) % self.events.len()] = event;
        self.len += 1;
        Ok(())
    }
    fn pop(&mut self) -> Option<[u8; 64]> {
        if self.len == 0 {
            return None;
        }
        let event = self.events[self.head];
        self.head = (self.head + 1) % self.events.len();
        self.len -= 1;
        Some(event)
    }
}
fn pointer(value: u32) -> Result<u32, Error> {
    if value >= SIZE || value % SLOT != 0 {
        Err(Error::Protocol)
    } else {
        Ok(value)
    }
}
fn header(kind: u8, length: u8) -> [u8; 64] {
    let mut command = [0; 64]; // linux-lit: 64=DMUB_RB_CMD_SIZE
    command[0] = kind;
    command[3] = length;
    command
}
fn valid_header(command: &[u8; 64]) -> bool {
    // One complete memory-based command. No register payloads, batches or
    // reserved header bits. ret_status has command-specific semantics.
    // linux-lit: 60=DMUB_RB_CMD_SIZE - sizeof(struct dmub_cmd_header)
    command[2] & !1 == 0 && command[3] <= 60
}
fn alive(io: &mut impl Io, l: Layout) -> Result<(), Error> {
    // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL@nbio
    if !is_running(io, l)? || read(io, l.nbio, 0x12d)? != 0x7f000 {
        return Err(Error::Protocol);
    }
    Ok(())
}
fn flush(io: &mut impl Io, l: Layout) -> Result<(), Error> {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    read(io, l.nbio, 0xc3)?; // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE@nbio
    fence(Ordering::SeqCst);
    Ok(())
}
fn download(io: &mut impl Io, l: Layout, map: MmioRegion, offset: u64) -> [u8; 64] {
    invalidate(io, l);
    let mut reply = [0; 64];
    for (i, word) in reply.chunks_exact_mut(4).enumerate() {
        word.copy_from_slice(&io.download(map, offset + (i * 4) as u64).to_le_bytes());
    }
    reply
}
impl<I: Io> Engine<I> {
    pub(super) fn begin_mailbox(&mut self) -> Result<(), Error> {
        if self.state != State::Running || self.mailbox.state != MailboxState::Ready {
            return Err(Error::Busy);
        }
        self.mailbox.state = MailboxState::InFlight;
        Ok(())
    }
    pub(super) fn finish_mailbox<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        self.mailbox.state = match &result {
            Ok(_) | Err(Error::CommandRejected(_) | Error::Aux(_)) => MailboxState::Ready,
            _ => MailboxState::Failed,
        };
        result
    }
    fn mailbox_offset(&self) -> u64 {
        u64::from(self.prepared.layout.region(fw::Window::Mailbox).offset)
    }
    fn check_mailbox(&mut self) -> Result<(), Error> {
        let l = self.layout;
        let address = self.memory.address() + self.mailbox_offset();
        let write = self.mailbox.write;
        let read_ptr = self.mailbox.read;
        self.access(|io| {
            alive(io, l)?;
            for (reg, value, mask) in [
                (0x1bd, address as u32, u32::MAX), // linux-lit: 0x1bd=mmDMCUB_REGION3_CW4_OFFSET
                // linux-lit: 0x1be=mmDMCUB_REGION3_CW4_OFFSET_HIGH
                (0x1be, (address >> 32) as u32, u32::MAX),
                (0x1a9, 0x04000000, MASK), // linux-lit: 0x1a9=mmDMCUB_REGION3_CW4_BASE_ADDRESS
                // linux-lit: 0x1b1=mmDMCUB_REGION3_CW4_TOP_ADDRESS
                // linux-lit: 31=DMCUB_REGION3_CW4_TOP_ADDRESS__DMCUB_REGION3_CW4_ENABLE__SHIFT
                (0x1b1, 0x84004000, MASK | (1 << 31)),
                (0x1d4, 0x64000000, u32::MAX), // linux-lit: 0x1d4=mmDMCUB_INBOX1_BASE_ADDRESS
                (0x1d5, SIZE, u32::MAX),       // linux-lit: 0x1d5=mmDMCUB_INBOX1_SIZE
                (0x1dc, 0x64002000, u32::MAX), // linux-lit: 0x1dc=mmDMCUB_OUTBOX1_BASE_ADDRESS
                (0x1dd, SIZE, u32::MAX),       // linux-lit: 0x1dd=mmDMCUB_OUTBOX1_SIZE
                (IN_W, write, u32::MAX),
                (IN_R, write, u32::MAX),
                (OUT_R, read_ptr, u32::MAX),
            ] {
                if read(io, l.dcn, reg)? & mask != value {
                    return Err(Error::Protocol);
                }
            }
            pointer(read(io, l.dcn, OUT_W)?)?;
            Ok(())
        })
    }
    pub(super) async fn initialize_mailbox(&mut self) -> Result<(), Error> {
        if self.state != State::Running || self.mailbox.state != MailboxState::Dormant {
            return Err(Error::Busy);
        }
        self.mailbox.state = MailboxState::InFlight;
        let result = self.initialize_mailbox_inner().await;
        self.finish_mailbox(result)
    }
    async fn initialize_mailbox_inner(&mut self) -> Result<(), Error> {
        self.check_mailbox()?;
        let l = self.layout;
        self.access(|io| {
            // linux-lit: 0x1ea=mmDMCUB_SCRATCH7
            io.write(l.dcn + 0x1ea * 4, 0); // exclude the inherited STOP reply
                                            // linux-lit: 0x10010000=(1 << 28) | (DMUB_GPINT__GET_FW_VERSION << 16)
            io.write(l.dcn + u64::from(GPINT) * 4, 0x10010000);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            let version = self.access(|io| {
                alive(io, l)?;
                // linux-lit: 0x00010000=DMUB_GPINT__GET_FW_VERSION << 16
                if read(io, l.dcn, GPINT)? == 0x00010000 {
                    Ok(Some(read(io, l.dcn, 0x1ea)?)) // linux-lit: 0x1ea=mmDMCUB_SCRATCH7
                } else {
                    Ok(None)
                }
            })?;
            if let Some(version) = version {
                if version != self.prepared.version {
                    if super::STRICT_VERSION {
                        return Err(Error::Protocol);
                    }
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: dmub firmware reports {version:#x}, header {:#x}",
                        self.prepared.version
                    );
                }
                break;
            }
            if deadline.expired() {
                return Err(Error::CommandTimeout);
            }
            tick().await;
        }
        // linux-lit: 6=DMUB_CMD__QUERY_FEATURE_CAPS
        // linux-lit: 14=sizeof(struct dmub_cmd_query_feature_caps_data)
        let mut request = header(6, 14); // QUERY_FEATURE_CAPS
        request[2] = 1;
        let reply = self.command(request).await?;
        // Linux dc_dmub_srv_query_caps_cmd: a processed query CLEARS the
        // request's ret_status bit. Unimplemented queries leave it set.
        // linux-lit: 4=offsetof(struct dmub_rb_cmd_query_feature_caps, query_feature_caps_data)
        // linux-lit: 18=sizeof(struct dmub_rb_cmd_query_feature_caps)
        let caps = (reply[2] == 0).then(|| FeatureCaps(reply[4..18].try_into().unwrap()));
        self.status.as_mut().ok_or(Error::Invalid)?.capabilities = caps;
        Ok(())
    }
    // Private raw transport: only typed, bounded requests below can reach it.
    // The outer operation holds InFlight across both inbox and AUX completion.
    pub(super) async fn command(&mut self, request: [u8; 64]) -> Result<[u8; 64], Error> {
        if !valid_header(&request) {
            return Err(Error::Invalid);
        }
        self.check_mailbox()?;
        let l = self.layout;
        let map = self.memory.mapping();
        let old = self.mailbox.write;
        let next = (old + SLOT) % SIZE;
        let offset = self.mailbox_offset() + u64::from(old);
        self.access(|io| {
            for (i, word) in request.chunks_exact(4).enumerate() {
                io.upload(
                    map,
                    offset + (i * 4) as u64,
                    u32::from_le_bytes(word.try_into().unwrap()),
                );
            }
            flush(io, l)
        })?;
        self.mailbox.write = next;
        self.access(|io| {
            io.write(l.dcn + u64::from(IN_W) * 4, next);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            let done = self.access(|io| {
                alive(io, l)?;
                if read(io, l.dcn, IN_W)? != next {
                    return Err(Error::Protocol);
                }
                let rp = pointer(read(io, l.dcn, IN_R)?)?;
                if rp != old && rp != next {
                    return Err(Error::Protocol);
                }
                Ok(rp == next)
            })?;
            if done {
                let reply = self.access(|io| Ok(download(io, l, map, offset)))?;
                if !valid_header(&reply) || reply[..2] != request[..2] || reply[3] != request[3] {
                    return Err(Error::Protocol);
                }
                return Ok(reply);
            }
            if deadline.expired() {
                return Err(Error::CommandTimeout);
            }
            tick().await;
        }
    }
    fn outbox(&mut self) -> Result<Option<[u8; 64]>, Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        let old = self.mailbox.read;
        let offset = self.mailbox_offset() + u64::from(SIZE + old);
        let event = self.access(|io| {
            alive(io, l)?;
            if read(io, l.dcn, OUT_R)? != old {
                return Err(Error::Protocol);
            }
            if pointer(read(io, l.dcn, OUT_W)?)? == old {
                return Ok(None);
            }
            let reply = download(io, l, map, offset);
            if !valid_header(&reply) {
                return Err(Error::Protocol);
            }
            fence(Ordering::SeqCst);
            io.write(l.dcn + u64::from(OUT_R) * 4, (old + SLOT) % SIZE);
            if read(io, l.dcn, OUT_R)? != (old + SLOT) % SIZE {
                return Err(Error::Protocol);
            }
            Ok(Some(reply))
        })?;
        if event.is_some() {
            self.mailbox.read = (old + SLOT) % SIZE;
        }
        Ok(event)
    }
    fn notification(event: [u8; 64]) -> Result<[u8; 64], Error> {
        // AUX has no usable request ID. A late/unmatched reply must never be
        // attributed to another transfer, even on the same physical link.
        // linux-lit: 1=DMUB_OUT_CMD__DP_AUX_REPLY
        if event[0] == 1 {
            Err(Error::Protocol)
        } else {
            Ok(event)
        }
    }
    pub(super) fn poll_notification(&mut self) -> Result<Option<[u8; 64]>, Error> {
        self.begin_mailbox()?;
        let result = (|| {
            self.check_mailbox()?;
            if let Some(event) = self.mailbox.pop() {
                Ok(Some(event))
            } else {
                self.outbox()?.map(Self::notification).transpose()
            }
        })();
        self.finish_mailbox(result)
    }
    pub(super) async fn hpd(&mut self, instance: u8) -> Result<bool, Error> {
        if instance >= NATIVE_CHANNELS {
            return Err(Error::Invalid);
        }
        self.begin_mailbox()?;
        // linux-lit: 82=DMUB_CMD__QUERY_HPD_STATE; 12=sizeof(struct dmub_cmd_hpd_state_query_data)
        let mut request = header(82, 12);
        // linux-lit: 4=offsetof(struct dmub_rb_cmd_query_hpd_state, data.instance)
        request[4] = instance;
        // Legacy/native AUX channel = 0. A sentinel prevents an unimplemented
        // query from looking like a successful disconnected port.
        // linux-lit: 12=offsetof(struct dmub_rb_cmd_query_hpd_state, data.status)
        // linux-lit: 16=sizeof(struct dmub_rb_cmd_query_hpd_state)
        request[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        let result = async {
            let reply = self.command(request).await?;
            // linux-lit: 4=offsetof(struct dmub_rb_cmd_query_hpd_state, data.instance)
            // linux-lit: 8=offsetof(struct dmub_rb_cmd_query_hpd_state, data.ch_type)
            // linux-lit: 12=offsetof(struct dmub_rb_cmd_query_hpd_state, data.status)
            if reply[4] != instance || reply[8..12] != [0; 4] {
                return Err(Error::Protocol);
            }
            // linux-lit: 12=offsetof(struct dmub_rb_cmd_query_hpd_state, data.status)
            // linux-lit: 16=sizeof(struct dmub_rb_cmd_query_hpd_state)
            let status = u32::from_le_bytes(reply[12..16].try_into().unwrap());
            if status != 0 {
                return Err(Error::CommandRejected(status));
            }
            // linux-lit: 5=offsetof(struct dmub_rb_cmd_query_hpd_state, data.result)
            match reply[5] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::Protocol),
            }
        }
        .await;
        self.finish_mailbox(result)
    }
    pub(super) async fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        use crate::amdgpu_dmub::{aux_command, Channel};
        if instance >= NATIVE_CHANNELS {
            return Err(Error::Invalid);
        }
        let request = aux_command(Channel::Legacy, instance, action, address, data)
            .map_err(|_| Error::Invalid)?;
        self.begin_mailbox()?;
        let result = self.aux_inner(request, instance, action, data).await;
        self.finish_mailbox(result)
    }
    async fn aux_inner(
        &mut self,
        request: [u8; 64],
        instance: u8,
        action: u8,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.check_mailbox()?;
        // Preserve preexisting notifications; refuse stale AUX before posting.
        while let Some(event) = self.outbox()? {
            self.mailbox.save(Self::notification(event)?)?;
        }
        if !self.mailbox.notifications {
            // linux-lit: 4=sizeof(struct dmub_rb_cmd_outbox1_enable) - sizeof(struct dmub_cmd_header)
            let mut enable = header(71, 4); // linux-lit: 71=DMUB_CMD__OUTBOX1_ENABLE
            enable[4] = 1; // linux-lit: 4=offsetof(struct dmub_rb_cmd_outbox1_enable, enable)
            self.command(enable).await?;
            self.mailbox.notifications = true;
        }
        self.command(request).await?;
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            // Bounded work per poll even if firmware keeps publishing events.
            for _ in 0..16 {
                let Some(reply) = self.outbox()? else { break };
                // linux-lit: 1=DMUB_OUT_CMD__DP_AUX_REPLY
                if reply[0] != 1 {
                    self.mailbox.save(reply)?;
                    continue;
                }
                // linux-lit: 28=sizeof(struct dmub_rb_cmd_dp_aux_reply) - sizeof(struct dmub_cmd_header)
                // linux-lit: 8=offsetof(struct dmub_rb_cmd_dp_aux_reply, control.instance)
                if reply[1] != 0 || reply[3] != 28 || reply[8] != instance {
                    return Err(Error::Protocol);
                }
                return crate::amdgpu_dmub::aux_reply(&reply, action, data).map_err(|e| match e {
                    crate::amdgpu_dmub::Error::Aux(code) => Error::Aux(code),
                    crate::amdgpu_dmub::Error::Firmware(code) => {
                        Error::CommandRejected(u32::from(code))
                    }
                    _ => Error::Protocol,
                });
            }
            if deadline.expired() {
                return Err(Error::CommandTimeout);
            }
            tick().await;
        }
    }
}
impl Dmub {
    pub fn mailbox_state(&self) -> MailboxState {
        self.engine.mailbox.state
    }
    /// Query a native AUX/HPD instance within this generation's channel count.
    pub async fn hpd(&mut self, instance: u8) -> Result<bool, Error> {
        self.engine.hpd(instance).await
    }
    /// Native AUX/I2C-over-AUX, at most 16 bytes. No automatic DEFER retry.
    pub async fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.engine.aux(instance, action, address, data).await
    }
    /// One raw, validated notification slot, including events saved during AUX.
    /// A stray AUX reply fails the transport instead of leaking to another call.
    pub fn poll_notification(&mut self) -> Result<Option<[u8; 64]>, Error> {
        self.engine.poll_notification()
    }
}
