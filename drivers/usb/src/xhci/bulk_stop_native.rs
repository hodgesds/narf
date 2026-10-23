//! xHCI adapter for the real Stop Endpoint / Set TR Dequeue coordinator.
use super::{
    bulk_owner,
    bulk_stop::{self, Bus, Context, Plan},
    device_dma_barrier, EndpointKind, Xhci, XhciError, CTRL_TR_TRBS,
};
impl From<bulk_stop::Error> for XhciError {
    fn from(_: bulk_stop::Error) -> Self {
        Self::CmdFailed(0xfb)
    }
}
impl Bus for Xhci {
    type Error = XhciError;
    fn claim(&self, token: &bulk_owner::Token) -> Result<Plan, XhciError> {
        let mut devices = self.devices.lock();
        let device = devices
            .get_mut(usize::from(token.slot()))
            .and_then(Option::as_mut)
            .ok_or(XhciError::CmdFailed(0xfd))?;
        if device.generation == 0 || device.generation != token.generation() {
            return Err(XhciError::CmdFailed(0xfd));
        }
        if device.control.active() || device.endpoint_configuration {
            return Err(XhciError::NotReady);
        }
        let ep = device
            .eps
            .get_mut(usize::from(token.endpoint() - 2))
            .and_then(Option::as_mut)
            .ok_or(XhciError::CmdFailed(0xfa))?;
        if !matches!(ep.kind, EndpointKind::BulkIn | EndpointKind::BulkOut) {
            return Err(XhciError::CmdFailed(0xf8));
        }
        let identity = ep
            .bulk
            .begin_stop(device.generation, token)
            .map_err(super::bulk_error)?;
        device.endpoint_configuration = true;
        Plan::new(
            identity,
            ep.tr.dma_addr().raw(),
            CTRL_TR_TRBS,
            ep.enq,
            ep.pcs,
        )
        .map_err(Into::into)
    }
    async fn command(&self, words: [u32; 4]) -> Result<(), XhciError> {
        let deadline = narf_time::Deadline::after_ms(250);
        let command = loop {
            match self.submit_command_record(words[0], words[1], words[2], words[3]) {
                Ok(pointer) => break pointer,
                Err(XhciError::NotReady) if !deadline.expired() => {
                    narf_scheduler::yield_now().await
                }
                Err(error) => return Err(error),
            }
        };
        let slot = (words[3] >> 24) as u8;
        let event = self
            .await_event(|event| bulk_owner::command_matches(event, slot, command))
            .await?;
        let code = (event[2] >> 24) as u8;
        if code != 1 {
            return Err(XhciError::CmdFailed(code));
        }
        Ok(())
    }
    fn context(&self, plan: &Plan) -> Result<Context, XhciError> {
        let devices = self.devices.lock();
        let d = devices
            .get(usize::from(plan.identity.slot))
            .and_then(Option::as_ref)
            .ok_or(XhciError::CmdFailed(0xfd))?;
        if d.generation != plan.identity.generation || !d.endpoint_configuration {
            return Err(XhciError::CmdFailed(0xfd));
        }
        let ep = d
            .eps
            .get(usize::from(plan.identity.dci - 2))
            .and_then(Option::as_ref)
            .ok_or(XhciError::CmdFailed(0xfa))?;
        ep.bulk
            .validate_stop(plan.identity)
            .map_err(super::bulk_error)?;
        let offset = usize::from(plan.identity.dci) * self.context_stride() as usize;
        d._device_ctx.sync(offset, 16);
        device_dma_barrier();
        // SAFETY: DCI2..31 and context stride32/64 fit the retained4KiB
        // output context. xHC updated it before the exact command CCE.
        let (state, dequeue) = unsafe {
            (
                core::ptr::read_volatile(d._device_ctx.cpu_ptr_at::<u32>(offset as u64)),
                core::ptr::read_volatile(d._device_ctx.cpu_ptr_at::<u64>(offset as u64 + 8)),
            )
        };
        Ok(Context {
            state: (state & 7) as u8,
            dequeue,
        })
    }
    fn purge_events(&self, plan: &Plan) -> Result<(), XhciError> {
        self.context(plan)?; // Check live generation and retained stop claim.
                             // The demux publication lock establishes all pre-Stop events routed
                             // before its CCE; State quarantines this endpoint until commit.
        self.transfer_events.lock().retain(|event| {
            !(event[3] & (0x3f << 10) == 32 << 10
                && event[3] >> 24 == u32::from(plan.identity.slot)
                && event[3] & (0x1f << 16) == u32::from(plan.identity.dci) << 16)
        });
        Ok(())
    }
    fn commit(&self, plan: Plan) -> Result<(), XhciError> {
        let mut devices = self.devices.lock();
        let d = devices
            .get_mut(usize::from(plan.identity.slot))
            .and_then(Option::as_mut)
            .ok_or(XhciError::CmdFailed(0xfd))?;
        if d.generation != plan.identity.generation || !d.endpoint_configuration {
            return Err(XhciError::CmdFailed(0xfd));
        }
        let ep = d
            .eps
            .get_mut(usize::from(plan.identity.dci - 2))
            .and_then(Option::as_mut)
            .ok_or(XhciError::CmdFailed(0xfa))?;
        ep.bulk
            .validate_stop(plan.identity)
            .map_err(super::bulk_error)?;
        ep.enq = plan.enqueue;
        ep.pcs = plan.cycle;
        ep.bulk
            .finish_stop(plan.identity)
            .map_err(super::bulk_error)?;
        d.endpoint_configuration = false;
        Ok(())
    }
}
