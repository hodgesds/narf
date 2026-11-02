//! Only the two concrete admitted physical owners can parent this control
//! child. This is private native dispatch, never an arbitrary provider trait
//! or a way to replace the original registered parent capability.
use super::*;
type Native<'a, T> = Pin<Box<dyn Future<Output = Result<T, WirelessError>> + Send + 'a>>;

#[derive(Clone)]
pub(in crate::iwlwifi) enum Parent {
    Mld(Arc<Device>),
    Mvm(Arc<super::super::super::mvm_device::Device>),
}
impl Parent {
    pub(in crate::iwlwifi) fn iface(&self) -> Arc<dyn WirelessNetIface> {
        match self {
            Self::Mld(device) => device.clone(),
            Self::Mvm(device) => device.clone(),
        }
    }
    pub(in crate::iwlwifi) fn iface_ref(&self) -> &dyn WirelessNetIface {
        match self {
            Self::Mld(device) => device.as_ref(),
            Self::Mvm(device) => device.as_ref(),
        }
    }
    pub(in crate::iwlwifi) fn invoke<T>(
        &self,
        action: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        match self {
            Self::Mld(device) => device.source.invoke(action),
            Self::Mvm(device) => device.p2p_invoke(action),
        }
    }
    pub(in crate::iwlwifi) fn waker(&self) -> Waker {
        match self {
            Self::Mld(device) => device.p2p.waker(),
            Self::Mvm(device) => device.p2p_waker(),
        }
    }
    pub(in crate::iwlwifi) fn p2p_source_current(&self) -> bool {
        match self {
            Self::Mld(device) => device.p2p_source_current(),
            Self::Mvm(device) => device.p2p_source_current(),
        }
    }
    pub(in crate::iwlwifi) fn quarantined(&self) -> bool {
        match self {
            Self::Mld(device) => device.quarantined.load(Ordering::Acquire),
            Self::Mvm(device) => device.p2p_quarantined(),
        }
    }
    pub(in crate::iwlwifi) fn poll_control(&self, cx: &mut Context<'_>) {
        match self {
            Self::Mld(device) => {
                let _ = device.poll_control(cx);
            }
            Self::Mvm(device) => device.p2p_poll_control(cx),
        }
    }
    pub(in crate::iwlwifi) fn reserve(
        &self,
    ) -> Result<Arc<dyn narf_wireless::ap_control::ApControlReservation>, WirelessError> {
        match self {
            Self::Mld(device) => device.radio_control.try_reserve(),
            Self::Mvm(device) => device.p2p_reserve(),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_start_request(&self, request: Arc<Request>) -> Native<'_, ()> {
        match self {
            Self::Mld(device) => Box::pin(device.p2p_start_request(request)),
            Self::Mvm(device) => Box::pin(device.p2p_start_request(request)),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_stop_request(&self) -> Native<'_, Vec<Event>> {
        match self {
            Self::Mld(device) => Box::pin(device.p2p_stop_request()),
            Self::Mvm(device) => Box::pin(device.p2p_stop_request()),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn prepare_power(
        &self,
        request: Arc<Request>,
        frequency: u32,
        only_if_missing: bool,
    ) -> Native<'_, Option<PowerSource>> {
        match self {
            Self::Mld(_) => Box::pin(async { Ok(None) }),
            Self::Mvm(device) => {
                Box::pin(device.p2p_prepare_power(request, frequency, only_if_missing))
            }
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_roc_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frequency: u32,
        duration: u32,
        activity: RocActivity,
        power: Option<PowerSource>,
    ) -> Native<'_, Vec<Event>> {
        match self {
            Self::Mld(device) => {
                Box::pin(device.p2p_roc_request(request, cookie, frequency, duration, activity))
            }
            Self::Mvm(device) => Box::pin(
                device.p2p_roc_request(request, cookie, frequency, duration, activity, power),
            ),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_cancel_request<'a>(
        &'a self,
        request: &'a Request,
        cookie: u64,
    ) -> Native<'a, Vec<Event>> {
        match self {
            Self::Mld(device) => Box::pin(device.p2p_cancel_request(request, cookie)),
            Self::Mvm(device) => Box::pin(device.p2p_cancel_request(request, cookie)),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_frame_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frame: narf_wireless::MgmtTxRequest,
        power: Option<PowerSource>,
    ) -> Native<'_, (bool, Vec<Event>)> {
        match self {
            Self::Mld(device) => Box::pin(device.p2p_frame_request(request, cookie, frame)),
            Self::Mvm(device) => Box::pin(device.p2p_frame_request(request, cookie, frame, power)),
        }
    }
    #[inline(never)]
    pub(in crate::iwlwifi) fn p2p_service_native(&self) -> Native<'_, (bool, Vec<Event>)> {
        match self {
            Self::Mld(device) => Box::pin(device.p2p_service_native()),
            Self::Mvm(device) => Box::pin(device.p2p_service_native()),
        }
    }
    pub(in crate::iwlwifi) async fn finished(&self) -> (bool, Vec<Arc<Request>>) {
        match self {
            Self::Mld(device) => {
                let mut state = device.state.lock().await;
                (
                    state.hardware.p2p_started(),
                    state.hardware.p2p_take_retired(),
                )
            }
            Self::Mvm(device) => device.p2p_finished().await,
        }
    }
    pub(in crate::iwlwifi) fn p2p_event_current(&self, event: &Event) -> bool {
        match self {
            Self::Mld(device) => device.p2p_event_current(event),
            Self::Mvm(device) => device.p2p_event_current(event),
        }
    }
    pub(in crate::iwlwifi) fn p2p_result_current(
        &self,
        request: &Request,
        roc: Option<(u64, u32)>,
    ) -> bool {
        match self {
            Self::Mld(device) => device.p2p_result_current(request, roc),
            Self::Mvm(device) => device.p2p_result_current(request, roc),
        }
    }
}
