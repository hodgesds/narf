//! Exact actual generic socket source; never keep SocketFile alive for an AP.
use super::*;
impl GenericReplyEndpoint {
    pub(super) fn capture(socket: &Arc<SocketFile>, portid: u32) -> Self {
        Self {
            socket: Arc::downgrade(socket),
            namespace: socket.net_ns_id(),
            portid,
            source: socket.native_source.lock().observe(),
        }
    }
    pub(super) fn native_source_guard(&self) -> Option<narf_net::native_emission::Lifetime> {
        use narf_net::netlink_generic::DeferredReplySink;
        if !self.current() || self.portid == 0 {
            return None;
        }
        if !self.current() || !self.source.current() {
            return None;
        }
        Some(self.source.clone())
    }
}
