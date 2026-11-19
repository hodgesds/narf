//! Source-cited fixed WMI PS packets over the retained native HTC/CE owner.
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
pub(super) type Policy =
    Arc<narf_lib::sync::IrqSafeSpinLock<Option<narf_wireless::reg::RegulatoryDomain>>>;
pub(super) struct Fixture {
    pub expected: VecDeque<Vec<u8>>,
    pub seen: usize,
    pub mode: Option<bool>,
    pub hold: Option<(usize, Arc<AtomicBool>)>,
    pub fail: Option<usize>,
    pub change: Option<(usize, Policy)>,
}
impl core::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativePowerSave")
            .field("seen", &self.seen)
            .field("mode", &self.mode)
            .finish()
    }
}
fn ids(dialect: Dialect) -> (u32, u32) {
    // Linux wmi.h enums: five-six-six-seven BA/management predecessors.
    match dialect {
        Dialect::Main | Dialect::Tlv => (0x9001, 0x9002),
        Dialect::TenOne => (0x902f, 0x9030),
        Dialect::TenTwo | Dialect::TenTwoFour => (0x9030, 0x9031),
        Dialect::TenFour => (0x9039, 0x903a),
    }
}
fn packet(dialect: Dialect, parameter: Option<(u32, u32)>, enabled: bool) -> Vec<u8> {
    let (mode, param) = ids(dialect);
    let mut bytes = if let Some((p, v)) = parameter {
        [param, 0, p, v]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        [mode, 0, u32::from(enabled)]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    };
    if dialect == Dialect::Tlv {
        let header = if parameter.is_some() {
            (109u32 << 16) | 12
        } else {
            (108u32 << 16) | 8
        };
        bytes.splice(4..4, header.to_le_bytes());
    }
    bytes
}
pub(super) fn handles(dialect: Dialect, bytes: &[u8]) -> bool {
    let Some(id) = bytes.get(..4) else {
        return false;
    };
    let id = u32::from_le_bytes(id.try_into().unwrap());
    let ids = ids(dialect);
    id == ids.0 || id == ids.1
}
impl Fixture {
    pub(super) fn new(dialect: Dialect, enabled: bool) -> Self {
        let mut fixture = Self {
            expected: VecDeque::new(),
            seen: 0,
            mode: None,
            hold: None,
            fail: None,
            change: None,
        };
        fixture.queue(dialect, enabled);
        fixture
    }
    pub(super) fn queue(&mut self, dialect: Dialect, enabled: bool) {
        if enabled {
            for fields in [(0, 0), (1, 1), (2, 0), (4, 0), (3, 100)] {
                self.expected.push_back(packet(dialect, Some(fields), true));
            }
        }
        self.expected.push_back(packet(dialect, None, enabled));
    }
}
pub(super) async fn send(model: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let dialect = model.inner.inner.dialect;
    if model.ps.is_none() {
        // The normal station fixture requires one actual awake-mode submission
        // before carrier. No parameter/enabled packet or duplicate is admitted.
        if model.ps_default_off || bytes[8..] != packet(dialect, None, false) {
            return Err(BmiError::BadResponse);
        }
        model.ps_default_off = true;
        model.sent.push(bytes.to_vec());
        model
            .inner
            .inner
            .rx
            .push_back((2, vec![2, 2, 8, 0, 8, 0, 0, 0, 1, 4, 0, 0, 2, 1, 0, 0]));
        return Ok(());
    }
    let f = model.ps.as_mut().unwrap();
    let at = f.seen;
    f.seen += 1;
    if f.expected.pop_front().as_deref() != Some(&bytes[8..]) {
        return Err(BmiError::BadResponse);
    }
    model.sent.push(bytes.to_vec());
    if f.fail == Some(at) {
        return Err(BmiError::BadResponse);
    }
    if let Some((step, policy)) = &f.change {
        if *step == at {
            *policy.lock() = None;
        }
    }
    if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) == ids(dialect).0 {
        f.mode = Some(u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) == 1);
    }
    model
        .inner
        .inner
        .rx
        .push_back((2, vec![2, 2, 8, 0, 8, 0, 0, 0, 1, 4, 0, 0, 2, 1, 0, 0]));
    if let Some((step, hold)) = &f.hold {
        if *step == at {
            core::future::poll_fn(|cx| {
                if hold.load(Ordering::Acquire) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
    }
    Ok(())
}
