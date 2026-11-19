//! Model TLV firmware WoW endpoint: records every GRP_WOW command, answers
//! WOW_ENABLE with the HTC endpoint-0 SEND_SUSPEND_COMPLETE and
//! WOW_HOSTWAKEUP_FROM_SLEEP with WOW_WAKEUP_HOST (`wmi-tlv.c`, `htc.c`);
//! the NLO config command (0x18001) is recorded with them.
use super::*;

#[derive(Debug, Default)]
pub(super) struct Fixture {
    /// `enum wmi_wow_wake_reason` reported after HOSTWAKEUP.
    pub reason: u32,
    /// Command payloads after the HTC header, in submission order.
    pub commands: Vec<Vec<u8>>,
}
pub(super) fn handles(model: &RadioModel, bytes: &[u8]) -> bool {
    model.wow.is_some()
        && model.inner.inner.dialect == Dialect::Tlv
        && bytes.get(..4).is_some_and(|id| {
            let id = u32::from_le_bytes(id.try_into().unwrap());
            // GRP_WOW, and the NLO_OFL config a net-detect suspend sends.
            (0x13001..=0x13005).contains(&id) || id == 0x18001
        })
}
pub(super) fn send(model: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let fixture = model.wow.as_mut().ok_or(BmiError::BadResponse)?;
    let id = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    fixture.commands.push(bytes[8..].to_vec());
    let reason = fixture.reason;
    model.sent.push(bytes.to_vec());
    // One WMI credit back, as every other native command fixture.
    model
        .inner
        .inner
        .rx
        .push_back((2, vec![2, 2, 8, 0, 8, 0, 0, 0, 1, 4, 0, 0, 2, 1, 0, 0]));
    match id {
        // ATH10K_HTC_MSG_SEND_SUSPEND_COMPLETE on endpoint 0 (CE pipe 1).
        0x13004 => model
            .inner
            .inner
            .rx
            .push_back((1, header(0, &[6, 0, 0, 0]))),
        0x13005 => {
            let mut info = Vec::new();
            for v in [0u32, 0, reason, 4] {
                info.extend_from_slice(&v.to_le_bytes());
            }
            let mut body = Vec::new();
            item(&mut body, 49, &info);
            item(&mut body, 17, &[0xde, 0xad, 0xbe, 0xef]);
            add_event(model, 0x13001, &body);
        }
        _ => {}
    }
    Ok(())
}
