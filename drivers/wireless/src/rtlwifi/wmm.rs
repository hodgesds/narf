//! RTL8188EE source rtl_get_hal_edca_param/rtl88ee HW_VAR_ACM_CTRL.
use super::{firmware_transport::Io, prepare::Error};
use narf_wireless::wmm::Parameters;
pub(super) fn admit(p: Parameters, short: bool) -> Result<[u32; 4], Error> {
    if p.ac[0].admission_control
        || p.ac.iter().any(|a| {
            a.ecw_min == 0
                || a.ecw_min > 15
                || a.ecw_max > 15
                || a.ecw_min > a.ecw_max
                || a.aifsn < 2
                || a.aifsn > 15
        })
    {
        return Err(Error::Packet);
    }
    let mut words = [0; 4];
    for (index, a) in p.ac.iter().enumerate() {
        let min = if index == 0 {
            a.ecw_min.max(5)
        } else {
            a.ecw_min
        };
        let max = if index == 0 {
            a.ecw_max.max(10)
        } else {
            a.ecw_max
        };
        let aifsn = if index == 0 { a.aifsn.max(3) } else { a.aifsn };
        let aifs = u32::from(aifsn) * if short { 9 } else { 20 } + 10;
        if aifs > 255 {
            return Err(Error::Packet);
        }
        let txop = if index == 0 { 0 } else { a.txop };
        words[index] = u32::from(txop) << 16 | u32::from(max) << 12 | u32::from(min) << 8 | aifs;
    }
    Ok(words)
}
pub(super) fn program(io: &impl Io, p: Parameters, short: bool) -> Result<(), Error> {
    let words = admit(p, short)?; // Reject every row before the first write.
    for (reg, value) in [0x508, 0x50c, 0x504, 0x500].into_iter().zip(words) {
        io.write32(reg, value)?;
        if io.read32(reg)? != value {
            return Err(Error::Readback);
        }
    }
    let acm = io.read8(0x5c0)? & !0x0e;
    io.write8(0x5c0, acm)?;
    if io.read8(0x5c0)? != acm {
        return Err(Error::Readback);
    }
    Ok(())
}
