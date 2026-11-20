// SPDX-License-Identifier: GPL-2.0-only
//! AE HT20 source helpers, admitted only by a distinct NASR2 program.
//! Linux rtlwifi/base.c::_rtl_init_hw_ht_capab and rtl8723ae/hw.c
//! HW_VAR_SHORTGI_DENSITY/AMPDU_FACTOR/AMPDU_MIN_SPACE. DMA bounds narrow
//! the source's optional7935-byte A-MSDU promise to3839 bytes.
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

pub const MCS0_7: u64 = 0xff << 12;
pub const LONGEST_RX: usize = 3839 + 26 + 16 + 4;

pub fn capability() -> LocalHt {
    LocalHt::new(
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        HtWidth::Twenty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: false,
            tx40: false,
        },
        3,
        7,
    )
    .expect("fixed AE one-stream HT20")
}
pub fn local() -> LocalPhy {
    LocalPhy::ht20(capability()).expect("fixed AE HT20 geometry")
}

/// The actual AE hardware type is BT_RTL8723A, so hw.c's CSR_BC4
/// aggregation-length row is unreachable. No BE chip recipe is borrowed.
pub fn timing(io: &impl Io, min_space: &mut u8, factor: u8, density: u8) -> Result<(), Error> {
    if factor > 3 || density > 7 {
        return Err(Error::State);
    }
    // base.c passes max_mss_density=0 for RF_1T1R, retaining other bits.
    io.write8(0x45c, *min_space)?;
    let mut lengths = [0x41u8, 0xa8, 0x72, 0xb9];
    let limit = (1u8 << (factor + 2)).min(15);
    for (index, value) in lengths.iter_mut().enumerate() {
        if *value & 0xf0 > limit << 4 {
            *value = (*value & 15) | (limit << 4);
        }
        if *value & 15 > limit {
            *value = (*value & 0xf0) | limit;
        }
        io.write8(0x458 + index as u16, *value)?;
    }
    // mac.current_ampdu_density starts at7 and takes max(peer), as source.
    *min_space = (*min_space & 0xf8) | density.max(7);
    io.write8(0x45c, *min_space)?;
    Ok(())
}
