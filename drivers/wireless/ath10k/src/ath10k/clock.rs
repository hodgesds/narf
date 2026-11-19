// SPDX-License-Identifier: GPL-2.0-or-later
//! QCA6174 hw3.2 / QCA9377 hw1.1 ROM clock setup. Ordering follows
//! Linux ath10k/hw.c::ath10k_hw_qca6174_enable_pll_clock exactly.

use super::bmi::{Bmi, BmiError, Transport};

// EFUSE_XTAL_SEL indexes qca6174_clk, not the PCI device revision.
// (divider, fractional divider, settle time), with refdiv=0/outdiv=1.
const CLOCKS: [(u32, u32, u32); 8] = [
    (0x0e, 0x2aaa8, 2400),
    (0x24, 0x2aaa8, 960),
    (0x1d, 0x15551, 1200),
    (0x1b, 0x04ec4, 1300),
    (0x12, 0x34b49, 1870),
    (0x12, 0x15551, 1920),
    (0x12, 0x26665, 2000),
    (0x1b, 0x04ec4, 2600),
];

async fn settled<T: Transport>(bmi: &mut Bmi<T>) -> Result<(), BmiError> {
    let deadline = narf_time::Deadline::after_ms(1000);
    loop {
        if bmi.read_soc(0x1244).await? & 0x20 == 0 {
            return Ok(());
        }
        if deadline.expired() {
            return Err(BmiError::Timeout);
        }
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(10_000)).await;
    }
}

pub(super) async fn enable<T: Transport>(bmi: &mut Bmi<T>) -> Result<(), BmiError> {
    let xtal = (bmi.read_soc(0xb2c).await? >> 8) & 7;
    let &(divider, fraction, settle) = CLOCKS.get(xtal as usize).ok_or(BmiError::Unsupported)?;
    let value = bmi.read_soc(0xaf4).await?;
    bmi.write_soc(0xaf4, (value & !0x1f_ffff) | fraction | (1 << 18))
        .await?;
    let value = bmi.read_soc(0x1018).await?;
    bmi.write_soc(0x1018, (value & !0x7ff) | (settle & 0x7ff))
        .await?;
    let value = bmi.read_soc(0x914).await?;
    bmi.write_soc(0x914, (value & !7) | 1).await?;
    bmi.write_u32(0x404028, 1).await?;

    let value = bmi.read_soc(0x1014).await?;
    bmi.write_soc(0x1014, value | divider | (1 << 18)).await?;
    settled(bmi).await?;
    let value = bmi.read_soc(0x1014).await?;
    bmi.write_soc(0x1014, value & !(1 << 16)).await?;
    settled(bmi).await?;
    let value = bmi.read_soc(0x820).await?;
    bmi.write_soc(0x820, (value & !3) | 1).await?;
    let value = bmi.read_soc(0x1014).await?;
    bmi.write_soc(0x1014, value & !(1 << 18)).await?;
    bmi.write_u32(0x404020, 1).await?;
    bmi.write_u32(0x404024, 176_000_000).await?;
    Ok(())
}
