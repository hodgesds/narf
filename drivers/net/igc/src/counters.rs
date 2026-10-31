//! Accumulated clear-on-read counters from Linux igc_regs.h (ecd997b0189a).
use super::hardware::Registers;
use alloc::{string::String, vec::Vec};
#[derive(Debug)]
pub(crate) struct Counters {
    totals: [u64; COUNTERS.len()],
    pub drops: [u64; 4],
    merge_errors: [u64; 4],
}
const COUNTERS: &[(&str, u64, bool)] = &[
    ("hw_crcerrs", 0x04000, false),
    ("hw_algnerrc", 0x04004, false),
    ("hw_rxerrc", 0x0400C, false),
    ("hw_mpc", 0x04010, false),
    ("hw_scc", 0x04014, false),
    ("hw_ecol", 0x04018, false),
    ("hw_mcc", 0x0401C, false),
    ("hw_latecol", 0x04020, false),
    ("hw_colc", 0x04028, false),
    ("hw_rerc", 0x0402C, false),
    ("hw_dc", 0x04030, false),
    ("hw_tncrs", 0x04034, false),
    ("hw_htdpmc", 0x0403C, false),
    ("hw_rlec", 0x04040, false),
    ("hw_xonrxc", 0x04048, false),
    ("hw_xontxc", 0x0404C, false),
    ("hw_xoffrxc", 0x04050, false),
    ("hw_xofftxc", 0x04054, false),
    ("hw_fcruc", 0x04058, false),
    ("hw_prc64", 0x0405C, false),
    ("hw_prc127", 0x04060, false),
    ("hw_prc255", 0x04064, false),
    ("hw_prc511", 0x04068, false),
    ("hw_prc1023", 0x0406C, false),
    ("hw_prc1522", 0x04070, false),
    ("hw_gprc", 0x04074, false),
    ("hw_bprc", 0x04078, false),
    ("hw_mprc", 0x0407C, false),
    ("hw_gptc", 0x04080, false),
    ("hw_gorcl", 0x04088, true),
    ("hw_gotcl", 0x04090, true),
    ("hw_rnbc", 0x040A0, false),
    ("hw_ruc", 0x040A4, false),
    ("hw_rfc", 0x040A8, false),
    ("hw_roc", 0x040AC, false),
    ("hw_rjc", 0x040B0, false),
    ("hw_mgtprc", 0x040B4, false),
    ("hw_mgtpdc", 0x040B8, false),
    ("hw_mgtptc", 0x040BC, false),
    ("hw_torl", 0x040C0, true),
    ("hw_totl", 0x040C8, true),
    ("hw_tpr", 0x040D0, false),
    ("hw_tpt", 0x040D4, false),
    ("hw_ptc64", 0x040D8, false),
    ("hw_ptc127", 0x040DC, false),
    ("hw_ptc255", 0x040E0, false),
    ("hw_ptc511", 0x040E4, false),
    ("hw_ptc1023", 0x040E8, false),
    ("hw_ptc1522", 0x040EC, false),
    ("hw_mptc", 0x040F0, false),
    ("hw_bptc", 0x040F4, false),
    ("hw_tsctc", 0x040F8, false),
    ("hw_iac", 0x04100, false),
    ("hw_rpthc", 0x04104, false),
    ("hw_tlpic", 0x04148, false),
    ("hw_rlpic", 0x0414C, false),
    ("hw_hgptc", 0x04118, false),
    ("hw_rxdmtc", 0x04120, false),
    ("hw_hgorcl", 0x04128, true),
    ("hw_hgotcl", 0x04130, true),
    ("hw_lenerrs", 0x04138, false),
    ("macmerge_assembly_ok", 0x4284, false),
    ("macmerge_tx_fragments", 0x4298, false),
    ("macmerge_rx_fragments", 0x429c, false),
];
impl Counters {
    pub const fn new() -> Self {
        Self {
            totals: [0; COUNTERS.len()],
            drops: [0; 4],
            merge_errors: [0; 4],
        }
    }
    pub fn sample(&mut self, r: &impl Registers, queues: usize, discard: bool) -> (u64, u64, u64) {
        let mut crc = 0;
        let mut missed = 0;
        let mut fifo = 0;
        for (i, &(_, reg, pair)) in COUNTERS.iter().enumerate() {
            let lo = r.read(reg);
            let hi = if pair { r.read(reg + 4) } else { 0 };
            if lo == u32::MAX && hi == u32::MAX {
                continue;
            }
            let value = u64::from(lo) | (u64::from(hi) << 32);
            if !discard {
                self.totals[i] = self.totals[i].wrapping_add(value);
                match reg {
                    0x4000 => crc = value,
                    0x4010 => missed = value,
                    _ => {}
                }
            }
        }
        let errors = r.read(0x42a0);
        if !discard && errors != u32::MAX {
            for i in 0..4 {
                self.merge_errors[i] += u64::from((errors >> (i * 8)) & 255);
            }
        }
        for q in 0..queues {
            let reg = 0xc030 + q as u64 * 0x40;
            let v = r.read(reg);
            r.write(reg, 0);
            if !discard && v != u32::MAX {
                self.drops[q] += u64::from(v);
                fifo += u64::from(v);
            }
        }
        (crc, missed, fifo)
    }
    pub fn value(&self, reg: u64) -> u64 {
        COUNTERS
            .iter()
            .position(|c| c.1 == reg)
            .map_or(0, |i| self.totals[i])
    }
    pub fn snapshot(&self) -> Vec<narf_net::nic::Statistic> {
        let mut out = COUNTERS
            .iter()
            .enumerate()
            .map(|(i, c)| narf_net::nic::Statistic {
                name: String::from(c.0),
                value: self.totals[i],
            })
            .collect::<Vec<_>>();
        for (name, value) in [
            "macmerge_smd_errors",
            "macmerge_frame_count_errors",
            "macmerge_frag_count_errors",
            "macmerge_missing_frame_frag",
        ]
        .into_iter()
        .zip(self.merge_errors)
        {
            out.push(narf_net::nic::Statistic {
                name: String::from(name),
                value,
            });
        }
        for (q, &value) in self.drops.iter().enumerate() {
            out.push(narf_net::nic::Statistic {
                name: alloc::format!("queue_{q}_rx_fifo_errors"),
                value,
            });
        }
        out
    }
}
