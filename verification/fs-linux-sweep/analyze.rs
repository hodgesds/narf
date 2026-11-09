//! Reuse the repository's tested §8 statistics, rather than a second implementation.
#[path = "../../build/xtask/src/bench_stats.rs"]
mod bench_stats;

use bench_stats::{benjamini_hochberg, delta_pct_ci, mann_whitney_u, summarize, welch_t_test};
use std::collections::BTreeMap;
use std::io::{self, Read};

fn summary_json(s: bench_stats::Summary) -> String {
    format!(
        "{{\"n\":{},\"median\":{},\"median_ci\":[{},{}],\"mean\":{},\"mean_ci\":[{},{}],\"p95\":{},\"p99\":{},\"p999\":{},\"cv\":{},\"min\":{},\"max\":{}}}",
        s.n, s.median, s.median_ci.0, s.median_ci.1, s.mean, s.mean_ci.0, s.mean_ci.1,
        s.p95, s.p99, s.p999, s.cv, s.min, s.max
    )
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut groups: BTreeMap<(String, String), BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    let mut contracts = BTreeMap::new();
    for line in input.lines() {
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 6, "expected fs, case, side, cycles, work, unit");
        assert!(v[..3]
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')));
        assert!(v[2] == "narf" || v[2] == "linux");
        let value: f64 = v[3].parse().unwrap();
        assert!(value.is_finite() && value > 0.0);
        let work: u64 = v[4].parse().unwrap();
        assert!(work > 0 && ["bytes", "operations", "entries"].contains(&v[5]));
        let key = (v[0].to_owned(), v[1].to_owned());
        if let Some(previous) = contracts.insert(key.clone(), (work, v[5].to_owned())) {
            assert_eq!(previous, (work, v[5].to_owned()));
        }
        groups
            .entry(key)
            .or_default()
            .entry(v[2].to_owned())
            .or_default()
            .push(value);
    }
    assert!(!groups.is_empty(), "no measurement groups supplied");
    let mut rows = Vec::new();
    let mut welch_ps = Vec::new();
    let mut mwu_ps = Vec::new();
    let mut sufficient = true;
    for ((fs, name), sides) in groups {
        let linux = &sides["linux"];
        let narf = &sides["narf"];
        assert!(linux.len() >= 2 && narf.len() >= 2);
        let l = summarize(linux, 10000, 1729);
        let n = summarize(narf, 10000, 1730);
        sufficient &=
            l.n >= 30 && n.n >= 30 && (l.cv <= 0.05 && n.cv <= 0.05 || l.n >= 100 && n.n >= 100);
        let (p, logged) = welch_t_test(linux, narf);
        let mwu = mann_whitney_u(linux, narf);
        let (delta, ci) = delta_pct_ci(linux, narf, 10000, 1731);
        assert!(p.is_finite() && mwu.is_finite());
        welch_ps.push(p);
        mwu_ps.push(mwu);
        let (work, unit) = &contracts[&(fs.clone(), name.clone())];
        rows.push((format!(
            "{{\"fs\":\"{fs}\",\"case\":\"{name}\",\"unit\":\"invariant_tsc_cycles\",\"lower_is_better\":true,\"work\":{work},\"work_unit\":\"{unit}\",\"linux\":{},\"narf\":{},\"narf_linux_ratio\":{},\"narf_linux_ratio_ci\":[{},{}],\"welch_p\":{p},\"welch_logged\":{logged},\"mwu_p\":{mwu}",
            summary_json(l), summary_json(n), 1.0 + delta / 100.0,
            1.0 + ci.0 / 100.0, 1.0 + ci.1 / 100.0
        ), ci));
    }
    let w = benjamini_hochberg(&welch_ps, 0.05);
    let m = benjamini_hochberg(&mwu_ps, 0.05);
    println!("{{\"sample_size_sufficient\":{sufficient},\"bootstrap_resamples\":10000,\"bh_q\":0.05,\"delta_percent\":3,\"series\":[");
    for (i, (row, ci)) in rows.iter().enumerate() {
        let decision = if w[i] != m[i] {
            "inconclusive"
        } else if !w[i] {
            "not-significant"
        } else if ci.0 > 3.0 {
            "narf-slower"
        } else if ci.1 < -3.0 {
            "narf-faster"
        } else {
            "significant-within-delta"
        };
        println!("{row},\"welch_bh_significant\":{},\"mwu_bh_significant\":{},\"decision\":\"{decision}\"}}{}",
            w[i], m[i], if i + 1 == rows.len() { "" } else { "," });
    }
    println!("]}}");
}
