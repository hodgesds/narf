//! Apply early Ethernet name assignments before drivers publish their netdevs.

use alloc::{string::String, vec::Vec};
use narf_boot::KernelCmdline;

fn parse_mapping(value: &str) -> Option<(&str, [u8; 6])> {
    let (name, address) = value.split_once(':')?;
    let index = name.strip_prefix("eth")?;
    if index.is_empty()
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
    {
        return None;
    }
    index.parse::<u32>().ok()?;

    let mut mac = [0; 6];
    let mut parts = address.split(':');
    for octet in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        *octet = u8::from_str_radix(part, 16).ok()?;
    }
    (parts.next().is_none() && mac != [0; 6] && mac[0] & 1 == 0).then_some((name, mac))
}

pub(super) fn allocate(
    args: KernelCmdline<'_>,
    pattern: &str,
    mac: Option<[u8; 6]>,
    occupied: impl Fn(&str) -> bool,
) -> String {
    let Some((prefix, suffix)) = pattern.split_once("%d") else {
        return String::from(pattern);
    };
    let mut mappings = Vec::new();
    if pattern == "eth%d" {
        for token in args.tokens() {
            let Some((name, address)) = token.strip_prefix("ifname=").and_then(parse_mapping)
            else {
                continue;
            };
            if !mappings.iter().any(|&(n, a)| n == name || a == address) {
                mappings.push((name, address));
            }
        }
        if let Some(&(name, _)) = mappings
            .iter()
            .find(|&&(n, a)| Some(a) == mac && !occupied(n))
        {
            return String::from(name);
        }
    }
    (0u32..)
        .map(|n| alloc::format!("{prefix}{n}{suffix}"))
        .find(|candidate| !occupied(candidate) && mappings.iter().all(|&(n, _)| n != candidate))
        .unwrap_or_default()
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_boot_mac_names() -> TestResult {
        let args = KernelCmdline::new(concat!(
            "ifname=eth1:02:00:00:00:00:AB ifname=eth0:02:00:00:00:00:bc ",
            "ifname=eth3:02:00:00:00:00:ab ifname=eth0:02:00:00:00:00:99"
        ));
        let nic = Some([2, 0, 0, 0, 0, 0xab]);
        let other = Some([2, 0, 0, 0, 0, 0x99]);
        if allocate(args, "eth%d", nic, |_| false) != "eth1"
            || allocate(args, "eth%d", other, |_| false) != "eth2"
            || allocate(args, "eth%d", None, |_| false) != "eth2"
            || allocate(args, "eth%d", nic, |name| name == "eth1") != "eth2"
            || allocate(args, "eth%d", None, |name| name == "eth2") != "eth3"
            || allocate(args, "wlan%d", nic, |_| false) != "wlan0"
            || allocate(args, "eth0", nic, |_| true) != "eth0"
        {
            return TestResult::Fail("boot name assignment, reservation, or collision");
        }
        for invalid in [
            "eth01:02:00:00:00:00:ab",
            "lo:02:00:00:00:00:ab",
            "eth0:00:00:00:00:00:00",
            "eth0:01:02:03:04:05:06",
            "eth0:02:00:00:00:00",
            "eth0:02:00:00:00:00:ab:22",
            "eth0:+1:00:00:00:00:ab",
            "eth4294967296:02:00:00:00:00:ab",
        ] {
            if parse_mapping(invalid).is_some() {
                return TestResult::Fail("invalid boot MAC or interface name accepted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("net/iface", smoke_boot_mac_names);
}
