#!/usr/bin/env python3
"""Run the network collector against fake PCI/netdev state and query tools."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('narf-network-capture').resolve()


class NetworkCapture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / 'bin'
        self.tools.mkdir()
        self.log = self.root / 'queries'
        self.sys = self.root / 'sys'
        self.proc = self.root / 'proc'
        for relative, value in {
            'bus/pci/devices/0000:0e:00.0/class': '0x020000',
            'bus/pci/devices/0000:0e:00.0/vendor': '0x8086',
            'bus/pci/devices/0000:0e:00.0/device': '0x15f3',
            'bus/pci/devices/0000:0f:00.0/class': '0x028000',
            'bus/pci/devices/0000:0f:00.0/vendor': '0x14c3',
            'bus/pci/devices/0000:0f:00.0/device': '0x0616',
            'bus/pci/devices/0000:03:00.0/class': '0x030000',
            'bus/pci/devices/0000:06:0a.0/class': '0x060400',
            'bus/pci/devices/0000:06:0a.0/vendor': '0x1022',
            'class/net/eth0/ifindex': '2',
            'class/net/eth0/carrier': '1',
            'class/net/eth0/statistics/tx_packets': '7',
            'class/net/eth0/statistics/rx_packets': '0',
            'class/net/lo/ifindex': '1',
        }.items():
            path = self.sys / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + '\n')
        (self.proc / 'net').mkdir(parents=True)
        (self.proc / 'uptime').write_text('55.00 20.00\n')
        (self.proc / 'net/packet').write_text('fixture packet socket\n')
        (self.proc / 'net/udp').write_text('fixture DHCP socket\n')
        driver = self.sys / 'bus/pci/drivers/igc'
        driver.mkdir(parents=True)
        (self.sys / 'bus/pci/devices/0000:0e:00.0/driver').symlink_to(driver)
        (self.sys / 'class/net/eth0/device').symlink_to(
            self.sys / 'bus/pci/devices/0000:0e:00.0')
        for tool in ('ethtool', 'ip', 'nmcli', 'journalctl', 'lspci', 'iw', 'genl'):
            path = self.tools / tool
            path.write_text('''#!/usr/bin/bash
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >> "$QUERY_LOG"
if [ "$tool" = ethtool ]; then
    case "$STUB_MODE:$*" in
        unsupported:*' -i '*) exit 95 ;;
        stuck:*' -S '*) trap '' TERM; exec /usr/bin/sleep 30 ;;
    esac
fi
if [ "$tool" = iw ]; then
    case "$STUB_MODE:$*" in
        missing-wireless:*) exit 127 ;;
        stuck-wireless:dev) trap '' TERM; exec /usr/bin/sleep 30 ;;
    esac
fi
printf 'fixture %s result\n' "$tool"
''')
            path.chmod(0o755)
        self.environment = {
            **os.environ,
            'PATH': str(self.tools) + os.pathsep + os.environ['PATH'],
            'NARF_CAPTURE_SYSFS_ROOT': str(self.sys),
            'NARF_CAPTURE_PROCFS_ROOT': str(self.proc),
            'QUERY_LOG': str(self.log),
            'STUB_MODE': '',
        }

    def run_capture(self, mode=''):
        result = subprocess.run(
            ['bash', str(SCRIPT), '--once'],
            env={**self.environment, 'STUB_MODE': mode},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('===== network sample'), 1)
        return result.stdout

    def test_unbound_radio_and_nic_counters_survive_without_wlan(self):
        output = self.run_capture()
        self.assertIn('pci: 0000:0f:00.0\nvendor: 0x14c3\ndevice: 0x0616\ndriver: unbound', output)
        self.assertNotIn('pci: 0000:03:00.0', output)
        self.assertIn('tx_packets: 7', output)
        self.assertIn('rx_packets: 0', output)
        self.assertIn('fixture packet socket', output)
        self.assertIn('fixture DHCP socket', output)
        queries = self.log.read_text().splitlines()
        self.assertIn('ethtool --disable-netlink -d eth0', queries)
        self.assertIn('ethtool --disable-netlink -S eth0', queries)
        self.assertIn('lspci -tv', queries)
        self.assertIn('lspci -vvxxx -s 0000:06:0a.0', queries)
        self.assertIn('lspci -vvxxx -s 0000:0f:00.0', queries)
        self.assertNotIn('lspci -vvxxx -s 0000:03:00.0', queries)
        for query in queries:
            if query.startswith('ethtool '):
                self.assertIn(query, [
                    f'ethtool --disable-netlink {option}eth0'
                    for option in ('', '-i ', '-l ', '-g ', '-x ', '-k ', '-S ', '-d ')
                ])

    def test_unsupported_ioctl_does_not_hide_statistics_or_dhcp_logs(self):
        output = self.run_capture('unsupported')
        self.assertIn('query-exit: 95', output)
        self.assertIn('query: ethtool --disable-netlink -S eth0', output)
        self.assertIn('fixture journalctl result', output)

    def test_stuck_tool_is_killed_and_collection_continues(self):
        output = self.run_capture('stuck')
        # GNU timeout returns 137 when its TERM grace period expires and it
        # sends KILL. Following read-only queries must still run.
        self.assertIn('query-exit: 137', output)
        self.assertIn('query: ethtool --disable-netlink -d eth0', output)
        self.assertIn('fixture journalctl result', output)

    def test_wireless_discovery_records_netlink_and_sysfs_identity(self):
        for relative, value in {
            'class/net/wlan0/ifindex': '3',
            'class/net/wlan0/type': '1',
            'class/net/wlan0/uevent': 'INTERFACE=wlan0\nIFINDEX=3\nDEVTYPE=wlan',
            'class/ieee80211/phy0/index': '0',
            'class/ieee80211/phy0/name': 'phy0',
        }.items():
            path = self.sys / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + '\n')
        phy = self.sys / 'class/ieee80211/phy0'
        (self.sys / 'class/net/wlan0/phy80211').symlink_to(phy)
        output = self.run_capture()
        self.assertIn('DEVTYPE=wlan', output)
        self.assertIn(f'phy80211: {phy}', output)
        self.assertIn('phy-index: 0\nphy-name: phy0', output)
        queries = self.log.read_text().splitlines()
        for query in ('genl ctrl get name nl80211', 'iw dev', 'iw phy',
                      'iw reg get', 'iw dev wlan0 info'):
            self.assertEqual(queries.count(query), 1)
        self.assertNotIn('iw dev eth0 info', queries)
        self.assertNotIn('iw dev lo info', queries)

    def test_missing_wireless_tool_does_not_stop_collection(self):
        output = self.run_capture('missing-wireless')
        self.assertIn('query-exit: 127', output)
        self.assertIn('interface: eth0', output)
        self.assertIn('fixture journalctl result', output)

    def test_stuck_wireless_discovery_does_not_hide_later_evidence(self):
        output = self.run_capture('stuck-wireless')
        self.assertIn('query-exit: 137', output)
        self.assertIn('query: iw phy', output)
        self.assertIn('interface: eth0', output)
        self.assertIn('fixture journalctl result', output)


if __name__ == '__main__':
    unittest.main()
