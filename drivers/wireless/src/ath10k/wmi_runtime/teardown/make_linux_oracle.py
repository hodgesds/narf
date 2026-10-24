#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile complete native Linux station teardown generators and event layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def declaration(source, kind, name):
    match = re.search(r'\b' + kind + ' ' + name + r'\s*\{', source)
    assert match, name
    cursor = match.end()
    depth = 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[match.start():source.index(';', cursor) + 1] + '\n'


def function(source, name):
    match = re.search(r'(?m)^' + name + r'\(', source)
    assert match, name
    cursor = source.index('{', match.end()) + 1
    depth = 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return 'static struct sk_buff *\n' + source[match.start():cursor] + '\n'


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('linux', nargs='?', type=Path, default=Path('/usr/src/linux'))
parser.add_argument('--write', action='store_true')
parser.add_argument('--artifacts', type=Path)
args = parser.parse_args()
if sys.byteorder != 'little':
    raise SystemExit('native endian glue requires a little-endian host')
directory = args.linux / 'drivers/net/wireless/ath/ath10k'
sources = {name: (directory / name).read_text() for name in ('wmi.h', 'wmi-tlv.h', 'wmi.c', 'wmi-tlv.c')}
h, t, c, tc = [sources[name] for name in ('wmi.h', 'wmi-tlv.h', 'wmi.c', 'wmi-tlv.c')]
code = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __packed __attribute__((packed))
#define __le16 uint16_t
#define __le32 uint32_t
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define __cpu_to_le16(x) (x)
#define __cpu_to_le32(x) (x)
#define WMI_CMD_GRP(n) (((n)<<12)|1)
#define WMI_EVT_GRP_START_ID(n) (((n)<<12)|1)
#define WMI_TLV_CMD(n) (((n)<<12)|1)
#define WMI_TLV_EV(n) (((n)<<12)|1)
#define BIT(n) (1u<<(n))
#define ETH_ALEN 6
#define ERR_PTR(x) NULL
#define ath10k_dbg(...) ((void)0)
#define ether_addr_copy(d,s) memcpy(d,s,6)
struct ath10k { int unused; };
struct sk_buff {u8 *data; size_t len;};
static struct sk_buff *ath10k_wmi_alloc_skb(struct ath10k *ar, size_t len) {
 struct sk_buff *s=calloc(1,sizeof(*s));s->data=calloc(1,len);s->len=len;return s;
}
static void dump(const char *name,u32 id,struct sk_buff *s) {
 printf("%s",name);for(int i=0;i<4;i++)printf(" %02x",(id>>(8*i))&255);
 for(size_t i=0;i<s->len;i++)printf(" %02x",s->data[i]);puts("");free(s->data);free(s);
}
'''
for name in ['wmi_cmd_group', 'wmi_cmd_id', 'wmi_10x_cmd_id', 'wmi_10_2_cmd_id', 'wmi_10_4_cmd_id',
             'wmi_event_id', 'wmi_10x_event_id', 'wmi_10_2_event_id', 'wmi_10_4_event_id']:
    code += declaration(h, 'enum', name)
for name in ['wmi_tlv_grp_id', 'wmi_tlv_cmd_id', 'wmi_tlv_event_id', 'wmi_tlv_tag', 'wmi_tlv_service']:
    code += declaration(t, 'enum', name)
for name in ['wmi_mac_addr', 'wmi_vdev_stop_cmd', 'wmi_vdev_down_cmd', 'wmi_peer_delete_cmd',
             'wmi_vdev_stopped_event', 'wmi_peer_delete_resp_ev_arg']:
    code += declaration(h, 'struct', name)
code += declaration(t, 'struct', 'wmi_tlv')
for source, prefix in [(c, 'ath10k_wmi_op_gen_'), (tc, 'ath10k_wmi_tlv_op_gen_')]:
    for command in ['vdev_down', 'peer_delete', 'vdev_stop']:
        code += function(source, prefix + command)
code += 'int main(void) {struct ath10k ar={0};\n'
for suffix, enum, generator in [('MAIN', 'WMI_', 'ath10k_wmi_op_gen_'),
                                ('10X', 'WMI_10X_', 'ath10k_wmi_op_gen_'),
                                ('102', 'WMI_10_2_', 'ath10k_wmi_op_gen_'),
                                ('104', 'WMI_10_4_', 'ath10k_wmi_op_gen_'),
                                ('TLV', 'WMI_TLV_', 'ath10k_wmi_tlv_op_gen_')]:
    for short, command, arguments in [('DOWN', 'vdev_down', '0'),
                                      ('DELETE', 'peer_delete', '0,(u8[]){2,8,9,10,11,12}'),
                                      ('STOP', 'vdev_stop', '0')]:
        code += f'dump("{short}_{suffix}",{enum}{command.upper()}_CMDID,{generator}{command}(&ar,{arguments}));\n'
    code += '{struct sk_buff *s=ath10k_wmi_alloc_skb(&ar,' + ('8' if suffix == 'TLV' else '4') + ');'
    if suffix == 'TLV':
        code += 'struct wmi_tlv *tlv=(void*)s->data;tlv->len=4;tlv->tag=WMI_TLV_TAG_STRUCT_VDEV_STOPPED_EVENT;'
    code += f'dump("STOPPED_{suffix}",{enum}VDEV_STOPPED_EVENTID,s);}}\n'
code += '''
 struct sk_buff *s=ath10k_wmi_alloc_skb(&ar,16);
 struct wmi_tlv *tlv=(void*)s->data;tlv->len=sizeof(struct wmi_peer_delete_resp_ev_arg);tlv->tag=WMI_TLV_TAG_STRUCT_PEER_DELETE_RESP_EVENT;
 struct wmi_peer_delete_resp_ev_arg *ev=(void*)tlv->value;memcpy(ev->peer_addr.addr,(u8[]){2,8,9,10,11,12},6);
 dump("DELETE_RESPONSE_TLV",WMI_TLV_PEER_DELETE_RESP_EVENTID,s);
 printf("SYNC_SERVICE %u\\n",WMI_TLV_SERVICE_SYNC_DELETE_CMDS);
}
'''
with tempfile.TemporaryDirectory(prefix='narf-ath10k-teardown-') as temporary:
    output = args.artifacts or Path(temporary)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'oracle.c').write_text(code)
    subprocess.run(['cc', '-w', str(output / 'oracle.c'), '-o', str(output / 'oracle')], check=True)
    raw = subprocess.check_output([str(output / 'oracle')], text=True)
    (output / 'oracle.txt').write_text(raw)
    scalar = raw.splitlines()[-1]
    assert scalar.startswith('SYNC_SERVICE ')
    fixtures = {name: bytes.fromhex(value) for name, value in
                (line.split(maxsplit=1) for line in raw.splitlines()[:-1])}
    golden = '// Native Linux teardown generators, enum IDs and packed event declarations.\n'
    golden += '\n'.join(f'const {name}: &[u8] = &[{",".join(hex(b) for b in data)}];'
                        for name, data in fixtures.items()) + '\n'
    golden += f'const SYNC_SERVICE: usize = {scalar.split()[1]};\n'
    destination = Path(__file__).resolve().parent
    provenance = json.dumps({'linux_makefile': (args.linux / 'Makefile').read_text().splitlines()[:6],
                             'source_sha256': {name: hashlib.sha256(value.encode()).hexdigest()
                                               for name, value in sources.items()},
                             'oracle_c_sha256': hashlib.sha256(code.encode()).hexdigest(),
                             'fixtures': {name: {'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                                          for name, data in fixtures.items()},
                             'sync_delete_service': int(scalar.split()[1])}, indent=2) + '\n'
    if args.write:
        (destination / 'golden.rs').write_text(golden)
        (destination / 'provenance.json').write_text(provenance)
    recorded = (destination / 'golden.rs').read_text()
    expected = {name: bytes(int(byte.strip(), 0) for byte in values.split(',') if byte.strip())
                for name, values in re.findall(r'const (\w+): &\[u8\] = &\[(.*?)\];', recorded, re.S)}
    assert expected == fixtures, 'stale teardown golden bytes'
    assert int(re.search(r'const SYNC_SERVICE: usize = (\d+);', recorded).group(1)) == int(scalar.split()[1])
    assert (destination / 'provenance.json').read_text() == provenance, 'stale source provenance'
    (output / 'provenance.json').write_text(provenance)
    print(f'{len(fixtures)} native Linux teardown fixtures and sync-delete service match')
