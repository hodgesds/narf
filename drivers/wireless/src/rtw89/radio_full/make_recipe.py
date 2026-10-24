#!/usr/bin/env python3
"""Bind source full-radio orchestration and exact B MCC notification ABI."""
from pathlib import Path
import argparse,re,hashlib,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
source=''
for file,names in [('core.c',['__rtw89_set_channel']),('phy.c',['rtw89_phy_dm_init']),('rtw8852b.c',['rtw8852b_rfk_init','rtw8852b_rfk_channel']),('rtw8852b_rfk.c',['rtw8852b_mcc_get_ch_info']),('fw.c',['rtw89_fw_h2c_rf_ntfy_mcc']),('coex.c',['rtw89_btc_ntfy_preserve_bt_time','rtw89_btc_ntfy_conn_rfk'])]:
 s=(a.linux/file).read_text()
 for name in names:
  m=re.search(r'^(?:static\s+)?(?:int|void)\s+'+name+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
  while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
  source+=s[m.start():e]+'\n'
h=(a.linux/'fw.h').read_text();source+=re.search(r'^struct rtw89_fw_h2c_rf_get_mccch \{.*?__packed;',h,re.M|re.S).group(0)
source+='\ninitialBPHY0/ch1/20/RF_AB,TX-A1M;noV0_B_MCC;freshslot0ch1slot1ch0;conservative30msBTpreservationbeforeTSSIandDPK;CMAC_TXcloseduntilallsourceownerscompleteandcurrentmeasuredv2\n'
digest=hashlib.sha256(source.encode()).digest();out='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original B full-radio composition SHA256 '+digest.hex()+'\npub(super) const RECIPE:[u8;32]=['+','.join(map(str,digest))+'];\n';out=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=out.encode()).decode()
if a.check:
 if (d/'recipe.rs').read_text()!=out:raise SystemExit('full radio source recipe differs')
else:(d/'recipe.rs').write_text(out)
