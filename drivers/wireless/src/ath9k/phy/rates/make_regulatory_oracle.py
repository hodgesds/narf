#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Independent native regulatory C oracle; see ORACLE.md. No Rust resolver."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
parser = argparse.ArgumentParser(description="Reproduce native Atheros EEPROM identity and initial CTL exhaustive hashes")
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
parser.add_argument("--out", type=Path)
parser.add_argument("--cc", default="cc")
args = parser.parse_args()
workspace = tempfile.TemporaryDirectory(prefix="narf-ath9k-regulatory-oracle-") if args.out is None else None
o = args.out if args.out is not None else Path(workspace.name)
o.mkdir(parents=True, exist_ok=True)
p = args.linux / "drivers/net/wireless/ath"
h=(p/'regd.h').read_text();common=(p/'regd_common.h').read_text();c=(p/'regd.c').read_text()
def decl(s,patt,end=';'):
 m=re.search(patt,s);assert m,patt
 i=s.index('{',m.start())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 if end:i=s.index(end,i)+len(end)
 return s[m.start():i]
def func(name):
 m=re.search((r'(?m)^u32 ' if name=='ath_regd_get_band_ctl' else r'(?m)^static ')+r'[^{;}]*?\b'+name+r'\([^;]+?\n\{',c);assert m,name
 i=m.end();d=1
 while d:d+=(c[i]=='{')-(c[i]=='}');i+=1
 return c[m.start():i]
header='''#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#define u16 uint16_t\n#define u32 uint32_t\n#define WORLD_SKU_MASK 0x00f0\n#define WORLD_SKU_PREFIX 0x0060\nenum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ };\nenum nl80211_dfs_regions { NL80211_DFS_UNSET, NL80211_DFS_FCC, NL80211_DFS_ETSI, NL80211_DFS_JP };
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define printk(...) ((void)0)
#define pr_err(...) ((void)0)
#define EINVAL 22
#define CTRY_DEBUG 0x1ff
#define CTRY_DEFAULT 0
#define NO_CTL 0xff\n#define SD_NO_CTL 0xe0
#define COUNTRY_ERD_FLAG 0x8000
#define WORLDWIDE_ROAMING_FLAG 0x4000
struct reg_dmn_pair_mapping {u16 reg_domain,reg_5ghz_ctl,reg_2ghz_ctl;};
struct country_code_to_enum_rd {u16 countryCode,regDmnEnum;const char *isoName;};
struct ath_regulatory {u16 current_rd,country_code;struct reg_dmn_pair_mapping *regpair;char alpha2[2]; enum nl80211_dfs_regions region;};
'''
header+='\n'.join([decl(h,r'enum ctl_group\s*\{'),decl(h,r'enum CountryCode\s*\{'),decl(common,r'enum EnumRd\s*\{'),decl(common,r'static struct reg_dmn_pair_mapping\s+regDomainPairs\[\]\s*=\s*\{'),decl(common,r'static struct country_code_to_enum_rd\s+allCountries\[\]\s*=\s*\{')])+'\n'
code=header+'\n'.join(func(n) for n in ['ath_regd_get_eepromRD','ath_regd_is_eeprom_valid','ath_regd_find_country','ath_regd_find_country_by_rd','ath_regd_get_default_country','ath_get_regpair','ath_regd_sanitize','__ath_regd_init','is_wwr_sku','ath_regd_get_band_ctl'])
code+='''
static uint64_t hash=0xcbf29ce484222325ULL;
static void byte(unsigned v){hash=(hash^(v&255))*0x100000001b3ULL;}
static void word(unsigned v){byte(v);byte(v>>8);}
int main(void){
 unsigned success=0;
 for(unsigned input=0;input<65536;input++){
  struct ath_regulatory r={.current_rd=input};
  if(__ath_regd_init(&r)){byte(0);continue;}
  success++;byte(1);word(r.current_rd);word(r.country_code);word(r.regpair->reg_domain);word(r.regpair->reg_5ghz_ctl);word(r.regpair->reg_2ghz_ctl);byte(r.alpha2[0]);byte(r.alpha2[1]);
 }
 printf("FACTORY %016llx %u\\n",(unsigned long long)hash,success);
 hash=0xcbf29ce484222325ULL;success=0;
 for(unsigned input=0;input<65536;input++){
  struct ath_regulatory r={.current_rd=input};
  if(__ath_regd_init(&r)){byte(0);continue;}
  success++;byte(1);word(ath_regd_get_band_ctl(&r,NL80211_BAND_2GHZ)|2);
 }
 printf("HASH %016llx %u\\n",(unsigned long long)hash,success);
}
'''
(o/'regulatory_oracle.c').write_text(code)

functions = ['ath_regd_get_eepromRD','ath_regd_is_eeprom_valid','ath_regd_find_country','ath_regd_find_country_by_rd','ath_regd_get_default_country','ath_get_regpair','ath_regd_sanitize','__ath_regd_init','is_wwr_sku','ath_regd_get_band_ctl']
provenance = {
    "reference": "local Linux drivers/net/wireless/ath",
    "extraction": "Unmodified native C regulatory initialization/helpers, tables and initial DFS-unset band CTL selector.",
    "sources": {name: hashlib.sha256((p/name).read_bytes()).hexdigest() for name in ['regd.h','regd_common.h','regd.c']},
    "extracted_function_sha256": {name: hashlib.sha256(func(name).encode()).hexdigest() for name in functions},
}
(o/'provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True)+'\n')
expected = Path(__file__).with_name('regulatory_oracle_provenance.json')
if expected.exists() and json.loads(expected.read_text()) != provenance:
    raise SystemExit("Linux regulatory source/function provenance changed; inspect generated provenance.json")
subprocess.run([args.cc,'-std=gnu11','-O2',str(o/'regulatory_oracle.c'),'-o',str(o/'regulatory_oracle')],check=True)
output = subprocess.check_output([str(o/'regulatory_oracle')],text=True)
(o/'hashes.txt').write_text(output)
if output != 'FACTORY ec8104beec6e96fc 611\nHASH 6ddb71ef849e3ba2 611\n':
    raise SystemExit('Independent exhaustive Linux regulatory hashes changed: '+output)
print('PASS: all 65,536 EEPROM inputs match Factory and initial-CTL hashes (611 valid)')
