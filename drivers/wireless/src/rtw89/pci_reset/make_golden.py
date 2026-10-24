#!/usr/bin/env python3
"""Compile unmodified Linux pending/FLR callbacks against inert trace shims."""
from pathlib import Path
import re
import subprocess
import tempfile

source = Path('/usr/src/linux/drivers/pci/pci.c').read_text()
regs = Path('/usr/src/linux/include/uapi/linux/pci_regs.h').read_text()


def function(name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


names = ['pci_wait_for_pending', 'pci_wait_for_pending_transaction', 'pcie_flr', 'pcie_reset_flr']
functions = '\n'.join(function(name) for name in names)
definitions = []
for name in ['PCI_EXP_DEVSTA', 'PCI_EXP_DEVSTA_TRPND', 'PCI_EXP_DEVCTL', 'PCI_EXP_DEVCTL_BCR_FLR', 'PCI_EXP_DEVCAP_FLR']:
    match = re.search(r'^#define\s+' + name + r'\s+([^/\n]+)', regs, re.M)
    definitions.append('#define ' + name + ' ' + match[1])
program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#define ENOTTY 25
#define PCI_DEV_FLAGS_NO_FLR_RESET 1
#define PCIE_RESET_READY_POLL_MS 60000
typedef uint16_t u16;
struct pci_dev { bool imm_ready; unsigned dev_flags,devcap; };
static unsigned now,clear_at,trigger,ready,count,times[4];
static bool pci_is_pcie(struct pci_dev*d){(void)d;return true;}
static int pci_pcie_cap(struct pci_dev*d){(void)d;return 0x40;}
static void pci_read_config_word(struct pci_dev*d,int p,u16*v){(void)d;(void)p;times[count++]=now;*v=now<clear_at?0x20:0;}
static void msleep(unsigned ms){now+=ms;}
static bool pci_dev_config_accessible(struct pci_dev*d,const char*s){(void)d;(void)s;return true;}
static int pci_dev_reset_iommu_prepare(struct pci_dev*d){(void)d;return 0;}
static void pci_dev_reset_iommu_done(struct pci_dev*d){(void)d;}
static void pcie_capability_set_word(struct pci_dev*d,int p,int b){(void)d;(void)p;(void)b;trigger=now;}
static int pci_dev_wait(struct pci_dev*d,const char*s,int t){(void)d;(void)s;(void)t;ready=now;return 0;}
#define pci_err(...) ((void)0)
'''
program += '\n'.join(definitions) + '\n' + functions + '\n'
program += r'''
int main(void){
 puts("// Generated from unmodified Linux pci.c pending/FLR functions.");
 puts("pub(super) const PENDING_READ_TIMES: &[&[u64]] = &[");
 for(unsigned scenario=0;scenario<3;scenario++){
  struct pci_dev d={0}; d.devcap=1u<<28;
  now=count=trigger=ready=0;clear_at=scenario==0?0:scenario==1?300:99999;
  if(pcie_reset_flr(&d,false))return 1;
  printf("&[");for(unsigned i=0;i<count;i++)printf("%s%u",i?",":"",times[i]);puts("],");
  if(ready-trigger!=100)return 2;
 }
 puts("];"); puts("pub(super) const SOURCE_QUIET_MS: u64 = 100;");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='narf-8852b-flr-') as directory:
    c = Path(directory) / 'oracle.c'
    executable = Path(directory) / 'oracle'
    c.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(executable)], check=True)
    result = subprocess.check_output([str(executable)], text=True)
Path(__file__).with_name('golden.rs').write_text(result)
