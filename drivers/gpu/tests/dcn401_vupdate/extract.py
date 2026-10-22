"""Expand actual Linux DCN401 IRQ table macros and primary ASIC headers."""
from pathlib import Path
import sys
linux, output=map(Path,sys.argv[1:])
base=linux/'drivers/gpu/drm/amd'
source=(base/'display/dc/irq/dcn401/irq_service_dcn401.c').read_text()
def macro(name):
    lines=source.splitlines(keepends=True)
    start=next(i for i,l in enumerate(lines) if l.startswith('#define '+name+'('))
    end=start+1
    while lines[end-1].rstrip().endswith('\\'):end+=1
    return ''.join(lines[start:end])
headers='\n'.join('#include "'+str(base/p)+'"' for p in ['include/asic_reg/dcn/dcn_4_1_0_offset.h','include/asic_reg/dcn/dcn_4_1_0_sh_mask.h','include/ivsrcid/dcn/irqsrcs_dcn_1_0.h'])
definition=next(l for l in source.splitlines() if l.startswith('#define DCN_BASE__INST0_SEG2'))
stubs='''#include <stdint.h>
#include <stdio.h>
'''+headers+'\n'+definition+'''
#define DC_IRQ_SOURCE_VUPDATE1 0
static const void *vupdate_no_lock_irq_info_funcs;
struct irq_source_info {
 unsigned enable_reg,enable_mask,enable_value[2],ack_reg,ack_mask,ack_value;
 const void *funcs;
};
'''
macros='\n'.join(macro(n) for n in ['BASE_INNER','BASE','SRI','IRQ_REG_ENTRY','vupdate_no_lock_int_entry'])
main='''
static const struct irq_source_info table[]={
 vupdate_no_lock_int_entry(0),vupdate_no_lock_int_entry(1),vupdate_no_lock_int_entry(2),vupdate_no_lock_int_entry(3),
};
int main(void) {
 const unsigned sources[]={DCN_1_0__SRCID__OTG0_IHC_V_UPDATE_NO_LOCK_INTERRUPT,DCN_1_0__SRCID__OTG1_IHC_V_UPDATE_NO_LOCK_INTERRUPT,DCN_1_0__SRCID__OTG2_IHC_V_UPDATE_NO_LOCK_INTERRUPT,DCN_1_0__SRCID__OTG3_IHC_V_UPDATE_NO_LOCK_INTERRUPT};
 unsigned clears=OTG0_OTG_GLOBAL_SYNC_STATUS__VSTARTUP_EVENT_CLEAR_MASK|OTG0_OTG_GLOBAL_SYNC_STATUS__VUPDATE_EVENT_CLEAR_MASK|OTG0_OTG_GLOBAL_SYNC_STATUS__VUPDATE_NO_LOCK_EVENT_CLEAR_MASK|OTG0_OTG_GLOBAL_SYNC_STATUS__VREADY_EVENT_CLEAR_MASK;
 for(unsigned i=0;i<4;i++) {
  const struct irq_source_info *r=&table[i];
  if(r->ack_reg!=r->enable_reg || r->ack_value!=r->ack_mask)return 1;
  printf("%x %x %x %x %x %x %x %x\\n",i,sources[i],r->enable_reg*4,r->enable_mask,r->ack_mask,r->enable_value[0]&r->enable_mask,r->enable_value[1]&r->enable_mask,clears);
 }
}
'''
output.write_text(stubs+macros+main)
