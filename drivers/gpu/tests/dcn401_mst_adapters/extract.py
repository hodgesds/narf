"""Extract primary helper bodies; host shims supply only platform plumbing."""
from pathlib import Path
import re
import sys
linux, out = map(Path, sys.argv[1:])
here=Path(__file__).parent

def function(source,name):
    start=re.search(r'(?m)^[^\n]*\b'+re.escape(name)+r'\s*\(',source).start()
    at=source.index('{',start)+1
    depth=1
    while depth:
        depth+=(source[at]=='{')-(source[at]=='}')
        at+=1
    return source[start:at]

base=linux/'drivers/gpu/drm/amd/display'
helpers=(base/'amdgpu_dm/amdgpu_dm_helpers.c').read_text()
header=(base/'amdgpu_dm/amdgpu_dm_mst_types.h').read_text()
vendor_defines='\n'.join(re.findall(r'(?m)^#define SYNAPTICS_RC_[^\n]+',header))+'\n'
if len(vendor_defines.splitlines()) != 5:
    raise ValueError('expected the five primary Synaptics command definitions')
vendor='\n'.join(function(helpers,name) for name in ['execute_synaptics_rc_command','apply_synaptics_fifo_reset_wa'])
link=(base/'dc/link/protocols/link_dp_capability.c').read_text()
mst=(base/'amdgpu_dm/amdgpu_dm_mst_types.c').read_text()
pcon=function(link,'intersect_frl_link_bw_support')+'\n'+function(mst,'get_conv_frl_bw')
for kind,body in [('vendor',vendor),('pcon',pcon)]:
    prefix=vendor_defines if kind=='vendor' else ''
    (out/(kind+'.c')).write_text(prefix+(here/(kind+'-stubs.h')).read_text()+body+'\n'+(here/(kind+'-main.c')).read_text())
