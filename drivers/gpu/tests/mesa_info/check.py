#!/usr/bin/env python3
"""Run pinned Mesa/libdrm initialization against actual NARF INFO dispatch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
from rust_answers import build

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mesa-build',type=Path,required=True)
p.add_argument('--libdrm-prefix',type=Path,required=True)
p.add_argument('--libdrm-build',type=Path,required=True)
p.add_argument('--mesa-archive',type=Path,required=True)
p.add_argument('--libdrm-archive',type=Path,required=True)
p.add_argument('--work-dir',type=Path,required=True)
a=p.parse_args();a.work_dir.mkdir(parents=True,exist_ok=True)
here=Path(__file__).resolve().parent;gpu=here.parents[1]
assert hashlib.sha256(a.mesa_archive.read_bytes()).hexdigest()=='bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9'
assert hashlib.sha256(a.libdrm_archive.read_bytes()).hexdigest()=='ac5e74d157830eb8bee44c6a6bf3ad49774ef0dd2a72bdad74a8f20308b52a95'
# Use the actual configured Mesa sources/flags; no initialization body is copied
# into the C adapter. Selected source files must equal the pinned release bytes.
commands=json.loads((a.mesa_build/'compile_commands.json').read_text())
entry=next(e for e in commands if e['file'].endswith('/ac_gpu_info.c'))
mesa=(Path(entry['directory'])/entry['file']).resolve().parents[3]
with tarfile.open(a.mesa_archive)as tar:
    for rel in ['src/amd/common/ac_gpu_info.c','src/amd/common/ac_linux_drm.c','src/amd/common/ac_video.c']:
        assert (mesa/rel).read_bytes()==tar.extractfile('mesa-26.2.4/'+rel).read(),rel
lib_commands=json.loads((a.libdrm_build/'compile_commands.json').read_text())
with tarfile.open(a.libdrm_archive)as tar:
    for name in ['amdgpu_device.c','amdgpu_gpu_info.c','amdgpu_vamgr.c']:
        record=next(e for e in lib_commands if e['file'].endswith('/'+name))
        source=(Path(record['directory'])/record['file']).resolve()
        assert source.read_bytes()==tar.extractfile('libdrm-2.4.134/amdgpu/'+name).read(),name
version=(a.libdrm_prefix/'lib64/pkgconfig/libdrm_amdgpu.pc').read_text()
assert 'Version: 2.4.134'in version
# Actual Rust production functions are extracted without field rewrites. Only
# hardware/publication/VM transport inputs and process-local copy hooks differ.
native_version=re.search(r'Card::new\("amdgpu",\s*"AMD GPU",\s*\((\d+),\s*(\d+),\s*(\d+)\)\)',(gpu/'src/amdgpu_navi48_kms.rs').read_text())
assert native_version,'native DRM version source not found'
major,minor,patch=map(int,native_version.groups())
assert (major,minor,patch)==(3,0,0),'production version gate changed; explicit review required'
(a.work_dir/'native_version.h').write_text(f'#define NARF_DRM_MAJOR {major}\n#define NARF_DRM_MINOR {minor}\n#define NARF_DRM_PATCH {patch}\n')
build(gpu,a.work_dir/'answers.rs')
subprocess.run(['rustc','--edition=2021','--crate-type','staticlib','-Dwarnings',str(a.work_dir/'answers.rs'),'-o',str(a.work_dir/'answers.a')],check=True)
flags=shlex.split(entry['command']);args=[];i=1
while i<len(flags):
    x=flags[i]
    if x in ['-o','-c','-MD','-MQ','-MF']:
        i+=1 if x=='-MD'else 2;continue
    if x=='-Werror=missing-prototypes':i+=1;continue
    args.append(x);i+=1
subprocess.run(['cc',*args,'-I'+str(a.work_dir),'-Werror','-fvisibility=default','-c',str(here/'replay.c'),'-o',str(a.work_dir/'replay.o')],cwd=a.mesa_build,check=True)
libs=[a.mesa_build/x for x in ['src/amd/common/libamd_common.a','src/util/libmesa_util.a','src/util/format/libmesa_format.a','src/amd/addrlib/libaddrlib.a','src/c11/impl/libmesa_util_c11.a']]
libs=[str(x)for x in libs if x.exists()];binary=a.work_dir/'replay'
subprocess.run(['c++','-Wl,--export-dynamic','-Wl,--gc-sections',str(a.work_dir/'replay.o'),str(a.work_dir/'answers.a'),'-Wl,--start-group',*libs,'-Wl,--end-group','-L'+str(a.libdrm_prefix/'lib64'),'-Wl,-rpath,'+str(a.libdrm_prefix/'lib64'),'-ldrm_amdgpu','-ldrm','-lm','-ldl','-lz','-lzstd','-pthread','-o',str(binary)],check=True)

env={k:v for k,v in os.environ.items()if not k.startswith(('AMD_','RADV_','R600_'))}
env.pop('LD_PRELOAD',None);env['LD_LIBRARY_PATH']=str(a.libdrm_prefix/'lib64')
def run(chip,mode,extra=(),status=0,contains=()):
    result=subprocess.run([str(binary),chip,mode,*extra],text=True,capture_output=True,env=env)
    output=result.stdout+result.stderr
    label='-'.join([chip,mode,*extra]).replace('=','_')
    (a.work_dir/(label+'.log')).write_text(output)
    assert result.returncode==status,(label,result.returncode,output)
    for text in contains:assert text in output,(label,text,output)
    return output

for chip in ['gfx1200','gfx1201']:
    run(chip,'production',status=2,contains=['AMDGPU_INFO_ACCEL_WORKING = 0','query_calls=1'])
    run(chip,'abi-only',status=2,contains=['AMDGPU_INFO_ACCEL_WORKING = 0'])
    run(chip,'accel-only',status=3,contains=['only compatible with 3.54.0'])
    output=run(chip,'hypothetical-3.54',contains=['mesa-query=0','family='+chip.upper(),'queues=1/1/1/1/1'])
    assert 'CU='+('32'if chip=='gfx1200'else'64')in output
    for query,message in [(22,'query_gpu_info_init failed'),(21,'query_gpu_info_init failed'),(25,'query_info(memory) failed'),(2,'failed to find gfx or compute')]:
        run(chip,'hypothetical-3.54',['query='+str(query)],2 if query in [22,21]else 3,contains=[message])
    for fw,name in [(4,'me'),(8,'mec'),(5,'pfp'),(14,'vcn')]:
        run(chip,'hypothetical-3.54',['firmware='+str(fw)],status=3,contains=['query_firmware_version('+name+') failed'])
    # Optional MAX_IBS refusal uses the actual Mesa fallback, rather than an
    # invented mandatory requirement. A missing media owner requires no VCN FW.
    run(chip,'hypothetical-3.54',['query=34'],contains=['mesa-query=0'])
    run(chip,'hypothetical-3.54',['no-media','firmware=14'],contains=['mesa-query=0','queues=1/1/1/0/0'])
    run(chip,'hypothetical-3.54',['withdraw-fw'],status=3,contains=['query_firmware_version(vcn) failed'])
    run(chip,'hypothetical-3.54',['unsupported-vcn'],status=3,contains=['query_firmware_version(vcn) failed'])
    run(chip,'hypothetical-3.54',['no-media','withdraw-fw'],contains=['mesa-query=0','queues=1/1/1/0/0'])
    for minor in [8,9,10,11]:
        raw=(1<<24)|(1<<20)|(minor<<12)|1
        run(chip,'hypothetical-3.54',['vcn='+str(raw)],contains=['FW_VCN=1.1.'+str(minor)+' '])
print('Both pinned Mesa/libdrm initializers passed actual Rust query replay only in the explicit host-only3.54/ACCEL envelope. Production gates, mandatory omissions, optional fallbacks and raw VCN fields checked.')
