from pathlib import Path
import re
import subprocess
import sys
import tempfile

linux, here = map(Path, sys.argv[1:])
def function(file, name):
    source = (linux / file).read_text()
    match = re.search(r'(?m)^(?:(?:static )?(?:void|bool)\s+)?' + name + r'\(', source)
    if match is None: raise RuntimeError('Missing Linux function: ' + name)
    at = source.index(name + '(', match.start())
    start = source.rfind('\n', 0, at) + 1
    if not source[start:at].strip():
        start = source.rfind('\n', 0, start - 1) + 1
    begin = source.index('{', at)
    depth, end = 1, begin + 1
    while depth:
        if source[end] == '{': depth += 1
        if source[end] == '}': depth -= 1
        end += 1
    return source[start:end]

frl = function('drivers/gpu/drm/amd/display/dc/hpo/dcn401/dcn401_hpo_frl_stream_encoder.c', 'hpo_enc401_set_hdmi_stream_attribute')
opp = function('drivers/gpu/drm/amd/display/dc/opp/dcn10/dcn10_opp.c', 'opp1_set_pixel_encoding')
tmds = function('drivers/gpu/drm/amd/display/dc/dio/dcn10/dcn10_stream_encoder.c', 'enc1_stream_encoder_set_stream_attribute_helper')
sink = function('drivers/gpu/drm/display/drm_hdmi_state_helper.c', 'sink_supports_format_bpc')
# Record named fields, with only platform/MMIO plumbing replaced.
fields = sorted(set(re.findall(r'\b(?:FMT_[A-Z0-9_]+|TMDS_[A-Z0-9_]+|HDMI_[A-Z0-9_]+|FIFO_UNCOMPRESSED_PIXEL_FORMAT)\b', opp + tmds + frl)))
text = (here / 'encoding.c').read_text().replace('/* LINUX_SINK */', sink).replace('/* LINUX_OPP */', opp).replace('/* LINUX_TMDS */', tmds).replace('/* LINUX_FRL */', frl)
text = text.replace('/* FIELD_ENUM */', 'enum { ' + ', '.join('FIELD_' + f for f in fields) + ', FIELD_COUNT };')
with tempfile.TemporaryDirectory(prefix='narf-hdmi-encoding-') as tmp:
    src, exe = Path(tmp) / 'reference.c', Path(tmp) / 'reference'
    src.write_text(text)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-unused-variable', '-I' + str(linux / 'drivers/gpu/drm/amd/include'), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
