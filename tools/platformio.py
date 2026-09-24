Import('env')
from SCons.Script import Dir
from pathlib import Path
chip = env.BoardConfig().get('build.mcu')
if chip not in ('esp32', 'esp32s3'):
    raise RuntimeError('ESP32 WebRTC currently packages only ESP32 and ESP32-S3')
root = Path(Dir('.').srcnode().abspath).parent
env.Append(LIBPATH=[str(root / 'src' / chip)], LIBS=['peer_default', 'esp_audio_codec'])
