#!/usr/bin/env python3
"""Build an Arduino-installable library ZIP, excluding caches and credentials."""
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.3.0'
OUTPUT = ROOT / 'dist' / f'ESP32-Arduino-WebRTC-{VERSION}.zip'
OUTPUT.parent.mkdir(exist_ok=True)
paths = [ROOT / name for name in ('library.properties', 'library.json', 'LICENSE', 'README.md', 'THIRD_PARTY.md', 'platformio.ini')]
for folder in ('src', 'tools', 'examples', 'browser', 'docs', 'test'):
    paths += [p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc' and p.name != '.DS_Store']
with ZipFile(OUTPUT, 'w', ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(paths):
        name = 'ESP32-Arduino-WebRTC/' + path.relative_to(ROOT).as_posix()
        info = ZipInfo(name, date_time=(2026, 9, 24, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = (0o100755 if path.suffix == '.sh' else 0o100644) << 16
        archive.writestr(info, path.read_bytes())
print(OUTPUT)
