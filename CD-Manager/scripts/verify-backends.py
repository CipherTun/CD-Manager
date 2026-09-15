#!/usr/bin/env python3
import json, pathlib, subprocess, sys
root = pathlib.Path(__file__).resolve().parents[1]
manifest = json.loads((root/'backend/BACKENDS.json').read_text())
backends = manifest['backends']
assert len(backends) == manifest['requiredBackendCount'] == 10
assert len({b['id'] for b in backends}) == 10
for b in backends:
    if b['runtime'] == 'android':
        assert b.get('aar'), b
    else:
        assert pathlib.Path(root/b['entry']).is_file(), b
print('CD Manager backend contract: 10/10 present and uniquely identified')
