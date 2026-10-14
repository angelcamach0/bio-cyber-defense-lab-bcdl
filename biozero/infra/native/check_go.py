#!/usr/bin/env python3
"""Run module tests and vet without putting build artifacts in the checkout."""
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[3]
for mod in sorted((root / 'biozero').rglob('go.mod')):
    print(str(mod.parent.relative_to(root)), flush=True)
    subprocess.run(['go', 'test', './...'], cwd=mod.parent, check=True)
    subprocess.run(['go', 'vet', './...'], cwd=mod.parent, check=True)
