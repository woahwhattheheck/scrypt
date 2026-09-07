#!/usr/bin/env python3
"""Reproduce PR426 with fixed revisions; never derive keys from large parameters.

Usage: python3 run.py CHECKOUT_DIRECTORY OUTPUT_DIRECTORY
Requires built scrypt executables in CHECKOUT_DIRECTORY/{base,head}; see the
accompanying workflow. No credentials, network, or production input are used.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

BASE = 'a71ae8281742ac638bc75baa4334f2292251e0eb'
HEAD = '294338c5853f039630bd1a5d6e0c87ccd4692fff'
ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
FIX = OUT / 'fixtures'
FIX.mkdir(exist_ok=True)
U64 = (1 << 64) - 1
records: list[dict] = []
failures: list[dict] = []
env = dict(os.environ, LC_ALL='C', UBSAN_OPTIONS='halt_on_error=0:print_stacktrace=1')

def header(logn: int = 16, r: int = 8, p: int = 1) -> bytes:
    h = bytearray(b'scrypt\x00' + bytes([logn]) + struct.pack('>II', r, p) + bytes(range(32)))
    h.extend(hashlib.sha256(h).digest()[:16])
    h.extend(bytes(32))  # Deliberately NOT a valid password authenticator.
    assert len(h) == 96
    return bytes(h)

def human(n: int) -> str:
    """Independent integer oracle for the project's documented SI display."""
    if n < 1000:
        return f'{n} B'
    unit = max(k for k in range(1, 7) if n >= 1000 ** k)
    divisor = 1000 ** unit
    prefix = ' kMGTPE'[unit]
    if n < 10 * divisor:
        tenths = (10 * n) // divisor
        return f'{tenths // 10}.{tenths % 10} {prefix}B'
    return f'{n // divisor} {prefix}B'

def expected_mem(rev: str, logn: int, r: int) -> str:
    n = 1 << logn
    value = min(U64, 128 * r * n) if rev == 'head' else (((128 * r) & 0xffffffff) * n) & U64
    return human(value)

def invoke(rev: str, name: str, data: bytes, *, stdin: bool = False, decrypt: bool = False) -> dict:
    path = FIX / (name + '.enc')
    path.write_bytes(data)
    exe = ROOT / rev / 'scrypt'
    if decrypt:
        args = [str(exe), 'dec', '-v', '-M', '1B', '-t', '0', '-P', str(path)]
        inp = b'MICA-synthetic-test-only\n'
    else:
        args = [str(exe), 'info', '-' if stdin else str(path)]
        inp = data if stdin else b''
    p = subprocess.run(args, input=inp, capture_output=True, timeout=10, env=env)
    row = {'revision': rev, 'case': name, 'mode': 'dec' if decrypt else 'info',
           'stdin': stdin, 'returncode': p.returncode, 'stdout': p.stdout.decode(errors='replace'),
           'stderr': p.stderr.decode(errors='replace'), 'input_sha256': hashlib.sha256(data).hexdigest()}
    records.append(row)
    return row

def verify(row: dict, condition: bool, expectation: str) -> None:
    if not condition:
        failures.append({'revision': row['revision'], 'case': row['case'],
                         'expectation': expectation, 'observed': row})

def check_info(row: dict, accepted: bool, logn: int | None = None, r: int = 8, p: int = 1) -> None:
    verify(row, row['returncode'] == (0 if accepted else 1), f'accepted={accepted}')
    verify(row, not row['stdout'], 'info writes no stdout')
    verify(row, 'runtime error:' not in row['stderr'], 'no UBSan diagnostic')
    if accepted and logn is not None:
        verify(row, f'N = {1 << logn}; r = {r}; p = {p};' in row['stderr'], 'exact N/r/p display')
        verify(row, f'at least {expected_mem(row["revision"], logn, r)} of memory' in row['stderr'], 'memory matches integer oracle')
    elif not accepted:
        verify(row, 'Parameters used:' not in row['stderr'], 'invalid header not displayed')

# Every byte value, including every undefined shift in the original revision.
for rev in ('base', 'head'):
    for logn in range(256):
        row = invoke(rev, f'logn-{logn:03}', header(logn))
        if rev == 'base' and logn >= 64:
            # Never assert a value produced by undefined C arithmetic.
            verify(row, 'runtime error: shift exponent' in row['stderr'], 'UBSan exposes out-of-range shift')
        else:
            check_info(row, rev == 'base' or 1 <= logn <= 63, logn)

pairs = [(0, 0), (0, 1), (1, 0), (1, 1), (8, 1),
         (1, (1 << 30)-1), (1, 1 << 30), ((1 << 30)-1, 1), (1 << 30, 1),
         (32768, 32767), (32768, 32768), (0xffffffff, 0xffffffff),
         (0xffffffff, 0), (2, 0x80000000), ((1 << 25)-1, 1),
         (1 << 25, 1), ((1 << 25)+1, 1)]
for rev in ('base', 'head'):
    for r, p in pairs:
        row = invoke(rev, f'rp-{r}-{p}', header(1, r, p))
        check_info(row, rev == 'base' or (r > 0 and p > 0 and r*p < 1 << 30), 1, r, p)

# Cross uint32 intermediate and uint64 final-product boundaries separately.
for rev in ('base', 'head'):
    for logn in (1, 24, 25, 26, 30, 54, 55, 56, 57, 62, 63):
        for r in (1, 8, (1 << 25)-1, 1 << 25, (1 << 25)+1, (1 << 30)-1):
            row = invoke(rev, f'memory-{logn}-{r}', header(logn, r, 1))
            check_info(row, True, logn, r)

# Every truncated length; an info-only 96-byte header is deliberately accepted.
for rev in ('base', 'head'):
    for length in range(97):
        row = invoke(rev, f'truncated-{length:03}', header()[:length])
        check_info(row, length == 96, 16)

# Corrupt every byte. The 32-byte authenticator is outside the public checksum.
for rev in ('base', 'head'):
    for offset in range(96):
        data = bytearray(header())
        data[offset] ^= 1
        row = invoke(rev, f'flip-{offset:02}', bytes(data))
        accepted = offset >= (7 if rev == 'base' else 64)
        ln = data[7]
        r, p = struct.unpack('>II', data[8:16])
        check_info(row, accepted, ln, r, p)

for rev in ('base', 'head'):
    for logn in (0, 1, 63, 64, 255):
        row = invoke(rev, f'stdin-{logn}', header(logn), stdin=True)
        if rev == 'base' and logn >= 64:
            verify(row, 'runtime error: shift exponent' in row['stderr'], 'stdin same undefined-shift diagnostic')
        else:
            check_info(row, rev == 'base' or 1 <= logn <= 63, logn)
    row = invoke(rev, 'trailing-payload', header()+b'not-authenticated-ciphertext')
    check_info(row, True, 16)

# Real verbose decryption with one-byte RAM/time-zero limits rejects BEFORE
# key derivation. Never use -f or encryption with these enormous parameters.
for rev in ('base', 'head'):
    for logn, r in ((1, 1 << 25), (56, 1), (62, 8), (63, 8)):
        row = invoke(rev, f'verbose-{logn}-{r}', header(logn, r), decrypt=True)
        verify(row, row['returncode'] == 1 and not row['stdout'], 'resource-limited decryption rejects with no plaintext')
        verify(row, 'runtime error:' not in row['stderr'], 'no undefined arithmetic for bounded logN')
        verify(row, f'at least {expected_mem(rev, logn, r)} of memory' in row['stderr'], 'verbose memory estimate matches oracle')
        match = re.search(r'approximately ([0-9.eE+-]+) seconds', row['stderr'])
        verify(row, bool(match), 'verbose CPU estimate exists')
        if match and logn >= 62:
            seconds = float(match.group(1))
            verify(row, seconds == 0 if rev == 'base' else seconds > 0, 'base wraps CPU estimate to zero; head remains positive')

# The exact submitted native scenario against each binary. Neither its shell
# source nor fixture is rewritten; only the binary directory differs.
native = []
for rev in ('base', 'head'):
    command = ['sh', str(ROOT/'head/tests/test_scrypt.sh'), str(ROOT/rev/'scrypt')]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                            env=dict(env, N='11', VERBOSE='1', USE_VALGRIND='0'))
    row = {'revision': rev, 'case': 'native-11-info', 'returncode': result.returncode,
           'stdout': result.stdout, 'stderr': result.stderr}
    native.append(row)
    verify(row, result.returncode == (1 if rev == 'base' else 0), 'native scenario differentiates base and head')

manifest = {}
for rev, expected in (('base', BASE), ('head', HEAD)):
    actual = subprocess.check_output(['git', '-C', str(ROOT/rev), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != expected:
        raise RuntimeError(f'{rev}: wrong source {actual}')
    manifest[rev] = {'commit': actual, 'scryptenc_blob': subprocess.check_output(
        ['git', '-C', str(ROOT/rev), 'rev-parse', 'HEAD:lib/scryptenc/scryptenc.c'], text=True).strip(),
        'binary_sha256': hashlib.sha256((ROOT/rev/'scrypt').read_bytes()).hexdigest()}

summary = {'application_cases': len(records), 'native_scenarios': len(native),
           'failures': len(failures), 'source': manifest,
           'head_ubsan_diagnostics': sum('runtime error:' in x['stderr'] for x in records if x['revision']=='head'),
           'base_undefined_shift_diagnostics': sum('runtime error: shift exponent' in x['stderr'] for x in records if x['revision']=='base'),
           'limits': ['UBSan-instrumented Linux/GCC builds only', 'No full make-check, valgrind, other-platform, or password-authenticity claim',
                      'Synthetic headers are not valid encrypted payloads; info is not decryption verification',
                      'No sponsor contact, upstream comment, award, or payment claimed']}
(OUT/'matrix.json').write_text(json.dumps(records, indent=2)+'\n')
(OUT/'native.json').write_text(json.dumps(native, indent=2)+'\n')
(OUT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
print(json.dumps(summary, indent=2), flush=True)
for row in native:
    print('NATIVE', json.dumps(row), flush=True)
for name in ('logn-255', 'memory-1-33554432', 'memory-63-8', 'verbose-63-8', 'flip-64'):
    for row in records:
        if row['case'] == name:
            print('SAMPLE', json.dumps(row), flush=True)
for failure in failures:
    print('FAIL', json.dumps(failure), flush=True)
raise SystemExit(1 if failures else 0)
