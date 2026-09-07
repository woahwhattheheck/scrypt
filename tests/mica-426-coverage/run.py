#!/usr/bin/env python3
"""Run actual native tests with three single-purpose arithmetic regressions.

Usage: python3 run.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
SOURCE must be an isolated built checkout of HEAD below, with CANDIDATE fetched.
Never run this against a shared checkout. Mutations are confined to this source
copy and are restored in finally. No network, credentials or real data are used.
"""
from __future__ import annotations
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HEAD = '294338c5853f039630bd1a5d6e0c87ccd4692fff'
CANDIDATE = '7a18e0ccb77e19271ceb4a5cba76a14ee5fd8d81'
EXPECTED_BLOB = 'e6d22dd678eb23b782501a5a37c2e27521cdb6ee'
SRC = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CFILE = SRC / 'lib/scryptenc/scryptenc.c'
TEST = SRC / 'tests/11-info.sh'
ENV = dict(os.environ, LC_ALL='C', N='11', VERBOSE='1', USE_VALGRIND='0')


def git(*args: str) -> str:
    return subprocess.check_output(['git', '-C', str(SRC), *args], text=True).strip()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError('Mutation does not match exactly one expression')
    return text.replace(old, new, 1)


if git('rev-parse', 'HEAD') != HEAD:
    raise RuntimeError('Wrong production revision')
subprocess.run(['git', '-C', str(SRC), 'diff', '--exit-code'], check=True)
if git('diff', '--name-only', HEAD, CANDIDATE) != 'tests/11-info.sh':
    raise RuntimeError('Candidate changes more than the intended test file')
if git('rev-parse', CANDIDATE + ':tests/11-info.sh') != EXPECTED_BLOB:
    raise RuntimeError('Unexpected candidate bytes')
original_c = CFILE.read_text()
original_test = TEST.read_text()
candidate = subprocess.check_output(['git', '-C', str(SRC), 'show',
                                    CANDIDATE + ':tests/11-info.sh'], text=True)
(OUT/'11-info.sh').write_text(candidate)
(OUT/'11-info.patch').write_text(''.join(difflib.unified_diff(
    original_test.splitlines(True), candidate.splitlines(True),
    fromfile='a/tests/11-info.sh', tofile='b/tests/11-info.sh')))
subprocess.run(['sh', '-n', str(OUT/'11-info.sh')], check=True)
subprocess.run(['git', '-C', str(SRC), 'apply', '--check', str(OUT/'11-info.patch')], check=True)

memory_guard = '\tif ((uint64_t)(r) > (UINT64_MAX / 128) / N)\n\t\tmem_minimum = UINT64_MAX;\n\telse\n\t\tmem_minimum = 128 * (uint64_t)(r) * N;\n'
variants = [
    ('clean-before', original_c, None),
    ('uint32-intermediate', replace_once(original_c,
        '\t\tmem_minimum = 128 * (uint64_t)(r) * N;',
        '\t\tmem_minimum = 128 * r * N;'), 'wide-r memory estimate'),
    ('uint64-product', replace_once(original_c, memory_guard,
        '\tmem_minimum = 128 * (uint64_t)(r) * N;\n'), 'huge-N memory estimate'),
    ('integer-cpu-product', replace_once(original_c,
        '4.0 * (double)N * (double)r * (double)p / opps : 0;',
        '(double)(4 * N * r * p) / opps : 0;'), 'nonzero CPU estimate'),
    ('clean-restored', original_c, None),
]
records = []
failures = []
builds = []
try:
    for name, source_text, failed_check in variants:
        CFILE.write_text(source_text)
        diff = subprocess.check_output(['git', '-C', str(SRC), 'diff', '--',
                                        'lib/scryptenc/scryptenc.c'], text=True)
        (OUT/(name+'.source.patch')).write_text(diff)
        build = subprocess.run(['make', '-s', '-j2'], cwd=SRC, capture_output=True,
                               text=True, timeout=180, env=ENV)
        (OUT/(name+'.build.log')).write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(f'{name}: build failed; see saved build log')
        builds.append({'variant': name, 'source_sha256': sha256(CFILE.read_bytes()),
                       'binary_sha256': sha256((SRC/'scrypt').read_bytes())})
        for suite, text in (('submitted', original_test), ('candidate', candidate)):
            TEST.write_text(text)
            result = subprocess.run(['sh', str(SRC/'tests/test_scrypt.sh'), str(SRC/'scrypt')],
                                    cwd=SRC, capture_output=True, text=True, timeout=45, env=ENV)
            case_dir = OUT / (name+'-'+suite)
            case_dir.mkdir()
            (case_dir/'stdout.txt').write_text(result.stdout)
            (case_dir/'stderr.txt').write_text(result.stderr)
            # Passing .exit files are deleted by the native harness. Preserve
            # whatever remains, but never require passing files to exist.
            native_out = SRC/'tests-output'
            if native_out.exists():
                shutil.copytree(native_out, case_dir/'tests-output')
            expected_rc = 1 if suite == 'candidate' and failed_check else 0
            diagnostic = result.stdout + result.stderr
            ok = result.returncode == expected_rc
            if expected_rc:
                ok = ok and failed_check in diagnostic
            else:
                ok = ok and 'SUCCESS!' in diagnostic
            row = {'variant': name, 'suite': suite, 'returncode': result.returncode,
                   'expected_returncode': expected_rc, 'expected_failed_check':
                   failed_check if expected_rc else None, 'expectation_passed': ok,
                   'stdout': result.stdout, 'stderr': result.stderr}
            records.append(row)
            if not ok:
                failures.append(row)
            print('CASE', json.dumps(row), flush=True)
finally:
    CFILE.write_text(original_c)
    TEST.write_text(original_test)
    subprocess.run(['git', '-C', str(SRC), 'diff', '--exit-code'], check=True)

summary = {'source_head': HEAD, 'candidate_commit': CANDIDATE,
           'candidate_blob': EXPECTED_BLOB, 'scenario_runs': len(records),
           'failed_expectations': len(failures), 'builds': builds,
           'submitted_native_checks': original_test.count('setup_check'),
           'candidate_native_checks': candidate.count('setup_check'),
           'limits': ['Linux x86-64 GCC -O2, no sanitizer or valgrind in this run',
                      'Only native scenario 11; no full-suite or portability claim',
                      'Deliberate source mutations test coverage, not new upstream defects',
                      'No password verification, production input, upstream report or award claim']}
(OUT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'matrix.json').write_text(json.dumps(records, indent=2)+'\n')
(OUT/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
print('SUMMARY', json.dumps(summary), flush=True)
raise SystemExit(1 if failures else 0)
