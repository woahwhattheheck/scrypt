#!/usr/bin/env python3
"""Mutation-test native scenario assertions using a real, already-built scrypt.
The wrapper deliberately writes an output AFTER real scrypt rejects a bad
passphrase. This tests the tests; it does not allege that scrypt makes that write.
All fixtures, injected writes, and output are contained in temporary directories.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ORIGINAL_TEST = 'ff4df75f61599009e870faa4c73f253870f841cb'
CORRECTED_TEST = '44ce960acd7b6113920a5ed64b78f27300a9c96f'
READER = '1f0cd35f2b4c489784c3ab1dbbd33b7272eee522'
WRAPPER = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
# Keep argv[0] unchanged so upstream's real diagnostics stay identical.
result = subprocess.run(['scrypt'] + args, executable=os.environ['RIVET_REAL_SCRYPT'])
kind = None
if len(args) == 5 and args[0:2] == ['dec', '--passphrase']:
    if args[2] == 'file:THIS_FILE_DOES_NOT_EXIST':
        kind = 'missing'
    elif args[2].endswith('-passphrase-bad.txt'):
        kind = 'wrong'
mode = os.environ['RIVET_MUTATION']
if kind is not None and result.returncode == 1 and mode in (kind, 'both'):
    destination = Path(args[-1]).resolve()
    root = Path(os.environ['RIVET_CASE_ROOT']).resolve()
    destination.relative_to(root)  # Refuse any write outside this case.
    destination.write_bytes(b'RIVET synthetic erroneous output\n')
    with open(os.environ['RIVET_MUTATION_LOG'], 'a') as log:
        log.write(json.dumps({'kind': kind, 'target': str(destination),
                              'real_exit': result.returncode}) + '\n')
sys.exit(result.returncode)
'''

def blob(path: Path) -> str:
    value = path.read_bytes()
    return hashlib.sha1(b'blob '+str(len(value)).encode()+b'\0'+value).hexdigest()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--built', type=Path, required=True)
    parser.add_argument('--patch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    built, patch, output = args.built.resolve(), args.patch.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = built/'scrypt'
    if not os.access(binary, os.X_OK):
        raise RuntimeError('The real scrypt binary must be built first')
    if blob(built/'libcperciva/util/readpass_file.c') != READER:
        raise RuntimeError('Unexpected reader revision')
    native = built/'tests/08-passphrase-file.sh'
    if blob(native) != ORIGINAL_TEST:
        raise RuntimeError('Unexpected native scenario revision')
    report = {'kind': 'synthetic output-side-effect mutation test of native assertions',
              'original_test': ORIGINAL_TEST, 'corrected_test': CORRECTED_TEST,
              'reader': READER, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'scenarios': []}
    with tempfile.TemporaryDirectory(prefix='rivet-negative-') as temporary:
        root = Path(temporary)
        for version in ['original', 'corrected']:
            for mutation in ['none', 'missing', 'wrong', 'both']:
                name = f'{version}-{mutation}'
                case = root/name
                case.mkdir()
                shutil.copytree(built/'tests', case/'tests', ignore=shutil.ignore_patterns('__pycache__'))
                test = case/'tests/08-passphrase-file.sh'
                if version == 'corrected':
                    changed = subprocess.run(['patch', '-p1', '--batch', '--fuzz=0', '-i', str(patch)],
                        cwd=case, capture_output=True, text=True, timeout=15)
                    if changed.returncode:
                        raise RuntimeError(changed.stdout+changed.stderr)
                wanted = ORIGINAL_TEST if version == 'original' else CORRECTED_TEST
                if blob(test) != wanted:
                    raise RuntimeError(f'{name}: test bytes changed unexpectedly')
                wrapped = case/'scrypt'
                wrapped.write_text(WRAPPER)
                wrapped.chmod(0o755)
                mutations = case/'injected.jsonl'
                env = dict(os.environ, N='8', VERBOSE='1', USE_VALGRIND='0', SMALLMEM='1',
                           RIVET_REAL_SCRYPT=str(binary), RIVET_MUTATION=mutation,
                           RIVET_CASE_ROOT=str(case), RIVET_MUTATION_LOG=str(mutations))
                result = subprocess.run(['sh', str(case/'tests/test_scrypt.sh'), str(wrapped)],
                    cwd=case, env=env, capture_output=True, text=True, timeout=180)
                (output/f'{name}.log').write_text(result.stdout+result.stderr)
                injected = [json.loads(line) for line in mutations.read_text().splitlines()] if mutations.exists() else []
                want_kinds = [] if mutation == 'none' else (['missing', 'wrong'] if mutation == 'both' else [mutation])
                if sorted(row['kind'] for row in injected) != sorted(want_kinds):
                    raise AssertionError(f'{name}: expected injection did not occur: {injected}')
                for row in injected:
                    if Path(row['target']).read_bytes() != b'RIVET synthetic erroneous output\n':
                        raise AssertionError(f'{name}: injected side effect not retained')
                failures = sorted(path.with_suffix('.desc').read_text().strip()
                    for path in (case/'tests-output').glob('08-passphrase-file-*.exit')
                    if path.read_text().strip() != '0')
                expected = []
                if version == 'corrected':
                    if mutation in ['missing', 'both']:
                        expected.append('scrypt dec file none no file')
                    if mutation in ['wrong', 'both']:
                        expected.append('scrypt dec file bad no file')
                expected.sort()
                if failures != expected or result.returncode != (1 if expected else 0):
                    raise AssertionError(f'{name}: unexpected exit={result.returncode}, failures={failures}; expected={expected}\n{result.stdout}{result.stderr}')
                shutil.copytree(case/'tests-output', output/f'{name}-output')
                (output/f'{name}-injected.json').write_text(json.dumps(injected, indent=2)+'\n')
                report['scenarios'].append({'version': version, 'mutation': mutation,
                    'native_checks': 13, 'exit': result.returncode, 'injections': len(injected),
                    'failed_checks': failures, 'expected_outcome': True})
                print(f'PASS {name}: exit={result.returncode}; injections={len(injected)}; failures={failures}', flush=True)
    if blob(native) != ORIGINAL_TEST or blob(built/'libcperciva/util/readpass_file.c') != READER:
        raise RuntimeError('Original source tree was changed')
    report['passed'] = len(report['scenarios'])
    (output/'negative-output-report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('RESULT: 8/8 expected scenarios. Old assertions miss both injected output errors; corrected assertions catch each. Real-binary clean controls pass.', flush=True)

if __name__ == '__main__':
    main()
