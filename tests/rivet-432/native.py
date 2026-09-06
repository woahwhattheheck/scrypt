#!/usr/bin/env python3
"""Run PR 432's exact native scenario against already-built base/head worktrees.
Only the base worktree's test script is changed; implementation bytes are checked.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

SOURCE_HASHES = {'base': '4379a61d72bc5d1224ec354fdba2a1fb65cac930',
                 'head': '1f0cd35f2b4c489784c3ab1dbbd33b7272eee522'}
TEST_HASH = 'ff4df75f61599009e870faa4c73f253870f841cb'
EXPECTED_FAILURES = sorted(['scrypt dec file stray CR',
                            'scrypt dec file stray CR error',
                            'scrypt dec file stray CR no file'])

def git_hash(path):
    data = path.read_bytes()
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--head', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    base, head = args.base.resolve(), args.head.resolve()
    test = head/'tests/08-passphrase-file.sh'
    if git_hash(test) != TEST_HASH:
        raise RuntimeError('Submitted native test bytes changed')
    shutil.copyfile(test, base/'tests/08-passphrase-file.sh')
    count = test.read_text().count('\tsetup_check ')
    report = {'native_scenario': 'tests/08-passphrase-file.sh',
              'test_blob': TEST_HASH, 'checks_per_revision': count, 'runs': []}
    for version, root in [('base', base), ('head', head)]:
        source = root/'libcperciva/util/readpass_file.c'
        if git_hash(source) != SOURCE_HASHES[version]:
            raise RuntimeError(f'{version} implementation changed')
        if git_hash(root/'tests/08-passphrase-file.sh') != TEST_HASH:
            raise RuntimeError(f'{version} test bytes differ')
        command = ['sh', 'tests/test_scrypt.sh', './scrypt']
        env = dict(os.environ, N='8', VERBOSE='1', USE_VALGRIND='0', SMALLMEM='1')
        result = subprocess.run(command, cwd=root, env=env, capture_output=True,
                                text=True, timeout=180)
        log = result.stdout + result.stderr
        (args.output/f'{version}-native.log').write_text(log)
        failures = []
        for path in sorted((root/'tests-output').glob('08-passphrase-file-*.exit')):
            value = path.read_text().strip()
            if value != '0':
                failures.append(path.with_suffix('.desc').read_text().strip())
        failures.sort()
        if version == 'base':
            if result.returncode != 1 or failures != EXPECTED_FAILURES:
                raise RuntimeError(f'Unexpected base outcome {result.returncode}: {failures}\n{log}')
            created = root/'tests-output/08-passphrase-file-decrypt-cr.txt'
            if created.read_bytes() != (root/'tests/verify-strings/test_scrypt.good').read_bytes():
                raise RuntimeError('Base did not decrypt with the truncated passphrase')
        else:
            if result.returncode != 0 or failures or 'SUCCESS!' not in log:
                raise RuntimeError(f'Unexpected head outcome {result.returncode}: {failures}\n{log}')
            if (root/'tests-output/08-passphrase-file-decrypt-cr.txt').exists():
                raise RuntimeError('Patched reader created an output for the rejected CR file')
        if git_hash(source) != SOURCE_HASHES[version]:
            raise RuntimeError('Implementation changed while tests ran')
        print(f'{version}: native exit={result.returncode}, checks={count}, failed checks={failures}')
        print(log)
        shutil.copytree(root/'tests-output', args.output/f'{version}-native-output', dirs_exist_ok=True)
        report['runs'].append({'version': version, 'exit': result.returncode,
                              'failures': failures, 'expected_outcome': True,
                              'reader_blob': SOURCE_HASHES[version]})
    (args.output/'native-report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE REGRESSION CONFIRMED: original fails exactly three new CR checks; patch passes.')

if __name__ == '__main__':
    main()
