#!/usr/bin/env python3
"""Compile pinned scrypt #432 reader sources and exercise synthetic files only.

Usage: python3 run.py --sources /path/to/materialized/sources --output results
Without --sources, exact Git objects are loaded from --repo (default: cwd).
No production secrets, encrypted user files, daemon or network calls are used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

BASE = 'a71ae8281742ac638bc75baa4334f2292251e0eb'
HEAD = '3fcb6826f01157682038036fcea2620b3509a12c'
MANIFEST = {
    'base/readpass_file.c': '4379a61d72bc5d1224ec354fdba2a1fb65cac930',
    'head/readpass_file.c': '1f0cd35f2b4c489784c3ab1dbbd33b7272eee522',
    'common/insecure_memzero.c': 'bd26bac4314e950941bf0ef7df3b50c4927a43e8',
    'common/insecure_memzero.h': '2c16083b90dba3951f9c57fe4ae780465b368d3a',
    'common/readpass.h': '2d6017bdc80ff491c45129207874046a0a69bbf8',
    'common/warnp.c': '04c0d0cfce276e7b7a69079b25b30a769c33b833',
    'common/warnp.h': '92ed2423993a69571089823148f490e10b71d4f5',
}

def blob_hash(data: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def sources_for(args, destination: Path) -> dict[str, str]:
    observed = {}
    for relative, expected in MANIFEST.items():
        group, filename = relative.split('/')
        if args.sources is not None:
            data = (args.sources / relative).read_bytes()
        else:
            revision = BASE if group == 'base' else HEAD
            data = subprocess.run(
                ['git', '-C', str(args.repo), 'show',
                 f'{revision}:libcperciva/util/{filename}'],
                capture_output=True, check=True, timeout=30).stdout
        observed[relative] = blob_hash(data)
        if observed[relative] != expected:
            raise RuntimeError(f'Source mismatch: {relative}: {observed[relative]} != {expected}')
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return observed

def cases():
    # name, file bytes (None means missing), base output, head output, diagnostic
    # A None output is a documented rejection; bytes are the accepted password.
    return [
        ('empty-file', b'', b'', b'', ''),
        ('empty-lf', b'\n', b'', b'', ''),
        ('empty-crlf', b'\r\n', b'', b'', ''),
        ('plain', b'hunter2', b'hunter2', b'hunter2', ''),
        ('unix-lf', b'hunter2\n', b'hunter2', b'hunter2', ''),
        ('windows-crlf', b'hunter2\r\n', b'hunter2', b'hunter2', ''),
        ('spaces-and-tab', b' a\tb \n', b' a\tb ', b' a\tb ', ''),
        ('high-bytes', b'\xff\x80x\n', b'\xff\x80x', b'\xff\x80x', ''),
        ('bare-cr', b'\r', b'', None, 'carriage return or newline'),
        ('trailing-cr', b'hunter2\r', b'hunter2', None, 'carriage return or newline'),
        ('interior-cr', b'hunter2\rextra', b'hunter2', None, 'carriage return or newline'),
        ('interior-cr-before-lf', b'hunter2\rextra\n', b'hunter2', None, 'carriage return or newline'),
        ('double-cr-before-lf', b'hunter2\r\r\n', b'hunter2', None, 'carriage return or newline'),
        ('leading-cr', b'\rhunter2\n', b'', None, 'carriage return or newline'),
        ('second-line', b'hunter2\nextra', None, None, 'more than 1 line'),
        ('two-newlines', b'hunter2\n\n', None, None, 'more than 1 line'),
        ('crlf-then-data', b'hunter2\r\nextra', None, None, 'more than 1 line'),
        ('2047-bytes', b'x'*2047, b'x'*2047, b'x'*2047, ''),
        ('2048-bytes', b'x'*2048, None, None, 'line too long'),
        ('2046-plus-lf', b'x'*2046+b'\n', b'x'*2046, b'x'*2046, ''),
        ('2047-plus-lf', b'x'*2047+b'\n', None, None, 'line too long'),
        ('2045-plus-crlf', b'x'*2045+b'\r\n', b'x'*2045, b'x'*2045, ''),
        ('2046-plus-crlf', b'x'*2046+b'\r\n', None, None, 'line too long'),
        ('missing-file', None, None, None, 'fopen('),
    ]

def observe(binary, path, env):
    result = subprocess.run([str(binary), str(path)], capture_output=True,
                            text=True, env=env, timeout=15)
    if result.returncode not in (0, 1):
        raise RuntimeError(f'Unexpected exit {result.returncode}: {result.stderr}')
    if result.returncode == 0:
        parts = result.stdout.rstrip('\n').split(' ', 2)
        if len(parts) != 3 or parts[0] != 'ACCEPT':
            raise RuntimeError(f'Bad probe output: {result.stdout!r}')
        password = bytes.fromhex(parts[2])
        if len(password) != int(parts[1]):
            raise RuntimeError('Probe length mismatch')
    else:
        if result.stdout.strip() != 'REJECT':
            raise RuntimeError(f'Bad rejection output: {result.stdout!r}')
        password = None
    if 'Sanitizer' in result.stderr or 'runtime error:' in result.stderr:
        raise RuntimeError(f'Sanitizer finding: {result.stderr}')
    return result, password

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, default=Path('rivet-432-results'))
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'base': BASE, 'head': HEAD, 'platform': platform.platform(),
              'scope': 'Exact reader unit; not the full scrypt application',
              'sources': {}, 'commands': [], 'cases': [], 'preexisting_observations': []}
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    report['compiler'] = subprocess.run(compiler+['--version'], capture_output=True,
                                         check=True, text=True, timeout=15).stdout.splitlines()[0]
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1:exitcode=97',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    with tempfile.TemporaryDirectory(prefix='rivet-432-') as temporary:
        tmp = Path(temporary)
        src = tmp/'sources'
        report['sources'] = sources_for(args, src)
        print('Verified all 7 source blobs')
        for version, index in [('base', 2), ('head', 3)]:
            binary = tmp/f'probe-{version}'
            command = compiler + ['-std=c99', '-D_POSIX_C_SOURCE=200809L',
                '-Wall', '-Wextra', '-Werror', '-pedantic', '-g', '-O1',
                '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
                '-fno-pie', '-no-pie', '-I'+str(src/'common'),
                str(src/version/'readpass_file.c'), str(src/'common/warnp.c'),
                str(src/'common/insecure_memzero.c'),
                str(Path(__file__).resolve().with_name('probe.c')), '-o', str(binary)]
            report['commands'].append(command)
            build = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (args.output/f'{version}-compile.log').write_text(build.stdout+build.stderr)
            if build.returncode:
                raise RuntimeError(f'{version} compile failed: {build.stderr}')
            for case in cases():
                name, data = case[:2]
                path = tmp/(version+'-'+name+'.pw')
                if data is not None:
                    path.write_bytes(data)
                result, actual = observe(binary, path, env)
                expected = case[index]
                diagnostic = case[4]
                if actual != expected:
                    raise AssertionError(f'{version}/{name}: expected {expected!r}, actual {actual!r}')
                if expected is None and diagnostic not in result.stderr:
                    raise AssertionError(f'{version}/{name}: missing diagnostic {diagnostic!r}')
                (args.output/f'{version}-{name}.log').write_text(result.stdout+result.stderr)
                report['cases'].append({'version': version, 'name': name,
                    'input_bytes': None if data is None else len(data),
                    'exit': result.returncode, 'accepted_bytes': None if actual is None else len(actual),
                    'expected': 'reject' if expected is None else 'accept', 'pass': True})
                print(f'PASS {version}/{name} -> '+('reject' if actual is None else f'accept {len(actual)} bytes'))
            # Not correctness assertions: unchanged behavior outside #432's CR-only fix.
            for name, data in [('embedded-nul', b'hunter2\0extra'),
                               ('nul-hides-cr', b'hunter2\0\rextra\n')]:
                path = tmp/(version+'-'+name+'.pw')
                path.write_bytes(data)
                result, actual = observe(binary, path, env)
                (args.output/f'{version}-{name}.log').write_text(result.stdout+result.stderr)
                report['preexisting_observations'].append({'version': version, 'name': name,
                    'input_hex': data.hex(), 'output_hex': None if actual is None else actual.hex(),
                    'exit': result.returncode})
                print(f'OBSERVATION (not new regression): {version}/{name} -> {actual!r}')
    report['passed'] = len(report['cases'])
    (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f"RESULT {report['passed']}/{len(cases())*2} expected outcomes; 4 separate preexisting NUL observations")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
