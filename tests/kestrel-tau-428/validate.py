#!/usr/bin/env python3
"""Replay scrypt PR 428 against two built, pinned, isolated checkouts.

Only generated files inside TemporaryDirectory are used as application inputs.
The native scenario writes into each supplied checkout's tests-output directory;
therefore supply disposable checkouts. No production data or credentials needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

BASE = "a71ae8281742ac638bc75baa4334f2292251e0eb"
HEAD = "30ac68db8070705e07e5cd376fa155a9443be8ba"
DIAG = b"Input and output files are the same:"
PASSWORD = b"kestrel-tau-generated-fixture-only\n"
ALIASES = ("same", "hardlink", "output_symlink", "input_symlink", "dotdot",
           "stdin_same", "stdin_hardlink", "stdin_symlink", "stdin_device")
CONTROLS = ("new", "existing", "equal_content", "symlink_new",
            "symlink_existing", "stdin", "stdout", "same_basename")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=90, check=False, **kwargs)


def require(ok: bool, description: str) -> None:
    if not ok:
        raise AssertionError(description)


def command(binary: Path, mode: str, password: Path, source: str,
            dest: str | None) -> list[str]:
    cmd = [str(binary), mode]
    if mode == "enc":
        cmd += ["--logN", "10", "-r", "1", "-p", "1"]
    cmd += ["--passphrase", f"file:{password}", source]
    if dest is not None:
        cmd.append(dest)
    return cmd


def decrypt(binary: Path, password: Path, data: bytes, directory: Path) -> bytes:
    path = directory / "roundtrip.enc"
    path.write_bytes(data)
    p = run(command(binary, "dec", password, str(path), None))
    require(p.returncode == 0, f"roundtrip failed: {p.stderr!r}")
    return p.stdout


def record(rows: list[dict], **data) -> None:
    rows.append(data)
    print(json.dumps(data, sort_keys=True), flush=True)


def matrix(root: Path, revision: str, password: Path, directory: Path,
           fixtures: dict[int, tuple[bytes, bytes]]) -> list[dict]:
    binary = root / "scrypt"
    rows: list[dict] = []
    for length, (plain, encrypted) in fixtures.items():
        for mode in ("enc", "dec"):
            for alias in ALIASES:
                label = f"{mode}-{length}-{alias}"
                work = directory / label
                work.mkdir()
                src = work / "input name $not-a-shell.bin"
                before = plain if mode == "enc" else encrypted
                src.write_bytes(before)
                src.chmod(0o600)
                identity = src.stat()
                target = work / "alias.bin"
                source_arg, dest_arg = str(src), str(src)
                stdin = None
                if alias in ("hardlink", "stdin_hardlink"):
                    os.link(src, target)
                    dest_arg = str(target)
                elif alias in ("output_symlink", "stdin_symlink"):
                    target.symlink_to(src.name)
                    dest_arg = str(target)
                elif alias == "input_symlink":
                    target.symlink_to(src.name)
                    source_arg = str(target)
                elif alias == "dotdot":
                    (work / "nested").mkdir()
                    dest_arg = str(work / "nested" / ".." / src.name)
                if alias.startswith("stdin_"):
                    source_arg = "-"
                    stdin = src.open("rb")
                if alias == "stdin_device":
                    dest_arg = "/dev/stdin"
                try:
                    p = run(command(binary, mode, password, source_arg, dest_arg), stdin=stdin)
                finally:
                    if stdin is not None:
                        stdin.close()
                after = src.read_bytes()
                if revision == "head":
                    require(p.returncode == 1 and DIAG in p.stderr and after == before,
                            f"{revision}/{label}: protection failed, rc={p.returncode}, stderr={p.stderr!r}")
                    require(src.stat().st_ino == identity.st_ino and
                            src.stat().st_mode == identity.st_mode,
                            f"{label}: input identity/permissions changed")
                else:
                    require(DIAG not in p.stderr and after != before,
                            f"{revision}/{label}: expected original data loss not observed")
                    if mode == "enc":
                        require(p.returncode == 0 and len(after) == 128,
                                f"{label}: baseline encryption did not become empty ciphertext")
                        require(decrypt(binary, password, after, work) == b"",
                                f"{label}: expected encryption of empty input")
                    else:
                        require(p.returncode in (0, 1), f"{label}: unexpected baseline exit")
                        if p.returncode == 0:
                            require(after == plain, f"{label}: successful in-place decrypt differs")
                record(rows, revision=revision, group="static_alias", case=label,
                       rc=p.returncode, preserved=after == before, before_bytes=len(before),
                       after_bytes=len(after), before_sha256=sha(before), after_sha256=sha(after),
                       stderr=p.stderr.decode(errors="replace"))

    plain, encrypted = fixtures[257]
    for mode in ("enc", "dec"):
        before = plain if mode == "enc" else encrypted
        for kind in CONTROLS:
            work = directory / f"control-{mode}-{kind}"
            work.mkdir()
            src, dest = work / "input.bin", work / "output.bin"
            src.write_bytes(before)
            stdin = None
            source_arg, dest_arg = str(src), str(dest)
            if kind == "existing":
                dest.write_bytes(b"replace this independent output")
            elif kind == "equal_content":
                dest.write_bytes(before)
            elif kind.startswith("symlink_"):
                other = work / "target.bin"
                if kind == "symlink_existing":
                    other.write_bytes(b"independent target")
                dest.symlink_to(other.name)
            elif kind == "stdin":
                source_arg = "-"
                stdin = src.open("rb")
            elif kind == "stdout":
                dest_arg = None
            elif kind == "same_basename":
                (work / "other").mkdir()
                dest = work / "other" / src.name
                dest_arg = str(dest)
            try:
                p = run(command(binary, mode, password, source_arg, dest_arg), stdin=stdin)
            finally:
                if stdin is not None:
                    stdin.close()
            require(p.returncode == 0 and src.read_bytes() == before and DIAG not in p.stderr,
                    f"{revision}/{mode}/{kind}: false positive or input changed: {p.stderr!r}")
            output = p.stdout if kind == "stdout" else dest.read_bytes()
            actual = decrypt(binary, password, output, work) if mode == "enc" else output
            require(actual == plain, f"{revision}/{mode}/{kind}: incorrect output")
            record(rows, revision=revision, group="different_file_control", case=f"{mode}-{kind}",
                   rc=p.returncode, preserved=True, roundtrip=True)

    for kind in ("null_same", "null_input", "null_enc_output", "null_dec_output"):
        work = directory / kind
        work.mkdir()
        src = work / "input.bin"
        mode = "dec" if kind == "null_dec_output" else "enc"
        before = encrypted if mode == "dec" else plain
        src.write_bytes(before)
        dest = work / "output.enc"
        source_arg = "/dev/null" if kind in ("null_same", "null_input") else str(src)
        dest_arg = str(dest) if kind == "null_input" else "/dev/null"
        p = run(command(binary, mode, password, source_arg, dest_arg))
        require(p.returncode == 0 and src.read_bytes() == before and DIAG not in p.stderr,
                f"{revision}/{kind}: {p.stderr!r}")
        if kind == "null_input":
            require(decrypt(binary, password, dest.read_bytes(), work) == b"", "null input not empty")
        record(rows, revision=revision, group="device_control", case=kind,
               rc=p.returncode, preserved=True)

    for mode in ("enc", "dec"):
        work = directory / f"early-{mode}"
        work.mkdir()
        src = work / "input.bin"
        before = plain if mode == "enc" else encrypted
        src.write_bytes(before)
        p = run(command(binary, mode, work / "missing-password", str(src), str(src)))
        require(p.returncode == 1 and src.read_bytes() == before, f"{revision}/early/{mode}")
        require((DIAG in p.stderr) == (revision == "head"), "pre-passphrase check ordering")
        record(rows, revision=revision, group="early_rejection", case=mode,
               rc=p.returncode, preserved=True, stderr=p.stderr.decode(errors="replace"))
    require(len(rows) == 76, f"unexpected matrix count {len(rows)}")
    return rows


def native(base: Path, head: Path, results: Path) -> list[dict]:
    # Copy only the submitted regression onto baseline; production sources remain exact.
    source = head / "tests/12-same-file.sh"
    shutil.copyfile(source, base / "tests/12-same-file.sh")
    rows = []
    for label, root in (("base", base), ("head", head)):
        env = dict(os.environ, N="12", VERBOSE="1", USE_VALGRIND="0")
        p = run(["sh", str(head / "tests/test_scrypt.sh"), str(root / "scrypt")], env=env, cwd=root)
        (results / f"native-{label}.log").write_bytes(p.stdout + p.stderr)
        checks = []
        for path in sorted((root / "tests-output").glob("*.exit")):
            description = path.with_suffix(".desc").read_text().strip()
            checks.append({"description": description, "status": path.read_text().strip()})
        require(len(checks) == 7, f"{label} native check count: {checks!r}, {p.stderr!r}")
        passing = sum(c["status"] == "0" for c in checks)
        require((p.returncode == 0 and passing == 7) if label == "head"
                else (p.returncode != 0 and passing < 7), f"native did not distinguish {label}")
        entry = {"revision": label, "rc": p.returncode, "passing": passing,
                 "total": len(checks), "checks": checks}
        rows.append(entry)
        print("NATIVE " + json.dumps(entry, sort_keys=True), flush=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("head", type=Path)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    base, head, results = (p.resolve() for p in (args.base, args.head, args.results))
    results.mkdir(parents=True, exist_ok=True)
    for root, expected in ((base, BASE), (head, HEAD)):
        actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        require(actual == expected, f"revision mismatch {actual} != {expected}")
        require((root / "scrypt").is_file(), f"build missing: {root}")
    summary = {"base_sha": BASE, "head_sha": HEAD, "platform": platform.platform(),
               "python": platform.python_version(), "matrix": [], "native": []}
    with tempfile.TemporaryDirectory(prefix="kestrel-tau-428-") as tmp:
        directory = Path(tmp)
        password = directory / "password"
        password.write_bytes(PASSWORD)
        fixtures = {}
        for length in (0, 257, 65537):
            plain = bytes((i * 17 + 13) % 256 for i in range(length))
            src = directory / f"fixture-{length}"
            src.write_bytes(plain)
            p = run(command(head / "scrypt", "enc", password, str(src), None))
            require(p.returncode == 0, f"fixture failed: {p.stderr!r}")
            fixtures[length] = (plain, p.stdout)
        for label, root in (("base", base), ("head", head)):
            work = directory / label
            work.mkdir()
            summary["matrix"] += matrix(root, label, password, work, fixtures)
    summary["native"] = native(base, head, results)
    summary["status"] = "PASS"
    summary["matrix_outcomes"] = len(summary["matrix"])
    summary["native_check_outcomes"] = sum(r["total"] for r in summary["native"])
    (results / "report.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {summary['matrix_outcomes']} matrix outcomes; "
          f"{summary['native_check_outcomes']} native check outcomes", flush=True)


if __name__ == "__main__":
    main()
