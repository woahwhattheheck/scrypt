#!/usr/bin/env python3
"""Exact-revision full-program validation of Tarsnap/scrypt PR 430.

Run from a Git checkout containing both revisions. Requires Linux /dev/full,
GCC/build tools, autoconf-archive, OpenSSL development files, and Valgrind.
No production source is changed; generated test data uses a public dummy password.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET

BASE = "a71ae8281742ac638bc75baa4334f2292251e0eb"
HEAD = "ed46fc642108434ab16a53f5e8bc252435242825"
SIZES = (8193, 65535, 65536, 65537, 131073)
PASSWORD = b"lattice-public-test-only\n"
REPO = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "lattice-430-results").resolve()
OUT.mkdir(parents=True, exist_ok=False)
RESULTS: list[dict] = []


def command(args: list[str], label: str, cwd: Path, *, data: bytes | None = None,
            env: dict[str, str] | None = None, timeout: int = 180) -> subprocess.CompletedProcess:
    cp = subprocess.run(args, cwd=cwd, input=data, capture_output=True, env=env, timeout=timeout)
    (OUT / f"{label}.stdout").write_bytes(cp.stdout)
    (OUT / f"{label}.stderr").write_bytes(cp.stderr)
    print(f"COMMAND {label}: exit={cp.returncode}", flush=True)
    return cp


def must(args: list[str], label: str, cwd: Path, **kwargs) -> subprocess.CompletedProcess:
    cp = command(args, label, cwd, **kwargs)
    if cp.returncode:
        print(cp.stdout.decode(errors="replace")[-5000:])
        print(cp.stderr.decode(errors="replace")[-5000:])
        raise RuntimeError(f"{label} failed: {cp.returncode}")
    return cp


def record(row: dict) -> None:
    RESULTS.append(row)
    print("RESULT " + json.dumps(row, sort_keys=True), flush=True)
    (OUT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")


def memory_run(binary: Path, args: list[str], label: str, expected_exit: int,
               expect_leak: bool, function: str | None = None) -> None:
    xml = OUT / f"{label}.xml"
    cp = command(["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                  "--errors-for-leak-kinds=definite,indirect", "--error-exitcode=97",
                  "--num-callers=30", "--xml=yes", f"--xml-file={xml}",
                  str(binary), *args], label, binary.parent, data=PASSWORD)
    tree = ET.parse(xml)
    errors = []
    for error in tree.findall(".//error"):
        errors.append({"kind": error.findtext("kind"),
                       "bytes": int(error.findtext("xwhat/leakedbytes", "0")),
                       "blocks": int(error.findtext("xwhat/leakedblocks", "0")),
                       "frames": [f.text or "" for f in error.findall(".//frame/fn")]})
    actual_leaks = [e for e in errors if e["kind"] in ("Leak_DefinitelyLost", "Leak_IndirectlyLost")]
    unexpected = [e for e in errors if not e["kind"].startswith("Leak_")]
    # This is an allocation-specific oracle, not just a generic nonzero exit.
    named = all(any("crypto_aes_key_expand" in fn for fn in e["frames"])
                and (function is None or function in e["frames"]) for e in actual_leaks)
    passed = (cp.returncode == expected_exit and not unexpected
              and bool(actual_leaks) == expect_leak and (not expect_leak or named))
    if "/dev/full" in args:
        passed = passed and b"Error writing file: /dev/full" in cp.stderr
    record({"case": label, "pass": passed, "exit": cp.returncode,
            "expected_exit": expected_exit, "expected_aes_leak": expect_leak,
            "definite_or_indirect_leaks": actual_leaks, "other_memory_errors": unexpected,
            "all_reported_memory_records": errors})


def main() -> None:
    if not Path("/dev/full").is_char_device():
        raise RuntimeError("Linux /dev/full is required; do not silently skip failure cases")
    for tool in ("git", "autoreconf", "make", "cc", "valgrind"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing required tool: {tool}")
    for tool in ("cc", "valgrind", "make", "autoconf"):
        must([tool, "--version"], "version-" + tool, REPO)
    (OUT / "os-release.txt").write_bytes(Path("/etc/os-release").read_bytes())
    manifest = {"base": BASE, "head": HEAD, "sizes": SIZES, "password_is_public_fixture": True}
    for revision, sha in (("base", BASE), ("head", HEAD)):
        if subprocess.check_output(["git", "rev-parse", sha], cwd=REPO, text=True).strip() != sha:
            raise RuntimeError("revision mismatch")
        manifest[revision + "_production_blob"] = subprocess.check_output(
            ["git", "rev-parse", f"{sha}:lib/scryptenc/scryptenc.c"], cwd=REPO, text=True).strip()
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("MANIFEST " + json.dumps(manifest, sort_keys=True), flush=True)
    with tempfile.TemporaryDirectory(prefix="lattice-scrypt430-") as td:
        root = Path(td)
        builds = {}
        for revision, sha in (("base", BASE), ("head", HEAD)):
            build = root / revision
            build.mkdir()
            archive = root / f"{revision}.tar"
            must(["git", "archive", "--format=tar", f"--output={archive}", sha], revision + "-archive", REPO)
            with tarfile.open(archive) as tf:
                tf.extractall(build, filter="data")
            before = hashlib.sha256((build / "lib/scryptenc/scryptenc.c").read_bytes()).hexdigest()
            must(["autoreconf", "-fi"], revision + "-autoreconf", build)
            must(["./configure", "CFLAGS=-O1 -g3 -fno-omit-frame-pointer"], revision + "-configure", build)
            must(["make", "-j2"], revision + "-build", build, timeout=240)
            after = hashlib.sha256((build / "lib/scryptenc/scryptenc.c").read_bytes()).hexdigest()
            if before != after:
                raise RuntimeError("production source changed during build")
            builds[revision] = build
            record({"case": revision + "-full-build", "pass": True, "sha256_scryptenc_c": after})
        # Use the submitted scenario and its unchanged original driver against both binaries.
        driver = builds["head"] / "tests/test_scrypt.sh"
        for revision, build in builds.items():
            binary = build / "scrypt"
            for size in SIZES:
                prefix = f"{revision}-{size}"
                source, ciphertext, decoded = [root / (prefix + suffix) for suffix in (".bin", ".enc", ".dec")]
                payload = (bytes(range(256)) * ((size + 255) // 256))[:size]
                source.write_bytes(payload)
                params = ["enc", "-f", "--logN", "10", "-r", "1", "-p", "1",
                          "--passphrase", "dev:stdin-once", str(source)]
                memory_run(binary, [*params, str(ciphertext)], prefix + "-enc-control", 0, False)
                decparams = ["dec", "-f", "--passphrase", "dev:stdin-once", str(ciphertext)]
                memory_run(binary, [*decparams, str(decoded)], prefix + "-dec-control", 0, False)
                record({"case": prefix + "-roundtrip", "pass": decoded.read_bytes() == payload})
                leak = revision == "base"
                memory_run(binary, [*params, "/dev/full"], prefix + "-enc-full",
                           97 if leak else 1, leak, "scryptenc_file")
                memory_run(binary, [*decparams, "/dev/full"], prefix + "-dec-full",
                           97 if leak else 1, leak, "scryptdec_file_copy")
            for use_valgrind in (0, 1):
                label = f"{revision}-native13-valgrind{use_valgrind}"
                env = dict(os.environ, N="13", USE_VALGRIND=str(use_valgrind), VERBOSE="1")
                cp = command(["sh", str(driver), str(binary)], label, build, env=env, timeout=240)
                expected = 108 if revision == "base" and use_valgrind else 0
                record({"case": label, "pass": cp.returncode == expected,
                        "exit": cp.returncode, "expected_exit": expected})
                for dirname in ("tests-output", "tests-valgrind"):
                    src = build / dirname
                    if src.exists():
                        shutil.copytree(src, OUT / f"{label}-{dirname}")
    failed = [row["case"] for row in RESULTS if not row["pass"]]
    summary = {"checks": len(RESULTS), "passed": len(RESULTS) - len(failed), "failed": failed}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("SUMMARY " + json.dumps(summary, sort_keys=True), flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
